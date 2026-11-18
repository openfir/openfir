package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/openfir/openfir/internal/transport"
)

const udpIdle = 90 * time.Second

func remoteUDP(control *tls.Conn, raw *transport.Conn, u *net.UDPConn, m *transport.Messages) {
	// Only send replies from destinations contacted by this association.
	allowed := make(map[netip.AddrPort]time.Time)
	var mu sync.Mutex
	go func() {
		_, _ = io.Copy(io.Discard, control)
		raw.Close()
		u.Close()
	}()
	go func() {
		defer raw.Close()
		buf := make([]byte, 65535)
		for {
			n, src, err := u.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
			mu.Lock()
			expiry := allowed[src]
			mu.Unlock()
			if time.Now().After(expiry) {
				continue
			}
			a, err := encodeAddr(src.String())
			if err != nil {
				continue
			}
			_ = m.Send(append(a, buf[:n]...))
		}
	}()
	for {
		p, err := m.Receive()
		if err != nil {
			return
		}
		a, data, err := splitMessage(p)
		if err != nil {
			continue
		}
		dst, err := net.ResolveUDPAddr("udp", a.String())
		if err != nil {
			continue
		}
		ap := dst.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		now := time.Now()
		mu.Lock()
		if len(allowed) >= 512 {
			for k, expiry := range allowed {
				if now.After(expiry) {
					delete(allowed, k)
				}
			}
		}
		if _, ok := allowed[ap]; !ok && len(allowed) >= 512 {
			mu.Unlock()
			continue
		}
		allowed[ap] = now.Add(udpIdle)
		mu.Unlock()
		_, _ = u.WriteToUDP(data, dst)
	}
}

func (e *endpoint) fixedUDP(u *net.UDPConn, remote address) error {
	type flow struct {
		queue chan []byte
		stop  chan struct{}
	}
	var mu sync.Mutex
	flows := make(map[netip.AddrPort]*flow)
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range flows {
			close(f.stop)
		}
	}()
	run := func(peer netip.AddrPort, f *flow) {
		defer func() { mu.Lock(); delete(flows, peer); mu.Unlock() }()
		t, raw, _, err := e.open(associate, zeroAddr)
		if err != nil {
			return
		}
		defer t.Close()
		m, err := transport.NewMessages(raw, t.ConnectionState(), false)
		if err != nil {
			return
		}
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			for {
				p, err := m.Receive()
				if err != nil {
					return
				}
				_, payload, err := splitMessage(p)
				if err != nil {
					continue
				}
				_, _ = u.WriteToUDPAddrPort(payload, peer)
			}
		}()
		timer := time.NewTimer(udpIdle)
		defer timer.Stop()
		for {
			select {
			case <-f.stop:
				return
			case <-closed:
				return
			case <-timer.C:
				return
			case p := <-f.queue:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(udpIdle)
				_ = m.Send(p)
			}
		}
	}
	buf := make([]byte, 65535)
	for {
		n, peer, err := u.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		mu.Lock()
		f := flows[peer]
		if f == nil && len(flows) < 128 {
			f = &flow{make(chan []byte, 16), make(chan struct{})}
			flows[peer] = f
			go run(peer, f)
		}
		if f != nil {
			p := make([]byte, 0, len(remote)+n)
			p = append(p, remote...)
			p = append(p, buf[:n]...)
			select {
			case f.queue <- p:
			default:
			}
		}
		mu.Unlock()
	}
}
