package proxy

import (
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/openfir/openfir/internal/transport"
)

const (
	connect      = 1
	associate    = 3
	setupTimeout = 15 * time.Second
)

type endpoint struct {
	p    *profile
	node *transport.Node
}

func Run(role, config string) error {
	server := role == "server"
	p, err := loadProfile(config, server)
	if err != nil {
		return err
	}
	addr := p.Server
	if server {
		addr = p.Listen
	}
	n, err := transport.Open(addr, p.secret, server, p.OpenFIR.Sockets)
	if err != nil {
		return err
	}
	defer n.Close()
	e := endpoint{p, n}
	if server {
		log.Printf("OpenFIR native proxy listening on %s/udp", n.LocalAddr())
		for {
			c, err := n.Accept()
			if err != nil {
				return err
			}
			go e.serveRemote(c)
		}
	}
	log.Printf("OpenFIR native proxy to %s over %d UDP sockets", addr, p.OpenFIR.Sockets)
	return e.serveLocal()
}

func (e *endpoint) open(op byte, a address) (*tls.Conn, *transport.Conn, address, error) {
	raw, err := e.node.Dial()
	if err != nil {
		return nil, nil, nil, err
	}
	t := tls.Client(raw, e.p.security)
	_ = t.SetDeadline(time.Now().Add(setupTimeout))
	h := []byte{1, op, byte(len(e.p.password))}
	h = append(h, e.p.password...)
	h = append(h, a...)
	if _, err = t.Write(h); err == nil {
		var rep [1]byte
		if _, err = io.ReadFull(t, rep[:]); err == nil {
			var bound address
			if bound, err = readAddr(t); err == nil {
				if rep[0] == 0 {
					_ = t.SetDeadline(time.Time{})
					return t, raw, bound, nil
				}
				err = fmt.Errorf("remote proxy request failed (code %d)", rep[0])
			}
		}
	}
	raw.Close()
	return nil, nil, nil, err
}

func (e *endpoint) serveRemote(raw *transport.Conn) {
	defer raw.Close()
	t := tls.Server(raw, e.p.security)
	_ = t.SetDeadline(time.Now().Add(setupTimeout))
	var h [3]byte
	if _, err := io.ReadFull(t, h[:]); err != nil || h[0] != 1 {
		return
	}
	password := make([]byte, h[2])
	if _, err := io.ReadFull(t, password); err != nil {
		return
	}
	if subtle.ConstantTimeCompare(password, []byte(e.p.password)) != 1 {
		_, _ = t.Write(append([]byte{2}, zeroAddr...))
		_ = t.Close()
		return
	}
	a, err := readAddr(t)
	if err != nil {
		return
	}
	defer t.Close()
	switch h[1] {
	case connect:
		up, err := net.DialTimeout("tcp", a.String(), 8*time.Second)
		if err != nil {
			_, _ = t.Write(append([]byte{5}, zeroAddr...))
			return
		}
		defer up.Close()
		bound, err := encodeAddr(up.LocalAddr().String())
		if err != nil {
			return
		}
		if _, err = t.Write(append([]byte{0}, bound...)); err != nil {
			return
		}
		_ = t.SetDeadline(time.Time{})
		relay(t, up.(*net.TCPConn))
	case associate:
		u, err := net.ListenUDP("udp", nil)
		if err != nil {
			_, _ = t.Write(append([]byte{1}, zeroAddr...))
			return
		}
		defer u.Close()
		m, err := transport.NewMessages(raw, t.ConnectionState(), true)
		if err != nil {
			return
		}
		if _, err = t.Write(append([]byte{0}, zeroAddr...)); err != nil {
			return
		}
		_ = t.SetDeadline(time.Time{})
		remoteUDP(t, raw, u, m)
	default:
		_, _ = t.Write(append([]byte{7}, zeroAddr...))
	}
}

type duplex interface {
	net.Conn
	CloseWrite() error
}

func relay(a, b duplex) {
	var wg sync.WaitGroup
	copySide := func(dst, src duplex) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			_ = a.SetDeadline(time.Now())
			_ = b.SetDeadline(time.Now())
		}
		_ = dst.CloseWrite()
	}
	wg.Add(2)
	go copySide(a, b)
	go copySide(b, a)
	wg.Wait()
}

func (e *endpoint) serveLocal() error {
	errs := make(chan error, 1+len(e.p.TCPForwarding)+len(e.p.UDPForwarding))
	var listeners []io.Closer
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	tcp := func(addr string, f func(*net.TCPConn)) error {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					errs <- err
					return
				}
				go f(c.(*net.TCPConn))
			}
		}()
		return nil
	}
	if s := e.p.Socks5.Listen; s != "" {
		if err := tcp(s, e.socks); err != nil {
			return err
		}
		log.Printf("SOCKS5 listening on %s", s)
	}
	for _, rule := range e.p.TCPForwarding {
		a, err := encodeAddr(rule.Remote)
		if err != nil {
			return err
		}
		err = tcp(rule.Listen, func(c *net.TCPConn) {
			defer c.Close()
			up, _, _, err := e.open(connect, a)
			if err != nil {
				return
			}
			defer up.Close()
			relay(c, up)
		})
		if err != nil {
			return err
		}
	}
	for _, rule := range e.p.UDPForwarding {
		a, err := encodeAddr(rule.Remote)
		if err != nil {
			return err
		}
		u, err := listenUDP(rule.Listen)
		if err != nil {
			return err
		}
		listeners = append(listeners, u)
		go func() { errs <- e.fixedUDP(u, a) }()
	}
	if len(listeners) == 0 {
		return errors.New("no local proxy listeners configured")
	}
	return <-errs
}
