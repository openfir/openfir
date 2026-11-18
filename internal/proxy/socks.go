package proxy

import (
	"bytes"
	"crypto/subtle"
	"io"
	"net"
	"time"

	"github.com/openfir/openfir/internal/transport"
)

func listenUDP(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", a)
}
func socksReply(c net.Conn, code byte, a address) error {
	_, err := c.Write(append([]byte{5, code, 0}, a...))
	return err
}
func (e *endpoint) socks(c *net.TCPConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(setupTimeout))
	var h [3]byte
	if _, err := io.ReadFull(c, h[:2]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	method := byte(0)
	if e.p.Socks5.Username != "" || e.p.Socks5.Password != "" {
		method = 2
	}
	if !bytes.Contains(methods, []byte{method}) {
		_, _ = c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, method}); err != nil {
		return
	}
	if method == 2 && !localLogin(c, e.p.Socks5.Username, e.p.Socks5.Password) {
		return
	}
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[2] != 0 {
		return
	}
	a, err := readAddr(c)
	if err != nil {
		_ = socksReply(c, 8, zeroAddr)
		return
	}
	if h[1] != connect && h[1] != associate {
		_ = socksReply(c, 7, zeroAddr)
		return
	}
	up, raw, bound, err := e.open(h[1], a)
	if err != nil {
		_ = socksReply(c, 1, zeroAddr)
		return
	}
	defer up.Close()
	if h[1] == connect {
		if socksReply(c, 0, bound) != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		relay(c, up)
		return
	}
	lip := c.LocalAddr().(*net.TCPAddr)
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: lip.IP, Zone: lip.Zone})
	if err != nil {
		_ = socksReply(c, 1, zeroAddr)
		return
	}
	defer u.Close()
	m, err := transport.NewMessages(raw, up.ConnectionState(), false)
	if err != nil {
		return
	}
	bound, err = encodeAddr(u.LocalAddr().String())
	if err != nil || socksReply(c, 0, bound) != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	peerIP := c.RemoteAddr().(*net.TCPAddr).IP
	go func() { _, _ = io.Copy(io.Discard, c); u.Close() }()
	go func() { _, _ = io.Copy(io.Discard, up); u.Close() }()
	// The first valid packet pins the UDP port when the client requested port zero.
	wanted, err := net.ResolveUDPAddr("udp", a.String())
	if err != nil || (!wanted.IP.IsUnspecified() && !wanted.IP.Equal(peerIP)) {
		return
	}
	buf := make([]byte, 65535)
	var peer *net.UDPAddr
	for {
		n, src, err := u.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !src.IP.Equal(peerIP) || (wanted.Port != 0 && wanted.Port != src.Port) || n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		if _, _, err := splitMessage(buf[3:n]); err != nil {
			continue
		}
		if peer == nil {
			peer = src
			go func(dst *net.UDPAddr) {
				defer u.Close()
				for {
					p, err := m.Receive()
					if err != nil {
						return
					}
					_, _ = u.WriteToUDP(append([]byte{0, 0, 0}, p...), dst)
				}
			}(src)
		}
		if peer.AddrPort() == src.AddrPort() {
			_ = m.Send(buf[3:n])
		}
	}
}

func localLogin(c net.Conn, username, password string) bool {
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 1 {
		return false
	}
	user := make([]byte, header[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	if _, err := io.ReadFull(c, header[:1]); err != nil {
		return false
	}
	pass := make([]byte, header[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	ok := subtle.ConstantTimeCompare(user, []byte(username)) & subtle.ConstantTimeCompare(pass, []byte(password))
	_, err := c.Write([]byte{1, byte(1 - ok)})
	return err == nil && ok == 1
}
