package proxy

import (
	"bytes"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/openfir/openfir/internal/transport"
)

func TestNativeAuthenticatedUDP(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profiles")
	if err := Init(dir, "127.0.0.1:443", "127.0.0.1:1080", 4); err != nil {
		t.Fatal(err)
	}
	s, err := loadProfile(filepath.Join(dir, "server", "config.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	client, err := loadProfile(filepath.Join(dir, "client", "config.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := transport.Open("127.0.0.1:0", s.secret, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		e := endpoint{s, srv}
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go e.serveRemote(c)
		}
	}()
	node, err := transport.Open(srv.LocalAddr().String(), client.secret, false, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	e := endpoint{client, node}

	wrong := *client
	wrong.security = client.security.Clone()
	wrong.security.ServerName = "wrong.example.org"
	invalid := endpoint{&wrong, node}
	if conn, _, _, err := invalid.open(associate, zeroAddr); err == nil {
		conn.Close()
		t.Fatal("invalid server certificate accepted")
	}
	wrong.security = client.security
	wrong.password = "invalid"
	if conn, _, _, err := invalid.open(associate, zeroAddr); err == nil {
		conn.Close()
		t.Fatal("wrong proxy password accepted")
	}

	control, raw, _, err := e.open(associate, zeroAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	m, err := transport.NewMessages(raw, control.ConnectionState(), false)
	if err != nil {
		t.Fatal(err)
	}
	u, err := listenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	dst, err := encodeAddr(u.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = u.WriteToUDP(buf[:n], src)
		}
	}()

	for _, size := range []int{0, 4096, 60000} {
		data := bytes.Repeat([]byte{0xa5}, size)
		if err = m.Send(append(append(address(nil), dst...), data...)); err != nil {
			t.Fatal(err)
		}
		ch := make(chan []byte, 1)
		go func() { p, _ := m.Receive(); ch <- p }()
		select {
		case p := <-ch:
			addr, payload, err := splitMessage(p)
			if err != nil || !bytes.Equal(payload, data) || !bytes.Equal(addr, dst) {
				t.Fatalf("bad UDP round-trip for %d bytes", size)
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("UDP round-trip timed out for %d bytes", size)
		}
	}
}

var _ net.Conn = (*transport.Conn)(nil)
