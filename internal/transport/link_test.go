package transport

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Relay real UDP packets, map each client source port to its own upstream
// socket, and drop four adjacent symbols plus two in the same parity group.
func TestStreamSurvivesBurstAndSelectiveRetransmit(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := Open("127.0.0.1:0", key, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var relayWG sync.WaitGroup
	var mu sync.Mutex
	paths := make(map[string]*net.UDPConn)
	dropped := 0
	seen := make(map[uint64]int)
	var retried bool
	relayWG.Add(1)
	go func() {
		defer relayWG.Done()
		defer func() {
			for _, c := range paths {
				c.Close()
			}
		}()
		var r Reader
		buf := make([]byte, 2048)
		for {
			n, src, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			dst := paths[src.String()]
			if dst == nil {
				dst, err = net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
				if err != nil {
					mu.Unlock()
					return
				}
				paths[src.String()] = dst
				relayWG.Add(1)
				go func(c *net.UDPConn, to *net.UDPAddr) {
					defer relayWG.Done()
					b := make([]byte, 2048)
					for {
						n, err := c.Read(b)
						if err != nil {
							return
						}
						_, _ = front.WriteToUDP(b[:n], to)
					}
				}(dst, src)
			}
			f, ok := r.Open(srv.wire, buf[:n])
			drop := false
			if ok && !f.Parity && f.Symbol[2] == recordData {
				seq := getSeq(f.Symbol[2:])
				seen[seq]++
				drop = seen[seq] == 1 && ((seq >= 2 && seq <= 5) || seq == 22 || seq == 27)
				if drop {
					dropped++
				}
				if seen[seq] > 1 && (seq == 22 || seq == 27) {
					retried = true
				}
			}
			mu.Unlock()
			if !drop {
				_, _ = dst.Write(buf[:n])
			}
		}
	}()
	defer func() { front.Close(); relayWG.Wait() }()
	cli, err := Open(front.LocalAddr().String(), key, false, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	c, err := cli.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data := make([]byte, 256<<10)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	_ = c.SetDeadline(deadline)
	wrote := make(chan error, 1)
	go func() { _, err := c.Write(data); wrote <- err }()
	var peer *Conn
	select {
	case peer = <-srv.accept:
	case <-time.After(time.Second):
		t.Fatal("initial stream did not arrive")
	}
	defer peer.Close()
	_ = peer.SetDeadline(deadline)
	got := make([]byte, len(data))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	peer.rxMu.Lock()
	recovered := peer.decoder.Recovered
	peer.rxMu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(data, got) || len(paths) != 4 || dropped != 6 || recovered == 0 || !retried {
		t.Fatalf("paths=%d dropped=%d recovered=%d retransmitted=%v equal=%v", len(paths), dropped, recovered, retried, bytes.Equal(data, got))
	}
}

func TestWireRejectsWrongKeyDirectionAndTampering(t *testing.T) {
	client, _ := NewWire([]byte("first"), false)
	server, _ := NewWire([]byte("first"), true)
	other, _ := NewWire([]byte("other"), true)
	msg := client.Seal(Frame{Symbol: []byte{0, 1, 42}})
	var r Reader
	if _, ok := r.Open(other, msg); ok {
		t.Fatal("wrong key accepted")
	}
	if _, ok := r.Open(client, msg); ok {
		t.Fatal("reflected packet accepted")
	}
	if _, ok := r.Open(server, msg); !ok {
		t.Fatal("valid packet rejected")
	}
	msg[len(msg)-1] ^= 1
	if _, ok := r.Open(server, msg); ok {
		t.Fatal("tampered packet accepted")
	}
}
