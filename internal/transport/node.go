package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const maxPeers = 16

// Node owns the shared UDP sockets. Independent proxy connections each have
// a separate cryptographically random routing ID and bounded state.
type epochReplay struct {
	seen ReplayWindow
	last time.Time
}

type Node struct {
	epochs  map[[16]byte]*epochReplay
	wire    *Wire
	sockets []*net.UDPConn
	target  *net.UDPAddr // nil on the server
	mu      sync.Mutex
	conns   map[SessionID]*Conn
	accept  chan *Conn
	done    chan struct{}
	wg      sync.WaitGroup
}

func Open(endpoint string, secret []byte, server bool, paths int) (*Node, error) {
	if paths < 1 || paths > maxPeers {
		return nil, fmt.Errorf("UDP socket count must be 1..%d", maxPeers)
	}
	peer, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}
	w, err := NewWire(secret, server)
	if err != nil {
		return nil, err
	}
	n := &Node{wire: w, epochs: make(map[[16]byte]*epochReplay), conns: make(map[SessionID]*Conn), accept: make(chan *Conn, 64), done: make(chan struct{})}
	if server {
		c, err := net.ListenUDP("udp", peer)
		if err != nil {
			return nil, err
		}
		n.sockets = []*net.UDPConn{c}
	} else {
		n.target = peer
		for i := 0; i < paths; i++ {
			c, err := net.DialUDP("udp", nil, peer)
			if err != nil {
				n.Close()
				return nil, err
			}
			n.sockets = append(n.sockets, c)
		}
	}
	for _, c := range n.sockets {
		_ = c.SetReadBuffer(4 << 20)
		_ = c.SetWriteBuffer(4 << 20)
		n.wg.Add(1)
		go func(sock *net.UDPConn) { defer n.wg.Done(); n.receive(sock) }(c)
	}
	return n, nil
}

func (n *Node) LocalAddr() net.Addr { return n.sockets[0].LocalAddr() }
func (n *Node) Accept() (*Conn, error) {
	select {
	case c := <-n.accept:
		return c, nil
	case <-n.done:
		return nil, net.ErrClosed
	}
}
func (n *Node) Dial() (*Conn, error) {
	var id SessionID
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.done:
		return nil, net.ErrClosed
	default:
	}
	if len(n.conns) >= 256 {
		return nil, errors.New("proxy session limit reached")
	}
	return n.createLocked(id, nil), nil
}
func (n *Node) createLocked(id SessionID, peer *net.UDPAddr) *Conn {
	c := newConn(n, id)
	if peer != nil {
		c.routes = []*net.UDPAddr{peer}
	}
	n.conns[id] = c
	n.wg.Add(1)
	go func() { defer n.wg.Done(); c.maintain() }()
	return c
}
func (n *Node) Close() {
	n.mu.Lock()
	select {
	case <-n.done:
		n.mu.Unlock()
		return
	default:
		close(n.done)
	}
	for _, c := range n.sockets {
		c.Close()
	}
	n.mu.Unlock()
	n.wg.Wait()
}
func (n *Node) receive(sock *net.UDPConn) {
	var reader Reader
	buf := make([]byte, MaxWire+1)
	for {
		l, peer, err := sock.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		f, ok := reader.Open(n.wire, buf[:l])
		if !ok {
			continue
		}
		n.mu.Lock()
		epoch := n.epochs[reader.epoch]
		if epoch == nil {
			if len(n.epochs) >= 256 {
				for key, v := range n.epochs {
					if time.Since(v.last) > 2*time.Minute {
						delete(n.epochs, key)
					}
				}
				if len(n.epochs) >= 256 {
					n.mu.Unlock()
					continue
				}
			}
			epoch = &epochReplay{}
			n.epochs[reader.epoch] = epoch
		}
		if !epoch.seen.CheckAndAccept(binary.BigEndian.Uint64(buf[16:24])) {
			n.mu.Unlock()
			continue
		}
		epoch.last = time.Now()
		c := n.conns[f.ID]
		if c == nil && n.target == nil && !f.Parity && len(f.Symbol) >= 2+recordHeader &&
			f.Symbol[2] == recordData && getSeq(f.Symbol[2:]) == 0 && len(n.conns) < 256 {
			select {
			case <-n.done:
				n.mu.Unlock()
				return
			default:
			}
			if len(n.accept) < cap(n.accept) {
				c = n.createLocked(f.ID, peer)
				n.accept <- c
			}
		}
		n.mu.Unlock()
		if c == nil {
			continue
		}
		c.rxMu.Lock()
		prev := c.decoder.Recovered
		accepted := c.decoder.Accept(f, c.consume)
		count := c.decoder.Recovered
		c.rxMu.Unlock()
		if accepted {
			c.tracker.Observe(f.SentNano, time.Now().UnixNano())
		}
		if accepted && n.target == nil {
			c.sendMu.Lock()
			known := false
			for _, p := range c.routes {
				if p.AddrPort() == peer.AddrPort() {
					known = true
					break
				}
			}
			if !known {
				if len(c.routes) == maxPeers {
					c.routes = c.routes[1:]
				}
				c.routes = append(c.routes, peer)
			}
			c.sendMu.Unlock()
		}
		if count != prev && (count == 1 || count%100 == 0) {
			log.Printf("OpenFIR session %x recovered %d datagrams with XOR", c.id[:4], count)
		}
	}
}
