package transport

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"time"
)

const (
	recordData byte = iota + 1
	recordAck
	recordDatagram
	recordHeader  = 9
	receiveWindow = 64
)

func getSeq(p []byte) uint64 { return binary.BigEndian.Uint64(p[1:9]) }

type segment struct {
	raw         []byte
	first, last time.Time
	retried     bool
}

// Conn carries a bidirectional reliable byte stream and an independent
// best-effort message channel. The TLS handshake runs on the byte stream.
type Conn struct {
	node    *Node
	id      SessionID
	rxMu    sync.Mutex
	decoder Decoder
	tracker *KalmanOWDTracker
	pacer   *MicroPacer
	sendMu  sync.Mutex
	encoder Encoder
	wireSeq uint64
	routes  []*net.UDPAddr

	mu                          sync.Mutex
	in                          map[uint64][]byte
	readOffset                  int
	readBase, next, remoteBase  uint64
	out                         map[uint64]*segment
	rto                         time.Duration
	lastRecv, lastAck           time.Time
	dirty                       bool
	closing                     time.Time
	readDeadline, writeDeadline time.Time
	changed                     chan struct{}
	done                        chan struct{}
	dgrams                      chan []byte
}

func newConn(n *Node, id SessionID) *Conn {
	now := time.Now()
	return &Conn{
		node: n, id: id,
		tracker: NewKalmanOWDTracker(), pacer: NewMicroPacer(10, 0.25, 100),
		in: make(map[uint64][]byte), out: make(map[uint64]*segment),
		rto: 180 * time.Millisecond, lastRecv: now, lastAck: now,
		changed: make(chan struct{}), done: make(chan struct{}), dgrams: make(chan []byte, 128),
	}
}
func (c *Conn) notifyLocked()       { close(c.changed); c.changed = make(chan struct{}) }
func (c *Conn) LocalAddr() net.Addr { return c.node.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr {
	if c.node.target != nil {
		return c.node.target
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.routes[0]
}
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	c.notifyLocked()
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.notifyLocked()
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	c.notifyLocked()
	return nil
}

func (c *Conn) wait(ch chan struct{}, deadline time.Time) error {
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case <-c.done:
		return net.ErrClosed
	case <-ch:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if !c.closing.IsZero() {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if s := c.in[c.readBase]; s != nil {
			n := copy(b, s[c.readOffset:])
			c.readOffset += n
			if c.readOffset == len(s) {
				delete(c.in, c.readBase)
				c.readBase++
				c.readOffset = 0
				c.dirty = true
			}
			c.mu.Unlock()
			return n, nil
		}
		ch, deadline := c.changed, c.readDeadline
		c.mu.Unlock()
		if err := c.wait(ch, deadline); err != nil {
			return 0, err
		}
	}
}
func (c *Conn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		c.mu.Lock()
		select {
		case <-c.done:
			c.mu.Unlock()
			return total, net.ErrClosed
		default:
		}
		if !c.closing.IsZero() {
			c.mu.Unlock()
			return total, net.ErrClosed
		}
		if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
			c.mu.Unlock()
			return total, os.ErrDeadlineExceeded
		}
		if c.next-c.remoteBase >= receiveWindow {
			ch, deadline := c.changed, c.writeDeadline
			c.mu.Unlock()
			if err := c.wait(ch, deadline); err != nil {
				return total, err
			}
			continue
		}
		n := min(len(b), MaxPayload-recordHeader)
		p := make([]byte, recordHeader+n)
		p[0] = recordData
		binary.BigEndian.PutUint64(p[1:9], c.next)
		copy(p[9:], b[:n])
		now := time.Now()
		c.out[c.next] = &segment{raw: p, first: now, last: now}
		c.next++
		c.mu.Unlock()
		if err := c.send(p); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}
func (c *Conn) send(p []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.encoder.Send(p, func(parity bool, idx uint64, symbol []byte) error {
		c.pacer.Wait(headerSize + 24 + 16 + len(symbol))
		wire := c.node.wire.Seal(Frame{ID: c.id, Parity: parity, Index: idx, SentNano: time.Now().UnixNano(), Symbol: symbol})
		seq := c.wireSeq
		c.wireSeq++
		if c.node.target != nil {
			_, err := c.node.sockets[Path(seq, len(c.node.sockets))].Write(wire)
			return err
		}
		_, err := c.node.sockets[0].WriteToUDP(wire, c.routes[Path(seq, len(c.routes))])
		return err
	})
}
func (c *Conn) consume(p []byte) {
	if len(p) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRecv = time.Now()
	switch p[0] {
	case recordData:
		if len(p) <= recordHeader {
			return
		}
		idx := getSeq(p)
		c.dirty = true
		if idx < c.readBase || idx-c.readBase >= receiveWindow || c.in[idx] != nil {
			return
		}
		c.in[idx] = p[recordHeader:]
		c.notifyLocked()
	case recordAck:
		if len(p) != 33 {
			return
		}
		base, mask := getSeq(p), binary.BigEndian.Uint64(p[9:])
		if base < c.remoteBase || base > c.next {
			return
		}
		c.pacer.UpdateFromKalman(int64(binary.BigEndian.Uint64(p[17:25])), int64(binary.BigEndian.Uint64(p[25:33])))
		if base > c.remoteBase {
			c.remoteBase = base
			c.notifyLocked()
		}
		for seq, s := range c.out {
			if seq < base || (seq-base < 64 && mask&(1<<(seq-base)) != 0) {
				if !s.retried {
					sample := 2 * time.Since(s.first)
					c.rto = max(60*time.Millisecond, min(3*time.Second, (7*c.rto+sample)/8))
				}
				delete(c.out, seq)
			}
		}
	case recordDatagram:
		c.dirty = true
		select {
		case c.dgrams <- p[1:]:
		default:
		}
	}
}
func (c *Conn) maintain() {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	defer func() {
		c.node.mu.Lock()
		delete(c.node.conns, c.id)
		c.node.mu.Unlock()
		close(c.done)
	}()
	for {
		select {
		case <-c.node.done:
			return
		case now := <-t.C:
			c.mu.Lock()
			if (!c.closing.IsZero() && (len(c.out) == 0 || now.Sub(c.closing) > 5*time.Second)) || now.Sub(c.lastRecv) > 60*time.Second {
				c.mu.Unlock()
				return
			}
			var packets [][]byte
			expired := false
			for _, s := range c.out {
				if now.Sub(s.first) > 45*time.Second {
					expired = true
					break
				}
				if now.Sub(s.last) >= c.rto {
					packets = append(packets, s.raw)
					s.last = now
					s.retried = true
				}
			}
			if c.dirty || now.Sub(c.lastAck) > time.Second {
				ack := make([]byte, 33)
				ack[0] = recordAck
				binary.BigEndian.PutUint64(ack[1:], c.readBase)
				var mask uint64
				for seq := range c.in {
					mask |= 1 << (seq - c.readBase)
				}
				binary.BigEndian.PutUint64(ack[9:], mask)
				grad, queue := c.tracker.Snapshot()
				binary.BigEndian.PutUint64(ack[17:25], uint64(grad))
				binary.BigEndian.PutUint64(ack[25:33], uint64(queue))
				packets = append(packets, ack)
				c.lastAck = now
				c.dirty = false
			}
			c.mu.Unlock()
			if expired {
				return
			}
			for _, p := range packets {
				_ = c.send(p)
			}
		}
	}
}
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing.IsZero() {
		c.closing = time.Now()
		c.notifyLocked()
	}
	return nil
}
