package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync/atomic"
)

const (
	// Includes the proxy record type and sequence. Even IPv6 parity datagrams
	// fit in a 1280-byte path MTU with the authenticated outer envelope.
	MaxPayload = 1140
	headerSize = 1 + 16 + 8 + 8
	MaxWire    = 16 + 8 + headerSize + 2 + MaxPayload + 16
)

type SessionID [16]byte
type Frame struct {
	ID       SessionID
	Parity   bool
	Index    uint64
	SentNano int64
	Symbol   []byte
}

// Each process chooses a fresh 128-bit epoch. Direction- and epoch-specific
// AES-GCM keys isolate restarts and the monotonically increasing packet nonce.
type Wire struct {
	epoch    [16]byte
	sequence atomic.Uint64
	tx       cipher.AEAD
	rxMaster []byte
}

func epochCipher(master, epoch []byte) cipher.AEAD {
	key := HKDF(master, epoch, []byte("OpenFIR proxy v1 wire epoch"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return a
}
func NewWire(secret []byte, server bool) (*Wire, error) {
	c2s := HKDF(secret, nil, []byte("OpenFIR proxy v1 client"))
	s2c := HKDF(secret, nil, []byte("OpenFIR proxy v1 server"))
	if server {
		c2s, s2c = s2c, c2s
	}
	w := &Wire{rxMaster: s2c[:]}
	if _, err := rand.Read(w.epoch[:]); err != nil {
		return nil, err
	}
	w.tx = epochCipher(c2s[:], w.epoch[:])
	return w, nil
}

func (w *Wire) Seal(f Frame) []byte {
	seq := w.sequence.Add(1)
	b := make([]byte, 24, MaxWire)
	copy(b, w.epoch[:])
	binary.BigEndian.PutUint64(b[16:], seq)
	p := make([]byte, headerSize+len(f.Symbol))
	if f.Parity {
		p[0] = 1
	}
	copy(p[1:17], f.ID[:])
	binary.BigEndian.PutUint64(p[17:25], f.Index)
	binary.BigEndian.PutUint64(p[25:33], uint64(f.SentNano))
	copy(p[headerSize:], f.Symbol)
	return w.tx.Seal(b, b[12:24], p, b)
}

// Reader is private to one UDP socket. Cache only authenticated epochs.
type Reader struct {
	wire  *Wire
	epoch [16]byte
	aead  cipher.AEAD
}

func (r *Reader) Open(w *Wire, b []byte) (Frame, bool) {
	if len(b) < 24+headerSize+2+16 || len(b) > MaxWire {
		return Frame{}, false
	}
	a := r.aead
	if r.wire != w || a == nil || !bytes.Equal(r.epoch[:], b[:16]) {
		a = epochCipher(w.rxMaster, b[:16])
	}
	p, err := a.Open(nil, b[12:24], b[24:], b[:24])
	if err != nil || p[0] > 1 {
		return Frame{}, false
	}
	r.wire = w
	r.aead = a
	copy(r.epoch[:], b[:16])
	f := Frame{Parity: p[0] == 1, Index: binary.BigEndian.Uint64(p[17:25]), SentNano: int64(binary.BigEndian.Uint64(p[25:33])), Symbol: p[headerSize:]}
	copy(f.ID[:], p[1:17])
	if f.Parity && f.Index%Window >= Stride {
		return Frame{}, false
	}
	if !f.Parity && int(binary.BigEndian.Uint16(f.Symbol)) != len(f.Symbol)-2 {
		return Frame{}, false
	}
	return f, true
}

// Encoder is owned by one sender. Data leaves immediately. A complete window
// adds five independent parity frames, covering positions 0/5/10/15 etc.
type Encoder struct {
	next   uint64
	parity [Stride][]byte
}

func (e *Encoder) Send(payload []byte, emit func(parity bool, index uint64, symbol []byte) error) error {
	if len(payload) > MaxPayload {
		return errors.New("OpenFIR proxy datagram too large")
	}
	i := e.next
	e.next++
	s := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(s, uint16(len(payload)))
	copy(s[2:], payload)
	group := i % Stride
	p := e.parity[group]
	if len(p) < len(s) {
		p = append(p, make([]byte, len(s)-len(p))...)
	}
	XOR(p, s)
	e.parity[group] = p
	err := emit(false, i, s)
	if (i+1)%Window == 0 {
		base := i + 1 - Window
		for g, p := range e.parity {
			if sendErr := emit(true, base+uint64(g), p); err == nil {
				err = sendErr
			}
			e.parity[g] = nil
		}
	}
	return err
}

// A bounded sliding set of windows tolerates reordering without retaining
// old datagrams for the lifetime of a proxy connection.
const retainedWindows = 16

type window struct {
	number uint64
	data   [Window][]byte
	parity [Stride][]byte
}
type Decoder struct {
	high      uint64
	windows   [retainedWindows]*window
	Recovered uint64
}

// Accept calls deliver at most twice: once for a newly received datagram,
// and once when that datagram completes a single-erasure equation.
func (d *Decoder) Accept(f Frame, deliver func([]byte)) bool {
	n := f.Index / Window
	if n < d.high && d.high-n >= retainedWindows {
		return false
	}
	if n > d.high {
		d.high = n
	}
	slot := n % retainedWindows
	w := d.windows[slot]
	if w == nil || w.number != n {
		w = &window{number: n}
		d.windows[slot] = w
	}
	pos := int(f.Index % Window)
	group := pos % Stride
	if f.Parity {
		if w.parity[group] != nil {
			return false
		}
		w.parity[group] = append([]byte(nil), f.Symbol...)
	} else {
		if w.data[pos] != nil {
			return false
		}
		w.data[pos] = append([]byte(nil), f.Symbol...)
		deliver(w.data[pos][2:])
	}
	p := w.parity[group]
	if p == nil {
		return true
	}
	missing := -1
	for j := 0; j < Members; j++ {
		idx := Member(group, j)
		if w.data[idx] == nil {
			if missing >= 0 {
				return true
			}
			missing = idx
		}
	}
	if missing < 0 {
		return true
	}
	for j := 0; j < Members; j++ {
		idx := Member(group, j)
		if idx == missing {
			continue
		}
		if len(w.data[idx]) > len(p) {
			return true
		}
		XOR(p, w.data[idx])
	}
	length := int(binary.BigEndian.Uint16(p)) + 2
	if length <= len(p) {
		w.data[missing] = p[:length]
		d.Recovered++
		deliver(p[2:length])
	}
	return true
}
