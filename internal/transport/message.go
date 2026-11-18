package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

const (
	partHeader = 10 // message ID, fragment ordinal, count
	partSize   = MaxPayload - 1 - partHeader
	maxMessage = 65535 + 260 // UDP payload plus address
	maxParts   = (maxMessage + 16 + partSize - 1) / partSize
)

type assembly struct {
	parts    [][]byte
	received int
	start    time.Time
}

// Messages binds best-effort UDP payloads to the authenticated TLS session.
// One goroutine owns Receive, Send is safe to call concurrently.
type Messages struct {
	conn             *Conn
	sendKey, recvKey cipher.AEAD
	next             atomic.Uint64
	pending          map[uint64]*assembly
}

func NewMessages(c *Conn, state tls.ConnectionState, server bool) (*Messages, error) {
	key, err := state.ExportKeyingMaterial("OpenFIR proxy v1 UDP messages", c.id[:], 64)
	if err != nil {
		return nil, err
	}
	tx, rx := key[:32], key[32:]
	if server {
		tx, rx = rx, tx
	}
	newAEAD := func(k []byte) cipher.AEAD { b, _ := aes.NewCipher(k); a, _ := cipher.NewGCM(b); return a }
	return &Messages{conn: c, sendKey: newAEAD(tx), recvKey: newAEAD(rx), pending: make(map[uint64]*assembly)}, nil
}

func (m *Messages) Send(b []byte) error {
	if len(b) > maxMessage {
		return errors.New("UDP message too large")
	}
	var nonce [12]byte
	id := m.next.Add(1)
	binary.BigEndian.PutUint64(nonce[4:], id)
	sealed := m.sendKey.Seal(nil, nonce[:], b, nil)
	count := (len(sealed) + partSize - 1) / partSize
	for i := 0; i < count; i++ {
		part := sealed[i*partSize : min(len(sealed), (i+1)*partSize)]
		p := make([]byte, 1+partHeader+len(part))
		p[0] = recordDatagram
		binary.BigEndian.PutUint64(p[1:9], id)
		p[9] = byte(i)
		p[10] = byte(count)
		copy(p[11:], part)
		if err := m.conn.send(p); err != nil {
			return err
		}
	}
	return nil
}
func (m *Messages) Receive() ([]byte, error) {
	for {
		select {
		case <-m.conn.done:
			return nil, net.ErrClosed
		case p := <-m.conn.dgrams:
			if len(p) <= partHeader {
				continue
			}
			id, i, count := binary.BigEndian.Uint64(p), int(p[8]), int(p[9])
			if count == 0 || count > maxParts || i >= count || (i+1 < count && len(p) != partHeader+partSize) {
				continue
			}
			a := m.pending[id]
			if a == nil {
				now := time.Now()
				for k, old := range m.pending {
					if now.Sub(old.start) > 3*time.Second {
						delete(m.pending, k)
					}
				}
				if len(m.pending) >= 24 {
					continue
				}
				a = &assembly{parts: make([][]byte, count), start: now}
				m.pending[id] = a
			}
			if count != len(a.parts) || a.parts[i] != nil {
				continue
			}
			a.parts[i] = p[partHeader:]
			a.received++
			if a.received != count {
				continue
			}
			delete(m.pending, id)
			sealed := make([]byte, 0, count*partSize)
			for _, part := range a.parts {
				sealed = append(sealed, part...)
			}
			var nonce [12]byte
			binary.BigEndian.PutUint64(nonce[4:], id)
			b, err := m.recvKey.Open(nil, nonce[:], sealed, nil)
			if err == nil && len(b) <= maxMessage {
				return b, nil
			}
		}
	}
}
