package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

type address []byte

var zeroAddr = address{1, 0, 0, 0, 0, 0, 0}

func readAddr(r io.Reader) (address, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:1]); err != nil {
		return nil, err
	}
	a := address{h[0]}
	var n int
	switch h[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if _, err := io.ReadFull(r, h[1:]); err != nil {
			return nil, err
		}
		n = int(h[1])
		if n == 0 {
			return nil, errors.New("empty domain")
		}
		a = append(a, h[1])
	default:
		return nil, errors.New("unsupported address type")
	}
	i := len(a)
	a = append(a, make([]byte, n+2)...)
	_, err := io.ReadFull(r, a[i:])
	return a, err
}
func encodeAddr(s string) (address, error) {
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return nil, err
	}
	var a address
	if ip := net.ParseIP(host); ip != nil {
		if v := ip.To4(); v != nil {
			a = append(address{1}, v...)
		} else {
			a = append(address{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid host length")
		}
		a = append(address{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(a, uint16(port)), nil
}
func (a address) String() string {
	end := len(a) - 2
	var host string
	if a[0] == 3 {
		host = string(a[2:end])
	} else {
		host = net.IP(a[1:end]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(a[end:]))))
}
func splitMessage(p []byte) (address, []byte, error) {
	a, err := readAddr(bytes.NewReader(p))
	if err != nil {
		return nil, nil, err
	}
	return a, p[len(a):], nil
}
