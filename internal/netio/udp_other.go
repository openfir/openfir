// SPDX-License-Identifier: Apache-2.0
//go:build !linux && !windows

package netio

import "net"

const SocketBufBytes = 8 * 1024 * 1024

func TuneHighResTimer() func() { return func() {} }

func TuneUDPConn(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	_ = conn.SetReadBuffer(SocketBufBytes)
	_ = conn.SetWriteBuffer(SocketBufBytes)
}

func ListenUDPReusePort(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	TuneUDPConn(c)
	return c, nil
}

type GSOBatchWriter struct {
	conn *net.UDPConn
}

func NewGSOBatchWriter(conn *net.UDPConn) *GSOBatchWriter {
	return &GSOBatchWriter{conn: conn}
}

func (w *GSOBatchWriter) SendBatch(packets [][]byte, dst *net.UDPAddr) error {
	for _, p := range packets {
		if _, err := w.conn.WriteToUDP(p, dst); err != nil {
			return err
		}
	}
	return nil
}

func ReadBatchGRO(conn *net.UDPConn, buf, _ []byte, onPacket func(pkt []byte, addr *net.UDPAddr)) error {
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	onPacket(buf[:n], addr)
	return nil
}
