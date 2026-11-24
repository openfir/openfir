// SPDX-License-Identifier: Apache-2.0
//go:build windows

package netio

import (
	"net"
	"syscall"
)

const SocketBufBytes = 16 * 1024 * 1024

var (
	winmmDLL            = syscall.NewLazyDLL("winmm.dll")
	procTimeBeginPeriod = winmmDLL.NewProc("timeBeginPeriod")
	procTimeEndPeriod   = winmmDLL.NewProc("timeEndPeriod")
)

// TuneHighResTimer raises Windows timer resolution from 15.6ms to 1ms so MicroPacer
// sustains multi-Gbps speeds with CAR-safe <=256KB bursts (no 8MB micro-bursts needed!).
func TuneHighResTimer() func() {
	_, _, _ = procTimeBeginPeriod.Call(1)
	return func() {
		_, _, _ = procTimeEndPeriod.Call(1)
	}
}

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
