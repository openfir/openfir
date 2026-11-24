// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openfir/openfir/internal/cc"
	"github.com/openfir/openfir/internal/cdc"
	"github.com/openfir/openfir/internal/netio"
	"github.com/openfir/openfir/internal/security"
	"github.com/openfir/openfir/internal/storage"
)

type ServerConfig struct {
	ListenAddr     string // Single port for BOTH TLS 1.3 TCP + OpenFIR v1 UDP (e.g. ":443" or ":9900")
	RootDir        string // Directory for received Push files & served Pull files
	MasterKey      [32]byte
	TLSCertFile    string // Optional CA-signed cert (auto-generates ephemeral TLS 1.3 cert if empty)
	TLSKeyFile     string
	AllowOverwrite bool
	MaxFileSize    int64
	MaxSessions    int
	DisableUDP     bool      // Optional: force TCP-only server mode (or test UDP-blocked environments!)
	UDPChaos       *UDPChaos // Optional chaos injector for selftest / ISP QoS simulation
}

type serverSession struct {
	sid       uint32
	cipher    *security.UDPSessionCipher
	udpRxCh   chan UDPInbound
	mu        sync.Mutex
	tcpConns  []io.ReadWriteCloser
	peerUDP   *net.UDPAddr
	closed    bool
	closeOnce sync.Once
}

func (ss *serverSession) close() {
	ss.closeOnce.Do(func() {
		ss.mu.Lock()
		ss.closed = true
		conns := append([]io.ReadWriteCloser(nil), ss.tcpConns...)
		ss.tcpConns = nil
		close(ss.udpRxCh)
		ss.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
}

func (ss *serverSession) enqueueUDP(pkt UDPInbound) {
	ss.mu.Lock()
	if !ss.closed {
		select {
		case ss.udpRxCh <- pkt:
		default:
		}
	}
	ss.mu.Unlock()
}

func (ss *serverSession) setPeerUDP(addr *net.UDPAddr) {
	cp := &net.UDPAddr{IP: append([]byte(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
	ss.mu.Lock()
	ss.peerUDP = cp
	ss.mu.Unlock()
}

func (ss *serverSession) getPeerUDP() *net.UDPAddr {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.peerUDP
}

func (ss *serverSession) addTCPConn(c io.ReadWriteCloser) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed {
		return false
	}
	ss.tcpConns = append(ss.tcpConns, c)
	return true
}

func (ss *serverSession) snapshotTCPConns() []io.ReadWriteCloser {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return append([]io.ReadWriteCloser(nil), ss.tcpConns...)
}

// Server implements the single-port OpenFIR v1.0 Enterprise File Transfer Server:
//   - Standard RFC 8446 TLS 1.3 (ALPN openfir/1) for Control + Multi-Stream TCP Data Lanes
//   - Open OF1\x01 X25519-PFS UDP Data Lane (Linux GSO/GRO + GF(256) RS FEC) on the same port
//   - Persistent Rabin CDC Cross-Session CAS Store (0% false positives across TB-scale dirs)
//   - Bidirectional Push (upload) and Pull (download)
type Server struct {
	cfg      ServerConfig
	tlsCfg   *tls.Config
	tcpLn    net.Listener
	udpConn  *net.UDPConn
	udpPort  uint16
	casStore *cdc.CASStore

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.RWMutex
	sessions   map[uint32]*serverSession
	completedN atomic.Int64
}

func NewServer(parentCtx context.Context, cfg ServerConfig) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":9900"
	}
	if cfg.RootDir == "" {
		cfg.RootDir = "./openfir_data"
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 256 * 1024 * 1024 * 1024 // 256 GB default cap
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	tlsCfg, err := security.BuildServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	tcpLn, err := tls.Listen("tcp", cfg.ListenAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("listen tls tcp %s: %w", cfg.ListenAddr, err)
	}
	tcpAddr := tcpLn.Addr().(*net.TCPAddr)

	var udpConn *net.UDPConn
	var udpPort uint16
	if !cfg.DisableUDP {
		host, _, _ := net.SplitHostPort(cfg.ListenAddr)
		udpBind := net.JoinHostPort(host, fmt.Sprintf("%d", tcpAddr.Port))
		uc, uErr := netio.ListenUDPReusePort(udpBind)
		if uErr != nil {
			// Fallback to ephemeral UDP port (advertised inside TLS 1.3 handshake!)
			uc, uErr = netio.ListenUDPReusePort(net.JoinHostPort(host, "0"))
		}
		if uErr == nil {
			udpConn = uc
			udpPort = uint16(uc.LocalAddr().(*net.UDPAddr).Port)
		}
	}

	casStore := cdc.NewCASStore(cdc.DefaultMaxCASEntries)
	go casStore.IndexPath(cfg.RootDir)

	ctx, cancel := context.WithCancel(parentCtx)
	s := &Server{
		cfg:      cfg,
		tlsCfg:   tlsCfg,
		tcpLn:    tcpLn,
		udpConn:  udpConn,
		udpPort:  udpPort,
		casStore: casStore,
		ctx:      ctx,
		cancel:   cancel,
		sessions: make(map[uint32]*serverSession),
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.tcpAcceptLoop()
	}()
	if udpConn != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.udpReadLoop()
		}()
	}
	return s, nil
}

func (s *Server) Addr() string          { return s.tcpLn.Addr().String() }
func (s *Server) UDPPort() uint16       { return s.udpPort }
func (s *Server) CASCount() int         { return s.casStore.Count() }
func (s *Server) CompletedCount() int64 { return s.completedN.Load() }

func (s *Server) Close() error {
	s.cancel()
	_ = s.tcpLn.Close()
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	s.mu.Lock()
	all := make([]*serverSession, 0, len(s.sessions))
	for id, ss := range s.sessions {
		all = append(all, ss)
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	for _, ss := range all {
		ss.close()
	}
	s.wg.Wait()
	s.casStore.Close()
	return nil
}

func (s *Server) allocSID() uint32 {
	var b [4]byte
	for {
		_, _ = io.ReadFull(rand.Reader, b[:])
		sid := binary.BigEndian.Uint32(b[:])
		if sid != 0 && s.sessions[sid] == nil {
			return sid
		}
	}
}

func (s *Server) tcpAcceptLoop() {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleTLSConn(c)
		}(conn)
	}
}

func (s *Server) handleTLSConn(rawConn net.Conn) {
	tc, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		return
	}
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(s.ctx); err != nil {
		_ = tc.Close()
		return
	}
	cs := tc.ConnectionState()

	var kind [1]byte
	if _, err := io.ReadFull(tc, kind[:]); err != nil {
		_ = tc.Close()
		return
	}

	switch kind[0] {
	case ConnKindTCPData:
		// Attach parallel TLS 1.3 TCP data lane to an already-authenticated SessionID:
		// [4B SID][16B Nonce][32B ChannelAuthProof]
		var hdr [52]byte
		if _, err := io.ReadFull(tc, hdr[:]); err != nil {
			_ = tc.Close()
			return
		}
		sid := binary.BigEndian.Uint32(hdr[0:4])
		if !security.VerifyChannelAuthProof(cs, s.cfg.MasterKey, "data-lane", hdr[4:20], hdr[20:52]) {
			_ = tc.Close()
			return
		}
		s.mu.RLock()
		ss := s.sessions[sid]
		s.mu.RUnlock()
		if ss == nil || !ss.addTCPConn(tc) {
			_ = tc.Close()
			return
		}
		_ = tc.SetDeadline(time.Time{})
		_, _ = tc.Write([]byte{0x01}) // Lane ready ACK!
		return

	case ConnKindControl:
		s.handleControlSession(tc, cs)

	default:
		_ = tc.Close()
	}
}

func (s *Server) handleControlSession(tc *tls.Conn, cs tls.ConnectionState) {
	defer tc.Close()

	// 1. Mutual RFC 5705 channel-bound authentication + X25519 PFS key exchange:
	//    Client -> Server: [16B ClientNonce][32B ClientX25519Pub][32B ClientAuthProof]
	var cliHello [80]byte
	if _, err := io.ReadFull(tc, cliHello[:]); err != nil {
		return
	}
	if !security.VerifyChannelAuthProof(cs, s.cfg.MasterKey, "client", cliHello[0:16], cliHello[48:80]) {
		_, _ = tc.Write([]byte{0x00})
		return
	}

	srvPriv, srvPub, err := security.GenerateX25519()
	if err != nil {
		_, _ = tc.Write([]byte{0x00})
		return
	}

	s.mu.Lock()
	if len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()
		_, _ = tc.Write([]byte{0x00})
		return
	}
	sid := s.allocSID()
	udpCipher, err := security.NewUDPSessionCipher(s.cfg.MasterKey, srvPriv, cliHello[16:48], sid, false)
	if err != nil {
		s.mu.Unlock()
		_, _ = tc.Write([]byte{0x00})
		return
	}
	ss := &serverSession{
		sid:     sid,
		cipher:  udpCipher,
		udpRxCh: make(chan UDPInbound, 4096),
	}
	s.sessions[sid] = ss
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		ss.close()
	}()

	var srvNonce [16]byte
	_, _ = io.ReadFull(rand.Reader, srvNonce[:])
	srvProof, err := security.ComputeChannelAuthProof(cs, s.cfg.MasterKey, "server", srvNonce[:])
	if err != nil {
		return
	}

	// Server -> Client: [1B OK=1][4B SID][16B ServerNonce][32B ServerX25519Pub][32B ServerAuthProof][2B UDPPort]
	var srvHello [87]byte
	srvHello[0] = 0x01
	binary.BigEndian.PutUint32(srvHello[1:5], sid)
	copy(srvHello[5:21], srvNonce[:])
	copy(srvHello[21:53], srvPub)
	copy(srvHello[53:85], srvProof[:])
	binary.BigEndian.PutUint16(srvHello[85:87], s.udpPort)
	if _, err := tc.Write(srvHello[:]); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})

	ctrl := NewCtrlChannel(tc)

	// 2. Receive TransferReq (Push or Pull)
	mType, body, err := ctrl.Recv()
	if err != nil || mType != MsgTransferReq {
		return
	}
	req, err := DecodeTransferReq(body)
	if err != nil {
		_ = ctrl.Send(MsgTransferMeta, EncodeTransferMeta(TransferMeta{OK: false, ErrMsg: err.Error()}))
		return
	}
	safeName, err := storage.ValidateSafeName(req.Name)
	if err != nil {
		_ = ctrl.Send(MsgTransferMeta, EncodeTransferMeta(TransferMeta{OK: false, ErrMsg: err.Error()}))
		return
	}

	switch req.Mode {
	case ModePush:
		if req.TotalSize < 0 || req.TotalSize > s.cfg.MaxFileSize {
			_ = ctrl.Send(MsgTransferMeta, EncodeTransferMeta(TransferMeta{OK: false, ErrMsg: "file size out of server limits"}))
			return
		}
		if err := ctrl.Send(MsgTransferMeta, EncodeTransferMeta(TransferMeta{OK: true, IsDir: req.IsDir, TotalSize: req.TotalSize})); err != nil {
			return
		}
		stats, err := RunReceiver(s.ctx, ReceiverConfig{
			OutDir:         s.cfg.RootDir,
			SafeName:       safeName,
			TotalSize:      req.TotalSize,
			IsDir:          req.IsDir,
			AllowOverwrite: s.cfg.AllowOverwrite,
			CASStore:       s.casStore,
			Ctrl:           ctrl,
			TCPConns:       ss.snapshotTCPConns(),
			UDPRxCh:        ss.udpRxCh,
		})
		if err != nil {
			log.Printf("[Server] Push %s paused/aborted (staging preserved for crash-resume): %v", safeName, err)
			return
		}
		s.completedN.Add(1)
		log.Printf("[Server] Push complete: %s (%.2f MB in %.3fs = %.2f MiB/s | UDP=%dB TCP=%dB CAS=%d Resumed=%d Zero=%d Deflate=%d FECRec=%d)",
			safeName, float64(stats.TotalBytes)/(1024*1024), stats.Elapsed.Seconds(), stats.GoodputMBps(),
			stats.WireUDPBytes, stats.WireTCPBytes, stats.CASBlocks, stats.ResumedBlocks, stats.ZeroBlocks, stats.CompressedBlocks, stats.FECRecovered)

	case ModePull:
		srcPath := filepath.Join(s.cfg.RootDir, safeName)
		readerAt, closer, size, isDir, _, oErr := storage.OpenSourceExtent(srcPath)
		if oErr != nil {
			_ = ctrl.Send(MsgTransferMeta, EncodeTransferMeta(TransferMeta{OK: false, ErrMsg: oErr.Error()}))
			return
		}
		defer closer.Close()
		if err := ctrl.Send(MsgTransferMeta, EncodeTransferMeta(TransferMeta{OK: true, IsDir: isDir, TotalSize: size})); err != nil {
			return
		}
		peerUDP := ss.getPeerUDP()
		stats, err := RunSender(s.ctx, SenderConfig{
			ReaderAt:      readerAt,
			TotalSize:     size,
			Ctrl:          ctrl,
			TCPConns:      ss.snapshotTCPConns(),
			UDPConn:       s.udpConn,
			UDPRemoteAddr: peerUDP,
			UDPCipher:     ss.cipher,
			Mode:          TransportAuto,
			UDPReachable:  s.udpConn != nil && peerUDP != nil,
			InitMBps:      cc.DefaultInitMBps,
			MaxMBps:       cc.DefaultMaxMBps,
			Chaos:         s.cfg.UDPChaos,
		})
		if err != nil {
			log.Printf("[Server] Pull %s failed: %v", safeName, err)
			return
		}
		s.completedN.Add(1)
		log.Printf("[Server] Pull complete: %s (%.2f MB in %.3fs = %.2f MiB/s | UDP=%dB TCP=%dB CAS=%d Resumed=%d)",
			safeName, float64(stats.TotalBytes)/(1024*1024), stats.Elapsed.Seconds(), stats.GoodputMBps(),
			stats.WireUDPBytes, stats.WireTCPBytes, stats.CASBlocks, stats.ResumedBlocks)

	default:
		_ = ctrl.Send(MsgTransferMeta, EncodeTransferMeta(TransferMeta{OK: false, ErrMsg: "unknown transfer mode"}))
	}
}

func (s *Server) udpReadLoop() {
	buf := make([]byte, 65536)
	oob := make([]byte, 256)
	for {
		err := netio.ReadBatchGRO(s.udpConn, buf, oob, func(wire []byte, addr *net.UDPAddr) {
			recvNano := time.Now().UnixNano()
			_, sid, _, ok := security.PeekUDPHeader(wire)
			if !ok {
				return
			}
			s.mu.RLock()
			ss := s.sessions[sid]
			s.mu.RUnlock()
			if ss == nil {
				return
			}

			flags, seq, plain, oErr := ss.cipher.Open(nil, wire)
			if oErr != nil {
				return
			}
			ss.setPeerUDP(addr)

			if flags == UDPFlagProbe {
				// Echo authenticated UDPProbeAck immediately for NAT punch + SRTT calibration!
				if s.cfg.UDPChaos != nil && s.cfg.UDPChaos.ShouldDrop() {
					return
				}
				resp, _ := ss.cipher.Seal(nil, UDPFlagProbeAck, plain)
				_, _ = s.udpConn.WriteToUDP(resp, addr)
				return
			}

			ss.enqueueUDP(UDPInbound{
				Flags:    flags,
				Seq:      seq,
				WireLen:  len(wire),
				RecvNano: recvNano,
				Plain:    plain,
			})
		})
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(2 * time.Millisecond)
			continue
		}
	}
}
