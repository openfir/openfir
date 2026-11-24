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
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/openfir/openfir/internal/cc"
	"github.com/openfir/openfir/internal/cdc"
	"github.com/openfir/openfir/internal/netio"
	"github.com/openfir/openfir/internal/security"
	"github.com/openfir/openfir/internal/storage"
)

type ClientConfig struct {
	ServerAddr     string // Single-port server address (e.g. "files.example.com:443" or "203.0.113.10:9900")
	ServerName     string // Optional TLS SNI (defaults to host from ServerAddr)
	VerifyCA       bool   // True when server uses a real CA-signed certificate; false pins via RFC 5705 MasterKey binding
	MasterKey      [32]byte
	Mode           TransportMode // "auto" (hybrid UDP+TCP), "udp", or "tcp"
	TCPStreams     int           // Number of parallel TLS 1.3 TCP data lanes (default 4 in auto/tcp mode)
	InitMBps       float64       // Slow-start entry rate in MiB/s (default 4.0 MiB/s)
	MaxMBps        float64       // Maximum pacing rate in MiB/s (default 1000.0 MiB/s)
	MaxParity      int           // Max GF(256) RS parity shards per 16-shard group (default 8)
	AllowOverwrite bool          // Used on Pull mode
	UDPChaos       *UDPChaos     // Optional chaos injector for selftest / ISP QoS verification
}

type Client struct {
	cfg      ClientConfig
	casStore *cdc.CASStore
}

func NewClient(cfg ClientConfig) *Client {
	if cfg.Mode == "" {
		cfg.Mode = TransportAuto
	}
	if cfg.TCPStreams <= 0 {
		cfg.TCPStreams = 4
	}
	if cfg.InitMBps <= 0 {
		cfg.InitMBps = cc.DefaultInitMBps
	}
	if cfg.MaxMBps <= 0 {
		cfg.MaxMBps = cc.DefaultMaxMBps
	}
	if cfg.MaxParity <= 0 {
		cfg.MaxParity = 8
	}
	return &Client{
		cfg:      cfg,
		casStore: cdc.NewCASStore(cdc.DefaultMaxCASEntries),
	}
}

func (c *Client) Close() {
	if c.casStore != nil {
		c.casStore.Close()
	}
}

type clientConnBundle struct {
	ctrl         *CtrlChannel
	sid          uint32
	udpConn      *net.UDPConn
	udpRemote    *net.UDPAddr
	udpCipher    *security.UDPSessionCipher
	udpReachable bool
	initialRTT   time.Duration
	tcpConns     []io.ReadWriteCloser
	udpRxCh      chan UDPInbound
	stopUDP      context.CancelFunc
	udpWG        sync.WaitGroup
}

func (b *clientConnBundle) close() {
	if b.stopUDP != nil {
		b.stopUDP()
	}
	if b.udpConn != nil {
		_ = b.udpConn.Close()
	}
	b.udpWG.Wait()
	for _, tc := range b.tcpConns {
		_ = tc.Close()
	}
	if b.ctrl != nil {
		_ = b.ctrl.Close()
	}
}

func (c *Client) connectSession(ctx context.Context, startUDPReader bool) (*clientConnBundle, error) {
	host, _, err := net.SplitHostPort(c.cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", c.cfg.ServerAddr, err)
	}
	sni := c.cfg.ServerName
	if sni == "" {
		sni = host
	}
	tlsCfg := security.BuildClientTLSConfig(sni, c.cfg.VerifyCA)

	// 1. Establish standard RFC 8446 TLS 1.3 Control Connection (ALPN: openfir/1)
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", c.cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("dial tls control %s: %w", c.cfg.ServerAddr, err)
	}
	tc := tls.Client(rawConn, tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("tls 1.3 handshake: %w", err)
	}
	cs := tc.ConnectionState()

	cliPriv, cliPub, err := security.GenerateX25519()
	if err != nil {
		_ = tc.Close()
		return nil, err
	}
	var cliNonce [16]byte
	_, _ = io.ReadFull(rand.Reader, cliNonce[:])
	cliProof, err := security.ComputeChannelAuthProof(cs, c.cfg.MasterKey, "client", cliNonce[:])
	if err != nil {
		_ = tc.Close()
		return nil, err
	}

	var hello [81]byte
	hello[0] = ConnKindControl
	copy(hello[1:17], cliNonce[:])
	copy(hello[17:49], cliPub)
	copy(hello[49:81], cliProof[:])
	if _, err := tc.Write(hello[:]); err != nil {
		_ = tc.Close()
		return nil, err
	}

	var srvResp [87]byte
	if _, err := io.ReadFull(tc, srvResp[:]); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("read server auth response: %w", err)
	}
	if srvResp[0] != 0x01 {
		_ = tc.Close()
		return nil, security.ErrAuthFailed
	}
	sid := binary.BigEndian.Uint32(srvResp[1:5])
	if !security.VerifyChannelAuthProof(cs, c.cfg.MasterKey, "server", srvResp[5:21], srvResp[53:85]) {
		_ = tc.Close()
		return nil, security.ErrAuthFailed
	}
	srvUDPPort := binary.BigEndian.Uint16(srvResp[85:87])

	udpCipher, err := security.NewUDPSessionCipher(c.cfg.MasterKey, cliPriv, srvResp[21:53], sid, true)
	if err != nil {
		_ = tc.Close()
		return nil, err
	}

	bundle := &clientConnBundle{
		ctrl:      NewCtrlChannel(tc),
		sid:       sid,
		udpCipher: udpCipher,
	}

	// 2. Open Parallel TLS 1.3 TCP Data Lanes (100% immune to ISP UDP QoS / UDP blackholes!)
	if c.cfg.Mode != TransportUDP && c.cfg.TCPStreams > 0 {
		for i := 0; i < c.cfg.TCPStreams; i++ {
			dc, dErr := dialer.DialContext(ctx, "tcp", c.cfg.ServerAddr)
			if dErr != nil {
				continue
			}
			dtc := tls.Client(dc, tlsCfg)
			if hErr := dtc.HandshakeContext(ctx); hErr != nil {
				_ = dtc.Close()
				continue
			}
			dcs := dtc.ConnectionState()
			var dNonce [16]byte
			_, _ = io.ReadFull(rand.Reader, dNonce[:])
			dProof, pErr := security.ComputeChannelAuthProof(dcs, c.cfg.MasterKey, "data-lane", dNonce[:])
			if pErr != nil {
				_ = dtc.Close()
				continue
			}
			var dh [53]byte
			dh[0] = ConnKindTCPData
			binary.BigEndian.PutUint32(dh[1:5], sid)
			copy(dh[5:21], dNonce[:])
			copy(dh[21:53], dProof[:])
			if _, wErr := dtc.Write(dh[:]); wErr != nil {
				_ = dtc.Close()
				continue
			}
			var ack [1]byte
			if _, rErr := io.ReadFull(dtc, ack[:]); rErr != nil || ack[0] != 0x01 {
				_ = dtc.Close()
				continue
			}
			bundle.tcpConns = append(bundle.tcpConns, dtc)
		}
	}

	// 3. Open Single Clean UDP Data Socket & Run Authenticated Probe (NAT Punch + Initial SRTT + Auto-Detect Blocked UDP!)
	if c.cfg.Mode != TransportTCP && srvUDPPort > 0 {
		remoteIP := rawConn.RemoteAddr().(*net.TCPAddr).IP
		udpRemote := &net.UDPAddr{IP: remoteIP, Port: int(srvUDPPort)}
		uc, uErr := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if uErr == nil {
			netio.TuneUDPConn(uc)
			bundle.udpConn = uc
			bundle.udpRemote = udpRemote

			// Probe UDP reachability & measure exact initial SRTT (5 quick attempts, 300ms worst-case budget)
			var probeToken [8]byte
			_, _ = io.ReadFull(rand.Reader, probeToken[:])
			buf := make([]byte, 2048)
			for attempt := 0; attempt < 5 && !bundle.udpReachable; attempt++ {
				pStart := time.Now()
				if c.cfg.UDPChaos == nil || !c.cfg.UDPChaos.ShouldDrop() {
					pkt, _ := udpCipher.Seal(nil, UDPFlagProbe, probeToken[:])
					_, _ = uc.WriteToUDP(pkt, udpRemote)
				}
				_ = uc.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
				n, _, rErr := uc.ReadFromUDP(buf)
				if rErr == nil {
					fl, _, pl, oErr := udpCipher.Open(nil, buf[:n])
					if oErr == nil && fl == UDPFlagProbeAck && len(pl) == 8 {
						bundle.udpReachable = true
						bundle.initialRTT = time.Since(pStart)
					}
				}
			}
			_ = uc.SetReadDeadline(time.Time{})

			if startUDPReader && bundle.udpReachable {
				uCtx, uCancel := context.WithCancel(ctx)
				bundle.stopUDP = uCancel
				bundle.udpRxCh = make(chan UDPInbound, 4096)
				bundle.udpWG.Add(1)
				go func() {
					defer bundle.udpWG.Done()
					rbuf := make([]byte, 65536)
					oob := make([]byte, 256)
					for {
						if uCtx.Err() != nil {
							return
						}
						_ = uc.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
						rErr := netio.ReadBatchGRO(uc, rbuf, oob, func(wire []byte, _ *net.UDPAddr) {
							recvNano := time.Now().UnixNano()
							fl, seq, pl, oErr := udpCipher.Open(nil, wire)
							if oErr != nil {
								return
							}
							select {
							case bundle.udpRxCh <- UDPInbound{
								Flags:    fl,
								Seq:      seq,
								WireLen:  len(wire),
								RecvNano: recvNano,
								Plain:    pl,
							}:
							default:
							}
						})
						if rErr != nil {
							if errors.Is(rErr, net.ErrClosed) || uCtx.Err() != nil {
								return
							}
							continue
						}
					}
				}()
			}
		}
	}

	return bundle, nil
}

// Push uploads a local file OR entire directory tree to the OpenFIR v1.0 server.
func (c *Client) Push(ctx context.Context, localPath, remoteName string) (*TransferStats, error) {
	restoreTimer := netio.TuneHighResTimer()
	defer restoreTimer()

	readerAt, closer, totalSize, isDir, _, err := storage.OpenSourceExtent(localPath)
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	if remoteName == "" {
		remoteName = filepath.Base(filepath.Clean(localPath))
	}
	safeName, err := storage.ValidateSafeName(remoteName)
	if err != nil {
		return nil, err
	}

	bundle, err := c.connectSession(ctx, false)
	if err != nil {
		return nil, err
	}
	defer bundle.close()

	if err := bundle.ctrl.Send(MsgTransferReq, EncodeTransferReq(TransferReq{
		Mode:      ModePush,
		IsDir:     isDir,
		TotalSize: totalSize,
		Name:      safeName,
	})); err != nil {
		return nil, err
	}
	mType, body, err := bundle.ctrl.Recv()
	if err != nil || mType != MsgTransferMeta {
		return nil, fmt.Errorf("expected transfer metadata ack, got err=%v type=%d", err, mType)
	}
	meta, err := DecodeTransferMeta(body)
	if err != nil {
		return nil, err
	}
	if !meta.OK {
		return nil, fmt.Errorf("server rejected push: %s", meta.ErrMsg)
	}

	return RunSender(ctx, SenderConfig{
		ReaderAt:      readerAt,
		TotalSize:     totalSize,
		Ctrl:          bundle.ctrl,
		TCPConns:      bundle.tcpConns,
		UDPConn:       bundle.udpConn,
		UDPRemoteAddr: bundle.udpRemote,
		UDPCipher:     bundle.udpCipher,
		Mode:          c.cfg.Mode,
		UDPReachable:  bundle.udpReachable,
		InitialRTT:    bundle.initialRTT,
		InitMBps:      c.cfg.InitMBps,
		MaxMBps:       c.cfg.MaxMBps,
		MaxParity:     c.cfg.MaxParity,
		Chaos:         c.cfg.UDPChaos,
	})
}

// Pull downloads a remote file OR entire directory tree from the OpenFIR v1.0 server into localOutDir.
func (c *Client) Pull(ctx context.Context, remoteName, localOutDir string) (*TransferStats, error) {
	restoreTimer := netio.TuneHighResTimer()
	defer restoreTimer()

	safeName, err := storage.ValidateSafeName(remoteName)
	if err != nil {
		return nil, err
	}
	if localOutDir == "" {
		localOutDir = "."
	}
	c.casStore.IndexPath(localOutDir)

	bundle, err := c.connectSession(ctx, true)
	if err != nil {
		return nil, err
	}
	defer bundle.close()

	if err := bundle.ctrl.Send(MsgTransferReq, EncodeTransferReq(TransferReq{
		Mode: ModePull,
		Name: safeName,
	})); err != nil {
		return nil, err
	}
	mType, body, err := bundle.ctrl.Recv()
	if err != nil || mType != MsgTransferMeta {
		return nil, fmt.Errorf("expected transfer metadata ack, got err=%v type=%d", err, mType)
	}
	meta, err := DecodeTransferMeta(body)
	if err != nil {
		return nil, err
	}
	if !meta.OK {
		return nil, fmt.Errorf("server rejected pull: %s", meta.ErrMsg)
	}

	var udpCh <-chan UDPInbound
	if bundle.udpReachable {
		udpCh = bundle.udpRxCh
	}
	return RunReceiver(ctx, ReceiverConfig{
		OutDir:         localOutDir,
		SafeName:       safeName,
		TotalSize:      meta.TotalSize,
		IsDir:          meta.IsDir,
		AllowOverwrite: c.cfg.AllowOverwrite,
		CASStore:       c.casStore,
		Ctrl:           bundle.ctrl,
		TCPConns:       bundle.tcpConns,
		UDPRxCh:        udpCh,
	})
}

// Helper to suppress unused import warning if strconv is needed later
var _ = strconv.Itoa
