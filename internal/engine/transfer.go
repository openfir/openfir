// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openfir/openfir/internal/cc"
	"github.com/openfir/openfir/internal/cdc"
	"github.com/openfir/openfir/internal/compress"
	"github.com/openfir/openfir/internal/fec"
	"github.com/openfir/openfir/internal/netio"
	"github.com/openfir/openfir/internal/security"
	"github.com/openfir/openfir/internal/storage"
)

// TransferStats summarizes complete telemetry for one OpenFIR v1.0 transfer.
type TransferStats struct {
	TotalBytes        int64
	TotalBlocks       uint32
	WireUDPBytes      uint64
	WireTCPBytes      uint64
	CASBlocks         uint32
	ResumedBlocks     uint32
	ZeroBlocks        uint32
	CompressedBlocks  uint32
	RawBlocks         uint32
	UDPBlocksSent     uint32
	TCPBlocksSent     uint32
	UDPFallbackBlocks uint32
	FECParitySent     uint64
	FECRecovered      uint32
	ExtractedItems    int
	Elapsed           time.Duration
	MerkleRoot        [32]byte
}

func (s *TransferStats) GoodputMBps() float64 {
	sec := s.Elapsed.Seconds()
	if sec <= 0 {
		sec = 0.001
	}
	return (float64(s.TotalBytes) / (1024 * 1024)) / sec
}

// ============================================================================
// Unified Symmetric Sender Engine (Runs on Client for Push, Server for Pull)
// ============================================================================

type SenderConfig struct {
	ReaderAt      io.ReaderAt
	TotalSize     int64
	Ctrl          *CtrlChannel
	TCPConns      []io.ReadWriteCloser // 0..K parallel TLS 1.3 TCP data lanes
	UDPConn       *net.UDPConn
	UDPRemoteAddr *net.UDPAddr
	UDPCipher     *security.UDPSessionCipher
	Mode          TransportMode
	UDPReachable  bool
	InitialRTT    time.Duration
	InitMBps      float64
	MaxMBps       float64
	MaxParity     int
	Chaos         *UDPChaos
}

type inflightBlock struct {
	meta        cdc.BlockMeta
	encoding    uint8
	wirePayload []byte
	totalSlices uint16
	sentViaUDP  bool
	sentAt      time.Time
	lastSliceTx map[uint16]time.Time
	acked       bool
	requeuedTCP bool
}

func RunSender(ctx context.Context, cfg SenderConfig) (*TransferStats, error) {
	start := time.Now()
	stats := &TransferStats{TotalBytes: cfg.TotalSize}

	useUDP := cfg.Mode != TransportTCP && cfg.UDPConn != nil && cfg.UDPRemoteAddr != nil && cfg.UDPCipher != nil && cfg.UDPReachable
	useTCP := cfg.Mode != TransportUDP && len(cfg.TCPConns) > 0
	if !useUDP && !useTCP {
		if len(cfg.TCPConns) > 0 {
			useTCP = true
		} else if cfg.UDPConn != nil && cfg.UDPRemoteAddr != nil && cfg.UDPCipher != nil {
			useUDP = true
		} else {
			return nil, errors.New("no active transport lane (neither UDP nor TLS TCP available)")
		}
	}

	ctrlCC := cc.NewController(cfg.InitMBps, cc.DefaultMinMBps, cfg.MaxMBps)
	if cfg.InitialRTT > 0 {
		ctrlCC.ObserveRTT(cfg.InitialRTT)
	}
	maxPar := cfg.MaxParity
	if maxPar <= 0 {
		maxPar = 8
	}
	fecAdapt := fec.NewAdaptiveController(fec.DefaultDataShards, maxPar)
	merkle := cdc.NewMerkleBuilder()

	var gsoWriter *netio.GSOBatchWriter
	if cfg.UDPConn != nil {
		gsoWriter = netio.NewGSOBatchWriter(cfg.UDPConn)
	}

	// Channels fed by the single non-blocking TLS Control reader goroutine
	casReplyCh := make(chan struct {
		batchID uint32
		states  []byte
	}, 64)
	fbCh := make(chan UDPFeedback, 128)
	ackCh := make(chan []uint32, 256)
	nackBlockCh := make(chan uint32, 128)
	finAckCh := make(chan struct {
		verified bool
		items    int
		errMsg   string
	}, 1)
	ctrlErrCh := make(chan error, 1)

	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	var ctrlWG sync.WaitGroup
	ctrlWG.Add(1)
	go func() {
		defer ctrlWG.Done()
		for {
			mType, body, err := cfg.Ctrl.Recv()
			if err != nil {
				select {
				case ctrlErrCh <- err:
				default:
				}
				return
			}
			switch mType {
			case MsgCASReply:
				bid, st, err := DecodeCASReply(body)
				if err == nil {
					select {
					case casReplyCh <- struct {
						batchID uint32
						states  []byte
					}{bid, st}:
					case <-sCtx.Done():
						return
					}
				}
			case MsgBlockAck:
				if len(body) >= 2 {
					cnt := int(binary.BigEndian.Uint16(body[0:2]))
					if len(body) >= 2+cnt*4 {
						ids := make([]uint32, cnt)
						for i := 0; i < cnt; i++ {
							ids[i] = binary.BigEndian.Uint32(body[2+i*4 : 6+i*4])
						}
						select {
						case ackCh <- ids:
						case <-sCtx.Done():
							return
						}
					}
				}
			case MsgBlockNack:
				if len(body) >= 4 {
					bIdx := binary.BigEndian.Uint32(body[0:4])
					select {
					case nackBlockCh <- bIdx:
					case <-sCtx.Done():
						return
					}
				}
			case MsgUDPFeedback:
				fb, err := DecodeUDPFeedback(body)
				if err == nil {
					select {
					case fbCh <- fb:
					case <-sCtx.Done():
						return
					}
				}
			case MsgFinAck:
				if len(body) >= 7 {
					ver := body[0] != 0
					items := int(binary.BigEndian.Uint32(body[1:5]))
					eLen := int(binary.BigEndian.Uint16(body[5:7]))
					msg := ""
					if len(body) >= 7+eLen {
						msg = string(body[7 : 7+eLen])
					}
					select {
					case finAckCh <- struct {
						verified bool
						items    int
						errMsg   string
					}{ver, items, msg}:
					default:
					}
					return
				}
			case MsgAbort:
				select {
				case ctrlErrCh <- fmt.Errorf("peer aborted transfer: %s", string(body)):
				default:
				}
				return
			}
		}
	}()

	// Shared in-flight block state + Hybrid Anti-QoS scheduler state
	var stateMu sync.Mutex
	inflightMap := make(map[uint32]*inflightBlock)
	var unackedCount atomic.Int64
	var udpDegraded atomic.Bool
	var lastUDPFeedbackNano atomic.Int64
	lastUDPFeedbackNano.Store(time.Now().UnixNano())
	var udpRateBps atomic.Uint64
	var tcpRateBps atomic.Uint64
	var wireUDPBytes atomic.Uint64
	var wireTCPBytes atomic.Uint64
	var fecParitySent atomic.Uint64
	var fecRecovered atomic.Uint32
	var udpBlocksSent atomic.Uint32
	var tcpBlocksSent atomic.Uint32
	var udpFallbackBlocks atomic.Uint32

	// Multi-Stream TLS 1.3 TCP worker pool
	type tcpJob struct {
		blockIdx    uint32
		encoding    uint8
		wirePayload []byte
	}
	tcpJobCh := make(chan tcpJob, 64)
	var tcpErr atomic.Value
	var tcpWG sync.WaitGroup
	if useTCP {
		for _, tc := range cfg.TCPConns {
			tcpWG.Add(1)
			go func(conn io.ReadWriteCloser) {
				defer tcpWG.Done()
				for {
					select {
					case <-sCtx.Done():
						return
					case job, ok := <-tcpJobCh:
						if !ok {
							return
						}
						if err := WriteTCPBlock(conn, job.blockIdx, job.encoding, job.wirePayload); err != nil {
							tcpErr.CompareAndSwap(nil, err)
							return
						}
						wireTCPBytes.Add(uint64(9 + len(job.wirePayload)))
					}
				}
			}(tc)
		}
	}

	// UDP sender goroutine (GSO batching + GF(256) RS FEC + CAR-safe pacing + RTT-scaled NACK retx!)
	type udpSliceJob struct {
		blockIdx    uint32
		encoding    uint8
		sliceIdx    uint16
		totalSlices uint16
		data        []byte
		isRetx      bool
	}
	udpJobCh := make(chan udpSliceJob, 512)
	var udpWG sync.WaitGroup
	var nextGroupID atomic.Uint32
	if useUDP {
		udpWG.Add(1)
		go func() {
			defer udpWG.Done()
			var fecBuf [][]byte
			flushFECGroup := func() {
				if len(fecBuf) == 0 {
					return
				}
				gid := nextGroupID.Add(1)
				baseParity := fecAdapt.ActiveParity()
				dCount := len(fecBuf)
				pCount := 0
				if baseParity > 0 && dCount >= 4 {
					pCount = (baseParity*dCount + fec.DefaultDataShards - 1) / fec.DefaultDataShards
					if pCount > baseParity {
						pCount = baseParity
					}
				}
				var batch [][]byte
				for i, payload := range fecBuf {
					wrapped := fec.WrapDataShard(gid, dCount, pCount, i, payload)
					sealed, _ := cfg.UDPCipher.Seal(nil, UDPFlagData, wrapped)
					batch = append(batch, sealed)
				}
				if pCount > 0 {
					if parFrames, err := fec.EncodeGroup(gid, fecBuf, pCount); err == nil {
						for _, pf := range parFrames {
							sealed, _ := cfg.UDPCipher.Seal(nil, UDPFlagParity, pf)
							batch = append(batch, sealed)
							fecParitySent.Add(1)
						}
					}
				}
				fecBuf = fecBuf[:0]

				var sendable [][]byte
				for _, pkt := range batch {
					ctrlCC.WaitPace(len(pkt))
					ctrlCC.OnPacketSent(len(pkt))
					wireUDPBytes.Add(uint64(len(pkt)))
					if cfg.Chaos != nil && cfg.Chaos.ShouldDrop() {
						continue
					}
					sendable = append(sendable, pkt)
				}
				if len(sendable) > 0 {
					_ = gsoWriter.SendBatch(sendable, cfg.UDPRemoteAddr)
				}
			}

			flushTimer := time.NewTicker(4 * time.Millisecond)
			defer flushTimer.Stop()

			for {
				select {
				case job, ok := <-udpJobCh:
					if !ok {
						flushFECGroup()
						return
					}
					// Enforce BDP Inflight Ceiling so UDP never overflows dead/policed links!
					waitStart := time.Now()
					for ctrlCC.Inflight() > ctrlCC.InflightLimit() && !udpDegraded.Load() {
						if time.Since(waitStart) > 80*time.Millisecond || sCtx.Err() != nil {
							break
						}
						time.Sleep(2 * time.Millisecond)
					}
					if udpDegraded.Load() && useTCP {
						continue // Diverted to TCP!
					}
					sliceFrame := EncodeUDPSlice(job.blockIdx, job.encoding, job.sliceIdx, job.totalSlices, time.Now().UnixNano(), job.data)
					fecBuf = append(fecBuf, sliceFrame)
					if len(fecBuf) >= fec.DefaultDataShards {
						flushFECGroup()
					}
				case <-flushTimer.C:
					if len(fecBuf) > 0 {
						flushFECGroup()
					}
				case <-sCtx.Done():
					return
				}
			}
		}()
	}

	// Feedback + ACK + Anti-QoS Stall Failover coordinator goroutine
	var fbWG sync.WaitGroup
	fbWG.Add(1)
	go func() {
		defer fbWG.Done()
		var prevDelivered uint64
		prevFBTime := time.Now()
		var tcpAckBytes uint64
		prevTCPTime := time.Now()
		stallTicker := time.NewTicker(40 * time.Millisecond)
		defer stallTicker.Stop()

		markBlockAcked := func(bIdx uint32) {
			stateMu.Lock()
			blk, ok := inflightMap[bIdx]
			var ackedTCPBytes uint64
			if ok && !blk.acked {
				blk.acked = true
				delete(inflightMap, bIdx)
				if blk.sentViaUDP {
					ctrlCC.OnBytesAckedOrLost(len(blk.wirePayload))
				} else if blk.encoding != compress.EncodingZero {
					ackedTCPBytes = uint64(9 + len(blk.wirePayload))
				}
				unackedCount.Add(-1)
			}
			stateMu.Unlock()
			if ackedTCPBytes > 0 {
				tcpAckBytes += ackedTCPBytes
				now := time.Now()
				dt := now.Sub(prevTCPTime).Seconds()
				if dt >= 0.025 {
					inst := uint64(float64(tcpAckBytes) / dt)
					old := tcpRateBps.Load()
					if old == 0 {
						tcpRateBps.Store(inst)
					} else {
						tcpRateBps.Store((old*3 + inst) / 4)
					}
					tcpAckBytes = 0
					prevTCPTime = now
				}
			}
		}

		for {
			select {
			case <-sCtx.Done():
				return

			case ids := <-ackCh:
				for _, id := range ids {
					markBlockAcked(id)
				}

			case bIdx := <-nackBlockCh:
				// Hash verification failed or receiver requested full block -> re-send over TCP if available, else UDP!
				stateMu.Lock()
				blk := inflightMap[bIdx]
				stateMu.Unlock()
				if blk != nil && !blk.acked {
					if useTCP {
						select {
						case tcpJobCh <- tcpJob{blockIdx: blk.meta.Index, encoding: blk.encoding, wirePayload: blk.wirePayload}:
						case <-sCtx.Done():
							return
						}
					} else if useUDP {
						for si := uint16(0); si < blk.totalSlices; si++ {
							lo := int(si) * UDPSlicePayloadBytes
							hi := lo + UDPSlicePayloadBytes
							if hi > len(blk.wirePayload) {
								hi = len(blk.wirePayload)
							}
							select {
							case udpJobCh <- udpSliceJob{blockIdx: blk.meta.Index, encoding: blk.encoding, sliceIdx: si, totalSlices: blk.totalSlices, data: blk.wirePayload[lo:hi], isRetx: true}:
							case <-sCtx.Done():
								return
							}
						}
					}
				}

			case fb := <-fbCh:
				now := time.Now()
				lastUDPFeedbackNano.Store(now.UnixNano())
				if fb.FECRecovered > fecRecovered.Load() {
					fecRecovered.Store(fb.FECRecovered)
				}
				for _, id := range fb.CompletedBlocks {
					markBlockAcked(id)
				}

				// Compute true WIRE-BYTE UDP delivery rate (zero CAS/Zero/Deflate inflation)
				var deliveryBps float64
				if fb.WireBytesDelivered > prevDelivered {
					dt := now.Sub(prevFBTime).Seconds()
					if dt >= 0.015 {
						dBytes := fb.WireBytesDelivered - prevDelivered
						deliveryBps = float64(dBytes) / dt
						ctrlCC.OnBytesAckedOrLost(int(dBytes))
						prevDelivered = fb.WireBytesDelivered
						prevFBTime = now
						udpRateBps.Store(uint64(deliveryBps))
					}
				}

				ctrlCC.UpdateFromTelemetry(deliveryBps, fb.NormGradient, fb.StandingQueueUs, fb.LossRatio)
				fecAdapt.ObserveLoss(fb.LossRatio)

				// Detect heavy ISP UDP QoS / blackhole: if loss > 35% and TCP is available, divert to TLS 1.3 TCP!
				if useTCP && fb.LossRatio > 0.35 && len(fb.MissingSlices) > 8 {
					udpDegraded.Store(true)
				}

				// Service missing UDP slices strictly with RTT-scaled cooldown = max(1.25*SRTT, 25ms)!
				if useUDP && !udpDegraded.Load() && len(fb.MissingSlices) > 0 {
					cooldown := ctrlCC.RetransmitCooldown()
					for _, ref := range fb.MissingSlices {
						stateMu.Lock()
						blk := inflightMap[ref.BlockIdx]
						var sliceData []byte
						var enc uint8
						var tot uint16
						if blk != nil && !blk.acked && ref.SliceIdx < blk.totalSlices {
							if now.Sub(blk.lastSliceTx[ref.SliceIdx]) >= cooldown {
								blk.lastSliceTx[ref.SliceIdx] = now
								lo := int(ref.SliceIdx) * UDPSlicePayloadBytes
								hi := lo + UDPSlicePayloadBytes
								if hi > len(blk.wirePayload) {
									hi = len(blk.wirePayload)
								}
								sliceData = blk.wirePayload[lo:hi]
								enc = blk.encoding
								tot = blk.totalSlices
							}
						}
						stateMu.Unlock()
						if sliceData != nil {
							select {
							case udpJobCh <- udpSliceJob{
								blockIdx:    ref.BlockIdx,
								encoding:    enc,
								sliceIdx:    ref.SliceIdx,
								totalSlices: tot,
								data:        sliceData,
								isRetx:      true,
							}:
							default:
							}
						}
					}
				}

			case <-stallTicker.C:
				// Anti-QoS Stall Detector: if UDP blocks sit unacked > max(4*SRTT, 350ms), seamlessly
				// fail over those blocks to Multi-Stream TLS 1.3 TCP (or re-send via UDP if UDP-only)!
				stallLimit := ctrlCC.SRTT() * 4
				if stallLimit < 350*time.Millisecond {
					stallLimit = 350 * time.Millisecond
				}
				now := time.Now()

				var stalled []*inflightBlock
				stateMu.Lock()
				for _, blk := range inflightMap {
					if !blk.acked && blk.sentViaUDP && now.Sub(blk.sentAt) >= stallLimit {
						stalled = append(stalled, blk)
					}
				}
				stateMu.Unlock()

				if len(stalled) > 0 {
					if useTCP {
						// Instant ISP UDP Blackhole / QoS Failover to Multi-Stream TLS 1.3 TCP!
						udpDegraded.Store(true)
						for _, blk := range stalled {
							stateMu.Lock()
							if !blk.acked && !blk.requeuedTCP {
								blk.requeuedTCP = true
								blk.sentAt = now
								stateMu.Unlock()
								udpFallbackBlocks.Add(1)
								tcpBlocksSent.Add(1)
								select {
								case tcpJobCh <- tcpJob{blockIdx: blk.meta.Index, encoding: blk.encoding, wirePayload: blk.wirePayload}:
								case <-sCtx.Done():
									return
								}
							} else {
								stateMu.Unlock()
							}
						}
					} else if useUDP {
						// Pure UDP mode: RTT-scaled whole-block recovery for completely lost blocks (all slices lost)
						cooldown := ctrlCC.RetransmitCooldown()
						for _, blk := range stalled {
							stateMu.Lock()
							if blk.acked || now.Sub(blk.sentAt) < cooldown {
								stateMu.Unlock()
								continue
							}
							blk.sentAt = now
							stateMu.Unlock()
							for si := uint16(0); si < blk.totalSlices; si++ {
								lo := int(si) * UDPSlicePayloadBytes
								hi := lo + UDPSlicePayloadBytes
								if hi > len(blk.wirePayload) {
									hi = len(blk.wirePayload)
								}
								select {
								case udpJobCh <- udpSliceJob{
									blockIdx:    blk.meta.Index,
									encoding:    blk.encoding,
									sliceIdx:    si,
									totalSlices: blk.totalSlices,
									data:        blk.wirePayload[lo:hi],
									isRetx:      true,
								}:
								default:
								}
							}
						}
					}
				}
			}
		}
	}()

	var cleanupOnce sync.Once
	cleanupWorkers := func() {
		cleanupOnce.Do(func() {
			sCancel()
			fbWG.Wait()
			if useTCP {
				close(tcpJobCh)
				tcpWG.Wait()
			}
			if useUDP {
				close(udpJobCh)
				udpWG.Wait()
			}
			_ = cfg.Ctrl.Close()
			ctrlWG.Wait()
		})
	}
	defer cleanupWorkers()

	// Stream Rabin CDC blocks with 0ms cold start in batches of 32 (~1.5MB per batch)
	chunker := cdc.NewChunker(storage.NewExtentReader(cfg.ReaderAt, cfg.TotalSize), cdc.DefaultMinChunk, cdc.DefaultAvgChunk, cdc.DefaultMaxChunk)
	var batchID uint32
	var totalBlocks uint32
	var dispatchIdx uint32

	chooseUDP := func() bool {
		if !useUDP || udpDegraded.Load() {
			return false
		}
		if !useTCP {
			return true
		}
		// Hybrid Auto weighting: send majority via UDP when healthy while keeping TCP warm for instant failover!
		uRate := udpRateBps.Load()
		tRate := tcpRateBps.Load()
		if uRate == 0 || tRate == 0 {
			// Alternate 3 UDP : 1 TCP during warmup to calibrate both delivery rates cleanly
			return (dispatchIdx % 4) != 3
		}
		// If UDP is severely slower than TCP (<25%), shift traffic onto TCP
		if uRate*4 < tRate {
			return (dispatchIdx % 8) == 0
		}
		// Proportional split favoring whichever lane delivers higher goodput
		udpShare := int((uRate * 10) / (uRate + tRate))
		if udpShare < 2 {
			udpShare = 2
		}
		if udpShare > 8 {
			udpShare = 8
		}
		return int(dispatchIdx%10) < udpShare
	}

	const batchCap = 32
	for {
		if err := sCtx.Err(); err != nil {
			return nil, err
		}
		if e := tcpErr.Load(); e != nil {
			return nil, e.(error)
		}
		select {
		case err := <-ctrlErrCh:
			return nil, err
		default:
		}

		// Backpressure: cap total unacked blocks in flight to bound sender RAM (~16 MB max)
		for unackedCount.Load() >= 192 {
			select {
			case err := <-ctrlErrCh:
				return nil, err
			case <-sCtx.Done():
				return nil, sCtx.Err()
			case <-time.After(5 * time.Millisecond):
			}
		}

		var metas []cdc.BlockMeta
		var payloads [][]byte
		hitEOF := false
		for len(metas) < batchCap {
			m, data, err := chunker.Next()
			if err == io.EOF {
				hitEOF = true
				break
			}
			if err != nil {
				_ = cfg.Ctrl.Send(MsgAbort, []byte(err.Error()))
				return nil, err
			}
			merkle.AddLeaf(m.Index, m.Length, m.Hash)
			metas = append(metas, m)
			payloads = append(payloads, data)
			totalBlocks++
		}
		if len(metas) == 0 {
			break
		}

		// Exact 0% false-positive interactive CAS + Persistent Crash-Resume check over TLS 1.3 Control!
		batchID++
		if err := cfg.Ctrl.Send(MsgCASQuery, EncodeCASQuery(batchID, metas)); err != nil {
			return nil, err
		}

		var states []byte
		select {
		case rep := <-casReplyCh:
			if rep.batchID != batchID || len(rep.states) != len(metas) {
				return nil, errors.New("mismatched CAS reply batch")
			}
			states = rep.states
		case err := <-ctrlErrCh:
			return nil, err
		case <-sCtx.Done():
			return nil, sCtx.Err()
		}

		for i, m := range metas {
			switch states[i] {
			case 1: // Exact Cross-Session Rabin CDC CAS Hit -> 0 wire payload bytes
				stats.CASBlocks++
				continue
			case 2: // Persistent .openfir-state Crash-Resume Hit -> 0 wire payload bytes
				stats.ResumedBlocks++
				continue
			}

			enc, wirePayload := compress.CompressBlock(payloads[i])
			switch enc {
			case compress.EncodingZero:
				stats.ZeroBlocks++
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], m.Index)
				stateMu.Lock()
				inflightMap[m.Index] = &inflightBlock{meta: m, encoding: enc, sentAt: time.Now()}
				stateMu.Unlock()
				unackedCount.Add(1)
				if err := cfg.Ctrl.Send(MsgZeroBlock, b[:]); err != nil {
					return nil, err
				}
				continue
			case compress.EncodingDeflate:
				stats.CompressedBlocks++
			default:
				stats.RawBlocks++
			}

			totalSlices := uint16((len(wirePayload) + UDPSlicePayloadBytes - 1) / UDPSlicePayloadBytes)
			if totalSlices == 0 {
				totalSlices = 1
			}
			dispatchIdx++
			sendViaUDP := chooseUDP()

			blk := &inflightBlock{
				meta:        m,
				encoding:    enc,
				wirePayload: wirePayload,
				totalSlices: totalSlices,
				sentViaUDP:  sendViaUDP,
				sentAt:      time.Now(),
				lastSliceTx: make(map[uint16]time.Time),
			}
			stateMu.Lock()
			inflightMap[m.Index] = blk
			stateMu.Unlock()
			unackedCount.Add(1)

			if sendViaUDP {
				udpBlocksSent.Add(1)
				for si := uint16(0); si < totalSlices; si++ {
					lo := int(si) * UDPSlicePayloadBytes
					hi := lo + UDPSlicePayloadBytes
					if hi > len(wirePayload) {
						hi = len(wirePayload)
					}
					select {
					case udpJobCh <- udpSliceJob{
						blockIdx:    m.Index,
						encoding:    enc,
						sliceIdx:    si,
						totalSlices: totalSlices,
						data:        wirePayload[lo:hi],
					}:
					case err := <-ctrlErrCh:
						return nil, err
					case <-sCtx.Done():
						return nil, sCtx.Err()
					}
				}
			} else {
				tcpBlocksSent.Add(1)
				select {
				case tcpJobCh <- tcpJob{blockIdx: m.Index, encoding: enc, wirePayload: wirePayload}:
				case err := <-ctrlErrCh:
					return nil, err
				case <-sCtx.Done():
					return nil, sCtx.Err()
				}
			}
		}

		if hitEOF {
			break
		}
	}

	// Wait until every dispatched block is cryptographically verified & ACKed by receiver!
	for unackedCount.Load() > 0 {
		if e := tcpErr.Load(); e != nil {
			return nil, e.(error)
		}
		select {
		case err := <-ctrlErrCh:
			return nil, err
		case <-sCtx.Done():
			return nil, sCtx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Send MsgFin carrying Streaming Binary Merkle Root!
	root := merkle.Root(totalBlocks)
	var finBody [36]byte
	binary.BigEndian.PutUint32(finBody[0:4], totalBlocks)
	copy(finBody[4:36], root[:])
	if err := cfg.Ctrl.Send(MsgFin, finBody[:]); err != nil {
		return nil, err
	}

	// Wait for Receiver's final verified MsgFinAck
	select {
	case fa := <-finAckCh:
		if !fa.verified {
			return nil, fmt.Errorf("receiver Merkle verification failed: %s", fa.errMsg)
		}
		stats.ExtractedItems = fa.items
	case err := <-ctrlErrCh:
		return nil, err
	case <-sCtx.Done():
		return nil, sCtx.Err()
	}

	cleanupWorkers()

	stats.TotalBlocks = totalBlocks
	stats.WireUDPBytes = wireUDPBytes.Load()
	stats.WireTCPBytes = wireTCPBytes.Load()
	stats.UDPBlocksSent = udpBlocksSent.Load()
	stats.TCPBlocksSent = tcpBlocksSent.Load()
	stats.UDPFallbackBlocks = udpFallbackBlocks.Load()
	stats.FECParitySent = fecParitySent.Load()
	stats.FECRecovered = fecRecovered.Load()
	stats.Elapsed = time.Since(start)
	stats.MerkleRoot = root
	return stats, nil
}

// ============================================================================
// Unified Symmetric Receiver Engine (Runs on Server for Push, Client for Pull)
// ============================================================================

type ReceiverConfig struct {
	OutDir         string
	SafeName       string
	TotalSize      int64
	IsDir          bool
	AllowOverwrite bool
	CASStore       *cdc.CASStore
	Ctrl           *CtrlChannel
	TCPConns       []io.ReadWriteCloser
	UDPRxCh        <-chan UDPInbound // Already decrypted & replay-checked by Server/Client UDP demux!
}

type UDPInbound struct {
	Flags     byte
	Seq       uint64
	WireLen   int
	RecvNano  int64
	Plain     []byte
}

type partialUDPBlock struct {
	encoding    uint8
	totalSlices uint16
	slices      [][]byte
	received    uint16
	firstSeen   time.Time
}

func RunReceiver(ctx context.Context, cfg ReceiverConfig) (*TransferStats, error) {
	start := time.Now()
	stats := &TransferStats{TotalBytes: cfg.TotalSize}

	staging, err := storage.OpenResumableStaging(cfg.OutDir, cfg.SafeName, cfg.TotalSize, cfg.IsDir)
	if err != nil {
		_ = cfg.Ctrl.Send(MsgAbort, []byte(err.Error()))
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			// Enterprise Crash-Resume: ALWAYS persist .openfir-state and keep .openfir-part on disconnect!
			staging.PauseAndClose()
		}
	}()

	merkle := cdc.NewMerkleBuilder()
	owdTracker := cc.NewNormalizedOWDTracker()
	fecDec := fec.NewDecoder(512)

	var mu sync.Mutex
	metas := make(map[uint32]cdc.BlockMeta)
	doneBlocks := make(map[uint32]bool)
	udpPartials := make(map[uint32]*partialUDPBlock)
	var pendingUDPAcks []uint32
	var committedSinceCheckpoint int

	var wireUDPBytes atomic.Uint64
	var wireTCPBytes atomic.Uint64
	var udpSeqMu sync.Mutex
	var udpRecvPkts uint64
	var udpMinSeq uint64
	var udpMaxSeq uint64
	var fecRecCount atomic.Uint32
	var casCount atomic.Uint32
	var resumedCount atomic.Uint32
	var zeroCount atomic.Uint32
	var compCount atomic.Uint32
	var rawCount atomic.Uint32

	commitBlock := func(bIdx uint32, encoding uint8, wirePayload []byte, fromUDP bool) {
		mu.Lock()
		if doneBlocks[bIdx] {
			mu.Unlock()
			return
		}
		meta, hasMeta := metas[bIdx]
		mu.Unlock()
		if !hasMeta {
			return
		}

		raw, err := compress.DecompressBlock(encoding, wirePayload, int(meta.Length))
		if err != nil || staging.WriteVerifiedBlock(meta, raw) != nil {
			// Corrupted block -> ask Sender for immediate clean retransmission!
			var nb [4]byte
			binary.BigEndian.PutUint32(nb[:], bIdx)
			_ = cfg.Ctrl.Send(MsgBlockNack, nb[:])
			return
		}
		merkle.AddLeaf(meta.Index, meta.Length, meta.Hash)

		switch encoding {
		case compress.EncodingZero:
			zeroCount.Add(1)
		case compress.EncodingDeflate:
			compCount.Add(1)
		default:
			rawCount.Add(1)
		}

		needCheckpoint := false
		mu.Lock()
		if !doneBlocks[bIdx] {
			doneBlocks[bIdx] = true
			delete(udpPartials, bIdx)
			committedSinceCheckpoint++
			if committedSinceCheckpoint >= 32 {
				committedSinceCheckpoint = 0
				needCheckpoint = true
			}
			if fromUDP {
				pendingUDPAcks = append(pendingUDPAcks, bIdx)
			}
		}
		mu.Unlock()

		if needCheckpoint {
			_ = staging.SaveCheckpoint()
		}
		if !fromUDP {
			var ab [6]byte
			binary.BigEndian.PutUint16(ab[0:2], 1)
			binary.BigEndian.PutUint32(ab[2:6], bIdx)
			_ = cfg.Ctrl.Send(MsgBlockAck, ab[:])
		}
	}

	rCtx, rCancel := context.WithCancel(ctx)
	defer rCancel()

	// 1. Multi-Stream TLS 1.3 TCP Data Lane Readers
	var dataWG sync.WaitGroup
	for _, tc := range cfg.TCPConns {
		dataWG.Add(1)
		go func(conn io.ReadWriteCloser) {
			defer dataWG.Done()
			for {
				bIdx, enc, payload, err := ReadTCPBlock(conn)
				if err != nil {
					return
				}
				wireTCPBytes.Add(uint64(9 + len(payload)))
				commitBlock(bIdx, enc, payload, false)
			}
		}(tc)
	}

	// 2. UDP Data + GF(256) RS FEC Recovery Reader
	if cfg.UDPRxCh != nil {
		ingestSlice := func(sliceFrame []byte, recvNano int64) {
			bIdx, enc, sIdx, tot, sendNano, sData, ok := DecodeUDPSlice(sliceFrame)
			if !ok {
				return
			}
			owdTracker.Observe(sendNano, recvNano)

			var assembled []byte
			var assembledEnc uint8

			mu.Lock()
			if doneBlocks[bIdx] {
				mu.Unlock()
				return
			}
			pb := udpPartials[bIdx]
			if pb == nil {
				pb = &partialUDPBlock{
					encoding:    enc,
					totalSlices: tot,
					slices:      make([][]byte, tot),
					firstSeen:   time.Now(),
				}
				udpPartials[bIdx] = pb
			}
			if pb.totalSlices == tot && pb.slices[sIdx] == nil {
				cp := make([]byte, len(sData))
				copy(cp, sData)
				pb.slices[sIdx] = cp
				pb.received++
				if pb.received == pb.totalSlices {
					totalLen := 0
					for _, s := range pb.slices {
						totalLen += len(s)
					}
					assembled = make([]byte, 0, totalLen)
					for _, s := range pb.slices {
						assembled = append(assembled, s...)
					}
					assembledEnc = pb.encoding
					delete(udpPartials, bIdx)
				}
			}
			mu.Unlock()

			if assembled != nil {
				commitBlock(bIdx, assembledEnc, assembled, true)
			}
		}

		dataWG.Add(1)
		go func() {
			defer dataWG.Done()
			for {
				select {
				case <-rCtx.Done():
					return
				case pkt, ok := <-cfg.UDPRxCh:
					if !ok {
						return
					}
					wireUDPBytes.Add(uint64(pkt.WireLen))
					udpSeqMu.Lock()
					udpRecvPkts++
					if udpMinSeq == 0 || pkt.Seq < udpMinSeq {
						udpMinSeq = pkt.Seq
					}
					if pkt.Seq > udpMaxSeq {
						udpMaxSeq = pkt.Seq
					}
					udpSeqMu.Unlock()

					switch pkt.Flags {
					case UDPFlagData:
						rawSlice, isNew, recovered, err := fecDec.PushData(pkt.Plain)
						if err != nil {
							continue
						}
						if isNew && rawSlice != nil {
							ingestSlice(rawSlice, pkt.RecvNano)
						}
						if len(recovered) > 0 {
							fecRecCount.Add(uint32(len(recovered)))
							for _, rec := range recovered {
								ingestSlice(rec, pkt.RecvNano)
							}
						}
					case UDPFlagParity:
						recovered, err := fecDec.PushParity(pkt.Plain)
						if err == nil && len(recovered) > 0 {
							fecRecCount.Add(uint32(len(recovered)))
							for _, rec := range recovered {
								ingestSlice(rec, pkt.RecvNano)
							}
						}
					}
				}
			}
		}()

		// 3. Periodic 30ms TLS 1.3 Control Telemetry & Selective Slice NACK Loop
		dataWG.Add(1)
		go func() {
			defer dataWG.Done()
			ticker := time.NewTicker(30 * time.Millisecond)
			defer ticker.Stop()
			var prevSeqMax uint64
			var prevRecv uint64
			for {
				select {
				case <-rCtx.Done():
					return
				case <-ticker.C:
					udpSeqMu.Lock()
					curRecv := udpRecvPkts
					curMin := udpMinSeq
					curMax := udpMaxSeq
					udpSeqMu.Unlock()

					var lossRatio float64
					if prevSeqMax == 0 {
						if curMin > 0 && curMax >= curMin {
							expDelta := curMax - curMin + 1
							if expDelta >= 4 && expDelta > curRecv {
								lossRatio = float64(expDelta-curRecv) / float64(expDelta)
							}
						}
					} else if curMax > prevSeqMax {
						expDelta := curMax - prevSeqMax
						gotDelta := curRecv - prevRecv
						if expDelta >= 4 && expDelta > gotDelta {
							lossRatio = float64(expDelta-gotDelta) / float64(expDelta)
						}
					}
					if curMax > 0 {
						prevSeqMax = curMax
						prevRecv = curRecv
					}

					now := time.Now()
					var acks []uint32
					var missing []SliceRef
					mu.Lock()
					if len(pendingUDPAcks) > 0 {
						acks = append(acks, pendingUDPAcks...)
						pendingUDPAcks = pendingUDPAcks[:0]
					}
					for bIdx, pb := range udpPartials {
						// Give in-flight FEC parity a brief 12ms grace window before NACKing slices
						if now.Sub(pb.firstSeen) < 12*time.Millisecond {
							continue
						}
						for si := uint16(0); si < pb.totalSlices && len(missing) < 256; si++ {
							if pb.slices[si] == nil {
								missing = append(missing, SliceRef{BlockIdx: bIdx, SliceIdx: si})
							}
						}
					}
					mu.Unlock()

					if len(acks) == 0 && len(missing) == 0 && curRecv == 0 {
						continue
					}
					grad, queueUs := owdTracker.Snapshot()
					_ = cfg.Ctrl.Send(MsgUDPFeedback, EncodeUDPFeedback(UDPFeedback{
						WireBytesDelivered: wireUDPBytes.Load(),
						NormGradient:       grad,
						StandingQueueUs:    queueUs,
						LossRatio:          lossRatio,
						FECRecovered:       fecRecCount.Load(),
						CompletedBlocks:    acks,
						MissingSlices:      missing,
					}))
				}
			}
		}()
	}

	// 4. Main TLS 1.3 Control Loop (Handles Exact CAS Query, Zero Blocks, Fin + Merkle Verification)
	var cleanupRxOnce sync.Once
	cleanupReceiver := func() {
		cleanupRxOnce.Do(func() {
			rCancel()
			for _, tc := range cfg.TCPConns {
				_ = tc.Close()
			}
			dataWG.Wait()
		})
	}
	defer cleanupReceiver()

	var finalTotalBlocks uint32
	for {
		mType, body, err := cfg.Ctrl.Recv()
		if err != nil {
			return nil, err
		}
		switch mType {
		case MsgCASQuery:
			bid, qMetas, err := DecodeCASQuery(body)
			if err != nil {
				return nil, err
			}
			states := make([]byte, len(qMetas))
			for i, m := range qMetas {
				mu.Lock()
				metas[m.Index] = m
				mu.Unlock()

				// Check 1: Persistent crash-resume from .openfir-state + verified bytes on disk!
				if staging.HasVerifiedBlock(m) {
					merkle.AddLeaf(m.Index, m.Length, m.Hash)
					mu.Lock()
					doneBlocks[m.Index] = true
					mu.Unlock()
					resumedCount.Add(1)
					states[i] = 2
					continue
				}

				// Check 2: Exact zero-false-positive Cross-Session Rabin CDC CAS hit!
				if cfg.CASStore != nil {
					if data, ok := cfg.CASStore.ReadVerifiedBlock(m.Hash, m.Length); ok {
						if err := staging.WriteVerifiedBlock(m, data); err == nil {
							merkle.AddLeaf(m.Index, m.Length, m.Hash)
							mu.Lock()
							doneBlocks[m.Index] = true
							mu.Unlock()
							casCount.Add(1)
							states[i] = 1
							continue
						}
					}
				}
				states[i] = 0
			}
			if err := cfg.Ctrl.Send(MsgCASReply, EncodeCASReply(bid, states)); err != nil {
				return nil, err
			}

		case MsgZeroBlock:
			if len(body) >= 4 {
				bIdx := binary.BigEndian.Uint32(body[0:4])
				commitBlock(bIdx, compress.EncodingZero, nil, false)
			}

		case MsgFin:
			if len(body) < 36 {
				return nil, errors.New("malformed MsgFin")
			}
			finalTotalBlocks = binary.BigEndian.Uint32(body[0:4])
			var expectedRoot [32]byte
			copy(expectedRoot[:], body[4:36])

			// Verify all blocks committed & Streaming Binary Merkle Root matches bit-for-bit!
			mu.Lock()
			gotBlocks := uint32(len(doneBlocks))
			mu.Unlock()

			actualRoot := merkle.Root(finalTotalBlocks)
			verified := gotBlocks == finalTotalBlocks && actualRoot == expectedRoot
			errMsg := ""
			extracted := 0
			if !verified {
				errMsg = fmt.Sprintf("merkle/count mismatch: got %d/%d blocks", gotBlocks, finalTotalBlocks)
			} else {
				items, cErr := staging.Commit(cfg.AllowOverwrite, cfg.CASStore)
				if cErr != nil {
					verified = false
					errMsg = cErr.Error()
				} else {
					committed = true
					extracted = items
				}
			}

			eb := []byte(errMsg)
			ack := make([]byte, 7+len(eb))
			if verified {
				ack[0] = 1
			}
			binary.BigEndian.PutUint32(ack[1:5], uint32(extracted))
			binary.BigEndian.PutUint16(ack[5:7], uint16(len(eb)))
			copy(ack[7:], eb)
			_ = cfg.Ctrl.Send(MsgFinAck, ack)

			cleanupReceiver()

			if !verified {
				return nil, errors.New(errMsg)
			}
			stats.TotalBlocks = finalTotalBlocks
			stats.WireUDPBytes = wireUDPBytes.Load()
			stats.WireTCPBytes = wireTCPBytes.Load()
			stats.CASBlocks = casCount.Load()
			stats.ResumedBlocks = resumedCount.Load()
			stats.ZeroBlocks = zeroCount.Load()
			stats.CompressedBlocks = compCount.Load()
			stats.RawBlocks = rawCount.Load()
			stats.FECRecovered = fecRecCount.Load()
			stats.ExtractedItems = extracted
			stats.Elapsed = time.Since(start)
			stats.MerkleRoot = actualRoot
			return stats, nil

		case MsgAbort:
			return nil, fmt.Errorf("sender aborted transfer: %s", string(body))
		}
	}
}
