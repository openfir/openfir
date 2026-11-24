// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"time"

	"github.com/openfir/openfir/internal/cdc"
)

// TransportMode selects the Hybrid data-plane strategy.
type TransportMode string

const (
	TransportAuto TransportMode = "auto" // Hybrid UDP (GSO+GF256 FEC) + Multi-Stream TLS 1.3 TCP (anti-QoS failover)
	TransportUDP  TransportMode = "udp"  // Pure UDP data plane (with TLS 1.3 control plane)
	TransportTCP  TransportMode = "tcp"  // Pure Multi-Stream TLS 1.3 TCP data plane (100% firewall/QoS proof)
)

const (
	// TLS 1.3 connection multiplexer roles (first byte after TLS handshake)
	ConnKindControl byte = 0x01
	ConnKindTCPData byte = 0x02

	// Transfer direction modes
	ModePush byte = 0x01 // Client -> Server
	ModePull byte = 0x02 // Server -> Client

	// TLS 1.3 Control Channel message types
	MsgTransferReq  byte = 0x10 // Client -> Server: Mode, IsDir, TotalSize, Name
	MsgTransferMeta byte = 0x11 // Server -> Client: Status, IsDir, TotalSize, ErrMsg
	MsgCASQuery     byte = 0x12 // Sender -> Receiver: batch of Rabin CDC BlockMeta (Index, Offset, Len, 32B Hash)
	MsgCASReply     byte = 0x13 // Receiver -> Sender: BatchID + exact bitmask of blocks already on disk/CAS
	MsgZeroBlock    byte = 0x14 // Sender -> Receiver: BlockIdx (0 wire payload bytes!)
	MsgBlockAck     byte = 0x15 // Receiver -> Sender: list of verified committed BlockIdx
	MsgBlockNack    byte = 0x16 // Receiver -> Sender: block failed hash/stalled -> retransmit whole block
	MsgUDPFeedback  byte = 0x17 // Receiver -> Sender: wireBytes, normGrad, queueUs, lossRatio, completedBlocks, missingSlices
	MsgFin          byte = 0x18 // Sender -> Receiver: TotalBlocks + 32B Streaming MerkleRoot
	MsgFinAck       byte = 0x19 // Receiver -> Sender: Verified(1B) + ExtractedItems(4B) + ErrMsg
	MsgAbort        byte = 0x1A // Bidirectional fatal error abort

	// OpenFIR v1 UDP header flags (wire[4])
	UDPFlagProbe    byte = 0x01
	UDPFlagProbeAck byte = 0x02
	UDPFlagData     byte = 0x03
	UDPFlagParity   byte = 0x04

	// UDP slice sizing: safe across IPv6/PPPoE/VPN WANs without IP fragmentation
	UDPSlicePayloadBytes = 1200
	UDPSliceHeaderBytes  = 17 // [4B BlockIdx][1B Encoding][2B SliceIdx][2B TotalSlices][8B SendNano]
	MaxCtrlMsgBytes      = 4 * 1024 * 1024
	MaxBlockWireBytes    = 2 * 1024 * 1024
)

// ============================================================================
// Thread-Safe Framed TLS 1.3 Control Channel
// ============================================================================

type CtrlChannel struct {
	rw      io.ReadWriteCloser
	writeMu sync.Mutex
}

func NewCtrlChannel(rw io.ReadWriteCloser) *CtrlChannel {
	return &CtrlChannel{rw: rw}
}

func (c *CtrlChannel) Send(msgType byte, body []byte) error {
	var hdr [5]byte
	hdr[0] = msgType
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(body)))

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.rw.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		_, err := c.rw.Write(body)
		return err
	}
	return nil
}

func (c *CtrlChannel) Recv() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.rw, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > MaxCtrlMsgBytes {
		return 0, nil, errors.New("control message exceeds size cap")
	}
	var body []byte
	if n > 0 {
		body = make([]byte, n)
		if _, err := io.ReadFull(c.rw, body); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], body, nil
}

func (c *CtrlChannel) Close() error { return c.rw.Close() }

// ============================================================================
// Multi-Stream TLS 1.3 TCP Data Lane Block Framing
// ============================================================================

// WriteTCPBlock frames one complete CDC block onto a TLS 1.3 TCP data lane:
// [4B BlockIdx][1B Encoding][4B WireLen][WirePayload]
func WriteTCPBlock(w io.Writer, blockIdx uint32, encoding uint8, wirePayload []byte) error {
	var hdr [9]byte
	binary.BigEndian.PutUint32(hdr[0:4], blockIdx)
	hdr[4] = encoding
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(wirePayload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(wirePayload) > 0 {
		_, err := w.Write(wirePayload)
		return err
	}
	return nil
}

func ReadTCPBlock(r io.Reader) (blockIdx uint32, encoding uint8, wirePayload []byte, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	blockIdx = binary.BigEndian.Uint32(hdr[0:4])
	encoding = hdr[4]
	wLen := binary.BigEndian.Uint32(hdr[5:9])
	if wLen > MaxBlockWireBytes {
		return 0, 0, nil, errors.New("tcp block exceeds size cap")
	}
	if wLen > 0 {
		wirePayload = make([]byte, wLen)
		if _, err = io.ReadFull(r, wirePayload); err != nil {
			return 0, 0, nil, err
		}
	}
	return blockIdx, encoding, wirePayload, nil
}

// ============================================================================
// Control Message Codecs
// ============================================================================

type TransferReq struct {
	Mode      byte
	IsDir     bool
	TotalSize int64
	Name      string
}

func EncodeTransferReq(r TransferReq) []byte {
	nb := []byte(r.Name)
	b := make([]byte, 12+len(nb))
	b[0] = r.Mode
	if r.IsDir {
		b[1] = 1
	}
	binary.BigEndian.PutUint64(b[2:10], uint64(r.TotalSize))
	binary.BigEndian.PutUint16(b[10:12], uint16(len(nb)))
	copy(b[12:], nb)
	return b
}

func DecodeTransferReq(b []byte) (TransferReq, error) {
	if len(b) < 12 {
		return TransferReq{}, errors.New("malformed transfer req")
	}
	nLen := int(binary.BigEndian.Uint16(b[10:12]))
	if len(b) < 12+nLen {
		return TransferReq{}, errors.New("truncated transfer req name")
	}
	return TransferReq{
		Mode:      b[0],
		IsDir:     b[1] != 0,
		TotalSize: int64(binary.BigEndian.Uint64(b[2:10])),
		Name:      string(b[12 : 12+nLen]),
	}, nil
}

type TransferMeta struct {
	OK        bool
	IsDir     bool
	TotalSize int64
	ErrMsg    string
}

func EncodeTransferMeta(m TransferMeta) []byte {
	eb := []byte(m.ErrMsg)
	b := make([]byte, 12+len(eb))
	if m.OK {
		b[0] = 1
	}
	if m.IsDir {
		b[1] = 1
	}
	binary.BigEndian.PutUint64(b[2:10], uint64(m.TotalSize))
	binary.BigEndian.PutUint16(b[10:12], uint16(len(eb)))
	copy(b[12:], eb)
	return b
}

func DecodeTransferMeta(b []byte) (TransferMeta, error) {
	if len(b) < 12 {
		return TransferMeta{}, errors.New("malformed transfer meta")
	}
	eLen := int(binary.BigEndian.Uint16(b[10:12]))
	if len(b) < 12+eLen {
		return TransferMeta{}, errors.New("truncated transfer meta")
	}
	return TransferMeta{
		OK:        b[0] != 0,
		IsDir:     b[1] != 0,
		TotalSize: int64(binary.BigEndian.Uint64(b[2:10])),
		ErrMsg:    string(b[12 : 12+eLen]),
	}, nil
}

func EncodeCASQuery(batchID uint32, metas []cdc.BlockMeta) []byte {
	const recSize = 4 + 8 + 4 + 32 // 48B
	b := make([]byte, 6+len(metas)*recSize)
	binary.BigEndian.PutUint32(b[0:4], batchID)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(metas)))
	pos := 6
	for _, m := range metas {
		binary.BigEndian.PutUint32(b[pos:pos+4], m.Index)
		binary.BigEndian.PutUint64(b[pos+4:pos+12], uint64(m.Offset))
		binary.BigEndian.PutUint32(b[pos+12:pos+16], m.Length)
		copy(b[pos+16:pos+48], m.Hash[:])
		pos += recSize
	}
	return b
}

func DecodeCASQuery(b []byte) (uint32, []cdc.BlockMeta, error) {
	if len(b) < 6 {
		return 0, nil, errors.New("malformed CAS query")
	}
	batchID := binary.BigEndian.Uint32(b[0:4])
	cnt := int(binary.BigEndian.Uint16(b[4:6]))
	const recSize = 48
	if len(b) < 6+cnt*recSize {
		return 0, nil, errors.New("truncated CAS query")
	}
	out := make([]cdc.BlockMeta, cnt)
	pos := 6
	for i := 0; i < cnt; i++ {
		out[i].Index = binary.BigEndian.Uint32(b[pos : pos+4])
		out[i].Offset = int64(binary.BigEndian.Uint64(b[pos+4 : pos+12]))
		out[i].Length = binary.BigEndian.Uint32(b[pos+12 : pos+16])
		copy(out[i].Hash[:], b[pos+16:pos+48])
		pos += recSize
	}
	return batchID, out, nil
}

// CASReply bit flags per queried block: 0 = need transfer, 1 = CAS hit, 2 = Resumed from staging
func EncodeCASReply(batchID uint32, states []byte) []byte {
	b := make([]byte, 6+len(states))
	binary.BigEndian.PutUint32(b[0:4], batchID)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(states)))
	copy(b[6:], states)
	return b
}

func DecodeCASReply(b []byte) (uint32, []byte, error) {
	if len(b) < 6 {
		return 0, nil, errors.New("malformed CAS reply")
	}
	batchID := binary.BigEndian.Uint32(b[0:4])
	cnt := int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 6+cnt {
		return 0, nil, errors.New("truncated CAS reply")
	}
	out := make([]byte, cnt)
	copy(out, b[6:6+cnt])
	return batchID, out, nil
}

type SliceRef struct {
	BlockIdx uint32
	SliceIdx uint16
}

type UDPFeedback struct {
	WireBytesDelivered uint64
	NormGradient       float64
	StandingQueueUs    int64
	LossRatio          float64
	FECRecovered       uint32
	CompletedBlocks    []uint32
	MissingSlices      []SliceRef
}

func EncodeUDPFeedback(fb UDPFeedback) []byte {
	nDone := len(fb.CompletedBlocks)
	nMiss := len(fb.MissingSlices)
	if nMiss > 256 {
		nMiss = 256
	}
	b := make([]byte, 40+nDone*4+nMiss*6)
	binary.BigEndian.PutUint64(b[0:8], fb.WireBytesDelivered)
	binary.BigEndian.PutUint64(b[8:16], math.Float64bits(fb.NormGradient))
	binary.BigEndian.PutUint64(b[16:24], uint64(fb.StandingQueueUs))
	binary.BigEndian.PutUint64(b[24:32], math.Float64bits(fb.LossRatio))
	binary.BigEndian.PutUint32(b[32:36], fb.FECRecovered)
	binary.BigEndian.PutUint16(b[36:38], uint16(nDone))
	binary.BigEndian.PutUint16(b[38:40], uint16(nMiss))
	pos := 40
	for i := 0; i < nDone; i++ {
		binary.BigEndian.PutUint32(b[pos:pos+4], fb.CompletedBlocks[i])
		pos += 4
	}
	for i := 0; i < nMiss; i++ {
		binary.BigEndian.PutUint32(b[pos:pos+4], fb.MissingSlices[i].BlockIdx)
		binary.BigEndian.PutUint16(b[pos+4:pos+6], fb.MissingSlices[i].SliceIdx)
		pos += 6
	}
	return b
}

func DecodeUDPFeedback(b []byte) (UDPFeedback, error) {
	if len(b) < 40 {
		return UDPFeedback{}, errors.New("malformed udp feedback")
	}
	nDone := int(binary.BigEndian.Uint16(b[36:38]))
	nMiss := int(binary.BigEndian.Uint16(b[38:40]))
	if len(b) < 40+nDone*4+nMiss*6 {
		return UDPFeedback{}, errors.New("truncated udp feedback")
	}
	fb := UDPFeedback{
		WireBytesDelivered: binary.BigEndian.Uint64(b[0:8]),
		NormGradient:       math.Float64frombits(binary.BigEndian.Uint64(b[8:16])),
		StandingQueueUs:    int64(binary.BigEndian.Uint64(b[16:24])),
		LossRatio:          math.Float64frombits(binary.BigEndian.Uint64(b[24:32])),
		FECRecovered:       binary.BigEndian.Uint32(b[32:36]),
		CompletedBlocks:    make([]uint32, nDone),
		MissingSlices:      make([]SliceRef, nMiss),
	}
	pos := 40
	for i := 0; i < nDone; i++ {
		fb.CompletedBlocks[i] = binary.BigEndian.Uint32(b[pos : pos+4])
		pos += 4
	}
	for i := 0; i < nMiss; i++ {
		fb.MissingSlices[i] = SliceRef{
			BlockIdx: binary.BigEndian.Uint32(b[pos : pos+4]),
			SliceIdx: binary.BigEndian.Uint16(b[pos+4 : pos+6]),
		}
		pos += 6
	}
	return fb, nil
}

// EncodeUDPSlice packs one UDP slice payload before FEC/AEAD:
// [4B BlockIdx][1B Encoding][2B SliceIdx][2B TotalSlices][8B SendNano][Data]
func EncodeUDPSlice(blockIdx uint32, encoding uint8, sliceIdx, totalSlices uint16, sendNano int64, data []byte) []byte {
	b := make([]byte, UDPSliceHeaderBytes+len(data))
	binary.BigEndian.PutUint32(b[0:4], blockIdx)
	b[4] = encoding
	binary.BigEndian.PutUint16(b[5:7], sliceIdx)
	binary.BigEndian.PutUint16(b[7:9], totalSlices)
	binary.BigEndian.PutUint64(b[9:17], uint64(sendNano))
	copy(b[17:], data)
	return b
}

func DecodeUDPSlice(b []byte) (blockIdx uint32, encoding uint8, sliceIdx, totalSlices uint16, sendNano int64, data []byte, ok bool) {
	if len(b) < UDPSliceHeaderBytes {
		return 0, 0, 0, 0, 0, nil, false
	}
	blockIdx = binary.BigEndian.Uint32(b[0:4])
	encoding = b[4]
	sliceIdx = binary.BigEndian.Uint16(b[5:7])
	totalSlices = binary.BigEndian.Uint16(b[7:9])
	sendNano = int64(binary.BigEndian.Uint64(b[9:17]))
	data = b[17:]
	if totalSlices == 0 || sliceIdx >= totalSlices {
		return 0, 0, 0, 0, 0, nil, false
	}
	return blockIdx, encoding, sliceIdx, totalSlices, sendNano, data, true
}

// ============================================================================
// Gilbert-Elliott Burst-Loss & UDP-Blackhole Simulator (for Chaos Tests & QoS Verification)
// ============================================================================

type UDPChaos struct {
	mu             sync.Mutex
	LossRate       float64 // 0.0 .. 1.0 (1.0 simulates total ISP UDP blackhole!)
	BurstLen       int
	BlackholeAfter uint64 // If >0, automatically engage 100% UDP blackhole after N passed packets
	ExtraDelay     time.Duration
	inBurst        int
	passedCount    uint64
	DroppedCount   uint64
}

func (c *UDPChaos) Dropped() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.DroppedCount
}

func (c *UDPChaos) SetBlackhole(blackhole bool) {
	c.mu.Lock()
	if blackhole {
		c.LossRate = 1.0
	} else {
		c.LossRate = 0.0
		c.inBurst = 0
	}
	c.mu.Unlock()
}

func (c *UDPChaos) ShouldDrop() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.BlackholeAfter > 0 && c.passedCount >= c.BlackholeAfter {
		c.LossRate = 1.0
	}
	if c.LossRate <= 0 {
		c.passedCount++
		return false
	}
	if c.LossRate >= 1.0 {
		c.DroppedCount++
		return true
	}
	if c.inBurst > 0 {
		c.inBurst--
		c.DroppedCount++
		return true
	}
	bl := c.BurstLen
	if bl < 1 {
		bl = 1
	}
	var rb [4]byte
	_, _ = io.ReadFull(rand.Reader, rb[:])
	r := float64(binary.BigEndian.Uint32(rb[:])&0xFFFFFF) / float64(0x1000000)
	if r < c.LossRate/float64(bl) {
		c.inBurst = bl - 1
		c.DroppedCount++
		return true
	}
	c.passedCount++
	return false
}
