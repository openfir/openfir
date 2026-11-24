// SPDX-License-Identifier: Apache-2.0

package fec

import (
	"encoding/binary"
	"errors"
	"math"
	"sync"
)

const (
	DefaultDataShards = 16
	MaxDataShards     = 32
	MaxParityShards   = 16
	MaxShardBytes     = 1400

	// Standard primitive polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
	gfPrimitivePoly = 0x11D
)

var ErrInvalidShard = errors.New("invalid FEC shard")

// ============================================================================
// Clean-Room GF(2^8) Arithmetic & Systematic Cauchy Reed-Solomon (1960 / 1995)
// Zero third-party dependencies, 100% public-domain textbook finite-field math!
// ============================================================================

var (
	gfExp      [512]byte
	gfLog      [256]byte
	gfInv      [256]byte
	gfMulTable [256][256]byte // 64 KiB L1/L2-hot byte multiplication lookup table
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfExp[i+255] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if (x & 0x100) != 0 {
			x ^= gfPrimitivePoly
		}
	}
	gfExp[510] = gfExp[0]
	gfExp[511] = gfExp[1]

	for a := 1; a < 256; a++ {
		gfInv[a] = gfExp[255-int(gfLog[a])]
		for b := 1; b < 256; b++ {
			gfMulTable[a][b] = gfExp[int(gfLog[a])+int(gfLog[b])]
		}
	}
}

// gfMulAddSlice computes dst[i] ^= coeff * src[i] in GF(2^8) with 8-byte loop unrolling.
func gfMulAddSlice(dst, src []byte, coeff byte) {
	if coeff == 0 {
		return
	}
	n := len(src)
	if len(dst) < n {
		n = len(dst)
	}
	if coeff == 1 {
		i := 0
		for ; i+8 <= n; i += 8 {
			dst[i] ^= src[i]
			dst[i+1] ^= src[i+1]
			dst[i+2] ^= src[i+2]
			dst[i+3] ^= src[i+3]
			dst[i+4] ^= src[i+4]
			dst[i+5] ^= src[i+5]
			dst[i+6] ^= src[i+6]
			dst[i+7] ^= src[i+7]
		}
		for ; i < n; i++ {
			dst[i] ^= src[i]
		}
		return
	}
	tbl := &gfMulTable[coeff]
	i := 0
	for ; i+8 <= n; i += 8 {
		dst[i] ^= tbl[src[i]]
		dst[i+1] ^= tbl[src[i+1]]
		dst[i+2] ^= tbl[src[i+2]]
		dst[i+3] ^= tbl[src[i+3]]
		dst[i+4] ^= tbl[src[i+4]]
		dst[i+5] ^= tbl[src[i+5]]
		dst[i+6] ^= tbl[src[i+6]]
		dst[i+7] ^= tbl[src[i+7]]
	}
	for ; i < n; i++ {
		dst[i] ^= tbl[src[i]]
	}
}

// cauchyParityRow returns the deterministic systematic Cauchy parity row r in [0..P-1]
// for D data shards: C[r][c] = 1 / (r XOR (P + c)) in GF(2^8).
// Every square submatrix of a Cauchy matrix is mathematically guaranteed invertible!
func cauchyCoeff(pCount, parityRow, dataCol int) byte {
	return gfInv[byte(parityRow)^byte(pCount+dataCol)]
}

// invertGF256Matrix inverts an n x n matrix over GF(2^8) via Gauss-Jordan elimination.
func invertGF256Matrix(mat [][]byte) ([][]byte, bool) {
	n := len(mat)
	aug := make([][]byte, n)
	for i := 0; i < n; i++ {
		row := make([]byte, 2*n)
		copy(row[:n], mat[i])
		row[n+i] = 1
		aug[i] = row
	}

	for col := 0; col < n; col++ {
		pivot := -1
		for r := col; r < n; r++ {
			if aug[r][col] != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return nil, false
		}
		if pivot != col {
			aug[col], aug[pivot] = aug[pivot], aug[col]
		}

		// Scale pivot row so aug[col][col] == 1
		invP := gfInv[aug[col][col]]
		if invP != 1 {
			tbl := &gfMulTable[invP]
			row := aug[col]
			for j := col; j < 2*n; j++ {
				row[j] = tbl[row[j]]
			}
		}

		// Eliminate column across all other rows
		pRow := aug[col]
		for r := 0; r < n; r++ {
			if r == col {
				continue
			}
			factor := aug[r][col]
			if factor == 0 {
				continue
			}
			tbl := &gfMulTable[factor]
			row := aug[r]
			for j := col; j < 2*n; j++ {
				row[j] ^= tbl[pRow[j]]
			}
		}
	}

	inv := make([][]byte, n)
	for i := 0; i < n; i++ {
		inv[i] = aug[i][n:]
	}
	return inv, true
}

// reconstructDataGF256 recovers all missing data shards (indices 0..dCount-1) in-place inside work
// using any dCount present shards across data + Cauchy parity rows.
func reconstructDataGF256(dCount, pCount, shardLen int, work [][]byte) bool {
	presentIdx := make([]int, 0, dCount)
	missingData := make([]int, 0, pCount)
	for i := 0; i < dCount; i++ {
		if work[i] != nil {
			presentIdx = append(presentIdx, i)
		} else {
			missingData = append(missingData, i)
		}
	}
	if len(missingData) == 0 {
		return true
	}
	for i := dCount; i < dCount+pCount && len(presentIdx) < dCount; i++ {
		if work[i] != nil {
			presentIdx = append(presentIdx, i)
		}
	}
	if len(presentIdx) < dCount {
		return false
	}

	// Assemble the dCount x dCount submatrix of systematic generator G for the selected rows.
	sub := make([][]byte, dCount)
	for r, idx := range presentIdx {
		row := make([]byte, dCount)
		if idx < dCount {
			row[idx] = 1
		} else {
			pRow := idx - dCount
			for c := 0; c < dCount; c++ {
				row[c] = cauchyCoeff(pCount, pRow, c)
			}
		}
		sub[r] = row
	}

	inv, ok := invertGF256Matrix(sub)
	if !ok {
		return false
	}

	// Reconstruct only the missing data shards using their exact inverse rows.
	for _, miss := range missingData {
		out := make([]byte, shardLen)
		invRow := inv[miss]
		for j, srcIdx := range presentIdx {
			gfMulAddSlice(out, work[srcIdx], invRow[j])
		}
		work[miss] = out
	}
	return true
}

// ============================================================================
// Adaptive Zero-Overhead-At-Zero-Loss Parity Controller & Streaming Decoder
// ============================================================================

// AdaptiveController scales GF(256) Reed-Solomon parity smoothly from 0% (zero loss = ZERO overhead!)
// up to maxParity based on continuous EWMA UDP loss telemetry.
type AdaptiveController struct {
	mu           sync.Mutex
	dataShards   int
	maxParity    int
	ewmaLoss     float64
	activeParity int
}

func NewAdaptiveController(dataShards, maxParity int) *AdaptiveController {
	if dataShards < 2 {
		dataShards = DefaultDataShards
	}
	if dataShards > MaxDataShards {
		dataShards = MaxDataShards
	}
	if maxParity < 0 {
		maxParity = 0
	}
	if maxParity > MaxParityShards {
		maxParity = MaxParityShards
	}
	return &AdaptiveController{
		dataShards: dataShards,
		maxParity:  maxParity,
	}
}

// ObserveLoss updates the EWMA UDP loss rate in [0.0, 1.0] and recomputes exact parity count.
// At 0% loss (< 0.2% noise floor), activeParity strictly drops to 0 (100% net goodput!).
func (a *AdaptiveController) ObserveLoss(sampleLoss float64) int {
	if sampleLoss < 0 {
		sampleLoss = 0
	}
	if sampleLoss > 0.6 {
		sampleLoss = 0.6
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if sampleLoss > a.ewmaLoss {
		// Fast attack on loss spike
		a.ewmaLoss = a.ewmaLoss*0.5 + sampleLoss*0.5
	} else {
		// Smooth decay when link cleans up
		a.ewmaLoss = a.ewmaLoss*0.8 + sampleLoss*0.2
	}
	if a.ewmaLoss < 0.002 || a.maxParity == 0 {
		a.activeParity = 0
		return 0
	}
	// Systematic RS needs P >= loss * (D + P) plus burst margin for multi-packet bursts
	ratio := a.ewmaLoss / (1.0 - a.ewmaLoss)
	need := int(math.Ceil(1.5 * ratio * float64(a.dataShards)))
	if a.ewmaLoss >= 0.05 {
		need++ // +1 burst margin to absorb contiguous 3-4 packet carrier bursts in 1 solve
	}
	if need < 1 {
		need = 1
	}
	if need > a.maxParity {
		need = a.maxParity
	}
	a.activeParity = need
	return need
}

func (a *AdaptiveController) ActiveParity() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.activeParity
}

// EncodeGroup encodes dataPayloads (each <= MaxShardBytes) into systematic Cauchy GF(256) RS parity shards.
// When parityShards == 0, returns nil with ZERO CPU and ZERO bandwidth overhead!
// Each data shard is internally length-prefixed ([2B payloadLen][payload][zero-pad]) so arbitrary
// variable-length packets reconstruct losslessly with exact byte lengths.
func EncodeGroup(groupID uint32, dataPayloads [][]byte, parityShards int) ([][]byte, error) {
	D := len(dataPayloads)
	if D == 0 || parityShards <= 0 {
		return nil, nil
	}
	if D > MaxDataShards || parityShards > MaxParityShards {
		return nil, ErrInvalidShard
	}

	maxLen := 0
	for _, p := range dataPayloads {
		if len(p) > MaxShardBytes {
			return nil, ErrInvalidShard
		}
		if 2+len(p) > maxLen {
			maxLen = 2 + len(p)
		}
	}
	if maxLen == 0 {
		return nil, nil
	}

	paddedData := make([][]byte, D)
	for i := 0; i < D; i++ {
		s := make([]byte, maxLen)
		binary.BigEndian.PutUint16(s[0:2], uint16(len(dataPayloads[i])))
		copy(s[2:], dataPayloads[i])
		paddedData[i] = s
	}

	// Parity wire frame: [4B GroupID][1B DataShards][1B ParityShards][1B ShardIdx][Payload]
	out := make([][]byte, parityShards)
	for r := 0; r < parityShards; r++ {
		frame := make([]byte, 7+maxLen)
		binary.BigEndian.PutUint32(frame[0:4], groupID)
		frame[4] = byte(D)
		frame[5] = byte(parityShards)
		frame[6] = byte(D + r)
		pPayload := frame[7:]
		for c := 0; c < D; c++ {
			gfMulAddSlice(pPayload, paddedData[c], cauchyCoeff(parityShards, r, c))
		}
		out[r] = frame
	}
	return out, nil
}

// WrapDataShard wraps a raw payload with its 7-byte FEC group header for transmission over UDP.
func WrapDataShard(groupID uint32, dCount, pCount, shardIdx int, payload []byte) []byte {
	frame := make([]byte, 7+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], groupID)
	frame[4] = byte(dCount)
	frame[5] = byte(pCount)
	frame[6] = byte(shardIdx)
	copy(frame[7:], payload)
	return frame
}

type rxGroup struct {
	dCount    int
	pCount    int
	shardLen  int
	shards    [][]byte
	present   uint64
	recvCount int
	completed bool
}

// Decoder performs bounded-memory Cauchy GF(256) Reed-Solomon recovery over out-of-order UDP streams.
type Decoder struct {
	mu       sync.Mutex
	groups   map[uint32]*rxGroup
	order    []uint32
	maxSlots int
}

func NewDecoder(maxGroups int) *Decoder {
	if maxGroups < 16 {
		maxGroups = 256
	}
	return &Decoder{
		groups:   make(map[uint32]*rxGroup, maxGroups),
		maxSlots: maxGroups,
	}
}

func (d *Decoder) getOrCreateLocked(groupID uint32, dCount, pCount int) (*rxGroup, error) {
	if dCount < 1 || dCount > MaxDataShards || pCount < 0 || pCount > MaxParityShards {
		return nil, ErrInvalidShard
	}
	if g, ok := d.groups[groupID]; ok {
		if g.dCount != dCount || (pCount > 0 && g.pCount > 0 && g.pCount != pCount) {
			return nil, ErrInvalidShard
		}
		if g.pCount == 0 && pCount > 0 {
			g.pCount = pCount
			newShards := make([][]byte, dCount+pCount)
			copy(newShards, g.shards)
			g.shards = newShards
		}
		return g, nil
	}
	if len(d.order) >= d.maxSlots {
		evict := d.order[0]
		d.order = d.order[1:]
		delete(d.groups, evict)
	}
	g := &rxGroup{
		dCount: dCount,
		pCount: pCount,
		shards: make([][]byte, dCount+pCount),
	}
	d.groups[groupID] = g
	d.order = append(d.order, groupID)
	return g, nil
}

// PushData ingests one data shard frame ([7B hdr][payload]).
// Returns (rawPayload, isNew, recoveredPayloads, err).
func (d *Decoder) PushData(frame []byte) (payload []byte, isNew bool, recovered [][]byte, err error) {
	if len(frame) < 8 {
		return nil, false, nil, ErrInvalidShard
	}
	groupID := binary.BigEndian.Uint32(frame[0:4])
	dCount := int(frame[4])
	pCount := int(frame[5])
	idx := int(frame[6])
	raw := frame[7:]
	if idx < 0 || idx >= dCount || len(raw) > MaxShardBytes {
		return nil, false, nil, ErrInvalidShard
	}

	// Fast path: 0 parity shards -> pure pass-through, ZERO RS allocation!
	if pCount == 0 {
		cp := make([]byte, len(raw))
		copy(cp, raw)
		return cp, true, nil, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	g, err := d.getOrCreateLocked(groupID, dCount, pCount)
	if err != nil {
		return nil, false, nil, err
	}
	bit := uint64(1) << uint(idx)
	if (g.present & bit) != 0 {
		return nil, false, nil, nil
	}

	cp := make([]byte, len(raw))
	copy(cp, raw)

	if !g.completed {
		enc := make([]byte, 2+len(raw))
		binary.BigEndian.PutUint16(enc[0:2], uint16(len(raw)))
		copy(enc[2:], raw)
		if len(enc) > g.shardLen {
			g.shardLen = len(enc)
		}
		g.shards[idx] = enc
		g.present |= bit
		g.recvCount++
		rec := d.tryReconstructLocked(g)
		return cp, true, rec, nil
	}
	return cp, false, nil, nil
}

// PushParity ingests one parity shard frame ([7B hdr][rsParityBytes]) and returns any recovered data payloads.
func (d *Decoder) PushParity(frame []byte) ([][]byte, error) {
	if len(frame) < 9 {
		return nil, ErrInvalidShard
	}
	groupID := binary.BigEndian.Uint32(frame[0:4])
	dCount := int(frame[4])
	pCount := int(frame[5])
	idx := int(frame[6])
	pBytes := frame[7:]
	if pCount <= 0 || idx < dCount || idx >= dCount+pCount {
		return nil, ErrInvalidShard
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	g, err := d.getOrCreateLocked(groupID, dCount, pCount)
	if err != nil {
		return nil, err
	}
	if g.completed {
		return nil, nil
	}
	bit := uint64(1) << uint(idx)
	if (g.present & bit) != 0 {
		return nil, nil
	}

	cp := make([]byte, len(pBytes))
	copy(cp, pBytes)
	if len(cp) > g.shardLen {
		g.shardLen = len(cp)
	}
	g.shards[idx] = cp
	g.present |= bit
	g.recvCount++
	return d.tryReconstructLocked(g), nil
}

func (d *Decoder) tryReconstructLocked(g *rxGroup) [][]byte {
	if g.completed || g.pCount == 0 || g.recvCount < g.dCount || g.shardLen < 2 {
		return nil
	}
	dataMask := (uint64(1) << uint(g.dCount)) - 1
	if (g.present & dataMask) == dataMask {
		g.completed = true
		g.shards = nil
		return nil
	}

	// Pad all present shards uniformly to g.shardLen before GF(256) Gaussian solve
	work := make([][]byte, g.dCount+g.pCount)
	for i := 0; i < len(work); i++ {
		if g.shards[i] != nil {
			if len(g.shards[i]) == g.shardLen {
				work[i] = g.shards[i]
			} else if len(g.shards[i]) < g.shardLen {
				padded := make([]byte, g.shardLen)
				copy(padded, g.shards[i])
				work[i] = padded
			} else {
				return nil
			}
		}
	}

	if !reconstructDataGF256(g.dCount, g.pCount, g.shardLen, work) {
		return nil
	}

	var recovered [][]byte
	for i := 0; i < g.dCount; i++ {
		bit := uint64(1) << uint(i)
		if (g.present & bit) == 0 {
			s := work[i]
			if len(s) < 2 {
				continue
			}
			pLen := int(binary.BigEndian.Uint16(s[0:2]))
			if pLen == 0 || 2+pLen > len(s) {
				continue
			}
			out := make([]byte, pLen)
			copy(out, s[2:2+pLen])
			recovered = append(recovered, out)
			g.present |= bit
		}
	}
	g.completed = true
	g.shards = nil
	return recovered
}
