// Copyright 2026 The OpenFIR Authors.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// OpenFIR Protocol Constants & Frame Definitions (v0.7.0 Hardened)
// OpenFIR = Open Fast Interleaved Reliable UDP Transport Protocol
// ============================================================================

const (
	ProtocolMagic0 = 0x4F // 'O'
	ProtocolMagic1 = 0x46 // 'F'

	PktHandshake       uint8 = 0x01 // Session metadata + X25519 pubkey synchronization
	PktHandshakeAck    uint8 = 0x02 // Handshake ACK + PFS SID/pubkey + resume + CAS Bloom + Server Port Matrix
	PktData            uint8 = 0x03 // Standard data payload frame
	PktTeleport        uint8 = 0x04 // Intra-session content-addressed / zero-chunk teleport frame
	PktPhiParity       uint8 = 0x05 // Coprime-stride interleaved GF(2) parity frame
	PktFeedback        uint8 = 0x06 // Receiver NACK/SACK + CAS telemetry + Per-Path Kalman OWDG
	PktFin             uint8 = 0x07 // Transfer completion announcement
	PktFinAck          uint8 = 0x08 // End-to-end SHA-256 verification confirmation
	PktError           uint8 = 0x09 // Explicit fatal error notification frame
	PktCookieChallenge uint8 = 0x0A // Stateless anti-spoofing HMAC cookie challenge
	PktCASTeleport     uint8 = 0x0B // Cross-session global CAS zero-byte teleport frame

	FlagSingleFile      uint8 = 0x00 // Payload represents a single regular file
	FlagDirectoryBundle uint8 = 0x01 // Payload represents a Virtual Continuous Directory Extent

	DirClientToServer uint8 = 0x00 // Directional domain: Client -> Server (even ASCII parity)
	DirServerToClient uint8 = 0x01 // Directional domain: Server -> Client (odd ASCII parity)

	EntryTypeFile uint8 = 0x00 // Directory bundle regular file entry
	EntryTypeDir  uint8 = 0x01 // Directory bundle explicit subdirectory entry

	DefaultChunkSize        = 1200             // Safe UDP payload size across WANs and tunnels
	MaxUDPPacketSize        = 1500             // Maximum valid OpenFIR protocol frame size
	MaxUDPDatagramSize      = 65536            // Full 64 KB buffer to prevent Windows WSAEMSGSIZE
	SocketBufferBytes       = 16 * 1024 * 1024 // 16 MB kernel socket buffer target
	PhiGroupMembers         = 4                // Data chunks per algebraic parity equation
	MaxPendingParity        = 2048             // Maximum active equations in O(1) peeling decoder graph
	MaxNackPerPacket        = 160              // Maximum NACK chunk IDs per feedback frame
	MaxUrgentNacks          = 4096             // Lossless urgent NACK queue capacity
	FeedbackScanWindow      = 32768            // Receiver NACK/SACK scan horizon per feedback frame
	MaxTrackedPeers         = 32               // Maximum concurrent client UDP paths tracked per session
	L1ChunkCacheSize        = 1024             // Receiver in-memory L1 ring cache slots
	MaxTeleportIndexEntries = 500000           // Cap sender deduplication map to bound memory usage
	MaxGlobalCASEntries     = 300000           // Cap server cross-session CAS index entries
	CASBloomBytes           = 1024             // 8192-bit (1024-byte) cross-session CAS Bloom filter
	FDLRUCacheCap           = 64               // Bounded open file descriptor LRU cache
	SocketRotateByteQuota   = 12 * 1024 * 1024 // Rotate client 5-tuple socket every 12 MB transmitted
	DeadPathSilenceNano     = int64(600 * time.Millisecond)
	DefaultServerPortSpan   = 4          // Default native multi-port server matrix width
	CookieSize              = 16         // 128-bit stateless handshake cookie size
	X25519PubSize           = 32         // X25519 public key length
	OuterHeaderSize         = 22         // [6B Polymorphic ASCII][8B MaskedSeq][4B MaskedSID][4B RandSalt]
	ReplayWindowWords       = 256        // 256 * 64 = 16384-packet sliding anti-replay window
	ReplayWindowBits        = ReplayWindowWords * 64
	ZeroChunkSentinel       = math.MaxUint32 // Reserved sourceIdx indicating an all-zero chunk
)

var (
	entryMagicBytes  = [4]byte{'O', 'F', 'E', 'N'}
	defaultDemoHex   = "a37f92c819e4b50d6b2e4a1c809f73e5d4c1b2a390817263544536271809abef"
	packetBufferPool = sync.Pool{
		New: func() any {
			b := make([]byte, MaxUDPDatagramSize)
			return &b
		},
	}
)

// ============================================================================
// Module 1: Fast AES-256-CTR CSPRNG Pool, AES-256 PRF, X25519 PFS & AES-GCM
// ============================================================================

type fastCSPRNG struct {
	stream   cipher.Stream
	buf      [4096]byte
	pos      int
	produced uint64
}

func newFastCSPRNG() *fastCSPRNG {
	r := &fastCSPRNG{pos: 4096}
	r.reseed()
	return r
}

func (r *fastCSPRNG) reseed() {
	var seed [48]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		panic(fmt.Sprintf("CSPRNG entropy failure: %v", err))
	}
	blk, err := aes.NewCipher(seed[0:32])
	if err != nil {
		panic(fmt.Sprintf("AES-256 DRBG init failed: %v", err))
	}
	r.stream = cipher.NewCTR(blk, seed[32:48])
	r.pos = len(r.buf)
	r.produced = 0
}

func (r *fastCSPRNG) Read(p []byte) {
	for len(p) > 0 {
		if r.produced >= 64*1024*1024 {
			r.reseed()
		}
		if r.pos >= len(r.buf) {
			for i := range r.buf {
				r.buf[i] = 0
			}
			r.stream.XORKeyStream(r.buf[:], r.buf[:])
			r.pos = 0
		}
		n := copy(p, r.buf[r.pos:])
		r.pos += n
		r.produced += uint64(n)
		p = p[n:]
	}
}

var csprngPool = sync.Pool{
	New: func() any {
		return newFastCSPRNG()
	},
}

func fastRandFill(p []byte) {
	if len(p) == 0 {
		return
	}
	r := csprngPool.Get().(*fastCSPRNG)
	r.Read(p)
	csprngPool.Put(r)
}

func cryptoRandUint64() uint64 {
	var b [8]byte
	fastRandFill(b[:])
	return binary.BigEndian.Uint64(b[:])
}

func cryptoRandUint32() uint32 {
	var b [4]byte
	fastRandFill(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// prf64 computes a zero-allocation, domain-separated, cryptographically uninvertible
// 64-bit PRF output using AES-256 over up to 14 bytes of input.
func prf64(blk cipher.Block, domain byte, data []byte) uint64 {
	var in, out [16]byte
	in[0] = domain
	in[1] = byte(len(data))
	copy(in[2:], data)
	blk.Encrypt(out[:], in[:])
	return binary.BigEndian.Uint64(out[0:8])
}

func hkdfSHA256(ikm, salt, info []byte) [32]byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(ikm)
	prk := extractor.Sum(nil)

	expander := hmac.New(sha256.New, prk)
	expander.Write(info)
	expander.Write([]byte{0x01})
	okm := expander.Sum(nil)

	var out [32]byte
	copy(out[:], okm[:32])
	return out
}

func parseSecretMaterial(raw string) ([32]byte, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		if envSec := strings.TrimSpace(os.Getenv("OPENFIR_SECRET")); envSec != "" {
			trimmed = envSec
		}
	}
	if trimmed == "" {
		return [32]byte{}, false, errors.New("missing secret key: specify -secret <hex-or-passphrase> or set OPENFIR_SECRET")
	}

	isDemo := strings.EqualFold(trimmed, "a37f92c819e4b50d") || strings.EqualFold(trimmed, defaultDemoHex)

	if len(trimmed) < 16 {
		return [32]byte{}, isDemo, errors.New("secret key too short: must be at least 16 characters (64 hex chars / 256 bits recommended)")
	}

	var ikm []byte
	if len(trimmed)%2 == 0 {
		if decoded, err := hex.DecodeString(trimmed); err == nil {
			ikm = decoded
		}
	}
	if len(ikm) == 0 {
		if strings.HasPrefix(strings.ToLower(trimmed), "pass:") {
			ikm = []byte(trimmed[5:])
			if len(ikm) < 12 {
				return [32]byte{}, isDemo, errors.New("passphrase after 'pass:' must be at least 12 characters")
			}
		} else {
			return [32]byte{}, isDemo, errors.New("invalid -secret format: provide valid even-length hex (>=16 hex chars) or prefix a passphrase with 'pass:'")
		}
	}

	masterKey := hkdfSHA256(ikm, []byte("OpenFIR-v7-Master-Salt"), []byte("OpenFIR-v7-Master-Key"))
	return masterKey, isDemo, nil
}

type SessionAEADPair struct {
	c2sAEAD cipher.AEAD
	s2cAEAD cipher.AEAD
}

func deriveSessionAEAD(masterKey [32]byte, sharedSecret []byte, tid uint64, sid uint32) (*SessionAEADPair, error) {
	ikm := make([]byte, 32+len(sharedSecret))
	copy(ikm[0:32], masterKey[:])
	copy(ikm[32:], sharedSecret)

	var salt [12]byte
	binary.BigEndian.PutUint64(salt[0:8], tid)
	binary.BigEndian.PutUint32(salt[8:12], sid)

	sessMaster := hkdfSHA256(ikm, salt[:], []byte("OpenFIR-v7-PFS-Session"))
	c2sKey := hkdfSHA256(sessMaster[:], salt[:], []byte("OpenFIR-v7-PFS-C2S-AEAD"))
	s2cKey := hkdfSHA256(sessMaster[:], salt[:], []byte("OpenFIR-v7-PFS-S2C-AEAD"))

	b1, err := aes.NewCipher(c2sKey[:])
	if err != nil {
		return nil, err
	}
	a1, err := cipher.NewGCM(b1)
	if err != nil {
		return nil, err
	}
	b2, err := aes.NewCipher(s2cKey[:])
	if err != nil {
		return nil, err
	}
	a2, err := cipher.NewGCM(b2)
	if err != nil {
		return nil, err
	}
	return &SessionAEADPair{c2sAEAD: a1, s2cAEAD: a2}, nil
}

type WireCryptoEngine struct {
	masterKey [32]byte
	c2sAEAD   cipher.AEAD // Pre-session handshake/control AEAD
	s2cAEAD   cipher.AEAD // Pre-session handshake/control AEAD
	hdrBlock  cipher.Block
}

func NewWireCryptoEngine(masterKey [32]byte) (*WireCryptoEngine, error) {
	c2sKey := hkdfSHA256(masterKey[:], []byte("OpenFIR-v7-Dir-Salt"), []byte("OpenFIR-v7-Pre-C2S-AEAD"))
	s2cKey := hkdfSHA256(masterKey[:], []byte("OpenFIR-v7-Dir-Salt"), []byte("OpenFIR-v7-Pre-S2C-AEAD"))
	hdrKey := hkdfSHA256(masterKey[:], []byte("OpenFIR-v7-Dir-Salt"), []byte("OpenFIR-v7-AES256-Header-PRF"))

	b1, err := aes.NewCipher(c2sKey[:])
	if err != nil {
		return nil, err
	}
	aead1, err := cipher.NewGCM(b1)
	if err != nil {
		return nil, err
	}

	b2, err := aes.NewCipher(s2cKey[:])
	if err != nil {
		return nil, err
	}
	aead2, err := cipher.NewGCM(b2)
	if err != nil {
		return nil, err
	}

	hdrBlock, err := aes.NewCipher(hdrKey[:])
	if err != nil {
		return nil, err
	}

	return &WireCryptoEngine{
		masterKey: masterKey,
		c2sAEAD:   aead1,
		s2cAEAD:   aead2,
		hdrBlock:  hdrBlock,
	}, nil
}

func (w *WireCryptoEngine) SealWith(raw []byte, direction uint8, sid uint32, seq uint64, customAEAD cipher.AEAD) []byte {
	aead := customAEAD
	if aead == nil {
		if direction == DirClientToServer {
			aead = w.c2sAEAD
		} else {
			aead = w.s2cAEAD
		}
	}
	if seq == 0 {
		seq = 1
	}

	var randBytes [12]byte
	fastRandFill(randBytes[:])
	pRand := binary.BigEndian.Uint64(randBytes[0:8])
	randSalt32 := binary.BigEndian.Uint32(randBytes[8:12])

	out := make([]byte, OuterHeaderSize, OuterHeaderSize+len(raw)+aead.Overhead())
	for i := 0; i < 5; i++ {
		out[i] = byte(0x21 + (pRand % 94))
		pRand /= 94
	}
	tag47 := int(prf64(w.hdrBlock, 0x01, out[0:5]) % 47)
	out[5] = byte(0x21 + tag47*2 + int(direction&1))

	seqMask := prf64(w.hdrBlock, 0x02, out[0:6])
	sidMask := uint32(prf64(w.hdrBlock, 0x03, out[0:6]))
	binary.BigEndian.PutUint64(out[6:14], seq^seqMask)
	binary.BigEndian.PutUint32(out[14:18], sid^sidMask)
	binary.BigEndian.PutUint32(out[18:22], randSalt32)

	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[0:8], seq)
	binary.BigEndian.PutUint32(nonce[8:12], randSalt32)

	aad := out[0:OuterHeaderSize]
	return aead.Seal(out, nonce[:], raw, aad)
}

func (w *WireCryptoEngine) PeekHeader(wire []byte, expectedDirection uint8) (sid uint32, seq uint64, ok bool) {
	if len(wire) < OuterHeaderSize+16+3 || len(wire) > MaxUDPPacketSize+256 {
		return 0, 0, false
	}
	for i := 0; i < 6; i++ {
		if wire[i] < 0x21 || wire[i] > 0x7E {
			return 0, 0, false
		}
	}
	tag47 := int(prf64(w.hdrBlock, 0x01, wire[0:5]) % 47)
	expectedByte5 := byte(0x21 + tag47*2 + int(expectedDirection&1))
	if wire[5] != expectedByte5 {
		return 0, 0, false
	}

	seqMask := prf64(w.hdrBlock, 0x02, wire[0:6])
	seq = binary.BigEndian.Uint64(wire[6:14]) ^ seqMask
	if seq == 0 {
		return 0, 0, false
	}
	sidMask := uint32(prf64(w.hdrBlock, 0x03, wire[0:6]))
	sid = binary.BigEndian.Uint32(wire[14:18]) ^ sidMask
	return sid, seq, true
}

func (w *WireCryptoEngine) OpenAfterPeek(wire []byte, expectedDirection uint8, seq uint64, customAEAD cipher.AEAD) ([]byte, bool) {
	aead := customAEAD
	if aead == nil {
		if expectedDirection == DirClientToServer {
			aead = w.c2sAEAD
		} else {
			aead = w.s2cAEAD
		}
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[0:8], seq)
	copy(nonce[8:12], wire[18:22])

	aad := wire[0:OuterHeaderSize]
	ciphertext := wire[OuterHeaderSize:]

	raw, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, false
	}
	if len(raw) < 3 || raw[0] != ProtocolMagic0 || raw[1] != ProtocolMagic1 {
		return nil, false
	}
	return raw, true
}

func makePreSessionSeq() uint64 {
	// Combine 32-bit epoch seconds + 32-bit CSPRNG entropy (never 0) -> 64-bit collision-free pre-session nonce prefix
	s := (uint64(uint32(time.Now().Unix())) << 32) | uint64(cryptoRandUint32())
	if s == 0 {
		s = 1
	}
	return s
}

type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	bitmap  [ReplayWindowWords]uint64
	init    bool
}

func (rw *ReplayWindow) CheckAndAccept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if !rw.init {
		rw.init = true
		rw.highest = seq
		rw.bitmap[0] = 1
		return true
	}

	if seq > rw.highest {
		shift := seq - rw.highest
		if shift >= ReplayWindowBits {
			rw.bitmap = [ReplayWindowWords]uint64{}
		} else {
			wordShift := shift / 64
			bitShift := shift % 64
			if bitShift == 0 {
				for i := ReplayWindowWords - 1; i >= int(wordShift); i-- {
					rw.bitmap[i] = rw.bitmap[i-int(wordShift)]
				}
			} else {
				for i := ReplayWindowWords - 1; i > int(wordShift); i-- {
					rw.bitmap[i] = (rw.bitmap[i-int(wordShift)] << bitShift) | (rw.bitmap[i-int(wordShift)-1] >> (64 - bitShift))
				}
				rw.bitmap[wordShift] = rw.bitmap[0] << bitShift
			}
			for i := 0; i < int(wordShift); i++ {
				rw.bitmap[i] = 0
			}
		}
		rw.bitmap[0] |= 1
		rw.highest = seq
		return true
	}

	diff := rw.highest - seq
	if diff >= ReplayWindowBits {
		return false
	}
	wordIdx := diff / 64
	bitMask := uint64(1) << (diff % 64)
	if (rw.bitmap[wordIdx] & bitMask) != 0 {
		return false
	}
	rw.bitmap[wordIdx] |= bitMask
	return true
}

// ============================================================================
// Module 2: Bounded LRU FD Cache, Compact Bitset & Global Persistent CAS Store
// ============================================================================

type fdLRUEntry struct {
	path     string
	file     *os.File
	lastUsed uint64
}

type FDLRUCache struct {
	mu      sync.Mutex
	cap     int
	clock   uint64
	entries map[string]*fdLRUEntry
}

func NewFDLRUCache(capacity int) *FDLRUCache {
	if capacity < 4 {
		capacity = 4
	}
	return &FDLRUCache{
		cap:     capacity,
		entries: make(map[string]*fdLRUEntry, capacity),
	}
}

func (c *FDLRUCache) ReadAt(path string, dst []byte, off int64) (int, error) {
	c.mu.Lock()
	c.clock++
	if e, ok := c.entries[path]; ok {
		e.lastUsed = c.clock
		f := e.file
		c.mu.Unlock()
		return f.ReadAt(dst, off)
	}
	c.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	n, rErr := f.ReadAt(dst, off)

	c.mu.Lock()
	c.clock++
	if existing, ok := c.entries[path]; ok {
		existing.lastUsed = c.clock
		c.mu.Unlock()
		_ = f.Close()
		return n, rErr
	}
	var evicted *os.File
	if len(c.entries) >= c.cap {
		var oldestKey string
		var oldestTick uint64 = math.MaxUint64
		for k, v := range c.entries {
			if v.lastUsed < oldestTick {
				oldestTick = v.lastUsed
				oldestKey = k
			}
		}
		if oldestKey != "" {
			evicted = c.entries[oldestKey].file
			delete(c.entries, oldestKey)
		}
	}
	c.entries[path] = &fdLRUEntry{path: path, file: f, lastUsed: c.clock}
	c.mu.Unlock()

	if evicted != nil {
		_ = evicted.Close()
	}
	return n, rErr
}

func (c *FDLRUCache) EvictPathPrefix(targetPath string) {
	cleanTarget := filepath.Clean(targetPath)
	prefix := cleanTarget + string(os.PathSeparator)

	c.mu.Lock()
	var toClose []*os.File
	for k, v := range c.entries {
		ck := filepath.Clean(k)
		if ck == cleanTarget || strings.HasPrefix(ck, prefix) {
			toClose = append(toClose, v.file)
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()

	for _, f := range toClose {
		_ = f.Close()
	}
}

func (c *FDLRUCache) Close() {
	c.mu.Lock()
	toClose := make([]*os.File, 0, len(c.entries))
	for k, v := range c.entries {
		toClose = append(toClose, v.file)
		delete(c.entries, k)
	}
	c.mu.Unlock()
	for _, f := range toClose {
		_ = f.Close()
	}
}

type CompactBitset struct {
	words []uint64
	size  uint32
}

func NewCompactBitset(size uint32) *CompactBitset {
	numWords := (uint64(size) + 63) / 64
	return &CompactBitset{
		words: make([]uint64, numWords),
		size:  size,
	}
}

func (b *CompactBitset) Get(idx uint32) bool {
	if idx >= b.size {
		return false
	}
	return (b.words[idx>>6] & (uint64(1) << (idx & 63))) != 0
}

func (b *CompactBitset) Set(idx uint32) {
	if idx >= b.size {
		return
	}
	b.words[idx>>6] |= (uint64(1) << (idx & 63))
}

func (b *CompactBitset) Clear(idx uint32) {
	if idx >= b.size {
		return
	}
	b.words[idx>>6] &^= (uint64(1) << (idx & 63))
}

func casBloomAdd(bloom *[CASBloomBytes]byte, h [32]byte) {
	for i := 0; i < 8; i += 2 {
		bit := binary.BigEndian.Uint16(h[i:i+2]) & 8191
		bloom[bit>>3] |= (1 << (bit & 7))
	}
}

func casBloomTest(bloom *[CASBloomBytes]byte, h [32]byte) bool {
	for i := 0; i < 8; i += 2 {
		bit := binary.BigEndian.Uint16(h[i:i+2]) & 8191
		if (bloom[bit>>3] & (1 << (bit & 7))) == 0 {
			return false
		}
	}
	return true
}

func casBloomFillRatio(bloom *[CASBloomBytes]byte) float64 {
	setBits := 0
	for i := 0; i < CASBloomBytes; i++ {
		setBits += bits.OnesCount8(bloom[i])
	}
	return float64(setBits) / float64(CASBloomBytes*8)
}

type casChunkLocation struct {
	filePath string
	offset   int64
	length   int
}

type GlobalCASStore struct {
	mu      sync.RWMutex
	entries map[[32]byte]casChunkLocation
	bloom   [CASBloomBytes]byte
	fdCache *FDLRUCache
}

func NewGlobalCASStore(rootDir string) *GlobalCASStore {
	store := &GlobalCASStore{
		entries: make(map[[32]byte]casChunkLocation),
		fdCache: NewFDLRUCache(FDLRUCacheCap),
	}

	var paths []string
	_ = filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") && strings.Contains(base, ".openfir-part-") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})

	// Index synchronously up to 1.5s startup budget, then finish remaining files asynchronously
	deadline := time.Now().Add(1500 * time.Millisecond)
	idx := 0
	for ; idx < len(paths); idx++ {
		if store.isFull() || time.Now().After(deadline) {
			break
		}
		store.indexSingleFile(paths[idx])
	}
	if idx < len(paths) && !store.isFull() {
		rem := paths[idx:]
		go func() {
			for _, p := range rem {
				if store.isFull() {
					return
				}
				store.indexSingleFile(p)
			}
		}()
	}
	return store
}

func (g *GlobalCASStore) Close() {
	g.fdCache.Close()
}

func (g *GlobalCASStore) EvictPath(path string) {
	g.fdCache.EvictPathPrefix(path)
}

func (g *GlobalCASStore) isFull() bool {
	g.mu.RLock()
	full := len(g.entries) >= MaxGlobalCASEntries
	g.mu.RUnlock()
	return full
}

func (g *GlobalCASStore) IndexPath(targetPath string) {
	if g.isFull() {
		return
	}
	st, err := os.Stat(targetPath)
	if err != nil {
		return
	}
	if st.IsDir() {
		_ = filepath.WalkDir(targetPath, func(p string, d fs.DirEntry, wErr error) error {
			if wErr != nil || d.IsDir() {
				return nil
			}
			if g.isFull() {
				return filepath.SkipAll
			}
			g.indexSingleFile(p)
			return nil
		})
		return
	}
	if st.Mode().IsRegular() {
		g.indexSingleFile(targetPath)
	}
}

func (g *GlobalCASStore) indexSingleFile(filePath string) {
	if g.isFull() {
		return
	}
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	buf := make([]byte, DefaultChunkSize)
	var offset int64 = 0
	for {
		n, rErr := f.ReadAt(buf, offset)
		if n > 0 {
			if !isAllZero(buf[:n]) {
				h := sha256.Sum256(buf[:n])
				g.mu.Lock()
				if len(g.entries) >= MaxGlobalCASEntries {
					g.mu.Unlock()
					return
				}
				g.entries[h] = casChunkLocation{
					filePath: filePath,
					offset:   offset,
					length:   n,
				}
				casBloomAdd(&g.bloom, h)
				g.mu.Unlock()
			}
			offset += int64(n)
		}
		if rErr != nil {
			break
		}
	}
}

func (g *GlobalCASStore) SnapshotBloom() (uint32, [CASBloomBytes]byte) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return uint32(len(g.entries)), g.bloom
}

func (g *GlobalCASStore) ReadVerifiedChunk(digest [32]byte, expectedLen int) ([]byte, bool) {
	g.mu.RLock()
	loc, exists := g.entries[digest]
	g.mu.RUnlock()
	if !exists || loc.length != expectedLen || expectedLen <= 0 {
		return nil, false
	}

	buf := make([]byte, expectedLen)
	n, err := g.fdCache.ReadAt(loc.filePath, buf, loc.offset)
	if (err != nil && err != io.EOF) || n != expectedLen {
		return nil, false
	}
	if sha256.Sum256(buf) != digest {
		return nil, false
	}
	return buf, true
}

func isAllZero(b []byte) bool {
	i := 0
	for ; i+8 <= len(b); i += 8 {
		if binary.LittleEndian.Uint64(b[i:i+8]) != 0 {
			return false
		}
	}
	for ; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

// ============================================================================
// Module 3: Zero-RTT Virtual Continuous Extent (LRU FD Pool + Safe Unpack)
// ============================================================================

type virtualEntry struct {
	absPath     string
	headerBytes []byte
	fileSize    int64
	startOffset int64
	endOffset   int64
}

type VirtualDirectoryExtent struct {
	entries   []virtualEntry
	totalSize int64
	fdCache   *FDLRUCache
}

func NewVirtualDirectoryExtent(rootDir string) (*VirtualDirectoryExtent, error) {
	rootDir = filepath.Clean(rootDir)
	var entries []virtualEntry
	var currentOffset int64 = 0

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == rootDir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// Never follow symlinks outside tree
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		slashRel := filepath.ToSlash(rel)
		relBytes := []byte(slashRel)
		if len(relBytes) == 0 || len(relBytes) > 65535 {
			return nil
		}

		var entryType uint8
		var fSize int64
		if d.IsDir() {
			entryType = EntryTypeDir
			fSize = 0
		} else if info.Mode().IsRegular() {
			entryType = EntryTypeFile
			fSize = info.Size()
		} else {
			return nil
		}

		hdr := make([]byte, 19+len(relBytes))
		copy(hdr[0:4], entryMagicBytes[:])
		hdr[4] = entryType
		binary.BigEndian.PutUint32(hdr[5:9], uint32(info.Mode().Perm()))
		binary.BigEndian.PutUint64(hdr[9:17], uint64(fSize))
		binary.BigEndian.PutUint16(hdr[17:19], uint16(len(relBytes)))
		copy(hdr[19:], relBytes)

		entrySpan := int64(len(hdr)) + fSize
		entries = append(entries, virtualEntry{
			absPath:     path,
			headerBytes: hdr,
			fileSize:    fSize,
			startOffset: currentOffset,
			endOffset:   currentOffset + entrySpan,
		})
		currentOffset += entrySpan
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &VirtualDirectoryExtent{
		entries:   entries,
		totalSize: currentOffset,
		fdCache:   NewFDLRUCache(FDLRUCacheCap),
	}, nil
}

func (v *VirtualDirectoryExtent) Size() int64 {
	return v.totalSize
}

func (v *VirtualDirectoryExtent) FileCount() int {
	return len(v.entries)
}

func (v *VirtualDirectoryExtent) Close() error {
	v.fdCache.Close()
	return nil
}

func (v *VirtualDirectoryExtent) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= v.totalSize {
		return 0, io.EOF
	}
	idx := sort.Search(len(v.entries), func(i int) bool {
		return v.entries[i].endOffset > off
	})

	totalCopied := 0
	curOff := off

	for totalCopied < len(p) && idx < len(v.entries) {
		e := &v.entries[idx]
		relOff := curOff - e.startOffset
		hdrLen := int64(len(e.headerBytes))

		if relOff < hdrLen {
			availHdr := int(hdrLen - relOff)
			need := len(p) - totalCopied
			if availHdr > need {
				availHdr = need
			}
			copy(p[totalCopied:totalCopied+availHdr], e.headerBytes[relOff:int(relOff)+availHdr])
			totalCopied += availHdr
			curOff += int64(availHdr)
			relOff += int64(availHdr)
		}

		if totalCopied < len(p) && relOff >= hdrLen {
			fileOff := relOff - hdrLen
			availFile := e.fileSize - fileOff
			if availFile > 0 {
				need := int64(len(p) - totalCopied)
				toRead := availFile
				if toRead > need {
					toRead = need
				}
				n, err := v.fdCache.ReadAt(e.absPath, p[totalCopied:totalCopied+int(toRead)], fileOff)
				totalCopied += n
				curOff += int64(n)
				if n == 0 || (err != nil && err != io.EOF) {
					if err != nil && err != io.EOF {
						return totalCopied, err
					}
					return totalCopied, errors.New("source file truncated during transfer")
				}
			}
		}
		idx++
	}

	if totalCopied < len(p) {
		return totalCopied, io.EOF
	}
	return totalCopied, nil
}

func validateSafeExtractPath(absRoot, rawSlashRel string) (string, error) {
	if strings.ContainsRune(rawSlashRel, 0) || strings.ContainsRune(rawSlashRel, '\\') {
		return "", errors.New("unsafe path characters rejected during bundle extraction")
	}
	cleanRel := filepath.Clean(filepath.FromSlash(rawSlashRel))
	if cleanRel == "." || cleanRel == ".." || filepath.IsAbs(cleanRel) || filepath.VolumeName(cleanRel) != "" {
		return "", errors.New("unsafe relative path rejected during bundle extraction")
	}
	if strings.HasPrefix(cleanRel, ".."+string(os.PathSeparator)) {
		return "", errors.New("directory traversal rejected during bundle extraction")
	}
	dstPath := filepath.Join(absRoot, cleanRel)
	absDst, err := filepath.Abs(dstPath)
	if err != nil {
		return "", err
	}
	relCheck, err := filepath.Rel(absRoot, absDst)
	if err != nil || relCheck == "." || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
		return "", errors.New("extracted path escapes target root directory")
	}
	return absDst, nil
}

func unpackDirectoryBundle(bundleFile *os.File, bundleSize int64, targetRootDir string) (int, error) {
	if err := os.MkdirAll(targetRootDir, 0755); err != nil {
		return 0, err
	}
	absRoot, err := filepath.Abs(targetRootDir)
	if err != nil {
		return 0, err
	}

	var offset int64 = 0
	var extractedCount int = 0
	hdrBuf := make([]byte, 19)
	copyBuf := make([]byte, 256*1024)

	for offset < bundleSize {
		if offset+19 > bundleSize {
			return extractedCount, errors.New("corrupted directory bundle entry header")
		}
		if n, err := bundleFile.ReadAt(hdrBuf, offset); n != 19 || (err != nil && err != io.EOF) {
			return extractedCount, errors.New("short read on directory bundle header")
		}
		for i := 0; i < 4; i++ {
			if hdrBuf[i] != entryMagicBytes[i] {
				return extractedCount, errors.New("invalid entry magic in directory bundle")
			}
		}
		entryType := hdrBuf[4]
		filePerm := fs.FileMode(binary.BigEndian.Uint32(hdrBuf[5:9])) & 0777
		if filePerm == 0 {
			filePerm = 0644
		}
		fileSize := int64(binary.BigEndian.Uint64(hdrBuf[9:17]))
		pathLen := int(binary.BigEndian.Uint16(hdrBuf[17:19]))
		offset += 19

		if pathLen <= 0 || fileSize < 0 || offset+int64(pathLen)+fileSize > bundleSize {
			return extractedCount, errors.New("corrupted entry bounds in directory bundle")
		}
		pathBytes := make([]byte, pathLen)
		if n, err := bundleFile.ReadAt(pathBytes, offset); n != pathLen || (err != nil && err != io.EOF) {
			return extractedCount, errors.New("short read on directory bundle path")
		}
		offset += int64(pathLen)

		dstPath, err := validateSafeExtractPath(absRoot, string(pathBytes))
		if err != nil {
			return extractedCount, err
		}

		if entryType == EntryTypeDir {
			if err := os.MkdirAll(dstPath, 0755); err != nil {
				return extractedCount, err
			}
			extractedCount++
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return extractedCount, err
		}
		// Prevent overwriting through pre-existing symlinks
		if linfo, lerr := os.Lstat(dstPath); lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
			if rmErr := os.Remove(dstPath); rmErr != nil {
				return extractedCount, rmErr
			}
		}

		outF, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
		if err != nil {
			return extractedCount, err
		}

		rem := fileSize
		for rem > 0 {
			step := int64(len(copyBuf))
			if rem < step {
				step = rem
			}
			n, rErr := bundleFile.ReadAt(copyBuf[:step], offset)
			if n > 0 {
				if _, wErr := outF.Write(copyBuf[:n]); wErr != nil {
					_ = outF.Close()
					return extractedCount, wErr
				}
				offset += int64(n)
				rem -= int64(n)
			}
			if n == 0 {
				_ = outF.Close()
				return extractedCount, io.ErrUnexpectedEOF
			}
			if rErr != nil && rErr != io.EOF {
				_ = outF.Close()
				return extractedCount, rErr
			}
		}
		_ = outF.Close()
		extractedCount++
	}
	return extractedCount, nil
}

// ============================================================================
// Module 4: Per-Path Kalman OWDG (Windowed MinOWD) & CAR-Aware MicroPacer
// ============================================================================

type KalmanOWDTracker struct {
	mu               sync.Mutex
	initialized      bool
	lastSendNano     int64
	lastRecvNano     int64
	curWinMin        int64
	prevWinMin       int64
	winStartNano     int64
	hatGradMicros    float64
	errCovP          float64
	processNoiseQ    float64
	measureNoiseR    float64
	standingQueueUs  int64
}

func NewKalmanOWDTracker() *KalmanOWDTracker {
	return &KalmanOWDTracker{
		curWinMin:     math.MaxInt64,
		prevWinMin:    math.MaxInt64,
		winStartNano:  time.Now().UnixNano(),
		errCovP:       100.0,
		processNoiseQ: 8.0,
		measureNoiseR: 220.0,
	}
}

func (k *KalmanOWDTracker) Observe(sendNano, recvNano int64) {
	if sendNano <= 0 || recvNano <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	oneWay := recvNano - sendNano

	// 2-bucket 10-second sliding minimum OWD: immune to clock frequency drift & bufferbloat baseline creep
	const bucketDurNano = int64(5 * time.Second)
	if recvNano-k.winStartNano >= bucketDurNano {
		k.prevWinMin = k.curWinMin
		k.curWinMin = oneWay
		k.winStartNano = recvNano
	} else if oneWay < k.curWinMin {
		k.curWinMin = oneWay
	}

	baseMin := k.curWinMin
	if k.prevWinMin < baseMin {
		baseMin = k.prevWinMin
	}
	if oneWay >= baseMin {
		k.standingQueueUs = (oneWay - baseMin) / 1000
	} else {
		k.standingQueueUs = 0
	}

	if !k.initialized {
		k.initialized = true
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
		return
	}

	if sendNano > k.lastSendNano {
		deltaSend := sendNano - k.lastSendNano
		deltaRecv := recvNano - k.lastRecvNano
		measuredGradUs := float64(deltaRecv-deltaSend) / 1000.0

		if measuredGradUs > -50000 && measuredGradUs < 50000 {
			pPred := k.errCovP + k.processNoiseQ
			kalmanGain := pPred / (pPred + k.measureNoiseR)
			k.hatGradMicros = k.hatGradMicros + kalmanGain*(measuredGradUs-k.hatGradMicros)
			k.errCovP = (1.0 - kalmanGain) * pPred
		}
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
	}
}

func (k *KalmanOWDTracker) Snapshot() (gradMicros int64, queueMicros int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return int64(k.hatGradMicros), k.standingQueueUs
}

type MicroPacer struct {
	mu           sync.Mutex
	rateBps      float64
	minRateBps   float64
	maxRateBps   float64
	tokens       float64
	lastRefill   time.Time
	btlBwCur     float64
	btlBwPrev    float64
	btlWinStart  time.Time
}

func NewMicroPacer(initialMBps, minMBps, maxMBps float64) *MicroPacer {
	initBps := initialMBps * 1024 * 1024
	if initBps < minMBps*1024*1024 {
		initBps = minMBps * 1024 * 1024
	}
	now := time.Now()
	return &MicroPacer{
		rateBps:     initBps,
		minRateBps:  minMBps * 1024 * 1024,
		maxRateBps:  maxMBps * 1024 * 1024,
		tokens:      64 * 1024,
		lastRefill:  now,
		btlWinStart: now,
	}
}

func (p *MicroPacer) Wait(bytesToSend int) {
	p.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(p.lastRefill).Seconds()
	p.lastRefill = now

	// Adaptive 25ms burst headroom breaks Windows 15.6ms sleep granularity ceiling
	maxBurst := p.rateBps * 0.025
	if maxBurst < 64*1024 {
		maxBurst = 64 * 1024
	}
	if maxBurst > 8*1024*1024 {
		maxBurst = 8 * 1024 * 1024
	}

	p.tokens += elapsed * p.rateBps
	if p.tokens > maxBurst {
		p.tokens = maxBurst
	}
	p.tokens -= float64(bytesToSend)

	var sleepDur time.Duration
	if p.tokens < 0 {
		waitSec := (-p.tokens) / p.rateBps
		sleepDur = time.Duration(waitSec * float64(time.Second))
	}
	p.mu.Unlock()

	if sleepDur > 400*time.Microsecond {
		time.Sleep(sleepDur)
	}
}

// UpdateFromTelemetry fuses KF-OWDG queue control with a BBR-style delivery-rate ceiling
// to ignore random link loss while neutralizing zero-queue carrier CAR policer avalanches.
func (p *MicroPacer) UpdateFromTelemetry(gradMicros, standingQueueUs int64, deliveryBps float64, lossActive bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if now.Sub(p.btlWinStart) >= 2*time.Second {
		p.btlBwPrev = p.btlBwCur
		p.btlBwCur = 0
		p.btlWinStart = now
	}
	if deliveryBps > p.btlBwCur {
		p.btlBwCur = deliveryBps
	}
	btlBw := p.btlBwCur
	if p.btlBwPrev > btlBw {
		btlBw = p.btlBwPrev
	}

	const targetQueueUs = 4000

	if gradMicros > 180 || standingQueueUs > targetQueueUs*2 {
		backoff := float64(gradMicros) / 4000.0
		if backoff < 0.02 {
			backoff = 0.02
		}
		if backoff > 0.15 {
			backoff = 0.15
		}
		p.rateBps = p.rateBps * (1.0 - backoff)
	} else if lossActive && btlBw > 0 && p.rateBps > btlBw*1.38 {
		// Zero-queue CAR policer regime: cap pacing cleanly near 1.25x real receiver delivery rate
		target := btlBw * 1.25
		p.rateBps = p.rateBps*0.85 + target*0.15
	} else if gradMicros < 40 && standingQueueUs < targetQueueUs {
		p.rateBps = p.rateBps*1.04 + 512*1024
	}

	if p.rateBps < p.minRateBps {
		p.rateBps = p.minRateBps
	}
	if p.rateBps > p.maxRateBps {
		p.rateBps = p.maxRateBps
	}
}

func (p *MicroPacer) CurrentMBps() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rateBps / (1024 * 1024)
}

// ============================================================================
// Module 5: Gilbert-Elliott Burst-Loss Chaos Simulator
// ============================================================================

type ChaosSimulator struct {
	mu           sync.Mutex
	enabled      bool
	baseLossProb float64
	burstLength  int
	inBurst      int
	rng          *fastCSPRNG
	droppedCount uint64
}

func NewChaosSimulator(lossRate float64, burstLen int) *ChaosSimulator {
	if lossRate <= 0 {
		return &ChaosSimulator{enabled: false}
	}
	if burstLen < 1 {
		burstLen = 1
	}
	return &ChaosSimulator{
		enabled:      true,
		baseLossProb: lossRate / float64(burstLen),
		burstLength:  burstLen,
		rng:          newFastCSPRNG(),
	}
}

func (c *ChaosSimulator) ShouldDrop() bool {
	if !c.enabled {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.inBurst > 0 {
		c.inBurst--
		c.droppedCount++
		return true
	}
	var rb [4]byte
	c.rng.Read(rb[:])
	r := float64(binary.BigEndian.Uint32(rb[:])&0xFFFFFF) / float64(0x1000000)
	if r < c.baseLossProb {
		c.inBurst = c.burstLength - 1
		c.droppedCount++
		return true
	}
	return false
}

// ============================================================================
// Geometry, Coprime Stride & Socket Helpers
// ============================================================================

func gcdInt(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// selectCoprimePhiStride chooses a parity stride coprime to numSockets so no two
// members of the same GF(2) equation land on the same UDP 5-tuple path.
func selectCoprimePhiStride(numSockets int) int {
	if numSockets <= 1 {
		return 5
	}
	for _, cand := range []int{5, 7, 9, 11, 13, 17} {
		if gcdInt(cand, numSockets) == 1 {
			return cand
		}
	}
	return 19
}

func expectedChunkLen(idx, totalChunks uint32, fileSize int64, chunkSize int) int {
	if totalChunks == 0 || idx >= totalChunks || chunkSize <= 0 {
		return 0
	}
	if idx < totalChunks-1 {
		return chunkSize
	}
	rem := fileSize - int64(totalChunks-1)*int64(chunkSize)
	if rem <= 0 || rem > int64(chunkSize) {
		return 0
	}
	return int(rem)
}

func tuneUDPConn(conn *net.UDPConn) {
	_ = conn.SetReadBuffer(SocketBufferBytes)
	_ = conn.SetWriteBuffer(SocketBufferBytes)
}

func bindClientUDPSocket() (*net.UDPConn, error) {
	for attempt := 0; attempt < 12; attempt++ {
		port := 10000 + int(cryptoRandUint32()%22000)
		laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue
		}
		conn, err := net.ListenUDP("udp", laddr)
		if err == nil {
			tuneUDPConn(conn)
			return conn, nil
		}
	}
	laddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	tuneUDPConn(conn)
	return conn, nil
}

func atomicReplaceFile(stagingPath, finalPath string, allowOverwrite bool, casStore *GlobalCASStore) error {
	if casStore != nil {
		casStore.EvictPath(finalPath)
	}
	if !allowOverwrite {
		if _, err := os.Stat(finalPath); err == nil {
			return errors.New("destination already exists and -overwrite is disabled")
		}
	} else {
		_ = os.Remove(finalPath)
	}
	return os.Rename(stagingPath, finalPath)
}

// ============================================================================
// Module 6: OpenFIR Multi-Session & Multi-Port Matrix Receiver Engine
// ============================================================================

type ParityEquation struct {
	members    []uint32
	xorPayload []byte
	resolved   bool
	evicted    bool
}

type l1CacheSlot struct {
	valid bool
	idx   uint32
	data  []byte
}

type trackedPeer struct {
	addr         *net.UDPAddr
	srvConn      *net.UDPConn
	kalman       *KalmanOWDTracker
	lastSeenNano int64
}

type commitWorkItem struct {
	idx    uint32
	data   []byte
	source string
}

type ReceiverSession struct {
	mu               sync.Mutex
	transferID       uint64
	sessionID        uint32
	serverPubBytes   []byte
	aeadPair         *SessionAEADPair
	s2cSeqGen        uint64
	fileName         string
	fileSize         int64
	chunkSize        int
	totalChunks      uint32
	flags            uint8
	expectedSHA256   [32]byte
	file             *os.File
	stagingPath      string
	finalOutputPath  string
	receivedBitmap   *CompactBitset
	receivedCount    uint32
	highestContig    uint32
	finalizing       bool
	completed        bool
	verifiedOK       bool
	fatalErr         error
	completedAtNano  int64
	lastActivityNano int64
	replay           ReplayWindow
	pendingEqRing    []*ParityEquation
	chunkToEqs       map[uint32][]*ParityEquation
	pendingTeleports map[uint32][]uint32
	urgentNacks      []uint32
	l1Cache          [L1ChunkCacheSize]l1CacheSlot
	peers            []*trackedPeer
	feedbackTurn     uint64
	lastFinKeepalive int64

	statsDataChunks        uint64
	statsTeleportChunks    uint64
	statsZeroChunks        uint64
	statsCASTeleportChunks uint64
	statsCASMisses         uint64
	statsParityHealed      uint64
	lastReportedHealed     uint64
	statsDuplicatePkts     uint64
	startTime              time.Time
}

func (sess *ReceiverSession) nextS2CSeq() uint64 {
	return atomic.AddUint64(&sess.s2cSeqGen, 1)
}

func (sess *ReceiverSession) touchActivity() {
	atomic.StoreInt64(&sess.lastActivityNano, time.Now().UnixNano())
}

func (sess *ReceiverSession) setFatalError(err error) {
	sess.mu.Lock()
	if sess.fatalErr == nil {
		sess.fatalErr = err
	}
	sess.mu.Unlock()
}

func (sess *ReceiverSession) getFatalError() error {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.fatalErr
}

func (sess *ReceiverSession) cacheChunkLocked(idx uint32, data []byte) {
	slot := &sess.l1Cache[idx%L1ChunkCacheSize]
	if cap(slot.data) < len(data) {
		slot.data = make([]byte, len(data))
	} else {
		slot.data = slot.data[:len(data)]
	}
	copy(slot.data, data)
	slot.idx = idx
	slot.valid = true
}

func (sess *ReceiverSession) readChunkFast(idx uint32, dst []byte) bool {
	expLen := expectedChunkLen(idx, sess.totalChunks, sess.fileSize, sess.chunkSize)
	if expLen <= 0 || len(dst) < expLen {
		return false
	}

	sess.mu.Lock()
	if sess.file == nil {
		sess.mu.Unlock()
		return false
	}
	slot := &sess.l1Cache[idx%L1ChunkCacheSize]
	if slot.valid && slot.idx == idx && len(slot.data) == expLen {
		copy(dst[:expLen], slot.data)
		sess.mu.Unlock()
		return true
	}
	f := sess.file
	sess.mu.Unlock()

	n, err := f.ReadAt(dst[:expLen], int64(idx)*int64(sess.chunkSize))
	if err != nil && err != io.EOF {
		return false
	}
	return n == expLen
}

func (sess *ReceiverSession) registerPeer(peer *net.UDPAddr, srvConn *net.UDPConn) *trackedPeer {
	if peer == nil {
		return nil
	}
	now := time.Now().UnixNano()
	sess.mu.Lock()
	defer sess.mu.Unlock()
	for _, tp := range sess.peers {
		if tp.addr.IP.Equal(peer.IP) && tp.addr.Port == peer.Port {
			tp.lastSeenNano = now
			if srvConn != nil {
				tp.srvConn = srvConn
			}
			return tp
		}
	}
	copied := &net.UDPAddr{
		IP:   append([]byte(nil), peer.IP...),
		Port: peer.Port,
		Zone: peer.Zone,
	}
	tp := &trackedPeer{
		addr:         copied,
		srvConn:      srvConn,
		kalman:       NewKalmanOWDTracker(),
		lastSeenNano: now,
	}
	if len(sess.peers) >= MaxTrackedPeers {
		sess.peers = append(sess.peers[1:], tp)
	} else {
		sess.peers = append(sess.peers, tp)
	}
	return tp
}

func (sess *ReceiverSession) nextLiveFeedbackPeer() (*trackedPeer, bool) {
	now := time.Now().UnixNano()
	const peerExpiryNano = int64(2500 * time.Millisecond)

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.completed || len(sess.peers) == 0 {
		return nil, false
	}

	if sess.finalizing {
		// Emit periodic keepalives while hashing/unpacking large files so client never times out
		if now-sess.lastFinKeepalive < int64(500*time.Millisecond) {
			return nil, false
		}
		sess.lastFinKeepalive = now
		idx := sess.feedbackTurn % uint64(len(sess.peers))
		sess.feedbackTurn++
		return sess.peers[idx], true
	}

	live := sess.peers[:0]
	for _, p := range sess.peers {
		if now-p.lastSeenNano <= peerExpiryNano {
			live = append(live, p)
		}
	}
	sess.peers = live
	if len(sess.peers) == 0 {
		return nil, false
	}
	idx := sess.feedbackTurn % uint64(len(sess.peers))
	sess.feedbackTurn++
	return sess.peers[idx], false
}

func (sess *ReceiverSession) allPeers(fallback *net.UDPAddr, fallbackConn *net.UDPConn) []*trackedPeer {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.peers) == 0 {
		if fallback != nil {
			return []*trackedPeer{{addr: fallback, srvConn: fallbackConn}}
		}
		return nil
	}
	out := make([]*trackedPeer, len(sess.peers))
	copy(out, sess.peers)
	return out
}

func (sess *ReceiverSession) abortAndCleanup() {
	sess.mu.Lock()
	f := sess.file
	sess.file = nil
	staging := sess.stagingPath
	sess.completed = true
	sess.receivedBitmap = nil
	sess.pendingEqRing = nil
	sess.chunkToEqs = nil
	sess.pendingTeleports = nil
	sess.urgentNacks = nil
	sess.mu.Unlock()

	if f != nil {
		_ = f.Close()
	}
	if staging != "" {
		_ = os.Remove(staging)
	}
}

type inboundDatagram struct {
	bufPtr   *[]byte
	n        int
	peer     *net.UDPAddr
	srvConn  *net.UDPConn
	recvNano int64
}

type ServerConfig struct {
	ListenAddr     string
	PortSpan       int
	OutputDir      string
	MasterKey      [32]byte
	AllowOverwrite bool
	MaxFileSize    int64
	MaxSessions    int
	IdleTimeout    time.Duration
}

type OpenFIRServer struct {
	conns          []*net.UDPConn
	boundPorts     []uint16
	outputDir      string
	crypto         *WireCryptoEngine
	cookieSecret   [32]byte
	casStore       *GlobalCASStore
	allowOverwrite bool
	maxFileSize    int64
	maxSessions    int
	idleTimeout    time.Duration

	mu             sync.RWMutex
	sessions       map[uint64]*ReceiverSession
	sessionsBySID  map[uint32]*ReceiverSession
	completedTx    map[uint64]int64 // 90s anti-replay tombstones for completed/aborted TxIDs
	completedCount int32
	doneChan       chan struct{}
}

func NewOpenFIRServer(cfg ServerConfig) (*OpenFIRServer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	primaryConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	tuneUDPConn(primaryConn)

	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		_ = primaryConn.Close()
		return nil, err
	}
	cryptoEngine, err := NewWireCryptoEngine(cfg.MasterKey)
	if err != nil {
		_ = primaryConn.Close()
		return nil, err
	}

	if cfg.PortSpan <= 0 {
		cfg.PortSpan = DefaultServerPortSpan
	}
	if cfg.PortSpan > 32 {
		cfg.PortSpan = 32
	}

	primaryLocal := primaryConn.LocalAddr().(*net.UDPAddr)
	conns := []*net.UDPConn{primaryConn}
	boundPorts := []uint16{uint16(primaryLocal.Port)}

	for offset := 1; offset < cfg.PortSpan; offset++ {
		candPort := primaryLocal.Port + offset
		if candPort > 65535 {
			break
		}
		candAddr := &net.UDPAddr{IP: primaryLocal.IP, Port: candPort, Zone: primaryLocal.Zone}
		if extraConn, lErr := net.ListenUDP("udp", candAddr); lErr == nil {
			tuneUDPConn(extraConn)
			conns = append(conns, extraConn)
			boundPorts = append(boundPorts, uint16(candPort))
		}
	}

	var cookieSeed [32]byte
	_, _ = io.ReadFull(rand.Reader, cookieSeed[:])

	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 64 * 1024 * 1024 * 1024
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 30 * time.Second
	}

	return &OpenFIRServer{
		conns:          conns,
		boundPorts:     boundPorts,
		outputDir:      cfg.OutputDir,
		crypto:         cryptoEngine,
		cookieSecret:   cookieSeed,
		casStore:       NewGlobalCASStore(cfg.OutputDir),
		allowOverwrite: cfg.AllowOverwrite,
		maxFileSize:    cfg.MaxFileSize,
		maxSessions:    cfg.MaxSessions,
		idleTimeout:    cfg.IdleTimeout,
		sessions:       make(map[uint64]*ReceiverSession),
		sessionsBySID:  make(map[uint32]*ReceiverSession),
		completedTx:    make(map[uint64]int64),
		doneChan:       make(chan struct{}),
	}, nil
}

func (s *OpenFIRServer) LocalAddr() string {
	return s.conns[0].LocalAddr().String()
}

func (s *OpenFIRServer) BoundPorts() []uint16 {
	return s.boundPorts
}

func (s *OpenFIRServer) Close() {
	select {
	case <-s.doneChan:
	default:
		close(s.doneChan)
		for _, c := range s.conns {
			_ = c.Close()
		}
	}
	s.mu.Lock()
	for tid, sess := range s.sessions {
		sess.abortAndCleanup()
		delete(s.sessionsBySID, sess.sessionID)
		delete(s.sessions, tid)
	}
	s.mu.Unlock()
	s.casStore.Close()
}

func (s *OpenFIRServer) sendPreSessionOn(raw []byte, peer *net.UDPAddr, srvConn *net.UDPConn) {
	if peer == nil {
		return
	}
	if srvConn == nil {
		srvConn = s.conns[0]
	}
	wire := s.crypto.SealWith(raw, DirServerToClient, 0, makePreSessionSeq(), nil)
	_, _ = srvConn.WriteToUDP(wire, peer)
}

func (s *OpenFIRServer) sendSessionOn(sess *ReceiverSession, raw []byte, peer *net.UDPAddr, srvConn *net.UDPConn) {
	if peer == nil || sess == nil {
		return
	}
	if srvConn == nil {
		srvConn = s.conns[0]
	}
	seq := sess.nextS2CSeq()
	wire := s.crypto.SealWith(raw, DirServerToClient, sess.sessionID, seq, sess.aeadPair.s2cAEAD)
	_, _ = srvConn.WriteToUDP(wire, peer)
}

func (s *OpenFIRServer) sendError(sess *ReceiverSession, tid uint64, code uint8, msg string, peer *net.UDPAddr, srvConn *net.UDPConn) {
	msgBytes := []byte(msg)
	if len(msgBytes) > 512 {
		msgBytes = msgBytes[:512]
	}
	pkt := make([]byte, 3+8+1+2+len(msgBytes))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktError
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	pkt[11] = code
	binary.BigEndian.PutUint16(pkt[12:14], uint16(len(msgBytes)))
	copy(pkt[14:], msgBytes)
	if sess != nil && sess.aeadPair != nil {
		s.sendSessionOn(sess, pkt, peer, srvConn)
	} else {
		s.sendPreSessionOn(pkt, peer, srvConn)
	}
}

func (s *OpenFIRServer) computeStatelessCookie(peer *net.UDPAddr, tid uint64, slot int64) [CookieSize]byte {
	mac := hmac.New(sha256.New, s.cookieSecret[:])
	ip16 := peer.IP.To16()
	if ip16 != nil {
		mac.Write(ip16)
	} else {
		mac.Write(peer.IP)
	}
	var b [18]byte
	binary.BigEndian.PutUint16(b[0:2], uint16(peer.Port))
	binary.BigEndian.PutUint64(b[2:10], tid)
	binary.BigEndian.PutUint64(b[10:18], uint64(slot))
	mac.Write(b[:])
	sum := mac.Sum(nil)
	var out [CookieSize]byte
	copy(out[:], sum[:CookieSize])
	return out
}

func (s *OpenFIRServer) verifyStatelessCookie(peer *net.UDPAddr, tid uint64, cookie []byte) bool {
	if len(cookie) != CookieSize || peer == nil {
		return false
	}
	nowSlot := time.Now().Unix() / 30
	for delta := int64(0); delta <= 1; delta++ {
		expected := s.computeStatelessCookie(peer, tid, nowSlot-delta)
		if subtle.ConstantTimeCompare(cookie, expected[:]) == 1 {
			return true
		}
	}
	return false
}

func (s *OpenFIRServer) getSessionBySID(sid uint32) *ReceiverSession {
	s.mu.RLock()
	sess := s.sessionsBySID[sid]
	s.mu.RUnlock()
	return sess
}

func (s *OpenFIRServer) reapSessions() {
	now := time.Now().UnixNano()
	nowSec := now / int64(time.Second)
	idleLimitNano := int64(s.idleTimeout)
	const completedGraceNano = int64(5 * time.Second)
	const tombstoneTTLSec = 90

	s.mu.Lock()
	defer s.mu.Unlock()

	for tid, ts := range s.completedTx {
		if nowSec-ts > tombstoneTTLSec {
			delete(s.completedTx, tid)
		}
	}

	for tid, sess := range s.sessions {
		sess.mu.Lock()
		isDone := sess.completed
		isFinalizing := sess.finalizing
		doneAt := sess.completedAtNano
		sid := sess.sessionID
		sess.mu.Unlock()

		if isFinalizing && !isDone {
			// Never reap an active session currently executing fsync/SHA-256/unpack
			continue
		}

		if isDone {
			if doneAt > 0 && now-doneAt > completedGraceNano {
				s.completedTx[tid] = nowSec
				delete(s.sessionsBySID, sid)
				delete(s.sessions, tid)
			}
			continue
		}

		lastAct := atomic.LoadInt64(&sess.lastActivityNano)
		if lastAct > 0 && now-lastAct > idleLimitNano {
			sess.abortAndCleanup()
			s.completedTx[tid] = nowSec
			delete(s.sessionsBySID, sid)
			delete(s.sessions, tid)
		}
	}
}

func (s *OpenFIRServer) Serve(targetCompletions int) error {
	var completeOnce sync.Once
	completedChan := make(chan struct{})

	feedbackDone := make(chan struct{})
	defer close(feedbackDone)
	go func() {
		fbTicker := time.NewTicker(15 * time.Millisecond)
		reapTicker := time.NewTicker(2 * time.Second)
		defer fbTicker.Stop()
		defer reapTicker.Stop()
		for {
			select {
			case <-s.doneChan:
				return
			case <-feedbackDone:
				return
			case <-reapTicker.C:
				s.reapSessions()
			case <-fbTicker.C:
				s.mu.RLock()
				activeList := make([]*ReceiverSession, 0, len(s.sessions))
				for _, sess := range s.sessions {
					activeList = append(activeList, sess)
				}
				s.mu.RUnlock()

				for _, sess := range activeList {
					if tp, isFinKeepalive := sess.nextLiveFeedbackPeer(); tp != nil {
						if fErr := sess.getFatalError(); fErr != nil {
							s.sendError(sess, sess.transferID, 2, fErr.Error(), tp.addr, tp.srvConn)
						} else {
							s.sendFeedback(sess, tp, isFinKeepalive)
						}
					}
				}
			}
		}
	}()

	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	if numWorkers > 16 {
		numWorkers = 16
	}
	workQueue := make(chan inboundDatagram, 4096)
	var workerWG sync.WaitGroup

	checkTargetReached := func() {
		if targetCompletions > 0 && int(atomic.LoadInt32(&s.completedCount)) >= targetCompletions {
			completeOnce.Do(func() {
				go func() {
					time.Sleep(25 * time.Millisecond)
					close(completedChan)
				}()
			})
		}
	}

	for w := 0; w < numWorkers; w++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for item := range workQueue {
				wire := (*item.bufPtr)[:item.n]
				sid, seq, ok := s.crypto.PeekHeader(wire, DirClientToServer)
				if !ok {
					packetBufferPool.Put(item.bufPtr)
					continue
				}

				if sid == 0 {
					raw, decOK := s.crypto.OpenAfterPeek(wire, DirClientToServer, seq, nil)
					packetBufferPool.Put(item.bufPtr)
					if !decOK || len(raw) < 11 {
						continue
					}
					pktType := raw[2]
					tid := binary.BigEndian.Uint64(raw[3:11])
					if pktType == PktHandshake {
						sess, justCompleted := s.handleHandshake(tid, raw[11:], item.peer, item.srvConn)
						if sess != nil && justCompleted {
							checkTargetReached()
						}
					}
					continue
				}

				sess := s.getSessionBySID(sid)
				if sess == nil || sess.aeadPair == nil {
					packetBufferPool.Put(item.bufPtr)
					continue
				}
				raw, decOK := s.crypto.OpenAfterPeek(wire, DirClientToServer, seq, sess.aeadPair.c2sAEAD)
				packetBufferPool.Put(item.bufPtr)
				if !decOK || len(raw) < 11 {
					continue
				}

				pktType := raw[2]
				tid := binary.BigEndian.Uint64(raw[3:11])
				if tid != sess.transferID {
					continue
				}
				if !sess.replay.CheckAndAccept(seq) {
					continue
				}
				payload := raw[11:]
				peer := item.peer
				srvConn := item.srvConn

				sess.touchActivity()
				tp := sess.registerPeer(peer, srvConn)

				if fErr := sess.getFatalError(); fErr != nil {
					s.sendError(sess, tid, 2, fErr.Error(), peer, srvConn)
					continue
				}

				switch pktType {
				case PktData:
					s.handleData(sess, tp, payload, item.recvNano)
					if sess.checkAndFinalize(s, peer, srvConn) {
						checkTargetReached()
					}

				case PktTeleport:
					s.handleTeleport(sess, tp, payload, item.recvNano)
					if sess.checkAndFinalize(s, peer, srvConn) {
						checkTargetReached()
					}

				case PktCASTeleport:
					s.handleCASTeleport(sess, tp, payload, item.recvNano)
					if sess.checkAndFinalize(s, peer, srvConn) {
						checkTargetReached()
					}

				case PktPhiParity:
					s.handlePhiParity(sess, tp, payload, item.recvNano)
					if sess.checkAndFinalize(s, peer, srvConn) {
						checkTargetReached()
					}

				case PktFin:
					if sess.checkAndFinalize(s, peer, srvConn) {
						checkTargetReached()
					} else if tp != nil {
						s.sendFeedback(sess, tp, false)
					}

				case PktError:
					sess.abortAndCleanup()
					s.mu.Lock()
					s.completedTx[tid] = time.Now().Unix()
					delete(s.sessionsBySID, sess.sessionID)
					delete(s.sessions, tid)
					s.mu.Unlock()
				}
			}
		}()
	}

	var readerWG sync.WaitGroup
	for _, c := range s.conns {
		readerWG.Add(1)
		go func(conn *net.UDPConn) {
			defer readerWG.Done()
			for {
				select {
				case <-completedChan:
					return
				case <-s.doneChan:
					return
				default:
				}

				_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				bufPtr := packetBufferPool.Get().(*[]byte)
				n, peer, err := conn.ReadFromUDP(*bufPtr)
				recvNano := time.Now().UnixNano()
				if err != nil {
					packetBufferPool.Put(bufPtr)
					select {
					case <-s.doneChan:
						return
					case <-completedChan:
						return
					default:
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					continue
				}

				if n < OuterHeaderSize+19 || n > MaxUDPPacketSize+256 {
					packetBufferPool.Put(bufPtr)
					continue
				}

				select {
				case workQueue <- inboundDatagram{
					bufPtr:   bufPtr,
					n:        n,
					peer:     peer,
					srvConn:  conn,
					recvNano: recvNano,
				}:
				case <-completedChan:
					packetBufferPool.Put(bufPtr)
					return
				case <-s.doneChan:
					packetBufferPool.Put(bufPtr)
					return
				}
			}
		}(c)
	}

	select {
	case <-completedChan:
	case <-s.doneChan:
	}

	readerWG.Wait()
	close(workQueue)
	workerWG.Wait()
	return nil
}

func (s *OpenFIRServer) handleHandshake(tid uint64, p []byte, peer *net.UDPAddr, srvConn *net.UDPConn) (*ReceiverSession, bool) {
	if len(p) < 99 {
		return nil, false
	}
	cookie := p[0:16]
	clientPubBytes := p[16:48]
	fileSize := int64(binary.BigEndian.Uint64(p[48:56]))
	chunkSize := int(binary.BigEndian.Uint32(p[56:60]))
	totalChunks := binary.BigEndian.Uint32(p[60:64])
	var expectedHash [32]byte
	copy(expectedHash[:], p[64:96])
	flags := p[96]
	nameLen := int(binary.BigEndian.Uint16(p[97:99]))
	if nameLen <= 0 || nameLen > 255 || len(p) < 99+nameLen {
		s.sendError(nil, tid, 1, "invalid filename length in handshake", peer, srvConn)
		return nil, false
	}

	rawName := string(p[99 : 99+nameLen])
	if strings.ContainsRune(rawName, 0) {
		s.sendError(nil, tid, 1, "invalid filename characters in handshake", peer, srvConn)
		return nil, false
	}
	fileName := filepath.Base(filepath.Clean(rawName))
	if fileName == "." || fileName == ".." || fileName == "/" || fileName == "\\" || fileName == "" || filepath.VolumeName(fileName) != "" {
		s.sendError(nil, tid, 1, "invalid target filename in handshake", peer, srvConn)
		return nil, false
	}

	if chunkSize != DefaultChunkSize {
		s.sendError(nil, tid, 1, fmt.Sprintf("unsupported chunk size %d (expected %d)", chunkSize, DefaultChunkSize), peer, srvConn)
		return nil, false
	}
	if fileSize < 0 || fileSize > s.maxFileSize {
		s.sendError(nil, tid, 1, fmt.Sprintf("file size %d exceeds server limit %d", fileSize, s.maxFileSize), peer, srvConn)
		return nil, false
	}
	var expectedChunks uint64 = 0
	if fileSize > 0 {
		expectedChunks = (uint64(fileSize) + uint64(chunkSize) - 1) / uint64(chunkSize)
	}
	if expectedChunks >= math.MaxUint32 || uint64(totalChunks) != expectedChunks {
		s.sendError(nil, tid, 1, "totalChunks does not match fileSize and chunkSize", peer, srvConn)
		return nil, false
	}
	if flags != FlagSingleFile && flags != FlagDirectoryBundle {
		s.sendError(nil, tid, 1, "invalid transfer flags", peer, srvConn)
		return nil, false
	}

	if !s.verifyStatelessCookie(peer, tid, cookie) {
		nowSlot := time.Now().Unix() / 30
		newCookie := s.computeStatelessCookie(peer, tid, nowSlot)
		chal := make([]byte, 3+8+CookieSize)
		chal[0] = ProtocolMagic0
		chal[1] = ProtocolMagic1
		chal[2] = PktCookieChallenge
		binary.BigEndian.PutUint64(chal[3:11], tid)
		copy(chal[11:27], newCookie[:])
		s.sendPreSessionOn(chal, peer, srvConn)
		return nil, false
	}

	cliPub, err := ecdh.X25519().NewPublicKey(clientPubBytes)
	if err != nil {
		s.sendError(nil, tid, 1, "invalid X25519 public key in handshake", peer, srvConn)
		return nil, false
	}

	finalOutPath := filepath.Join(s.outputDir, fileName)

	s.mu.Lock()
	// Anti-replay tombstone check prevents 60s cookie replay from re-creating a finished session
	if _, tombstoned := s.completedTx[tid]; tombstoned {
		s.mu.Unlock()
		return nil, false
	}
	sess, exists := s.sessions[tid]
	if !exists {
		if len(s.sessions) >= s.maxSessions {
			s.mu.Unlock()
			s.sendError(nil, tid, 1, "server max concurrent sessions reached", peer, srvConn)
			return nil, false
		}
		if !s.allowOverwrite {
			if _, statErr := os.Stat(finalOutPath); statErr == nil {
				s.mu.Unlock()
				s.sendError(nil, tid, 1, "destination already exists on server (enable -overwrite to allow)", peer, srvConn)
				return nil, false
			}
		}

		srvPriv, kErr := ecdh.X25519().GenerateKey(rand.Reader)
		if kErr != nil {
			s.mu.Unlock()
			s.sendError(nil, tid, 2, "failed to generate ephemeral X25519 key", peer, srvConn)
			return nil, false
		}
		sharedSecret, eErr := srvPriv.ECDH(cliPub)
		if eErr != nil {
			s.mu.Unlock()
			s.sendError(nil, tid, 1, "X25519 key agreement failed", peer, srvConn)
			return nil, false
		}

		var sid uint32
		for {
			sid = cryptoRandUint32()
			if sid != 0 && s.sessionsBySID[sid] == nil {
				break
			}
		}
		aeadPair, aErr := deriveSessionAEAD(s.crypto.masterKey, sharedSecret, tid, sid)
		if aErr != nil {
			s.mu.Unlock()
			s.sendError(nil, tid, 2, "failed to derive PFS session cipher", peer, srvConn)
			return nil, false
		}

		stagingPath := filepath.Join(s.outputDir, fmt.Sprintf(".%s.openfir-part-%x", fileName, tid))
		f, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			s.mu.Unlock()
			s.sendError(nil, tid, 2, fmt.Sprintf("failed to create staging file: %v", err), peer, srvConn)
			return nil, false
		}
		if fileSize > 0 {
			if err := f.Truncate(fileSize); err != nil {
				_ = f.Close()
				_ = os.Remove(stagingPath)
				s.mu.Unlock()
				s.sendError(nil, tid, 2, fmt.Sprintf("failed to allocate disk space: %v", err), peer, srvConn)
				return nil, false
			}
		}

		sess = &ReceiverSession{
			transferID:       tid,
			sessionID:        sid,
			serverPubBytes:   srvPriv.PublicKey().Bytes(),
			aeadPair:         aeadPair,
			s2cSeqGen:        1,
			fileName:         fileName,
			fileSize:         fileSize,
			chunkSize:        chunkSize,
			totalChunks:      totalChunks,
			flags:            flags,
			expectedSHA256:   expectedHash,
			file:             f,
			stagingPath:      stagingPath,
			finalOutputPath:  finalOutPath,
			receivedBitmap:   NewCompactBitset(totalChunks),
			lastActivityNano: time.Now().UnixNano(),
			chunkToEqs:       make(map[uint32][]*ParityEquation),
			pendingTeleports: make(map[uint32][]uint32),
			startTime:        time.Now(),
		}
		s.sessions[tid] = sess
		s.sessionsBySID[sid] = sess
		modeStr := "SingleFile"
		if flags == FlagDirectoryBundle {
			modeStr = "DirectoryBundle"
		}
		fmt.Printf("[Server] Session initialized (%s, X25519-PFS): target=%s size=%d bytes chunks=%d\n",
			modeStr, fileName, fileSize, totalChunks)
	}
	s.mu.Unlock()

	sess.touchActivity()
	sess.registerPeer(peer, srvConn)

	casCount, casBloom := s.casStore.SnapshotBloom()
	portCount := len(s.boundPorts)
	if portCount > 32 {
		portCount = 32
	}

	ack := make([]byte, 11+4+4+X25519PubSize+4+CASBloomBytes+1+portCount*2)
	ack[0] = ProtocolMagic0
	ack[1] = ProtocolMagic1
	ack[2] = PktHandshakeAck
	binary.BigEndian.PutUint64(ack[3:11], tid)
	sess.mu.Lock()
	hc := sess.highestContig
	sid := sess.sessionID
	srvPub := sess.serverPubBytes
	sess.mu.Unlock()
	binary.BigEndian.PutUint32(ack[11:15], hc)
	binary.BigEndian.PutUint32(ack[15:19], sid)
	copy(ack[19:51], srvPub)
	binary.BigEndian.PutUint32(ack[51:55], casCount)
	copy(ack[55:55+CASBloomBytes], casBloom[:])
	pOff := 55 + CASBloomBytes
	ack[pOff] = uint8(portCount)
	pOff++
	for i := 0; i < portCount; i++ {
		binary.BigEndian.PutUint16(ack[pOff:pOff+2], s.boundPorts[i])
		pOff += 2
	}
	s.sendPreSessionOn(ack, peer, srvConn)

	if sess.totalChunks == 0 {
		done := sess.checkAndFinalize(s, peer, srvConn)
		return sess, done
	}
	return sess, false
}

func (s *OpenFIRServer) handleData(sess *ReceiverSession, tp *trackedPeer, p []byte, recvNano int64) {
	if len(p) < 14 {
		return
	}
	idx := binary.BigEndian.Uint32(p[0:4])
	sendNano := int64(binary.BigEndian.Uint64(p[4:12]))
	dataLen := int(binary.BigEndian.Uint16(p[12:14]))
	if len(p) < 14+dataLen {
		return
	}
	if tp != nil && tp.kalman != nil {
		tp.kalman.Observe(sendNano, recvNano)
	}
	sess.commitChunkIterative(idx, p[14:14+dataLen], "data")
}

func (s *OpenFIRServer) handleTeleport(sess *ReceiverSession, tp *trackedPeer, p []byte, recvNano int64) {
	if len(p) < 16 {
		return
	}
	targetIdx := binary.BigEndian.Uint32(p[0:4])
	sourceIdx := binary.BigEndian.Uint32(p[4:8])
	sendNano := int64(binary.BigEndian.Uint64(p[8:16]))

	if tp != nil && tp.kalman != nil {
		tp.kalman.Observe(sendNano, recvNano)
	}

	if targetIdx >= sess.totalChunks {
		return
	}

	// Fast path: reserved ZeroChunkSentinel skips disk read completely
	if sourceIdx == ZeroChunkSentinel {
		expLen := expectedChunkLen(targetIdx, sess.totalChunks, sess.fileSize, sess.chunkSize)
		if expLen > 0 {
			sess.commitChunkIterative(targetIdx, make([]byte, expLen), "zero")
		}
		return
	}

	if sourceIdx >= sess.totalChunks || sourceIdx == targetIdx {
		return
	}

	sess.mu.Lock()
	if sess.completed || sess.receivedBitmap == nil {
		sess.mu.Unlock()
		return
	}
	hasTarget := sess.receivedBitmap.Get(targetIdx)
	hasSource := sess.receivedBitmap.Get(sourceIdx)
	if hasTarget && hasSource {
		sess.mu.Unlock()
		return
	}
	// Bidirectional GF(2) equality edge (Target XOR Source == 0): heal whichever side is missing!
	if !hasSource && !hasTarget {
		if len(sess.pendingTeleports[sourceIdx]) < 4096 {
			sess.pendingTeleports[sourceIdx] = append(sess.pendingTeleports[sourceIdx], targetIdx)
		}
		if len(sess.pendingTeleports[targetIdx]) < 4096 {
			sess.pendingTeleports[targetIdx] = append(sess.pendingTeleports[targetIdx], sourceIdx)
		}
		sess.mu.Unlock()
		return
	}
	sess.mu.Unlock()

	src, dst := sourceIdx, targetIdx
	if hasTarget && !hasSource {
		src, dst = targetIdx, sourceIdx
	}
	expLen := expectedChunkLen(dst, sess.totalChunks, sess.fileSize, sess.chunkSize)
	srcLen := expectedChunkLen(src, sess.totalChunks, sess.fileSize, sess.chunkSize)
	if expLen <= 0 || expLen != srcLen {
		return
	}
	buf := make([]byte, expLen)
	if sess.readChunkFast(src, buf) {
		sess.commitChunkIterative(dst, buf, "teleport")
	}
}

func (s *OpenFIRServer) handleCASTeleport(sess *ReceiverSession, tp *trackedPeer, p []byte, recvNano int64) {
	if len(p) < 44 {
		return
	}
	targetIdx := binary.BigEndian.Uint32(p[0:4])
	var digest [32]byte
	copy(digest[:], p[4:36])
	sendNano := int64(binary.BigEndian.Uint64(p[36:44]))

	if tp != nil && tp.kalman != nil {
		tp.kalman.Observe(sendNano, recvNano)
	}

	if targetIdx >= sess.totalChunks {
		return
	}

	sess.mu.Lock()
	if sess.completed || sess.receivedBitmap == nil || sess.receivedBitmap.Get(targetIdx) {
		sess.mu.Unlock()
		return
	}
	sess.mu.Unlock()

	expLen := expectedChunkLen(targetIdx, sess.totalChunks, sess.fileSize, sess.chunkSize)
	if expLen <= 0 {
		return
	}

	if chunkBytes, ok := s.casStore.ReadVerifiedChunk(digest, expLen); ok {
		sess.commitChunkIterative(targetIdx, chunkBytes, "cas")
		return
	}

	sess.mu.Lock()
	if !sess.completed && sess.receivedBitmap != nil && !sess.receivedBitmap.Get(targetIdx) {
		sess.statsCASMisses++
		if len(sess.urgentNacks) < MaxUrgentNacks {
			sess.urgentNacks = append(sess.urgentNacks, targetIdx)
		}
	}
	sess.mu.Unlock()
}

func (s *OpenFIRServer) handlePhiParity(sess *ReceiverSession, tp *trackedPeer, p []byte, recvNano int64) {
	if len(p) < 11 {
		return
	}
	sendNano := int64(binary.BigEndian.Uint64(p[0:8]))
	if tp != nil && tp.kalman != nil {
		tp.kalman.Observe(sendNano, recvNano)
	}

	count := int(p[8])
	if count < 2 || count > 8 || len(p) < 9+count*4+2 {
		return
	}
	members := make([]uint32, count)
	offset := 9
	for i := 0; i < count; i++ {
		m := binary.BigEndian.Uint32(p[offset : offset+4])
		offset += 4
		if m >= sess.totalChunks {
			return
		}
		for j := 0; j < i; j++ {
			if members[j] == m {
				return
			}
		}
		members[i] = m
	}
	parityLen := int(binary.BigEndian.Uint16(p[offset : offset+2]))
	offset += 2
	if parityLen != sess.chunkSize || len(p) < offset+parityLen {
		return
	}
	xorPayload := make([]byte, parityLen)
	copy(xorPayload, p[offset:offset+parityLen])

	eq := &ParityEquation{
		members:    members,
		xorPayload: xorPayload,
	}
	sess.processOrEnqueueEquation(eq)
}

func (sess *ReceiverSession) commitChunkIterative(initialIdx uint32, initialData []byte, initialSource string) {
	queue := []commitWorkItem{{idx: initialIdx, data: initialData, source: initialSource}}
	tmpBuf := make([]byte, sess.chunkSize)

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		idx := item.idx
		data := item.data
		if idx >= sess.totalChunks {
			continue
		}
		expLen := expectedChunkLen(idx, sess.totalChunks, sess.fileSize, sess.chunkSize)
		if expLen <= 0 || len(data) < expLen {
			continue
		}
		if len(data) > expLen {
			data = data[:expLen]
		}

		sess.mu.Lock()
		if sess.completed || sess.fatalErr != nil || sess.file == nil || sess.receivedBitmap == nil {
			sess.mu.Unlock()
			return
		}
		if sess.receivedBitmap.Get(idx) {
			sess.statsDuplicatePkts++
			sess.mu.Unlock()
			continue
		}
		f := sess.file
		sess.mu.Unlock()

		offset := int64(idx) * int64(sess.chunkSize)
		if _, err := f.WriteAt(data, offset); err != nil {
			sess.setFatalError(fmt.Errorf("receiver disk write failed: %w", err))
			return
		}

		sess.mu.Lock()
		if sess.completed || sess.receivedBitmap == nil || sess.receivedBitmap.Get(idx) {
			sess.mu.Unlock()
			continue
		}
		sess.receivedBitmap.Set(idx)
		sess.receivedCount++
		sess.cacheChunkLocked(idx, data)

		switch item.source {
		case "data":
			sess.statsDataChunks++
		case "teleport":
			sess.statsTeleportChunks++
		case "zero":
			sess.statsZeroChunks++
		case "cas":
			sess.statsCASTeleportChunks++
		case "parity":
			sess.statsParityHealed++
		}
		for sess.highestContig < sess.totalChunks && sess.receivedBitmap.Get(sess.highestContig) {
			sess.highestContig++
		}

		waitingTeleports := sess.pendingTeleports[idx]
		delete(sess.pendingTeleports, idx)

		// O(1) Bipartite Graph adjacency lookup: inspect ONLY equations referencing idx!
		var readyEquations []*ParityEquation
		if eqs := sess.chunkToEqs[idx]; len(eqs) > 0 {
			delete(sess.chunkToEqs, idx)
			for _, eq := range eqs {
				if eq.resolved || eq.evicted {
					continue
				}
				missingCount := 0
				for _, m := range eq.members {
					if !sess.receivedBitmap.Get(m) {
						missingCount++
					}
				}
				if missingCount == 0 {
					eq.resolved = true
				} else if missingCount == 1 {
					eq.resolved = true
					readyEquations = append(readyEquations, eq)
				}
			}
		}
		sess.mu.Unlock()

		for _, tIdx := range waitingTeleports {
			if expectedChunkLen(tIdx, sess.totalChunks, sess.fileSize, sess.chunkSize) == len(data) {
				cloned := make([]byte, len(data))
				copy(cloned, data)
				queue = append(queue, commitWorkItem{idx: tIdx, data: cloned, source: "teleport"})
			}
		}

		for _, eq := range readyEquations {
			if healedIdx, healedBytes, ok := sess.resolveEquation(eq, tmpBuf); ok {
				queue = append(queue, commitWorkItem{idx: healedIdx, data: healedBytes, source: "parity"})
			}
		}
	}
}

func (sess *ReceiverSession) processOrEnqueueEquation(eq *ParityEquation) {
	sess.mu.Lock()
	if sess.completed || sess.receivedBitmap == nil {
		sess.mu.Unlock()
		return
	}
	missingCount := 0
	for _, m := range eq.members {
		if !sess.receivedBitmap.Get(m) {
			missingCount++
		}
	}
	if missingCount == 0 {
		sess.mu.Unlock()
		return
	}
	if missingCount > 1 {
		if len(sess.pendingEqRing) >= MaxPendingParity {
			old := sess.pendingEqRing[0]
			old.evicted = true
			sess.pendingEqRing = sess.pendingEqRing[1:]
		}
		sess.pendingEqRing = append(sess.pendingEqRing, eq)
		for _, m := range eq.members {
			if !sess.receivedBitmap.Get(m) {
				sess.chunkToEqs[m] = append(sess.chunkToEqs[m], eq)
			}
		}
		sess.mu.Unlock()
		return
	}
	eq.resolved = true
	sess.mu.Unlock()

	tmpBuf := make([]byte, sess.chunkSize)
	if healedIdx, healedBytes, ok := sess.resolveEquation(eq, tmpBuf); ok {
		sess.commitChunkIterative(healedIdx, healedBytes, "parity")
	}
}

func (sess *ReceiverSession) resolveEquation(eq *ParityEquation, tmpBuf []byte) (uint32, []byte, bool) {
	sess.mu.Lock()
	if sess.completed || sess.receivedBitmap == nil {
		sess.mu.Unlock()
		return 0, nil, false
	}
	var missingIdx uint32 = math.MaxUint32
	missingCount := 0
	for _, m := range eq.members {
		if m < sess.totalChunks && !sess.receivedBitmap.Get(m) {
			missingIdx = m
			missingCount++
		}
	}
	sess.mu.Unlock()

	if missingCount != 1 || missingIdx == math.MaxUint32 {
		return 0, nil, false
	}

	healed := make([]byte, sess.chunkSize)
	copy(healed, eq.xorPayload)

	for _, m := range eq.members {
		if m == missingIdx {
			continue
		}
		expLen := expectedChunkLen(m, sess.totalChunks, sess.fileSize, sess.chunkSize)
		if expLen <= 0 || !sess.readChunkFast(m, tmpBuf[:expLen]) {
			return 0, nil, false
		}
		for b := 0; b < expLen; b++ {
			healed[b] ^= tmpBuf[b]
		}
	}

	targetLen := expectedChunkLen(missingIdx, sess.totalChunks, sess.fileSize, sess.chunkSize)
	if targetLen <= 0 {
		return 0, nil, false
	}
	return missingIdx, healed[:targetLen], true
}

func (s *OpenFIRServer) sendFeedback(sess *ReceiverSession, tp *trackedPeer, isFinKeepalive bool) {
	sess.mu.Lock()
	if sess.completed {
		sess.mu.Unlock()
		return
	}
	hc := sess.highestContig
	rc := sess.receivedCount
	total := sess.totalChunks
	casHits := uint32(sess.statsCASTeleportChunks)
	casMisses := uint32(sess.statsCASMisses)
	healedSignal := sess.statsParityHealed > sess.lastReportedHealed
	sess.lastReportedHealed = sess.statsParityHealed

	var nacks []uint32
	scanLimit := hc
	if !isFinKeepalive && sess.receivedBitmap != nil {
		if len(sess.urgentNacks) > 0 {
			remUrgent := sess.urgentNacks[:0]
			for _, uIdx := range sess.urgentNacks {
				if uIdx >= hc && uIdx < total && !sess.receivedBitmap.Get(uIdx) {
					if len(nacks) < MaxNackPerPacket {
						nacks = append(nacks, uIdx)
					} else {
						remUrgent = append(remUrgent, uIdx)
					}
				}
			}
			sess.urgentNacks = remUrgent
		}

		scanIdx := hc
		maxScan := hc + FeedbackScanWindow
		if maxScan > total || maxScan < hc {
			maxScan = total
		}
		for ; scanIdx < maxScan && len(nacks) < MaxNackPerPacket; scanIdx++ {
			if !sess.receivedBitmap.Get(scanIdx) {
				nacks = append(nacks, scanIdx)
			}
		}
		scanLimit = scanIdx
	} else {
		scanLimit = total
	}
	sess.mu.Unlock()

	var gradUs, queueUs int64
	if tp != nil && tp.kalman != nil {
		gradUs, queueUs = tp.kalman.Snapshot()
	}

	nackHeaderField := uint16(len(nacks) & 0x3FFF)
	if healedSignal {
		nackHeaderField |= 0x8000
	}
	if isFinKeepalive {
		nackHeaderField |= 0x4000
	}

	pkt := make([]byte, 49+len(nacks)*4)
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktFeedback
	binary.BigEndian.PutUint64(pkt[3:11], sess.transferID)
	binary.BigEndian.PutUint32(pkt[11:15], hc)
	binary.BigEndian.PutUint32(pkt[15:19], scanLimit)
	binary.BigEndian.PutUint32(pkt[19:23], rc)
	binary.BigEndian.PutUint64(pkt[23:31], uint64(gradUs))
	binary.BigEndian.PutUint64(pkt[31:39], uint64(queueUs))
	binary.BigEndian.PutUint32(pkt[39:43], casHits)
	binary.BigEndian.PutUint32(pkt[43:47], casMisses)
	binary.BigEndian.PutUint16(pkt[47:49], nackHeaderField)

	offset := 49
	for _, nackIdx := range nacks {
		binary.BigEndian.PutUint32(pkt[offset:offset+4], nackIdx)
		offset += 4
	}
	s.sendSessionOn(sess, pkt, tp.addr, tp.srvConn)
}

func (sess *ReceiverSession) checkAndFinalize(s *OpenFIRServer, fallbackPeer *net.UDPAddr, fallbackConn *net.UDPConn) bool {
	sess.mu.Lock()
	if sess.receivedCount < sess.totalChunks {
		sess.mu.Unlock()
		return false
	}
	if sess.completed {
		verified := sess.verifiedOK
		tid := sess.transferID
		sess.mu.Unlock()
		s.broadcastFinAck(sess, tid, verified, fallbackPeer, fallbackConn)
		return true
	}
	if sess.finalizing {
		sess.mu.Unlock()
		return false
	}
	sess.finalizing = true
	f := sess.file
	sess.mu.Unlock()

	_ = f.Sync()
	_, _ = f.Seek(0, io.SeekStart)
	h := sha256.New()
	_, _ = io.Copy(h, f)
	var actualHash [32]byte
	copy(actualHash[:], h.Sum(nil))
	hashMatch := (actualHash == sess.expectedSHA256)

	extractedFiles := 1
	var commitErr error
	if hashMatch {
		if sess.flags == FlagDirectoryBundle {
			s.casStore.EvictPath(sess.finalOutputPath)
			cnt, err := unpackDirectoryBundle(f, sess.fileSize, sess.finalOutputPath)
			_ = f.Close()
			_ = os.Remove(sess.stagingPath)
			if err != nil {
				hashMatch = false
				commitErr = err
			} else {
				extractedFiles = cnt
				s.casStore.IndexPath(sess.finalOutputPath)
			}
		} else {
			_ = f.Close()
			if err := atomicReplaceFile(sess.stagingPath, sess.finalOutputPath, s.allowOverwrite, s.casStore); err != nil {
				_ = os.Remove(sess.stagingPath)
				hashMatch = false
				commitErr = err
			} else {
				s.casStore.IndexPath(sess.finalOutputPath)
			}
		}
	} else {
		_ = f.Close()
		_ = os.Remove(sess.stagingPath)
	}

	sess.mu.Lock()
	sess.file = nil
	sess.verifiedOK = hashMatch
	sess.completed = true
	sess.completedAtNano = time.Now().UnixNano()
	sess.receivedBitmap = nil
	sess.pendingEqRing = nil
	sess.chunkToEqs = nil
	sess.pendingTeleports = nil
	sess.urgentNacks = nil
	tid := sess.transferID

	elapsed := time.Since(sess.startTime).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	mbps := (float64(sess.fileSize) / (1024 * 1024)) / elapsed
	fmt.Printf("\n====================================================================\n")
	fmt.Printf("[Server] Transfer Complete! Target: %s (%.2f MB, %d item(s))\n",
		sess.finalOutputPath, float64(sess.fileSize)/(1024*1024), extractedFiles)
	fmt.Printf("  ├─ Elapsed & Goodput : %.3f s (Effective Goodput: %.2f MB/s)\n", elapsed, mbps)
	fmt.Printf("  ├─ Chunk Breakdown   : Data=%d | Teleported=%d | Zero=%d | CASTeleported=%d | PhiParityHealed=%d\n",
		sess.statsDataChunks, sess.statsTeleportChunks, sess.statsZeroChunks, sess.statsCASTeleportChunks, sess.statsParityHealed)
	fmt.Printf("  └─ SHA-256 Verified  : %v (%s...)\n", sess.verifiedOK, hex.EncodeToString(actualHash[:8]))
	if commitErr != nil {
		fmt.Printf("  └─ Commit Error      : %v\n", commitErr)
	}
	fmt.Printf("====================================================================\n")
	sess.mu.Unlock()

	atomic.AddInt32(&s.completedCount, 1)
	if commitErr != nil {
		s.sendError(sess, tid, 2, commitErr.Error(), fallbackPeer, fallbackConn)
	}
	s.broadcastFinAck(sess, tid, hashMatch, fallbackPeer, fallbackConn)
	return true
}

func (s *OpenFIRServer) broadcastFinAck(sess *ReceiverSession, tid uint64, verified bool, fallbackPeer *net.UDPAddr, fallbackConn *net.UDPConn) {
	finAck := make([]byte, 12)
	finAck[0] = ProtocolMagic0
	finAck[1] = ProtocolMagic1
	finAck[2] = PktFinAck
	binary.BigEndian.PutUint64(finAck[3:11], tid)
	if verified {
		finAck[11] = 1
	} else {
		finAck[11] = 0
	}

	peers := sess.allPeers(fallbackPeer, fallbackConn)
	for round := 0; round < 3; round++ {
		for _, p := range peers {
			s.sendSessionOn(sess, finAck, p.addr, p.srvConn)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ============================================================================
// Module 7: OpenFIR Multi-Path Sender Engine (Zero-Leak Rotation & PFS)
// ============================================================================

type ClientConfig struct {
	ServerAddr  string
	MasterKey   [32]byte
	NumSockets  int
	InitMBps    float64
	MaxMBps     float64
	IdleTimeout time.Duration
	Chaos       *ChaosSimulator
}

type OpenFIRClient struct {
	connMu              sync.RWMutex
	conns               []*net.UDPConn
	drainingConns       map[*net.UDPConn]struct{}
	socketBytes         []uint64
	unansweredSinceNano []int64
	socketDestPortIdx   []uint32
	serverPorts         []uint16
	serverAddr          *net.UDPAddr
	crypto              *WireCryptoEngine
	sessMu              sync.RWMutex
	sessionID           uint32
	sessionAEAD         *SessionAEADPair
	replay              ReplayWindow
	seqGen              uint64
	pacer               *MicroPacer
	idleTimeout         time.Duration
	chaos               *ChaosSimulator
	closed              atomic.Bool
}

func NewOpenFIRClient(cfg ClientConfig) (*OpenFIRClient, error) {
	if cfg.NumSockets < 1 {
		cfg.NumSockets = 1
	}
	if cfg.NumSockets > 64 {
		cfg.NumSockets = 64
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 20 * time.Second
	}
	raddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return nil, err
	}
	cryptoEngine, err := NewWireCryptoEngine(cfg.MasterKey)
	if err != nil {
		return nil, err
	}

	conns := make([]*net.UDPConn, 0, cfg.NumSockets)
	destIdx := make([]uint32, cfg.NumSockets)

	for i := 0; i < cfg.NumSockets; i++ {
		conn, err := bindClientUDPSocket()
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, err
		}
		conns = append(conns, conn)
		destIdx[i] = uint32(i)
	}
	return &OpenFIRClient{
		conns:               conns,
		drainingConns:       make(map[*net.UDPConn]struct{}),
		socketBytes:         make([]uint64, len(conns)),
		unansweredSinceNano: make([]int64, len(conns)),
		socketDestPortIdx:   destIdx,
		serverPorts:         []uint16{uint16(raddr.Port)},
		serverAddr:          raddr,
		crypto:              cryptoEngine,
		seqGen:              1,
		pacer:               NewMicroPacer(cfg.InitMBps, 2.0, cfg.MaxMBps),
		idleTimeout:         cfg.IdleTimeout,
		chaos:               cfg.Chaos,
	}, nil
}

func (c *OpenFIRClient) Close() {
	c.closed.Store(true)
	c.connMu.Lock()
	for _, conn := range c.conns {
		_ = conn.Close()
	}
	for conn := range c.drainingConns {
		_ = conn.Close()
		delete(c.drainingConns, conn)
	}
	c.connMu.Unlock()
}

func (c *OpenFIRClient) deadPathGraceNano() int64 {
	c.connMu.RLock()
	n := len(c.conns)
	c.connMu.RUnlock()
	// Dynamically scale grace period to 4 full server round-robin feedback cycles + 300ms margin
	grace := int64(n*4*15)*int64(time.Millisecond) + int64(300*time.Millisecond)
	if grace < DeadPathSilenceNano {
		grace = DeadPathSilenceNano
	}
	return grace
}

func (c *OpenFIRClient) rotateSocketSlot(connIdx int, onRotate func(*net.UDPConn, int)) {
	if c.closed.Load() {
		return
	}
	freshConn, err := bindClientUDPSocket()
	if err != nil {
		return
	}
	c.connMu.Lock()
	if c.closed.Load() || connIdx < 0 || connIdx >= len(c.conns) {
		c.connMu.Unlock()
		_ = freshConn.Close()
		return
	}
	oldConn := c.conns[connIdx]
	c.conns[connIdx] = freshConn
	c.drainingConns[oldConn] = struct{}{}
	atomic.StoreUint64(&c.socketBytes[connIdx], 0)
	atomic.StoreInt64(&c.unansweredSinceNano[connIdx], 0)
	atomic.AddUint32(&c.socketDestPortIdx[connIdx], 1)
	c.connMu.Unlock()

	if onRotate != nil {
		onRotate(freshConn, connIdx)
	}

	// Reclaim retired socket & its reader goroutine after 2s grace (zero FD/goroutine leak on 100GB+ transfers)
	time.AfterFunc(2*time.Second, func() {
		c.connMu.Lock()
		delete(c.drainingConns, oldConn)
		c.connMu.Unlock()
		_ = oldConn.Close()
	})
}

func (c *OpenFIRClient) sendPreSession(raw []byte) {
	if c.chaos != nil && c.chaos.ShouldDrop() {
		return
	}
	wire := c.crypto.SealWith(raw, DirClientToServer, 0, makePreSessionSeq(), nil)
	c.connMu.RLock()
	conn := c.conns[0]
	c.connMu.RUnlock()
	_, _ = conn.WriteToUDP(wire, c.serverAddr)
}

func (c *OpenFIRClient) sendCloaked(raw []byte, onRotate func(*net.UDPConn, int)) {
	if c.chaos != nil && c.chaos.ShouldDrop() {
		return
	}
	c.sessMu.RLock()
	sid := c.sessionID
	aead := cipher.AEAD(nil)
	if c.sessionAEAD != nil {
		aead = c.sessionAEAD.c2sAEAD
	}
	c.sessMu.RUnlock()

	seq := atomic.AddUint64(&c.seqGen, 1)
	wire := c.crypto.SealWith(raw, DirClientToServer, sid, seq, aead)
	nowNano := time.Now().UnixNano()

	c.connMu.RLock()
	connIdx := int(seq % uint64(len(c.conns)))
	conn := c.conns[connIdx]
	newBytes := atomic.AddUint64(&c.socketBytes[connIdx], uint64(len(wire)))
	atomic.CompareAndSwapInt64(&c.unansweredSinceNano[connIdx], 0, nowNano)
	sinceUnanswered := atomic.LoadInt64(&c.unansweredSinceNano[connIdx])
	destIdx := atomic.LoadUint32(&c.socketDestPortIdx[connIdx])

	target := c.serverAddr
	if len(c.serverPorts) > 1 {
		chosenPort := int(c.serverPorts[destIdx%uint32(len(c.serverPorts))])
		if chosenPort > 0 && chosenPort != c.serverAddr.Port {
			target = &net.UDPAddr{IP: c.serverAddr.IP, Port: chosenPort, Zone: c.serverAddr.Zone}
		}
	}
	c.connMu.RUnlock()

	_, _ = conn.WriteToUDP(wire, target)

	if onRotate == nil {
		return
	}

	if newBytes >= SocketRotateByteQuota {
		if atomic.CompareAndSwapUint64(&c.socketBytes[connIdx], newBytes, 0) {
			c.rotateSocketSlot(connIdx, onRotate)
			return
		}
	}

	grace := c.deadPathGraceNano()
	if sinceUnanswered > 0 && nowNano-sinceUnanswered > grace {
		if atomic.CompareAndSwapInt64(&c.unansweredSinceNano[connIdx], sinceUnanswered, 0) {
			c.rotateSocketSlot(connIdx, onRotate)
		}
	}
}

func (c *OpenFIRClient) sendError(tid uint64, msg string) {
	msgBytes := []byte(msg)
	if len(msgBytes) > 256 {
		msgBytes = msgBytes[:256]
	}
	pkt := make([]byte, 3+8+1+2+len(msgBytes))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktError
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	pkt[11] = 3
	binary.BigEndian.PutUint16(pkt[12:14], uint16(len(msgBytes)))
	copy(pkt[14:], msgBytes)
	c.sendCloaked(pkt, nil)
}

func computeExtentSHA256(r io.ReaderAt, totalSize int64) ([32]byte, error) {
	h := sha256.New()
	buf := make([]byte, 256*1024)
	var offset int64 = 0
	for offset < totalSize {
		step := int64(len(buf))
		if totalSize-offset < step {
			step = totalSize - offset
		}
		n, err := r.ReadAt(buf[:step], offset)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			offset += int64(n)
		}
		if n == 0 || (err != nil && err != io.EOF) {
			if err != nil && err != io.EOF {
				return [32]byte{}, err
			}
			return [32]byte{}, errors.New("unexpected EOF while computing source SHA-256")
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func (c *OpenFIRClient) SendFile(targetPath string) error {
	stat, err := os.Stat(targetPath)
	if err != nil {
		return err
	}

	var readerAt io.ReaderAt
	var closer io.Closer
	var totalSize int64
	var flags uint8
	var fileCount int = 1

	if stat.IsDir() {
		ext, err := NewVirtualDirectoryExtent(targetPath)
		if err != nil {
			return err
		}
		readerAt = ext
		closer = ext
		totalSize = ext.Size()
		flags = FlagDirectoryBundle
		fileCount = ext.FileCount()
	} else {
		f, err := os.Open(targetPath)
		if err != nil {
			return err
		}
		readerAt = f
		closer = f
		totalSize = stat.Size()
		flags = FlagSingleFile
	}
	defer closer.Close()

	chunkSize := DefaultChunkSize
	var totalChunks64 uint64 = 0
	if totalSize > 0 {
		totalChunks64 = (uint64(totalSize) + uint64(chunkSize) - 1) / uint64(chunkSize)
	}
	if totalChunks64 >= math.MaxUint32 {
		return fmt.Errorf("transfer size %d exceeds maximum supported chunk count", totalSize)
	}
	totalChunks := uint32(totalChunks64)

	streamSHA256, err := computeExtentSHA256(readerAt, totalSize)
	if err != nil {
		return err
	}

	cliPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cliPubBytes := cliPriv.PublicKey().Bytes()

	transferID := cryptoRandUint64()
	baseName := filepath.Base(filepath.Clean(targetPath))
	phiStride := selectCoprimePhiStride(len(c.conns))
	phiWindowSize := phiStride * PhiGroupMembers

	fmt.Printf("[Client] Starting OpenFIR transfer (X25519-PFS): %s (%.2f MB, %d item(s), %d chunks, %d UDP paths, stride=%d)\n",
		baseName, float64(totalSize)/(1024*1024), fileCount, totalChunks, len(c.conns), phiStride)

	var stateMu sync.Mutex
	ackedBitmap := NewCompactBitset(totalChunks)
	inRetransQueue := NewCompactBitset(totalChunks)
	lastRetxTime := make(map[uint32]time.Time)
	var highestContig uint32
	var remoteRecvCount uint32
	var prevFeedbackRC uint32
	prevFeedbackTime := time.Now()
	retransmitQueue := make([]uint32, 0, 1024)
	var serverCookie [CookieSize]byte
	var serverCASBloom [CASBloomBytes]byte
	hasServerCAS := false
	casCircuitOpen := false
	var remoteCASHits uint32
	var remoteCASMisses uint32
	cookieReady := make(chan struct{}, 1)
	handshakeDone := false
	transferFinAcked := false
	remoteVerified := false
	var remoteFatalErr error
	lastServerContact := time.Now()
	lastProgressTime := time.Now()

	var lossArmorUntilNano atomic.Int64
	lossArmorUntilNano.Store(time.Now().Add(400 * time.Millisecond).UnixNano())
	if c.chaos != nil && c.chaos.enabled {
		lossArmorUntilNano.Store(time.Now().Add(1 * time.Hour).UnixNano())
	}

	stopRecv := make(chan struct{})
	var recvWG sync.WaitGroup

	spawnSocketReader := func(conn *net.UDPConn, slotIdx int) {
		recvWG.Add(1)
		go func(sock *net.UDPConn, sIdx int) {
			defer recvWG.Done()
			buf := make([]byte, MaxUDPDatagramSize)
			for {
				select {
				case <-stopRecv:
					return
				default:
				}
				_ = sock.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
				n, _, err := sock.ReadFromUDP(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				if n < OuterHeaderSize+19 || n > MaxUDPPacketSize+256 {
					continue
				}

				wire := buf[:n]
				sid, seq, ok := c.crypto.PeekHeader(wire, DirServerToClient)
				if !ok {
					continue
				}

				var raw []byte
				var decOK bool
				if sid == 0 {
					raw, decOK = c.crypto.OpenAfterPeek(wire, DirServerToClient, seq, nil)
				} else {
					c.sessMu.RLock()
					expectedSID := c.sessionID
					aeadPair := c.sessionAEAD
					c.sessMu.RUnlock()
					if sid != expectedSID || aeadPair == nil {
						continue
					}
					raw, decOK = c.crypto.OpenAfterPeek(wire, DirServerToClient, seq, aeadPair.s2cAEAD)
					if decOK && !c.replay.CheckAndAccept(seq) {
						continue
					}
				}
				if !decOK || len(raw) < 11 {
					continue
				}

				c.connMu.RLock()
				if sIdx >= 0 && sIdx < len(c.conns) && c.conns[sIdx] == sock {
					atomic.StoreInt64(&c.unansweredSinceNano[sIdx], 0)
				}
				c.connMu.RUnlock()

				pktType := raw[2]
				pktTxID := binary.BigEndian.Uint64(raw[3:11])
				if pktTxID != transferID {
					continue
				}
				p := raw[11:]

				switch pktType {
				case PktCookieChallenge:
					if len(p) >= CookieSize {
						stateMu.Lock()
						copy(serverCookie[:], p[:CookieSize])
						lastServerContact = time.Now()
						stateMu.Unlock()
						select {
						case cookieReady <- struct{}{}:
						default:
						}
					}

				case PktHandshakeAck:
					if len(p) >= 44+CASBloomBytes {
						ackHc := binary.BigEndian.Uint32(p[0:4])
						assignedSID := binary.BigEndian.Uint32(p[4:8])
						srvPubBytes := p[8:40]

						c.sessMu.Lock()
						if c.sessionAEAD == nil && assignedSID != 0 {
							if srvPub, kErr := ecdh.X25519().NewPublicKey(srvPubBytes); kErr == nil {
								if shared, eErr := cliPriv.ECDH(srvPub); eErr == nil {
									if pair, aErr := deriveSessionAEAD(c.crypto.masterKey, shared, transferID, assignedSID); aErr == nil {
										c.sessionID = assignedSID
										c.sessionAEAD = pair
									}
								}
							}
						}
						readyPFS := c.sessionAEAD != nil
						c.sessMu.Unlock()

						if !readyPFS {
							continue
						}

						stateMu.Lock()
						handshakeDone = true
						lastServerContact = time.Now()
						casCnt := binary.BigEndian.Uint32(p[40:44])
						if casCnt > 0 {
							copy(serverCASBloom[:], p[44:44+CASBloomBytes])
							hasServerCAS = true
						}
						pOff := 44 + CASBloomBytes
						if len(p) >= pOff+1 {
							pCnt := int(p[pOff])
							pOff++
							if pCnt > 0 && pCnt <= 32 && len(p) >= pOff+pCnt*2 {
								discovered := make([]uint16, 0, pCnt)
								for i := 0; i < pCnt; i++ {
									prt := binary.BigEndian.Uint16(p[pOff : pOff+2])
									if prt > 0 {
										discovered = append(discovered, prt)
									}
									pOff += 2
								}
								if len(discovered) > 0 {
									c.connMu.Lock()
									c.serverPorts = discovered
									c.connMu.Unlock()
								}
							}
						}
						if ackHc > highestContig && ackHc <= totalChunks {
							for idx := highestContig; idx < ackHc; idx++ {
								ackedBitmap.Set(idx)
							}
							highestContig = ackHc
							lastProgressTime = time.Now()
						}
						stateMu.Unlock()
					}

				case PktFeedback:
					if len(p) < 38 {
						continue
					}
					hc := binary.BigEndian.Uint32(p[0:4])
					scanLimit := binary.BigEndian.Uint32(p[4:8])
					rc := binary.BigEndian.Uint32(p[8:12])
					gradUs := int64(binary.BigEndian.Uint64(p[12:20]))
					queueUs := int64(binary.BigEndian.Uint64(p[20:28]))
					casHits := binary.BigEndian.Uint32(p[28:32])
					casMisses := binary.BigEndian.Uint32(p[32:36])
					rawNackField := binary.BigEndian.Uint16(p[36:38])
					remoteHealedActive := (rawNackField & 0x8000) != 0
					isFinKeepalive := (rawNackField & 0x4000) != 0
					nackCount := int(rawNackField & 0x3FFF)

					stateMu.Lock()
					now := time.Now()
					handshakeDone = true
					lastServerContact = now

					if isFinKeepalive {
						// Server is actively hashing/unpacking the completed file -> keep progress alive
						lastProgressTime = now
					}

					var deliveryBps float64
					if rc > prevFeedbackRC {
						dt := now.Sub(prevFeedbackTime).Seconds()
						dChunks := rc - prevFeedbackRC
						if dt >= 0.015 && dChunks >= 8 {
							deliveryBps = float64(dChunks) * float64(chunkSize) / dt
							prevFeedbackRC = rc
							prevFeedbackTime = now
						}
					}

					if rc > remoteRecvCount {
						remoteRecvCount = rc
						lastProgressTime = now
					}

					// Real-time CAS Bloom False-Positive Circuit Breaker
					if casHits > remoteCASHits {
						remoteCASHits = casHits
					}
					if casMisses > remoteCASMisses {
						remoteCASMisses = casMisses
					}
					totalCASProbes := remoteCASHits + remoteCASMisses
					if totalCASProbes >= 64 && remoteCASHits*4 < totalCASProbes {
						casCircuitOpen = true
					}

					if hc > highestContig && hc <= totalChunks {
						for idx := highestContig; idx < hc; idx++ {
							ackedBitmap.Set(idx)
							delete(lastRetxTime, idx)
						}
						highestContig = hc
						lastProgressTime = now
					}

					nackSet := make(map[uint32]struct{}, nackCount)
					offset := 38
					for i := 0; i < nackCount && offset+4 <= len(p); i++ {
						nackIdx := binary.BigEndian.Uint32(p[offset : offset+4])
						offset += 4
						nackSet[nackIdx] = struct{}{}
						if nackIdx < totalChunks && !ackedBitmap.Get(nackIdx) && !inRetransQueue.Get(nackIdx) {
							if now.Sub(lastRetxTime[nackIdx]) >= 20*time.Millisecond {
								inRetransQueue.Set(nackIdx)
								retransmitQueue = append(retransmitQueue, nackIdx)
							}
						}
					}
					if scanLimit > hc && scanLimit <= totalChunks {
						for idx := hc; idx < scanLimit; idx++ {
							if _, isMissing := nackSet[idx]; !isMissing {
								if !ackedBitmap.Get(idx) {
									ackedBitmap.Set(idx)
									delete(lastRetxTime, idx)
									lastProgressTime = now
								}
							}
						}
					}
					stateMu.Unlock()

					lossActive := nackCount > 0 || remoteHealedActive
					if lossActive {
						lossArmorUntilNano.Store(time.Now().Add(1500 * time.Millisecond).UnixNano())
					}
					if !isFinKeepalive {
						c.pacer.UpdateFromTelemetry(gradUs, queueUs, deliveryBps, lossActive)
					}

				case PktFinAck:
					if len(p) >= 1 {
						stateMu.Lock()
						handshakeDone = true
						transferFinAcked = true
						remoteVerified = (p[0] == 1)
						lastServerContact = time.Now()
						stateMu.Unlock()
					}

				case PktError:
					if len(p) >= 3 {
						msgLen := int(binary.BigEndian.Uint16(p[1:3]))
						if len(p) >= 3+msgLen {
							errMsg := string(p[3 : 3+msgLen])
							stateMu.Lock()
							remoteFatalErr = fmt.Errorf("server aborted transfer: %s", errMsg)
							stateMu.Unlock()
						}
					}
				}
			}
		}(conn, slotIdx)
	}

	c.connMu.RLock()
	for sIdx, sock := range c.conns {
		spawnSocketReader(sock, sIdx)
	}
	c.connMu.RUnlock()

	defer func() {
		close(stopRecv)
		c.Close()
		recvWG.Wait()
	}()

	// Phase 1: Mandatory Cookie + X25519 PFS Handshake synchronization (Fails closed on timeout)
	handshakeDeadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(handshakeDeadline) {
		stateMu.Lock()
		done := handshakeDone
		fErr := remoteFatalErr
		cookieCopy := serverCookie
		stateMu.Unlock()

		if fErr != nil {
			return fErr
		}
		if done {
			break
		}
		hsPkt := buildHandshakePacket(transferID, cookieCopy, cliPubBytes, totalSize, chunkSize, totalChunks, streamSHA256, flags, baseName)
		c.sendPreSession(hsPkt)

		select {
		case <-cookieReady:
		case <-time.After(35 * time.Millisecond):
		}
	}

	stateMu.Lock()
	if remoteFatalErr != nil {
		err := remoteFatalErr
		stateMu.Unlock()
		return err
	}
	if !handshakeDone {
		stateMu.Unlock()
		return errors.New("handshake timeout: peer unreachable or secret key mismatch")
	}
	nextChunk := highestContig
	useCAS := hasServerCAS
	casBloomCopy := serverCASBloom
	stateMu.Unlock()

	bloomFill := casBloomFillRatio(&casBloomCopy)
	if useCAS && bloomFill > 0.995 {
		fmt.Printf("[Client] CAS Bloom heavily saturated (%.1f%% fill); circuit breaker armed for rapid auto-disable on fresh files.\n", bloomFill*100)
	}

	c.connMu.Lock()
	for i := range c.unansweredSinceNano {
		atomic.StoreInt64(&c.unansweredSinceNano[i], 0)
	}
	c.connMu.Unlock()

	contentHashToChunk := make(map[[32]byte]uint32)
	var teleportSentCount uint64
	var zeroSentCount uint64
	var casTeleportSentCount uint64
	var phiParitySentCount uint64
	var dedupChecked uint64
	var dedupHits uint64
	highEntropyBypass := false

	windowChunks := make([][]byte, phiWindowSize)
	windowIndices := make([]uint32, phiWindowSize)
	windowFill := 0
	tailParityFlushed := false

	const readAheadBytes = 200 * DefaultChunkSize
	readAheadBuf := make([]byte, readAheadBytes)
	var readAheadStart int64 = -1
	var readAheadValid int64 = 0

	readChunkExact := func(idx uint32, dst []byte, useReadAhead bool) error {
		byteOff := int64(idx) * int64(chunkSize)
		expLen := len(dst)
		if useReadAhead {
			if byteOff >= readAheadStart && byteOff+int64(expLen) <= readAheadStart+readAheadValid {
				rel := int(byteOff - readAheadStart)
				copy(dst, readAheadBuf[rel:rel+expLen])
				return nil
			}
			n, _ := readerAt.ReadAt(readAheadBuf, byteOff)
			if n > 0 {
				readAheadStart = byteOff
				readAheadValid = int64(n)
				if n >= expLen {
					copy(dst, readAheadBuf[:expLen])
					return nil
				}
			}
		}
		n, err := readerAt.ReadAt(dst, byteOff)
		if n != expLen {
			if err != nil && err != io.EOF {
				return err
			}
			return fmt.Errorf("source read short at chunk %d (%d/%d bytes): file modified during transfer", idx, n, expLen)
		}
		return nil
	}

	var sweepCursor uint32 = 0
	lastFinSendTime := time.Time{}
	finBackoff := 15 * time.Millisecond
	readBuf := make([]byte, chunkSize)

	// Phase 2: Main transmission & selective repeat loop
	for {
		stateMu.Lock()
		fErr := remoteFatalErr
		finAcked := transferFinAcked
		verified := remoteVerified
		hc := highestContig
		casTripped := casCircuitOpen
		sinceContact := time.Since(lastServerContact)
		sinceProgress := time.Since(lastProgressTime)

		var nackIdx uint32 = math.MaxUint32
		if len(retransmitQueue) > 0 {
			nackIdx = retransmitQueue[0]
			retransmitQueue = retransmitQueue[1:]
			inRetransQueue.Clear(nackIdx)
			if !ackedBitmap.Get(nackIdx) && nackIdx >= hc {
				lastRetxTime[nackIdx] = time.Now()
			}
		}
		stateMu.Unlock()

		if fErr != nil {
			return fErr
		}
		if finAcked {
			if !verified {
				return errors.New("end-to-end SHA-256 verification failed on receiver")
			}
			fmt.Printf("[Client] Transfer 100%% verified! (TeleportCmds=%d, ZeroCmds=%d, CASTeleportCmds=%d, PhiParityFrames=%d, Rate=%.2f MB/s)\n",
				teleportSentCount, zeroSentCount, casTeleportSentCount, phiParitySentCount, c.pacer.CurrentMBps())
			return nil
		}

		if sinceContact > c.idleTimeout || sinceProgress > c.idleTimeout*2 {
			return fmt.Errorf("transfer timed out: no progress for %v (last server contact %v ago)",
				sinceProgress.Round(time.Millisecond), sinceContact.Round(time.Millisecond))
		}

		// Priority 1: Service explicit NACK retransmissions (strictly using raw PktData)
		if nackIdx != math.MaxUint32 {
			stateMu.Lock()
			alreadyAcked := ackedBitmap.Get(nackIdx)
			stateMu.Unlock()
			if !alreadyAcked && nackIdx >= hc && nackIdx < totalChunks {
				expLen := expectedChunkLen(nackIdx, totalChunks, totalSize, chunkSize)
				if err := readChunkExact(nackIdx, readBuf[:expLen], false); err != nil {
					c.sendError(transferID, err.Error())
					return err
				}
				pkt := buildDataPacket(transferID, nackIdx, readBuf[:expLen])
				c.pacer.Wait(len(pkt))
				c.sendCloaked(pkt, spawnSocketReader)
			}
			continue
		}

		// Priority 2: First-pass transmission with Inline Staggered Adaptive Phi-Parity Injection
		if nextChunk < totalChunks {
			idx := nextChunk
			nextChunk++

			stateMu.Lock()
			alreadyDone := ackedBitmap.Get(idx)
			stateMu.Unlock()
			if alreadyDone {
				continue
			}

			expLen := expectedChunkLen(idx, totalChunks, totalSize, chunkSize)
			if err := readChunkExact(idx, readBuf[:expLen], true); err != nil {
				c.sendError(transferID, err.Error())
				return err
			}
			chunkData := make([]byte, expLen)
			copy(chunkData, readBuf[:expLen])

			casActive := useCAS && !casTripped

			if isAllZero(chunkData) {
				tpPkt := buildTeleportPacket(transferID, idx, ZeroChunkSentinel)
				c.pacer.Wait(len(tpPkt))
				c.sendCloaked(tpPkt, spawnSocketReader)
				zeroSentCount++
			} else {
				// Adaptive high-entropy bypass: skip SHA-256 on compressed files (1-in-64 probe stays active)
				shouldHash := casActive || !highEntropyBypass || (idx&63 == 0)
				sentTeleport := false
				if shouldHash {
					chunkHash := sha256.Sum256(chunkData)
					dedupChecked++
					prevIdx, seenBefore := contentHashToChunk[chunkHash]
					if !seenBefore && len(contentHashToChunk) < MaxTeleportIndexEntries {
						contentHashToChunk[chunkHash] = idx
					}

					if seenBefore && prevIdx < idx {
						dedupHits++
						highEntropyBypass = false
						tpPkt := buildTeleportPacket(transferID, idx, prevIdx)
						c.pacer.Wait(len(tpPkt))
						c.sendCloaked(tpPkt, spawnSocketReader)
						teleportSentCount++
						sentTeleport = true
					} else if casActive && casBloomTest(&casBloomCopy, chunkHash) {
						casPkt := buildCASTeleportPacket(transferID, idx, chunkHash)
						c.pacer.Wait(len(casPkt))
						c.sendCloaked(casPkt, spawnSocketReader)
						casTeleportSentCount++
						sentTeleport = true
					}

					if !casActive && dedupChecked >= 1024 && dedupHits*500 < dedupChecked {
						highEntropyBypass = true
					}
				}

				if !sentTeleport {
					dataPkt := buildDataPacket(transferID, idx, chunkData)
					c.pacer.Wait(len(dataPkt))
					c.sendCloaked(dataPkt, spawnSocketReader)
				}
			}

			padded := make([]byte, chunkSize)
			copy(padded, chunkData)
			pos := windowFill
			windowChunks[pos] = padded
			windowIndices[pos] = idx
			windowFill++

			if pos >= phiWindowSize-phiStride {
				bucket := pos - (phiWindowSize - phiStride)
				activeBuckets := 1
				if time.Now().UnixNano() < lossArmorUntilNano.Load() {
					activeBuckets = phiStride
				}
				if bucket < activeBuckets {
					members := make([]uint32, PhiGroupMembers)
					xorPayload := make([]byte, chunkSize)
					for m := 0; m < PhiGroupMembers; m++ {
						mPos := bucket + m*phiStride
						members[m] = windowIndices[mPos]
						for b := 0; b < chunkSize; b++ {
							xorPayload[b] ^= windowChunks[mPos][b]
						}
					}
					parityPkt := buildPhiParityPacket(transferID, members, xorPayload)
					c.pacer.Wait(len(parityPkt))
					c.sendCloaked(parityPkt, spawnSocketReader)
					phiParitySentCount++
				}
			}

			if windowFill == phiWindowSize {
				windowFill = 0
			}
			continue
		}

		// Flush remaining tail window parity once
		if !tailParityFlushed {
			tailParityFlushed = true
			if windowFill >= 2 {
				half := windowFill / 2
				for i := 0; i < half; i++ {
					members := []uint32{windowIndices[i], windowIndices[i+half]}
					xorPayload := make([]byte, chunkSize)
					for b := 0; b < chunkSize; b++ {
						xorPayload[b] = windowChunks[i][b] ^ windowChunks[i+half][b]
					}
					parityPkt := buildPhiParityPacket(transferID, members, xorPayload)
					c.pacer.Wait(len(parityPkt))
					c.sendCloaked(parityPkt, spawnSocketReader)
					phiParitySentCount++
				}
				windowFill = 0
			}
		}

		// Priority 3: Direct hc recovery & paced batch tail sweep, or FIN announcement
		if hc < totalChunks {
			var batchTargets []uint32
			now := time.Now()

			stateMu.Lock()
			if !ackedBitmap.Get(hc) && now.Sub(lastRetxTime[hc]) >= 25*time.Millisecond {
				lastRetxTime[hc] = now
				batchTargets = append(batchTargets, hc)
			}

			if sweepCursor < hc || sweepCursor >= totalChunks {
				sweepCursor = hc
			}
			span := totalChunks - hc
			for scanned := uint32(0); scanned < span && len(batchTargets) < 8; scanned++ {
				cand := hc + ((sweepCursor - hc + scanned) % span)
				if !ackedBitmap.Get(cand) && now.Sub(lastRetxTime[cand]) >= 25*time.Millisecond {
					lastRetxTime[cand] = now
					batchTargets = append(batchTargets, cand)
					sweepCursor = cand + 1
				}
			}
			stateMu.Unlock()

			if len(batchTargets) > 0 {
				for _, targetIdx := range batchTargets {
					expLen := expectedChunkLen(targetIdx, totalChunks, totalSize, chunkSize)
					if err := readChunkExact(targetIdx, readBuf[:expLen], false); err != nil {
						c.sendError(transferID, err.Error())
						return err
					}
					pkt := buildDataPacket(transferID, targetIdx, readBuf[:expLen])
					c.pacer.Wait(len(pkt))
					c.sendCloaked(pkt, spawnSocketReader)
				}
			} else {
				time.Sleep(4 * time.Millisecond)
			}
		} else {
			if time.Since(lastFinSendTime) >= finBackoff {
				finPkt := make([]byte, 11)
				finPkt[0] = ProtocolMagic0
				finPkt[1] = ProtocolMagic1
				finPkt[2] = PktFin
				binary.BigEndian.PutUint64(finPkt[3:11], transferID)
				c.sendCloaked(finPkt, nil)
				lastFinSendTime = time.Now()
				if finBackoff < 120*time.Millisecond {
					finBackoff += 15 * time.Millisecond
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// ============================================================================
// Wire Frame Builders (All Frames Prefix-Routed with 8-Byte TxID)
// ============================================================================

func buildHandshakePacket(tid uint64, cookie [CookieSize]byte, cliPub []byte, fileSize int64, chunkSize int, totalChunks uint32, sha [32]byte, flags uint8, name string) []byte {
	nameBytes := []byte(name)
	pkt := make([]byte, 3+8+99+len(nameBytes))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktHandshake
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	copy(pkt[11:27], cookie[:])
	copy(pkt[27:59], cliPub)
	binary.BigEndian.PutUint64(pkt[59:67], uint64(fileSize))
	binary.BigEndian.PutUint32(pkt[67:71], uint32(chunkSize))
	binary.BigEndian.PutUint32(pkt[71:75], totalChunks)
	copy(pkt[75:107], sha[:])
	pkt[107] = flags
	binary.BigEndian.PutUint16(pkt[108:110], uint16(len(nameBytes)))
	copy(pkt[110:], nameBytes)
	return pkt
}

func buildDataPacket(tid uint64, idx uint32, data []byte) []byte {
	pkt := make([]byte, 3+8+14+len(data))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktData
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	binary.BigEndian.PutUint32(pkt[11:15], idx)
	binary.BigEndian.PutUint64(pkt[15:23], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(pkt[23:25], uint16(len(data)))
	copy(pkt[25:], data)
	return pkt
}

func buildTeleportPacket(tid uint64, targetIdx, sourceIdx uint32) []byte {
	pkt := make([]byte, 3+8+16)
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktTeleport
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	binary.BigEndian.PutUint32(pkt[11:15], targetIdx)
	binary.BigEndian.PutUint32(pkt[15:19], sourceIdx)
	binary.BigEndian.PutUint64(pkt[19:27], uint64(time.Now().UnixNano()))
	return pkt
}

func buildCASTeleportPacket(tid uint64, targetIdx uint32, digest [32]byte) []byte {
	pkt := make([]byte, 3+8+44)
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktCASTeleport
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	binary.BigEndian.PutUint32(pkt[11:15], targetIdx)
	copy(pkt[15:47], digest[:])
	binary.BigEndian.PutUint64(pkt[47:55], uint64(time.Now().UnixNano()))
	return pkt
}

func buildPhiParityPacket(tid uint64, members []uint32, xorPayload []byte) []byte {
	count := len(members)
	pkt := make([]byte, 3+8+8+1+count*4+2+len(xorPayload))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktPhiParity
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	binary.BigEndian.PutUint64(pkt[11:19], uint64(time.Now().UnixNano()))
	pkt[19] = uint8(count)
	offset := 20
	for _, m := range members {
		binary.BigEndian.PutUint32(pkt[offset:offset+4], m)
		offset += 4
	}
	binary.BigEndian.PutUint16(pkt[offset:offset+2], uint16(len(xorPayload)))
	offset += 2
	copy(pkt[offset:], xorPayload)
	return pkt
}

// ============================================================================
// Module 8: Automated Chaos Self-Test Engine (-mode selftest)
// ============================================================================

func sendOversizedUDPProbes(targetAddr string) error {
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return err
	}
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	probeConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer probeConn.Close()
	tuneUDPConn(probeConn)

	for _, sz := range []int{1757, 4000, 65000} {
		oversized := make([]byte, sz)
		fastRandFill(oversized)
		_, _ = probeConn.WriteToUDP(oversized, raddr)
	}
	time.Sleep(15 * time.Millisecond)
	return nil
}

func runSelfTest(lossRate float64, burstLen int, numSockets int) error {
	fmt.Printf("====================================================================\n")
	fmt.Printf("  OpenFIR Automated Chaos Self-Test Engine (v0.7.0 Hardened)\n")
	fmt.Printf("  Injected Channel Conditions: LossRate=%.1f%% | MeanBurstLength=%d | Sockets=%d\n",
		lossRate*100, burstLen, numSockets)
	fmt.Printf("====================================================================\n")

	tmpDir, err := os.MkdirTemp("", "openfir_selftest_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	var testMasterKey [32]byte
	_, _ = io.ReadFull(rand.Reader, testMasterKey[:])
	outDir := filepath.Join(tmpDir, "received")

	// ------------------------------------------------------------------------
	// Suite 1: 16 MB Mixed-Entropy + Sparse Zero Regions (3 Consecutive Runs + Probes)
	// ------------------------------------------------------------------------
	srcFile := filepath.Join(tmpDir, "test_payload.bin")
	const totalTestBytes = 16 * 1024 * 1024
	rawFileBytes := make([]byte, totalTestBytes)
	patternBlock := make([]byte, 64*1024)
	fastRandFill(patternBlock)

	offset := 0
	for offset < totalTestBytes {
		blkIdx := offset / (64 * 1024)
		switch blkIdx % 4 {
		case 0:
			copy(rawFileBytes[offset:], patternBlock)
		case 1:
			// Keep all-zero sparse region to validate ZeroChunkSentinel teleportation
		default:
			fastRandFill(rawFileBytes[offset : offset+64*1024])
		}
		offset += 64 * 1024
	}
	if err := os.WriteFile(srcFile, rawFileBytes, 0644); err != nil {
		return err
	}

	var totalDropped uint64
	for iter := 1; iter <= 3; iter++ {
		fmt.Printf("\n--- [Suite 1/5 - Iteration %d/3] Single Large File Transfer (16.00 MB) ---\n", iter)
		srv1, err := NewOpenFIRServer(ServerConfig{
			ListenAddr:     "127.0.0.1:0",
			PortSpan:       4,
			OutputDir:      outDir,
			MasterKey:      testMasterKey,
			AllowOverwrite: true,
		})
		if err != nil {
			return err
		}
		srv1Err := make(chan error, 1)
		go func() { srv1Err <- srv1.Serve(1) }()

		if err := sendOversizedUDPProbes(srv1.LocalAddr()); err != nil {
			srv1.Close()
			return err
		}

		chaos1 := NewChaosSimulator(lossRate, burstLen)
		cli1, err := NewOpenFIRClient(ClientConfig{
			ServerAddr: srv1.LocalAddr(),
			MasterKey:  testMasterKey,
			NumSockets: numSockets,
			InitMBps:   80.0,
			MaxMBps:    500.0,
			Chaos:      chaos1,
		})
		if err != nil {
			srv1.Close()
			return err
		}
		if err := cli1.SendFile(srcFile); err != nil {
			cli1.Close()
			srv1.Close()
			return err
		}
		cli1.Close()
		if err := <-srv1Err; err != nil {
			srv1.Close()
			return err
		}
		srv1.Close()
		totalDropped += chaos1.droppedCount

		dstFile := filepath.Join(outDir, "test_payload.bin")
		receivedBytes, err := os.ReadFile(dstFile)
		if err != nil {
			return err
		}
		if !bytes.Equal(rawFileBytes, receivedBytes) {
			return fmt.Errorf("suite 1 iteration %d failure: received large file mismatch", iter)
		}
	}

	// ------------------------------------------------------------------------
	// Suite 2: 200 Small Files + Empty Subdirectory via Zero-RTT Virtual Extent
	// ------------------------------------------------------------------------
	fmt.Printf("\n--- [Suite 2/5] Massive Small-Files Directory Tree (200 files) ---\n")
	srcSmallDir := filepath.Join(tmpDir, "small_files_dataset")
	expectedSmallFiles := make(map[string][]byte)
	sharedSmallTemplate := make([]byte, 4096)
	fastRandFill(sharedSmallTemplate)

	emptySubDir := filepath.Join(srcSmallDir, "empty_nested_dir", "inner_empty")
	if err := os.MkdirAll(emptySubDir, 0755); err != nil {
		return err
	}

	for i := 0; i < 200; i++ {
		subDir := filepath.Join(srcSmallDir, fmt.Sprintf("module_%02d", i%10), fmt.Sprintf("layer_%02d", i%4))
		if err := os.MkdirAll(subDir, 0755); err != nil {
			return err
		}
		fName := fmt.Sprintf("asset_%03d.dat", i)
		fullPath := filepath.Join(subDir, fName)

		var content []byte
		switch {
		case i%5 == 0:
			content = append([]byte(nil), sharedSmallTemplate...)
		case i%17 == 0:
			content = make([]byte, 37)
			fastRandFill(content)
		default:
			sz := 300 + (i*97)%8192
			content = make([]byte, sz)
			fastRandFill(content)
		}
		if err := os.WriteFile(fullPath, content, 0644); err != nil {
			return err
		}
		rel, _ := filepath.Rel(srcSmallDir, fullPath)
		expectedSmallFiles[rel] = content
	}

	srv2, err := NewOpenFIRServer(ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		PortSpan:       4,
		OutputDir:      outDir,
		MasterKey:      testMasterKey,
		AllowOverwrite: true,
	})
	if err != nil {
		return err
	}
	srv2Err := make(chan error, 1)
	go func() { srv2Err <- srv2.Serve(1) }()

	chaos2 := NewChaosSimulator(lossRate, burstLen)
	cli2, err := NewOpenFIRClient(ClientConfig{
		ServerAddr: srv2.LocalAddr(),
		MasterKey:  testMasterKey,
		NumSockets: numSockets,
		InitMBps:   80.0,
		MaxMBps:    500.0,
		Chaos:      chaos2,
	})
	if err != nil {
		srv2.Close()
		return err
	}
	if err := cli2.SendFile(srcSmallDir); err != nil {
		cli2.Close()
		srv2.Close()
		return err
	}
	cli2.Close()
	if err := <-srv2Err; err != nil {
		srv2.Close()
		return err
	}
	srv2.Close()
	totalDropped += chaos2.droppedCount

	dstSmallDir := filepath.Join(outDir, "small_files_dataset")
	if st, err := os.Stat(filepath.Join(dstSmallDir, "empty_nested_dir", "inner_empty")); err != nil || !st.IsDir() {
		return errors.New("suite 2 failure: empty nested subdirectory was not preserved")
	}
	for rel, expBytes := range expectedSmallFiles {
		gotBytes, err := os.ReadFile(filepath.Join(dstSmallDir, rel))
		if err != nil {
			return fmt.Errorf("suite 2 failure: missing extracted small file %s: %w", rel, err)
		}
		if !bytes.Equal(expBytes, gotBytes) {
			return fmt.Errorf("suite 2 failure: content mismatch in extracted small file %s", rel)
		}
	}

	// ------------------------------------------------------------------------
	// Suite 3: Concurrent Multi-Client Isolation Test (Independent PFS Keys & Seqs)
	// ------------------------------------------------------------------------
	fmt.Printf("\n--- [Suite 3/5] Concurrent Multi-Client Isolation Test ---\n")
	fileA := filepath.Join(tmpDir, "concurrent_A.bin")
	fileB := filepath.Join(tmpDir, "concurrent_B.bin")
	bytesA := make([]byte, 4*1024*1024)
	bytesB := make([]byte, 2*1024*1024)
	fastRandFill(bytesA)
	fastRandFill(bytesB)
	if err := os.WriteFile(fileA, bytesA, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(fileB, bytesB, 0644); err != nil {
		return err
	}

	srv3, err := NewOpenFIRServer(ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		PortSpan:       4,
		OutputDir:      outDir,
		MasterKey:      testMasterKey,
		AllowOverwrite: true,
	})
	if err != nil {
		return err
	}
	srv3Err := make(chan error, 1)
	go func() { srv3Err <- srv3.Serve(2) }()

	var concWG sync.WaitGroup
	errA := make(chan error, 1)
	errB := make(chan error, 1)

	concWG.Add(2)
	go func() {
		defer concWG.Done()
		cA, err := NewOpenFIRClient(ClientConfig{
			ServerAddr: srv3.LocalAddr(),
			MasterKey:  testMasterKey,
			NumSockets: 4,
			InitMBps:   40.0,
			MaxMBps:    200.0,
			Chaos:      NewChaosSimulator(lossRate/2, burstLen),
		})
		if err != nil {
			errA <- err
			return
		}
		defer cA.Close()
		errA <- cA.SendFile(fileA)
	}()

	go func() {
		defer concWG.Done()
		cB, err := NewOpenFIRClient(ClientConfig{
			ServerAddr: srv3.LocalAddr(),
			MasterKey:  testMasterKey,
			NumSockets: 4,
			InitMBps:   40.0,
			MaxMBps:    200.0,
			Chaos:      NewChaosSimulator(lossRate/2, burstLen),
		})
		if err != nil {
			errB <- err
			return
		}
		defer cB.Close()
		errB <- cB.SendFile(fileB)
	}()

	concWG.Wait()
	if err := <-errA; err != nil {
		srv3.Close()
		return fmt.Errorf("suite 3 client A failed: %w", err)
	}
	if err := <-errB; err != nil {
		srv3.Close()
		return fmt.Errorf("suite 3 client B failed: %w", err)
	}
	if err := <-srv3Err; err != nil {
		srv3.Close()
		return err
	}
	srv3.Close()

	gotA, err := os.ReadFile(filepath.Join(outDir, "concurrent_A.bin"))
	if err != nil || !bytes.Equal(bytesA, gotA) {
		return errors.New("suite 3 failure: concurrent_A.bin corrupted")
	}
	gotB, err := os.ReadFile(filepath.Join(outDir, "concurrent_B.bin"))
	if err != nil || !bytes.Equal(bytesB, gotB) {
		return errors.New("suite 3 failure: concurrent_B.bin corrupted")
	}

	// ------------------------------------------------------------------------
	// Suite 4: Cross-Session Persistent CAS Instant Teleportation Test
	// ------------------------------------------------------------------------
	fmt.Printf("\n--- [Suite 4/5] Cross-Session Persistent CAS Instant Teleportation ---\n")
	v2File := filepath.Join(tmpDir, "incremental_v2.bin")
	v2Bytes := make([]byte, 8*1024*1024)
	copy(v2Bytes[0:4*1024*1024], bytesA)
	copy(v2Bytes[4*1024*1024:8*1024*1024], rawFileBytes[0:4*1024*1024])
	fastRandFill(v2Bytes[1024*1024 : 2*1024*1024])
	if err := os.WriteFile(v2File, v2Bytes, 0644); err != nil {
		return err
	}

	srv4, err := NewOpenFIRServer(ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		PortSpan:       4,
		OutputDir:      outDir,
		MasterKey:      testMasterKey,
		AllowOverwrite: true,
	})
	if err != nil {
		return err
	}
	srv4Err := make(chan error, 1)
	go func() { srv4Err <- srv4.Serve(1) }()

	chaos4 := NewChaosSimulator(lossRate, burstLen)
	cli4, err := NewOpenFIRClient(ClientConfig{
		ServerAddr: srv4.LocalAddr(),
		MasterKey:  testMasterKey,
		NumSockets: numSockets,
		InitMBps:   80.0,
		MaxMBps:    500.0,
		Chaos:      chaos4,
	})
	if err != nil {
		srv4.Close()
		return err
	}
	if err := cli4.SendFile(v2File); err != nil {
		cli4.Close()
		srv4.Close()
		return err
	}
	cli4.Close()
	if err := <-srv4Err; err != nil {
		srv4.Close()
		return err
	}
	srv4.Close()
	totalDropped += chaos4.droppedCount

	gotV2, err := os.ReadFile(filepath.Join(outDir, "incremental_v2.bin"))
	if err != nil || !bytes.Equal(v2Bytes, gotV2) {
		return errors.New("suite 4 failure: incremental_v2.bin content mismatch after cross-session CAS teleportation")
	}

	// ------------------------------------------------------------------------
	// Suite 5: Fresh High-Entropy File Under Saturated CAS Bloom (Circuit Breaker Test)
	// ------------------------------------------------------------------------
	fmt.Printf("\n--- [Suite 5/5] Fresh High-Entropy File Under Saturated CAS Bloom ---\n")
	freshFile := filepath.Join(tmpDir, "fresh_random.bin")
	freshBytes := make([]byte, 8*1024*1024)
	fastRandFill(freshBytes)
	if err := os.WriteFile(freshFile, freshBytes, 0644); err != nil {
		return err
	}

	srv5, err := NewOpenFIRServer(ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		PortSpan:       4,
		OutputDir:      outDir,
		MasterKey:      testMasterKey,
		AllowOverwrite: true,
	})
	if err != nil {
		return err
	}
	srv5Err := make(chan error, 1)
	go func() { srv5Err <- srv5.Serve(1) }()

	chaos5 := NewChaosSimulator(lossRate, burstLen)
	cli5, err := NewOpenFIRClient(ClientConfig{
		ServerAddr: srv5.LocalAddr(),
		MasterKey:  testMasterKey,
		NumSockets: numSockets,
		InitMBps:   80.0,
		MaxMBps:    500.0,
		Chaos:      chaos5,
	})
	if err != nil {
		srv5.Close()
		return err
	}
	if err := cli5.SendFile(freshFile); err != nil {
		cli5.Close()
		srv5.Close()
		return err
	}
	cli5.Close()
	if err := <-srv5Err; err != nil {
		srv5.Close()
		return err
	}
	srv5.Close()
	totalDropped += chaos5.droppedCount

	gotFresh, err := os.ReadFile(filepath.Join(outDir, "fresh_random.bin"))
	if err != nil || !bytes.Equal(freshBytes, gotFresh) {
		return errors.New("suite 5 failure: fresh_random.bin content mismatch under saturated CAS Bloom")
	}

	fmt.Printf("\n[SelfTest] ALL 5 SUITES PASSED 100%%! (Total dropped packets recovered: %d)\n", totalDropped)
	return nil
}

// ============================================================================
// CLI Entrypoint
// ============================================================================

func main() {
	mode := flag.String("mode", "", "Execution mode: server | client | selftest")
	listen := flag.String("listen", "0.0.0.0:9900", "Server primary UDP listen address")
	portSpan := flag.Int("port-span", DefaultServerPortSpan, "Number of contiguous UDP ports in server listener matrix")
	outDir := flag.String("out", "./openfir_downloads", "Server output directory for received files/directories")
	serverAddr := flag.String("server", "127.0.0.1:9900", "Target server UDP address for client mode")
	filePath := flag.String("file", "", "Path to input file OR directory for client mode")
	numSockets := flag.Int("sockets", 8, "Number of concurrent local UDP sockets for multi-path striping")
	initRate := flag.Float64("init-mbps", 50.0, "Initial client pacing rate in MiB/s (MegaBytes/sec; e.g. 50 = ~400 Mbps)")
	maxRate := flag.Float64("max-mbps", 1000.0, "Maximum client pacing rate ceiling in MiB/s (MegaBytes/sec; e.g. 125 = 1 Gbps)")
	secretInput := flag.String("secret", "", "Shared secret (64-char hex or 'pass:<passphrase>', or via OPENFIR_SECRET)")
	overwrite := flag.Bool("overwrite", false, "Allow server to overwrite existing destination files")
	maxFileGB := flag.Int64("max-file-gb", 64, "Maximum allowed transfer size in GB on server")
	maxSessions := flag.Int("max-sessions", 64, "Maximum concurrent active transfer sessions on server")
	timeoutSec := flag.Int("timeout", 25, "Session idle/stall timeout in seconds")
	simLoss := flag.Float64("sim-loss", 0.0, "Simulated packet loss ratio (0.0 disables simulation in production)")
	simBurst := flag.Int("sim-burst", 4, "Simulated contiguous burst drop length")
	flag.Parse()

	if *mode == "" {
		fmt.Fprintf(os.Stderr, "OpenFIR v0.7.0 Hardened — Multi-Path X25519-PFS UDP File & Directory Transfer Protocol\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Run self-test : openfir -mode selftest\n")
		fmt.Fprintf(os.Stderr, "  Start server  : openfir -mode server -listen 0.0.0.0:9900 -out ./downloads -secret <64-hex-chars>\n")
		fmt.Fprintf(os.Stderr, "  Send file/dir : openfir -mode client -server <ip>:9900 -file ./path -secret <64-hex-chars>\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch *mode {
	case "selftest":
		loss := *simLoss
		if loss <= 0 {
			loss = 0.08
		}
		if err := runSelfTest(loss, *simBurst, *numSockets); err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Self-test failed: %v\n", err)
			os.Exit(1)
		}

	case "server":
		masterKey, isDemo, err := parseSecretMaterial(*secretInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] %v\n", err)
			os.Exit(1)
		}
		if isDemo {
			fmt.Fprintln(os.Stderr, "[WARN] Using public documentation example secret key! Generate a unique 256-bit key for production.")
		}
		srv, err := NewOpenFIRServer(ServerConfig{
			ListenAddr:     *listen,
			PortSpan:       *portSpan,
			OutputDir:      *outDir,
			MasterKey:      masterKey,
			AllowOverwrite: *overwrite,
			MaxFileSize:    (*maxFileGB) * 1024 * 1024 * 1024,
			MaxSessions:    *maxSessions,
			IdleTimeout:    time.Duration(*timeoutSec) * time.Second,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Failed to initialize server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[Server] OpenFIR v0.7.0 Hardened listening on %s (matrix ports: %v, output dir: %s, overwrite: %v)\n",
			srv.LocalAddr(), srv.BoundPorts(), *outDir, *overwrite)
		if err := srv.Serve(0); err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Server runtime error: %v\n", err)
			os.Exit(1)
		}

	case "client":
		if *filePath == "" {
			fmt.Fprintln(os.Stderr, "[Error] -file flag (path to file or directory) is required in client mode")
			os.Exit(1)
		}
		masterKey, isDemo, err := parseSecretMaterial(*secretInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] %v\n", err)
			os.Exit(1)
		}
		if isDemo {
			fmt.Fprintln(os.Stderr, "[WARN] Using public documentation example secret key! Generate a unique 256-bit key for production.")
		}
		var chaos *ChaosSimulator
		if *simLoss > 0 {
			fmt.Fprintf(os.Stderr, "[WARN] Chaos packet-loss simulation ACTIVE: loss=%.1f%%, burst=%d\n",
				(*simLoss)*100, *simBurst)
			chaos = NewChaosSimulator(*simLoss, *simBurst)
		}
		cli, err := NewOpenFIRClient(ClientConfig{
			ServerAddr:  *serverAddr,
			MasterKey:   masterKey,
			NumSockets:  *numSockets,
			InitMBps:    *initRate,
			MaxMBps:     *maxRate,
			IdleTimeout: time.Duration(*timeoutSec) * time.Second,
			Chaos:       chaos,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Failed to initialize client: %v\n", err)
			os.Exit(1)
		}
		defer cli.Close()
		if err := cli.SendFile(*filePath); err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Transfer failed: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s (expected: selftest | server | client)\n", *mode)
		os.Exit(1)
	}
}
