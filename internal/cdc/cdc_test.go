// SPDX-License-Identifier: Apache-2.0

package cdc

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestRabinWindowExactPrefixInvariance(t *testing.T) {
	data := make([]byte, 512)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}

	var h uint64
	for i, b := range data {
		if i >= rabinWindowBytes {
			h ^= rabinOutTable[data[i-rabinWindowBytes]]
		}
		top := h >> rabinShift
		h = (((h & rabinLowMask) << 8) | uint64(b)) ^ rabinModTable[top]
		if i >= rabinWindowBytes-1 {
			want := RabinWindowFingerprint(data[i-rabinWindowBytes+1 : i+1])
			if h != want {
				t.Fatalf("Rabin rolling fingerprint diverged at pos %d: got %#x want %#x", i, h, want)
			}
		}
	}
}

func TestRabinCDCShiftImmunityAfter1BytePrepend(t *testing.T) {
	// 4 MB random incompressible data — worst case for fixed-size chunking!
	orig := make([]byte, 4*1024*1024)
	if _, err := io.ReadFull(rand.Reader, orig); err != nil {
		t.Fatal(err)
	}

	origHashes := make(map[[32]byte]struct{})
	ch1 := NewChunker(bytes.NewReader(orig), DefaultMinChunk, DefaultAvgChunk, DefaultMaxChunk)
	origCount := 0
	for {
		m, _, err := ch1.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		origHashes[m.Hash] = struct{}{}
		origCount++
	}

	// Prepend 1 SINGLE BYTE at offset 0 (fixed chunking drops to 0% reuse; Rabin 48B CDC realigns immediately!)
	shifted := append([]byte{0x42}, orig...)
	ch2 := NewChunker(bytes.NewReader(shifted), DefaultMinChunk, DefaultAvgChunk, DefaultMaxChunk)
	hits, total := 0, 0
	for {
		m, _, err := ch2.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		total++
		if _, ok := origHashes[m.Hash]; ok {
			hits++
		}
	}

	reuse := float64(hits) * 100.0 / float64(total)
	if reuse < 94.0 {
		t.Fatalf("expected >=94%% Rabin CDC shift immunity after 1-byte prepend, got %.2f%% (%d/%d)", reuse, hits, total)
	}
	t.Logf("PASS: Classic 1981 Rabin CDC 1-byte prepend shift immunity = %.2f%% (%d/%d blocks reused; orig=%d blocks, avg=%dKB)",
		reuse, hits, total, origCount, len(orig)/(origCount*1024))
}

func TestStreamingMerkleTreeOrderIndependentDeterminism(t *testing.T) {
	m1 := NewMerkleBuilder()
	m2 := NewMerkleBuilder()
	hashes := make([][32]byte, 37)
	for i := range hashes {
		hashes[i] = HashBlock([]byte{byte(i), byte(i * 7)})
		m1.AddLeaf(uint32(i), 100+uint32(i), hashes[i])
	}
	// Insert in reverse/out-of-order into m2
	for i := len(hashes) - 1; i >= 0; i-- {
		m2.AddLeaf(uint32(i), 100+uint32(i), hashes[i])
	}
	if m1.Root(37) != m2.Root(37) {
		t.Fatal("Merkle root differed for out-of-order leaf insertion")
	}
}
