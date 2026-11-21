// Copyright 2026 The OpenFIR Authors.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestCompactBitsetSetGetClear(t *testing.T) {
	bs := NewCompactBitset(1000)
	indices := []uint32{0, 1, 63, 64, 65, 127, 128, 511, 999}

	for _, idx := range indices {
		if bs.Get(idx) {
			t.Fatalf("expected index %d to be false initially", idx)
		}
		bs.Set(idx)
		if !bs.Get(idx) {
			t.Fatalf("expected index %d to be true after Set", idx)
		}
		bs.Clear(idx)
		if bs.Get(idx) {
			t.Fatalf("expected index %d to be false after Clear (re-arm regression check)", idx)
		}
		bs.Set(idx)
	}

	bs.Set(1000)
	bs.Clear(1000)
	if bs.Get(1000) {
		t.Fatalf("expected out-of-bounds index to return false")
	}
}

func TestReplayWindowSlidingAndReordering(t *testing.T) {
	var rw ReplayWindow

	if rw.CheckAndAccept(0) {
		t.Fatalf("sequence 0 must be rejected")
	}
	if !rw.CheckAndAccept(1) {
		t.Fatalf("initial sequence 1 must be accepted")
	}
	if rw.CheckAndAccept(1) {
		t.Fatalf("duplicate sequence 1 must be rejected")
	}

	if !rw.CheckAndAccept(5001) {
		t.Fatalf("sequence 5001 must be accepted")
	}
	if !rw.CheckAndAccept(2000) {
		t.Fatalf("out-of-order sequence 2000 within window must be accepted")
	}
	if rw.CheckAndAccept(2000) {
		t.Fatalf("replayed sequence 2000 must be rejected")
	}

	if !rw.CheckAndAccept(20000) {
		t.Fatalf("sequence 20000 must be accepted")
	}
	if rw.CheckAndAccept(5001) {
		t.Fatalf("already-seen sequence 5001 must be rejected")
	}
	// Exact lower boundary of 16384-packet sliding window:
	// highest=20000 -> diff=16384 (seq=3616) is stale; diff=16383 (seq=3617) is still valid.
	staleSeq := uint64(20000 - ReplayWindowBits)
	if rw.CheckAndAccept(staleSeq) {
		t.Fatalf("stale sequence %d outside %d-packet window must be rejected", staleSeq, ReplayWindowBits)
	}
	if !rw.CheckAndAccept(staleSeq + 1) {
		t.Fatalf("boundary sequence %d within %d-packet window must be accepted", staleSeq+1, ReplayWindowBits)
	}
	if rw.CheckAndAccept(staleSeq + 1) {
		t.Fatalf("replayed boundary sequence %d must be rejected", staleSeq+1)
	}
}

func TestWireCryptoDirectionSeparationPFSAndTamper(t *testing.T) {
	var masterKey [32]byte
	_, _ = rand.Read(masterKey[:])

	eng, err := NewWireCryptoEngine(masterKey)
	if err != nil {
		t.Fatalf("NewWireCryptoEngine failed: %v", err)
	}

	// 1. Pre-session envelope (SID=0) direction separation & 22-byte AAD tamper detection
	plain := []byte{ProtocolMagic0, ProtocolMagic1, PktData, 1, 2, 3, 4, 5, 6, 7, 8}
	wire := eng.SealWith(plain, DirClientToServer, 0, 42, nil)

	if _, _, ok := eng.PeekHeader(wire, DirServerToClient); ok {
		t.Fatalf("cross-direction reflection packet must be rejected at PeekHeader")
	}

	sid, seq, ok := eng.PeekHeader(wire, DirClientToServer)
	if !ok || sid != 0 || seq != 42 {
		t.Fatalf("valid C2S pre-session header failed PeekHeader: sid=%d seq=%d ok=%v", sid, seq, ok)
	}
	got, ok := eng.OpenAfterPeek(wire, DirClientToServer, seq, nil)
	if !ok || !bytes.Equal(got, plain) {
		t.Fatalf("valid C2S pre-session packet failed to open")
	}

	for i := 0; i < OuterHeaderSize; i++ {
		tampered := append([]byte(nil), wire...)
		tampered[i] ^= 0x01
		if _, tSeq, pOK := eng.PeekHeader(tampered, DirClientToServer); pOK {
			if _, dOK := eng.OpenAfterPeek(tampered, DirClientToServer, tSeq, nil); dOK {
				t.Fatalf("outer header tamper at byte %d must be rejected", i)
			}
		}
	}

	// 2. X25519 PFS per-session AEAD derivation & SID masking
	cliPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client X25519 keygen failed: %v", err)
	}
	srvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server X25519 keygen failed: %v", err)
	}
	cliShared, err := cliPriv.ECDH(srvPriv.PublicKey())
	if err != nil {
		t.Fatalf("client ECDH failed: %v", err)
	}
	srvShared, err := srvPriv.ECDH(cliPriv.PublicKey())
	if err != nil {
		t.Fatalf("server ECDH failed: %v", err)
	}

	const testTID uint64 = 0x1122334455667788
	const testSID uint32 = 0xAABBCCDD
	cliPair, err := deriveSessionAEAD(masterKey, cliShared, testTID, testSID)
	if err != nil {
		t.Fatalf("client deriveSessionAEAD failed: %v", err)
	}
	srvPair, err := deriveSessionAEAD(masterKey, srvShared, testTID, testSID)
	if err != nil {
		t.Fatalf("server deriveSessionAEAD failed: %v", err)
	}

	pfsWire := eng.SealWith(plain, DirClientToServer, testSID, 77, cliPair.c2sAEAD)
	gotSID, gotSeq, ok := eng.PeekHeader(pfsWire, DirClientToServer)
	if !ok || gotSID != testSID || gotSeq != 77 {
		t.Fatalf("PFS header unmask failed: got sid=%x seq=%d ok=%v", gotSID, gotSeq, ok)
	}
	// Pre-session key must fail to decrypt PFS session packet
	if _, ok := eng.OpenAfterPeek(pfsWire, DirClientToServer, gotSeq, nil); ok {
		t.Fatalf("pre-session AEAD must not decrypt X25519 PFS packet")
	}
	pfsPlain, ok := eng.OpenAfterPeek(pfsWire, DirClientToServer, gotSeq, srvPair.c2sAEAD)
	if !ok || !bytes.Equal(pfsPlain, plain) {
		t.Fatalf("server failed to decrypt X25519 PFS packet")
	}
}

func TestStatelessCookieBindsIPPortAndTxID(t *testing.T) {
	srv := &OpenFIRServer{}
	_, _ = rand.Read(srv.cookieSecret[:])

	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345}
	peerDiffPort := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12346}
	peerDiffIP := &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 12345}

	cookie := srv.computeStatelessCookie(peer, 999, time.Now().Unix()/30)
	if !srv.verifyStatelessCookie(peer, 999, cookie[:]) {
		t.Fatalf("valid cookie must be accepted")
	}
	if srv.verifyStatelessCookie(peerDiffPort, 999, cookie[:]) {
		t.Fatalf("cookie must reject mismatched client port")
	}
	if srv.verifyStatelessCookie(peerDiffIP, 999, cookie[:]) {
		t.Fatalf("cookie must reject mismatched client IP")
	}
	if srv.verifyStatelessCookie(peer, 1000, cookie[:]) {
		t.Fatalf("cookie must reject mismatched transfer ID")
	}
}

func TestValidateSafeExtractPath(t *testing.T) {
	absRoot, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatalf("filepath.Abs failed: %v", err)
	}

	valid := []string{"file.txt", "nested/dir/asset.dat"}
	for _, rel := range valid {
		if _, err := validateSafeExtractPath(absRoot, rel); err != nil {
			t.Fatalf("expected valid path %q to succeed, got %v", rel, err)
		}
	}

	unsafe := []string{"..", ".", "../escape.txt", "a/../../escape.txt", "/etc/passwd", "bad\x00name", "win\\slash.txt"}
	for _, rel := range unsafe {
		if _, err := validateSafeExtractPath(absRoot, rel); err == nil {
			t.Fatalf("expected unsafe path %q to be rejected", rel)
		}
	}
}

func TestCoprimePhiStrideAndZeroChunk(t *testing.T) {
	for n := 1; n <= 64; n++ {
		s := selectCoprimePhiStride(n)
		if gcdInt(s, n) != 1 {
			t.Fatalf("stride %d is not coprime to numSockets=%d", s, n)
		}
	}

	zeros := make([]byte, DefaultChunkSize)
	if !isAllZero(zeros) {
		t.Fatalf("expected all-zero slice to return true")
	}
	zeros[DefaultChunkSize-1] = 1
	if isAllZero(zeros) {
		t.Fatalf("expected non-zero slice to return false")
	}
}
