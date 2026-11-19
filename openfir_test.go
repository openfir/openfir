// Copyright 2026 The OpenFIR Authors.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"bytes"
	"crypto/rand"
	"testing"
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
		t.Fatalf("stale sequence 5001 outside window must be rejected")
	}
}

func TestWireCryptoDirectionSeparationAndTamper(t *testing.T) {
	var masterKey [32]byte
	_, _ = rand.Read(masterKey[:])

	eng, err := NewWireCryptoEngine(masterKey)
	if err != nil {
		t.Fatalf("NewWireCryptoEngine failed: %v", err)
	}

	plain := []byte{ProtocolMagic0, ProtocolMagic1, PktData, 1, 2, 3, 4, 5, 6, 7, 8}
	wire := eng.Seal(plain, DirClientToServer, 42)

	if _, _, ok := eng.Open(wire, DirServerToClient); ok {
		t.Fatalf("cross-direction reflection packet must be rejected")
	}

	got, seq, ok := eng.Open(wire, DirClientToServer)
	if !ok || seq != 42 || !bytes.Equal(got, plain) {
		t.Fatalf("valid C2S packet failed to open")
	}

	// Verify that mutating any single byte across the entire 18-byte outer header fails authentication
	for i := 0; i < OuterHeaderSize; i++ {
		tampered := append([]byte(nil), wire...)
		tampered[i] ^= 0x01
		if _, _, ok := eng.Open(tampered, DirClientToServer); ok {
			t.Fatalf("outer header tamper at byte %d must be rejected", i)
		}
	}
}
