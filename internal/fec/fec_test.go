// SPDX-License-Identifier: Apache-2.0

package fec

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestGF256FieldAxioms(t *testing.T) {
	for a := 1; a < 256; a++ {
		inv := gfInv[a]
		if gfMulTable[a][inv] != 1 {
			t.Fatalf("GF(256) inverse failed for %d: %d * %d = %d", a, a, inv, gfMulTable[a][inv])
		}
	}
}

func TestZeroLossProducesStrictlyZeroParityOverhead(t *testing.T) {
	ac := NewAdaptiveController(16, 8)
	for i := 0; i < 20; i++ {
		if p := ac.ObserveLoss(0.0); p != 0 {
			t.Fatalf("expected strictly 0 parity at 0%% loss, got %d", p)
		}
	}
	par, err := EncodeGroup(1, [][]byte{[]byte("a"), []byte("b")}, 0)
	if err != nil || len(par) != 0 {
		t.Fatalf("EncodeGroup with 0 parity emitted %d frames (err=%v)", len(par), err)
	}
}

func TestGF256RSRecoversContiguousBurstDropsWithVariableLengths(t *testing.T) {
	const D, P = 16, 4
	payloads := make([][]byte, D)
	for i := 0; i < D; i++ {
		sz := 120 + i*63 // Variable payload lengths!
		payloads[i] = make([]byte, sz)
		_, _ = io.ReadFull(rand.Reader, payloads[i])
	}

	parFrames, err := EncodeGroup(42, payloads, P)
	if err != nil || len(parFrames) != P {
		t.Fatalf("EncodeGroup failed: err=%v len=%d", err, len(parFrames))
	}

	dec := NewDecoder(64)
	// Drop 4 CONTIGUOUS packets (#5, #6, #7, #8) — a burst that breaks simple XOR completely!
	var got [][]byte
	for i := 0; i < D; i++ {
		if i >= 5 && i <= 8 {
			continue
		}
		frame := WrapDataShard(42, D, P, i, payloads[i])
		p, isNew, rec, err := dec.PushData(frame)
		if err != nil || !isNew {
			t.Fatalf("PushData(%d) failed: err=%v isNew=%v", i, err, isNew)
		}
		got = append(got, p)
		got = append(got, rec...)
	}
	for _, pf := range parFrames {
		rec, err := dec.PushParity(pf)
		if err != nil {
			t.Fatalf("PushParity failed: %v", err)
		}
		got = append(got, rec...)
	}

	if len(got) != D {
		t.Fatalf("expected all %d payloads recovered across 4-packet contiguous burst drop, got %d", D, len(got))
	}
	for i := 0; i < D; i++ {
		found := false
		for _, g := range got {
			if bytes.Equal(g, payloads[i]) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing or corrupted recovered payload #%d", i)
		}
	}
	t.Logf("PASS: Clean-Room Cauchy GF(256) RS(16,4) recovered 4 contiguous burst drops of variable-length packets in 1 solve!")
}

func TestGF256RSRecoversMixedDataAndParityDrops(t *testing.T) {
	const D, P = 16, 6
	payloads := make([][]byte, D)
	for i := 0; i < D; i++ {
		payloads[i] = make([]byte, 1200)
		_, _ = io.ReadFull(rand.Reader, payloads[i])
	}
	parFrames, err := EncodeGroup(99, payloads, P)
	if err != nil {
		t.Fatal(err)
	}
	dec := NewDecoder(64)
	// Drop 4 data shards (0, 7, 14, 15) AND 2 parity shards (1, 4) -> 12 data + 4 parity = 16 exact!
	droppedData := map[int]bool{0: true, 7: true, 14: true, 15: true}
	droppedParity := map[int]bool{1: true, 4: true}
	var got [][]byte
	for i := 0; i < D; i++ {
		if droppedData[i] {
			continue
		}
		p, _, rec, err := dec.PushData(WrapDataShard(99, D, P, i, payloads[i]))
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
		got = append(got, rec...)
	}
	for r := 0; r < P; r++ {
		if droppedParity[r] {
			continue
		}
		rec, err := dec.PushParity(parFrames[r])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, rec...)
	}
	if len(got) != D {
		t.Fatalf("expected %d recovered payloads, got %d", D, len(got))
	}
}
