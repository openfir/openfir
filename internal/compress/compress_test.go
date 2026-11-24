// SPDX-License-Identifier: Apache-2.0

package compress

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestAdaptiveEntropyGatedCompression(t *testing.T) {
	// 1. All-zero sparse block -> EncodingZero with 0 wire bytes
	zeros := make([]byte, 64*1024)
	enc, wire := CompressBlock(zeros)
	if enc != EncodingZero || len(wire) != 0 {
		t.Fatalf("expected EncodingZero with 0 wire bytes, got enc=%d len=%d", enc, len(wire))
	}
	dec, err := DecompressBlock(enc, wire, len(zeros))
	if err != nil || !bytes.Equal(dec, zeros) {
		t.Fatalf("failed to restore zero block: err=%v", err)
	}

	// 2. Highly compressible structured log block -> EncodingDeflate with >=50% reduction
	text := bytes.Repeat([]byte(`{"ts":"2026-11-24T09:00:00Z","service":"openfir","level":"INFO","msg":"block verified"}`+"\n"), 800)
	enc, wire = CompressBlock(text)
	if enc != EncodingDeflate || len(wire) >= len(text)/2 {
		t.Fatalf("expected strong RFC 1951 DEFLATE compression, got enc=%d wire=%d raw=%d", enc, len(wire), len(text))
	}
	dec, err = DecompressBlock(enc, wire, len(text))
	if err != nil || !bytes.Equal(dec, text) {
		t.Fatalf("DEFLATE round-trip mismatch: err=%v", err)
	}

	// 3. Incompressible high-entropy block -> 4KB sample bypass -> EncodingRaw
	rnd := make([]byte, 64*1024)
	if _, err := io.ReadFull(rand.Reader, rnd); err != nil {
		t.Fatal(err)
	}
	enc, wire = CompressBlock(rnd)
	if enc != EncodingRaw || !bytes.Equal(wire, rnd) {
		t.Fatalf("expected 4KB entropy bypass to EncodingRaw, got enc=%d len=%d", enc, len(wire))
	}
	dec, err = DecompressBlock(enc, wire, len(rnd))
	if err != nil || !bytes.Equal(dec, rnd) {
		t.Fatalf("raw round-trip mismatch: err=%v", err)
	}
}
