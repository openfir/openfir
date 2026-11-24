// SPDX-License-Identifier: Apache-2.0

package compress

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"sync"

	"github.com/openfir/openfir/internal/cdc"
)

const (
	EncodingRaw     uint8 = 0x00 // Uncompressed raw bytes (used for high-entropy/media blocks)
	EncodingDeflate uint8 = 0x01 // Standard RFC 1951 DEFLATE fast compression (>=10% savings, Go stdlib)
	EncodingZero    uint8 = 0x02 // Sparse all-zero block (0 wire bytes!)
)

var (
	encPool = sync.Pool{
		New: func() any {
			w, err := flate.NewWriter(io.Discard, flate.BestSpeed)
			if err != nil {
				panic(err)
			}
			return w
		},
	}
)

func deflateBytes(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(len(src)/2 + 64)
	w := encPool.Get().(*flate.Writer)
	w.Reset(&buf)
	_, wErr := w.Write(src)
	cErr := w.Close()
	encPool.Put(w)
	if wErr != nil {
		return nil, wErr
	}
	if cErr != nil {
		return nil, cErr
	}
	return buf.Bytes(), nil
}

// CompressBlock performs adaptive entropy-gated block compression using Go stdlib RFC 1951 DEFLATE:
//   - All-zero blocks -> EncodingZero (0 wire bytes!)
//   - Incompressible blocks (sampled on first 4KB) -> EncodingRaw (near-zero CPU bypass!)
//   - Compressible blocks (>=10% savings) -> EncodingDeflate (100% public-domain RFC 1951 DEFLATE)
func CompressBlock(raw []byte) (encoding uint8, wirePayload []byte) {
	if len(raw) == 0 {
		return EncodingRaw, nil
	}
	if cdc.IsAllZero(raw) {
		return EncodingZero, nil
	}
	// Fast 4KB sample bypass for incompressible media/archives/encrypted payloads
	if len(raw) >= 12*1024 {
		probe, err := deflateBytes(raw[:4096])
		if err != nil || len(probe) > (4096*92)/100 {
			return EncodingRaw, raw
		}
	}
	comp, err := deflateBytes(raw)
	if err == nil && len(comp) < (len(raw)*90)/100 {
		return EncodingDeflate, comp
	}
	return EncodingRaw, raw
}

// DecompressBlock restores the original exact expectedLen block from wirePayload.
func DecompressBlock(encoding uint8, wirePayload []byte, expectedLen int) ([]byte, error) {
	switch encoding {
	case EncodingZero:
		if expectedLen < 0 {
			return nil, errors.New("negative zero-block length")
		}
		return make([]byte, expectedLen), nil
	case EncodingRaw:
		if len(wirePayload) != expectedLen {
			return nil, errors.New("raw block length mismatch")
		}
		return wirePayload, nil
	case EncodingDeflate:
		if expectedLen < 0 {
			return nil, errors.New("negative deflate block length")
		}
		r := flate.NewReader(bytes.NewReader(wirePayload))
		defer r.Close()
		out := make([]byte, expectedLen)
		n, err := io.ReadFull(r, out)
		if err != nil || n != expectedLen {
			return nil, errors.New("deflate decompressed length mismatch")
		}
		// Ensure no trailing uncompressed garbage beyond expectedLen
		var extra [1]byte
		if en, _ := r.Read(extra[:]); en != 0 {
			return nil, errors.New("deflate stream exceeded expected block length")
		}
		return out, nil
	default:
		return nil, errors.New("unknown block encoding")
	}
}
