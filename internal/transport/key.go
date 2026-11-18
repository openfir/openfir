package transport

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HKDF derives one 32-byte output with HKDF-SHA256.
func HKDF(ikm, salt, info []byte) [32]byte {
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
