// SPDX-License-Identifier: Apache-2.0

package security

import (
	"bytes"
	"testing"
)

func TestParseSecretArgon2idAndHex(t *testing.T) {
	k1, err := ParseSecret("pass:EnterpriseSecret2026!")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseSecret("pass:EnterpriseSecret2026!")
	if err != nil {
		t.Fatal(err)
	}
	k3, err := ParseSecret("pass:DifferentSecret2026!")
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatal("Argon2id key derivation must be deterministic")
	}
	if k1 == k3 {
		t.Fatal("distinct passphrases must yield distinct keys")
	}
	if _, err := ParseSecret("pass:short"); err == nil {
		t.Fatal("expected short passphrase rejection")
	}

	hexKey, err := GenerateRandomKeyHex()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSecret(hexKey); err != nil {
		t.Fatalf("failed to parse generated hex key: %v", err)
	}
}

func TestUDPSessionCipherPFSHeaderTamperAndReplayWindow(t *testing.T) {
	mk, _ := ParseSecret("pass:OpenFIR-Test-PFS-Key!")
	cPriv, cPub, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	sPriv, sPub, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewUDPSessionCipher(mk, cPriv, sPub, 0x11223344, true)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewUDPSessionCipher(mk, sPriv, cPub, 0x11223344, false)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("openfir-v1-standard-wire-payload")
	wire, seq := cli.Seal(nil, 0x03, msg)
	if seq != 1 {
		t.Fatalf("expected seq=1, got %d", seq)
	}
	// Verify open Wireshark-friendly "OF1\x01" header
	fl, sid, pSeq, ok := PeekUDPHeader(wire)
	if !ok || fl != 0x03 || sid != 0x11223344 || pSeq != 1 {
		t.Fatalf("PeekUDPHeader mismatch: ok=%v fl=%d sid=%x seq=%d", ok, fl, sid, pSeq)
	}

	// Tampering any AAD header byte must fail AES-256-GCM verification
	tampered := append([]byte(nil), wire...)
	tampered[4] ^= 0x01
	if _, _, _, err := srv.Open(nil, tampered); err == nil {
		t.Fatal("expected AAD header tamper to fail authentication")
	}

	// Directional isolation: client cannot decrypt its own c2s packet
	if _, _, _, err := cli.Open(nil, wire); err == nil {
		t.Fatal("expected directional key isolation to reject self-decrypt")
	}

	// Valid decrypt succeeds once, immediate replay must fail with ErrReplay
	gotFl, gotSeq, gotPlain, err := srv.Open(nil, wire)
	if err != nil || gotFl != 0x03 || gotSeq != 1 || !bytes.Equal(gotPlain, msg) {
		t.Fatalf("valid decrypt failed: err=%v plain=%q", err, gotPlain)
	}
	if _, _, _, err := srv.Open(nil, wire); err != ErrReplay {
		t.Fatalf("expected ErrReplay on duplicate packet, got %v", err)
	}

	// Verify 16,384-packet sliding window accepts out-of-order packets within window and rejects stale ones
	var rw ReplayWindow
	if !rw.Record(20000) {
		t.Fatal("expected Record(20000) to succeed")
	}
	if !rw.Record(20000 - ReplayWindowBits + 1) {
		t.Fatal("expected boundary packet inside 16384-pkt window to succeed")
	}
	if rw.Record(20000 - ReplayWindowBits) {
		t.Fatal("expected stale packet outside 16384-pkt window to be rejected")
	}
}
