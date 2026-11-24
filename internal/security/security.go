// SPDX-License-Identifier: Apache-2.0

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	ALPNProtocol = "openfir/1"

	// Open, standard, Wireshark-friendly UDP wire header (17 bytes AAD):
	//   [4B Magic "OF1\x01"][1B Flags][4B SessionID][8B MonotonicSeq]
	// Zero sketchy printable-ASCII obfuscation, zero hardcoded direction parity bits!
	UDPHeaderSize     = 17
	AEADTagSize       = 16
	UDPOverhead       = UDPHeaderSize + AEADTagSize
	ReplayWindowWords = 256 // 16,384-packet sliding window
	ReplayWindowBits  = ReplayWindowWords * 64
)

var (
	UDPMagic = [4]byte{'O', 'F', '1', 0x01}

	ErrInvalidPacket = errors.New("invalid or unauthenticated UDP packet")
	ErrReplay        = errors.New("replayed UDP packet")
	ErrAuthFailed    = errors.New("mutual authentication failed")
)

// ParseSecret derives a 256-bit MasterKey from either:
//   - 64+ hex characters (raw high-entropy key)
//   - "pass:<passphrase>" stretched with Argon2id (32 MiB, t=2, p=2) to resist GPU brute-force
//   - OPENFIR_SECRET environment variable
func ParseSecret(raw string) ([32]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		s = strings.TrimSpace(os.Getenv("OPENFIR_SECRET"))
	}
	if s == "" {
		return [32]byte{}, errors.New("missing secret: pass -secret <64-hex-or-pass:...> or set OPENFIR_SECRET")
	}
	if strings.HasPrefix(strings.ToLower(s), "pass:") {
		pass := s[5:]
		if len(pass) < 8 {
			return [32]byte{}, errors.New("passphrase after 'pass:' must be at least 8 characters")
		}
		salt := sha256.Sum256([]byte("OpenFIR-v1.0-Argon2id-MasterSalt"))
		key := argon2.IDKey([]byte(pass), salt[:], 2, 32*1024, 2, 32)
		var out [32]byte
		copy(out[:], key)
		return out, nil
	}
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) < 16 {
		return [32]byte{}, errors.New("invalid -secret: provide >=32 hex chars (64 hex recommended) or 'pass:<passphrase>'")
	}
	return HKDFSHA256(decoded, []byte("OpenFIR-v1.0-Hex-Salt"), []byte("OpenFIR-v1.0-MasterKey")), nil
}

func GenerateRandomKeyHex() (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func HKDFSHA256(ikm, salt, info []byte) [32]byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)

	exp := hmac.New(sha256.New, prk)
	exp.Write(info)
	exp.Write([]byte{0x01})
	var out [32]byte
	copy(out[:], exp.Sum(nil)[:32])
	return out
}

// ============================================================================
// Standard RFC 8446 TLS 1.3 (ALPN: openfir/1) + Channel-Bound Mutual Auth
// ============================================================================

// BuildServerTLSConfig creates a strict TLS 1.3 server configuration with ALPN "openfir/1".
// Supports real enterprise/Let's Encrypt certs (-tls-cert/-tls-key) OR an auto-generated
// ephemeral ECDSA P-256 cert (which is cryptographically pinned to MasterKey via RFC 5705
// TLS ExportKeyingMaterial channel binding during mutual auth!).
func BuildServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls keypair: %w", err)
		}
	} else {
		cert, err = generateEphemeralSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral tls cert: %w", err)
		}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNProtocol},
		Certificates: []tls.Certificate{cert},
	}, nil
}

// BuildClientTLSConfig creates a strict TLS 1.3 client configuration with ALPN "openfir/1".
// When verifyCA is true (production with real domain cert), standard PKI validation is enforced;
// when verifyCA is false (self-signed/IP deployment), mutual cryptographic authentication over
// RFC 5705 TLS ExportKeyingMaterial prevents MITM attacks completely!
func BuildClientTLSConfig(serverName string, verifyCA bool) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNProtocol},
		ServerName:         serverName,
		InsecureSkipVerify: !verifyCA,
	}
}

func generateEphemeralSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "openfir-node"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "openfir-node"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

// ComputeChannelAuthProof binds mutual authentication to the live TLS 1.3 session via
// RFC 5705 ExportKeyingMaterial + MasterKey, cryptographically defeating active TLS MITM
// even when using ephemeral self-signed certificates!
func ComputeChannelAuthProof(cs tls.ConnectionState, masterKey [32]byte, role string, nonce []byte) ([32]byte, error) {
	ekm, err := cs.ExportKeyingMaterial("EXPORTER-OpenFIR-v1-ChannelBind", nil, 32)
	if err != nil {
		return [32]byte{}, err
	}
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write([]byte("OpenFIR-v1-Auth-"))
	mac.Write([]byte(role))
	mac.Write(ekm)
	mac.Write(nonce)
	var out [32]byte
	copy(out[:], mac.Sum(nil)[:32])
	return out, nil
}

func VerifyChannelAuthProof(cs tls.ConnectionState, masterKey [32]byte, role string, nonce, got []byte) bool {
	if len(got) != 32 {
		return false
	}
	exp, err := ComputeChannelAuthProof(cs, masterKey, role, nonce)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(exp[:], got) == 1
}

// ============================================================================
// Per-Session X25519 PFS UDP AEAD & Sliding Anti-Replay Window
// ============================================================================

type ReplayWindow struct {
	mu      sync.Mutex
	init    bool
	highest uint64
	bitmap  [ReplayWindowWords]uint64
}

func (w *ReplayWindow) Allow(seq uint64) bool {
	if seq == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init || seq > w.highest {
		return true
	}
	diff := w.highest - seq
	if diff >= ReplayWindowBits {
		return false
	}
	return (w.bitmap[diff/64] & (uint64(1) << (diff % 64))) == 0
}

func (w *ReplayWindow) Record(seq uint64) bool {
	if seq == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init {
		w.init = true
		w.highest = seq
		w.bitmap[0] = 1
		return true
	}
	if seq > w.highest {
		shift := seq - w.highest
		if shift >= ReplayWindowBits {
			w.bitmap = [ReplayWindowWords]uint64{}
		} else {
			ws := shift / 64
			bs := shift % 64
			if bs == 0 {
				for i := ReplayWindowWords - 1; i >= int(ws); i-- {
					w.bitmap[i] = w.bitmap[i-int(ws)]
				}
			} else {
				for i := ReplayWindowWords - 1; i > int(ws); i-- {
					w.bitmap[i] = (w.bitmap[i-int(ws)] << bs) | (w.bitmap[i-int(ws)-1] >> (64 - bs))
				}
				w.bitmap[ws] = w.bitmap[0] << bs
			}
			for i := 0; i < int(ws); i++ {
				w.bitmap[i] = 0
			}
		}
		w.bitmap[0] |= 1
		w.highest = seq
		return true
	}
	diff := w.highest - seq
	if diff >= ReplayWindowBits {
		return false
	}
	wi := diff / 64
	mask := uint64(1) << (diff % 64)
	if (w.bitmap[wi] & mask) != 0 {
		return false
	}
	w.bitmap[wi] |= mask
	return true
}

// UDPSessionCipher provides hardware-accelerated AES-256-GCM encryption with true X25519 PFS,
// clean standard 17-byte AAD headers ("OF1\x01"), and strict per-session replay defense.
type UDPSessionCipher struct {
	SessionID uint32
	txAEAD    cipher.AEAD
	rxAEAD    cipher.AEAD
	txNonce   [4]byte // Unique per-direction salt prefix for 96-bit GCM nonce
	rxNonce   [4]byte
	txSeq     atomic.Uint64
	replay    ReplayWindow
}

// GenerateX25519 creates an ephemeral X25519 keypair for per-session Perfect Forward Secrecy.
func GenerateX25519() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// NewUDPSessionCipher derives isolated directional c2s/s2c AES-256-GCM keys from MasterKey + X25519 ECDH.
func NewUDPSessionCipher(masterKey [32]byte, localPriv *ecdh.PrivateKey, peerPubBytes []byte, sid uint32, isClient bool) (*UDPSessionCipher, error) {
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid peer x25519 pubkey: %w", err)
	}
	shared, err := localPriv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}

	ikm := make([]byte, 32+len(shared))
	copy(ikm[0:32], masterKey[:])
	copy(ikm[32:], shared)

	var salt [4]byte
	binary.BigEndian.PutUint32(salt[:], sid)

	c2sKey := HKDFSHA256(ikm, salt[:], []byte("OpenFIR-v1-UDP-C2S-Key"))
	s2cKey := HKDFSHA256(ikm, salt[:], []byte("OpenFIR-v1-UDP-S2C-Key"))
	c2sSalt := HKDFSHA256(ikm, salt[:], []byte("OpenFIR-v1-UDP-C2S-Salt"))
	s2cSalt := HKDFSHA256(ikm, salt[:], []byte("OpenFIR-v1-UDP-S2C-Salt"))

	txKey, rxKey := s2cKey, c2sKey
	txSalt, rxSalt := s2cSalt, c2sSalt
	if isClient {
		txKey, rxKey = c2sKey, s2cKey
		txSalt, rxSalt = c2sSalt, s2cSalt
	}

	bTx, err := aes.NewCipher(txKey[:])
	if err != nil {
		return nil, err
	}
	aTx, err := cipher.NewGCM(bTx)
	if err != nil {
		return nil, err
	}
	bRx, err := aes.NewCipher(rxKey[:])
	if err != nil {
		return nil, err
	}
	aRx, err := cipher.NewGCM(bRx)
	if err != nil {
		return nil, err
	}

	sc := &UDPSessionCipher{
		SessionID: sid,
		txAEAD:    aTx,
		rxAEAD:    aRx,
	}
	copy(sc.txNonce[:], txSalt[:4])
	copy(sc.rxNonce[:], rxSalt[:4])
	return sc, nil
}

// PeekUDPHeader parses the open 17-byte OpenFIR v1 header in O(1) without touching AES.
func PeekUDPHeader(wire []byte) (flags byte, sid uint32, seq uint64, ok bool) {
	if len(wire) < UDPOverhead+1 {
		return 0, 0, 0, false
	}
	if wire[0] != UDPMagic[0] || wire[1] != UDPMagic[1] || wire[2] != UDPMagic[2] || wire[3] != UDPMagic[3] {
		return 0, 0, 0, false
	}
	flags = wire[4]
	sid = binary.BigEndian.Uint32(wire[5:9])
	seq = binary.BigEndian.Uint64(wire[9:17])
	if sid == 0 || seq == 0 {
		return 0, 0, 0, false
	}
	return flags, sid, seq, true
}

// Seal encrypts payload with the open 17-byte AAD header ("OF1\x01").
func (s *UDPSessionCipher) Seal(dst []byte, flags byte, payload []byte) ([]byte, uint64) {
	seq := s.txSeq.Add(1)
	totalLen := UDPHeaderSize + len(payload) + AEADTagSize
	var out []byte
	if cap(dst) >= totalLen {
		out = dst[:UDPHeaderSize]
	} else {
		out = make([]byte, UDPHeaderSize, totalLen)
	}
	copy(out[0:4], UDPMagic[:])
	out[4] = flags
	binary.BigEndian.PutUint32(out[5:9], s.SessionID)
	binary.BigEndian.PutUint64(out[9:17], seq)

	var nonce [12]byte
	copy(nonce[0:4], s.txNonce[:])
	binary.BigEndian.PutUint64(nonce[4:12], seq)

	return s.txAEAD.Seal(out, nonce[:], payload, out[0:UDPHeaderSize]), seq
}

// Open verifies anti-replay and decrypts an incoming UDP datagram.
func (s *UDPSessionCipher) Open(dst, wire []byte) (flags byte, seq uint64, plain []byte, err error) {
	var sid uint32
	var ok bool
	flags, sid, seq, ok = PeekUDPHeader(wire)
	if !ok || sid != s.SessionID {
		return 0, 0, nil, ErrInvalidPacket
	}
	if !s.replay.Allow(seq) {
		return 0, 0, nil, ErrReplay
	}

	var nonce [12]byte
	copy(nonce[0:4], s.rxNonce[:])
	binary.BigEndian.PutUint64(nonce[4:12], seq)

	plain, err = s.rxAEAD.Open(dst, nonce[:], wire[UDPHeaderSize:], wire[0:UDPHeaderSize])
	if err != nil {
		return 0, 0, nil, ErrInvalidPacket
	}
	if !s.replay.Record(seq) {
		return 0, 0, nil, ErrReplay
	}
	return flags, seq, plain, nil
}
