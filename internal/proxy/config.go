// Package proxy prepares paired native UDP proxy configurations for OpenFIR proxy modes.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func password() (string, error) {
	var b [32]byte
	_, err := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), err
}

func certificate(host string) (cert, key []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), nil
}

func Init(dir, endpoint, socks string, paths int) error {
	if paths < 1 || paths > 16 {
		return errors.New("-sockets must be in [1,16]")
	}
	host, port, err := net.SplitHostPort(endpoint)
	portNum, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid proxy endpoint %q, expected host:port", endpoint)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return errors.New("use the address clients will connect to for -server")
	}
	addr, err := net.ResolveTCPAddr("tcp", socks)
	if err != nil || addr.Port == 0 || !addr.IP.IsLoopback() {
		return errors.New("-socks must be a loopback address with a nonzero port")
	}
	auth, err := password()
	if err != nil {
		return err
	}
	transportKey, err := password()
	if err != nil {
		return err
	}
	cert, key, err := certificate(host)
	if err != nil {
		return err
	}
	wire := map[string]any{"key": transportKey, "sockets": paths}
	serverConfig := map[string]any{
		"listen":  net.JoinHostPort("", port),
		"auth":    map[string]string{"type": "password", "password": auth},
		"openfir": wire,
		"tls":     map[string]string{"cert": "server.crt", "key": "server.key"},
	}
	clientConfig := map[string]any{
		"server":  endpoint,
		"auth":    auth,
		"openfir": wire,
		"tls":     map[string]string{"ca": "server.crt"},
		"socks5":  map[string]string{"listen": addr.String()},
	}
	// Reserve a fresh directory so a second invocation cannot replace credentials.
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	err = writeProfile(filepath.Join(dir, "server"), serverConfig, cert, key)
	if err == nil {
		err = writeProfile(filepath.Join(dir, "client"), clientConfig, cert, nil)
	}
	if err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	return nil
}

func writeProfile(dir string, config map[string]any, cert, key []byte) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), cert, 0600); err != nil {
		return err
	}
	if key != nil {
		return os.WriteFile(filepath.Join(dir, "server.key"), key, 0600)
	}
	return nil
}
