package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type forwarding struct{ Listen, Remote string }
type profile struct {
	Listen, Server string
	Auth           json.RawMessage
	TLS            struct{ Cert, Key, CA, SNI string }
	OpenFIR        struct {
		Key     string
		Sockets int
	}
	Obfs struct {
		Type       string
		Salamander struct{ Password string }
	} // previous generated profile
	Socks5                       struct{ Listen, Username, Password string }
	TCPForwarding, UDPForwarding []forwarding
	password                     string
	secret                       []byte
	security                     *tls.Config
}

func loadProfile(path string, server bool) (*profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p profile
	if err = json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.OpenFIR.Key == "" && p.Obfs.Type == "salamander" {
		p.OpenFIR.Key = p.Obfs.Salamander.Password
	}
	p.secret, err = base64.RawURLEncoding.DecodeString(p.OpenFIR.Key)
	if err != nil || len(p.secret) != 32 {
		return nil, errors.New("expected a generated 256-bit OpenFIR transport key")
	}
	if p.OpenFIR.Sockets == 0 {
		p.OpenFIR.Sockets = 4
	}
	filename := func(name string) string {
		if filepath.IsAbs(name) {
			return name
		}
		return filepath.Join(filepath.Dir(path), name)
	}
	p.security = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"openfir-proxy/1"}}
	if server {
		var a struct{ Type, Password string }
		if err := json.Unmarshal(p.Auth, &a); err != nil || a.Type != "password" {
			return nil, errors.New("invalid server password profile")
		}
		p.password = a.Password
		if p.Listen == "" {
			return nil, errors.New("missing server listen address")
		}
		cert, err := tls.LoadX509KeyPair(filename(p.TLS.Cert), filename(p.TLS.Key))
		if err != nil {
			return nil, err
		}
		p.security.Certificates = []tls.Certificate{cert}
	} else {
		if err := json.Unmarshal(p.Auth, &p.password); err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(p.Server)
		if err != nil {
			return nil, err
		}
		p.security.ServerName = host
		if p.TLS.SNI != "" {
			p.security.ServerName = p.TLS.SNI
		}
		pem, err := os.ReadFile(filename(p.TLS.CA))
		if err != nil {
			return nil, err
		}
		p.security.RootCAs = x509.NewCertPool()
		if !p.security.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid server trust certificate")
		}
	}
	if len(p.password) == 0 || len(p.password) > 255 {
		return nil, fmt.Errorf("proxy password must be 1..255 bytes")
	}
	return &p, nil
}
