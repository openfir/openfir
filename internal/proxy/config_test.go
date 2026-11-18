package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPairedProfiles(t *testing.T) {
	for _, endpoint := range []string{"relay.example.org:443", "[::1]:443", "127.0.0.1:443"} {
		t.Run(endpoint, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "profiles")
			const socks = "127.0.0.1:1081"
			if err := Init(dir, endpoint, socks, 4); err != nil {
				t.Fatal(err)
			}
			if err := Init(dir, endpoint, socks, 4); err == nil {
				t.Fatal("second initialization replaced existing profiles")
			}
			read := func(name string) []byte {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			var client struct {
				Server  string
				Auth    string
				OpenFIR json.RawMessage
				TLS     struct{ CA string }
				Socks5  struct{ Listen string }
			}
			var server struct {
				Listen  string
				Auth    struct{ Type, Password string }
				OpenFIR json.RawMessage
				TLS     struct{ Cert, Key string }
			}
			if err := json.Unmarshal(read("client/config.json"), &client); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(read("server/config.json"), &server); err != nil {
				t.Fatal(err)
			}
			if client.Server != endpoint || client.Socks5.Listen != socks || server.Listen != ":443" ||
				len(client.Auth) < 32 || server.Auth.Type != "password" || server.Auth.Password != client.Auth ||
				len(client.OpenFIR) == 0 || string(client.OpenFIR) != string(server.OpenFIR) {
				t.Fatal("profiles disagree on relay settings or credentials")
			}
			pair, err := tls.X509KeyPair(read("server/"+server.TLS.Cert), read("server/"+server.TLS.Key))
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(read("client/" + client.TLS.CA)) {
				t.Fatal("invalid client trust store")
			}
			host, _, _ := net.SplitHostPort(endpoint)
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
				t.Fatal(err)
			}
			if err := leaf.VerifyHostname("wrong.example.org"); err == nil {
				t.Fatal("accepted unexpected hostname")
			}
			if _, err := os.Stat(filepath.Join(dir, "client", server.TLS.Key)); !os.IsNotExist(err) {
				t.Fatal("client profile contains server private key")
			}
		})
	}
}
