package tlsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"graphrelay/internal/config"
)

// serve runs a TLS server with the manager's configuration and returns its address.
func serve(t *testing.T, m *Manager) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	return ln.Addr().String()
}

// keyServed connects with the given client settings and returns the server certificate's key type.
func keyServed(addr string, c *tls.Config) (x509.PublicKeyAlgorithm, error) {
	c.InsecureSkipVerify = true
	conn, err := tls.Dial("tcp", addr, c)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].PublicKeyAlgorithm, nil
}

// rsaOnlySuites is what an RSA-only device offers: no ECDSA suite at all. These are the ECDHE
// suites from a multifunction printer's cipher list that Go's TLS server also supports.
var rsaOnlySuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

func setup(t *testing.T, rsaFallback bool) *Manager {
	t.Helper()
	cfg := &config.Config{Hostname: "relay.test"}
	cfg.TLS.Mode = "selfsigned"
	cfg.TLS.RSAFallback = &rsaFallback
	m, err := Setup(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEachClientGetsACertificateItSupports(t *testing.T) {
	addr := serve(t, setup(t, true))

	for name, tc := range map[string]struct {
		client *tls.Config
		want   x509.PublicKeyAlgorithm
	}{
		"modern client, TLS 1.3":        {&tls.Config{}, x509.ECDSA},
		"TLS 1.2 with ECDSA suites":     {&tls.Config{MaxVersion: tls.VersionTLS12}, x509.ECDSA},
		"RSA-only device, TLS 1.2":      {&tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: rsaOnlySuites}, x509.RSA},
		"RSA-only, single GCM suite":    {&tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: rsaOnlySuites[:1]}, x509.RSA},
		"ECDSA-only client stays ECDSA": {&tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}, x509.ECDSA},
		"no SNI (many SMTP clients)":    {&tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: rsaOnlySuites, ServerName: ""}, x509.RSA},
	} {
		got, err := keyServed(addr, tc.client)
		if err != nil {
			t.Errorf("%s: handshake failed: %v", name, err)
		} else if got != tc.want {
			t.Errorf("%s: got %v certificate, want %v", name, got, tc.want)
		}
	}
}

// Without the fallback, an RSA-only device cannot connect; this is the failure the option fixes.
func TestRSAOnlyClientFailsWithoutFallback(t *testing.T) {
	addr := serve(t, setup(t, false))
	if _, err := keyServed(addr, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: rsaOnlySuites}); err == nil {
		t.Fatal("RSA-only client connected although only an ECDSA certificate exists")
	}
	if got, err := keyServed(addr, &tls.Config{}); err != nil || got != x509.ECDSA {
		t.Fatalf("modern client: %v %v", got, err)
	}
}

func TestChainsListBothKeyTypes(t *testing.T) {
	chains := setup(t, true).Chains(context.Background())
	if len(chains) != 2 || chains[0].Key != "ecdsa" || chains[1].Key != "rsa" {
		t.Fatalf("chains = %+v", chains)
	}
	if chains[0].Certs[0].PublicKeyAlgorithm != x509.ECDSA || chains[1].Certs[0].PublicKeyAlgorithm != x509.RSA {
		t.Fatal("chains carry the wrong key types")
	}
	if len(setup(t, false).Chains(context.Background())) != 1 {
		t.Fatal("RSA chain listed although the fallback is off")
	}
}
