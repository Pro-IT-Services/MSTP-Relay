package portal

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"

	"graphrelay/internal/config"
)

func (e *portalEnv) download(t *testing.T, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := e.client.Get(e.url + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestCertificateDownloads(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})

	// Nothing is served before sign-in.
	for _, path := range []string{"/settings/certs/ecdsa/0/pem", "/settings/certs/rsa/0/der", "/settings/ca-bundle.pem"} {
		if resp, _ := e.download(t, path); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("%s without login = %d", path, resp.StatusCode)
		}
	}
	resp, _ := e.signIn(t, map[string]any{"roles": []string{"Relay.Admin"}})
	resp.Body.Close()

	_, page := e.get(t, "/settings")
	for _, want := range []string{"TLS certificates", "Server certificate (self-signed)", "ECDSA certificate", "RSA certificate",
		`href="/settings/certs/ecdsa/0/der"`, `href="/settings/certs/rsa/0/pem"`, "RSA 2048", `href="/settings/ca-bundle.pem"`} {
		if !strings.Contains(page, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}

	// PEM: one CERTIFICATE block that parses and names the relay.
	resp, body := e.download(t, "/settings/certs/ecdsa/0/pem")
	block, rest := pem.Decode(body)
	if resp.StatusCode != 200 || block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("pem download = %d %q", resp.StatusCode, body)
	}
	fromPEM, err := x509.ParseCertificate(block.Bytes)
	if err != nil || fromPEM.Subject.CommonName != "relay.test" {
		t.Fatalf("pem certificate: %v", err)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="relay.test-ecdsa.pem"` {
		t.Errorf("Content-Disposition = %q", cd)
	}

	// DER: the same certificate in binary form, as a .cer file.
	resp, body = e.download(t, "/settings/certs/ecdsa/0/der")
	fromDER, err := x509.ParseCertificate(body)
	if resp.StatusCode != 200 || err != nil || !fromDER.Equal(fromPEM) {
		t.Fatalf("der download = %d, %v", resp.StatusCode, err)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="relay.test-ecdsa.cer"` {
		t.Errorf("Content-Disposition = %q", cd)
	}

	// The RSA fallback certificate is a different certificate with an RSA key.
	resp, body = e.download(t, "/settings/certs/rsa/0/der")
	fromRSA, err := x509.ParseCertificate(body)
	if resp.StatusCode != 200 || err != nil || fromRSA.Equal(fromPEM) || fromRSA.PublicKeyAlgorithm != x509.RSA {
		t.Fatalf("rsa download = %d, %v", resp.StatusCode, err)
	}

	// Self-signed server certificates are their own CAs, so the bundle holds both, once each.
	resp, body = e.download(t, "/settings/ca-bundle.pem")
	var bundle []*x509.Certificate
	for block, rest := pem.Decode(body); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, c)
	}
	if resp.StatusCode != 200 || len(bundle) != 2 || !bundle[0].Equal(fromPEM) || !bundle[1].Equal(fromRSA) {
		t.Fatalf("bundle = %d with %d certificates", resp.StatusCode, len(bundle))
	}

	for _, path := range []string{"/settings/certs/ecdsa/9/pem", "/settings/certs/ecdsa/-1/pem", "/settings/certs/ecdsa/x/pem",
		"/settings/certs/ecdsa/0/exe", "/settings/certs/dsa/0/pem"} {
		if resp, _ := e.download(t, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestCertFileName(t *testing.T) {
	for cn, want := range map[string]string{
		"relay.example.com": "relay.example.com",
		"ISRG Root X1":      "isrg-root-x1",
		"../../etc/passwd":  "etc-passwd",
		`a"b\c`:             "a-b-c",
		"":                  "certificate",
	} {
		c := &x509.Certificate{}
		c.Subject.CommonName = cn
		if got := certFileName(c); got != want {
			t.Errorf("certFileName(%q) = %q, want %q", cn, got, want)
		}
	}
}
