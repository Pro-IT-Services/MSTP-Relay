package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// issue creates a certificate named cn, signed by parent (or self-signed when parent is nil).
func issue(t *testing.T, cn string, parent *testCA, isCA bool, aia string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if aia != "" {
		tmpl.IssuingCertificateURL = []string{aia}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert, key}
}

func managerFor(chain ...*testCA) *Manager {
	c := tls.Certificate{PrivateKey: chain[0].key}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.cert.Raw)
	}
	return &Manager{Domains: []string{"relay.test"}, TLSConfig: &tls.Config{Certificates: []tls.Certificate{c}}}
}

func stubHTTP(t *testing.T, fn func(url string) ([]byte, error)) {
	t.Helper()
	old := httpGet
	httpGet = func(_ context.Context, u string) ([]byte, error) { return fn(u) }
	t.Cleanup(func() { httpGet = old })
}

func names(chain []*x509.Certificate) (out []string) {
	for _, c := range chain {
		out = append(out, c.Subject.CommonName)
	}
	return
}

func TestChainFetchesMissingRoot(t *testing.T) {
	root := issue(t, "Test Root", nil, true, "")
	inter := issue(t, "Test Intermediate", root, true, "http://ca.test/root")
	leaf := issue(t, "relay.test", inter, false, "http://ca.test/inter")
	stubHTTP(t, func(u string) ([]byte, error) {
		if u == "http://ca.test/root" {
			return root.cert.Raw, nil
		}
		return nil, errors.New("unexpected fetch " + u)
	})

	chain, err := managerFor(leaf, inter).Chain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := names(chain)
	if len(got) != 3 || got[0] != "relay.test" || got[1] != "Test Intermediate" || got[2] != "Test Root" {
		t.Fatalf("chain = %v", got)
	}
	if !SelfSigned(chain[2]) || SelfSigned(chain[1]) {
		t.Fatal("root detection is wrong")
	}
}

// A certificate that didn't sign the chain must never be offered as its CA.
func TestChainRejectsImpostorIssuer(t *testing.T) {
	root := issue(t, "Test Root", nil, true, "")
	impostor := issue(t, "Test Root", nil, true, "") // same name, different key
	inter := issue(t, "Test Intermediate", root, true, "http://ca.test/root")
	leaf := issue(t, "relay2.test", inter, false, "")
	stubHTTP(t, func(string) ([]byte, error) { return impostor.cert.Raw, nil })

	chain, err := managerFor(leaf, inter).Chain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := names(chain); len(got) != 2 {
		t.Fatalf("impostor accepted: %v", got)
	}
}

func TestChainSelfSignedNeedsNoFetch(t *testing.T) {
	cert, err := selfSigned([]string{"relay3.test"})
	if err != nil {
		t.Fatal(err)
	}
	stubHTTP(t, func(u string) ([]byte, error) { t.Errorf("unexpected fetch %s", u); return nil, errors.New("no") })
	m := &Manager{Domains: []string{"relay3.test"}, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	chain, err := m.Chain(context.Background())
	if err != nil || len(chain) != 1 || !SelfSigned(chain[0]) {
		t.Fatalf("chain = %v, err = %v", names(chain), err)
	}
}
