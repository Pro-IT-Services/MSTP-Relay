package portal

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"graphrelay/internal/tlsmgr"
)

// certGroup is one certificate chain on the Settings page (ECDSA, or the RSA fallback).
type certGroup struct {
	Key   string // "ecdsa" or "rsa", part of the download URL
	Label string
	Rows  []certRow
}

// certRow is one certificate of a chain.
type certRow struct {
	Index    int
	Role     string // "Server certificate", "Intermediate CA", "Root CA"
	Subject  string
	Issuer   string
	Key      string
	NotAfter time.Time
	Root     bool
}

// certChains returns the relay's certificate chains, each completed up to the root where
// possible. It returns nil when no certificate is available.
func (p *Portal) certChains(ctx context.Context) []tlsmgr.Chain {
	if p.TLS == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return p.TLS.Chains(ctx)
}

func (p *Portal) certGroups(ctx context.Context) []certGroup {
	var groups []certGroup
	for _, ch := range p.certChains(ctx) {
		g := certGroup{Key: ch.Key, Label: ch.Label}
		for i, c := range ch.Certs {
			root := tlsmgr.SelfSigned(c)
			role := "Intermediate CA"
			switch {
			case i == 0 && root:
				role = "Server certificate (self-signed)"
			case i == 0:
				role = "Server certificate"
			case root:
				role = "Root CA"
			}
			g.Rows = append(g.Rows, certRow{
				Index: i, Role: role, Subject: certName(c.Subject.CommonName, c.Subject.String()),
				Issuer: certName(c.Issuer.CommonName, c.Issuer.String()), Key: keyType(c), NotAfter: c.NotAfter, Root: root,
			})
		}
		groups = append(groups, g)
	}
	return groups
}

func certName(cn, full string) string {
	if cn != "" {
		return cn
	}
	return full
}

func keyType(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	}
	return c.PublicKeyAlgorithm.String()
}

// certFileName turns a certificate's name into a safe download file name (without extension).
func certFileName(c *x509.Certificate) string {
	var b strings.Builder
	for _, r := range strings.ToLower(certName(c.Subject.CommonName, "certificate")) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-.")
	if name == "" {
		name = "certificate"
	}
	return name
}

func pemEncode(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

func sendFile(w http.ResponseWriter, name, contentType string, data []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

// certDownload serves one certificate: GET /settings/certs/{chain}/{n}/{format}, chain "ecdsa"
// or "rsa", format "pem" (text) or "der" (binary .cer, which many printers and Windows expect).
func (p *Portal) certDownload(w http.ResponseWriter, r *http.Request) {
	var certs []*x509.Certificate
	for _, ch := range p.certChains(r.Context()) {
		if ch.Key == r.PathValue("chain") {
			certs = ch.Certs
		}
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 || n >= len(certs) {
		http.NotFound(w, r)
		return
	}
	c := certs[n]
	name := certFileName(c)
	if n == 0 { // the two server certificates share a name
		name += "-" + r.PathValue("chain")
	}
	switch r.PathValue("format") {
	case "pem":
		sendFile(w, name+".pem", "application/x-pem-file", pemEncode(c))
	case "der":
		sendFile(w, name+".cer", "application/pkix-cert", c.Raw)
	default:
		http.NotFound(w, r)
	}
}

// caBundle serves every CA certificate of all chains (everything but the server certificates,
// without duplicates) as one PEM file. A self-signed server certificate is its own CA.
func (p *Portal) caBundle(w http.ResponseWriter, r *http.Request) {
	var cas []*x509.Certificate
	seen := map[string]bool{}
	for _, ch := range p.certChains(r.Context()) {
		certs := ch.Certs[1:]
		if len(certs) == 0 {
			certs = ch.Certs
		}
		for _, c := range certs {
			if !seen[string(c.Raw)] {
				seen[string(c.Raw)] = true
				cas = append(cas, c)
			}
		}
	}
	if len(cas) == 0 {
		http.NotFound(w, r)
		return
	}
	sendFile(w, "relay-ca-bundle.pem", "application/x-pem-file", pemEncode(cas...))
}
