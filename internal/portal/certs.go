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

// certRow is one certificate of the relay's chain on the Settings page.
type certRow struct {
	Index    int
	Role     string // "Server certificate", "Intermediate CA", "Root CA"
	Subject  string
	Issuer   string
	Key      string
	NotAfter time.Time
	Root     bool
}

// certChain returns the relay's certificate chain, server certificate first, completed up to
// the root where possible. It returns nil when no certificate is available.
func (p *Portal) certChain(ctx context.Context) []*x509.Certificate {
	if p.TLS == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	chain, err := p.TLS.Chain(ctx)
	if err != nil {
		p.Log.Warn("read certificate chain", "err", err)
		return nil
	}
	return chain
}

func (p *Portal) certRows(ctx context.Context) []certRow {
	var rows []certRow
	for i, c := range p.certChain(ctx) {
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
		rows = append(rows, certRow{
			Index: i, Role: role, Subject: certName(c.Subject.CommonName, c.Subject.String()),
			Issuer: certName(c.Issuer.CommonName, c.Issuer.String()), Key: keyType(c), NotAfter: c.NotAfter, Root: root,
		})
	}
	return rows
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

// certDownload serves one certificate of the chain: GET /settings/certs/{n}/{format},
// format "pem" (text) or "der" (binary .cer, which many printers and Windows expect).
func (p *Portal) certDownload(w http.ResponseWriter, r *http.Request) {
	chain := p.certChain(r.Context())
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 || n >= len(chain) {
		http.NotFound(w, r)
		return
	}
	c := chain[n]
	switch r.PathValue("format") {
	case "pem":
		sendFile(w, certFileName(c)+".pem", "application/x-pem-file", pemEncode(c))
	case "der":
		sendFile(w, certFileName(c)+".cer", "application/pkix-cert", c.Raw)
	default:
		http.NotFound(w, r)
	}
}

// caBundle serves every CA certificate of the chain (all but the server certificate) as one
// PEM file. For a self-signed server certificate, that certificate is its own CA.
func (p *Portal) caBundle(w http.ResponseWriter, r *http.Request) {
	chain := p.certChain(r.Context())
	if len(chain) == 0 {
		http.NotFound(w, r)
		return
	}
	cas := chain[1:]
	if len(cas) == 0 {
		cas = chain
	}
	sendFile(w, "relay-ca-bundle.pem", "application/x-pem-file", pemEncode(cas...))
}
