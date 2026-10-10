package tlsmgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Chain is one certificate chain the relay serves, server certificate first.
type Chain struct {
	Key   string // "ecdsa" or "rsa"; used in download URLs
	Label string
	Certs []*x509.Certificate
}

// Chains returns the certificate chains for the main hostname, for download in the portal
// (devices often need the CA imported before they trust the relay): the ECDSA chain and, when
// the RSA fallback is active, the RSA chain.
//
// Servers don't send the root, and Let's Encrypt chains can end in a cross-signed certificate, so
// a served chain usually lacks the self-signed root that devices want as a trust anchor. Each
// chain is therefore completed by following the top certificate's "CA Issuers" URL (Authority
// Information Access) until a self-signed certificate is reached. A fetched certificate is only
// accepted if it really signed the one below it. If fetching fails, the served chain is returned.
func (m *Manager) Chains(ctx context.Context) []Chain {
	var out []Chain
	for _, src := range []struct {
		key, label string
		get        getCert
	}{
		{"ecdsa", "ECDSA certificate (modern clients)", m.primary},
		{"rsa", "RSA certificate (fallback for older devices)", m.legacy},
	} {
		if src.get == nil {
			continue
		}
		c, err := src.get(&tls.ClientHelloInfo{ServerName: m.Domains[0]})
		if err != nil || c == nil {
			continue
		}
		if certs, err := completeChain(ctx, c); err == nil {
			out = append(out, Chain{Key: src.key, Label: src.label, Certs: certs})
		}
	}
	return out
}

type cachedChain struct {
	certs   []*x509.Certificate
	expires time.Time
}

var chainCache = struct {
	sync.Mutex
	m map[string]cachedChain // keyed by the server certificate
}{m: map[string]cachedChain{}}

func completeChain(ctx context.Context, c *tls.Certificate) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(c.Certificate)+1)
	for _, der := range c.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, errors.New("no certificate")
	}

	key := string(chain[0].Raw)
	chainCache.Lock()
	defer chainCache.Unlock()
	now := time.Now()
	if hit, ok := chainCache.m[key]; ok && now.Before(hit.expires) {
		return hit.certs, nil
	}
	for k, v := range chainCache.m { // drop entries of renewed certificates
		if now.After(v.expires) {
			delete(chainCache.m, k)
		}
	}
	complete := true
	for hops := 0; hops < 4 && !SelfSigned(chain[len(chain)-1]); hops++ {
		parent, err := fetchIssuer(ctx, chain[len(chain)-1])
		if err != nil {
			complete = false
			break
		}
		chain = append(chain, parent)
	}
	// Cache a complete chain for a day; retry an incomplete one soon.
	ttl := 24 * time.Hour
	if !complete {
		ttl = time.Minute
	}
	chainCache.m[key] = cachedChain{chain, now.Add(ttl)}
	return chain, nil
}

// SelfSigned reports whether c is a root: issued by itself and signed with its own key.
// The signature is checked directly (not with CheckSignatureFrom, which also demands the CA
// flag), so the relay's own self-signed test certificate counts too.
func SelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// httpGet is replaced in tests.
var httpGet = func(ctx context.Context, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", rawURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<10))
}

// fetchIssuer downloads child's issuer from its "CA Issuers" URLs and checks the signature.
func fetchIssuer(ctx context.Context, child *x509.Certificate) (*x509.Certificate, error) {
	var lastErr error = errors.New("certificate has no CA Issuers URL")
	for _, raw := range child.IssuingCertificateURL {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		data, err := httpGet(ctx, raw)
		if err != nil {
			lastErr = err
			continue
		}
		if block, _ := pem.Decode(data); block != nil {
			data = block.Bytes
		}
		parent, err := x509.ParseCertificate(data)
		if err != nil {
			lastErr = err
			continue
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			lastErr = fmt.Errorf("%s: not the issuer: %w", raw, err)
			continue
		}
		return parent, nil
	}
	return nil, lastErr
}
