// Package tlsmgr provides certificates for the SMTP listeners and the portal.
// In "acme" mode certificates come from Let's Encrypt using the Cloudflare DNS-01
// challenge and are renewed automatically by certmagic in the background.
//
// The relay holds an ECDSA certificate and, unless turned off, an RSA one as well. Each client
// gets the one it supports: many printers and scanners only offer RSA cipher suites and cannot
// complete a handshake with an ECDSA certificate at all.
package tlsmgr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"

	"graphrelay/internal/config"
)

type getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)

type Manager struct {
	TLSConfig *tls.Config
	Mode      string
	Domains   []string
	// Warnings are non-fatal setup problems (for example the RSA fallback certificate could not
	// be obtained). The caller should log them.
	Warnings []string

	primary getCert // ECDSA
	legacy  getCert // RSA fallback; nil when disabled or unavailable
}

// CertInfo describes the certificate currently served for the main hostname.
type CertInfo struct {
	Subject  []string
	Issuer   string
	NotAfter time.Time
	Err      error
}

func Setup(ctx context.Context, cfg *config.Config) (*Manager, error) {
	domains := append([]string{cfg.Hostname}, cfg.TLS.ExtraDomains...)
	m := &Manager{Mode: cfg.TLS.Mode, Domains: domains}
	m.TLSConfig = &tls.Config{GetCertificate: m.pick, MinVersion: tls.VersionTLS12}

	if cfg.TLS.Mode == "selfsigned" {
		ec, err := selfSigned(domains, false)
		if err != nil {
			return nil, err
		}
		m.primary = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &ec, nil }
		if cfg.TLS.RSAFallbackEnabled() {
			rs, err := selfSigned(domains, true)
			if err != nil {
				return nil, err
			}
			m.legacy = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &rs, nil }
		}
		return m, nil
	}

	// Each key type has its own certmagic storage, because certmagic keeps one certificate per name.
	ec := newMagic(cfg, "certs", certmagic.P256)
	if err := ec.ManageSync(ctx, domains); err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}
	m.primary = ec.GetCertificate
	if cfg.TLS.RSAFallbackEnabled() {
		rs := newMagic(cfg, "certs-rsa", certmagic.RSA2048)
		if err := rs.ManageSync(ctx, domains); err != nil {
			// Modern clients still work; only RSA-only devices are affected.
			m.Warnings = append(m.Warnings, fmt.Sprintf("RSA fallback certificate unavailable, RSA-only devices cannot connect: %v", err))
		} else {
			m.legacy = rs.GetCertificate
		}
	}
	m.TLSConfig.NextProtos = []string{"h2", "http/1.1"} // no acme-tls/1, we only do DNS-01
	return m, nil
}

// newMagic returns a certmagic configuration that obtains certificates of the given key type
// from Let's Encrypt via Cloudflare DNS-01 and stores them under data_dir/<dir>.
func newMagic(cfg *config.Config, dir string, keyType certmagic.KeyType) *certmagic.Config {
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
	})
	magic = certmagic.New(cache, certmagic.Config{
		Storage:           &certmagic.FileStorage{Path: filepath.Join(cfg.DataDir, dir)},
		DefaultServerName: cfg.Hostname, // many SMTP clients don't send SNI
		KeySource:         certmagic.StandardKeyGenerator{KeyType: keyType},
	})
	ca := certmagic.LetsEncryptProductionCA
	if cfg.TLS.ACMEStaging {
		ca = certmagic.LetsEncryptStagingCA
	}
	solver := &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflare.Provider{APIToken: cfg.TLS.CloudflareAPIToken},
			Resolvers:   cfg.TLS.Resolvers,
		},
	}
	if cfg.TLS.SkipDNSPropagationCheck {
		solver.PropagationTimeout = -1 // certmagic: -1 disables the check
		solver.PropagationDelay = cfg.TLS.DNSPropagationDelay
		if solver.PropagationDelay <= 0 {
			solver.PropagationDelay = time.Minute
		}
	}
	magic.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   cfg.TLS.ACMEEmail,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver:             solver,
	})}
	return magic
}

// pick chooses the certificate for a handshake: ECDSA when the client can use it, otherwise
// the RSA fallback. A hello without cipher suites (our own lookups) gets the ECDSA one.
func (m *Manager) pick(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := m.primary(hello)
	if m.legacy == nil {
		return c, err
	}
	if err == nil && c != nil && (len(hello.CipherSuites) == 0 || hello.SupportsCertificate(c) == nil) {
		return c, nil
	}
	if l, lerr := m.legacy(hello); lerr == nil && l != nil {
		return l, nil
	}
	return c, err
}

func (m *Manager) Info() CertInfo {
	c, err := m.primary(&tls.ClientHelloInfo{ServerName: m.Domains[0]})
	if err != nil || c == nil {
		return CertInfo{Err: fmt.Errorf("no certificate: %v", err)}
	}
	leaf := c.Leaf
	if leaf == nil && len(c.Certificate) > 0 {
		leaf, err = x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return CertInfo{Err: err}
		}
	}
	return CertInfo{Subject: leaf.DNSNames, Issuer: leaf.Issuer.CommonName, NotAfter: leaf.NotAfter}
}

// selfSigned makes a throwaway certificate for testing, with an ECDSA P-256 or RSA 2048 key.
func selfSigned(domains []string, useRSA bool) (tls.Certificate, error) {
	var key crypto.Signer
	var err error
	usage := x509.KeyUsageDigitalSignature
	if useRSA {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		usage |= x509.KeyUsageKeyEncipherment
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     usage,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
