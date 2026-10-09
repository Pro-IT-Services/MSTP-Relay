// Package tlsmgr provides certificates for the SMTP listeners and the portal.
// In "acme" mode certificates come from Let's Encrypt using the Cloudflare DNS-01
// challenge and are renewed automatically by certmagic in the background.
package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

type Manager struct {
	TLSConfig *tls.Config
	Mode      string
	Domains   []string
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

	if cfg.TLS.Mode == "selfsigned" {
		cert, err := selfSigned(domains)
		if err != nil {
			return nil, err
		}
		m.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		return m, nil
	}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
	})
	magic = certmagic.New(cache, certmagic.Config{
		Storage:           &certmagic.FileStorage{Path: filepath.Join(cfg.DataDir, "certs")},
		DefaultServerName: cfg.Hostname, // many SMTP clients don't send SNI
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
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   cfg.TLS.ACMEEmail,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver:             solver,
	})
	magic.Issuers = []certmagic.Issuer{issuer}

	// Obtains (or loads from storage) the certificates and keeps them renewed.
	if err := magic.ManageSync(ctx, domains); err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}
	tc := magic.TLSConfig()
	tc.NextProtos = []string{"h2", "http/1.1"} // drop acme-tls/1, we only do DNS-01
	tc.MinVersion = tls.VersionTLS12
	m.TLSConfig = tc
	return m, nil
}

func (m *Manager) Info() CertInfo {
	var c *tls.Certificate
	var err error
	if m.TLSConfig.GetCertificate != nil {
		c, err = m.TLSConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: m.Domains[0]})
	} else if len(m.TLSConfig.Certificates) > 0 {
		c = &m.TLSConfig.Certificates[0]
	}
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

func selfSigned(domains []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
