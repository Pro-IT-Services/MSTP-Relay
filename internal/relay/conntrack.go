package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"graphrelay/internal/store"
)

// Connection tracking: one record per SMTP connection that reaches the relay, including the
// ones that never get as far as sending a message (failed TLS handshakes, wrong logins, clients
// that connect and leave). go-smtp reports none of this, so every accepted connection is wrapped
// and the TLS handshake is observed through tls.Config hooks. The record is written on close.

// connInfo collects what happened on one connection.
type connInfo struct {
	mu    sync.Mutex
	start time.Time
	ip    netip.Addr
	port  string

	helo string

	helloSeen     bool   // a TLS ClientHello arrived
	helloIssue    string // why the handshake is expected to fail, "" if it should work
	tlsNegotiated bool   // version and cipher were agreed (VerifyConnection ran)
	tlsVersion    uint16
	readAfterTLS  int    // bytes received from the client after tlsNegotiated
	tlsDone       bool   // the client spoke SMTP inside TLS
	tlsDesc       string // "TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256"
	certKey       string // "ECDSA" or "RSA"

	authUser  string
	authOK    bool
	authFails int

	hostID   int64
	hostName string

	sent, failed, rejected int
	lastErr                string
}

type trackedConn struct {
	net.Conn
	info  *connInfo
	relay *Relay
	once  sync.Once
}

// Read counts what the client sends after the TLS parameters were agreed; see handshakeCompleted.
func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.info.mu.Lock()
		if c.info.tlsNegotiated {
			c.info.readAfterTLS += n
		}
		c.info.mu.Unlock()
	}
	return n, err
}

// handshakeCompleted reports whether the TLS handshake finished from the client's side too.
// The TLS library gives the server no completion callback, so this is derived:
//   - the client spoke SMTP inside TLS: certain;
//   - TLS 1.2: VerifyConnection runs after the client's key exchange, which a client only sends
//     once it has accepted the certificate;
//   - TLS 1.3: VerifyConnection runs before the client has judged the certificate. The client then
//     answers with either its Finished message (at least 58 bytes on the wire) or an alert
//     (24 bytes), optionally preceded by a 6-byte compatibility record. 50 bytes separates them.
//
// Caller holds info.mu.
func (info *connInfo) handshakeCompleted() bool {
	switch {
	case info.tlsDone:
		return true
	case !info.tlsNegotiated:
		return false
	case info.tlsVersion >= tls.VersionTLS13:
		return info.readAfterTLS >= 50
	}
	return true
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.relay.finishConn(c.info) })
	return err
}

type trackedListener struct {
	net.Listener
	relay *Relay
	port  string
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	info := &connInfo{start: time.Now(), ip: remoteIP(c), port: l.port}
	return &trackedConn{Conn: c, info: info, relay: l.relay}, nil
}

// Listener wraps an accepted-connection source so every connection is recorded. port is the
// listener label ("25", "465", "587"). Wrap the TCP listener, below any TLS listener.
func (r *Relay) Listener(ln net.Listener, port string) net.Listener {
	return &trackedListener{Listener: ln, relay: r, port: port}
}

// infoOf finds the tracking record of a connection, looking through a TLS layer.
func infoOf(c net.Conn) *connInfo {
	for c != nil {
		switch v := c.(type) {
		case *trackedConn:
			return v.info
		case *tls.Conn:
			c = v.NetConn()
		default:
			return nil
		}
	}
	return nil
}

// TLSConfig returns base with hooks that record each handshake on its connection: what the
// client offered, which certificate was served, and whether the handshake completed.
func (r *Relay) TLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		info := infoOf(hello.Conn)
		if info == nil {
			return nil, nil
		}
		info.mu.Lock()
		info.helloSeen = true
		info.helloIssue = ""
		if maxVersion(hello.SupportedVersions) < tls.VersionTLS12 {
			info.helloIssue = "the device only supports TLS 1.0/1.1, the relay requires TLS 1.2 or newer"
		}
		info.mu.Unlock()

		// A per-connection copy, so the callbacks below know which connection they belong to.
		c := base.Clone()
		if base.GetCertificate != nil {
			c.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := base.GetCertificate(h)
				if err == nil && cert != nil {
					info.mu.Lock()
					info.certKey = certKeyType(cert)
					if serr := h.SupportsCertificate(cert); serr != nil && info.helloIssue == "" {
						info.helloIssue = "no cipher suite in common with the device (" + serr.Error() + ")"
					}
					info.mu.Unlock()
				}
				return cert, err
			}
		}
		// Called once the parameters are negotiated. That is not yet proof of success: in TLS 1.3
		// the client can still reject the certificate afterwards (see handshakeCompleted).
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			info.mu.Lock()
			info.tlsNegotiated, info.tlsVersion, info.readAfterTLS = true, cs.Version, 0
			info.tlsDesc = tls.VersionName(cs.Version) + " " + tls.CipherSuiteName(cs.CipherSuite)
			info.mu.Unlock()
			return nil
		}
		return c, nil
	}
	return cfg
}

func maxVersion(versions []uint16) uint16 {
	var m uint16
	for _, v := range versions {
		if v > m && v <= tls.VersionTLS13 { // ignore GREASE values
			m = v
		}
	}
	return m
}

func certKeyType(c *tls.Certificate) string {
	leaf := c.Leaf
	if leaf == nil {
		return ""
	}
	switch leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	}
	return leaf.PublicKeyAlgorithm.String()
}

// note updates the record of the session's connection, if it is tracked.
func (s *session) note(fn func(*connInfo)) {
	if s.info == nil {
		return
	}
	s.info.mu.Lock()
	fn(s.info)
	s.info.mu.Unlock()
}

// finishConn classifies a closed connection and stores its record.
func (r *Relay) finishConn(info *connInfo) {
	info.mu.Lock()
	defer info.mu.Unlock()

	e := &store.ConnEntry{
		Time: info.start, ClientIP: info.ip.String(), Port: info.port, Helo: info.helo,
		CertKey: info.certKey, AuthUser: info.authUser, AuthOK: info.authOK,
		HostID: info.hostID, HostName: info.hostName,
		Sent: info.sent, Failed: info.failed, Rejected: info.rejected,
		DurationMS: time.Since(info.start).Milliseconds(),
	}
	tlsOK := info.handshakeCompleted()
	if tlsOK {
		e.TLS = info.tlsDesc
	}
	switch {
	case info.sent > 0:
		e.Outcome = store.ConnOK
		e.Detail = plural(info.sent, "message") + " delivered"
		if n := info.failed + info.rejected; n > 0 {
			e.Detail += fmt.Sprintf(", %d not delivered: %s", n, info.lastErr)
		}
	case info.helloSeen && !tlsOK:
		e.Outcome = store.ConnTLSFailed
		e.Detail = "TLS handshake failed: "
		if info.helloIssue != "" {
			e.Detail += info.helloIssue
		} else {
			e.Detail += "the device ended it. It may not trust the relay's certificate (import the CA from Settings) or the connection was interrupted"
		}
	case info.authFails > 0 && !info.authOK:
		e.Outcome = store.ConnAuthFailed
		e.Detail = fmt.Sprintf("SMTP login failed for user %q (%s)", truncate(info.authUser, 64), plural(info.authFails, "attempt"))
	case info.rejected > 0:
		e.Outcome, e.Detail = store.ConnRejected, info.lastErr
	case info.failed > 0:
		e.Outcome, e.Detail = store.ConnFailed, info.lastErr
	default:
		e.Outcome = store.ConnIdle
		e.Detail = "connected, no message sent"
		switch {
		case info.authOK:
			e.Detail = "logged in, no message sent"
		case tlsOK:
			e.Detail = "connected with TLS, no message sent"
		}
	}
	// Name the device by its host rule even if it never got to MAIL FROM.
	if e.HostName == "" {
		if h, err := r.Matcher.Match(context.Background(), info.ip); err == nil && h != nil {
			e.HostID, e.HostName = h.ID, h.Name
		}
	}
	if err := r.Store.AddConn(e); err != nil {
		r.Log.Error("write connection log", "err", err)
	}
	if e.Problem() {
		r.Log.Warn("connection problem", "ip", e.ClientIP, "port", e.Port, "host", e.HostName, "outcome", e.Outcome, "detail", e.Detail)
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
