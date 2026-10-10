package relay

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"graphrelay/internal/store"
)

// lastConn waits for the connection record that is written when the server closes a connection.
func (e *env) lastConn(t *testing.T, want int) store.ConnEntry {
	t.Helper()
	for i := 0; i < 200; i++ {
		list, err := e.store.ListConns(store.ConnFilter{Since: time.Now().Add(-time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if len(list) >= want {
			return list[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("connection record %d was never written", want)
	return store.ConnEntry{}
}

func TestConnLogDelivered(t *testing.T) {
	e := setupAuth(t)
	if err := e.send(t, true, loginAuth{"printer01", "correct horse battery"}); err != nil {
		t.Fatal(err)
	}
	c := e.lastConn(t, 1)
	if c.Outcome != store.ConnOK || c.Sent != 1 || c.Helo != "client.test" || c.HostName != "printer" ||
		!c.AuthOK || c.AuthUser != "printer01" || c.ClientIP != "127.0.0.1" || c.Port != "25" {
		t.Fatalf("record = %+v", c)
	}
	if !strings.HasPrefix(c.TLS, "TLS 1.3 ") || c.CertKey != "ECDSA" {
		t.Errorf("tls = %q, certificate = %q", c.TLS, c.CertKey)
	}
}

func TestConnLogWrongPassword(t *testing.T) {
	e := setupAuth(t)
	wantCode(t, e.send(t, true, loginAuth{"printer01", "wrong"}), "535")
	c := e.lastConn(t, 1)
	if c.Outcome != store.ConnAuthFailed || !strings.Contains(c.Detail, "printer01") || c.AuthOK || c.Sent != 0 {
		t.Fatalf("record = %+v", c)
	}
}

func TestConnLogUnknownHostAndIdle(t *testing.T) {
	e := setup(t) // no host rules, no TLS
	wantCode(t, e.send(t, false, nil), "554")
	if c := e.lastConn(t, 1); c.Outcome != store.ConnRejected || !strings.Contains(c.Detail, "not in allowed hosts") || c.TLS != "" {
		t.Fatalf("rejected record = %+v", c)
	}

	// Connect, say hello, leave: recorded as idle, not as a problem.
	cl, err := smtp.Dial(e.addr)
	if err != nil {
		t.Fatal(err)
	}
	cl.Hello("probe.test")
	cl.Quit()
	if c := e.lastConn(t, 2); c.Outcome != store.ConnIdle || c.Helo != "probe.test" || c.Problem() {
		t.Fatalf("idle record = %+v", c)
	}
}

// starttls connects and attempts STARTTLS with the given client settings.
func (e *env) starttls(t *testing.T, cfg *tls.Config) error {
	t.Helper()
	cl, err := smtp.Dial(e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	cl.Hello("old-device.test")
	return cl.StartTLS(cfg)
}

func TestConnLogTLSFailures(t *testing.T) {
	e := setupAuth(t)

	// A device that only speaks TLS 1.0/1.1.
	if err := e.starttls(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Fatal("TLS 1.1 handshake succeeded")
	}
	c := e.lastConn(t, 1)
	if c.Outcome != store.ConnTLSFailed || !strings.Contains(c.Detail, "TLS 1.0/1.1") || c.Helo != "old-device.test" || c.HostName != "printer" {
		t.Fatalf("old TLS record = %+v", c)
	}

	// A device that doesn't trust the relay's (here self-signed) certificate ends the handshake itself.
	if err := e.starttls(t, &tls.Config{ServerName: "relay.test"}); err == nil {
		t.Fatal("untrusted certificate was accepted")
	}
	c = e.lastConn(t, 2)
	if c.Outcome != store.ConnTLSFailed || !strings.Contains(c.Detail, "may not trust") {
		t.Fatalf("untrusted-certificate record = %+v", c)
	}
}

// handshakeOnly connects, upgrades to TLS on the raw connection and closes without any SMTP
// command inside TLS, like a monitoring probe.
func (e *env) handshakeOnly(t *testing.T, cfg *tls.Config) error {
	t.Helper()
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	expect := func(code string) {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("waiting for %s: %v", code, err)
			}
			if strings.HasPrefix(line, code+" ") {
				return
			}
		}
	}
	expect("220")
	conn.Write([]byte("EHLO probe.test\r\n"))
	expect("250")
	conn.Write([]byte("STARTTLS\r\n"))
	expect("220")
	tc := tls.Client(conn, cfg)
	defer tc.Close()
	return tc.Handshake()
}

// The handshake result must be right for both protocol versions, whether or not SMTP follows.
func TestConnLogHandshakeResultPerVersion(t *testing.T) {
	for name, v := range map[string]uint16{"TLS 1.2": tls.VersionTLS12, "TLS 1.3": tls.VersionTLS13} {
		e := setupAuth(t)

		// Completed handshake, then nothing: not a problem.
		if err := e.handshakeOnly(t, &tls.Config{InsecureSkipVerify: true, MinVersion: v, MaxVersion: v}); err != nil {
			t.Fatalf("%s: handshake: %v", name, err)
		}
		if c := e.lastConn(t, 1); c.Outcome != store.ConnIdle || !strings.HasPrefix(c.TLS, name+" ") || !strings.Contains(c.Detail, "with TLS") {
			t.Errorf("%s, completed handshake: %+v", name, c)
		}

		// The client rejects the (self-signed) certificate: a TLS failure.
		if err := e.handshakeOnly(t, &tls.Config{ServerName: "relay.test", MinVersion: v, MaxVersion: v}); err == nil {
			t.Fatalf("%s: untrusted certificate accepted", name)
		}
		if c := e.lastConn(t, 2); c.Outcome != store.ConnTLSFailed || c.TLS != "" || !strings.Contains(c.Detail, "may not trust") {
			t.Errorf("%s, rejected certificate: %+v", name, c)
		}
	}
}

// An RSA-only device completes the handshake with the RSA fallback certificate, and the record says so.
func TestConnLogRecordsRSAFallback(t *testing.T) {
	e := setupAuth(t)
	err := e.starttls(t, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	c := e.lastConn(t, 1)
	if c.CertKey != "RSA" || c.TLS != "TLS 1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || c.Outcome != store.ConnIdle {
		t.Fatalf("record = %+v", c)
	}
}
