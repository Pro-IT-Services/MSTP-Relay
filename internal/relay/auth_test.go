package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"net/smtp"
	"path/filepath"
	"strings"
	"testing"

	"graphrelay/internal/config"
	"graphrelay/internal/store"
	"graphrelay/internal/tlsmgr"
)

const authMsg = "To: x@example.com\r\nSubject: auth test\r\n\r\nbody\r\n"

func setupAuth(t *testing.T) *env {
	t.Helper()
	cfg := &config.Config{Hostname: "relay.test", DataDir: filepath.Join(t.TempDir(), "data")}
	cfg.TLS.Mode = "selfsigned"
	tm, err := tlsmgr.Setup(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := setupTLS(t, tm.TLSConfig)
	hash, err := HashSMTPPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	h := &store.Host{Name: "printer", Match: "127.0.0.1", Sender: "relay@contoso.com", RewriteFrom: true,
		Enabled: true, SMTPUser: "printer01", SMTPPassHash: hash}
	if err := e.store.SaveHost(h); err != nil {
		t.Fatal(err)
	}
	if err := e.store.SetAllowedSenders([]string{"relay@contoso.com"}); err != nil {
		t.Fatal(err)
	}
	return e
}

// loginAuth is the client side of AUTH LOGIN (net/smtp only has PLAIN and CRAM-MD5).
type loginAuth struct{ user, pass string }

func (a loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }
func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch string(fromServer) {
	case "Username:":
		return []byte(a.user), nil
	case "Password:":
		return []byte(a.pass), nil
	}
	return nil, errors.New("unexpected challenge " + string(fromServer))
}

// send runs one SMTP transaction. With useTLS it does STARTTLS first; with auth it logs in.
func (e *env) send(t *testing.T, useTLS bool, auth smtp.Auth) error {
	t.Helper()
	c, err := smtp.Dial(e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("client.test"); err != nil {
		return err
	}
	if useTLS {
		if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return err
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail("app@client.test"); err != nil {
		return err
	}
	if err := c.Rcpt("x@example.com"); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	w.Write([]byte(authMsg))
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestAuthRequiredWhenHostHasCredentials(t *testing.T) {
	e := setupAuth(t)
	wantCode(t, e.send(t, true, nil), "530")
	if e.fake.mimeUser != "" {
		t.Fatal("message was sent without login")
	}
}

func TestAuthPlainAndLogin(t *testing.T) {
	e := setupAuth(t)
	// net/smtp's PlainAuth refuses non-TLS connections to non-localhost; we always use TLS here.
	if err := e.send(t, true, smtp.PlainAuth("", "printer01", "correct horse battery", "127.0.0.1")); err != nil {
		t.Fatalf("PLAIN: %v", err)
	}
	if e.fake.mimeUser != "relay@contoso.com" {
		t.Fatalf("sent as %q", e.fake.mimeUser)
	}
	e.fake.mimeUser = ""
	if err := e.send(t, true, loginAuth{"printer01", "correct horse battery"}); err != nil {
		t.Fatalf("LOGIN: %v", err)
	}
	if e.fake.mimeUser != "relay@contoso.com" {
		t.Fatalf("LOGIN: sent as %q", e.fake.mimeUser)
	}
}

func TestAuthWrongPasswordAndLockout(t *testing.T) {
	e := setupAuth(t)
	wantCode(t, e.send(t, true, loginAuth{"printer01", "wrong"}), "535")
	wantCode(t, e.send(t, true, loginAuth{"someone", "correct horse battery"}), "535")
	logs, _ := e.store.ListLog(store.LogFilter{Status: "rejected"})
	if len(logs) != 2 || !strings.Contains(logs[0].Error, "login failed") {
		t.Fatalf("failed logins not logged: %+v", logs)
	}
	for i := 0; i < authMaxFailures-2; i++ {
		e.send(t, true, loginAuth{"printer01", "wrong"})
	}
	// Locked out now, even with the right password.
	wantCode(t, e.send(t, true, loginAuth{"printer01", "correct horse battery"}), "454")
}

func TestAuthNotOfferedWithoutTLS(t *testing.T) {
	e := setupAuth(t)
	c, err := smtp.Dial(e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Hello("client.test")
	if ok, _ := c.Extension("AUTH"); ok {
		t.Fatal("AUTH offered on a plain-text connection")
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatal(err)
	}
	if ok, mechs := c.Extension("AUTH"); !ok || !strings.Contains(mechs, "PLAIN") || !strings.Contains(mechs, "LOGIN") {
		t.Fatalf("AUTH after STARTTLS = %v %q", ok, mechs)
	}
}

func TestNoAuthHostUnchanged(t *testing.T) {
	e := setupAuth(t)
	h, _ := e.store.GetHost(1)
	h.SMTPUser, h.SMTPPassHash = "", ""
	if err := e.store.SaveHost(&h); err != nil {
		t.Fatal(err)
	}
	// Without credentials on the rule: works by IP, and AUTH isn't offered even over TLS.
	if err := e.send(t, true, nil); err != nil {
		t.Fatalf("IP-only host: %v", err)
	}
	c, _ := smtp.Dial(e.addr)
	defer c.Close()
	c.Hello("client.test")
	c.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if ok, _ := c.Extension("AUTH"); ok {
		t.Fatal("AUTH offered to a host without credentials")
	}
}
