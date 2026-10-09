package relay

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/smtp"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"graphrelay/internal/graph"
	"graphrelay/internal/store"
)

// fakeGraph records what the relay sends to Microsoft Graph.
type fakeGraph struct {
	mu          sync.Mutex
	mimeUser    string
	mime        []byte
	draft       map[string]any
	attachments []string // names posted directly
	uploaded    int      // bytes received through upload sessions
	sent        bool
	failStatus  int
}

func (f *fakeGraph) handler(srvURL *string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
	})
	mux.HandleFunc("POST /v1.0/users/{user}/sendMail", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failStatus != 0 {
			w.WriteHeader(f.failStatus)
			fmt.Fprint(w, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mimeUser = r.PathValue("user")
		f.mime, _ = base64.StdEncoding.DecodeString(string(body))
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("POST /v1.0/users/{user}/messages", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewDecoder(r.Body).Decode(&f.draft)
		fmt.Fprint(w, `{"id":"m1"}`)
	})
	mux.HandleFunc("POST /v1.0/users/{user}/messages/m1/attachments", func(w http.ResponseWriter, r *http.Request) {
		var a struct{ Name string }
		json.NewDecoder(r.Body).Decode(&a)
		f.mu.Lock()
		f.attachments = append(f.attachments, a.Name)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /v1.0/users/{user}/messages/m1/attachments/createUploadSession", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"uploadUrl":%q}`, *srvURL+"/upload")
	})
	mux.HandleFunc("PUT /upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "no auth allowed", 401)
			return
		}
		n, _ := io.Copy(io.Discard, r.Body)
		f.mu.Lock()
		f.uploaded += int(n)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /v1.0/users/{user}/messages/m1/send", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.sent = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}

type env struct {
	addr  string
	fake  *fakeGraph
	store *store.Store
}

func setup(t *testing.T) *env { return setupTLS(t, nil) }

// setupTLS starts a test relay; with tc set it offers STARTTLS (and thus AUTH).
func setupTLS(t *testing.T, tc *tls.Config) *env {
	t.Helper()
	fake := &fakeGraph{}
	var url string
	srv := httptest.NewServer(fake.handler(&url))
	url = srv.URL
	t.Cleanup(srv.Close)
	graph.SetEndpoints(srv.URL+"/v1.0", srv.URL)

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	rl := &Relay{
		Store: st, Graph: graph.New("tenant", "id", "secret", 30*time.Second),
		Matcher: NewMatcher(st), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), SendTimeout: 30 * time.Second,
	}
	s := gosmtp.NewServer(rl.Backend("25", false))
	s.Domain = "relay.test"
	s.TLSConfig = tc
	s.MaxMessageBytes = 20 << 20
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return &env{addr: ln.Addr().String(), fake: fake, store: st}
}

func (e *env) addHost(t *testing.T, match, sender string, rewrite, enabled bool) {
	t.Helper()
	h := &store.Host{Name: match, Match: match, Sender: sender, RewriteFrom: rewrite, Enabled: enabled}
	if err := e.store.SaveHost(h); err != nil {
		t.Fatal(err)
	}
	list, _ := e.store.AllowedSenders()
	if err := e.store.SetAllowedSenders(append(list, sender)); err != nil {
		t.Fatal(err)
	}
}

func TestSenderNotAllowedRejected(t *testing.T) {
	e := setup(t)
	e.addHost(t, "127.0.0.1", "relay@contoso.com", true, true)
	if err := e.store.SetAllowedSenders([]string{"other@contoso.com"}); err != nil {
		t.Fatal(err)
	}
	err := smtp.SendMail(e.addr, nil, "a@b.c", []string{"x@example.com"}, []byte("To: x@example.com\r\nSubject: x\r\n\r\nx\r\n"))
	if err == nil || !strings.Contains(err.Error(), "554") {
		t.Fatalf("want 554 rejection, got %v", err)
	}
	if e.fake.mimeUser != "" {
		t.Errorf("message was sent as %q although the mailbox is not allowed", e.fake.mimeUser)
	}
	logs, _ := e.store.ListLog(store.LogFilter{Status: "rejected"})
	if len(logs) != 1 || logs[0].Sender != "relay@contoso.com" || !strings.Contains(logs[0].Error, "allowed list") {
		t.Errorf("unexpected log: %+v", logs)
	}
}

func TestSmallMessageRewritesFromAndAddsBcc(t *testing.T) {
	e := setup(t)
	e.addHost(t, "127.0.0.0/8", "wrong@contoso.com", true, true)
	e.addHost(t, "127.0.0.1", "relay@contoso.com", true, true) // more specific, must win

	msg := "From: \"Office Printer\" <scan@printer.local>\r\n" +
		"To: alice@example.com\r\n" +
		"Subject: Scan ready\r\n" +
		"\r\n" +
		"Hello.\r\n"
	err := smtp.SendMail(e.addr, nil, "scan@printer.local", []string{"alice@example.com", "hidden@example.com"}, []byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	if e.fake.mimeUser != "relay@contoso.com" {
		t.Errorf("sent as %q, want relay@contoso.com", e.fake.mimeUser)
	}
	got := string(e.fake.mime)
	for _, want := range []string{`From: "Office Printer" <relay@contoso.com>`, "Bcc: <hidden@example.com>", "Subject: Scan ready", "Hello."} {
		if !strings.Contains(got, want) {
			t.Errorf("MIME missing %q:\n%s", want, got)
		}
	}
	logs, _ := e.store.ListLog(store.LogFilter{})
	if len(logs) != 1 || logs[0].Status != "sent" || logs[0].Subject != "Scan ready" {
		t.Errorf("unexpected log: %+v", logs)
	}
}

func TestKeepFromWhenRewriteDisabled(t *testing.T) {
	e := setup(t)
	e.addHost(t, "127.0.0.1", "relay@contoso.com", false, true)
	msg := "From: app@contoso.com\r\nTo: bob@example.com\r\nSubject: x\r\n\r\nbody\r\n"
	if err := smtp.SendMail(e.addr, nil, "app@contoso.com", []string{"bob@example.com"}, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(e.fake.mime), "From: app@contoso.com") {
		t.Errorf("From was rewritten:\n%s", e.fake.mime)
	}
}

func TestUnknownHostRejected(t *testing.T) {
	e := setup(t)
	e.addHost(t, "127.0.0.1", "relay@contoso.com", true, false) // disabled
	err := smtp.SendMail(e.addr, nil, "a@b.c", []string{"x@example.com"}, []byte("Subject: x\r\n\r\nx\r\n"))
	if err == nil || !strings.Contains(err.Error(), "554") {
		t.Fatalf("want 554 rejection, got %v", err)
	}
	logs, _ := e.store.ListLog(store.LogFilter{Status: "rejected"})
	if len(logs) != 1 {
		t.Errorf("want 1 rejected log entry, got %d", len(logs))
	}
}

func TestGraphPermanentErrorReturns554(t *testing.T) {
	e := setup(t)
	e.addHost(t, "127.0.0.1", "relay@contoso.com", true, true)
	e.fake.failStatus = 403
	err := smtp.SendMail(e.addr, nil, "a@b.c", []string{"x@example.com"}, []byte("To: x@example.com\r\nSubject: x\r\n\r\nx\r\n"))
	if err == nil || !strings.Contains(err.Error(), "554") || !strings.Contains(err.Error(), "Access is denied") {
		t.Fatalf("want 554 with Graph error, got %v", err)
	}
}

func TestLargeMessageUsesDraftAndUploadSession(t *testing.T) {
	e := setup(t)
	e.addHost(t, "127.0.0.1", "relay@contoso.com", true, true)

	big := bytes.Repeat([]byte("0123456789abcdef"), 4<<20/16) // 4 MiB
	small := []byte("hello attachment")
	var b strings.Builder
	b.WriteString("From: Scanner <scan@printer.local>\r\nTo: Alice <alice@example.com>\r\nCc: carol@example.com\r\n")
	b.WriteString("Subject: Big scan\r\nX-Priority: 1\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XYZ\r\n\r\n")
	b.WriteString("--XYZ\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>See attached</p>\r\n")
	b.WriteString("--XYZ\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"note.txt\"\r\n\r\n")
	b.Write(small)
	b.WriteString("\r\n--XYZ\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"scan.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString(big)
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n--XYZ--\r\n")

	err := smtp.SendMail(e.addr, nil, "scan@printer.local", []string{"alice@example.com", "carol@example.com", "dave@example.com"}, []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	f := e.fake
	if !f.sent {
		t.Fatal("draft was not sent")
	}
	if f.uploaded != len(big) {
		t.Errorf("uploaded %d bytes, want %d", f.uploaded, len(big))
	}
	if len(f.attachments) != 1 || f.attachments[0] != "note.txt" {
		t.Errorf("direct attachments = %v", f.attachments)
	}
	if f.draft["subject"] != "Big scan" || f.draft["importance"] != "high" {
		t.Errorf("draft = %v", f.draft)
	}
	body := f.draft["body"].(map[string]any)
	if body["contentType"] != "HTML" || !strings.Contains(body["content"].(string), "See attached") {
		t.Errorf("body = %v", body)
	}
	bcc, _ := json.Marshal(f.draft["bccRecipients"])
	if !strings.Contains(string(bcc), "dave@example.com") {
		t.Errorf("envelope-only recipient missing from bcc: %s", bcc)
	}
	from, _ := json.Marshal(f.draft["from"])
	if !strings.Contains(string(from), "relay@contoso.com") || !strings.Contains(string(from), "Scanner") {
		t.Errorf("from = %s", from)
	}
}

func TestValidateMatch(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5":           "10.0.0.5",
		"10.0.0.7/24":        "10.0.0.0/24",
		"::ffff:10.0.0.1":    "10.0.0.1",
		"2001:db8::/32":      "2001:db8::/32",
		"Scanner.Corp.Local": "scanner.corp.local",
	}
	for in, want := range cases {
		got, ok := ValidateMatch(in)
		if !ok || got != want {
			t.Errorf("ValidateMatch(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "10.0.0.0/33", "bad host!", "a..b"} {
		if _, ok := ValidateMatch(bad); ok {
			t.Errorf("ValidateMatch(%q) accepted", bad)
		}
	}
}

func TestMatcherPrefersMostSpecific(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "m.db"))
	defer st.Close()
	for _, h := range []store.Host{
		{Name: "all", Match: "10.0.0.0/8", Sender: "a@x", Enabled: true},
		{Name: "lan", Match: "10.1.0.0/16", Sender: "b@x", Enabled: true},
		{Name: "one", Match: "10.1.2.3", Sender: "c@x", Enabled: true},
	} {
		st.SaveHost(&h)
	}
	m := NewMatcher(st)
	for ip, want := range map[string]string{"10.1.2.3": "one", "10.1.9.9": "lan", "10.9.9.9": "all"} {
		h, _ := m.Match(t.Context(), netip.MustParseAddr(ip))
		if h == nil || h.Name != want {
			t.Errorf("%s matched %v, want %s", ip, h, want)
		}
	}
	if h, _ := m.Match(t.Context(), netip.MustParseAddr("192.168.1.1")); h != nil {
		t.Errorf("unexpected match %v", h.Name)
	}
}
