package store

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// A hosts table from before SMTP login existed gets the new columns on open, and old rows
// read back with an empty login.
func TestMigrateAddsSMTPLoginColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, match TEXT NOT NULL UNIQUE,
		sender TEXT NOT NULL, rewrite_from INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
		note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
		INSERT INTO hosts(name, match, sender, created_at) VALUES('old', '10.0.0.1', 'a@contoso.com', 1);`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	for i := 0; i < 2; i++ { // second open: columns already exist
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		h, err := s.GetHost(1)
		if err != nil || h.Name != "old" || h.SMTPUser != "" || h.SMTPPassHash != "" {
			t.Fatalf("open %d: %+v %v", i, h, err)
		}
		s.Close()
	}
}

func TestAllowedSendersNormalized(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if list, _ := s.AllowedSenders(); len(list) != 0 {
		t.Fatalf("fresh database: want empty list, got %v", list)
	}
	if err := s.SetAllowedSenders([]string{" Notify@Contoso.com", "", "alerts@contoso.com", "notify@contoso.com"}); err != nil {
		t.Fatal(err)
	}
	list, _ := s.AllowedSenders()
	if want := []string{"alerts@contoso.com", "notify@contoso.com"}; !slices.Equal(list, want) {
		t.Fatalf("got %v, want %v", list, want)
	}
	for addr, want := range map[string]bool{"NOTIFY@contoso.com": true, "x@contoso.com": false} {
		if got, _ := s.SenderAllowed(addr); got != want {
			t.Errorf("SenderAllowed(%q) = %v, want %v", addr, got, want)
		}
	}
}

// A database created before the allowed list existed is seeded from the hosts' mailboxes
// on first open, so upgrading doesn't reject mail that worked before.
func TestAllowedSendersSeededOnUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []Host{
		{Name: "a", Match: "10.0.0.1", Sender: "Reports@contoso.com", Enabled: true},
		{Name: "b", Match: "10.0.0.2", Sender: "reports@contoso.com", Enabled: true},
		{Name: "c", Match: "10.0.0.3", Sender: "notify@contoso.com", Enabled: false},
	} {
		if err := s.SaveHost(&h); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	// Simulate the old schema state: no allowed_senders setting yet.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM settings WHERE key = ?`, keyAllowedSenders); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	list, _ := s.AllowedSenders()
	if want := []string{"notify@contoso.com", "reports@contoso.com"}; !slices.Equal(list, want) {
		t.Fatalf("seeded %v, want %v", list, want)
	}

	// Once set (even to empty), reopening must not re-seed.
	if err := s.SetAllowedSenders(nil); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, _ = Open(path)
	defer s.Close()
	if list, _ := s.AllowedSenders(); len(list) != 0 {
		t.Fatalf("re-seeded after explicit empty list: %v", list)
	}
}

func TestConnLog(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	for _, e := range []ConnEntry{
		{Time: now.Add(-3 * time.Hour), ClientIP: "192.0.2.10", Port: "587", Helo: "scanner", HostName: "Scanner", Sent: 2, Outcome: ConnOK, TLS: "TLS 1.2 X"},
		{Time: now.Add(-2 * time.Hour), ClientIP: "192.0.2.10", Port: "587", Helo: "scanner", HostName: "Scanner", Outcome: ConnTLSFailed, Detail: "no cipher suite in common"},
		{Time: now.Add(-90 * time.Minute), ClientIP: "192.0.2.20", Port: "25", Helo: "backup", Outcome: ConnIdle},
		{Time: now.Add(-time.Hour), ClientIP: "192.0.2.10", Port: "587", Helo: "scanner-new", HostName: "Scanner", Sent: 1, Outcome: ConnOK, TLS: "TLS 1.2 Y"},
		{Time: now.Add(-48 * time.Hour), ClientIP: "192.0.2.99", Port: "25", Outcome: ConnRejected, Detail: "old"},
	} {
		if err := s.AddConn(&e); err != nil {
			t.Fatal(err)
		}
	}
	since := now.Add(-24 * time.Hour)

	st, err := s.ConnStats(since)
	if err != nil || st != (ConnStats{Connections: 4, Devices: 2, Delivered: 3, Problems: 1}) {
		t.Fatalf("stats = %+v, %v", st, err)
	}

	devs, err := s.ConnDevices(since)
	if err != nil || len(devs) != 2 {
		t.Fatalf("devices = %+v, %v", devs, err)
	}
	// Most recently seen first, with the fields of its latest connection.
	d := devs[0]
	if d.ClientIP != "192.0.2.10" || d.Connections != 3 || d.Sent != 3 || d.Problems != 1 ||
		d.Helo != "scanner-new" || d.LastOutcome != ConnOK || d.LastTLS != "TLS 1.2 Y" {
		t.Fatalf("device = %+v", d)
	}

	for kind, want := range map[string]int{"": 4, "ok": 2, "idle": 1, "problem": 1} {
		list, err := s.ListConns(ConnFilter{Kind: kind, Since: since})
		if err != nil || len(list) != want {
			t.Errorf("kind %q: %d rows, want %d (%v)", kind, len(list), want, err)
		}
	}
	if list, _ := s.ListConns(ConnFilter{Query: "cipher", Since: since}); len(list) != 1 || !list[0].Problem() {
		t.Errorf("search by detail: %+v", list)
	}
	if list, _ := s.ListConns(ConnFilter{Query: "%", Since: since}); len(list) != 0 {
		t.Errorf("a literal %% must not match everything: %d rows", len(list))
	}

	hours, err := s.ConnHourly(since)
	if err != nil || len(hours) < 24 || len(hours) > 26 {
		t.Fatalf("hourly = %d buckets, %v", len(hours), err)
	}
	var ok, problems int
	for _, h := range hours {
		ok, problems = ok+h.OK, problems+h.Problems
	}
	if ok != 3 || problems != 1 {
		t.Fatalf("hourly totals ok=%d problems=%d", ok, problems)
	}

	if n, _ := s.PruneConns(since); n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
}
