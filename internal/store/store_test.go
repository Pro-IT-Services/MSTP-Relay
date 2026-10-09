package store

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
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
