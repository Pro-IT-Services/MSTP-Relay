// Package store persists hosts, settings and the message log in SQLite.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Host is an allowed client. Match is an IP address, a CIDR, or a DNS name
// that is resolved when clients connect.
type Host struct {
	ID     int64
	Name   string
	Match  string
	Sender string // mailbox used to send through Graph
	// Optional SMTP AUTH. When SMTPUser is set, the client must also log in with these
	// credentials (over TLS). SMTPPassHash is a bcrypt hash.
	SMTPUser     string
	SMTPPassHash string
	RewriteFrom  bool // replace the From header address with Sender
	Enabled      bool
	Note         string
	CreatedAt    time.Time
}

type LogEntry struct {
	ID         int64
	Time       time.Time
	ClientIP   string
	Port       string
	HostID     int64
	HostName   string
	Sender     string
	EnvFrom    string
	Recipients string
	Subject    string
	Size       int64
	Status     string // "sent", "rejected", "failed"
	Error      string
	DurationMS int64
}

type Stats struct {
	Sent24h, Failed24h, Rejected24h int
}

var ErrNotFound = errors.New("not found")

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL,
	match        TEXT NOT NULL UNIQUE,
	sender       TEXT NOT NULL,
	rewrite_from INTEGER NOT NULL DEFAULT 1,
	enabled      INTEGER NOT NULL DEFAULT 1,
	note         TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS message_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          INTEGER NOT NULL,
	client_ip   TEXT NOT NULL,
	port        TEXT NOT NULL,
	host_id     INTEGER NOT NULL DEFAULT 0,
	host_name   TEXT NOT NULL DEFAULT '',
	sender      TEXT NOT NULL DEFAULT '',
	env_from    TEXT NOT NULL DEFAULT '',
	recipients  TEXT NOT NULL DEFAULT '',
	subject     TEXT NOT NULL DEFAULT '',
	size        INTEGER NOT NULL DEFAULT 0,
	status      TEXT NOT NULL,
	error       TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS message_log_ts ON message_log(ts);
`)
	if err != nil {
		return err
	}
	// Columns added after the first release.
	for _, col := range []string{
		`smtp_user TEXT NOT NULL DEFAULT ''`,
		`smtp_pass_hash TEXT NOT NULL DEFAULT ''`,
	} {
		if err := s.addColumn("hosts", col); err != nil {
			return err
		}
	}
	if err := s.migrateConns(); err != nil {
		return err
	}
	// Databases from before the allowed-senders list: seed it from the hosts' current
	// mailboxes, so upgrading doesn't block mail that works today.
	if _, err := s.GetSetting(keyAllowedSenders); errors.Is(err, ErrNotFound) {
		rows, err := s.db.Query(`SELECT DISTINCT sender FROM hosts`)
		if err != nil {
			return err
		}
		var seed []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return err
			}
			seed = append(seed, v)
		}
		rows.Close()
		return s.SetAllowedSenders(seed)
	}
	return nil
}

// addColumn adds a column definition to table unless a column of that name exists.
func (s *Store) addColumn(table, def string) error {
	name := strings.Fields(def)[0]
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		if n == name {
			return nil
		}
	}
	rows.Close()
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + def)
	return err
}

// --- allowed sender mailboxes ---

const keyAllowedSenders = "allowed_senders"

// NormalizeSenders lower-cases, trims, de-duplicates and sorts mailbox addresses.
func NormalizeSenders(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range list {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// AllowedSenders returns the mailboxes host rules may send as, sorted.
func (s *Store) AllowedSenders() ([]string, error) {
	v, err := s.GetSetting(keyAllowedSenders)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return NormalizeSenders(strings.Split(v, "\n")), nil
}

func (s *Store) SetAllowedSenders(list []string) error {
	return s.SetSetting(keyAllowedSenders, strings.Join(NormalizeSenders(list), "\n"))
}

// SenderAllowed reports whether mailbox is on the allowed list (case-insensitive).
func (s *Store) SenderAllowed(mailbox string) (bool, error) {
	list, err := s.AllowedSenders()
	if err != nil {
		return false, err
	}
	_, found := slices.BinarySearch(list, strings.ToLower(strings.TrimSpace(mailbox)))
	return found, nil
}

// --- settings ---

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// --- hosts ---

const hostCols = `id, name, match, sender, rewrite_from, enabled, note, created_at, smtp_user, smtp_pass_hash`

func scanHost(sc interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var created int64
	err := sc.Scan(&h.ID, &h.Name, &h.Match, &h.Sender, &h.RewriteFrom, &h.Enabled, &h.Note, &created,
		&h.SMTPUser, &h.SMTPPassHash)
	h.CreatedAt = time.Unix(created, 0)
	return h, err
}

func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT ` + hostCols + ` FROM hosts ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) GetHost(id int64) (Host, error) {
	h, err := scanHost(s.db.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	return h, err
}

func (s *Store) SaveHost(h *Host) error {
	if h.ID == 0 {
		res, err := s.db.Exec(`INSERT INTO hosts(name, match, sender, rewrite_from, enabled, note, created_at,
			smtp_user, smtp_pass_hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.Name, h.Match, h.Sender, h.RewriteFrom, h.Enabled, h.Note, time.Now().Unix(), h.SMTPUser, h.SMTPPassHash)
		if err != nil {
			return friendly(err)
		}
		h.ID, err = res.LastInsertId()
		return err
	}
	_, err := s.db.Exec(`UPDATE hosts SET name = ?, match = ?, sender = ?, rewrite_from = ?, enabled = ?, note = ?,
		smtp_user = ?, smtp_pass_hash = ? WHERE id = ?`,
		h.Name, h.Match, h.Sender, h.RewriteFrom, h.Enabled, h.Note, h.SMTPUser, h.SMTPPassHash, h.ID)
	return friendly(err)
}

func (s *Store) DeleteHost(id int64) error {
	_, err := s.db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	return err
}

func friendly(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: hosts.match") {
		return errors.New("another host already uses this address / network / hostname")
	}
	return err
}

// --- message log ---

func (s *Store) AddLog(e *LogEntry) error {
	_, err := s.db.Exec(`INSERT INTO message_log(ts, client_ip, port, host_id, host_name, sender, env_from,
		recipients, subject, size, status, error, duration_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Time.Unix(), e.ClientIP, e.Port, e.HostID, e.HostName, e.Sender, e.EnvFrom,
		e.Recipients, e.Subject, e.Size, e.Status, e.Error, e.DurationMS)
	return err
}

type LogFilter struct {
	Status string
	Query  string // matches IP, host, sender, from, recipients, subject
	Limit  int
	Offset int
}

func (s *Store) ListLog(f LogFilter) ([]LogEntry, error) {
	where := []string{"1=1"}
	var args []any
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.Query != "" {
		where = append(where, `(client_ip LIKE ? OR host_name LIKE ? OR sender LIKE ? OR env_from LIKE ?
			OR recipients LIKE ? OR subject LIKE ?)`)
		q := "%" + f.Query + "%"
		args = append(args, q, q, q, q, q, q)
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Query(`SELECT id, ts, client_ip, port, host_id, host_name, sender, env_from, recipients,
		subject, size, status, error, duration_ms FROM message_log WHERE `+strings.Join(where, " AND ")+`
		ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.ClientIP, &e.Port, &e.HostID, &e.HostName, &e.Sender, &e.EnvFrom,
			&e.Recipients, &e.Subject, &e.Size, &e.Status, &e.Error, &e.DurationMS); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Stats() (Stats, error) {
	var st Stats
	since := time.Now().Add(-24 * time.Hour).Unix()
	err := s.db.QueryRow(`SELECT
		COALESCE(SUM(status = 'sent'), 0),
		COALESCE(SUM(status = 'failed'), 0),
		COALESCE(SUM(status = 'rejected'), 0)
		FROM message_log WHERE ts >= ?`, since).Scan(&st.Sent24h, &st.Failed24h, &st.Rejected24h)
	return st, err
}

func (s *Store) PruneLog(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM message_log WHERE ts < ?`, olderThan.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
