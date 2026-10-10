package store

import (
	"strings"
	"time"
)

// Connection outcomes. A connection is a "problem" when it is one of the failure outcomes.
const (
	ConnOK         = "ok"          // at least one message was delivered
	ConnIdle       = "idle"        // connected and left without sending anything, nothing went wrong
	ConnTLSFailed  = "tls_failed"  // the TLS handshake did not complete
	ConnAuthFailed = "auth_failed" // SMTP login failed
	ConnRejected   = "rejected"    // the relay refused the client or its message
	ConnFailed     = "failed"      // Graph refused or could not take the message
)

const problemOutcomes = `'tls_failed','auth_failed','rejected','failed'`

// ConnEntry is one SMTP connection that reached the relay.
type ConnEntry struct {
	ID         int64
	Time       time.Time
	ClientIP   string
	Port       string
	Helo       string // name the client announced in EHLO/HELO
	TLS        string // e.g. "TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256", empty for plain text
	CertKey    string // certificate type served: "ECDSA" or "RSA"
	AuthUser   string
	AuthOK     bool
	HostID     int64
	HostName   string
	Sent       int
	Failed     int
	Rejected   int
	Outcome    string
	Detail     string
	DurationMS int64
}

// Problem reports whether the connection ended in a failure.
func (e ConnEntry) Problem() bool {
	switch e.Outcome {
	case ConnTLSFailed, ConnAuthFailed, ConnRejected, ConnFailed:
		return true
	}
	return false
}

func (s *Store) migrateConns() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS conn_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          INTEGER NOT NULL,
	client_ip   TEXT NOT NULL,
	port        TEXT NOT NULL,
	helo        TEXT NOT NULL DEFAULT '',
	tls         TEXT NOT NULL DEFAULT '',
	cert_key    TEXT NOT NULL DEFAULT '',
	auth_user   TEXT NOT NULL DEFAULT '',
	auth_ok     INTEGER NOT NULL DEFAULT 0,
	host_id     INTEGER NOT NULL DEFAULT 0,
	host_name   TEXT NOT NULL DEFAULT '',
	sent        INTEGER NOT NULL DEFAULT 0,
	failed      INTEGER NOT NULL DEFAULT 0,
	rejected    INTEGER NOT NULL DEFAULT 0,
	outcome     TEXT NOT NULL,
	detail      TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS conn_log_ts ON conn_log(ts);
CREATE INDEX IF NOT EXISTS conn_log_ip ON conn_log(client_ip, ts);`)
	return err
}

func (s *Store) AddConn(e *ConnEntry) error {
	_, err := s.db.Exec(`INSERT INTO conn_log(ts, client_ip, port, helo, tls, cert_key, auth_user, auth_ok,
		host_id, host_name, sent, failed, rejected, outcome, detail, duration_ms)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Time.Unix(), e.ClientIP, e.Port, e.Helo, e.TLS, e.CertKey, e.AuthUser, e.AuthOK,
		e.HostID, e.HostName, e.Sent, e.Failed, e.Rejected, e.Outcome, e.Detail, e.DurationMS)
	return err
}

// ConnFilter selects connections. Kind is "" (all), "ok" (delivered), "idle" or "problem".
type ConnFilter struct {
	Kind  string
	Query string // matches IP, announced name, host rule, login or detail
	Since time.Time
	Limit int
}

func (s *Store) ListConns(f ConnFilter) ([]ConnEntry, error) {
	where, args := []string{"ts >= ?"}, []any{f.Since.Unix()}
	switch f.Kind {
	case "ok":
		where = append(where, `outcome = 'ok'`)
	case "idle":
		where = append(where, `outcome = 'idle'`)
	case "problem":
		where = append(where, `outcome IN (`+problemOutcomes+`)`)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
		where = append(where, `(client_ip LIKE ? ESCAPE '\' OR helo LIKE ? ESCAPE '\' OR host_name LIKE ? ESCAPE '\'
			OR auth_user LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like, like, like)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	args = append(args, f.Limit)
	rows, err := s.db.Query(`SELECT id, ts, client_ip, port, helo, tls, cert_key, auth_user, auth_ok, host_id, host_name,
		sent, failed, rejected, outcome, detail, duration_ms FROM conn_log
		WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnEntry
	for rows.Next() {
		var e ConnEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.ClientIP, &e.Port, &e.Helo, &e.TLS, &e.CertKey, &e.AuthUser, &e.AuthOK,
			&e.HostID, &e.HostName, &e.Sent, &e.Failed, &e.Rejected, &e.Outcome, &e.Detail, &e.DurationMS); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ConnDevice summarises the connections of one client IP.
type ConnDevice struct {
	ClientIP    string
	Connections int
	Sent        int
	Problems    int
	LastSeen    time.Time
	// From the most recent connection:
	HostName    string
	Helo        string
	LastOutcome string
	LastDetail  string
	LastTLS     string
}

// ConnDevices returns one row per client IP seen since the given time, most recent first.
func (s *Store) ConnDevices(since time.Time) ([]ConnDevice, error) {
	// With a single MAX() aggregate, SQLite takes the bare columns from the row holding the maximum,
	// which gives the fields of each IP's latest connection.
	rows, err := s.db.Query(`SELECT client_ip, COUNT(*), SUM(sent),
		SUM(CASE WHEN outcome IN (`+problemOutcomes+`) THEN 1 ELSE 0 END),
		MAX(ts), host_name, helo, outcome, detail, tls
		FROM conn_log WHERE ts >= ? GROUP BY client_ip ORDER BY 5 DESC LIMIT 500`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnDevice
	for rows.Next() {
		var d ConnDevice
		var ts int64
		if err := rows.Scan(&d.ClientIP, &d.Connections, &d.Sent, &d.Problems, &ts,
			&d.HostName, &d.Helo, &d.LastOutcome, &d.LastDetail, &d.LastTLS); err != nil {
			return nil, err
		}
		d.LastSeen = time.Unix(ts, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ConnBucket counts the connections that started within one hour.
type ConnBucket struct {
	Start    time.Time
	OK       int // delivered or idle
	Problems int
}

// ConnHourly returns one bucket per hour from since until now, including empty hours.
func (s *Store) ConnHourly(since time.Time) ([]ConnBucket, error) {
	rows, err := s.db.Query(`SELECT ts / 3600, COUNT(*),
		SUM(CASE WHEN outcome IN (`+problemOutcomes+`) THEN 1 ELSE 0 END)
		FROM conn_log WHERE ts >= ? GROUP BY ts / 3600`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[int64][2]int{}
	for rows.Next() {
		var h int64
		var total, problems int
		if err := rows.Scan(&h, &total, &problems); err != nil {
			return nil, err
		}
		counts[h] = [2]int{total - problems, problems}
	}
	var out []ConnBucket
	for h := since.Unix() / 3600; h <= time.Now().Unix()/3600; h++ {
		c := counts[h]
		out = append(out, ConnBucket{Start: time.Unix(h*3600, 0), OK: c[0], Problems: c[1]})
	}
	return out, rows.Err()
}

// ConnStats are the headline numbers since a given time.
type ConnStats struct {
	Connections int
	Devices     int
	Delivered   int // messages
	Problems    int // connections
}

func (s *Store) ConnStats(since time.Time) (ConnStats, error) {
	var st ConnStats
	err := s.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT client_ip), COALESCE(SUM(sent), 0),
		COALESCE(SUM(CASE WHEN outcome IN (`+problemOutcomes+`) THEN 1 ELSE 0 END), 0)
		FROM conn_log WHERE ts >= ?`, since.Unix()).Scan(&st.Connections, &st.Devices, &st.Delivered, &st.Problems)
	return st, err
}

func (s *Store) PruneConns(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM conn_log WHERE ts < ?`, olderThan.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
