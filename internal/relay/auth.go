package relay

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"

	"graphrelay/internal/store"
)

// Optional SMTP AUTH per host rule. A host with SMTPUser set must match by IP *and* log in;
// a host without credentials keeps working by IP alone and AUTH isn't offered to it.
// go-smtp only offers AUTH on TLS connections (STARTTLS or port 465), because
// Server.AllowInsecureAuth stays false.

const (
	authMaxFailures = 5
	authLockout     = 15 * time.Minute
)

var (
	errAuthFailed  = smtpErr(535, smtp.EnhancedCode{5, 7, 8}, "Authentication credentials invalid")
	errAuthLocked  = smtpErr(454, smtp.EnhancedCode{4, 7, 0}, "Too many failed logins, try again later")
	errAuthNotHere = smtpErr(503, smtp.EnhancedCode{5, 5, 1}, "Authentication is not enabled for this host")
)

// failLimiter counts failed logins per client IP and locks an IP out after too many.
type failLimiter struct {
	mu    sync.Mutex
	fails map[netip.Addr][]time.Time
}

func (l *failLimiter) locked(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip, now)) >= authMaxFailures
}

func (l *failLimiter) fail(ip netip.Addr, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = map[netip.Addr][]time.Time{}
	}
	l.fails[ip] = append(l.recent(ip, now), now)
}

func (l *failLimiter) reset(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// recent drops failures older than the lockout window. Caller holds mu.
func (l *failLimiter) recent(ip netip.Addr, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.fails[ip] {
		if now.Sub(t) < authLockout {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, ip)
	} else {
		l.fails[ip] = keep
	}
	return keep
}

// HashSMTPPassword returns the bcrypt hash stored for a host's SMTP password.
func HashSMTPPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// AuthMechanisms is called for EHLO. Only hosts with credentials are offered AUTH.
func (s *session) AuthMechanisms() []string {
	host, err := s.relay.Matcher.Match(context.Background(), s.ip)
	if err != nil || host == nil || host.SMTPUser == "" {
		return nil
	}
	return []string{sasl.Plain, sasl.Login}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, user, pass string) error {
			if identity != "" && identity != user {
				return s.checkLogin("", "") // authorization identity must match; count as a failure
			}
			return s.checkLogin(user, pass)
		}), nil
	case sasl.Login:
		return &loginServer{check: s.checkLogin}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

// checkLogin verifies credentials against the host rule matching the client IP.
func (s *session) checkLogin(user, pass string) error {
	now := time.Now()
	if s.relay.authFails.locked(s.ip, now) {
		s.relay.Log.Warn("smtp login refused: locked out", "ip", s.ip, "user", user)
		return errAuthLocked
	}
	host, err := s.relay.Matcher.Match(context.Background(), s.ip)
	if err != nil {
		return smtpErr(451, smtp.EnhancedCode{4, 3, 0}, "Temporary server error, try again later")
	}
	if host == nil || host.SMTPUser == "" {
		return errAuthNotHere
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(host.SMTPUser)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(host.SMTPPassHash), []byte(pass)) == nil
	if !userOK || !passOK {
		s.relay.authFails.fail(s.ip, now)
		s.record(&store.LogEntry{Status: "rejected", HostID: host.ID, HostName: host.Name, Sender: host.Sender,
			Error: fmt.Sprintf("SMTP login failed for user %q", truncate(user, 64))})
		s.relay.Log.Warn("smtp login failed", "ip", s.ip, "host", host.Name, "user", truncate(user, 64))
		return errAuthFailed
	}
	s.relay.authFails.reset(s.ip)
	s.authHostID = host.ID
	s.relay.Log.Info("smtp login", "ip", s.ip, "host", host.Name, "user", user)
	return nil
}

// loginServer implements the non-standard but widely used AUTH LOGIN mechanism
// (many printers and scanners support nothing else). go-sasl only ships a client.
type loginServer struct {
	check    func(user, pass string) error
	step     int
	username string
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.step {
	case 0:
		l.step = 1
		if len(response) == 0 { // no initial response: ask for the username
			return []byte("Username:"), false, nil
		}
		fallthrough
	case 1:
		l.username = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 2:
		l.step = 3
		return nil, true, l.check(l.username, string(response))
	}
	return nil, false, errors.New("unexpected client response")
}
