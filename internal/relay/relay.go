// Package relay implements the SMTP side: it accepts mail from allowed hosts
// and forwards it to Microsoft Graph as the mailbox mapped to that host.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"graphrelay/internal/graph"
	"graphrelay/internal/store"
)

type Relay struct {
	Store   *store.Store
	Graph   *graph.Client
	Matcher *Matcher
	Log     *slog.Logger
	// Timeout for delivering one message to Graph.
	SendTimeout time.Duration

	authFails failLimiter // failed SMTP logins per client IP
}

// Backend returns an SMTP backend for one listener. port is a label for the log
// ("25", "465", "587"); requireTLS rejects MAIL FROM on unencrypted connections.
func (r *Relay) Backend(port string, requireTLS bool) smtp.Backend {
	return smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		ip := remoteIP(c.Conn())
		s := &session{relay: r, conn: c, ip: ip, port: port, requireTLS: requireTLS, info: infoOf(c.Conn())}
		s.note(func(i *connInfo) {
			i.helo = c.Hostname()
			if _, ok := c.TLSConnectionState(); ok {
				i.tlsDone = true // the client is speaking SMTP inside TLS
			}
		})
		return s, nil
	})
}

func remoteIP(c net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

type session struct {
	relay      *Relay
	conn       *smtp.Conn
	ip         netip.Addr
	port       string
	requireTLS bool

	host  *store.Host
	from  string
	rcpts []string

	authHostID int64 // host rule the client logged in for (0 = not logged in); survives RSET

	info *connInfo // connection record; nil when the listener isn't tracked
}

func smtpErr(code int, enh smtp.EnhancedCode, msg string) *smtp.SMTPError {
	return &smtp.SMTPError{Code: code, EnhancedCode: enh, Message: msg}
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.requireTLS {
		if _, ok := s.conn.TLSConnectionState(); !ok {
			return smtpErr(530, smtp.EnhancedCode{5, 7, 0}, "Must issue a STARTTLS command first")
		}
	}
	host, err := s.relay.Matcher.Match(context.Background(), s.ip)
	if err != nil {
		s.relay.Log.Error("host lookup failed", "err", err)
		return smtpErr(451, smtp.EnhancedCode{4, 3, 0}, "Temporary server error, try again later")
	}
	if host == nil {
		s.record(&store.LogEntry{EnvFrom: from, Status: "rejected", Error: "client IP not in allowed hosts"})
		s.relay.Log.Warn("rejected unknown client", "ip", s.ip, "port", s.port, "from", from)
		return smtpErr(554, smtp.EnhancedCode{5, 7, 1}, fmt.Sprintf("Relay access denied for %s", s.ip))
	}
	allowed, err := s.relay.Store.SenderAllowed(host.Sender)
	if err != nil {
		s.relay.Log.Error("allowed senders lookup failed", "err", err)
		return smtpErr(451, smtp.EnhancedCode{4, 3, 0}, "Temporary server error, try again later")
	}
	if !allowed {
		s.record(&store.LogEntry{EnvFrom: from, Status: "rejected",
			HostID: host.ID, HostName: host.Name, Sender: host.Sender,
			Error: fmt.Sprintf("sender mailbox %s is not in the allowed list (Settings)", host.Sender)})
		s.relay.Log.Warn("rejected: host's sender mailbox not allowed", "ip", s.ip, "host", host.Name, "sender", host.Sender)
		return smtpErr(554, smtp.EnhancedCode{5, 7, 1}, "Sender mailbox for this host is not allowed")
	}
	if host.SMTPUser != "" && s.authHostID != host.ID {
		s.record(&store.LogEntry{EnvFrom: from, Status: "rejected",
			HostID: host.ID, HostName: host.Name, Sender: host.Sender,
			Error: "SMTP login required for this host"})
		s.relay.Log.Warn("rejected: login required", "ip", s.ip, "host", host.Name)
		return smtpErr(530, smtp.EnhancedCode{5, 7, 0}, "Authentication required")
	}
	s.host = host
	s.from = from
	s.rcpts = nil
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.host == nil {
		return smtpErr(503, smtp.EnhancedCode{5, 5, 1}, "MAIL FROM first")
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return smtpErr(553, smtp.EnhancedCode{5, 1, 3}, "Invalid recipient address")
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	start := time.Now()
	raw, err := io.ReadAll(r)
	if err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) {
			s.record(&store.LogEntry{Size: int64(len(raw)), Status: "rejected", Error: se.Message})
		}
		return err
	}
	entry := &store.LogEntry{Size: int64(len(raw))}
	defer func() {
		entry.DurationMS = time.Since(start).Milliseconds()
		s.record(entry)
	}()

	p, err := prepare(raw, s.rcpts, s.host.Sender, s.host.RewriteFrom)
	if err != nil {
		entry.Status, entry.Error = "rejected", err.Error()
		return smtpErr(554, smtp.EnhancedCode{5, 6, 0}, "Message could not be parsed")
	}
	entry.Subject = p.subject

	ctx, cancel := context.WithTimeout(context.Background(), s.relay.SendTimeout)
	defer cancel()
	if len(p.raw) <= graph.MaxMIMEBytes {
		err = s.relay.Graph.SendMIME(ctx, s.host.Sender, p.raw)
	} else {
		var gm *graph.Message
		gm, err = toGraphMessage(p.raw)
		if err != nil {
			entry.Status, entry.Error = "rejected", "parse MIME: "+err.Error()
			return smtpErr(554, smtp.EnhancedCode{5, 6, 0}, "Message could not be parsed")
		}
		err = s.relay.Graph.SendLarge(ctx, s.host.Sender, gm)
	}
	if err != nil {
		entry.Status, entry.Error = "failed", err.Error()
		s.relay.Log.Error("graph send failed", "host", s.host.Name, "mailbox", s.host.Sender, "err", err)
		if graph.Temporary(err) {
			return smtpErr(451, smtp.EnhancedCode{4, 4, 0}, "Upstream delivery failed temporarily, try again later")
		}
		return smtpErr(554, smtp.EnhancedCode{5, 0, 0}, "Upstream rejected the message: "+truncate(err.Error(), 200))
	}
	entry.Status = "sent"
	s.relay.Log.Info("sent", "host", s.host.Name, "ip", s.ip, "mailbox", s.host.Sender,
		"rcpts", len(s.rcpts), "bytes", len(raw), "ms", time.Since(start).Milliseconds())
	return nil
}

func (s *session) record(e *store.LogEntry) {
	e.Time = time.Now()
	e.ClientIP = s.ip.String()
	e.Port = s.port
	if e.EnvFrom == "" {
		e.EnvFrom = s.from
	}
	e.Recipients = strings.Join(s.rcpts, ", ")
	if s.host != nil {
		e.HostID, e.HostName, e.Sender = s.host.ID, s.host.Name, s.host.Sender
	}
	if err := s.relay.Store.AddLog(e); err != nil {
		s.relay.Log.Error("write message log", "err", err)
	}
	s.note(func(i *connInfo) {
		if e.HostID != 0 {
			i.hostID, i.hostName = e.HostID, e.HostName
		}
		switch e.Status {
		case "sent":
			i.sent++
		case "failed":
			i.failed++
			i.lastErr = e.Error
		default:
			i.rejected++
			i.lastErr = e.Error
		}
	})
}

func (s *session) Reset() {
	s.host, s.from, s.rcpts = nil, "", nil
}

func (s *session) Logout() error { return nil }

// truncate shortens s for an SMTP reply line (which must not contain line breaks).
func truncate(s string, n int) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
