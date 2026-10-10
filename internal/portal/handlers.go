package portal

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"

	"graphrelay/internal/relay"
	"graphrelay/internal/store"
	"graphrelay/internal/tlsmgr"
)

// --- dashboard ---

func (p *Portal) dashboard(w http.ResponseWriter, r *http.Request) {
	stats, _ := p.Store.Stats()
	hosts, _ := p.Store.ListHosts()
	recent, _ := p.Store.ListLog(store.LogFilter{Limit: 10})

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	graphErr := p.Graph.CheckToken(ctx)

	enabled := 0
	for _, h := range hosts {
		if h.Enabled {
			enabled++
		}
	}
	p.render(w, r, "dashboard", "Dashboard", struct {
		Stats        store.Stats
		Hosts        int
		EnabledHosts int
		Recent       []store.LogEntry
		Cert         tlsmgr.CertInfo
		TLSMode      string
		GraphErr     error
		Ports        [][2]string
		Uptime       string
	}{
		Stats: stats, Hosts: len(hosts), EnabledHosts: enabled, Recent: recent,
		Cert: p.TLS.Info(), TLSMode: p.TLS.Mode, GraphErr: graphErr,
		Ports: [][2]string{
			{"SMTP (STARTTLS)", hostPort(p.Cfg.SMTP.Plain)},
			{"SMTPS (implicit TLS)", hostPort(p.Cfg.SMTP.SMTPS)},
			{"Submission (STARTTLS)", hostPort(p.Cfg.SMTP.Submission)},
		},
		Uptime: time.Since(p.Started).Round(time.Minute).String(),
	})
}

// --- hosts ---

func (p *Portal) hostsList(w http.ResponseWriter, r *http.Request) {
	hosts, err := p.Store.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	type check struct {
		IP    string
		Valid bool
		Host  *store.Host
	}
	var chk *check
	if q := strings.TrimSpace(r.URL.Query().Get("check")); q != "" {
		chk = &check{IP: q}
		if ip, err := netip.ParseAddr(q); err == nil {
			chk.Valid = true
			chk.Host, _ = p.Matcher.Match(r.Context(), ip)
		}
	}
	allowed := map[string]bool{}
	for _, m := range p.senders() {
		allowed[m] = true
	}
	p.render(w, r, "hosts", "Allowed hosts", struct {
		Hosts   []store.Host
		Check   *check
		Allowed map[string]bool
	}{hosts, chk, allowed})
}

type hostFormData struct {
	Host    store.Host
	Senders []string // allowed mailboxes for the dropdown
	Error   string
}

func (p *Portal) hostForm(w http.ResponseWriter, r *http.Request) {
	h := store.Host{Enabled: true, RewriteFrom: true}
	if idStr := r.PathValue("id"); idStr != "" {
		id, _ := strconv.ParseInt(idStr, 10, 64)
		var err error
		if h, err = p.Store.GetHost(id); err != nil {
			p.redirect(w, r, "/hosts", "Host not found.", false)
			return
		}
	}
	title := "Add host"
	if h.ID != 0 {
		title = "Edit host"
	} else if m, ok := relay.ValidateMatch(r.URL.Query().Get("match")); ok {
		h.Match = m // prefilled from the Activity page ("Add a host" next to an address)
	}
	p.render(w, r, "host_form", title, hostFormData{Host: h, Senders: p.senders()})
}

func (p *Portal) hostSave(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	h := store.Host{
		ID:          id,
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		Match:       strings.TrimSpace(r.PostFormValue("match")),
		Sender:      strings.TrimSpace(r.PostFormValue("sender")),
		RewriteFrom: r.PostFormValue("rewrite_from") == "on",
		Enabled:     r.PostFormValue("enabled") == "on",
		Note:        strings.TrimSpace(r.PostFormValue("note")),
		SMTPUser:    strings.TrimSpace(r.PostFormValue("smtp_user")), // redisplayed if the form fails
	}
	fail := func(msg string) {
		title := "Add host"
		if h.ID != 0 {
			title = "Edit host"
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		p.render(w, r, "host_form", title, hostFormData{Host: h, Senders: p.senders(), Error: msg})
	}
	if h.Name == "" {
		fail("Name is required.")
		return
	}
	norm, ok := relay.ValidateMatch(h.Match)
	if !ok {
		fail("Address must be an IP address (10.0.0.5), a network in CIDR notation (10.0.0.0/24) or a DNS hostname.")
		return
	}
	h.Match = norm
	h.Sender = strings.ToLower(h.Sender)
	if ok, _ := p.Store.SenderAllowed(h.Sender); !ok {
		fail("Choose a sender mailbox from the list. Add new mailboxes under Settings → Allowed sender mailboxes.")
		return
	}
	if msg := p.applySMTPAuth(r, &h); msg != "" {
		fail(msg)
		return
	}
	if err := p.Store.SaveHost(&h); err != nil {
		fail(err.Error())
		return
	}
	p.hostsChanged()
	p.Log.Info("host saved", "id", h.ID, "name", h.Name, "match", h.Match, "sender", h.Sender,
		"smtp_login", h.SMTPUser != "")
	p.redirect(w, r, "/hosts", fmt.Sprintf("Saved %q.", h.Name), true)
}

var smtpUserRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)

const minSMTPPasswordLen = 12

// applySMTPAuth sets the host's optional SMTP login from the form. An empty password keeps
// the stored one; "smtp_remove" or an empty username turns the login off. Returns an error
// message for the form, or "".
func (p *Portal) applySMTPAuth(r *http.Request, h *store.Host) string {
	user := strings.TrimSpace(r.PostFormValue("smtp_user"))
	pass := r.PostFormValue("smtp_password")
	var old store.Host
	if h.ID != 0 {
		old, _ = p.Store.GetHost(h.ID)
	}
	if r.PostFormValue("smtp_remove") == "on" || (user == "" && pass == "") {
		h.SMTPUser, h.SMTPPassHash = "", ""
		return ""
	}
	if user == "" {
		return "Enter an SMTP username, or leave both login fields empty."
	}
	if !smtpUserRe.MatchString(user) {
		return "SMTP username may contain letters, digits and . _ @ + - (up to 64 characters)."
	}
	h.SMTPUser = user
	switch {
	case pass != "":
		if len(pass) < minSMTPPasswordLen {
			return fmt.Sprintf("SMTP password must be at least %d characters.", minSMTPPasswordLen)
		}
		hash, err := relay.HashSMTPPassword(pass)
		if err != nil {
			return err.Error()
		}
		h.SMTPPassHash = hash
	case old.SMTPPassHash != "":
		h.SMTPPassHash = old.SMTPPassHash // keep the current password
	default:
		return "Set an SMTP password for this username."
	}
	return ""
}

func (p *Portal) hostDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	h, err := p.Store.GetHost(id)
	if err != nil {
		p.redirect(w, r, "/hosts", "Host not found.", false)
		return
	}
	if err := p.Store.DeleteHost(id); err != nil {
		p.redirect(w, r, "/hosts", err.Error(), false)
		return
	}
	p.hostsChanged()
	p.Log.Info("host deleted", "id", id, "name", h.Name, "match", h.Match)
	p.redirect(w, r, "/hosts", fmt.Sprintf("Deleted %q.", h.Name), true)
}

func (p *Portal) hostToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	h, err := p.Store.GetHost(id)
	if err != nil {
		p.redirect(w, r, "/hosts", "Host not found.", false)
		return
	}
	h.Enabled = !h.Enabled
	if err := p.Store.SaveHost(&h); err != nil {
		p.redirect(w, r, "/hosts", err.Error(), false)
		return
	}
	p.hostsChanged()
	state := "disabled"
	if h.Enabled {
		state = "enabled"
	}
	p.redirect(w, r, "/hosts", fmt.Sprintf("%q %s.", h.Name, state), true)
}

// --- message log ---

const logPageSize = 100

func (p *Portal) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	f := store.LogFilter{
		Status: q.Get("status"),
		Query:  strings.TrimSpace(q.Get("q")),
		Limit:  logPageSize + 1,
		Offset: (page - 1) * logPageSize,
	}
	entries, err := p.Store.ListLog(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	more := len(entries) > logPageSize
	if more {
		entries = entries[:logPageSize]
	}
	p.render(w, r, "logs", "Message log", struct {
		Entries        []store.LogEntry
		Status, Query  string
		Page           int
		Prev, Next     int
		HasPrev, HasNx bool
	}{entries, f.Status, f.Query, page, page - 1, page + 1, page > 1, more})
}

// --- test send ---

type testData struct {
	Senders                    []string
	Mailbox, To, Subject, Body string
	Error                      string
}

// senders returns the mailboxes that may be chosen as senders (Settings → Allowed sender mailboxes).
func (p *Portal) senders() []string {
	list, err := p.Store.AllowedSenders()
	if err != nil {
		p.Log.Error("read allowed senders", "err", err)
	}
	return list
}

func (p *Portal) testPage(w http.ResponseWriter, r *http.Request) {
	d := testData{Senders: p.senders(), Subject: "Graph relay test", Body: "This is a test message from the SMTP → Microsoft Graph relay."}
	if len(d.Senders) > 0 {
		d.Mailbox = d.Senders[0]
	}
	p.render(w, r, "test", "Send test email", d)
}

func (p *Portal) testSend(w http.ResponseWriter, r *http.Request) {
	d := testData{
		Senders: p.senders(),
		Mailbox: strings.TrimSpace(r.PostFormValue("mailbox")),
		To:      strings.TrimSpace(r.PostFormValue("to")),
		Subject: r.PostFormValue("subject"),
		Body:    r.PostFormValue("body"),
	}
	fail := func(msg string) {
		d.Error = msg
		p.render(w, r, "test", "Send test email", d)
	}
	if ok, _ := p.Store.SenderAllowed(d.Mailbox); !ok {
		fail("Choose a sender mailbox from the list. Add new mailboxes under Settings → Allowed sender mailboxes.")
		return
	}
	from, err1 := mail.ParseAddress(d.Mailbox)
	to, err2 := mail.ParseAddress(d.To)
	if err1 != nil || err2 != nil {
		fail("The recipient must be a valid email address.")
		return
	}

	var buf bytes.Buffer
	var h gomail.Header
	h.SetDate(time.Now())
	h.SetAddressList("From", []*gomail.Address{{Address: from.Address}})
	h.SetAddressList("To", []*gomail.Address{{Address: to.Address}})
	h.SetSubject(d.Subject)
	h.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
	h.GenerateMessageID()
	wr, err := gomail.CreateSingleInlineWriter(&buf, h)
	if err == nil {
		_, err = wr.Write([]byte(d.Body))
		wr.Close()
	}
	if err != nil {
		fail(err.Error())
		return
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	sendErr := p.Graph.SendMIME(ctx, from.Address, buf.Bytes())
	entry := &store.LogEntry{
		Time: time.Now(), ClientIP: clientIP(r).String(), Port: "portal", HostName: "(portal test)",
		Sender: from.Address, EnvFrom: from.Address, Recipients: to.Address, Subject: d.Subject,
		Size: int64(buf.Len()), Status: "sent", DurationMS: time.Since(start).Milliseconds(),
	}
	if sendErr != nil {
		entry.Status, entry.Error = "failed", sendErr.Error()
	}
	p.Store.AddLog(entry)
	if sendErr != nil {
		fail("Graph rejected the message: " + sendErr.Error())
		return
	}
	p.redirect(w, r, "/test", fmt.Sprintf("Test message sent from %s to %s.", from.Address, to.Address), true)
}

// --- settings ---

func (p *Portal) settingsPage(w http.ResponseWriter, r *http.Request) {
	p.render(w, r, "settings", "Settings", p.settingsData(""))
}

// sendersSave replaces the allowed sender mailboxes (one address per line).
func (p *Portal) sendersSave(w http.ResponseWriter, r *http.Request) {
	text := r.PostFormValue("senders")
	var list, bad []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune("\n\r,; \t", r) }) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if a, err := mail.ParseAddress(line); err != nil || a.Name != "" || a.Address != line {
			bad = append(bad, line)
			continue
		}
		list = append(list, line)
	}
	if len(bad) > 0 {
		d := p.settingsData("")
		d.SendersText = text
		d.SendersError = "Not a plain email address: " + strings.Join(bad, ", ")
		w.WriteHeader(http.StatusUnprocessableEntity)
		p.render(w, r, "settings", "Settings", d)
		return
	}
	if err := p.Store.SetAllowedSenders(list); err != nil {
		p.redirect(w, r, "/settings", err.Error(), false)
		return
	}
	list, _ = p.Store.AllowedSenders()
	p.Log.Info("allowed sender mailboxes changed", "ip", clientIP(r), "mailboxes", strings.Join(list, ","))
	msg := fmt.Sprintf("Saved %d allowed sender mailbox(es).", len(list))
	if n := len(p.hostsWithDisallowedSender()); n > 0 {
		msg += fmt.Sprintf(" %d host(s) use a mailbox that is no longer allowed and will be rejected. Check Hosts.", n)
	}
	p.redirect(w, r, "/settings", msg, true)
}

// hostsWithDisallowedSender returns the enabled hosts whose mailbox is not on the allowed list.
func (p *Portal) hostsWithDisallowedSender() []store.Host {
	hosts, _ := p.Store.ListHosts()
	var out []store.Host
	for _, h := range hosts {
		if ok, _ := p.Store.SenderAllowed(h.Sender); h.Enabled && !ok {
			out = append(out, h)
		}
	}
	return out
}

type settingsView struct {
	Error        string
	LocalLogin   bool
	Rows         [][2]string
	SendersText  string
	SendersError string
	Disallowed   []store.Host
	Certs        []certGroup // the relay's certificate chains, for download
}

func (p *Portal) settingsData(errMsg string) *settingsView {
	c := p.Cfg
	secret := "not set"
	if n := len(c.Graph.ClientSecret); n > 4 {
		secret = strings.Repeat("•", 8) + c.Graph.ClientSecret[n-4:]
	}
	ca := "Let's Encrypt (production)"
	if c.TLS.ACMEStaging {
		ca = "Let's Encrypt (staging)"
	}
	if c.TLS.Mode == "selfsigned" {
		ca = "self-signed (testing)"
	}
	signIn := "local account only"
	if ml := c.Portal.MicrosoftLogin; ml.Enabled {
		signIn = "Microsoft (Entra ID)"
		if c.Portal.LocalLoginAllowed() {
			signIn += " + local break-glass account"
		}
	}
	roles := strings.Join(c.Portal.MicrosoftLogin.RequiredRoles, ", ")
	if w := c.Portal.MicrosoftLogin.AllowedDirectoryRoles; len(w) > 0 {
		if roles != "" {
			roles += "; "
		}
		roles += "directory roles " + strings.Join(w, ", ")
	}
	rows := [][2]string{{"Portal sign-in", signIn}}
	if c.Portal.MicrosoftLogin.Enabled {
		rows = append(rows, [2]string{"Admin roles", roles}, [2]string{"Redirect URI", c.Portal.MicrosoftLogin.RedirectURL})
	}
	var certNames []string
	if p.TLS != nil {
		certNames = p.TLS.Domains
	}
	return &settingsView{
		Error: errMsg, LocalLogin: c.Portal.LocalLoginAllowed(),
		SendersText: strings.Join(p.senders(), "\n"), Disallowed: p.hostsWithDisallowedSender(),
		Certs: p.certGroups(context.Background()),
		Rows: append(rows, [][2]string{
			{"Hostname", c.Hostname},
			{"Certificate names", strings.Join(certNames, ", ")},
			{"Certificate authority", ca},
			{"DNS provider", "Cloudflare (DNS-01)"},
			{"SMTP listener", orDisabled(c.SMTP.Plain)},
			{"SMTPS listener", orDisabled(c.SMTP.SMTPS)},
			{"Submission listener", orDisabled(c.SMTP.Submission)},
			{"TLS required on submission", strconv.FormatBool(c.SMTP.RequireTLSOnSubmission)},
			{"Max message size", humanBytes(c.SMTP.MaxMessageBytes)},
			{"Graph tenant ID", c.Graph.TenantID},
			{"Graph client ID", c.Graph.ClientID},
			{"Graph client secret", secret},
			{"Log retention", fmt.Sprintf("%d days", c.LogRetentionDays)},
			{"Data directory", c.DataDir},
		}...)}
}

func orDisabled(s string) string {
	if s == "" {
		return "disabled"
	}
	return s
}

func (p *Portal) changePassword(w http.ResponseWriter, r *http.Request) {
	cur, n1, n2 := r.PostFormValue("current"), r.PostFormValue("new"), r.PostFormValue("confirm")
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		p.render(w, r, "settings", "Settings", p.settingsData(msg))
	}
	hash, _ := p.Store.GetSetting(keyPassword)
	if bcryptCompare(hash, cur) != nil {
		fail("Current password is incorrect.")
		return
	}
	if len(n1) < minPasswordLen {
		fail(fmt.Sprintf("New password must be at least %d characters.", minPasswordLen))
		return
	}
	if n1 != n2 {
		fail("New passwords do not match.")
		return
	}
	if err := SetAdminPassword(p.Store, n1); err != nil {
		fail(err.Error())
		return
	}
	p.Log.Info("admin password changed", "ip", clientIP(r))
	p.redirect(w, r, "/settings", "Password changed.", true)
}

func (p *Portal) hostsChanged() {
	if p.HostsChanged != nil {
		p.HostsChanged()
	}
}
