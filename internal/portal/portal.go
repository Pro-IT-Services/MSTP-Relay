// Package portal is the HTTPS management UI: allowed hosts, host→mailbox mapping,
// message log, test sending and admin password.
package portal

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"graphrelay/internal/config"
	"graphrelay/internal/graph"
	"graphrelay/internal/relay"
	"graphrelay/internal/store"
	"graphrelay/internal/tlsmgr"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	cookieName     = "relay_session"
	sessionTTL     = 12 * time.Hour
	maxLoginFails  = 8
	loginLockout   = 15 * time.Minute
	keyPassword    = "admin_password_hash"
	keyUser        = "admin_user"
	minPasswordLen = 10
)

type Portal struct {
	Cfg     *config.Config
	Store   *store.Store
	Graph   *graph.Client
	TLS     *tlsmgr.Manager
	Matcher *relay.Matcher
	Log     *slog.Logger
	Started time.Time
	// HostsChanged, if set, is called after a host rule is added, changed or deleted.
	HostsChanged func()

	allowed []netip.Prefix
	pages   map[string]*template.Template
	ms      *msLogin // nil when Microsoft login is disabled

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*loginFail
}

type session struct {
	csrf    string
	expires time.Time
	flash   string
	flashOK bool
	user    string // UPN for Microsoft logins, "admin" for local
	display string
	method  string // "microsoft" or "local"
}

type loginFail struct {
	count int
	until time.Time
}

// EnsureAdmin creates the admin account on first start. It returns the generated
// password if one had to be generated (so it can be printed once).
func EnsureAdmin(s *store.Store, initial string) (generated string, err error) {
	if _, err := s.GetSetting(keyPassword); err == nil {
		return "", nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	pw := initial
	if pw == "" {
		pw = randomToken(9)
		generated = pw
	}
	if err := SetAdminPassword(s, pw); err != nil {
		return "", err
	}
	if err := s.SetSetting(keyUser, "admin"); err != nil {
		return "", err
	}
	return generated, nil
}

func SetAdminPassword(s *store.Store, pw string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.SetSetting(keyPassword, string(hash))
}

func bcryptCompare(hash, pw string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
}

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Portal) Handler() (http.Handler, error) {
	for _, c := range p.Cfg.Portal.AllowedCIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			a, err2 := netip.ParseAddr(c)
			if err2 != nil {
				return nil, fmt.Errorf("portal.allowed_cidrs: %q is not an IP or CIDR", c)
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		p.allowed = append(p.allowed, pfx.Masked())
	}
	p.sessions = map[string]*session{}
	p.fails = map[string]*loginFail{}
	if err := p.parseTemplates(); err != nil {
		return nil, err
	}

	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /login", p.loginPage)
	if p.Cfg.Portal.LocalLoginAllowed() {
		mux.HandleFunc("POST /login", p.login)
		mux.HandleFunc("POST /settings/password", p.auth(p.changePassword))
	}
	if p.Cfg.Portal.MicrosoftLogin.Enabled {
		p.ms = newMSLogin(p.Cfg.Portal.MicrosoftLogin, p.Cfg.Graph.TenantID)
		mux.HandleFunc("GET /auth/microsoft", p.msStart)
		mux.HandleFunc("GET /auth/callback", p.msCallback)
	}
	mux.HandleFunc("POST /logout", p.auth(p.logout))
	mux.HandleFunc("GET /{$}", p.auth(p.dashboard))
	mux.HandleFunc("GET /hosts", p.auth(p.hostsList))
	mux.HandleFunc("GET /hosts/new", p.auth(p.hostForm))
	mux.HandleFunc("GET /hosts/{id}", p.auth(p.hostForm))
	mux.HandleFunc("POST /hosts/save", p.auth(p.hostSave))
	mux.HandleFunc("POST /hosts/{id}/delete", p.auth(p.hostDelete))
	mux.HandleFunc("POST /hosts/{id}/toggle", p.auth(p.hostToggle))
	mux.HandleFunc("GET /logs", p.auth(p.logs))
	mux.HandleFunc("GET /activity", p.auth(p.activityPage))
	mux.HandleFunc("GET /activity/data", p.auth(p.activityJSON))
	mux.HandleFunc("GET /test", p.auth(p.testPage))
	mux.HandleFunc("POST /test", p.auth(p.testSend))
	mux.HandleFunc("GET /settings", p.auth(p.settingsPage))
	mux.HandleFunc("POST /settings/senders", p.auth(p.sendersSave))
	mux.HandleFunc("GET /settings/certs/{chain}/{n}/{format}", p.auth(p.certDownload))
	mux.HandleFunc("GET /settings/ca-bundle.pem", p.auth(p.caBundle))

	go p.gc()
	return p.ipFilter(securityHeaders(mux)), nil
}

func (p *Portal) parseTemplates() error {
	funcs := template.FuncMap{
		"ago":   ago,
		"bytes": humanBytes,
		"fmtTime": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"days": func(t time.Time) int { return int(time.Until(t).Hours() / 24) },
	}
	p.pages = map[string]*template.Template{}
	pages, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	for _, page := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(page, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/layout.html", page)
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		p.pages[name] = t
	}
	return nil
}

// --- middleware ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func (p *Portal) ipFilter(next http.Handler) http.Handler {
	if len(p.allowed) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		for _, pfx := range p.allowed {
			if pfx.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

type ctxKey struct{}

func (p *Portal) currentSession(r *http.Request) (string, *session) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[c.Value]
	if !ok || time.Now().After(s.expires) {
		delete(p.sessions, c.Value)
		return "", nil
	}
	s.expires = time.Now().Add(sessionTTL)
	return c.Value, s
}

// auth requires a logged-in session and, for POST requests, a valid CSRF token.
func (p *Portal) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, s := p.currentSession(r)
		if s == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrf)) != 1 {
				http.Error(w, "Invalid or expired form, reload the page and try again.", http.StatusForbidden)
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	}
}

func sess(r *http.Request) *session { return r.Context().Value(ctxKey{}).(*session) }

func (p *Portal) gc() {
	for range time.Tick(10 * time.Minute) {
		p.mu.Lock()
		now := time.Now()
		for k, s := range p.sessions {
			if now.After(s.expires) {
				delete(p.sessions, k)
			}
		}
		for k, f := range p.fails {
			if now.After(f.until) {
				delete(p.fails, k)
			}
		}
		p.mu.Unlock()
		if p.ms != nil {
			p.ms.gc()
		}
	}
}

// --- rendering ---

type pageData struct {
	Title   string
	Active  string
	CSRF    string
	Flash   string
	FlashOK bool
	User    string // display name of the signed-in admin
	Method  string
	D       any
}

func (p *Portal) render(w http.ResponseWriter, r *http.Request, page, title string, data any) {
	pd := pageData{Title: title, Active: page, D: data}
	if v := r.Context().Value(ctxKey{}); v != nil {
		s := v.(*session)
		p.mu.Lock()
		pd.CSRF, pd.Flash, pd.FlashOK = s.csrf, s.flash, s.flashOK
		pd.User, pd.Method = s.display, s.method
		s.flash = ""
		p.mu.Unlock()
	}
	t, ok := p.pages[page]
	if !ok {
		http.Error(w, "unknown page", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", pd); err != nil {
		p.Log.Error("render", "page", page, "err", err)
	}
}

func (p *Portal) flash(r *http.Request, msg string, ok bool) {
	s := sess(r)
	p.mu.Lock()
	s.flash, s.flashOK = msg, ok
	p.mu.Unlock()
}

func (p *Portal) redirect(w http.ResponseWriter, r *http.Request, to, msg string, ok bool) {
	if msg != "" {
		p.flash(r, msg, ok)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// --- login ---

type loginData struct {
	Error     string
	Local     bool
	Microsoft bool
}

func (p *Portal) renderLogin(w http.ResponseWriter, r *http.Request, errMsg string) {
	p.render(w, r, "login", "Sign in", loginData{
		Error:     errMsg,
		Local:     p.Cfg.Portal.LocalLoginAllowed(),
		Microsoft: p.ms != nil,
	})
}

func (p *Portal) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, s := p.currentSession(r); s != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	p.renderLogin(w, r, "")
}

func (p *Portal) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r).String()
	p.mu.Lock()
	f := p.fails[ip]
	locked := f != nil && f.count >= maxLoginFails && time.Now().Before(f.until)
	p.mu.Unlock()
	if locked {
		p.renderLogin(w, r, "Too many failed attempts. Try again later.")
		return
	}

	user, pass := r.PostFormValue("username"), r.PostFormValue("password")
	wantUser, _ := p.Store.GetSetting(keyUser)
	hash, _ := p.Store.GetSetting(keyPassword)
	pwErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	if pwErr != nil || subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) != 1 {
		p.mu.Lock()
		if f == nil {
			f = &loginFail{}
			p.fails[ip] = f
		}
		f.count++
		f.until = time.Now().Add(loginLockout)
		p.mu.Unlock()
		p.Log.Warn("portal login failed", "ip", ip, "user", user)
		p.renderLogin(w, r, "Invalid username or password.")
		return
	}
	p.mu.Lock()
	delete(p.fails, ip)
	p.mu.Unlock()
	p.startSession(w, r, user, user, "local")
}

// startSession issues a fresh session cookie and sends the user to the dashboard.
func (p *Portal) startSession(w http.ResponseWriter, r *http.Request, user, display, method string) {
	token := randomToken(32)
	p.mu.Lock()
	p.sessions[token] = &session{
		csrf: randomToken(16), expires: time.Now().Add(sessionTTL),
		user: user, display: display, method: method,
	}
	p.mu.Unlock()
	// Lax (not Strict) so the cookie is sent on the redirect chain that starts at
	// login.microsoftonline.com; every state-changing request also needs a CSRF token.
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	p.Log.Info("portal login", "ip", clientIP(r), "user", user, "method", method)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Portal) logout(w http.ResponseWriter, r *http.Request) {
	token, _ := p.currentSession(r)
	p.mu.Lock()
	delete(p.sessions, token)
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- helpers ---

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func hostPort(addr string) string {
	if addr == "" {
		return "disabled"
	}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}
