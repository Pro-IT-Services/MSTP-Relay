package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"graphrelay/internal/config"
)

// msAuthority is the Entra ID login host; a variable so tests can use a fake IdP.
var msAuthority = "https://login.microsoftonline.com"

const (
	oidcCookie     = "relay_oidc"
	oidcPendingTTL = 10 * time.Minute
)

// msLogin implements "Sign in with Microsoft" (OpenID Connect authorization
// code flow with PKCE) and only admits users holding an allowed role.
type msLogin struct {
	cfg    config.MicrosoftLoginConfig
	tenant string

	initMu   sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier

	mu      sync.Mutex
	pending map[string]pendingLogin // keyed by state
}

type pendingLogin struct {
	nonce, codeVerifier string
	expires             time.Time
}

type msClaims struct {
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	OID               string   `json:"oid"`
	TID               string   `json:"tid"`
	Roles             []string `json:"roles"`
	WIDs              []string `json:"wids"`
}

func newMSLogin(cfg config.MicrosoftLoginConfig, tenant string) *msLogin {
	return &msLogin{cfg: cfg, tenant: strings.ToLower(tenant), pending: map[string]pendingLogin{}}
}

// setup discovers the tenant's OpenID configuration on first use, so a network
// hiccup at startup doesn't stop the relay.
func (m *msLogin) setup(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	m.initMu.Lock()
	defer m.initMu.Unlock()
	if m.oauth != nil {
		return m.oauth, m.verifier, nil
	}
	provider, err := oidc.NewProvider(ctx, msAuthority+"/"+m.tenant+"/v2.0")
	if err != nil {
		return nil, nil, fmt.Errorf("OpenID discovery: %w", err)
	}
	ep := provider.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInParams
	m.oauth = &oauth2.Config{
		ClientID:     m.cfg.ClientID,
		ClientSecret: m.cfg.ClientSecret,
		Endpoint:     ep,
		RedirectURL:  m.cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	m.verifier = provider.Verifier(&oidc.Config{ClientID: m.cfg.ClientID})
	return m.oauth, m.verifier, nil
}

func (m *msLogin) gc() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, p := range m.pending {
		if now.After(p.expires) {
			delete(m.pending, k)
		}
	}
}

// authorized reports whether the token grants access to the portal.
func (m *msLogin) authorized(c *msClaims) bool {
	for _, r := range c.Roles {
		if slices.ContainsFunc(m.cfg.RequiredRoles, func(want string) bool { return strings.EqualFold(want, r) }) {
			return true
		}
	}
	for _, w := range c.WIDs {
		if slices.ContainsFunc(m.cfg.AllowedDirectoryRoles, func(want string) bool { return strings.EqualFold(want, w) }) {
			return true
		}
	}
	return false
}

// msStart redirects the browser to Microsoft's sign-in page.
func (p *Portal) msStart(w http.ResponseWriter, r *http.Request) {
	oauthCfg, _, err := p.ms.setup(r.Context())
	if err != nil {
		p.Log.Error("microsoft login unavailable", "err", err)
		p.renderLogin(w, r, "Microsoft sign-in is unavailable right now: "+err.Error())
		return
	}
	state, nonce, verifier := randomToken(16), randomToken(16), oauth2.GenerateVerifier()
	p.ms.mu.Lock()
	p.ms.pending[state] = pendingLogin{nonce: nonce, codeVerifier: verifier, expires: time.Now().Add(oidcPendingTTL)}
	p.ms.mu.Unlock()
	// Lax so the cookie survives the top-level redirect back from Microsoft.
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: state, Path: "/auth/", MaxAge: int(oidcPendingTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, oauthCfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	), http.StatusFound)
}

// msCallback completes the sign-in after Microsoft redirects back.
func (p *Portal) msCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/auth/", MaxAge: -1, Secure: true, HttpOnly: true})
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if i := strings.IndexAny(desc, "\r\n"); i > 0 {
			desc = desc[:i]
		}
		p.Log.Warn("microsoft login error", "ip", clientIP(r), "error", e, "description", desc)
		p.renderLogin(w, r, "Microsoft sign-in failed: "+e+". "+desc)
		return
	}

	claims, err := p.msExchange(r)
	if err != nil {
		p.Log.Warn("microsoft login rejected", "ip", clientIP(r), "err", err)
		p.renderLogin(w, r, "Microsoft sign-in failed. Please try again.")
		return
	}
	user := claims.PreferredUsername
	if user == "" {
		user = claims.Email
	}
	if !p.ms.authorized(claims) {
		p.Log.Warn("microsoft login denied: missing admin role", "ip", clientIP(r), "user", user, "oid", claims.OID, "roles", claims.Roles)
		role := "relay admin"
		if len(p.ms.cfg.RequiredRoles) > 0 {
			role = strings.Join(p.ms.cfg.RequiredRoles, " / ")
		}
		p.renderLogin(w, r, fmt.Sprintf("%s is not allowed to manage this relay. Ask an administrator to assign you the %s role.", user, role))
		return
	}
	display := claims.Name
	if display == "" {
		display = user
	}
	p.startSession(w, r, user, display, "microsoft")
}

func (p *Portal) msExchange(r *http.Request) (*msClaims, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	oauthCfg, verifier, err := p.ms.setup(ctx)
	if err != nil {
		return nil, err
	}
	state := r.URL.Query().Get("state")
	c, err := r.Cookie(oidcCookie)
	if err != nil || state == "" || c.Value != state {
		return nil, errors.New("state mismatch (cookie missing or different browser)")
	}
	p.ms.mu.Lock()
	pend, ok := p.ms.pending[state]
	delete(p.ms.pending, state) // one-time use
	p.ms.mu.Unlock()
	if !ok || time.Now().After(pend.expires) {
		return nil, errors.New("login attempt expired")
	}

	tok, err := oauthCfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pend.codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("no id_token in token response")
	}
	idt, err := verifier.Verify(ctx, raw) // signature, issuer, audience, expiry
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	if idt.Nonce != pend.nonce {
		return nil, errors.New("id_token nonce mismatch")
	}
	var claims msClaims
	if err := idt.Claims(&claims); err != nil {
		return nil, err
	}
	if !strings.EqualFold(claims.TID, p.ms.tenant) {
		return nil, fmt.Errorf("token from foreign tenant %q", claims.TID)
	}
	return &claims, nil
}
