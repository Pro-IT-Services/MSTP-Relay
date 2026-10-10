package portal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"graphrelay/internal/config"
	"graphrelay/internal/relay"
	"graphrelay/internal/store"
	"graphrelay/internal/tlsmgr"
)

const testTenant = "11111111-2222-3333-4444-555555555555"

// fakeEntra is a minimal OpenID Connect provider that mimics Entra ID.
type fakeEntra struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu        sync.Mutex
	challenge string         // PKCE challenge from the last authorize request
	nonce     string         // nonce from the last authorize request
	claims    map[string]any // extra claims for the next id_token
}

func newFakeEntra(t *testing.T) *fakeEntra {
	f := &fakeEntra{}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	issuer := func() string { return f.srv.URL + "/" + testTenant + "/v2.0" }
	mux.HandleFunc("GET /"+testTenant+"/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer(),
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge || r.Form.Get("code") != "good-code" ||
			r.Form.Get("client_secret") != "secret" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		claims := map[string]any{
			"iss": issuer(), "aud": "client-id", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": f.nonce, "tid": testTenant, "oid": "user-oid",
			"name": "Ada Admin", "preferred_username": "ada@contoso.com",
		}
		for k, v := range f.claims {
			claims[k] = v
		}
		payload, _ := json.Marshal(claims)
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		obj, _ := signer.Sign(payload)
		idt, _ := obj.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type portalEnv struct {
	url    string
	client *http.Client
	entra  *fakeEntra
	store  *store.Store
}

func newPortalEnv(t *testing.T, ml config.MicrosoftLoginConfig) *portalEnv {
	entra := newFakeEntra(t)
	msAuthority = entra.srv.URL

	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	srv := httptest.NewUnstartedServer(nil)
	ml.Enabled, ml.ClientID, ml.ClientSecret = true, "client-id", "secret"
	cfg := &config.Config{Hostname: "relay.test"}
	cfg.Graph.TenantID = testTenant
	cfg.Portal.MicrosoftLogin = ml
	cfg.TLS.Mode = "selfsigned"
	tm, err := tlsmgr.Setup(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &Portal{Cfg: cfg, Store: st, TLS: tm, Matcher: relay.NewMatcher(st), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h, err := p.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.StartTLS()
	t.Cleanup(srv.Close)
	p.ms.cfg.RedirectURL = srv.URL + "/auth/callback"

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &portalEnv{url: srv.URL, client: client, entra: entra, store: st}
}

// signIn runs the browser side of the flow and returns the callback response.
func (e *portalEnv) signIn(t *testing.T, claims map[string]any) (*http.Response, string) {
	t.Helper()
	resp, err := e.client.Get(e.url + "/auth/microsoft")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if resp.StatusCode != http.StatusFound || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		t.Fatalf("bad authorize redirect %d %s", resp.StatusCode, loc)
	}
	e.entra.mu.Lock()
	e.entra.challenge, e.entra.nonce, e.entra.claims = q.Get("code_challenge"), q.Get("nonce"), claims
	e.entra.mu.Unlock()

	state := q.Get("state")
	resp, err = e.client.Get(e.url + "/auth/callback?code=good-code&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatal(err)
	}
	return resp, state
}

func (e *portalEnv) get(t *testing.T, path string) (int, string) {
	resp, err := e.client.Get(e.url + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func body(r *http.Response) string {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func TestMicrosoftLoginAdminAllowed(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})
	resp, _ := e.signIn(t, map[string]any{"roles": []string{"Relay.Admin"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	code, page := e.get(t, "/hosts")
	if code != 200 || !strings.Contains(page, "Ada Admin") || !strings.Contains(page, "Microsoft account") {
		t.Fatalf("hosts page after login: %d", code)
	}
	// Local password login is disabled when Microsoft login is on.
	resp, _ = e.client.PostForm(e.url+"/login", url.Values{"username": {"admin"}, "password": {"x"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("local login POST = %d, want 405", resp.StatusCode)
	}
}

func TestMicrosoftLoginDirectoryRoleAllowed(t *testing.T) {
	ga := "62e90394-69f5-4237-9190-012177145e10"
	e := newPortalEnv(t, config.MicrosoftLoginConfig{AllowedDirectoryRoles: []string{ga}})
	resp, _ := e.signIn(t, map[string]any{"wids": []string{ga}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
}

func TestMicrosoftLoginNonAdminDenied(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})
	resp, _ := e.signIn(t, map[string]any{"roles": []string{"Relay.Reader"}})
	page := body(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, "is not allowed to manage this relay") {
		t.Fatalf("want denial page, got %d", resp.StatusCode)
	}
	if code, _ := e.get(t, "/hosts"); code != http.StatusSeeOther {
		t.Errorf("non-admin reached /hosts: %d", code)
	}
}

func TestMicrosoftLoginForeignTenantDenied(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})
	resp, _ := e.signIn(t, map[string]any{"roles": []string{"Relay.Admin"}, "tid": "99999999-0000-0000-0000-000000000000"})
	if page := body(resp); !strings.Contains(page, "Microsoft sign-in failed") {
		t.Fatal("token from another tenant was accepted")
	}
}

func TestMicrosoftLoginStateReplayDenied(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})
	resp, state := e.signIn(t, map[string]any{"roles": []string{"Relay.Admin"}})
	resp.Body.Close()
	// Same state again (cookie re-added by an attacker) must not log in a second time.
	u, _ := url.Parse(e.url)
	e.client.Jar.SetCookies(u, []*http.Cookie{{Name: oidcCookie, Value: state, Path: "/auth/"}})
	e.client.Jar.SetCookies(u, []*http.Cookie{{Name: cookieName, Value: "", Path: "/", MaxAge: -1}})
	resp, err := e.client.Get(e.url + "/auth/callback?code=good-code&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatal(err)
	}
	if page := body(resp); resp.StatusCode == http.StatusSeeOther || !strings.Contains(page, "sign-in failed") {
		t.Fatalf("replayed state accepted: %d", resp.StatusCode)
	}
}

func TestMicrosoftLoginStateMismatchDenied(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})
	resp, err := e.client.Get(e.url + "/auth/callback?code=good-code&state=forged")
	if err != nil {
		t.Fatal(err)
	}
	if page := body(resp); resp.StatusCode == http.StatusSeeOther || !strings.Contains(page, "sign-in failed") {
		t.Fatalf("forged state accepted: %d", resp.StatusCode)
	}
}
