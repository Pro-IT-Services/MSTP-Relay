package portal

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"graphrelay/internal/config"
)

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// post submits a form with the CSRF token taken from page, like a browser would.
func (e *portalEnv) post(t *testing.T, page, path string, form url.Values) (int, string) {
	t.Helper()
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no CSRF token on page for %s", path)
	}
	form.Set("csrf", m[1])
	resp, err := e.client.PostForm(e.url+path, form)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body(resp)
}

func TestAllowedSendersDropdownAndValidation(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})
	resp, _ := e.signIn(t, map[string]any{"roles": []string{"Relay.Admin"}})
	resp.Body.Close()

	// No mailboxes yet: the host form says so and offers nothing to pick.
	_, page := e.get(t, "/hosts/new")
	if !strings.Contains(page, "No mailboxes are allowed yet") || strings.Contains(page, `<option value="reports@contoso.com"`) {
		t.Fatalf("empty list not shown on host form")
	}

	// Invalid entries are refused and nothing is saved.
	_, settings := e.get(t, "/settings")
	code, page := e.post(t, settings, "/settings/senders", url.Values{"senders": {"reports@contoso.com\nnot an address"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(page, "Not a plain email address") {
		t.Fatalf("bad list accepted: %d", code)
	}
	if list, _ := e.store.AllowedSenders(); len(list) != 0 {
		t.Fatalf("list saved despite error: %v", list)
	}

	// Valid list is normalised.
	code, _ = e.post(t, settings, "/settings/senders", url.Values{"senders": {"Reports@Contoso.com\r\nnotify@contoso.com\n\n"}})
	if code != http.StatusSeeOther {
		t.Fatalf("save list = %d", code)
	}
	if list, _ := e.store.AllowedSenders(); !slices.Equal(list, []string{"notify@contoso.com", "reports@contoso.com"}) {
		t.Fatalf("list = %v", list)
	}

	// The host form now offers a dropdown with exactly those mailboxes.
	_, form := e.get(t, "/hosts/new")
	if !strings.Contains(form, `<select name="sender"`) || !strings.Contains(form, `<option value="reports@contoso.com"`) {
		t.Fatalf("dropdown missing on host form")
	}

	// A hand-crafted request with another mailbox is refused.
	host := url.Values{"name": {"backup-server"}, "match": {"192.0.2.10"}, "enabled": {"on"}, "rewrite_from": {"on"}}
	host.Set("sender", "ceo@contoso.com")
	code, page = e.post(t, form, "/hosts/save", host)
	if code != http.StatusUnprocessableEntity || !strings.Contains(page, "Choose a sender mailbox from the list") {
		t.Fatalf("unlisted sender accepted: %d", code)
	}
	host.Set("sender", "reports@contoso.com")
	if code, _ = e.post(t, form, "/hosts/save", host); code != http.StatusSeeOther {
		t.Fatalf("save host = %d", code)
	}

	// Removing the mailbox from the list flags the host everywhere.
	_, settings = e.get(t, "/settings")
	e.post(t, settings, "/settings/senders", url.Values{"senders": {"notify@contoso.com"}})
	_, settings = e.get(t, "/settings")
	if !strings.Contains(settings, "backup-server") || !strings.Contains(settings, "their mail is rejected") {
		t.Errorf("settings page doesn't warn about the host")
	}
	_, hosts := e.get(t, "/hosts")
	if !strings.Contains(hosts, "not allowed") {
		t.Errorf("hosts list doesn't flag the host")
	}

	// The test page only sends from listed mailboxes.
	_, testPage := e.get(t, "/test")
	if !strings.Contains(testPage, `<select name="mailbox"`) {
		t.Fatalf("test page has no dropdown")
	}
	code, page = e.post(t, testPage, "/test", url.Values{"mailbox": {"reports@contoso.com"}, "to": {"x@example.com"}, "subject": {"s"}})
	if !strings.Contains(page, "Choose a sender mailbox from the list") {
		t.Errorf("test send from unlisted mailbox not refused: %d", code)
	}
}
