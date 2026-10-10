package portal

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"graphrelay/internal/config"
	"graphrelay/internal/store"
)

func TestActivity(t *testing.T) {
	e := newPortalEnv(t, config.MicrosoftLoginConfig{RequiredRoles: []string{"Relay.Admin"}})

	// Not available without a login.
	if resp, _ := e.download(t, "/activity/data"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("data without login = %d", resp.StatusCode)
	}
	resp, _ := e.signIn(t, map[string]any{"roles": []string{"Relay.Admin"}})
	resp.Body.Close()

	// A host rule for one of the blocked addresses, so it is reported as allowed by now.
	if err := e.store.SaveHost(&store.Host{Name: "Scanner", Match: "192.0.2.50", Sender: "scanner@contoso.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, c := range []store.ConnEntry{
		{Time: now.Add(-2 * time.Hour), ClientIP: "192.0.2.10", Port: "587", Helo: "printer", HostName: "Printer", Sent: 2, Outcome: store.ConnOK, TLS: "TLS 1.2 X", CertKey: "RSA"},
		{Time: now.Add(-time.Hour), ClientIP: "192.0.2.10", Port: "587", Helo: `<script>alert(1)</script>`, HostName: "Printer", Outcome: store.ConnTLSFailed, Detail: "TLS handshake failed: no cipher suite in common"},
		{Time: now.Add(-30 * time.Minute), ClientIP: "192.0.2.20", Port: "25", Helo: "probe", Outcome: store.ConnIdle},
		{Time: now.Add(-72 * time.Hour), ClientIP: "192.0.2.30", Port: "25", Outcome: store.ConnRejected, Detail: "three days ago"},
	} {
		if err := e.store.AddConn(&c); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	e.cfg.Firewall.BlockedDir = dir
	blocked := `{"nftables": [{"set": {"timeout": 86400, "elem": [
		{"elem": {"val": "192.0.2.50", "expires": 86000, "counter": {"packets": 6}}},
		{"elem": {"val": "198.51.100.77", "expires": 80000, "counter": {"packets": 3}}}]}}]}`
	if err := os.WriteFile(filepath.Join(dir, "smtp_blocked4.json"), []byte(blocked), 0o644); err != nil {
		t.Fatal(err)
	}

	fetch := func(query string) activityData {
		t.Helper()
		resp, body := e.download(t, "/activity/data"+query)
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("%s = %d %s", query, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		var d activityData
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatalf("%s: %v\n%s", query, err, body)
		}
		return d
	}

	d := fetch("")
	if d.Range != "24h" || d.StepHours != 1 || !d.Firewall {
		t.Fatalf("defaults = %+v", d)
	}
	if d.Stats != (activityStats{Connections: 3, Devices: 2, Delivered: 2, Problems: 1, Blocked: 2}) {
		t.Fatalf("stats = %+v", d.Stats)
	}
	if n := len(d.Buckets); n < 24 || n > 26 {
		t.Fatalf("%d buckets", n)
	}
	var ok, problems int
	for _, b := range d.Buckets {
		ok, problems = ok+b.OK, problems+b.Problems
	}
	if ok != 2 || problems != 1 {
		t.Fatalf("bucket totals ok=%d problems=%d", ok, problems)
	}
	if len(d.Devices) != 2 || d.Devices[0].IP != "192.0.2.20" || d.Devices[1].Problems != 1 || d.Devices[1].Sent != 2 {
		t.Fatalf("devices = %+v", d.Devices)
	}
	if len(d.Conns) != 3 || d.Conns[0].Outcome != store.ConnIdle || d.Conns[2].CertKey != "RSA" {
		t.Fatalf("conns = %+v", d.Conns)
	}
	if len(d.Blocked) != 2 || d.Blocked[0].IP != "192.0.2.50" || d.Blocked[0].Host != "Scanner" || d.Blocked[1].Host != "" || d.Blocked[1].Packets != 3 {
		t.Fatalf("blocked = %+v", d.Blocked)
	}

	// Filters and ranges.
	if d := fetch("?kind=problem"); len(d.Conns) != 1 || d.Conns[0].Outcome != store.ConnTLSFailed || d.Stats.Connections != 3 {
		t.Fatalf("problem filter = %+v", d.Conns)
	}
	if d := fetch("?q=192.0.2.20"); len(d.Conns) != 1 {
		t.Fatalf("search = %+v", d.Conns)
	}
	if d := fetch("?range=7d"); d.Stats.Connections != 4 || d.StepHours != 6 || len(d.Buckets) < 28 {
		t.Fatalf("7d = %+v, %d buckets", d.Stats, len(d.Buckets))
	}
	if d := fetch("?range=1h"); d.Stats.Connections != 2 {
		t.Fatalf("1h = %+v", d.Stats)
	}
	if d := fetch("?range=nonsense"); d.Range != "24h" {
		t.Fatalf("bad range = %q", d.Range)
	}

	// The page shell: no device-supplied text is rendered server-side, the script fills it in.
	code, page := e.get(t, "/activity")
	if code != 200 || !strings.Contains(page, `id="act-chart"`) || !strings.Contains(page, `src="/static/activity.js"`) ||
		!strings.Contains(page, `href="/activity" class="active"`) {
		t.Fatalf("activity page = %d", code)
	}
	// "Add a host" next to an address opens the form with that address filled in; junk is ignored.
	if _, form := e.get(t, "/hosts/new?match=198.51.100.77"); !strings.Contains(form, `name="match" value="198.51.100.77"`) {
		t.Error("host form not prefilled from ?match=")
	}
	if _, form := e.get(t, "/hosts/new?match="+url.QueryEscape(`"><script>`)); !strings.Contains(form, `name="match" value=""`) {
		t.Error("invalid ?match= was not ignored")
	}
	if _, js := e.get(t, "/static/activity.js"); !strings.Contains(js, `"/hosts/new?match=" + encodeURIComponent(ip)`) {
		t.Error("activity.js doesn't link to the prefilled host form")
	}
	if code, js := e.get(t, "/static/activity.js"); code != 200 || strings.Contains(js, "innerHTML") {
		t.Fatalf("activity.js = %d; it must not build HTML from data", code)
	}
}
