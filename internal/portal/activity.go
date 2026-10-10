package portal

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"graphrelay/internal/firewall"
	"graphrelay/internal/store"
)

// The Activity page shows every connection that reached the relay (delivered, idle or failed)
// and, with the firewall integration, the sources the firewall dropped before they got that far.
// The page is rendered by static/activity.js from the JSON served at /activity/data.

// activityRanges maps the range selector to its duration and chart bucket size in hours.
var activityRanges = map[string]struct {
	dur   time.Duration
	step  int
	label string
}{
	"1h":  {time.Hour, 1, "last hour"},
	"24h": {24 * time.Hour, 1, "last 24 hours"},
	"7d":  {7 * 24 * time.Hour, 6, "last 7 days"},
	"30d": {30 * 24 * time.Hour, 24, "last 30 days"},
}

type activityData struct {
	Generated int64            `json:"generated"`
	Range     string           `json:"range"`
	Label     string           `json:"label"`
	StepHours int              `json:"stepHours"`
	Stats     activityStats    `json:"stats"`
	Buckets   []activityBucket `json:"buckets"`
	Devices   []activityDevice `json:"devices"`
	Conns     []activityConn   `json:"conns"`
	Blocked   []activityBlock  `json:"blocked"`
	Firewall  bool             `json:"firewall"` // block counting is configured
}

type activityStats struct {
	Connections int `json:"connections"`
	Devices     int `json:"devices"`
	Delivered   int `json:"delivered"`
	Problems    int `json:"problems"`
	Blocked     int `json:"blocked"` // distinct sources dropped by the firewall
}

type activityBucket struct {
	Start    int64 `json:"start"`
	OK       int   `json:"ok"`
	Problems int   `json:"problems"`
}

type activityDevice struct {
	IP          string `json:"ip"`
	Host        string `json:"host"`
	Helo        string `json:"helo"`
	Connections int    `json:"connections"`
	Sent        int    `json:"sent"`
	Problems    int    `json:"problems"`
	LastSeen    int64  `json:"lastSeen"`
	LastOutcome string `json:"lastOutcome"`
	LastDetail  string `json:"lastDetail"`
	LastTLS     string `json:"lastTLS"`
}

type activityConn struct {
	Time     int64  `json:"time"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Helo     string `json:"helo"`
	TLS      string `json:"tls"`
	CertKey  string `json:"certKey"`
	AuthUser string `json:"authUser"`
	AuthOK   bool   `json:"authOK"`
	Sent     int    `json:"sent"`
	Outcome  string `json:"outcome"`
	Detail   string `json:"detail"`
	Millis   int64  `json:"millis"`
}

type activityBlock struct {
	IP       string `json:"ip"`
	Packets  int64  `json:"packets"`
	LastSeen int64  `json:"lastSeen"`
	Host     string `json:"host"` // set when a host rule allows this address by now
}

func (p *Portal) activityPage(w http.ResponseWriter, r *http.Request) {
	p.render(w, r, "activity", "Activity", nil)
}

func (p *Portal) activityJSON(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key := q.Get("range")
	rng, ok := activityRanges[key]
	if !ok {
		key, rng = "24h", activityRanges["24h"]
	}
	now := time.Now()
	since := now.Add(-rng.dur)
	d := activityData{Generated: now.Unix(), Range: key, Label: rng.label, StepHours: rng.step,
		Firewall: p.Cfg.Firewall.BlockedDir != "",
		// Non-nil so the JSON has [] instead of null.
		Buckets: []activityBucket{}, Devices: []activityDevice{}, Conns: []activityConn{}, Blocked: []activityBlock{}}

	st, err := p.Store.ConnStats(since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.Stats = activityStats{Connections: st.Connections, Devices: st.Devices, Delivered: st.Delivered, Problems: st.Problems}

	hours, _ := p.Store.ConnHourly(since)
	for i := 0; i < len(hours); i += rng.step {
		b := activityBucket{Start: hours[i].Start.Unix()}
		for _, h := range hours[i:min(i+rng.step, len(hours))] {
			b.OK, b.Problems = b.OK+h.OK, b.Problems+h.Problems
		}
		d.Buckets = append(d.Buckets, b)
	}

	devs, _ := p.Store.ConnDevices(since)
	for _, v := range devs {
		d.Devices = append(d.Devices, activityDevice{IP: v.ClientIP, Host: v.HostName, Helo: v.Helo,
			Connections: v.Connections, Sent: v.Sent, Problems: v.Problems, LastSeen: v.LastSeen.Unix(),
			LastOutcome: v.LastOutcome, LastDetail: v.LastDetail, LastTLS: v.LastTLS})
	}

	conns, _ := p.Store.ListConns(store.ConnFilter{Kind: q.Get("kind"), Query: q.Get("q"), Since: since, Limit: 300})
	for _, c := range conns {
		d.Conns = append(d.Conns, activityConn{Time: c.Time.Unix(), IP: c.ClientIP, Port: c.Port, Host: c.HostName,
			Helo: c.Helo, TLS: c.TLS, CertKey: c.CertKey, AuthUser: c.AuthUser, AuthOK: c.AuthOK, Sent: c.Sent,
			Outcome: c.Outcome, Detail: c.Detail, Millis: c.DurationMS})
	}

	if d.Firewall {
		for _, b := range firewall.ReadBlocked(p.Cfg.Firewall.BlockedDir) {
			if b.LastSeen.Before(since) {
				continue
			}
			row := activityBlock{IP: b.IP.String(), Packets: b.Packets, LastSeen: b.LastSeen.Unix()}
			if h, err := p.Matcher.Match(r.Context(), netip.Addr(b.IP)); err == nil && h != nil {
				row.Host = h.Name
			}
			d.Blocked = append(d.Blocked, row)
		}
		d.Stats.Blocked = len(d.Blocked)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(d)
}
