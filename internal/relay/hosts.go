package relay

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"graphrelay/internal/store"
)

// Matcher finds the host rule for a client IP. When several rules match,
// the most specific wins: exact IP / DNS name, then the longest CIDR prefix.
type Matcher struct {
	store *store.Store

	mu    sync.Mutex
	cache map[string]dnsEntry
}

type dnsEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

const dnsCacheTTL = 2 * time.Minute

func NewMatcher(s *store.Store) *Matcher {
	return &Matcher{store: s, cache: map[string]dnsEntry{}}
}

func (m *Matcher) Match(ctx context.Context, ip netip.Addr) (*store.Host, error) {
	hosts, err := m.store.ListHosts()
	if err != nil {
		return nil, err
	}
	ip = ip.Unmap()
	var best *store.Host
	bestScore := -1
	for i := range hosts {
		h := &hosts[i]
		if !h.Enabled {
			continue
		}
		if score := m.score(ctx, h.Match, ip); score > bestScore {
			best, bestScore = h, score
		}
	}
	return best, nil
}

// score returns -1 for no match, otherwise a specificity value.
func (m *Matcher) score(ctx context.Context, match string, ip netip.Addr) int {
	if a, err := netip.ParseAddr(match); err == nil {
		if a.Unmap() == ip {
			return 1000
		}
		return -1
	}
	if p, err := netip.ParsePrefix(match); err == nil {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p.Addr()))
		if p.Contains(ip) {
			return p.Bits()
		}
		return -1
	}
	for _, a := range m.resolve(ctx, match) {
		if a == ip {
			return 999
		}
	}
	return -1
}

func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

// Resolve returns the cached addresses of a DNS host rule.
func (m *Matcher) Resolve(ctx context.Context, name string) []netip.Addr { return m.resolve(ctx, name) }

func (m *Matcher) resolve(ctx context.Context, name string) []netip.Addr {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	m.mu.Lock()
	e, ok := m.cache[name]
	m.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.addrs
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil && ok {
		return e.addrs // keep serving the last good answer if DNS hiccups
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, a := range ips {
		addrs = append(addrs, a.Unmap())
	}
	m.mu.Lock()
	m.cache[name] = dnsEntry{addrs: addrs, expires: time.Now().Add(dnsCacheTTL)}
	m.mu.Unlock()
	return addrs
}

// ValidateMatch checks the syntax of a host match value and normalises it.
func ValidateMatch(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String(), true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	// DNS name: letters, digits, hyphens and dots.
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for _, r := range label {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return "", false
			}
		}
	}
	return strings.ToLower(s), true
}
