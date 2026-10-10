package firewall

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Blocked is a source address whose connection attempts to the SMTP ports were dropped by the
// host firewall, because no enabled host rule allows it.
type Blocked struct {
	IP       netip.Addr
	Packets  int64     // dropped connection attempts (SYN packets, so retries count too)
	LastSeen time.Time // approximate: derived from the set element's remaining lifetime
}

// nftSet is the part of `nft -j list set` output we read.
type nftSet struct {
	Nftables []struct {
		Set *struct {
			Timeout int64             `json:"timeout"`
			Elem    []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

type nftElem struct {
	Elem *struct {
		Val     string `json:"val"`
		Expires int64  `json:"expires"`
		Counter *struct {
			Packets int64 `json:"packets"`
		} `json:"counter"`
	} `json:"elem"`
}

// ReadBlocked reads the files written by deploy/graphrelay-fw-report in dir, most recent first.
// Missing files give an empty result: the firewall integration is optional.
func ReadBlocked(dir string) []Blocked {
	var out []Blocked
	for _, name := range []string{"smtp_blocked4.json", "smtp_blocked6.json"} {
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil || st.Size() > 8<<20 {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var doc nftSet
		if json.Unmarshal(raw, &doc) != nil {
			continue
		}
		for _, obj := range doc.Nftables {
			if obj.Set == nil {
				continue
			}
			for _, rawElem := range obj.Set.Elem {
				var e nftElem
				if json.Unmarshal(rawElem, &e) != nil || e.Elem == nil {
					continue // plain values carry no counter; nothing to show
				}
				ip, err := netip.ParseAddr(e.Elem.Val)
				if err != nil {
					continue
				}
				b := Blocked{IP: ip.Unmap(), LastSeen: st.ModTime()}
				if e.Elem.Counter != nil {
					b.Packets = e.Elem.Counter.Packets
				}
				// Each dropped packet resets the element's timeout, so the time already
				// elapsed since then is (timeout - expires).
				if obj.Set.Timeout > 0 && e.Elem.Expires > 0 && e.Elem.Expires <= obj.Set.Timeout {
					b.LastSeen = st.ModTime().Add(-time.Duration(obj.Set.Timeout-e.Elem.Expires) * time.Second)
				}
				out = append(out, b)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
