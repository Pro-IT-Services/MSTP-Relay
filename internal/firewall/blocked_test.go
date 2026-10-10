package firewall

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Output of `nft -j list set` (nftables 1.1), shortened.
const nftSample = `{"nftables": [{"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
 {"set": {"family": "inet", "name": "smtp_blocked4", "table": "filter", "type": "ipv4_addr", "size": 4096,
  "flags": ["timeout", "dynamic"], "timeout": 86400, "elem": [
   {"elem": {"val": "192.0.2.7", "expires": 86399, "counter": {"packets": 0, "bytes": 0}}},
   {"elem": {"val": "198.51.100.9", "expires": 82800, "counter": {"packets": 5, "bytes": 300}}},
   "203.0.113.1",
   {"elem": {"val": "not-an-ip", "expires": 10, "counter": {"packets": 1}}}],
  "stmt": [{"counter": null}]}}]}`

func TestReadBlocked(t *testing.T) {
	dir := t.TempDir()
	if got := ReadBlocked(dir); len(got) != 0 {
		t.Fatalf("no files: %v", got)
	}
	path := filepath.Join(dir, "smtp_blocked4.json")
	if err := os.WriteFile(path, []byte(nftSample), 0o644); err != nil {
		t.Fatal(err)
	}
	// An empty set (no "elem") and garbage in the IPv6 file must not break anything.
	os.WriteFile(filepath.Join(dir, "smtp_blocked6.json"), []byte(`{"nftables": [{"set": {"timeout": 86400}}]}`), 0o644)
	written := time.Now()
	os.Chtimes(path, written, written)

	got := ReadBlocked(dir)
	if len(got) != 2 {
		t.Fatalf("entries = %+v", got)
	}
	// Most recently seen first.
	if got[0].IP.String() != "192.0.2.7" || got[0].Packets != 0 || got[1].IP.String() != "198.51.100.9" || got[1].Packets != 5 {
		t.Fatalf("entries = %+v", got)
	}
	// 86400 - 82800 = 3600 s since the last dropped packet.
	if ago := written.Sub(got[1].LastSeen).Round(time.Minute); ago != time.Hour {
		t.Fatalf("last seen %v ago, want 1h", ago)
	}

	os.WriteFile(path, []byte("not json"), 0o644)
	if got := ReadBlocked(dir); len(got) != 0 {
		t.Fatalf("garbage file: %v", got)
	}
}
