package config

import (
	"os"
	"path/filepath"
	"testing"
)

// allow_local_login can come from the environment. Unset or empty must fall back to the
// default (off while Microsoft login is enabled), so the break-glass login is opt-in.
func TestAllowLocalLoginFromEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yml := `hostname: relay.example.com
tls: {mode: selfsigned}
graph: {tenant_id: 00000000-0000-0000-0000-000000000001, client_id: c, client_secret: s}
portal:
  microsoft_login: {enabled: true, required_roles: [Relay.Admin]}
  allow_local_login: ${TEST_ALLOW_LOCAL_LOGIN}
`
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		env  string
		want bool
	}{{"", false}, {"false", false}, {"true", true}} {
		t.Setenv("TEST_ALLOW_LOCAL_LOGIN", tc.env)
		c, err := Load(path)
		if err != nil {
			t.Fatalf("env %q: %v", tc.env, err)
		}
		if got := c.Portal.LocalLoginAllowed(); got != tc.want {
			t.Errorf("env %q: LocalLoginAllowed = %v, want %v", tc.env, got, tc.want)
		}
	}
}
