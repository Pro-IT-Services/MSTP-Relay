// Package config loads the relay's YAML configuration file.
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Hostname announced in the SMTP greeting and used for the TLS certificate.
	Hostname string `yaml:"hostname"`
	DataDir  string `yaml:"data_dir"`

	SMTP   SMTPConfig   `yaml:"smtp"`
	TLS    TLSConfig    `yaml:"tls"`
	Graph  GraphConfig  `yaml:"graph"`
	Portal PortalConfig `yaml:"portal"`

	Firewall FirewallConfig `yaml:"firewall"`

	// Days to keep the message log. 0 keeps everything.
	LogRetentionDays int `yaml:"log_retention_days"`
}

type SMTPConfig struct {
	// Listen addresses. An empty value disables that listener.
	Plain      string `yaml:"listen_smtp"`       // :25  (STARTTLS optional)
	Submission string `yaml:"listen_submission"` // :587 (STARTTLS)
	SMTPS      string `yaml:"listen_smtps"`      // :465 (implicit TLS)

	// Require STARTTLS before MAIL FROM on the submission port.
	RequireTLSOnSubmission bool `yaml:"require_tls_on_submission"`

	MaxMessageBytes int64         `yaml:"max_message_bytes"`
	MaxRecipients   int           `yaml:"max_recipients"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
}

type TLSConfig struct {
	// "acme" (Let's Encrypt via Cloudflare DNS-01) or "selfsigned" (testing only).
	Mode string `yaml:"mode"`
	// Extra names on the certificate besides Hostname.
	ExtraDomains []string `yaml:"extra_domains"`
	ACMEEmail    string   `yaml:"acme_email"`
	// Use the Let's Encrypt staging CA (for testing; certificates are not trusted).
	ACMEStaging        bool   `yaml:"acme_staging"`
	CloudflareAPIToken string `yaml:"cloudflare_api_token"`
	// Optional DNS resolvers used to check challenge propagation, e.g. ["1.1.1.1:53"].
	Resolvers []string `yaml:"resolvers"`
	// Skip checking that the challenge TXT record is visible on the zone's nameservers. Needed
	// where the network redirects all outbound DNS to an internal (split-horizon) server, which
	// never sees the record. The relay then just waits DNSPropagationDelay (default 60s).
	SkipDNSPropagationCheck bool          `yaml:"skip_dns_propagation_check"`
	DNSPropagationDelay     time.Duration `yaml:"dns_propagation_delay"`
}

type FirewallConfig struct {
	// File that receives the enabled host rules as IP prefixes (DNS names resolved), one per
	// line, for deploy/graphrelay-fw-sync to load into nftables. Empty disables the export.
	AllowlistFile string `yaml:"allowlist_file"`
}

type GraphConfig struct {
	TenantID     string `yaml:"tenant_id"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// Overall timeout for sending one message (large attachments can take a while).
	Timeout time.Duration `yaml:"timeout"`
}

type PortalConfig struct {
	Listen string `yaml:"listen"`
	// Only these client networks may reach the portal. Empty = everyone.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	// Used only when no admin password exists yet in the database.
	InitialAdminPassword string `yaml:"initial_admin_password"`

	MicrosoftLogin MicrosoftLoginConfig `yaml:"microsoft_login"`
	// Allow the local admin/password login. Defaults to true, or false when
	// Microsoft login is enabled (set true to keep a break-glass account).
	AllowLocalLogin *bool `yaml:"allow_local_login"`
}

// MicrosoftLoginConfig enables "Sign in with Microsoft" (Entra ID OpenID Connect)
// for the portal. Only users holding one of the listed roles are let in.
type MicrosoftLoginConfig struct {
	Enabled bool `yaml:"enabled"`
	// App roles (the "roles" claim) that grant access, e.g. ["Relay.Admin"].
	RequiredRoles []string `yaml:"required_roles"`
	// Entra directory role template IDs (the "wids" claim) that grant access,
	// e.g. Global Administrator = 62e90394-69f5-4237-9190-012177145e10.
	AllowedDirectoryRoles []string `yaml:"allowed_directory_roles"`
	// Defaults to the Graph app registration.
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// Defaults to https://<hostname>[:port]/auth/callback. Must be registered as a
	// "Web" redirect URI on the app registration.
	RedirectURL string `yaml:"redirect_url"`
}

// LocalLoginAllowed reports whether username/password login is enabled.
func (p PortalConfig) LocalLoginAllowed() bool {
	if p.AllowLocalLogin != nil {
		return *p.AllowLocalLogin
	}
	return !p.MicrosoftLogin.Enabled
}

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func portSuffix(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "443" && port != "" {
		return ":" + port
	}
	return ""
}

// Load reads the file at path. ${VAR} references are expanded from the environment,
// so secrets can be kept out of the file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{
		DataDir: "./data",
		SMTP: SMTPConfig{
			Plain:                  ":25",
			Submission:             ":587",
			SMTPS:                  ":465",
			RequireTLSOnSubmission: true,
			MaxMessageBytes:        35 << 20,
			MaxRecipients:          100,
			ReadTimeout:            2 * time.Minute,
			WriteTimeout:           2 * time.Minute,
		},
		TLS:              TLSConfig{Mode: "acme"},
		Graph:            GraphConfig{Timeout: 5 * time.Minute},
		Portal:           PortalConfig{Listen: ":8443"},
		LogRetentionDays: 30,
	}
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(raw))), c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	switch c.TLS.Mode {
	case "acme":
		if c.TLS.CloudflareAPIToken == "" {
			return fmt.Errorf("tls.cloudflare_api_token is required for acme mode")
		}
		if c.TLS.ACMEEmail == "" {
			return fmt.Errorf("tls.acme_email is required for acme mode")
		}
	case "selfsigned":
	default:
		return fmt.Errorf("tls.mode must be \"acme\" or \"selfsigned\"")
	}
	if c.Graph.TenantID == "" || c.Graph.ClientID == "" || c.Graph.ClientSecret == "" {
		return fmt.Errorf("graph.tenant_id, graph.client_id and graph.client_secret are required")
	}
	if c.SMTP.MaxMessageBytes > 150<<20 {
		return fmt.Errorf("smtp.max_message_bytes cannot exceed 150 MB (Graph limit)")
	}
	ml := &c.Portal.MicrosoftLogin
	if ml.Enabled {
		if len(ml.RequiredRoles) == 0 && len(ml.AllowedDirectoryRoles) == 0 {
			return fmt.Errorf("portal.microsoft_login needs required_roles and/or allowed_directory_roles, " +
				"otherwise every user in the tenant could sign in")
		}
		if !guidRe.MatchString(c.Graph.TenantID) {
			return fmt.Errorf("graph.tenant_id must be the tenant GUID (Directory ID) when microsoft_login is enabled")
		}
		if ml.ClientID == "" {
			ml.ClientID, ml.ClientSecret = c.Graph.ClientID, c.Graph.ClientSecret
		}
		if ml.RedirectURL == "" {
			ml.RedirectURL = "https://" + c.Hostname + portSuffix(c.Portal.Listen) + "/auth/callback"
		}
	}
	if !c.Portal.LocalLoginAllowed() && !ml.Enabled {
		return fmt.Errorf("portal.allow_local_login is false but microsoft_login is not enabled: nobody could sign in")
	}
	return nil
}
