# Architecture and code walkthrough

This document explains how Graph Relay works, package by package, and why it is built the way it is.
For installation see [setup.md](setup.md).

## Overview

```
 SMTP client ──25/465/587──▶ relay (go-smtp) ──HTTPS──▶ Microsoft Graph ──▶ Exchange Online
 (printer, app)              │  host rules, auth,          /users/{mailbox}/sendMail
                             │  header rewrite             or draft + upload session
                             │
 admin browser ──8443──▶ portal (net/http)
                             │
                        SQLite (hosts, settings, message log)
                             │
                        allowlist file ──▶ graphrelay-fw-sync (root) ──▶ nftables sets
```

One process runs three SMTP listeners, the HTTPS portal, a log-pruning loop and, optionally, the firewall
allowlist exporter. All state lives in one SQLite file and a certificate directory under `data_dir`.

## Repository layout

| Path | Purpose |
|---|---|
| `cmd/graphrelay/main.go` | Entry point: flags, wiring, listeners, shutdown |
| `internal/config` | YAML configuration, `${ENV}` expansion, defaults, validation |
| `internal/relay` | SMTP sessions, host matching, SMTP AUTH, MIME rewriting |
| `internal/graph` | Microsoft Graph client: OAuth token cache, small and large send paths |
| `internal/tlsmgr` | Certificates: Let's Encrypt via Cloudflare DNS-01, or self-signed |
| `internal/portal` | HTTPS management UI, Microsoft sign-in (OIDC), CSRF, sessions |
| `internal/store` | SQLite persistence: hosts, settings, message log, migrations |
| `internal/firewall` | Writes the enabled host rules as an IP allowlist file |
| `deploy/` | systemd units, installer, host hardening, firewall sync, deploy script |
| `config.example.yaml` | Annotated configuration template |

## Startup (`cmd/graphrelay/main.go`)

1. Parse flags: `-config`, `-reset-admin-password`, `-version`. `LOG_LEVEL=debug` enables SMTP
   connection-level logging. Logs are structured text (`log/slog`) on stdout.
2. Load and validate the configuration (`config.Load`).
3. Create `data_dir` (mode 0700) and open `relay.db` (`store.Open`, which also runs migrations).
4. With `-reset-admin-password`: set a random local admin password, print it, exit.
5. Create the local admin account on first start (`portal.EnsureAdmin`). If no
   `initial_admin_password` is configured, a random one is printed once to the log.
6. Set up TLS (`tlsmgr.Setup`). In ACME mode this blocks until a certificate exists, because the SMTPS
   and portal listeners need it.
7. Create the Graph client and check the credentials in the background (logs
   "Microsoft Graph authentication OK" or the error).
8. Create the relay with its host matcher; if `firewall.allowlist_file` is set, start the allowlist exporter.
9. Start the SMTP listeners (`:25` plain with STARTTLS offered, `:465` implicit TLS, `:587` with STARTTLS
   required when `require_tls_on_submission` is true) and the portal.
10. Start the log-pruning loop (every 6 hours, deletes log rows older than `log_retention_days`).
11. Wait for SIGINT/SIGTERM or a listener failure, then shut everything down with a 30 s grace period.

## Configuration (`internal/config`)

`config.Load` reads the YAML file, replaces `${VAR}` references with environment variables
(`os.ExpandEnv`), unmarshals over built-in defaults, and validates:

- `hostname` is required.
- `tls.mode` is `acme` (needs `cloudflare_api_token` and `acme_email`) or `selfsigned`.
- `graph.tenant_id`, `client_id` and `client_secret` are required; the tenant must be a GUID when Microsoft
  sign-in is enabled.
- `smtp.max_message_bytes` may not exceed 150 MB (the Graph limit).
- Microsoft sign-in needs at least one required app role or directory role, otherwise every user of the
  tenant could sign in.
- At least one portal sign-in method must remain enabled.

`portal.allow_local_login` is a `*bool`: unset (or an empty `${VAR}`) means "on only if Microsoft sign-in is
off". This lets the break-glass switch live in the environment file (`allow_local_login:
${GRAPHRELAY_ALLOW_LOCAL_LOGIN}`) while defaulting to off.

## SMTP side (`internal/relay`)

The SMTP protocol is handled by `github.com/emersion/go-smtp`. `Relay.Backend(port, requireTLS)` returns a
backend per listener; every connection gets a `session` that knows the client IP and the listener.

### Host matching (`hosts.go`)

At `MAIL FROM` the client IP is matched against all **enabled** host rules. A rule's `match` is one of:

| Kind | Example | Specificity score |
|---|---|---|
| Exact IP (v4 or v6) | `192.0.2.10` | 1000 |
| DNS name (resolved, cached 2 minutes) | `scanner.example.com` | 999 |
| CIDR | `198.51.100.0/24` | prefix length (24) |

The highest score wins, so a specific rule overrides a broader network rule. IPv4-mapped IPv6 addresses are
unmapped before comparison. If DNS fails, the last good answer is reused. `ValidateMatch` normalises input
from the portal (lower-case names, masked prefixes).

### Session checks, in order

1. **TLS on submission:** on 587 with `require_tls_on_submission`, `MAIL FROM` before STARTTLS → `530`.
2. **Host rule:** no enabled rule matches → `554 5.7.1 Relay access denied` (logged as `rejected`).
3. **Allowed sender:** the rule's mailbox is not on the allowed sender list → `554 5.7.1` (logged).
4. **SMTP login:** the rule has a login but the client did not authenticate for this rule → `530 5.7.0
   Authentication required` (logged).
5. `RCPT TO` addresses are syntax-checked (`553` if invalid); `max_recipients` is enforced by go-smtp.
6. `DATA` is read into memory (`max_message_bytes` is enforced and advertised as `SIZE`), then delivered.

Authentication state survives `RSET`, so a logged-in client can send several messages per connection.

### Optional SMTP login (`auth.go`)

A host rule may carry `smtp_user` and a bcrypt `smtp_pass_hash`.

- `AuthMechanisms()` is called for EHLO. It returns `PLAIN` and `LOGIN` only if the client's matching rule has
  a login, so devices behind IP-only rules never see AUTH. go-smtp additionally offers AUTH only on TLS
  connections (`AllowInsecureAuth` is false), so credentials never cross the network in clear text.
- `PLAIN` uses go-sasl's server. `LOGIN` (the non-standard mechanism many printers use) is implemented in
  `loginServer`, because go-sasl only ships a LOGIN client.
- `checkLogin` compares the username in constant time and the password with bcrypt, against the rule that
  matches the client IP. A successful login remembers the rule ID; `MAIL FROM` requires that it matches.
- `failLimiter` counts failures per client IP: 5 failures within 15 minutes lock the IP out (`454`), even for
  correct credentials. A success resets the counter. Failed logins are written to the message log.

### Header rewriting (`mime.go`, `prepare`)

Only headers are rewritten; the body bytes are passed through unchanged.

- **From:** if the rule has `rewrite_from` on, `From` becomes the rule's mailbox, keeping the original display
  name, and any `Sender` header is removed. Without it, Graph only accepts the message if the mailbox has
  *Send As* rights for the original address.
- **Envelope recipients:** Graph delivers to the header recipients, not to the SMTP envelope. Every `RCPT TO`
  address missing from To/Cc/Bcc is therefore added as `Bcc`.

Implementation note: `mail.Header{Header: message.Header{Header: th}}` copies the textproto struct, so new
fields must be written through `h.Header.Header`, never through the original `th`.

### Delivery and SMTP replies

- Messages up to `graph.MaxMIMEBytes` (about 2.9 MB) go to `SendMIME`: the raw MIME, base64-encoded, to
  `POST /users/{mailbox}/sendMail` (Graph limits that request to 4 MB).
- Larger messages are decomposed by `toGraphMessage` (subject, addresses, importance from
  `Importance`/`X-Priority`, the first HTML or plain-text body, every other part as an attachment with
  filename, content type and Content-ID for inline images) and sent with `SendLarge`.
- The reply depends on the Graph result: success → `250`; HTTP 429, 5xx or network error → `451` (the client
  retries later); any other error → `554` with Graph's error text (truncated to 200 characters).
- Every attempt is written to the message log with its status (`sent`, `failed`, `rejected`).

There is deliberately **no queue**: the client is told the truth synchronously, and nothing is written to
disk, so a crash cannot lose accepted mail. Devices retry `451` by themselves.

## Microsoft Graph client (`internal/graph`)

- **Authentication:** OAuth 2.0 client credentials against
  `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, scope `https://graph.microsoft.com/.default`.
  The access token is cached until 2 minutes before expiry.
- **Requests (`do`):** retries up to 4 times on 429/503 (honouring `Retry-After`, max 30 s) and on 401 (after
  dropping the cached token). Errors become `*graph.Error{Status, Code, Message}`; `Temporary(err)` decides
  between `451` and `554`.
- **Small path:** `SendMIME`.
- **Large path (`SendLarge`):** create a draft (`POST /users/{mailbox}/messages`); attachments up to 2.5 MB
  are posted directly, bigger ones through an upload session in 3.2 MB chunks (a multiple of 320 KiB, as Graph
  requires; the pre-authorised upload URL must not receive a bearer token); then
  `POST /messages/{id}/send`. If any step fails, the draft is deleted.
- **Permissions needed:** `Mail.Send` (all messages) and `Mail.ReadWrite` (drafts for messages over ~3 MB),
  both as application permissions. [setup.md](setup.md) shows how to scope them to specific mailboxes.
- `graph.SetEndpoints` lets tests point the client at a fake server.

## TLS certificates (`internal/tlsmgr`)

- **`acme` mode:** `certmagic` obtains a Let's Encrypt certificate (production or staging CA) for `hostname`
  plus `extra_domains` using the **DNS-01** challenge through the Cloudflare API (`libdns/cloudflare`). No
  inbound port 80/443 is needed. Certificates, keys and the ACME account are stored under
  `data_dir/certs` and renewed automatically in the background. `DefaultServerName` is set because many SMTP
  clients don't send SNI.
- **Propagation check:** before asking Let's Encrypt to validate, certmagic checks that the TXT record is
  visible on the zone's authoritative nameservers. On networks that redirect all outbound DNS to an internal
  resolver (split-horizon), that check can never succeed; `skip_dns_propagation_check: true` replaces it with a
  fixed wait (`dns_propagation_delay`, default 60 s).
- **`selfsigned` mode:** an in-memory ECDSA P-256 certificate valid for one year, for testing.
- The same `tls.Config` (TLS 1.2+) serves STARTTLS, port 465 and the portal.
- **Chain for download (`chain.go`):** `Manager.Chain` returns the served chain and completes it up to the
  self-signed root by following each top certificate's *CA Issuers* URL (Authority Information Access). Servers
  don't send the root, and a Let's Encrypt chain ends in a cross-signed certificate, yet devices want the root
  as their trust anchor. A fetched certificate is accepted only if it verifiably signed the one below it. The
  result is cached for a day. The portal offers each certificate as PEM or DER and all CA certificates as one
  bundle; the private key is never exposed.

## Management portal (`internal/portal`)

Plain `net/http` with `html/template`; templates and static files are embedded (`go:embed`), so the binary
needs no extra files.

### Pages

| Page | Function |
|---|---|
| Dashboard | Counters for the last 24 h (sent, failed, rejected), recent messages, certificate status |
| Hosts | List, add, edit, enable/disable, delete rules; "Which rule applies?" checker for an IP |
| Host form | Name, address, sender mailbox (dropdown from the allowed list), optional SMTP login with a password generator, Rewrite From, enabled, note |
| Log | Message log with status filter, search and paging (100 per page) |
| Test | Sends a test message straight through Graph from an allowed mailbox |
| Settings | Allowed sender mailboxes, TLS certificate chain with downloads (PEM, DER, CA bundle), effective configuration (secrets masked), local password change |

### Security model

- **Network filter:** `portal.allowed_cidrs` restricts which client IPs reach the portal at all.
- **Microsoft sign-in (`oidc.go`):** OpenID Connect authorization code flow with PKCE (`go-oidc`, `oauth2`).
  The ID token's signature, issuer, audience, expiry and nonce are verified, the `tid` claim must equal the
  configured tenant, the `state` is one-time and expires, and the user must hold an app role from
  `required_roles` (claim `roles`) or a directory role from `allowed_directory_roles` (claim `wids`).
  Denials are logged with the user's UPN and the roles found.
- **Local login:** only when allowed by configuration. The password is a bcrypt hash; 8 failures per IP cause
  a 15-minute lockout. When local login is off, its routes are not even registered.
- **Sessions:** random 32-byte IDs, in memory only (a restart signs everyone out), 12 h sliding expiry,
  cookie `HttpOnly`, `Secure`, `SameSite=Lax`. Lax is required because a Strict cookie is dropped on the
  redirect back from login.microsoftonline.com.
- **CSRF:** every POST must carry the session's CSRF token (compared in constant time).
- **Headers:** a Content-Security-Policy without inline scripts (`static/app.js` provides delete confirmations
  and the password generator), `nosniff`, `no-referrer`, HSTS and `no-store`.
- **Server-side validation:** the sender mailbox must be on the allowed list (also for hand-crafted
  requests), host addresses are normalised, SMTP usernames are restricted to `[A-Za-z0-9._@+-]`, SMTP
  passwords need at least 12 characters and are never rendered back into a page.

## Storage (`internal/store`)

SQLite through `modernc.org/sqlite` (pure Go, no CGO), WAL mode, one connection, file `data_dir/relay.db`.

| Table | Content |
|---|---|
| `hosts` | `name`, `match`, `sender`, `rewrite_from`, `enabled`, `note`, `created_at`, `smtp_user`, `smtp_pass_hash` |
| `settings` | Key/value: `allowed_senders` (one address per line), `admin_user`, `admin_password_hash` |
| `message_log` | Time, client IP, port, host rule, sender mailbox, envelope sender, envelope recipients, subject, size, status, error, duration |

- **Message content is never stored.** Bodies and attachments exist only in memory while being delivered.
  Graph keeps a copy in the sending mailbox's Sent Items.
- **Migrations** run on every open: tables are created if missing, columns added later are appended with
  `ALTER TABLE` (`addColumn`), and on first open after an upgrade the allowed sender list is seeded from the
  existing rules' mailboxes so working mail isn't blocked.
- Secrets (Graph client secret, Cloudflare token) are never stored in the database; they come from the
  configuration or environment.

## Firewall integration (`internal/firewall`, `deploy/graphrelay-fw-*`)

Optional, for Linux hosts with nftables. The idea: the SMTP ports are closed to everyone except the hosts
configured in the portal, without giving the network-facing relay any firewall privilege.

1. With `firewall.allowlist_file` set, `firewall.Exporter` writes all **enabled** rules as IP prefixes, one
   per line (single IPs as /32 or /128, CIDRs as is, DNS names resolved). It writes on start, after every host
   change in the portal, and every 2 minutes (so DNS rules follow address changes), but only when the content
   actually changes, via write-to-temp-and-rename.
2. The root-owned systemd path unit `graphrelay-fw.path` watches the file and starts `graphrelay-fw.service`.
3. `graphrelay-fw-sync` treats the file as untrusted: only strict IPv4/IPv6 prefix syntax is accepted, at most
   10,000 entries, and the nftables sets `inet filter smtp4` / `smtp6` are replaced in a single `nft -f`
   transaction. If nft rejects anything, the previous contents stay. A missing file empties the sets (closed).
4. The nftables ruleset (from `deploy/harden-host.sh`) accepts 25/465/587 only from `@smtp4` / `@smtp6`.
   The sync service is `PartOf=nftables.service`, so reloading the firewall refills the sets.

The relay itself runs as an unprivileged user with only `CAP_NET_BIND_SERVICE`.

## Deployment files (`deploy/`)

| File | Purpose |
|---|---|
| `graphrelay.service` | systemd unit: user `graphrelay`, `CAP_NET_BIND_SERVICE` only, `ProtectSystem=strict`, writes only to `/opt/graphrelay`, secrets from `/etc/graphrelay.env`, restart after 30 s |
| `graphrelay.env.example` | Template for `/etc/graphrelay.env` (mode 0600) |
| `install.sh` | Creates the user and directories, installs binary and units; never overwrites an existing config or env file; starts the service only when the env file is filled |
| `push.sh` | From a workstation: builds the Linux binary and ships it together with all current deploy files, then runs `install.sh` |
| `harden-host.sh` | Debian host hardening: updates, unattended-upgrades, key-only SSH, nftables default-drop with a 120 s automatic rollback |
| `graphrelay-fw-sync`, `graphrelay-fw.path`, `graphrelay-fw.service` | Firewall allowlist sync (see above) |

## Tests

`go test ./...` covers, among others:

- SMTP end-to-end against a fake Graph server: From rewriting, Bcc for envelope recipients, unknown hosts,
  permanent errors, the large-message draft and upload-session path, allowed-sender enforcement.
- SMTP AUTH: login required, PLAIN and LOGIN, wrong password and lockout, no AUTH without TLS, IP-only rules
  unchanged.
- Portal against a fake Entra ID (OIDC provider): role checks, foreign tenants, state replay, CSRF-protected
  forms, the allowed-sender dropdowns, SMTP login fields (validation, hashing, keep-on-edit, removal).
- Store migrations from an older schema, configuration from environment variables, the allowlist exporter.
