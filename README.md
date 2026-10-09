# Graph Relay

An SMTP relay written in Go that delivers mail through **Microsoft Graph** (`/users/{mailbox}/sendMail`)
instead of SMTP AUTH. It is meant for printers, scanners, backup jobs, line-of-business applications and
anything else that can only send email over SMTP, in a Microsoft 365 tenant where basic SMTP authentication
is disabled or unwanted.

- **SMTP listeners** on 25 (STARTTLS offered), 465 (implicit TLS) and 587 (submission, STARTTLS required).
- **Host rules**: only clients matching an enabled rule (IP, CIDR or DNS name) may relay. Each rule sends as
  one Microsoft 365 mailbox, optionally rewriting the From header, and can optionally require an SMTP login.
- **Allowed sender mailboxes**: an admin-managed list of the only mailboxes rules may send as.
- **Messages up to 150 MB**: small ones as raw MIME, large ones as a Graph draft with upload sessions.
- **Synchronous delivery, no queue**: the client gets `250` only after Graph accepted the message.
- **TLS certificates** from Let's Encrypt via the Cloudflare DNS-01 challenge, renewed automatically.
- **HTTPS management portal**: hosts, allowed mailboxes, message log, test send, settings; sign-in with
  Microsoft (Entra ID app role) and an optional break-glass local account.
- **Firewall integration** (optional, Linux/nftables): the SMTP ports open only for the hosts in the portal.
- A single static binary (no CGO); SQLite storage is embedded.

## Documentation

| Document | Content |
|---|---|
| [docs/architecture.md](docs/architecture.md) | How the code works: packages, message flow, security model, data stored |
| [docs/setup.md](docs/setup.md) | Step-by-step setup: Entra ID, Exchange Online, Cloudflare, server, first start, operation |
| [config.example.yaml](config.example.yaml) | Every configuration option with comments |

## Quick start (local test, no Microsoft or Cloudflare account)

```bash
cp config.example.yaml config.yaml
# in config.yaml: tls.mode: selfsigned, ports 2525/4465/5587, portal 8443,
#                 portal.microsoft_login.enabled: false, any dummy graph.* values
go run ./cmd/graphrelay -config config.yaml
```

The portal is then at `https://localhost:8443` (self-signed certificate). The first start prints a generated
admin password. Sending fails at the Graph step with a clear error, which is expected without a real tenant.

## Build and test

```bash
go test ./...
go vet ./... && gofmt -l .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o graphrelay ./cmd/graphrelay
```

A `Dockerfile` is included as well.
