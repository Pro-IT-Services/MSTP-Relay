#!/bin/bash
# Build Graph Relay and deploy it to a host, from a workstation (Git Bash, Linux or macOS).
#   CONFIG=path/to/config.yaml deploy/push.sh root@relay.example.com
# CONFIG is copied to the host only if it has no /opt/graphrelay/config.yaml yet.
# It always ships the complete, current deploy/ files from the repo, so a unit file patched by
# hand on the host can't be silently reverted by an older staged copy. install.sh keeps the
# host's existing config.yaml and /etc/graphrelay.env.
set -euo pipefail
HOST=${1:?usage: CONFIG=path/to/config.yaml deploy/push.sh user@host}
CONFIG=${CONFIG:-config.yaml}
[ -f "$CONFIG" ] || { echo "config file $CONFIG not found (set CONFIG=...)" >&2; exit 1; }
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
VERSION=$(git describe --always --dirty)
echo "== build $VERSION"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$VERSION" -o "$TMP/graphrelay" ./cmd/graphrelay
cp deploy/install.sh deploy/graphrelay.service deploy/graphrelay.env.example \
   deploy/graphrelay-fw-sync deploy/graphrelay-fw.service deploy/graphrelay-fw.path    deploy/graphrelay-fw-report deploy/graphrelay-fw-report.service deploy/graphrelay-fw-report.timer "$TMP/"
cp "$CONFIG" "$TMP/config.yaml"

echo "== upload to $HOST"
ssh "$HOST" 'rm -rf /root/graphrelay-deploy && mkdir -m 700 /root/graphrelay-deploy'
scp -q "$TMP"/* "$HOST":/root/graphrelay-deploy/

echo "== install"
ssh "$HOST" 'bash /root/graphrelay-deploy/install.sh \
  && echo "version: $(/opt/graphrelay/graphrelay -version)" \
  && systemctl is-active graphrelay graphrelay-fw.path \
  && nft list set inet filter smtp4 | grep -E "elements" || echo "smtp4: (no entries)"'
