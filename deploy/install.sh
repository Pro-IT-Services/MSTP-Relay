#!/bin/bash
# Install or upgrade Graph Relay on a Debian host. Run as root from a directory holding:
#   graphrelay (linux/amd64 binary), config.yaml, graphrelay.service, graphrelay.env.example,
#   graphrelay-fw-sync, graphrelay-fw.service, graphrelay-fw.path,
#   graphrelay-fw-report, graphrelay-fw-report.service, graphrelay-fw-report.timer
# An existing /opt/graphrelay/config.yaml and /etc/graphrelay.env are never overwritten.
# The service is started only once /etc/graphrelay.env has all values filled in.
set -euo pipefail
cd "$(dirname "$0")"

id graphrelay >/dev/null 2>&1 || useradd --system --home-dir /opt/graphrelay --shell /usr/sbin/nologin graphrelay

install -d -o root -g graphrelay -m 0750 /opt/graphrelay
install -d -o graphrelay -g graphrelay -m 0700 /opt/graphrelay/data
# The binary and config are root-owned, so the service cannot modify them.
install -o root -g root -m 0755 graphrelay /opt/graphrelay/graphrelay.new
mv -f /opt/graphrelay/graphrelay.new /opt/graphrelay/graphrelay
[ -e /opt/graphrelay/config.yaml ] || install -o root -g graphrelay -m 0640 config.yaml /opt/graphrelay/config.yaml
[ -e /etc/graphrelay.env ] || install -o root -g root -m 0600 graphrelay.env.example /etc/graphrelay.env

install -o root -g root -m 0755 graphrelay-fw-sync graphrelay-fw-report /usr/local/sbin/
install -o root -g root -m 0644 graphrelay.service graphrelay-fw.service graphrelay-fw.path   graphrelay-fw-report.service graphrelay-fw-report.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q graphrelay-fw.service graphrelay-fw.path graphrelay-fw-report.timer graphrelay.service
systemctl start graphrelay-fw.path
systemctl start graphrelay-fw.service
systemctl start graphrelay-fw-report.timer
systemctl start graphrelay-fw-report.service

if grep -qE '^[A-Z_]+=\s*$' /etc/graphrelay.env; then
  echo "Installed. /etc/graphrelay.env still has empty values, so graphrelay was not started."
  echo "Fill it in, then: systemctl start graphrelay && journalctl -u graphrelay -f"
else
  systemctl restart graphrelay
  sleep 3
  systemctl --no-pager --lines=15 status graphrelay || true
fi
