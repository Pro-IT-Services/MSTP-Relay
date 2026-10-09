#!/bin/bash
# Update and harden the Graph Relay host (Debian 13 LXC).
# Run as root, e.g. from a workstation:  ssh root@relay.example.com 'bash -s' < deploy/harden-host.sh
# Idempotent. The firewall step rolls itself back after 120 s unless you confirm it from a NEW ssh session.
set -euo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l

# Networks allowed to reach SSH and the portal (8443). The SMTP ports (25/465/587) are closed by default
# and opened only for the portal's host rules, via graphrelay-fw-sync and the smtp4/smtp6 sets.
TRUSTED_V4="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"

echo "== 1. Packages"
apt-get update -q
apt-get full-upgrade -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold
apt-get install -y -q unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'C'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
C
apt-get autoremove --purge -y -q
apt-get clean

echo "== 2. SSH (key-only; no account has a password, all logins use keys)"
cat > /etc/ssh/sshd_config.d/10-hardening.conf <<'C'
# Managed by Graph Relay deploy/harden-host.sh
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
C
if ! sshd -t; then
  rm -f /etc/ssh/sshd_config.d/10-hardening.conf
  echo "sshd -t failed, hardening reverted" >&2; exit 1
fi
# This host had both ssh.socket and ssh.service on :22. A reload (SIGHUP re-exec) then dies with
# "Cannot bind any address". Keep only the service; existing sessions survive a restart.
if systemctl is-enabled -q ssh.socket 2>/dev/null; then
  systemctl disable -q --now ssh.socket
fi
systemctl enable -q ssh.service
systemctl restart ssh.service
sleep 2
if ! systemctl is-active -q ssh.service; then
  systemctl enable -q --now ssh.socket
  echo "ssh.service did not come back, ssh.socket re-enabled" >&2; exit 1
fi

echo "== 3. Firewall (nftables, default drop inbound)"
cp -n /etc/nftables.conf /root/nftables.conf.orig 2>/dev/null || true
cat > /etc/nftables.conf.new <<C
#!/usr/sbin/nft -f
# Managed by Graph Relay deploy/harden-host.sh
flush ruleset
table inet filter {
  set trusted4 { type ipv4_addr; flags interval; elements = { $TRUSTED_V4 } }
  # SMTP clients. Empty here; graphrelay-fw-sync fills them from the portal's host rules.
  set smtp4 { type ipv4_addr; flags interval; auto-merge; }
  set smtp6 { type ipv6_addr; flags interval; auto-merge; }
  chain input {
    type filter hook input priority filter; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp accept
    meta l4proto ipv6-icmp accept
    ip saddr @trusted4 tcp dport 22 ct state new limit rate 10/minute burst 20 packets accept
    ip saddr @trusted4 tcp dport 8443 accept
    ip saddr @smtp4 tcp dport { 25, 465, 587 } accept
    ip6 saddr @smtp6 tcp dport { 25, 465, 587 } accept
  }
  chain forward { type filter hook forward priority filter; policy drop; }
  chain output  { type filter hook output priority filter; policy accept; }
}
C
nft -c -f /etc/nftables.conf.new
# Safety net: restore the old (open) ruleset in 120 s unless the timer is cancelled.
systemctl stop nft-rollback.timer 2>/dev/null || true
systemd-run --unit=nft-rollback --on-active=120 /bin/sh -c \
  'cp /root/nftables.conf.orig /etc/nftables.conf && /usr/sbin/nft -f /etc/nftables.conf'
mv /etc/nftables.conf.new /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable -q nftables
# Refill the SMTP sets right away if Graph Relay is installed.
if [ -x /usr/local/sbin/graphrelay-fw-sync ]; then /usr/local/sbin/graphrelay-fw-sync || true; fi

echo
echo "Firewall applied. Within 120 s, open a NEW ssh session and run:"
echo "    systemctl stop nft-rollback.timer"
echo "Otherwise the old open ruleset and /etc/nftables.conf come back by themselves."
