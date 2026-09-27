#!/bin/sh
# Install a built nknguard binary and its systemd unit.
#   make build && sudo ./scripts/install.sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
BIN=${BIN:-bin/nknguard}
[ -x "$BIN" ] || { echo "$BIN not found — run 'make build' first" >&2; exit 1; }
command -v wg >/dev/null 2>&1 || echo "warning: 'wg' not found — install wireguard-tools" >&2
install -m 0755 "$BIN" /usr/local/bin/nknguard
install -d -m 0755 /etc/nknguard
install -d -m 0700 /var/lib/nknguard
install -m 0644 deploy/systemd/nknguard.service /etc/systemd/system/nknguard.service
systemctl daemon-reload
echo "Installed. Next:"
echo "  sudo nknguard init --name nas-home"
echo "  systemctl enable --now nknguard"
echo "  Open http://127.0.0.1:7878/ on the NAS to pair and approve devices."
