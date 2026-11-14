#!/usr/bin/env bash
# One-time, OPERATOR-run setup on the bench Pi (asks for the sudo password once):
#   ssh -t claude@10.200.0.4 'bash ~/pi4-wsensor/bootstrap-sudo.sh'
# 1. installs the sensor into root-owned /opt/pi4-wsensor (from ~/pi4-wsensor) — service NOT started
# 2. grants the `claude` user passwordless sudo for ONLY the sensor's runtime operations:
#    start/stop/restart/status of pi4-wsensor, the root-owned dongle-lock/monitor-test helpers,
#    and reading its journal. Updating /opt still needs the operator (re-run this script) —
#    that keeps the grant short of root-equivalent.
set -euo pipefail
SRC=$(cd "$(dirname "$0")" && pwd)
sudo bash "$SRC/install.sh"
sudo chown -R root:root /opt/pi4-wsensor && sudo chmod -R go-w /opt/pi4-wsensor
TMP=$(mktemp)
cat >"$TMP" <<'EOF'
# pi4-wsensor runtime operations for the bench automation user (see tools/pi4-wsensor/bootstrap-sudo.sh)
Cmnd_Alias WSENSOR = /usr/bin/systemctl start pi4-wsensor, /usr/bin/systemctl stop pi4-wsensor, \
                     /usr/bin/systemctl restart pi4-wsensor, /usr/bin/systemctl enable pi4-wsensor, \
                     /usr/bin/systemctl disable pi4-wsensor, /usr/bin/systemctl status pi4-wsensor, \
                     /opt/pi4-wsensor/dongle-lock.sh, /opt/pi4-wsensor/dongle-lock.sh *, \
                     /opt/pi4-wsensor/m0-monitor-test.sh *, \
                     /usr/bin/journalctl -u pi4-wsensor, /usr/bin/journalctl -u pi4-wsensor *
claude ALL=(root) NOPASSWD: WSENSOR
EOF
sudo visudo -cf "$TMP"
sudo install -m 0440 -o root -g root "$TMP" /etc/sudoers.d/050-pi4-wsensor
rm -f "$TMP"
echo "done: sensor installed (not started); scoped sudo rule /etc/sudoers.d/050-pi4-wsensor"
