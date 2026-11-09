#!/usr/bin/env bash
# cm5-discovery-check — discovery D2 on metal: the bench Pi re-announces itself over mDNS (avahi restart) and
# heqk must learn its name passively (served in /api/devices as mdns_name).
#   tools/diagnostics/cm5-discovery-check.sh <owner-key-file> [pi-ssh-target] [mc-url]
# The Pi's sudo password, if needed for the avahi restart, is read from PI_SUDO_FILE (a 0600 file) — never
# passed on the command line or stored in the repo. Without it the check relies on the Pi's periodic announcements.
set -u -o pipefail
KEY="${1:?owner key file}"
PI="${2:-claude@10.200.0.4}"
MC="${3:-https://192.168.200.146}"
if [ -n "${PI_SUDO_FILE:-}" ]; then
  ssh -o BatchMode=yes "$PI" 'sudo -S -p "" systemctl restart avahi-daemon' < "$PI_SUDO_FILE" >/dev/null 2>&1
else
  ssh -o BatchMode=yes "$PI" 'sudo -n systemctl restart avahi-daemon' >/dev/null 2>&1 || true
fi
sleep 8
J=$(mktemp); trap 'rm -f "$J"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
D=$(curl -sk -m 10 -b "$J" "$MC/api/devices?limit=50")
python3 -c '
import json,sys
d=json.loads(sys.argv[1]).get("devices",[])
ok=False
for x in d:
    print("  ", x.get("ip"), x.get("hostname"), "| mdns:", x.get("mdns_name"), x.get("mdns_model"), "svc", x.get("services"), "|", x.get("model"), x.get("category"), x.get("id_source"), x.get("identity_basis"))
    ok |= bool(x.get("mdns_name"))
print("D2-DISCOVERY:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)' "$D"
