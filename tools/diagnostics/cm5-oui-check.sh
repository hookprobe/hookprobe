#!/usr/bin/env bash
# cm5-oui-check — discovery D3 on metal: the signed IEEE OUI pack loaded at boot names the vendor of the bench
# Pi's Wi-Fi adapter (TP-Link USB dongle -> "ieee-oui"; its built-in Wi-Fi stays the curated pinned Raspberry Pi).
#   tools/diagnostics/cm5-oui-check.sh <owner-key-file> [mc-url] [serial-log] [serial-offset]
set -u -o pipefail
KEY="${1:?owner key file}"; MC="${2:-https://192.168.200.146}"; LOG="${3:-}"; OFF="${4:-0}"
ok=1
if [ -n "$LOG" ]; then
  L=$(tail -c +$((OFF + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[OUI\]" | tail -1); echo "  $L"
  grep -q "assignments (operator signature OK)$" <<<"$L" && ! grep -q "skipped" <<<"$L" || ok=0
fi
J=$(mktemp); trap 'rm -f "$J"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
D=$(curl -sk -m 10 -b "$J" "$MC/api/devices?limit=50")
python3 -c '
import json,sys
ok=False
for x in json.loads(sys.argv[1]).get("devices",[]):
    m=(x.get("mac") or "").lower()
    print("  ", x.get("ip"), m, "| vendor:", x.get("vendor"), "| model:", x.get("model"), "| via", x.get("id_source"), x.get("confidence"))
    if m.startswith("a8:29:48"): ok |= x.get("id_source")=="ieee-oui" and (x.get("vendor") or "").startswith("TP-Link")
    if m.startswith("dc:a6:32"): ok |= x.get("id_source")=="pinned-oui" and x.get("model")=="Raspberry Pi"
sys.exit(0 if ok else 1)' "$D" || ok=0
[ "$ok" = 1 ] && { echo "D3-OUI: PASS"; exit 0; } || { echo "D3-OUI: FAIL"; exit 1; }
