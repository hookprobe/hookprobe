#!/usr/bin/env bash
# cm5-device-label-check — parity G47 on metal: an owner-set device label (owner-rules kind=device_label) shows in
# /api/devices, an invalid label is refused, the label survives a reboot (owner journal in the DataVolume), and
# removing it clears it. Targets the bench Pi's onboard Wi-Fi (the first leased device on the AP).
#   tools/diagnostics/cm5-device-label-check.sh <owner-key-file> [mc]
set -u -o pipefail
KEY="${1:?owner key file}"; MC="${2:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
"$HERE/pi-ensure-ap.sh" >/dev/null 2>&1 || true
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
J=$(mktemp); trap 'rm -f "$J"' EXIT
login() { curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"; }
sess() { S=$(curl -sk -m 10 -b "$J" "$MC/api/session"); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S"); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S"); }
post() { R=$(curl -sk -m 10 -b "$J" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "$1&seq=$SQ" --data-urlencode "owner_key=$(cat "$KEY")" "$MC/api/owner-rules"); SQ=$((SQ + 1)); }
label_of() { curl -sk -m 10 -b "$J" "$MC/api/devices?limit=64" | python3 -c '
import json, sys
d = json.load(sys.stdin).get("devices", [])
m = sys.argv[1].lower()
for x in d:
    if (x.get("mac") or "").lower() == m:
        print(x.get("label")); break
else:
    print("NO-DEVICE")' "$1"; }
up() { for _ in $(seq 1 100); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
login; sess
MAC=$(curl -sk -m 10 -b "$J" "$MC/api/devices?limit=64" | python3 -c '
import json, sys
d = [x for x in json.load(sys.stdin).get("devices", []) if x.get("mac") and x.get("active")]
print(d[0]["mac"] if d else "")')
[ -n "$MAC" ]; chk $? "an active device on the AP to label (${MAC:-none})"
LBL="Bench Pi (G47 test)"
post "op=set&kind=device_label&target=$MAC&value=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$LBL")&reason=G47+metal+check&permanent=true"
echo "   set: $(echo "$R" | cut -c1-140)"
[ "$(label_of "$MAC")" = "$LBL" ]; chk $? "/api/devices shows the owner label \"$LBL\""
post "op=set&kind=device_label&target=$MAC&value=%3Cscript%3E&reason=G47+metal+check&permanent=true"
echo "   invalid: $(echo "$R" | cut -c1-140)"
grep -q '"ok": *false\|"refused"' <<<"$R" && [ "$(label_of "$MAC")" = "$LBL" ]; chk $? "a label with characters outside the grammar is refused (the old label kept)"
echo "   reboot: $(python3 -I "$ROOT/os/kernel/tools/hq-upload.py" --mc "$MC" --owner-key-file "$KEY" --insecure --reboot "G47 label persistence check" 2>&1 | tail -1 | cut -c1-100)"
sleep 20; up; sleep 40
# the label lives in the owner journal, but /api/devices lists a device only once it is seen again: wait for the Pi to
# rejoin (up to 5 min) before reading it, and read the journal-backed rule list too
l="NO-DEVICE"
for _ in $(seq 1 30); do
  "$HERE/pi-ensure-ap.sh" >/dev/null 2>&1 || true; login; sess
  l=$(label_of "$MAC"); [ "$l" != "NO-DEVICE" ] && break; sleep 10
done
rules=$(curl -sk -m 10 -b "$J" "$MC/api/owner-rules")
grep -qi "device_label" <<<"$rules" && grep -qi "${MAC}" <<<"$rules"; chk $? "after a reboot the owner journal still holds the device_label rule"
[ "$l" = "$LBL" ]; chk $? "after a reboot /api/devices shows the label again once the device rejoins (\"$l\")"
post "op=remove&kind=device_label&target=$MAC&reason=G47+cleanup"
echo "   remove: $(echo "$R" | cut -c1-140)"
# removing the owner label falls back to the signed DEVICES.TXT baseline label (if any), never keeps the owner's
l=$(label_of "$MAC"); [ "$l" != "$LBL" ] && [ "$l" != "NO-DEVICE" ]; chk $? "removed: the owner label is gone (now \"$l\": the signed baseline label, or none)"
grep -q '"after":"signed DEVICES.TXT label"\|"after":"unlabelled"\|"after":"none"' <<<"$R"; chk $? "the remove reports what the device falls back to"
echo "DEVICE-LABEL: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
