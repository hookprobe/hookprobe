#!/usr/bin/env bash
# cm5-config-journey-check — ADR 0058 on metal (operator rules 2026-11-10):
#   A. a signed WAN.TXT uploaded over Mission Control is STAGED (applies at the next boot); /api/reboot applies it;
#      the serial log shows the store copy verified; a second generation + rollback returns to the first.
#   B. the owner enrolls their own configuration key (proof of possession); a vendor-signed WAN.TXT is then
#      refused and an owner-signed one accepted (config files verified by the owner key only).
#   C. rule 7: an owner-signed WAN.TXT that takes the uplink AND the management VLAN away still leaves Mission
#      Control on the Wi-Fi AP; the bench Pi (a Wi-Fi client) rolls it back and restarts — the device returns.
#   D. a factory reset clears the enrolled owner key (vendor key stays).
# Bench only: changes the bench unit's WAN; the next reflash resets everything.
#   tools/diagnostics/cm5-config-journey-check.sh <owner-key-file> <serial-log> <vendor-key> [mc] [pi]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; VK="${3:?vendor (policy) signing key}"
MC="${4:-https://192.168.200.146}"; PI="${5:-claude@10.200.0.4}"; AP_MC=https://10.99.0.1
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
SIGN="python3 -I $ROOT/os/kernel/tools/policy-sign.py"; UPT="$ROOT/os/kernel/tools/hq-upload.py"
UP="python3 -I $UPT --mc $MC --owner-key-file $KEY --insecure"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
T=$(mktemp -d); trap 'rm -rf "$T"; pi "shred -u /tmp/hqcj.key /tmp/hq-upload.py 2>/dev/null" >/dev/null 2>&1' EXIT
up() { for _ in $(seq 1 100); do curl -sk -o /dev/null -m 5 "$1/" && return 0; sleep 3; done; return 1; }
since() { tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000'; }
wan_gen() { $UP --status | python3 -c 'import json,sys; t=[x for x in json.load(sys.stdin)["types"] if x["type"]=="wan"][0]; print(t["generation"], t["source"], t.get("applies"))'; }
anchor() { python3 -I - "$MC" "$KEY" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key = sys.argv[1], open(sys.argv[2]).read().strip()
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
print(o.open(mc + "/api/anchor", timeout=10).read().decode())
PY
}
reboot_wait() { mark=$(stat -c %s "$LOG"); $UP --reboot "$1" > "$T/r" 2>&1; sleep 15; up "$2"; }
WAN="$ROOT/docs/design/bench-task26/wan-vlan-mgmtdhcp.txt"
read -r G0 SRC0 AP0 <<<"$(wan_gen)"; echo "wan: generation $G0 from $SRC0 (applies $AP0)"
[ "$AP0" = next_boot ]; chk $? "/api/upload lists wan as a staged type (applies next_boot)"
G1=$((G0 + 10)); G2=$((G0 + 11)); G3=$((G0 + 12)); G4=$((G0 + 13))
# --- A: staged WAN upload, reboot, rollback (vendor key) ---
$SIGN sign-wan "$VK" "$WAN" $G1 "$T/W1.SIG" >/dev/null
$UP --type wan --sig "$T/W1.SIG" --file "$WAN" > "$T/r" 2>&1; R=$(cat "$T/r")
grep -q '"staged": true' <<<"$R"; chk $? "A1 signed WAN gen $G1 activated as staged ($(grep activate "$T/r" | cut -c1-110))"
$UP --rollback wan > "$T/r" 2>&1; grep -q 'nothing to roll back' "$T/r"; chk $? "A2 rollback with one generation is refused ($(cut -c1-90 "$T/r"))"
reboot_wait "apply staged WAN" "$MC"; chk $? "A3 /api/reboot: device back on the management VLAN"
since | grep -a "\[WAN\] WAN.TXT signature OK — operator key, generation $G1" >/dev/null; chk $? "A4 next boot: the staged WAN.TXT (gen $G1) verified from the store"
$SIGN sign-wan "$VK" "$WAN" $G2 "$T/W2.SIG" >/dev/null
$UP --type wan --sig "$T/W2.SIG" --file "$WAN" > /dev/null 2>&1
$UP --rollback wan > "$T/r" 2>&1; grep -q '"ok": true' "$T/r" && grep -q "\"generation\": $G1" "$T/r"; chk $? "A5 gen $G2 uploaded, rollback re-activates gen $G1 ($(cut -c1-110 "$T/r"))"
# --- B: owner key enrollment ---
$SIGN keygen "$T/owner.key" > /dev/null; $SIGN enroll-proof "$T/owner.key" > "$T/enroll.txt"
$SIGN keygen "$T/other.key" > /dev/null; $SIGN enroll-proof "$T/other.key" | sed 's/^proof=.\{8\}/proof=00000000/' > "$T/bad.txt"
$UP --enroll "$T/bad.txt" > "$T/r" 2>&1; grep -q 'proof of possession' "$T/r"; chk $? "B1 enrollment with a bad proof refused ($(cut -c1-90 "$T/r"))"
$UP --enroll "$T/enroll.txt" > "$T/r" 2>&1; grep -q '"ok": true' "$T/r"; chk $? "B2 owner key enrolled ($(cut -c1-90 "$T/r"))"
A=$(anchor); OPK=$(grep '^public_key=' "$T/enroll.txt" | cut -d= -f2)
grep -q "\"owner_key\":\"$OPK\"" <<<"$A" && grep -q '"config_files_verified_by":"owner"' <<<"$A"; chk $? "B3 /api/anchor: owner key in force for configuration files"
$UP --enroll "$T/enroll.txt" > "$T/r" 2>&1; grep -q 'already enrolled' "$T/r"; chk $? "B4 a second enrollment is refused (one-shot)"
$SIGN sign-wan "$VK" "$WAN" $G3 "$T/W3.SIG" >/dev/null
$UP --type wan --sig "$T/W3.SIG" --file "$WAN" > "$T/r" 2>&1; grep -q '"ok": false' "$T/r"; chk $? "B5 a VENDOR-signed WAN.TXT is now refused"
$SIGN sign-wan "$T/owner.key" "$WAN" $G3 "$T/W3o.SIG" >/dev/null
$UP --type wan --sig "$T/W3o.SIG" --file "$WAN" > "$T/r" 2>&1; grep -q '"staged": true' "$T/r"; chk $? "B6 an OWNER-signed WAN.TXT is accepted"
reboot_wait "apply owner WAN" "$MC"; chk $? "B7 device back after reboot"
since | grep -a "\[WAN\] WAN.TXT signature OK — operator key, generation $G3" >/dev/null; chk $? "B8 boot verified the owner-signed WAN.TXT (gen $G3)"
# --- C: rule 7 — a WAN change that removes the uplink and the management VLAN; recovery over the Wi-Fi AP ---
printf 'HQWAN1\n# config-journey check: internet on an unused VLAN, no management VLAN\nmode=dhcp\nvlan=999\n' > "$T/BAD.TXT"
python3 -c 'import sys; b=open(sys.argv[1],"rb").read(); open(sys.argv[1],"wb").write(b.ljust(512,b"\n"))' "$T/BAD.TXT"
$SIGN sign-wan "$T/owner.key" "$T/BAD.TXT" $G4 "$T/BAD.SIG" >/dev/null
$UP --type wan --sig "$T/BAD.SIG" --file "$T/BAD.TXT" > "$T/r" 2>&1; grep -q '"staged": true' "$T/r"; chk $? "C1 a disconnecting WAN.TXT (vlan 999, no mgmt) staged"
mark=$(stat -c %s "$LOG"); $UP --reboot "check rule 7" > /dev/null 2>&1; sleep 60
scp -q -o BatchMode=yes "$UPT" "$PI:/tmp/hq-upload.py" && scp -q -o BatchMode=yes "$KEY" "$PI:/tmp/hqcj.key"
for _ in $(seq 1 60); do pi "curl -sk -o /dev/null -m 5 $AP_MC/" && break; sleep 5; done
pi "curl -sk -o /dev/null -w '%{http_code}' -m 8 $AP_MC/api/health" | grep -q 200; chk $? "C2 Mission Control still answers on the Wi-Fi AP ($AP_MC) with the uplink gone"
curl -sk -o /dev/null -m 5 "$MC/"; [ $? -ne 0 ]; chk $? "C3 the management VLAN address is gone (the bad WAN really applied)"
pi "python3 -I /tmp/hq-upload.py --mc $AP_MC --owner-key-file /tmp/hqcj.key --insecure --rollback wan" > "$T/r" 2>&1; grep -q '"ok": true' "$T/r"; chk $? "C4 rollback from the Wi-Fi client ($(cut -c1-100 "$T/r"))"
pi "python3 -I /tmp/hq-upload.py --mc $AP_MC --owner-key-file /tmp/hqcj.key --insecure --reboot recover" > /dev/null 2>&1
sleep 15; up "$MC"; chk $? "C5 after the restart the device is back on the management VLAN (gen $G3 restored)"
# --- D: factory reset clears the owner key ---
"$HERE/cm5-factory-reset-check.sh" "$KEY" "$LOG" "$MC" > "$T/fr" 2>&1; tail -1 "$T/fr" | sed 's/^/  /'
A=$(anchor); grep -q '"owner_enrolled":false' <<<"$A" && grep -q '"vendor_key":"[0-9a-f]\{64\}"' <<<"$A"; chk $? "D1 factory reset: owner key cleared, vendor key kept"
[ "$ok" -eq "$n" ] && { echo "CONFIG-JOURNEY: PASS ($ok/$n)"; exit 0; } || { echo "CONFIG-JOURNEY: FAIL ($ok/$n)"; exit 1; }
