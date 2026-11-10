#!/usr/bin/env bash
# cm5-cfgd-check — ADR 0059 step 3 (cfgd) on metal: an HQCFG1 bundle is uploaded as type "config", boots as a TRIAL,
# and (a) a good bundle that touches the management plane waits for the owner's confirm, then commits and survives
# a reboot; (b) a bundle whose WAN never comes up REVERTS by itself after the window and the device reboots into the
# last-known-good — while Mission Control stays reachable on the Wi-Fi AP throughout (rule 7).
# Bench only; the next reflash resets the store.
#   tools/diagnostics/cm5-cfgd-check.sh <owner-key-file> <serial-log> <config-key> [mc] [pi]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; CK="${3:?configuration signing key (vendor, or the enrolled owner key)}"
MC="${4:-https://192.168.200.146}"; PI="${5:-claude@10.200.0.4}"; AP_MC=https://10.99.0.1
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
HQ="python3 -I $ROOT/os/kernel/tools/hqcfg.py"; UPT="$ROOT/os/kernel/tools/hq-upload.py"
UP="python3 -I $UPT --mc $MC --owner-key-file $KEY --insecure"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
T=$(mktemp -d); trap 'rm -rf "$T"; pi "shred -u /tmp/hqcf.key /tmp/hq-upload.py 2>/dev/null" >/dev/null 2>&1' EXIT
up() { for _ in $(seq 1 100); do curl -sk -o /dev/null -m 5 "$1/" && return 0; sleep 3; done; return 1; }
since() { tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000'; }
cfg() { python3 -I - "$1" "$KEY" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key = sys.argv[1], open(sys.argv[2]).read().strip()
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
print(o.open(mc + "/api/config", timeout=10).read().decode())
PY
}
WAN="$ROOT/docs/design/bench-task26/wan-vlan-mgmtdhcp.txt"; POL="$ROOT/docs/design/bench-task26/policy-bench.txt"
G0=$(cfg "$MC" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(max(d["generation"], d["floor"]))'); G1=$((G0 + 1)); G2=$((G0 + 2))
# --- A: a good bundle (bench WAN + policy). It touches the management VLAN -> the owner must confirm ---
$HQ bundle "$CK" $G1 "$T/g.bin" "$T/g.sig" --wan "$WAN" --policy "$POL" >/dev/null
$UP --type config --sig "$T/g.sig" --file "$T/g.bin" > "$T/r" 2>&1; grep -q '"staged": true' "$T/r"; chk $? "A1 HQCFG1 bundle gen $G1 staged ($(grep activate "$T/r" | cut -c1-100))"
mark=$(stat -c %s "$LOG"); $UP --reboot "cfgd trial A" > /dev/null 2>&1; sleep 15; up "$MC"; chk $? "A2 device back after reboot"
since | grep -a "\[CFGD\] HQCFG1 bundle generation $G1 on TRIAL" >/dev/null; chk $? "A3 boot: bundle gen $G1 runs as a TRIAL"
C=$(cfg "$MC"); python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d["state"]=="trial" and d["needs_confirm"] and d["generation"]==int(sys.argv[2]) else 1)' "$C" $G1
chk $? "A4 /api/config: trial, needs_confirm (management-plane bundle) ($C)"
sleep 20; C=$(cfg "$MC"); grep -q '"state":"trial"' <<<"$C"; chk $? "A5 WAN usable but NOT auto-committed (waits for the owner)"
python3 -I - "$MC" "$KEY" > "$T/c" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key = sys.argv[1], open(sys.argv[2]).read().strip()
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
s = json.loads(o.open(mc + "/api/session", timeout=10).read())
rq = urllib.request.Request(mc + "/api/config/confirm", urllib.parse.urlencode({"reason": "cfgd check", "permanent": "true", "seq": s["next_seq"], "owner_key": key}).encode(), {"Origin": mc, "X-HQ-CSRF": s["csrf"]})
try:
    print(o.open(rq, timeout=10).read().decode())
except urllib.error.HTTPError as e:
    print(e.read().decode())
PY
grep -q '"committed":true' "$T/c"; chk $? "A6 owner confirm commits gen $G1 ($(cut -c1-90 "$T/c"))"
mark=$(stat -c %s "$LOG"); $UP --reboot "cfgd committed" > /dev/null 2>&1; sleep 15; up "$MC"
since | grep -a "\[CFGD\] HQCFG1 configuration bundle generation $G1 in force (committed)" >/dev/null; chk $? "A7 next boot: gen $G1 committed (last-known-good)"
# --- B: a bundle whose WAN never comes up (vlan 999, no mgmt VLAN) -> automatic revert after the window ---
printf 'HQWAN1\nmode=dhcp\nvlan=999\n' > "$T/bad.txt"
$HQ bundle "$CK" $G2 "$T/b.bin" "$T/b.sig" --wan "$T/bad.txt" --policy "$POL" >/dev/null
$UP --type config --sig "$T/b.sig" --file "$T/b.bin" > "$T/r" 2>&1; grep -q '"staged": true' "$T/r"; chk $? "B1 a bundle that breaks the WAN staged (gen $G2)"
scp -q -o BatchMode=yes "$KEY" "$PI:/tmp/hqcf.key"
mark=$(stat -c %s "$LOG"); $UP --reboot "cfgd trial B" > /dev/null 2>&1; sleep 60
for _ in $(seq 1 40); do pi "curl -sk -o /dev/null -m 5 $AP_MC/" && break; sleep 5; done
pi "curl -sk -o /dev/null -w '%{http_code}' -m 8 $AP_MC/api/health" | grep -q 200; chk $? "B2 rule 7: Mission Control answers on the Wi-Fi AP while the trial has no uplink"
for _ in $(seq 1 90); do since | grep -a "trial NOT healthy within" >/dev/null && break; sleep 5; done
since | grep -a "\[CFGD\] trial NOT healthy within" >/dev/null; chk $? "B3 the trial reverted by itself after the window (no WAN)"
up "$MC"; chk $? "B4 the device rebooted into the last-known-good: back on the management VLAN"
since | grep -a "generation $G1 in force (committed)" >/dev/null; chk $? "B5 gen $G1 (last-known-good) in force again"
[ "$ok" -eq "$n" ] && { echo "CFGD: PASS ($ok/$n)"; exit 0; } || { echo "CFGD: FAIL ($ok/$n)"; exit 1; }
