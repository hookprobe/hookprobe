#!/usr/bin/env bash
# cm5-cfgd-live-check — sealed-config / live apply (steps 6-11) on metal: signed HQCFG1 bundles change the policy and
# the WAN WITHOUT a reboot; a healthy change commits by itself (or after the owner's confirm when the management plane
# changes); a WAN that never gets usable reverts LIVE after the window; Mission Control stays reachable on the Wi-Fi AP
# throughout (rule 7); the committed bundle survives a reboot, sealed at rest.
# Bench: fortress port-4 VLAN bench up (docs/design/bench-task26/fortress-vlan-bench.sh setup), the bench AP image
# (fac.sh: per-file WAN = wan-vlan-mgmtdhcp.txt, POLICY = policy-bench.txt), the bench Pi on the AP via wlan1.
#   tools/diagnostics/cm5-cfgd-live-check.sh <owner-key-file> <serial-log> <config-key> [mc] [pi]
# Optional: PPPOE=1 runs the wrong-password case against a bench pppoe-server on enp4s0.100 (not started here).
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; CK="${3:?configuration signing key}"
MC="${4:-https://192.168.200.146}"; PI="${5:-claude@10.200.0.4}"; AP_MC=https://10.99.0.1
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
HQ="python3 -I $ROOT/os/kernel/tools/hqcfg.py"
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
since() { tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000'; }
waitlog() { for _ in $(seq 1 "$2"); do since | grep -aq "$1" && return 0; sleep 2; done; return 1; }
api() { python3 -I - "$MC" "$KEY" "$1" "${2:-}" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key, path, reason = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3], sys.argv[4]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
if not reason:
    print(o.open(mc + path, timeout=10).read().decode()); sys.exit(0)
s = json.loads(o.open(mc + "/api/session", timeout=10).read())
rq = urllib.request.Request(mc + path, urllib.parse.urlencode({"reason": reason, "permanent": "true", "seq": s["next_seq"], "owner_key": key}).encode(), {"Origin": mc, "X-HQ-CSRF": s["csrf"]})
try:
    print(o.open(rq, timeout=10).read().decode())
except urllib.error.HTTPError as e:
    print(e.read().decode())
PY
}
# R6 = D (PR #1010/#1013/#1018): activate + confirm need an HQMGMT1 envelope signed by the ENROLLED owner key; the
# token only opens the session. SIGN_KEY (default: ~/heqk-owner-ca/bench-owner.key, a bench-only Ed25519 key) is that key; enrolled here if the device
# reports none (bench unit: a reflash / factory reset clears it).
SIGN="${SIGN_KEY:-$HOME/heqk-owner-ca/bench-owner.key}"  # the bench OWNER key (must differ from the vendor/config key)
UP="$UP --sign-key $SIGN"
ensure_owner() { local e; e=$(api /api/config | python3 -c 'import json,sys; print(bool(json.load(sys.stdin).get("envelope", {}).get("owner_enrolled")))')
  [ "$e" = True ] && return 0
  python3 -I "$ROOT/os/kernel/tools/policy-sign.py" enroll-proof "$SIGN" > "$T/enroll.txt" && $UP --enroll "$T/enroll.txt" > "$T/enroll.out" 2>&1
  local rc=$?; echo "     owner key enrolled for the R6 envelopes (rc=$rc: $(cut -c1-100 "$T/enroll.out"))"; return $rc; }
rule7() { pi "curl -sk -o /dev/null -w '%{http_code}' -m 8 $AP_MC/api/health" | grep -q 200; }
boots() { tr -d '\r\000' < "$LOG" | grep -ac "HEQK Core"; }
ensure_owner
gen0=$(api /api/config | python3 -c 'import json,sys; d=json.load(sys.stdin); print(max(d["generation"], d["floor"]))')
G=$gen0
bundle() { G=$((G + 1)); $HQ bundle "$CK" $G "$T/b$G.bin" "$T/b$G.sig" "$@" >/dev/null; mark=$(stat -c %s "$LOG")
  $UP --type config --sig "$T/b$G.sig" --file "$T/b$G.bin" > "$T/r$G" 2>&1; }
B0=$(boots)
# policies without management bindings (a change of them alone auto-commits)
printf 'HQPOL1\nacl LAN-IN seq 10 block tcp any 1.1.1.1/32 80\nacl LAN-IN default allow\ninterface lan acl in LAN-IN\nroute 0.0.0.0/0 via wan\n' > "$T/pa.txt"
dns9() { pi "timeout 5 dig +short +time=2 +tries=1 -b \$(ip -4 -o addr show wlan1 | awk '{print \$4}' | cut -d/ -f1) @9.9.9.9 example.com" | grep -qE '^[0-9.]+$'; }
dns9; chk $((1 - $?)) "A0 per-file policy-bench in force: DNS to 9.9.9.9 is DROPPED"
# --- A: a policy-only bundle applies LIVE and auto-commits (no management lines) ---
bundle --policy "$T/pa.txt"
grep -q '"applies": "live"' "$T/r$G" && grep -q '"reboot_required": false' "$T/r$G" && grep -q '"needs_confirm": false' "$T/r$G"
chk $? "A1 policy bundle gen $G: applies live, no reboot, no confirm ($(grep -oE '"(applies|needs_confirm|window_s)": [^,}]*' "$T/r$G" | tr '\n' ' '))"
waitlog "\[POLICY\] live apply: swapped in" 15; chk $? "A2 the policy was swapped in live"
dns9; chk $? "A3 behaviour changed without a reboot: DNS to 9.9.9.9 now answers"
waitlog "bundle generation $G COMMITTED" 30; chk $? "A4 healthy -> committed by itself"
rule7; chk $? "A5 rule 7: Mission Control answers on the AP"
# --- B: a static WAN on VLAN 100, same management keys -> live, needs confirm (management lines enter the bundle) ---
printf 'HQWAN1\nmode=static\nip=10.100.0.200/24\ngw=10.100.0.1\ndns=10.100.0.1\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n' > "$T/ws.txt"
bundle --wan "$T/ws.txt" --policy "$T/pa.txt"; GS=$G
grep -q '"applies": "live"' "$T/r$G" && grep -q '"needs_confirm": true' "$T/r$G"; chk $? "B1 static WAN bundle gen $G: live, waits for the owner's confirm"
waitlog "\[WAN\] live apply: mode STATIC" 30; chk $? "B2 WAN re-brought up live as STATIC"
sleep 10; pi "curl -s -o /dev/null -w '%{http_code}' -m 10 --interface wlan1 http://10.100.0.1:8088/blob -r 0-1023" | grep -q 206; chk $? "B3 LAN client reaches the WAN side through the new static WAN"
rule7; chk $? "B4 rule 7 during the trial"
$UP --config-confirm "live check B" 2>\&1 | grep -qE \'"committed": ?true\'; chk $? "B5 owner confirm commits gen $G"
# --- C: a static WAN whose gateway never answers -> LIVE revert to gen B after the 120-s window ---
sed 's/^gw=.*/gw=10.100.0.254/' "$T/ws.txt" > "$T/wd.txt"
bundle --wan "$T/wd.txt" --policy "$T/pa.txt"
grep -q '"needs_confirm": false' "$T/r$G"; chk $? "C1 dead-gateway bundle gen $G: live, auto window (management unchanged)"
waitlog "reverted LIVE to generation $GS" 100; chk $? "C2 not usable within the window -> reverted LIVE to gen $GS"
sleep 10; pi "curl -s -o /dev/null -w '%{http_code}' -m 10 --interface wlan1 http://10.100.0.1:8088/blob -r 0-1023" | grep -q 206; chk $? "C3 the last-known-good WAN works again"
[ "$(boots)" = "$B0" ]; chk $? "C4 no reboot so far (boot banners unchanged: $B0)"
rule7; chk $? "C5 rule 7 after the live revert"
# --- D (optional): a PPPoE bundle with a wrong password reverts at once (Q5), not after the window ---
if [ "${PPPOE:-0}" = 1 ]; then
  printf 'HQWAN1\nmode=pppoe\npppoe_user=bench\npppoe_pass=wrong-on-purpose\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n' > "$T/wp.txt"
  bundle --wan "$T/wp.txt" --policy "$T/pa.txt"; t0=$(date +%s)
  waitlog "reverted LIVE to generation $GS" 60; r=$?; chk $r "D1 PPPoE auth rejected -> reverted LIVE in $(( $(date +%s) - t0 )) s (< window)"
  shred -u "$T/wp.txt"
fi
# --- E: back to DHCP (the bench's own keys) -> live, then a reboot keeps it, sealed at rest ---
grep -v '^#' "$ROOT/docs/design/bench-task26/wan-vlan-mgmtdhcp.txt" > "$T/wh.txt"
bundle --wan "$T/wh.txt" --policy "$T/pa.txt"; GE=$G
waitlog "\[WAN\] live apply: mode DHCP" 30; chk $? "E1 DHCP WAN live (gen $G)"
waitlog "bundle generation $G COMMITTED" 60; chk $? "E2 committed by itself once leased"
mark=$(stat -c %s "$LOG"); $UP --reboot "live check: survives reboot" >/dev/null 2>&1; sleep 20
for _ in $(seq 1 60); do curl -sk -o /dev/null -m 5 "$MC/" && break; sleep 3; done
since | grep -aq "generation $GE in force (committed)"; chk $? "E3 after a reboot gen $GE is in force (last-known-good)"
api /api/config | python3 -c 'import json,sys; a=json.load(sys.stdin).get("at_rest",{}); sys.exit(0 if a.get("sealed") and a.get("secrets_protected") else 1)'; chk $? "E4 /api/config at_rest: sealed, secrets protected"
[ "$ok" -eq "$n" ] && { echo "CFGD-LIVE: PASS ($ok/$n)"; exit 0; } || { echo "CFGD-LIVE: FAIL ($ok/$n)"; exit 1; }
