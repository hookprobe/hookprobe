#!/usr/bin/env bash
# cm5-phase0-check — ADR 0059 Phase 0 on metal: 0.5 the configuration is protected (no CONFIG UNPROTECTED, /api/anchor
# config_protected + floors); 0.3 WAN generation floors — a newer signed WAN.TXT is accepted and moves the floor, an
# OLDER one is refused at boot ("below the floor ... REFUSED") and the WAN keeps working, the floor survives reboots.
# Run on a freshly flashed image BEFORE any HQCFG1 bundle is committed (a bundle's WAN section takes precedence).
# 0.4 (other-half fallback) needs a corrupted store half on the eMMC — QEMU evidence only ([P-artstore]).
#   tools/diagnostics/cm5-phase0-check.sh <owner-key-file> <serial-log> [mc]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; MC="${3:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
PSG="python3 -I $ROOT/os/kernel/tools/policy-sign.py"
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure"
SIGN="${SIGN_KEY:-$HOME/heqk-owner-ca/bench-owner.key}"   # the bench OWNER key (must differ from the vendor key)
UP="$UP --sign-key $SIGN"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
T=$(mktemp -d); chmod 700 "$T"; trap 'rm -rf "$T"' EXIT
since() { tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000'; }
waitlog() { for _ in $(seq 1 "$2"); do since | grep -aq "$1" && return 0; sleep 2; done; return 1; }
api() { python3 -I - "$MC" "$KEY" "$1" <<'PY'
import ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key, path = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
print(o.open(mc + path, timeout=10).read().decode())
PY
}
anc() { api /api/anchor | python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
mc_up() { for _ in $(seq 1 60); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
reboot() { mark=$(stat -c %s "$LOG"); $UP --reboot "phase0 check: $1" >/dev/null 2>&1; sleep 25; mc_up; }
ensure_owner() { [ "$(api /api/config | python3 -c 'import json,sys; print(bool(json.load(sys.stdin).get("envelope", {}).get("owner_enrolled")))')" = True ] && return 0
  $PSG enroll-proof "$SIGN" > "$T/enroll.txt" && $UP --enroll "$T/enroll.txt" > "$T/enroll.out" 2>&1; local rc=$?
  echo "     owner key enrolled (rc=$rc: $(cut -c1-90 "$T/enroll.out"))"; return $rc; }
grep -v '^#' "$ROOT/docs/design/bench-task26/wan-vlan-mgmtdhcp.txt" > "$T/wan.txt"   # the bench's own WAN (no change in behaviour)
wan() { $PSG sign-wan "$SIGN" "$T/wan.txt" "$1" "$T/wan$1.sig" >/dev/null && $UP --type wan --sig "$T/wan$1.sig" --file "$T/wan.txt" > "$T/up$1" 2>&1; }
wan_ok() { curl -sk -o /dev/null -m 6 "$MC/api/health"; }   # the management VLAN rides the WAN port's VLAN 200
# --- 0.5: protected configuration ---
mark=$(grep -abo "HEQK Core" "$LOG" | tail -1 | cut -d: -f1); mark=${mark:-0}   # from the last boot banner
! since | grep -aq "CONFIG UNPROTECTED"; chk $? "0.5 boot banner: no CONFIG UNPROTECTED (release image has a policy key)"
[ "$(anc 'd.get("config_protected")')" = True ]; chk $? "0.5 /api/anchor config_protected = true (state: $(anc 'd.get("state")'))"
ensure_owner
C0=$(anc 'd["floors"]["wan"]["current"]'); F0=$(anc 'd["floors"]["wan"]["floor"]'); echo "     WAN generation in force $C0, floor $F0"
G1=$((C0 + 2)); G2=$((C0 + 3))   # leave C0+1 free: the replay below the floor
# --- 0.3: newer generations are accepted and move the floor ---
wan $G1; reboot "wan gen $G1"; waitlog "WAN.TXT signature OK — operator key, generation $G1" 60
chk $? "0.3 signed WAN gen $G1 accepted at boot ($(grep -oE '"(ok|applies|refused)": [^,}]*' "$T/up$G1" | tr '\n' ' '))"
[ "$(anc 'd["floors"]["wan"]["current"]')" = "$G1" ]; chk $? "0.3 /api/anchor WAN current = $G1 (floor $(anc 'd["floors"]["wan"]["floor"]'))"
wan $G2; reboot "wan gen $G2"; waitlog "generation $G2" 60
c=$(anc 'd["floors"]["wan"]["current"]'); f=$(anc 'd["floors"]["wan"]["floor"]')
[ "$c" = "$G2" ] && [ "$f" -ge "$G1" ]; chk $? "0.3 WAN gen $G2 accepted: current $c, floor $f (moved to the previous generation)"
# --- 0.3: an OLDER signed generation (below the floor) is refused; the WAN keeps working ---
G0=$((G1 - 1))   # newer than what was in force at the start, but below the floor G1
wan $G0
if grep -qE '"ok": ?false|refused' "$T/up$G0"; then
  chk 0 "0.3 WAN gen $G0 (< floor $f) refused at upload ($(grep -oE '"refused": "[^"]*"' "$T/up$G0" | cut -c1-80))"
else
  reboot "wan gen $G0 (below the floor)"
  waitlog "WAN.TXT generation $G0 is below the floor" 60; chk $? "0.3 WAN gen $G0 (< floor $f) REFUSED at boot"
fi
[ "$(anc 'd["floors"]["wan"]["current"]')" = "$G2" ]; chk $? "0.3 generation in force is still $G2"
wan_ok; chk $? "0.3 the WAN / management path still works after the refused replay"
reboot "floor persistence"; [ "$(anc 'd["floors"]["wan"]["floor"]')" -ge "$G1" ]; chk $? "0.3 the floor survives a reboot ($(anc 'd["floors"]["wan"]'))"
[ "$ok" -eq "$n" ] && { echo "PHASE0: PASS ($ok/$n)"; exit 0; } || { echo "PHASE0: FAIL ($ok/$n)"; exit 1; }
