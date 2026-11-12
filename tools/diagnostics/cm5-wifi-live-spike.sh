#!/usr/bin/env bash
# cm5-wifi-live-spike — sealed-config step 10 metal spike (design R2): repeated LIVE bounces of the CYW43455 AP by
# signed Wi-Fi bundles, alternating WPA3 transition <-> WPA2-PSK (same SSID / passphrase, so the bench Pi's saved
# profile re-joins either way). Each bounce: the AP restarts on the same channel, the Pi re-joins, Mission Control
# answers on the AP, the owner confirms, the generation commits; no firmware halt anywhere. Then one change is left
# UNconfirmed: after the 300-s window cfgd reverts LIVE and the Pi re-joins the last-known-good.
# The passphrase is read from the Pi's saved profile and never printed; the bundles carrying it are shredded.
#   tools/diagnostics/cm5-wifi-live-spike.sh <owner-key-file> <serial-log> <config-key> [rounds] [mc] [pi]
#   (needs PI_SUDO_FILE; rounds default 10)
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; CK="${3:?configuration signing key}"; R="${4:-10}"
MC="${5:-https://192.168.200.146}"; PI="${6:-claude@10.200.0.4}"; PS="${PI_SUDO_FILE:?PI_SUDO_FILE}"; AP_MC=https://10.99.0.1
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
HQ="python3 -I $ROOT/os/kernel/tools/hqcfg.py"
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
psudo() { pi "sudo -S -p '' $*" < "$PS"; }
T=$(mktemp -d); chmod 700 "$T"; trap 'shred -u "$T"/* 2>/dev/null; rm -rf "$T"' EXIT
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
rejoin() { for _ in $(seq 1 30); do pi "curl -sk -o /dev/null -w '%{http_code}' -m 5 --interface wlan0 $AP_MC/api/health" 2>/dev/null | grep -q 200 && return 0
  PI_SUDO_FILE="$PS" "$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1; sleep 3; done; return 1; }
PROF=$(pi "nmcli -t -f NAME con show | grep -i hookprobe | head -1")
SSID=$(psudo "nmcli -s -g 802-11-wireless.ssid con show '$PROF'"); PSK=$(psudo "nmcli -s -g 802-11-wireless-security.psk con show '$PROF'")
[ -n "$SSID" ] && [ -n "$PSK" ] || { echo "SPIKE: cannot read the AP SSID / passphrase from the Pi profile"; exit 1; }
ensure_owner
G=$(api /api/config | python3 -c 'import json,sys; d=json.load(sys.stdin); print(max(d["generation"], d["floor"]))')
FH0=$(tr -d '\r\000' < "$LOG" | grep -ac "FWHALT")
# A bundle is the WHOLE configuration: a Wi-Fi-only bundle would also remove the WAN / POLICY sections of the bundle in
# force (cfgd changes 0x07, MB5 2026-11-12). Carry the bench WAN + POLICY so only the Wi-Fi changes round to round.
grep -v '^#' "$ROOT/docs/design/bench-task26/wan-vlan-mgmtdhcp.txt" > "$T/wan.txt"
grep -v '^#' "$ROOT/docs/design/bench-task26/policy-bench.txt" > "$T/pol.txt"
mkw() { umask 077; printf 'ssid=%s\npsk=%s\nsecurity=%s\n' "$SSID" "$PSK" "$1" > "$T/w.txt"; }
push() { G=$((G + 1)); mkw "$1"; $HQ bundle "$SIGN" $G "$T/b.bin" "$T/b.sig" --wan "$T/wan.txt" --policy "$T/pol.txt" --wifi "$T/w.txt" >/dev/null; shred -u "$T/w.txt"
  mark=$(stat -c %s "$LOG"); $UP --type config --sig "$T/b.sig" --file "$T/b.bin" > "$T/r" 2>&1; shred -u "$T/b.bin"; }
t_all=$(date +%s)
for i in $(seq 1 "$R"); do
  if [ $((i % 2)) = 1 ]; then sec=wpa2; want="WPA2-PSK"; else sec=wpa3-transition; want="WPA3 transition"; fi
  push $sec; t0=$(date +%s)
  grep -q '"applies": "live"' "$T/r" && grep -q '"needs_confirm": true' "$T/r"; a=$?
  waitlog "\[WIFI\] live apply: SSID [0-9]* bytes, security $want — BSS re-started" 20; b=$?
  rejoin; c=$?; dt=$(( $(date +%s) - t0 ))
  $UP --config-confirm "wifi spike $i" 2>&1 | grep -qE '"committed": ?true'; d=$?
  chk $(( a | b | c | d )) "round $i: $want gen $G — live (reply=$a), BSS restarted (log=$b), Pi re-joined + MC on the AP (rejoin=$c, ${dt}s), confirm committed ($d)"
done
FH1=$(tr -d '\r\000' < "$LOG" | grep -ac "FWHALT")
[ "$FH1" = "$FH0" ]; chk $? "no firmware halt across $R live bounces in $(( $(date +%s) - t_all )) s"
# --- an UNconfirmed change: the window passes -> LIVE revert to the last-known-good, the Pi re-joins it ---
GL=$G; push wpa3-transition
waitlog "\[WIFI\] live apply" 20; chk $? "unconfirmed change gen $G applied live"
rejoin; for _ in $(seq 1 200); do since | grep -aq "reverted LIVE to generation $GL" && break; sleep 2; done
since | grep -aq "reverted LIVE to generation $GL"; chk $? "no confirm within the window -> reverted LIVE to gen $GL (no reboot)"
rejoin; chk $? "the Pi re-joined the last-known-good AP; Mission Control answers"
[ "$ok" -eq "$n" ] && { echo "WIFI-LIVE-SPIKE: PASS ($ok/$n)"; exit 0; } || { echo "WIFI-LIVE-SPIKE: FAIL ($ok/$n)"; exit 1; }
