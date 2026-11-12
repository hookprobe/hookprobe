#!/usr/bin/env bash
# cm5-house-check — docs/design/heqk-house-test-plan.md on metal: change settings live -> reboot -> kept; change the
# Wi-Fi password live -> connect / reconnect -> reboot -> kept; revert to the original setup -> reboot -> kept.
# Passphrases are never printed; temp files 0700 and shredded.
#   tools/diagnostics/cm5-house-check.sh <owner-key-file> <serial-log> <config-key> [mc] [pi]   (needs PI_SUDO_FILE)
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; CK="${3:?configuration signing key}"
MC="${4:-https://192.168.200.146}"; PI="${5:-claude@10.200.0.4}"; PS="${PI_SUDO_FILE:?PI_SUDO_FILE}"; AP_MC=https://10.99.0.1
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
HQ="python3 -I $ROOT/os/kernel/tools/hqcfg.py"
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure"
ok=0; n=0; wifi_ok=1
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; return "$1"; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
psudo() { pi "sudo -S -p '' $*" < "$PS"; }
T=$(mktemp -d); chmod 700 "$T"; umask 077
cleanup() { psudo "nmcli con delete hq-house" >/dev/null 2>&1; shred -u "$T"/* 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
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
cfgval() { api /api/config | python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
mc_up() { for _ in $(seq 1 60); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
confirm() { $UP --config-confirm "house check $1" 2>&1 | grep -qE '"committed": ?true'; }
reboot() { mark=$(stat -c %s "$LOG"); $UP --reboot "house check: $1" >/dev/null 2>&1; sleep 25; mc_up; }
# Pi side: join a profile on wlan0 and prove the AP serves it (lease + Mission Control on the AP)
join() { local r; for _ in 1 2 3; do psudo "nmcli dev disconnect wlan0" >/dev/null 2>&1; sleep 2
    r=$(psudo "nmcli -w 40 con up '$1' ifname wlan0" 2>&1 | tail -1); grep -q success <<<"$r" && break; sleep 5; done
  grep -q success <<<"$r" || return 1
  for _ in $(seq 1 15); do pi "ip -4 -o addr show wlan0" | grep -q "10\.99\.0\." && \
    pi "curl -sk -o /dev/null -w '%{http_code}' -m 5 --interface \$(ip -4 -o addr | awk '\$4 ~ /^10\\.99\\.0\\./ {print \$2; exit}') $AP_MC/api/health" | grep -q 200 && return 0; sleep 2; done; return 1; }
refused() { psudo "nmcli dev disconnect wlan0" >/dev/null 2>&1; sleep 2; ! psudo "nmcli -w 25 con up '$1' ifname wlan0" 2>&1 | tail -1 | grep -q success; }
dns9() { local r; r=$(pi 'a=$(ip -4 -o addr | awk '"'"'$4 ~ /^10\.99\.0\./ {split($4, x, "/"); print x[1]; exit}'"'"'); [ -n "$a" ] || { echo NOADDR; exit 0; }; timeout 5 dig +short +time=2 +tries=1 -b "$a" @9.9.9.9 example.com' 2>/dev/null)
  [ "$r" = NOADDR ] && { echo "     (the Pi has no AP address 10.99.0.x — DNS probe not run)"; return 2; }   # 2: neither "answers" nor "dropped"
  grep -qE '^[0-9.]+$' <<<"$r"; }
canon() { sed -e 's/[[:space:]]*$//' -e '/^#/d' -e '/^$/d' "$1"; }
ensure_owner
G=$(cfgval 'max(d["generation"], d["floor"])')
bundle() { G=$((G + 1)); $HQ bundle "$SIGN" $G "$T/b.bin" "$T/b.sig" "$@" >/dev/null; mark=$(stat -c %s "$LOG")
  $UP --type config --sig "$T/b.sig" --file "$T/b.bin" > "$T/r" 2>&1; shred -u "$T/b.bin"; }
# ---- 0. baseline ----
PROF=$(pi "nmcli -t -f NAME con show | grep -i hookprobe | head -1")
SSID=$(psudo "nmcli -s -g 802-11-wireless.ssid con show '$PROF'"); psudo "nmcli -s -g 802-11-wireless-security.psk con show '$PROF'" > "$T/psk0"
[ -n "$SSID" ] && [ -s "$T/psk0" ] || { echo "HOUSE: cannot read the AP profile from the Pi"; exit 1; }
python3 -I -c 'import secrets; print("hq-" + secrets.token_urlsafe(15))' > "$T/psk1"
echo "baseline: generation $G, $(cfgval '"at_rest=" + json.dumps(d.get("at_rest"))'), Pi profile '$PROF'"
join "$PROF"; chk $? "0.1 the Pi is on the AP with its original profile, Mission Control answers on the AP"
dns9; r=$?; chk $([ $r = 1 ] && echo 0 || echo 1) "0.2 original policy in force: DNS to 9.9.9.9 dropped"
# ---- 1. change settings live ----
printf 'HQWAN1\nmode=static\nip=10.100.0.200/24\ngw=10.100.0.1\ndns=10.100.0.1\nvlan=100\nmgmt_vlan=200\nmgmt=dhcp\n' > "$T/wan1"
printf 'HQPOL1\nacl LAN-IN seq 10 block tcp any 1.1.1.1/32 80\nacl LAN-IN default allow\ninterface lan acl in LAN-IN\nroute 0.0.0.0/0 via wan\n' > "$T/pol1"
bundle --wan "$T/wan1" --policy "$T/pol1"; GA=$G
grep -q '"applies": "live"' "$T/r" && grep -q '"reboot_required": false' "$T/r"; chk $? "1.1 settings bundle gen $GA applies live, no reboot"
waitlog "\[WAN\] live apply: mode STATIC" 30 && waitlog "\[POLICY\] live apply: swapped in" 5; chk $? "1.2 WAN re-brought up as STATIC + policy swapped, live"
sleep 8; join "$PROF" >/dev/null; dns9; chk $? "1.3 behaviour changed without a reboot: DNS to 9.9.9.9 answers"
confirm A; chk $? "1.4 owner confirm commits gen $GA"
# ---- 2. reboot -> kept ----
reboot "settings kept"; chk $? "2.1 device back after reboot"
since | grep -aq "generation $GA in force (committed)"; chk $? "2.2 gen $GA in force after the reboot"
[ "$(cfgval 'd["generation"]')" = "$GA" ] && [ "$(cfgval 'd.get("at_rest",{}).get("sealed")')" = True ]; chk $? "2.3 /api/config: gen $GA, sealed at rest"
join "$PROF" >/dev/null; dns9; chk $? "2.4 still static + DNS 9.9.9.9 answers after the reboot"
# ---- 3-6. Wi-Fi password: change live, connect / reconnect, reboot, kept ----
{ printf 'ssid=%s\npsk=' "$SSID"; cat "$T/psk1"; printf 'security=wpa3-transition\n'; } > "$T/wifi1"
bundle --wan "$T/wan1" --policy "$T/pol1" --wifi "$T/wifi1"; GB=$G
grep -q '"applies": "live"' "$T/r" && grep -q '"needs_confirm": true' "$T/r"; chk $? "3.1 Wi-Fi password bundle gen $GB: live, waits for the owner's confirm" || wifi_ok=0
waitlog "\[WIFI\] live apply: .* BSS re-started" 20; chk $? "3.2 BSS re-started live with the new passphrase" || wifi_ok=0
if [ $wifi_ok = 1 ]; then
  psudo "nmcli con delete hq-house" >/dev/null 2>&1
  psudo "nmcli con add type wifi ifname wlan0 con-name hq-house ssid '$SSID' wifi-sec.key-mgmt wpa-psk wifi-sec.psk '$(cat "$T/psk1")' ipv4.method auto connection.autoconnect no" >/dev/null 2>&1
  join hq-house; chk $? "4.1 connect with the NEW passphrase: lease + Mission Control on the AP" || wifi_ok=0
  confirm B; chk $? "4.2 owner confirm commits gen $GB"
  refused "$PROF"; chk $? "4.3 the OLD passphrase is refused"
  for k in 1 2 3; do join hq-house; chk $? "5.$k disconnect / reconnect with the new passphrase"; done
  reboot "wifi kept"; chk $? "6.1 device back after reboot"
  since | grep -aq "generation $GB in force (committed)"; chk $? "6.2 gen $GB in force after the reboot"
  join hq-house; chk $? "6.3 after the reboot the Pi joins with the NEW passphrase (kept, sealed)"
  refused "$PROF"; chk $? "6.4 the old passphrase is still refused after the reboot"
else
  echo "    (Wi-Fi phases 4-6 skipped: the change did not apply; waiting out a live revert before the restore)"; sleep 320
fi
# ---- 7-8. revert to the original setup, reboot, kept ----
{ printf 'ssid=%s\npsk=' "$SSID"; cat "$T/psk0"; printf 'security=wpa3-transition\n'; } > "$T/wifi0"
canon "$ROOT/docs/design/bench-task26/wan-vlan-mgmtdhcp.txt" > "$T/wan0"; canon "$ROOT/docs/design/bench-task26/policy-bench.txt" > "$T/pol0"
bundle --wan "$T/wan0" --policy "$T/pol0" --wifi "$T/wifi0"; GC=$G
grep -q '"applies": "live"' "$T/r"; chk $? "7.1 original-setup bundle gen $GC applies live"
waitlog "\[WAN\] live apply: mode DHCP" 40; chk $? "7.2 WAN back to the bench DHCP (VLAN 100 + mgmt VLAN 200)"
join "$PROF"; chk $? "7.3 the Pi's ORIGINAL profile reconnects"
confirm C; chk $? "7.4 owner confirm commits gen $GC"
dns9; r=$?; chk $([ $r = 1 ] && echo 0 || echo 1) "7.5 original policy again: DNS to 9.9.9.9 dropped"
reboot "original kept"; chk $? "8.1 device back after reboot"
since | grep -aq "generation $GC in force (committed)"; chk $? "8.2 gen $GC (original setup) in force after the reboot"
join "$PROF"; chk $? "8.3 the Pi joins on its original profile after the reboot"
refused hq-house; chk $? "8.4 the test passphrase is refused"
join "$PROF" >/dev/null; dns9; r=$?; chk $([ $r = 1 ] && echo 0 || echo 1) "8.5 original policy after the reboot: DNS to 9.9.9.9 dropped"
[ "$(cfgval 'd.get("at_rest",{}).get("sealed")')" = True ]; chk $? "8.6 sealed at rest"
fh=$(tail -c +1 "$LOG" | tr -d '\r\000' | tail -c 3000000 | grep -ac "Wi-Fi firmware HALTED")
echo "    firmware-halt lines in the recent serial log: $fh"
[ "$ok" -eq "$n" ] && { echo "HOUSE: PASS ($ok/$n)"; exit 0; } || { echo "HOUSE: FAIL ($ok/$n)"; exit 1; }
