#!/usr/bin/env bash
# ADR 0065 step 4g S4 — the operator's fault-isolation evidence (decision 2026-11-15), on CM5 metal, against an image
# built with the BENCH feature `wifi-inject` (never a release image: make-cm5-heqk-image.sh refuses it).
# Two stations on the bench Pi: A = wlan1 (USB rtw88, SAE in software, profile hq-iso-a) and B = wlan0 (onboard, its
# HookProbe profile). Every injection goes through POST /api/bench/wifi-inject (owner re-auth).
#   E1 an injected CMD53 timeout restarts the bus server, never the WPA server
#   E2 a bus-server fault keeps every PMKSA entry
#   E3 after the bus recovery a station reconnects from its cached PMKSA (pmkids=1, no SAE exchange)
#   E4 a fault on station B's M2 is contained: B retries and keys, A's PMKSA survives and A reconnects cached
#   E5 a WPA-server fault full-wipes (state + key-transfer page zeroed, new group keys) and both stations redo full SAE
#   E6 throughput >= 96 Mbps (ADR 0065 baseline)
#   E7 [WDOG] worst_loop_gap_ms < 2000 throughout, and a reconnect soak (>= 50 cycles over both stations) all keyed
# usage: cm5-wifi-isolation-check.sh <serial-log> <owner-key-file> [mc-url] [pi] [soak-cycles]   (needs PI_SUDO_FILE)
set -u
LOG="${1:?serial log}"; KEYF="${2:?owner key file}"; MC="${3:-https://192.168.200.146}"; PI="${4:-claude@10.200.0.4}"
CYC="${5:-50}"; PS="${PI_SUDO_FILE:?PI_SUDO_FILE}"; R=$(cd "$(dirname "$0")/../.." && pwd)
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
psudo() { pi "sudo -S -p '' $*" < "$PS"; }
M0=$(stat -c %s "$LOG")
mark() { stat -c %s "$LOG"; }
since() { tail -c +$(($1 + 1)) "$LOG" | tr -d '\r\000'; }
# --- the device API (login; health; the guarded injection) ---
api() { python3 -I - "$MC" "$KEYF" "$@" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, urllib.error, http.cookiejar
mc, key, what = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
if what == "health":
    w = json.loads(o.open(mc + "/api/health", timeout=10).read()).get("wifi_driver") or {}
    b, s = w.get("bus", {}), w.get("security", {})
    print(b.get("restarts", -1), b.get("faults", -1), s.get("restarts", -1), s.get("faults", -1), s.get("full_wipes", -1), s.get("pmksa_entries", -1), b.get("state", "?"), s.get("state", "?"))
    sys.exit(0)
s = json.loads(o.open(mc + "/api/session", timeout=10).read())
f = {"kind": what, "reason": "ADR 0065 S4 fault-isolation evidence", "seq": s["next_seq"], "owner_key": key}
if len(sys.argv) > 4:
    f["sta"] = sys.argv[4]
rq = urllib.request.Request(mc + "/api/bench/wifi-inject", urllib.parse.urlencode(f).encode(), {"Origin": mc, "X-HQ-CSRF": s["csrf"]})
try:
    print(o.open(rq, timeout=10).read().decode())
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read().decode())
PY
}
H() { api health 2>/dev/null; }   # bus_restarts bus_faults wpa_restarts wpa_faults full_wipes pmksa bus_state wpa_state
f() { echo "$1" | awk -v i="$2" '{print $i}'; }
# a reconnect that KEEPS the supplicant's PMKSA cache (an `iw disconnect` did not make the station leave at all):
# wpa_supplicant's D-Bus Reassociate on that interface
reassoc() { psudo "sh -c 'p=\$(busctl call fi.w1.wpa_supplicant1 /fi/w1/wpa_supplicant1 fi.w1.wpa_supplicant1 GetInterface s $1 | cut -d\\\" -f2); busctl call fi.w1.wpa_supplicant1 \$p fi.w1.wpa_supplicant1.Interface Reassociate'" >/dev/null 2>&1; }
# wlan0 (brcmfmac, FullMAC: no host PMKSA caching) reconnects through NetworkManager; wlan1 keeps its PMKSA (Reassociate)
recon() { if [ "$1" = wlan1 ]; then reassoc wlan1; else psudo "nmcli dev disconnect wlan0" >/dev/null 2>&1; psudo "timeout 50 nmcli -w 45 con up '$PROF' ifname wlan0" >/dev/null 2>&1; fi; }
# wait (up to $3 s) for an association line of MAC $2 since mark $1 matching $4; prints it
poll_assoc() { local t=0; while [ $t -lt "$3" ]; do local l; l=$(assoc_of "$1" "$2" | grep -a -- "$4" | tail -1); [ -n "$l" ] && { echo "$l"; return 0; }; sleep 2; t=$((t + 2)); done; return 1; }
# the USB adapter (rtw88) can wedge (interface_disabled / SCAN-FAILED -100): bounce it before a step that needs it
unwedge_a() { pi "nmcli -t -f GENERAL.STATE dev show wlan1" 2>/dev/null | grep -q "unavailable\|disconnected" || return 0
  psudo "ip link set wlan1 down; sleep 2; ip link set wlan1 up" >/dev/null 2>&1; sleep 3; psudo "timeout 70 nmcli -w 60 con up hq-iso-a" >/dev/null 2>&1; }
pi_journal() { psudo "journalctl --since '$1' -u wpa_supplicant --no-pager" 2>/dev/null | grep -a "wlan1" | grep -aE "$2" | tail -3 | cut -c1-160 | sed 's/^/  pi: /'; }
gw_ok() { pi "ping -c 2 -W 2 -I $1 10.99.0.1" >/dev/null 2>&1; }
wait_gw() { for _ in $(seq 1 ${2:-20}); do gw_ok "$1" && return 0; sleep 2; done; return 1; }
# station associations the AP logged since a mark, for one MAC: "akm pmkids how"
assoc_of() { since "$1" | grep -a "assoc RSNE" | grep -ai "sta $2" | sed -E 's/.*akm=(0x[0-9a-f]+) pmkids=([0-9]+) -> (.*) sta .*/\1 \2 \3/'; }
sae_of() { since "$1" | grep -ai "\[WPA3\] SAE $2" | grep -c "Committed\|Accepted"; }

cleanup() { psudo "nmcli con down hq-iso-a" >/dev/null 2>&1; psudo "nmcli con delete hq-iso-a" >/dev/null 2>&1; }
trap cleanup EXIT

# --- the two stations ---
PROF=$(pi "nmcli -t -f NAME con show | grep -i hookprobe | head -1")
SSID=$(psudo "nmcli -s -g 802-11-wireless.ssid con show '$PROF'"); PSK=$(psudo "nmcli -s -g 802-11-wireless-security.psk con show '$PROF'")
psudo "nmcli con up '$PROF' ifname wlan0" >/dev/null 2>&1
psudo "nmcli con delete hq-iso-a" >/dev/null 2>&1
psudo "nmcli dev set wlan1 managed yes" >/dev/null 2>&1
psudo "nmcli con add type wifi ifname wlan1 con-name hq-iso-a ssid '$SSID' wifi-sec.key-mgmt sae wifi-sec.psk '$PSK' wifi-sec.pmf required ipv4.method auto ipv4.never-default yes ipv6.method ignore connection.autoconnect yes connection.autoconnect-retries 0" >/dev/null 2>&1
psudo "timeout 70 nmcli -w 60 con up hq-iso-a" >/dev/null 2>&1
A=$(pi "cat /sys/class/net/wlan1/address"); B=$(pi "cat /sys/class/net/wlan0/address")
for _ in 1 2 3; do wait_gw wlan1 20 && break; psudo "ip link set wlan1 down; sleep 2; ip link set wlan1 up" >/dev/null 2>&1; sleep 4; psudo "timeout 70 nmcli -w 60 con up hq-iso-a" >/dev/null 2>&1; done
wait_gw wlan1 && wait_gw wlan0; chk $? "both stations joined (A=wlan1 $A SAE, B=wlan0 $B) and reach the gateway"
echo "  A: $(assoc_of "$M0" "$A" | tail -1) | B: $(assoc_of "$M0" "$B" | tail -1)"

# --- E1 + E2: an injected CMD53 timeout ---
h0=$(H); echo "  health before: $h0"
m=$(mark); echo "  inject: $(api cmd53-stall)"; sleep 6
h1=$(H); echo "  health after:  $h1"
since "$m" | grep -a "WIFI-INJECT\|WIFI-SPLIT\|EL0-WIFI.*fault\|timeout\|RxRead\|BadHdr\|rxfail" | head -6 | cut -c1-220 | sed 's/^/  /'
[ "$(f "$h1" 1)" -gt "$(f "$h0" 1)" ] && [ "$(f "$h1" 3)" = "$(f "$h0" 3)" ] && [ "$(f "$h1" 4)" = "$(f "$h0" 4)" ]
chk $? "E1 the CMD53 stall restarted the bus server (restarts $(f "$h0" 1) -> $(f "$h1" 1)) and NOT the WPA server (restarts $(f "$h0" 3) -> $(f "$h1" 3), faults $(f "$h0" 4) -> $(f "$h1" 4))"
since "$m" | grep -a "\[WIFI-SPLIT\]" | tail -1 | cut -c1-200 | sed 's/^/  /'
[ "$(f "$h1" 6)" = "$(f "$h0" 6)" ] && [ "$(f "$h0" 6)" -ge 1 ]
chk $? "E2 PMKSA entries preserved across the bus fault ($(f "$h0" 6) -> $(f "$h1" 6))"
wait_gw wlan1 15 && wait_gw wlan0 15; chk $? "both stations still reach the gateway after the bus recovery (data path resynced)"

# --- E3: a cached-PMKSA reconnect after the bus recovery ---
m=$(mark); reassoc wlan1
a=$(poll_assoc "$m" "$A" 15 "SAE") || { reassoc wlan1; a=$(poll_assoc "$m" "$A" 20 "SAE"); }
wait_gw wlan1 20; g=$?; echo "  A reconnect: $a (SAE frames: $(sae_of "$m" "$A"))"
[ $g = 0 ] && grep -q " 1 SAE (cached PMKSA)" <<<"$a" && [ "$(sae_of "$m" "$A")" = 0 ]
chk $? "E3 A re-joined from its cached PMKSA (pmkids=1, no SAE exchange) and reaches the gateway"

# --- E4: a fault on B's M2 is contained ---
h0=$(H); m=$(mark); echo "  inject: $(api wpa-station-m2 "$B")"
recon wlan0
for _ in $(seq 1 30); do h1=$(H); [ "$(f "$h1" 4)" -gt "$(f "$h0" 4)" ] && break; sleep 2; done
# B's own retry after its aborted 4-way is NetworkManager's (minutes): retry it the way a user would, every 40 s
gb=1; for _ in 1 2 3; do wait_gw wlan0 40 && { gb=0; break; }; recon wlan0; done
h1=$(H); echo "  health: $h0 -> $h1"; echo "  B after the fault: $(assoc_of "$m" "$B" | tr '\n' ';')"
since "$m" | grep -a "WIFI-INJECT\|WIFI-SPLIT\|ptk_set=" | head -6 | cut -c1-200 | sed 's/^/  /'
[ $gb = 0 ] && [ "$(f "$h1" 4)" -gt "$(f "$h0" 4)" ] && [ "$(f "$h1" 5)" = "$(f "$h0" 5)" ]
chk $? "E4 B's M2 faulted el0-wpa (faults $(f "$h0" 4) -> $(f "$h1" 4)), contained (full wipes $(f "$h0" 5) -> $(f "$h1" 5)); B retried, keyed and reaches the gateway"
m2=$(mark); reassoc wlan1
a=$(poll_assoc "$m2" "$A" 15 "SAE") || { reassoc wlan1; a=$(poll_assoc "$m2" "$A" 20 "SAE"); }
wait_gw wlan1 20; g=$?; echo "  A reconnect: $a"
[ $g = 0 ] && grep -q " 1 SAE (cached PMKSA)" <<<"$a" && wait_gw wlan1 5
chk $? "E4 A's PMKSA entry survived B's fault: A re-joined cached and stays connected"

# --- E5: a WPA-server fault ---
h0=$(H); m=$(mark); echo "  inject: $(api wpa-fault)"; sleep 4
since "$m" | grep -a "FULL WIPE\|full-wiped\|group keys generated" | head -3 | cut -c1-240 | sed 's/^/  /'
hw=$(H); echo "  health right after: $hw"
since "$m" | grep -aq "FULL WIPE: [1-9][0-9]* state page(s) + the key-transfer page zeroed"
chk $? "E5 the WPA-server fault full-wiped: state pages + key-transfer page zeroed"
sleep 3; since "$m" | grep -a "re-provisioned after the full wipe" | head -1 | cut -c1-200 | sed 's/^/  /'
since "$m" | grep -aq "full-wiped: every station deauthenticated" && since "$m" | grep -aq "re-provisioned after the full wipe: passphrase re-provisioned=true, new group keys installed=true"
chk $? "E5 every station deauthenticated, then the passphrase re-provisioned and NEW group keys installed"
T5=$(pi "date '+%Y-%m-%d %H:%M:%S'")
gb=1; for _ in 1 2 3; do wait_gw wlan0 40 && { gb=0; break; }; recon wlan0; done
echo "  B after the wipe: $(assoc_of "$m" "$B" | tr '\n' ';') (SAE frames $(sae_of "$m" "$B"))"
[ $gb = 0 ] && [ "$(f "$hw" 5)" -gt "$(f "$h0" 5)" ] && grep -q " 0 SAE (just authenticated)" <<<"$(assoc_of "$m" "$B")" && [ "$(sae_of "$m" "$B")" -ge 1 ]
chk $? "E5 B re-joined with a full SAE (pmkids=0) after the wipe (full wipes $(f "$h0" 5) -> $(f "$hw" 5))"
# A (wpa_supplicant SME, PMKSA caching) first offers its now-stale PMKID: refused (reason 49); its supplicant then drops
# the entry (PMKSA-CACHE-REMOVED when NetworkManager fails that attempt) and the autoconnect retry does a full SAE
ga=1; for _ in 1 2 3; do wait_gw wlan1 50 && { ga=0; break; }; unwedge_a; done
aa=$(assoc_of "$m" "$A"); echo "  A after the wipe: $(echo "$aa" | tr '\n' ';') (SAE frames $(sae_of "$m" "$A"))"
pi_journal "$T5" "PMKSA-CACHE-REMOVED|reason=49|TEMP-DISABLED"
# only each station's FIRST keying after the wipe matters: a later cached reconnect uses a PMKSA made after the wipe
fa=$(echo "$aa" | grep -v "reject" | head -1); fb=$(assoc_of "$m" "$B" | grep -v "reject" | head -1)
! grep -q "cached PMKSA" <<<"$fa$fb"
chk $? "E5 no station was keyed from a pre-wipe PMKSA (first keying after the wipe: A '$fa' B '$fb'; stale PMKIDs refused)"
[ $ga = 0 ] && grep -q " 0 SAE (just authenticated)" <<<"$aa" && [ "$(sae_of "$m" "$A")" -ge 1 ]
chk $? "E5 A dropped its stale PMKSA and re-joined with a full SAE (pmkids=0)"

# --- E6: throughput ---
tm=""; for k in 1 2 3; do T=$("$R/tools/diagnostics/cm5-throughput-check.sh" "$PI" auto 40 5 2>&1 | grep -a "THROUGHPUT" | tail -1); echo "  run $k: $T"; tm="$tm $(grep -o 'median [0-9.]*' <<<"$T" | cut -d' ' -f2)"; done
med=$(tr ' ' '\n' <<<"$tm" | grep . | sort -n | sed -n 2p)
awk -v m="${med:-0}" 'BEGIN{exit !(m >= 96)}'; chk $? "E6 throughput median of 3 runs ${med:-?} Mbps >= 96 (ADR 0065 baseline; runs:$tm)"

# --- E7: reconnect soak over both stations + the loop gap ---
m=$(mark); good=0
for i in $(seq 1 "$CYC"); do
  if [ $((i % 2)) = 1 ]; then ifc=wlan1; else ifc=wlan0; fi
  [ "$ifc" = wlan1 ] && unwedge_a
  timeout 90 bash -c "$(declare -f pi psudo reassoc recon); PI=$PI PS=$PS PROF=\"$PROF\" recon $ifc" >/dev/null 2>&1; sleep 2
  wait_gw "$ifc" 40 && good=$((good + 1))
done
auth=$(since "$m" | grep -a "P11-AP3 auth\]" ); na=$(grep -c . <<<"$auth"); nk=$(grep -c "ptk_set=true authorized=true" <<<"$auth")
echo "  soak: $good/$CYC reconnects reached the gateway; AP handshakes $na, keyed+authorized $nk"
[ "$good" = "$CYC" ] && [ "$na" -ge "$CYC" ] && [ "$nk" = "$na" ]
chk $? "E7 reconnect soak: $CYC cycles over both stations, every one keyed and authorized"
gap=$(since "$M0" | grep -a -o "worst_loop_gap_ms=[0-9]*" | cut -d= -f2 | sort -n | tail -1)
[ -n "$gap" ] && [ "$gap" -lt 2000 ]; chk $? "E7 [WDOG] worst_loop_gap_ms ${gap:-?} < 2000 throughout"

echo "WIFI-ISOLATION: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
