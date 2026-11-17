#!/usr/bin/env bash
# ADR 0065 Wi-Fi split — the CUSTOMER CLAIMS, each backed by a measurement on CM5 metal (bench `wifi-inject` image).
#   C1 Wi-Fi recovers without losing authentication state — CMD53 timeout; WPA server alive, PMKSA kept; data-path outage
#   C2 other devices remain connected — B's handshake faults while A carries continuous traffic (loss, longest gap)
#   C3 faster reconnect — cached-PMKSA reconnect vs full SAE, N each, timed on the client (median / p90)
#   C4 security isolation — the bus server tries to read el0-wpa's image + state pages (PMKSA cache): must FAULT
#   C5 reliable recovery — repeated bus faults (bounded per-fault outage, no WPA restart) and a fault burst that
#      escalates to a firmware reload (bounded recovery, PMKSA kept); loop gap throughout
#   C6 stability — a multi-hour soak: traffic on both stations, periodic reconnects, faults, throughput samples
# Two stations only (the bench Pi's two radios: A = wlan1 USB rtw88, B = wlan0 onboard) — multi-client means two.
# usage: cm5-wifi-claims-check.sh <serial-log> <owner-key-file> [mc-url] [pi] [soak-hours]   (needs PI_SUDO_FILE)
#   ONLY=C3 (etc.) runs one claim; SOAK_H=0 skips C6.
set -u
LOG="${1:?serial log}"; KEYF="${2:?owner key file}"; MC="${3:-https://192.168.200.146}"; PI="${4:-claude@10.200.0.4}"
SOAK_H="${SOAK_H:-${5:-2}}"; PS="${PI_SUDO_FILE:?PI_SUDO_FILE}"; R=$(cd "$(dirname "$0")/../.." && pwd)
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
# After a failed 4-way NetworkManager marks the profile need-auth and, with no secrets agent on the bench Pi, fails it
# ("no-secrets", metal 2026-11-17 C2): the PSK goes in through a 0600 passwd-file, removed right after.
recon() { if [ "$1" = wlan1 ]; then dbus_cycle wlan1; else psudo "nmcli dev disconnect wlan0" >/dev/null 2>&1
  pi "umask 077; printf '802-11-wireless-security.psk:%s\n' '$PSK' > /tmp/hq-pw"
  psudo "timeout 50 nmcli -w 45 con up '$PROF' ifname wlan0 passwd-file /tmp/hq-pw" >/dev/null 2>&1; pi "shred -u /tmp/hq-pw 2>/dev/null || rm -f /tmp/hq-pw"; fi; }
# wait (up to $3 s) for an association line of MAC $2 since mark $1 matching $4; prints it
poll_assoc() { local t=0; while [ $t -lt "$3" ]; do local l; l=$(assoc_of "$1" "$2" | grep -a -- "$4" | tail -1); [ -n "$l" ] && { echo "$l"; return 0; }; sleep 2; t=$((t + 2)); done; return 1; }
# the USB adapter (rtw88) can wedge (interface_disabled / SCAN-FAILED -100): bounce it before a step that needs it
unwedge_a() { pi "nmcli -t -f GENERAL.STATE dev show wlan1" 2>/dev/null | grep -q "unavailable\|disconnected" || return 0
  psudo "ip link set wlan1 down; sleep 2; ip link set wlan1 up" >/dev/null 2>&1; sleep 3; psudo "timeout 70 nmcli -w 60 con up hq-iso-a" >/dev/null 2>&1; }
pi_journal() { psudo "journalctl --since '$1' -u wpa_supplicant --no-pager" 2>/dev/null | grep -a "wlan1" | grep -aE "$2" | tail -3 | cut -c1-160 | sed 's/^/  pi: /'; }
# a forced leave + rejoin that keeps the PMKSA cache (Reassociate was a no-op in ~1 of 3 soak cycles on wlan1)
dbus_cycle() { psudo "sh -c 'p=\$(busctl call fi.w1.wpa_supplicant1 /fi/w1/wpa_supplicant1 fi.w1.wpa_supplicant1 GetInterface s $1 | cut -d\\\" -f2); busctl call fi.w1.wpa_supplicant1 \$p fi.w1.wpa_supplicant1.Interface Disconnect; sleep 1; busctl call fi.w1.wpa_supplicant1 \$p fi.w1.wpa_supplicant1.Interface Reconnect'" >/dev/null 2>&1; }
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
run() { [ "${ONLY:-}" != P53 ] && { [ -z "${ONLY:-}" ] || [ "$ONLY" = "$1" ]; }; }
# continuous traffic on a station: 5 Hz pings to the gateway for $2 s, in the background on the Pi -> /tmp/hq-ping-$1.log
ping_start() { pi "nohup timeout $2 ping -D -i 0.2 -W 1 -I $1 10.99.0.1 > /tmp/hq-ping-$1.log 2>&1 &" >/dev/null 2>&1; }
# "<sent> <received> <loss %> <longest gap between replies, ms>" of that run (sent counted from its duration)
ping_stat() { pi "cat /tmp/hq-ping-$1.log" 2>/dev/null | awk -v dur="$2" '/bytes from/ && $1 ~ /^\[[0-9]+\.[0-9]+\]$/ { gsub(/[\[\]]/, "", $1); t = $1 * 1000; if (p) { g = t - p; if (g > mg) mg = g }; p = t; r++ }
  END { s = int(dur / 0.2); printf "%d %d %.1f %d\n", s, r, (s > 0 ? 100 * (s - r) / s : 0), mg }'; }

# ================= C1: recovery without losing authentication state =================
if run C1; then
  h0=$(H); ping_start wlan1 40; ping_start wlan0 40; sleep 5
  m=$(mark); echo "  inject: $(api cmd53-stall)"; sleep 36; h1=$(H)
  sa=$(ping_stat wlan1 40); sb=$(ping_stat wlan0 40)
  echo "  health $h0 -> $h1 | A ping sent/recv/loss%/max-gap-ms: $sa | B: $sb"
  [ "$(f "$h1" 1)" -gt "$(f "$h0" 1)" ] && [ "$(f "$h1" 3)" = "$(f "$h0" 3)" ] && [ "$(f "$h1" 6)" = "$(f "$h0" 6)" ] && [ "$(f "$h0" 6)" -ge 1 ]
  chk $? "C1 CMD53 timeout: bus server restarted ($(f "$h0" 1) -> $(f "$h1" 1)), WPA server untouched (restarts $(f "$h0" 3) -> $(f "$h1" 3)), PMKSA kept ($(f "$h0" 6) -> $(f "$h1" 6))"
  ga=$(echo "$sa" | cut -d' ' -f4); gb=$(echo "$sb" | cut -d' ' -f4)
  [ "${ga:-99999}" -lt 2000 ] && [ "${gb:-99999}" -lt 2000 ] && ! since "$m" | grep -aq "station .* left"
  chk $? "C1 no station was disconnected; the data path was back within ${ga}/${gb} ms (A/B longest reply gap; bound 2000 ms)"
fi

# ================= C2: other devices remain connected =================
if run C2; then
  h0=$(H); ping_start wlan1 150; t2=$SECONDS; sleep 5
  m=$(mark); echo "  inject: $(api wpa-station-m2 "$B")"; recon wlan0
  for _ in $(seq 1 30); do h1=$(H); [ "$(f "$h1" 4)" -gt "$(f "$h0" 4)" ] && break; sleep 2; done
  gb=1; for _ in 1 2 3; do wait_gw wlan0 40 && { gb=0; break; }; recon wlan0; done
  left=$(( 152 - (SECONDS - t2) )); [ "$left" -gt 0 ] && sleep "$left"   # let A's 150-s traffic run finish
  sa=$(ping_stat wlan1 150); h1=$(H)
  echo "  A (traffic during B's fault + B's re-join) sent/recv/loss%/max-gap-ms: $sa | health $h0 -> $h1"
  echo "  C2 window: worst loop gap $(since "$m" | grep -a -o 'worst_loop_gap_ms=[0-9]*' | cut -d= -f2 | sort -n | tail -1) ms; $(since "$m" | grep -ac 'WIFI-HEAL\] firmware reload\|BSS bounce') heal reload/bounce(s); prof max: $(since "$m" | grep -a -o 'ap_poll=[0-9]*x/[0-9]*ms([0-9]*%)/max[0-9]*us' | sed 's/.*max//' | sort -n | tail -1)"
  ! since "$m" | grep -ai "station" | grep -aqi "$A left"; aleft=$?
  echo "  C2 parts: B's handshake fault counted $(f "$h0" 4) -> $(f "$h1" 4) | full wipes $(f "$h0" 5) -> $(f "$h1" 5) | B back on the gateway: $([ $gb = 0 ] && echo yes || echo NO) | A stayed associated: $([ $aleft = 0 ] && echo yes || echo NO)"
  [ "$(f "$h1" 4)" -gt "$(f "$h0" 4)" ] && [ "$(f "$h1" 5)" = "$(f "$h0" 5)" ] && [ $gb = 0 ] && [ $aleft = 0 ] \
    && awk -v l="$(echo "$sa" | cut -d' ' -f3)" -v g="$(echo "$sa" | cut -d' ' -f4)" 'BEGIN{exit !(l <= 1.0 && g < 1000)}'
  chk $? "C2 B's handshake faulted (contained, no wipe) and B re-keyed; A stayed associated with loss $(echo "$sa" | cut -d' ' -f3)% and longest gap $(echo "$sa" | cut -d' ' -f4) ms (bounds 1 %, 1000 ms)"
fi

# ================= C3: faster reconnect (cached PMKSA vs full SAE) =================
if run C3; then
  N=${C3_N:-15}
  # a standalone supplicant on wlan1 (control socket): the same client and the same commands for both kinds
  psudo "nmcli con down hq-iso-a" >/dev/null 2>&1; psudo "nmcli dev set wlan1 managed no" >/dev/null 2>&1; sleep 2
  pi "umask 077; printf 'ctrl_interface=/run/hq-claims\nsae_pwe=2\nnetwork={\n ssid=\"%s\"\n key_mgmt=SAE\n sae_password=\"%s\"\n ieee80211w=2\n}\n' '$SSID' '$PSK' > /tmp/hq-claims.conf"
  # (-f needs CONFIG_DEBUG_FILE, absent in this build: the daemon then never started — round 2. Redirect instead.)
  psudo "sh -c 'rm -f /tmp/hq-claims-sup.log; nohup wpa_supplicant -i wlan1 -D nl80211 -c /tmp/hq-claims.conf -dd -t > /tmp/hq-claims-sup.log 2>&1 & echo \$! > /run/hq-claims.pid'" >/dev/null 2>&1; sleep 8
  psudo "wpa_cli -p /run/hq-claims -i wlan1 status" 2>/dev/null | grep -q "wpa_state" || echo "  WARNING: the standalone supplicant is not answering"
  m3=$(mark)
  # on the Pi: time from `reconnect` to wpa_state=COMPLETED (4-way done), polled every 10 ms
  T=$(psudo "sh -c 'W=\"wpa_cli -p /run/hq-claims -i wlan1\"; t() { \$W disconnect >/dev/null; sleep 1; [ \"\$1\" = full ] && \$W pmksa_flush >/dev/null; a=\$(date +%s%N); \$W reconnect >/dev/null; i=0; while ! \$W status | grep -q wpa_state=COMPLETED; do sleep 0.01; i=\$((i+1)); [ \$i -gt 1500 ] && break; done; echo \$1 \$(( (\$(date +%s%N) - a) / 1000000 )); sleep 1; }; for k in \$(seq 1 $N); do t cached; t full; done'")
  pi "rm -f /tmp/hq-claims.conf"; psudo "kill \$(cat /run/hq-claims.pid)" >/dev/null 2>&1; sleep 1
  SUPLOG=$(psudo "grep -aE \"Control interface command 'RECONNECT'|SME: Trying to authenticate|Authentication request send successfully|SME: Authentication response|CTRL-EVENT-CONNECTED\" /tmp/hq-claims-sup.log")
  # what the client did on the "cached" attempts (no key material in these lines)
  echo "  supplicant: PMKSA cache tried $(psudo "grep -c 'try to use PMKSA caching' /tmp/hq-claims-sup.log") | SAE auth started $(psudo "grep -c 'SME: Trying to authenticate with' /tmp/hq-claims-sup.log") | PMKSA rejected/dropped $(psudo "grep -c 'PMKSA caching attempt rejected\|Drop PMKSA\|PMKSA-CACHE-REMOVED' /tmp/hq-claims-sup.log") | assoc reject $(psudo "grep -c 'CTRL-EVENT-ASSOC-REJECT' /tmp/hq-claims-sup.log") | auth timeout $(psudo "grep -c 'Authentication with .* timed out\|SME: Authentication timeout' /tmp/hq-claims-sup.log")"
  psudo "grep -aE 'try to use PMKSA caching|CTRL-EVENT-ASSOC-REJECT|PMKSA caching attempt rejected|SME: Trying to authenticate|CTRL-EVENT-CONNECTED|auth_alg|status_code=' /tmp/hq-claims-sup.log | head -16 | cut -c1-170" | sed 's/^/    sup: /'
  psudo "rm -f /tmp/hq-claims-sup.log" >/dev/null 2>&1
  psudo "nmcli dev set wlan1 managed yes" >/dev/null 2>&1; psudo "timeout 70 nmcli -w 60 con up hq-iso-a" >/dev/null 2>&1
  st() { echo "$T" | awk -v k="$1" '$1 == k {print $2}' | sort -n | awk '{a[NR]=$1} END {if (NR) printf "n=%d median=%d p90=%d min=%d max=%d", NR, a[int((NR+1)/2)], a[int(NR*0.9+0.999)], a[1], a[NR]}'; }
  sc=$(st cached); sf=$(st full); echo "  end-to-end reconnect (command -> 4-way complete, incl. the client's scan), ms — cached PMKSA: $sc | full SAE: $sf"
  # the claim itself, AP + air only: the client's first authentication frame SENT -> connected (the client's scan and
  # its ~0.5 s driver latency to send that frame are excluded — metal: both are client-side, identical for both kinds).
  # An attempt is "full" if any SAE (auth_type=3) response came back in it, "cached" otherwise (open auth + PMKID).
  A3=$(echo "$SUPLOG" | awk '/RECONNECT/ {inatt=1; t=0; sae=0; next} inatt && /Authentication request send successfully/ && !t {t=$1+0} inatt && /auth_type=3/ {sae=1} inatt && /CTRL-EVENT-CONNECTED/ && t {printf "%s %d\n", (sae?"full":"cached"), ($1-t)*1000; inatt=0}')
  st2() { echo "$A3" | awk -v k="$1" '$1 == k {print $2}' | sort -n | awk '{a[NR]=$1} END {if (NR) printf "n=%d median=%d p90=%d min=%d max=%d", NR, a[int((NR+1)/2)], a[int(NR*0.9+0.999)], a[1], a[NR]}'; }
  ac=$(st2 cached); af=$(st2 full); echo "  AP + air: first auth frame sent -> connected (ms) — cached PMKSA: $ac | full SAE: $af"
  mc=$(echo "$ac" | grep -o 'median=[0-9]*' | cut -d= -f2); mf=$(echo "$af" | grep -o 'median=[0-9]*' | cut -d= -f2)
  nc=$(echo "$ac" | grep -o '^n=[0-9]*' | cut -d= -f2); nf=$(echo "$af" | grep -o '^n=[0-9]*' | cut -d= -f2)
  # the AP's own clock: first authentication frame of the join (open auth or SAE commit) -> keyed + authorized. The
  # verdict uses this: the client-side interval above also counts the bench's USB client losing its first SAE commit
  # after a scan and retrying 2 s later (mac80211 "send auth (try 2/3)", metal 2026-11-17; the onboard client does not)
  J=$(since "$m3" | grep -a "join took [0-9]* ms at the AP" | sed -E 's/.*join took ([0-9]+) ms at the AP \((SAE|open-auth) .*/\2 \1/')
  st3() { echo "$J" | awk -v k="$1" '$1 == k {print $2}' | sort -n | awk '{a[NR]=$1} END {if (NR) printf "n=%d median=%d p90=%d min=%d max=%d", NR, a[int((NR+1)/2)], a[int(NR*0.9+0.999)], a[1], a[NR]}'; }
  jc=$(st3 open-auth); jf=$(st3 SAE); echo "  at the AP: first auth frame -> keyed + authorized (ms) — cached PMKSA: $jc | full SAE: $jf"
  apc=$(echo "$jc" | grep -o 'median=[0-9]*' | cut -d= -f2); apf=$(echo "$jf" | grep -o 'median=[0-9]*' | cut -d= -f2)
  njc=$(echo "$jc" | grep -o '^n=[0-9]*' | cut -d= -f2); njf=$(echo "$jf" | grep -o '^n=[0-9]*' | cut -d= -f2)
  [ "${njc:-0}" -ge $((N - 1)) ] && [ "${njf:-0}" -ge $((N - 1)) ] && [ "${apc:-99999}" -lt "${apf:-0}" ]
  chk $? "C3 at the AP, a cached-PMKSA reconnect takes ${apc:-?} ms vs ${apf:-?} ms for a full SAE (median, first auth frame -> keyed; $njc / $njf joins); client-side (auth frame sent -> connected): cached ${mc:-?} ms vs full ${mf:-?} ms ($nc / $nf)"
fi

# ================= P53: post-wipe PMKSA recovery (operator 2026-11-16; task 111) =================
# Does keeping the firmware's PMKSA list in sync with el0-wpa's cache (a) make cached reconnects fast and (b) make the
# firmware itself REJECT a stale PMKID after a wipe (status 53), so a PMKSA-caching client falls back to SAE at once?
if [ "${ONLY:-}" = P53 ]; then
  W="wpa_cli -p /run/hq-claims -i wlan1"
  sup_start() { psudo "nmcli con down hq-iso-a" >/dev/null 2>&1; psudo "nmcli dev set wlan1 managed no" >/dev/null 2>&1; sleep 2
    pi "umask 077; printf 'ctrl_interface=/run/hq-claims\nsae_pwe=2\nnetwork={\n ssid=\"%s\"\n key_mgmt=SAE\n sae_password=\"%s\"\n ieee80211w=2\n}\n' '$SSID' '$PSK' > /tmp/hq-claims.conf"
    psudo "sh -c 'rm -f /tmp/hq-p53.log; nohup wpa_supplicant -i wlan1 -D nl80211 -c /tmp/hq-claims.conf -dd -t > /tmp/hq-p53.log 2>&1 & echo \$! > /run/hq-claims.pid'" >/dev/null 2>&1; sleep 10; pi "rm -f /tmp/hq-claims.conf"; }
  sup_stop() { psudo "kill \$(cat /run/hq-claims.pid)" >/dev/null 2>&1; sleep 1; psudo "nmcli dev set wlan1 managed yes" >/dev/null 2>&1; psudo "timeout 70 nmcli -w 60 con up hq-iso-a" >/dev/null 2>&1; }
  # one reconnect (keeping the PMKSA): ms from the reconnect command to COMPLETED, polled on the Pi
  cyc() { psudo "sh -c '$W disconnect >/dev/null; sleep 1; a=\$(date +%s%N); $W reconnect >/dev/null; i=0; while ! $W status | grep -q wpa_state=COMPLETED; do sleep 0.01; i=\$((i+1)); [ \$i -gt 4000 ] && break; done; echo \$(( (\$(date +%s%N) - a) / 1000000 ))'"; }
  lg() { psudo "grep -aE '$1' /tmp/hq-p53.log" | wc -l; }
  auth_ms() { psudo "awk '/PMKSA cache entry found/ {c=1} /SME: Trying to authenticate/ {t=\$1+0; k=(c?\"cached\":\"full\"); c=0} /CTRL-EVENT-CONNECTED/ && t {printf \"%s %d\\n\", k, (\$1-t)*1000; t=0}' /tmp/hq-p53.log"; }
  # (metal 2026-11-16: keeping the firmware PMKSA list in sync made no difference and the firmware never answered a
  # stale PMKID with status 53 — the toggle was removed; this section now records post-wipe recovery as it stands)
  for mode in current; do
    echo "  --- post-wipe recovery ($mode behaviour)"
    sup_start; c0=$(lg 'CTRL-EVENT-CONNECTED'); echo "  initial connect: $c0 connection(s)"
    for k in 1 2 3 4 5; do echo "  cached reconnect $k: $(cyc) ms end-to-end"; done
    echo "  auth->connected per attempt (kind ms): $(auth_ms | tr '\n' ';')"
    r0=$(lg 'CTRL-EVENT-ASSOC-REJECT'); m=$(mark); echo "  inject: $(api wpa-fault)"; sleep 4
    t=$(cyc); r1=$(lg 'CTRL-EVENT-ASSOC-REJECT'); s53=$(lg 'CTRL-EVENT-ASSOC-REJECT.*status_code=53')
    echo "  after the wipe: reconnect took $t ms; assoc rejects $((r1 - r0)) (status 53: $s53); PMKSA dropped by the client: $(lg 'PMKSA caching attempt rejected|Drop PMKSA')"
    echo "  AP: $(since "$m" | grep -a "assoc RSNE" | grep -ai "$A" | sed -E 's/.*pmkids=([0-9]).*-> (.*) sta.*/pmkids=\1 \2/' | tr '\n' ';')"
    psudo "grep -aE 'CTRL-EVENT-ASSOC-REJECT|PMKSA caching attempt rejected|CTRL-EVENT-DISCONNECTED' /tmp/hq-p53.log | tail -4 | cut -c1-160" | sed 's/^/    sup: /'
    for k in 1 2 3; do echo "  cached reconnect after the wipe $k: $(cyc) ms"; done
    echo "  auth->connected (all, this mode): $(auth_ms | tr '\n' ';')"
    sup_stop
  done
fi

# ================= C4: security isolation =================
if run C4; then
  h0=$(H); m=$(mark); r=$(api bus-read-wpa); echo "  $r"; sleep 3; h1=$(H)
  since "$m" | grep -a "WIFI-ISOLATION\]" | tail -1 | cut -c1-260 | sed 's/^/  /'
  grep -q "image + state pages FAULT, key-transfer page empty" <<<"$r" && [ "$(f "$h1" 3)" = "$(f "$h0" 3)" ] && [ "$(f "$h1" 6)" = "$(f "$h0" 6)" ]
  chk $? "C4 the bus server cannot read el0-wpa's image or state pages (PMKSA, SAE, PMKs, group keys): both FAULT; key-transfer page empty; WPA server untouched, PMKSA kept"
  wait_gw wlan1 30 && wait_gw wlan0 30; chk $? "C4 both stations still pass traffic after the probes"
fi

# ================= C5: reliable recovery =================
if run C5; then
  # C4's isolation probes are real (intended) bus faults: let the 60-s escalation window pass first, so the spaced
  # faults below are judged on their own (metal round 4: C1 + two probes + fault 1 = an escalation at fault 2)
  [ -z "${ONLY:-}" ] && sleep 65
  K=${C5_K:-10}; h0=$(H); worst=0; ok5=0
  for k in $(seq 1 "$K"); do
    ping_start wlan1 22; ping_start wlan0 22; sleep 3; api cmd53-stall >/dev/null; sleep 21
    ga=$(ping_stat wlan1 22 | cut -d' ' -f4); gb=$(ping_stat wlan0 22 | cut -d' ' -f4)
    g=$(( ga > gb ? ga : gb )); [ "$g" -gt "$worst" ] && worst=$g; [ "$g" -lt 2000 ] && ok5=$((ok5 + 1))
    echo "  fault $k: longest reply gap A $ga ms, B $gb ms"
    sleep 10   # <= 2 faults per 60 s: below the escalation threshold
  done
  h1=$(H); echo "  health $h0 -> $h1"
  [ "$(f "$h1" 1)" -ge $(( $(f "$h0" 1) + K )) ] && [ "$(f "$h1" 3)" = "$(f "$h0" 3)" ] && [ "$(f "$h1" 6)" = "$(f "$h0" 6)" ] && [ "$ok5" = "$K" ]
  chk $? "C5 $K spaced bus faults: $K bus restarts, 0 WPA restarts, PMKSA kept; every outage < 2000 ms (worst $worst ms)"
  # a burst: 3 faults in ~10 s -> escalation to a firmware reload; measure until both stations pass traffic again
  m=$(mark); h0=$(H); t0=$(date +%s%N)
  for _ in 1 2 3; do api cmd53-stall >/dev/null; sleep 3; done
  ra=1; rb=1; for _ in $(seq 1 60); do gw_ok wlan1 && ra=0; gw_ok wlan0 && rb=0; [ $ra = 0 ] && [ $rb = 0 ] && break; sleep 2; [ $((RANDOM % 10)) = 0 ] && { recon wlan0; unwedge_a; }; done
  tr=$(( ($(date +%s%N) - t0) / 1000000 )); h1=$(H)
  since "$m" | grep -a "bus-faults\|FirmwareReload\|firmware reload\|reload" | head -3 | cut -c1-220 | sed 's/^/  /'
  echo "  burst: health $h0 -> $h1; both stations back after $tr ms"
  since "$m" | grep -aq "bus-faults" && [ $ra = 0 ] && [ $rb = 0 ] && [ "$(f "$h1" 3)" = "$(f "$h0" 3)" ]
  chk $? "C5 a burst of 3 bus faults escalated (class bus-faults, firmware reload); both stations back in $tr ms; the WPA server never restarted"
  gap=$(since "$M0" | grep -a -o "worst_loop_gap_ms=[0-9]*" | cut -d= -f2 | sort -n | tail -1)
  [ -n "$gap" ] && [ "$gap" -lt 2000 ]; chk $? "C5 [WDOG] worst_loop_gap_ms ${gap:-?} < 2000 throughout"
fi

# ================= C6: stability soak =================
# (throughput samples on wlan0: wlan1's soak profile is never-default, so "auto" picked a station with no route to
# the sink and measured 0.0 — metal 2026-11-17)
if run C6 && [ "$SOAK_H" != 0 ]; then
  end=$(( $(date +%s) + SOAK_H * 3600 )); m=$(mark); h0=$(H); i=0; rok=0; rn=0; tps=""
  while [ "$(date +%s)" -lt "$end" ]; do
    i=$((i + 1)); ping_start wlan1 290; ping_start wlan0 290
    sleep 60; if [ $((i % 2)) = 1 ]; then ifc=wlan1; mac=$A; else ifc=wlan0; mac=$B; fi
    mc=$(mark); [ "$ifc" = wlan1 ] && unwedge_a; recon "$ifc"; rn=$((rn + 1)); poll_assoc "$mc" "$mac" 30 "SAE" >/dev/null && wait_gw "$ifc" 40 && rok=$((rok + 1))
    [ $((i % 4)) = 0 ] && api cmd53-stall >/dev/null
    if [ $((i % 6)) = 0 ]; then tpo=$("$R/tools/diagnostics/cm5-throughput-check.sh" "$PI" wlan0 40 5 2>&1); tps="$tps $(grep -o 'median [0-9.]*' <<<"$tpo" | cut -d' ' -f2)"
      echo "  soak throughput sample: $(grep -E 'client interface|THROUGHPUT' <<<"$tpo" | tr '\n' ' ')"; fi
    sleep 170; echo "  soak $(date +%T): reconnects $rok/$rn | A $(ping_stat wlan1 290) | B $(ping_stat wlan0 290)"
  done
  h1=$(H); auth=$(since "$m" | grep -a "P11-AP3 auth\]"); na=$(grep -c . <<<"$auth"); nk=$(grep -c "ptk_set=true authorized=true" <<<"$auth")
  gap=$(since "$m" | grep -a -o "worst_loop_gap_ms=[0-9]*" | cut -d= -f2 | sort -n | tail -1)
  rst=$(since "$m" | grep -ac "prev_reset_was_watchdog=true\|PANIC")
  echo "  soak ${SOAK_H} h: reconnects $rok/$rn, AP handshakes $nk/$na keyed+authorized, throughput samples:$tps, health $h0 -> $h1, worst loop gap $gap ms"
  [ "$rok" = "$rn" ] && [ "$nk" = "$na" ] && [ "${gap:-99999}" -lt 2000 ] && [ "$rst" = 0 ] && [ "$(f "$h1" 3)" = "$(f "$h0" 3)" ]
  chk $? "C6 ${SOAK_H} h soak on two stations: every reconnect keyed + authorized, no WPA restart, no reset, loop gap < 2000 ms"
fi

echo "WIFI-CLAIMS: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
