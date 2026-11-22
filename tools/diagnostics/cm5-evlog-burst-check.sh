#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Pre-soak item 2 on metal: the evidence log under a detection burst (> 20 in 5 s). Bench image EVB = main + the
# bench-only `evlog-burst-N` injector (wifi-inject). PASS = every synthetic detection is either sealed to the eMMC
# log or counted in `dropped` (written + dropped deltas account for all of them), a 40-burst loses nothing, the AP
# loop never stalls (worst gap < 2 s), the log reopens after a reboot with the burst records, no panic.
# Ends on am35B. No sudo.
J="${IMG_DIR:?dir holding img<NAME>/heqk8.img + img<NAME>.bid}"; MC=https://192.168.200.146; S=~/heqk-metal-logs/20261108-relay-serial.log
K=~/hookprobe/os/build/generated/cm5-heqk/hookprobe-heqk-cm5-74cb1a9-zerolinux-APMC-VLAN.img.owner-key
UP="python3 -I $HOME/wt-np2/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $K --insecure --sign-key $HOME/heqk-owner-ca/bench-owner.key"
ok=0; n=0; chk() { n=$((n+1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok+1)); else echo "BAD $2"; fi; }
since() { tail -c +$(($1 + 1)) "$S" | tr -d '\r\000'; }
wait_for() { local t=0; while [ $t -lt "$3" ]; do since "$1" | grep -aE "$2" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }
[ "$(find "$S" -mmin -2 | wc -l)" = 1 ] || { echo "serial capture is not running — stop"; exit 1; }
inject() { python3 -I - "$MC" "$K" "$1" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, urllib.error, http.cookiejar
mc, key, kind = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
s = json.loads(o.open(mc + "/api/session", timeout=10).read())
f = {"kind": kind, "reason": "pre-soak evlog burst evidence", "seq": s["next_seq"], "owner_key": key}
rq = urllib.request.Request(mc + "/api/bench/wifi-inject", urllib.parse.urlencode(f).encode(), {"Origin": mc, "X-HQ-CSRF": s["csrf"]})
try:
    print(o.open(rq, timeout=10).read().decode()[:160])
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read().decode()[:160])
PY
}
install() { local M=$(stat -c %s "$S"); echo "== $(date +%T) install $(cat $J/img$1.bid)"; local r=$($UP --type os_image --file $J/img$1/heqk8.img 2>&1 | tail -1 | cut -c1-100); echo "   $r"
  [[ "$r" == *"already running"* ]] && return 0; wait_for "$M" "\[OTA\] COMMITTED" 600; local rc=$?; sleep 90; $HOME/wt-np2/tools/diagnostics/pi-ensure-ap.sh >/dev/null 2>&1; return $rc; }
# totals from the latest "[AP-EVLOG] k detections sealed ... (W total this boot, ring R records, D not kept ...)"
totals() { since "$1" | grep -a "\[AP-EVLOG\] [0-9]* detections sealed" | tail -1 | sed -E 's/.*\(([0-9]+) total this boot, ring ([0-9]+) records, ([0-9]+) not kept.*/\1 \2 \3/'; }
burst() { # <N> <label>
  local N=$1 M=$(stat -c %s "$S"); read -r w0 r0 d0 <<<"$(totals 0)"; w0=${w0:-0}; d0=${d0:-0}
  local r; r=$(inject "evlog-burst-$N"); echo "   inject: $r"
  # the leftover batch is sealed by the heartbeat flush (<= 60 s pacing with a clock); wait for the next EVLOG line
  wait_for "$M" "\[AP-EVLOG\] [0-9]* detections sealed" 120; sleep 2
  read -r w1 r1 d1 <<<"$(totals "$M")"; w1=${w1:-0}; d1=${d1:-0}
  local dw=$((w1 - w0)) dd=$((d1 - d0)); echo "   $2: written +$dw dropped +$dd (ring now $r1 records)"
  since "$M" | grep -a "\[BENCH\] evlog-burst\|\[AP-EVLOG\]" | head -4 | cut -c1-200
  DW=$dw; DD=$dd
}
install EVB; chk $? "EVB committed"
sleep 30; M0=$(stat -c %s "$S")
echo "== burst of 40 (two full batches in one drain)"; burst 40 "N=40"
[ $((DW + DD)) -ge 40 ] && [ "$DD" = 0 ]; chk $? "40 detections in one burst: all sealed, none dropped (written +$DW, dropped +$DD)"
sleep 10
echo "== burst of 60 (over the paced write rate)"; burst 60 "N=60"
[ $((DW + DD)) -ge 60 ] && [ "$DD" -ge 1 ] && [ "$DD" -le 20 ]; chk $? "60 in one burst: every one sealed or counted (written +$DW + dropped +$DD >= 60), drops bounded by the pacing"
RING=$(totals "$M0" | awk '{print $2}'); echo "   ring before reboot: $RING records"
gap=$(since "$M0" | grep -a "\[WDOG\] armed\|worst_loop_gap_ms" | tail -1 | grep -o "worst_loop_gap_ms=[0-9]*" | cut -d= -f2); echo "   worst loop gap: ${gap} ms"
[ "${gap:-99999}" -lt 2000 ]; chk $? "the AP loop never stalled during the bursts (worst gap < 2 s)"
! since "$M0" | grep -aE "^\[PANIC\]|\[CRASH\] the previous|Sync/SPx" >/dev/null; chk $? "no panic / crash"
echo "== reboot: the sealed log reopens with the burst records"
M2=$(stat -c %s "$S"); install AM35B; chk $? "bench restored to am35B (reboot)"
kept=$(since "$M2" | grep -a "\[AP-EVLOG\] sealed evidence log" | tail -1 | grep -o "[0-9]* records" | head -1 | cut -d' ' -f1); echo "   reopened: $kept records (before: $RING)"
[ -n "$kept" ] && [ -n "$RING" ] && [ "$kept" -ge "$RING" ]; chk $? "after the reboot the log holds every record written in the bursts"
echo "EVLOG-BURST-METAL: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
