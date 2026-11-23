#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Neuro 64-device slot pressure on CM5 (status register open item), synthetic stations through the real host path.
# Image SLOTS = main + bench-only neuro-slots injector (shipping set + neuro + wifi-inject). The Pi browses (1 real slot).
#  A) open hour: 70 synthetic devices -> slots fill to 64, the rest DROPPED + counted, 0 evictions (a fed device is never evicted)
#  B) the hour closes with 64 devices scored: 0 failed, close_hour timing recorded
#  C) next hour: 10 fresh devices -> 10 evictions (least recently seen, RESET_DEV), 0 dropped
#  D) /api/neuro devices_tracked 64; loop gap < 2 s; no panic. Ends on am35B.
J="${IMG_DIR:?dir holding img<NAME>/heqk8.img + img<NAME>.bid}"; MC=https://192.168.200.146; S=~/heqk-metal-logs/20261108-relay-serial.log
K=~/hookprobe/os/build/generated/cm5-heqk/hookprobe-heqk-cm5-74cb1a9-zerolinux-APMC-VLAN.img.owner-key
UP="python3 -I $HOME/wt-np2/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $K --insecure --sign-key $HOME/heqk-owner-ca/bench-owner.key"
PI=claude@10.200.0.4; pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
ok=0; n=0; chk() { n=$((n+1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok+1)); else echo "BAD $2"; fi; }
since() { tail -c +$(($1 + 1)) "$S" | tr -d '\r\000'; }
wait_for() { local t=0; while [ $t -lt "$3" ]; do since "$1" | grep -aE "$2" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }
[ "$(find "$S" -mmin -2 | wc -l)" = 1 ] || { echo "serial capture is not running — stop"; exit 1; }
py() { python3 -I - "$MC" "$K" "$@" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, urllib.error, http.cookiejar
mc, key, what = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
try:
    if what == "api":
        print(o.open(mc + "/api/neuro?limit=64", timeout=10).read().decode()); sys.exit(0)
    s = json.loads(o.open(mc + "/api/session", timeout=10).read())
    f = {"kind": what, "reason": "neuro slot pressure evidence", "seq": s["next_seq"], "owner_key": key}
    rq = urllib.request.Request(mc + "/api/bench/wifi-inject", urllib.parse.urlencode(f).encode(), {"Origin": mc, "X-HQ-CSRF": s["csrf"]})
    print(o.open(rq, timeout=20).read().decode()[:160])
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read().decode()[:160])
PY
}
install() { local M=$(stat -c %s "$S"); echo "== $(date +%T) install $(cat $J/img$1.bid)"; local r=$($UP --type os_image --file $J/img$1/heqk8.img 2>&1 | tail -1 | cut -c1-100); echo "   $r"
  [[ "$r" == *"already running"* ]] && return 0; wait_for "$M" "\[OTA\] COMMITTED" 600; local rc=$?; sleep 90; $HOME/wt-np2/tools/diagnostics/pi-ensure-ap.sh >/dev/null 2>&1; return $rc; }
num() { echo "$1" | grep -o "$2 [0-9]* -> [0-9]*\|$2 +[0-9]*" | grep -o "[0-9]*$"; }
install SLOTS || { echo "NEURO-SLOTS: FAIL (did not commit)"; install AM35B; exit 1; }
M0=$(stat -c %s "$S")
pi "nohup bash -c 'end=\$((SECONDS+6000)); while [ \$SECONDS -lt \$end ]; do for d in wikipedia.org github.com cloudflare.com; do curl -s -o /dev/null -m 8 https://\$d; sleep 4; done; done' >/dev/null 2>&1 &"
wait_for "$M0" "\[NEURO beat\].* fed=[1-9]" 600   # the clock is synced and the Pi is being observed
# A — make sure we are not within 3 min of an hour boundary (the whole burst must land in one hour)
m=$(date -u +%M); [ "$m" -ge 57 ] && sleep $(( (60 - m) * 60 + 30 ))
MA=$(stat -c %s "$S"); r=$(py neuro-slots-70-0); echo "   A: $r"; sleep 3
L=$(since "$MA" | grep -a "\[NEURO\] bench slots" | tail -1); echo "   $L" | cut -c1-220
trk=$(echo "$L" | grep -o "tracked [0-9]* -> [0-9]*" | grep -o "[0-9]*$"); drp=$(echo "$L" | grep -o "dropped +[0-9]*" | grep -o "[0-9]*$"); ev=$(echo "$L" | grep -o "evictions +[0-9]*" | grep -o "[0-9]*$")
[ "$trk" = 64 ] && [ "${drp:-0}" -gt 0 ] && [ "$ev" = 0 ]; chk $? "A: 70 synthetic devices in one open hour -> 64 slots tracked, the rest dropped+counted (+$drp), 0 evictions"
# B — the hour closes with 64 devices
H0=$(since "$MA" | grep -a "\[NEURO beat\]" | tail -1 | grep -o "hours=[0-9]*" | cut -d= -f2)
echo "== waiting for the hour close (hours ${H0} -> $((H0+1)))"
wait_for "$MA" "\[NEURO beat\].* hours=$((H0+1)) " 4000; chk $? "B: the hour closed"
sleep 70
B=$(since "$MA" | grep -a "\[NEURO beat\]" | tail -1); echo "   $B" | cut -c1-200
X=$(since "$MA" | grep -a "\[NEURO exc\]" | tail -1); echo "   $X" | cut -c1-200
echo "$B" | grep -q "failed=0"; chk $? "B: 0 failed hours with 64 devices"
# C — next hour, 10 fresh devices evict the least recently seen
MC2=$(stat -c %s "$S"); r=$(py neuro-slots-10-1000); echo "   C: $r"; sleep 3
L=$(since "$MC2" | grep -a "\[NEURO\] bench slots" | tail -1); echo "   $L" | cut -c1-220
ev=$(echo "$L" | grep -o "evictions +[0-9]*" | grep -o "[0-9]*$"); drp=$(echo "$L" | grep -o "dropped +[0-9]*" | grep -o "[0-9]*$")
[ "$ev" = 10 ] && [ "$drp" = 0 ]; chk $? "C: 10 fresh devices in the next hour -> 10 evictions (RESET_DEV), 0 dropped"
A=$(py api); echo "$A" > $J/slots-api.json
python3 -I -c "import json,sys; j=json.load(open('$J/slots-api.json')); print('   api devices_tracked', j['devices_tracked'], 'evictions', j['counters']['slot_evictions'], 'hours_failed', j['counters']['hours_failed'], 'records', len(j['evidence'])); sys.exit(0 if j['devices_tracked']==64 and j['counters']['hours_failed']==0 else 1)"; chk $? "D: /api/neuro devices_tracked 64, 0 failed hours"
gap=$(since "$M0" | grep -a "\[WDOG\] armed" | tail -1 | grep -o "worst_loop_gap_ms=[0-9]*" | cut -d= -f2); echo "   worst loop gap ${gap} ms"
[ "${gap:-99999}" -lt 2000 ]; chk $? "D: AP loop never stalled (< 2 s)"
! since "$M0" | grep -aE "^\[PANIC\]|\[CRASH\] the previous|Sync/SPx" >/dev/null; chk $? "D: no panic / crash"
install AM35B; chk $? "bench restored to am35B"
echo "NEURO-SLOTS-METAL: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
