#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Neuro on metal, fault injection (bench am36F = neuro + wifi-inject): el0-neuro faulted through its supervised path —
# once, then a rapid burst — while the Pi keeps browsing through the AP. PASS = every fault contained + journaled, the
# server back after each, hold-off honoured in the burst, Neuro keeps receiving events afterwards, the AP never stalls
# (worst loop gap < 2 s), no panic. Ends on am35B. No sudo.
J=/home/andrei/.claude/jobs/a53f1b84/tmp; MC=https://192.168.200.146; S=~/heqk-metal-logs/20261108-relay-serial.log
K=~/hookprobe/os/build/generated/cm5-heqk/hookprobe-heqk-cm5-74cb1a9-zerolinux-APMC-VLAN.img.owner-key
UP="python3 -I $HOME/wt-np2/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $K --insecure --sign-key $HOME/heqk-owner-ca/bench-owner.key"
PI=claude@10.200.0.4; pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
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
f = {"kind": kind, "reason": "Neuro metal fault evidence", "seq": s["next_seq"], "owner_key": key}
rq = urllib.request.Request(mc + "/api/bench/wifi-inject", urllib.parse.urlencode(f).encode(), {"Origin": mc, "X-HQ-CSRF": s["csrf"]})
try:
    print(o.open(rq, timeout=10).read().decode()[:160])
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read().decode()[:160])
PY
}
install() { local M=$(stat -c %s "$S"); echo "== $(date +%T) install $(cat $J/img$1.bid)"; local r=$($UP --type os_image --file $J/img$1/heqk8.img 2>&1 | tail -1 | cut -c1-100); echo "   $r"
  [[ "$r" == *"already running"* ]] && return 0; wait_for "$M" "\[OTA\] COMMITTED" 600; local rc=$?; sleep 90; $HOME/wt-np2/tools/diagnostics/pi-ensure-ap.sh >/dev/null 2>&1; return $rc; }
traffic() { pi "nohup bash -c 'end=\$((\$(date +%s)+$1)); while [ \$(date +%s) -lt \$end ]; do for d in google.com wikipedia.org github.com cloudflare.com example.org mozilla.org; do getent ahosts \$d >/dev/null; curl -s -o /dev/null -m 6 https://\$d; done; done' >/dev/null 2>&1 &"; }
install AM36G; chk $? "am36G committed"
traffic 600; sleep 60; M0=$(stat -c %s "$S")
fed0=$(since 0 | grep -a "\[NEURO beat\]" | tail -1 | grep -o "fed=[0-9]*" | cut -d= -f2)
echo "== one fault"; r=$(inject neuro-fault); echo "   $r"; [[ "$r" == *"contained"* ]]; chk $? "el0-neuro faulted: contained + reset"
sleep 3; since "$M0" | grep -a "\[NEURO\] bench fault\|\[SUPERV\].*neuro\|el0-neuro" | head -4 | cut -c1-200
c=$(pi "curl -s -o /dev/null -m 8 -w '%{http_code}' https://example.com"); [ "$c" = 200 ]; chk $? "the AP still forwards right after the fault (Pi -> example.com: $c; example.org is on the bench Shield blocklist)"
echo "== burst of 10 (hold-off)"; M1=$(stat -c %s "$S"); held=0; faulted=0
for i in $(seq 1 10); do r=$(inject neuro-fault); [[ "$r" == *"held off"* ]] && held=$((held+1)); [[ "$r" == *"contained"* ]] && faulted=$((faulted+1)); sleep 0.2; done
echo "   faulted=$faulted held-off=$held"; [ "$held" -ge 1 ]; chk $? "the supervisor held el0-neuro off during the burst (restart backoff)"
sleep 120
fed1=$(since "$M1" | grep -a "\[NEURO beat\]" | tail -1 | grep -o "fed=[0-9]*" | cut -d= -f2); echo "   [NEURO beat] fed before=$fed0 after=$fed1"
since "$M1" | grep -a "\[NEURO beat\]" | tail -1 | cut -c1-200
[ -n "$fed1" ] && [ "${fed1:-0}" -gt "${fed0:-0}" ]; chk $? "Neuro keeps receiving events after the faults (relearning from cold)"
gap=$(since "$M0" | grep -a "\[WDOG\] armed" | tail -1 | grep -o "worst_loop_gap_ms=[0-9]*" | cut -d= -f2); echo "   worst loop gap since boot ${gap} ms"
[ "${gap:-99999}" -lt 2000 ]; chk $? "the AP loop never stalled (worst gap < 2 s)"
! since "$M0" | grep -aE "^\[PANIC\]|\[CRASH\] the previous|Sync/SPx" >/dev/null; chk $? "no panic / crash"
install AM35B; chk $? "bench restored to am35B"
echo "NEURO-FAULT-METAL: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
