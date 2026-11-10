#!/usr/bin/env bash
# cm5-g19-check — G19 SASE tunnel on metal against the bench super-PoP (fortress: `sudo ~/superpop-bench/bench.sh start`).
# Image: built with HEQK_POP_PUB=<the PoP's public blob> and a signed POLICY.TXT `tunnel pop 10.100.0.1 split 192.168.200.1/32`.
#   1. after boot: `[G19] tunnel to the super-PoP … up` and `[G19] inner address 198.18.0.2/32 mtu 1380` on serial;
#   2. the bench Pi (a Wi-Fi client) fetches http://192.168.200.1:8099/g19.txt THROUGH the tunnel (split route);
#   3. ordinary internet traffic is unaffected (not tunnelled): https://example.com still loads;
#   4. the PoP log counts the handshake and records (when readable).
#   tools/diagnostics/cm5-g19-check.sh <serial-log> [pi] [mark]
set -u -o pipefail
LOG="${1:?serial log}"; PI="${2:-claude@10.200.0.4}"; MARK="${3:-0}"
HERE=$(cd "$(dirname "$0")" && pwd)
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
since() { tail -c +$((MARK + 1)) "$LOG" | tr -d '\r\000'; }
wait_for() { local t=0; while [ $t -lt "$2" ]; do since | grep -aE "$1" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
since | grep -a "\[G19\] POLICY" | tail -1 | sed 's/^/  /'
wait_for "\[G19\] tunnel to the super-PoP .* up" 240; chk $? "the Noise tunnel to the super-PoP is up (unicast handshake via the WAN gateway)"
wait_for "\[G19\] inner address 198\.18\.0\.2/32 mtu 1380" 60; chk $? "ASSIGN received: inner 198.18.0.2/32, mtu 1380"
since | grep -a "\[G19\]" | tail -3 | sed 's/^/  /'
"$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1
B=$(pi "curl -s -m 10 http://192.168.200.1:8099/g19.txt" 2>/dev/null)
echo "  through the tunnel: ${B:-<nothing>}"
grep -q "heqk G19 bench sink OK" <<<"$B"; chk $? "a LAN client reaches the split-route destination THROUGH the tunnel"
c=$(pi "curl -s -o /dev/null -m 10 -w '%{http_code}' https://example.com/" 2>/dev/null)
[ "$c" = 200 ]; chk $? "ordinary internet traffic is not tunnelled and still works (HTTP $c)"
P=~/superpop-bench/pop.log
if [ -r "$P" ]; then tail -5 "$P" | sed 's/^/  pop: /' | cut -c1-200; fi
echo "G19: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
