#!/usr/bin/env bash
# cm5-wan6-adversarial — G17.3: the IPv4 enforcement rules, applied to IPv6, attacked from the WAN side.
# The port-4 bench host plays the internet: it routes the CM5's delegated prefix to the CM5's WAN link-local
# (`fortress-vlan-bench.sh v6route`) and sends UNSOLICITED inbound traffic to LAN addresses. Expect:
#   - no answer reaches the attacker (default-deny inbound, stateful);
#   - the device counts it (`drop no_flow` rises in the [P11-AP3 v6] beat line);
#   - packets with a hop limit of 1 are not forwarded into the LAN (`hop` drop rises or no_flow — never delivered);
#   - the device's own WAN link-local still answers (the management of the WAN path is not broken).
#   tools/diagnostics/cm5-wan6-adversarial.sh --log SERIAL.log [--iface enp4s0.100] [--bench path/to/fortress-vlan-bench.sh]
set -u -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG=""; IF=enp4s0.100; BENCH="$HERE/../../docs/design/bench-task26/fortress-vlan-bench.sh"
while [ $# -gt 0 ]; do
  case "$1" in --log) LOG="$2"; shift ;; --iface) IF="$2"; shift ;; --bench) BENCH="$2"; shift ;; *) echo "unknown $1" >&2; exit 2 ;; esac
  shift
done
[ -f "$LOG" ] || { echo "--log required" >&2; exit 2; }
rs() { if [ -n "${SUDO_PASS_FILE:-}" ]; then sudo -S -p '' "$@" < "$SUDO_PASS_FILE"; else sudo "$@"; fi; }
v6beat() { tail -c 200000 "$LOG" | tr -d '\r\000' | grep -aE '\[P11-AP3 v6\]' | tail -1; }
field() { grep -oE "$1=[0-9]+" <<<"$2" | head -1 | cut -d= -f2; }
wait_beat() { # wait until a beat line newer than $1 appears (beats are ~5 s apart)
  local before="$1" t0; t0=$(date +%s)
  while [ "$(v6beat)" = "$before" ] && [ $(( $(date +%s) - t0 )) -lt 30 ]; do sleep 2; done
}
ok=0; need=5
chk() { if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }

out=$(rs bash "$BENCH" v6route); echo "$out" | sed 's/^/   /'
PFX=$(grep -oE 'route [0-9a-f:]+/[0-9]+' <<<"$out" | head -1 | awk '{print $2}')
[ -n "$PFX" ] || { echo "BAD no delegated prefix routed (is the CM5 leased? run cm5-wan6-check first)"; exit 1; }
BASE=${PFX%%::/*}
VICTIM="${BASE}::99"            # a LAN address inside the delegated /64
ROUTER_GUA="${BASE}::1"
B0=$(v6beat); NF0=$(field 'no_flow' "$B0"); IN0=$(field ' in' "$B0")
echo "   before: drop no_flow=${NF0:-?}"

# 1. unsolicited ICMPv6 echo + TCP SYNs to a LAN address: nothing may come back
ping -6 -c 3 -W 2 "$VICTIM" > /dev/null 2>&1; [ $? -ne 0 ]; chk $? "unsolicited ping6 to $VICTIM gets no answer"
answered=0
for p in 22 80 443 3389; do timeout 3 bash -c "</dev/tcp/$VICTIM/$p" 2>/dev/null && answered=1; done
[ $answered -eq 0 ]; chk $? "unsolicited TCP SYN to $VICTIM :22/:80/:443/:3389 — no connection"
# 2. hop limit 1 into the LAN: must never be delivered
ping -6 -c 2 -W 2 -t 1 "$VICTIM" > /dev/null 2>&1
wait_beat "$B0"
B1=$(v6beat); NF1=$(field 'no_flow' "$B1")
[ -n "$NF0" ] && [ -n "$NF1" ] && [ "$NF1" -gt "$NF0" ]; chk $? "the device counted the unsolicited inbound (drop no_flow ${NF0:-?} -> ${NF1:-?})"
# 3. the device's own WAN link-local still answers (the WAN path itself is not collateral)
own=$(ip -6 addr show dev "$IF" | awk '/inet6/ {sub("/.*","",$2); print $2}')
LL=$(ip -6 neigh show dev "$IF" | awk '/^fe80::/ && !/router/ {print $1}' | grep -vxF "$own" | head -1)
[ -n "$LL" ] && ping -6 -c 2 -W 2 "$LL%$IF" > /dev/null 2>&1; chk $? "the CM5 WAN link-local ${LL:-?} still answers"
# 4. ADR 0049 D2/D3 (observe-only scan tier): those SYNs were one-sided (no host answered) -> never counted
SO=$(grep -oE 'v6 scan \(observe-only\) over=[0-9]+' <<<"$B1" | grep -oE '[0-9]+$')
if [ -z "$SO" ]; then echo "   (image without the D2 counters — row skipped)"; ok=$((ok + 1)); else
  [ "$SO" = 0 ]; chk $? "one-sided v6 SYN sweep never counted as a scan (v6 scan over=$SO)"; fi
echo "   after:  $(grep -oE 'drop no_flow=[0-9]+ no_neigh=[0-9]+ hop=[0-9]+ src=[0-9]+' <<<"$B1")"
[ "$ok" -eq "$need" ] && { echo "WAN6-ADVERSARIAL: PASS"; exit 0; } || { echo "WAN6-ADVERSARIAL: FAIL ($ok/$need)"; exit 1; }
