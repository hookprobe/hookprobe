#!/usr/bin/env bash
# cm5-wan6-check — G17 bench check (after a boot on the port-4 bench with `fortress-vlan-bench.sh v6up`):
#   device side (serial):  Ethernet-WAN IPv6 router seen, a delegated prefix, the LAN numbered from it;
#   router side (fortress): kea holds a PD lease, the CM5's WAN link-local answers ping6.
#   tools/diagnostics/cm5-wan6-check.sh --log SERIAL.log [--since BYTES] [--iface enp4s0.100]
set -u -o pipefail
LOG=""; SINCE=0; IF=enp4s0.100
while [ $# -gt 0 ]; do
  case "$1" in --log) LOG="$2"; shift ;; --since) SINCE="$2"; shift ;; --iface) IF="$2"; shift ;; *) echo "unknown $1" >&2; exit 2 ;; esac
  shift
done
[ -f "$LOG" ] || { echo "--log required" >&2; exit 2; }
NEW=$(tail -c +$((SINCE + 1)) "$LOG" | tr -d '\r\000')
ok=0; need=5
chk() { if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
grep -aqE '\[WAN6\] Ethernet WAN: .*router seen' <<<"$NEW"; chk $? "device: IPv6 router seen on the Ethernet WAN"
grep -aqE '\[WAN6\] DELEGATED PREFIX' <<<"$NEW"; chk $? "device: delegated prefix received"
grep -aqE '\[V6LAN\] LAN numbered' <<<"$NEW"; chk $? "device: LAN numbered from the delegated prefix (RA on the AP)"
grep -aE '\[WAN6\] (Ethernet WAN|DELEGATED)|\[V6LAN\] LAN numbered' <<<"$NEW" | tail -3 | cut -c1-170 | sed 's/^/   | /'
LEASES=/var/lib/kea/kea-leases6.csv
if sudo -n true 2>/dev/null || [ -n "${SUDO_PASS_FILE:-}" ]; then
  rs() { if [ -n "${SUDO_PASS_FILE:-}" ]; then sudo -S -p '' "$@" < "$SUDO_PASS_FILE"; else sudo "$@"; fi; }
  pd=$(rs awk -F, 'NR>1 && $7==2 {print $1"/"$9}' "$LEASES" 2>/dev/null | tail -1)
  [ -n "$pd" ]; chk $? "router: kea delegated ${pd:-nothing}"
else
  echo "BAD router: no sudo to read $LEASES"
fi
iid=$(grep -aoE 'link-local fe80::\[[0-9a-f, ]+\]' <<<"$NEW" | tail -1 | sed -E 's/.*\[([^]]*)\].*/\1/' | grep -oE '[0-9a-f]{2}' | tr -d '\n')
if [ ${#iid} -eq 16 ]; then
  ll="fe80::${iid:0:4}:${iid:4:4}:${iid:8:4}:${iid:12:4}"
  ping -6 -c 3 -W 2 "$ll%$IF" > /dev/null 2>&1; chk $? "router: ping6 $ll%$IF (the CM5 answers ND + echo on its WAN link-local)"
else
  echo "BAD router: link-local not found in the log"
fi
[ "$ok" -eq "$need" ] && { echo "WAN6-CHECK: PASS"; exit 0; } || { echo "WAN6-CHECK: FAIL ($ok/$need)"; exit 1; }
