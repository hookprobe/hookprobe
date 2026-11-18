#!/usr/bin/env bash
# cm5-wan-outage-check — metal test plan J8: an ISP outage must not degrade the LAN, and the WAN must come
# back by itself. The CM5 boots while WAN DHCP is blocked (temporary nft table on the fortress, udp/67 in on
# enp4s0.100, removed on exit); during the outage the bench Pi (a Wi-Fi client) asks the AP's DNS (Shield) for 60 s
# and Mission Control answers (over the management address: with a management VLAN it is not served on Wi-Fi, G12-M,
# so an HTTP probe of 10.99.0.1 from Wi-Fi tested nothing); then DHCP is unblocked and the in-loop acquisition must lease the WAN
# without a reboot (`[M-NAT0] WAN came up (in-loop DHCP`).
#   tools/diagnostics/cm5-wan-outage-check.sh <serial-log> [pi]        (needs SUDO_PASS_FILE)
set -u -o pipefail
# (no grep -q at the end of a pipe: SIGPIPE + pipefail would turn a match into a failure)
LOG="${1:?serial log}"; PI="${2:-claude@10.200.0.4}"; MC="${MC:-https://192.168.200.146}"; HERE=$(cd "$(dirname "$0")" && pwd)
SP="${SUDO_PASS_FILE:?SUDO_PASS_FILE}"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
since() { tail -c +$(($1 + 1)) "$LOG" | tr -d '\r\000'; }
wait_for() { local t=0; while [ $t -lt "$3" ]; do since "$1" | grep -aE "$2" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
unblock() { sudo -S -p '' nft delete table inet hqoutage < "$SP" 2>/dev/null || true; }
trap unblock EXIT

NFT=$(mktemp); printf 'table inet hqoutage {\n chain input { type filter hook input priority -10; iifname "enp4s0.100" udp dport 67 drop; }\n}\n' > "$NFT"
sudo -S -p '' nft -f "$NFT" < "$SP"; rm -f "$NFT"
sudo -S -p '' nft list table inet hqoutage < "$SP" >/dev/null 2>&1; chk $? "WAN DHCP blocked (simulated ISP outage)"
mark=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1
wait_for "$mark" "\[P11-AP3\] persistent WPA2 AP serve loop up" 240; chk $? "the AP comes up although the WAN has no lease"
"$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1
sleep 20
# responsiveness: 60 DNS queries to the AP, one a second, for a name Shield blocks (answered by the AP loop itself:
# no upstream needed during the outage; the AP does not answer ICMP echo on its LAN IP). Each line: "<ms>" or "fail".
L=$(pi "for k in \$(seq 1 60); do t0=\$(date +%s%N); if dig +short +time=2 +tries=1 @10.99.0.1 doubleclick.net A >/dev/null 2>&1; then echo \$(( (\$(date +%s%N) - t0) / 1000000 )); else echo fail; fi; sleep 1; done" 2>/dev/null)
fails=$(grep -c '^fail' <<<"$L"); worst=$(grep -v '^fail' <<<"$L" | sort -n | tail -1)
echo "  60 DNS probes to the AP: $fails failed, worst ${worst:-?} ms"
[ "$fails" -le 1 ]; chk $? "LAN responsive during the outage: $fails of 60 DNS probes failed (<= 1)"
[ "${worst:-99999}" -lt 1000 ]; chk $? "no stall during the outage: worst response ${worst} ms (< 1 s; the old blocking retry froze the loop ~5 s)"
code=$(curl -sk -o /dev/null -m 8 -w '%{http_code}' "$MC/api/health" 2>/dev/null)
[ "$code" = 200 ] || [ "$code" = 401 ] || [ "$code" = 308 ]; chk $? "Mission Control answers during the WAN outage (management address, HTTP $code)"
since "$mark" | grep -a "in-loop DHCP: discovers=" >/dev/null; chk $? "the WAN is being acquired in the loop (discovers counted)"
m2=$(stat -c %s "$LOG")
unblock
wait_for "$m2" "WAN came up \(in-loop DHCP" 120; chk $? "WAN leased by the in-loop DHCP after the outage ends — no reboot"
echo "WAN-OUTAGE: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
