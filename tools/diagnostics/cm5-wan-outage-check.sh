#!/usr/bin/env bash
# cm5-wan-outage-check — metal test plan J8: an ISP outage must not degrade the LAN, and the WAN must come
# back by itself. The CM5 boots while WAN DHCP is blocked (temporary nft table on the fortress, udp/67 in on
# enp4s0.100, removed on exit); during the outage the bench Pi (a Wi-Fi client) pings the AP for 60 s and
# Mission Control answers over Wi-Fi; then DHCP is unblocked and the in-loop acquisition must lease the WAN
# without a reboot (`[M-NAT0] WAN came up (in-loop DHCP`).
#   tools/diagnostics/cm5-wan-outage-check.sh <serial-log> [pi]        (needs SUDO_PASS_FILE)
set -u -o pipefail
# (no grep -q at the end of a pipe: SIGPIPE + pipefail would turn a match into a failure)
LOG="${1:?serial log}"; PI="${2:-claude@10.200.0.4}"; HERE=$(cd "$(dirname "$0")" && pwd)
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
L=$(pi "ping -c 60 -i 1 -W 1 10.99.0.1 | tail -2" 2>/dev/null); echo "  $L"
loss=$(sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p' <<<"$L"); maxrtt=$(sed -n 's#.*= [0-9.]*/[0-9.]*/\([0-9.]*\)/.*#\1#p' <<<"$L")
awk -v l="${loss:-100}" 'BEGIN{exit !(l <= 2)}'; chk $? "LAN responsive during the outage: ${loss:-?}% loss over 60 s (<= 2%)"
awk -v m="${maxrtt:-99999}" 'BEGIN{exit !(m < 1000)}'; chk $? "no stall during the outage: worst RTT ${maxrtt:-?} ms (< 1 s; the old blocking retry froze the loop ~5 s)"
code=$(pi "curl -s -o /dev/null -m 8 -w '%{http_code}' http://10.99.0.1/api/health" 2>/dev/null)
[ "$code" = 200 ] || [ "$code" = 401 ] || [ "$code" = 308 ]; chk $? "Mission Control answers over Wi-Fi during the outage (HTTP $code)"
since "$mark" | grep -a "in-loop DHCP: discovers=" >/dev/null; chk $? "the WAN is being acquired in the loop (discovers counted)"
m2=$(stat -c %s "$LOG")
unblock
wait_for "$m2" "WAN came up \(in-loop DHCP" 120; chk $? "WAN leased by the in-loop DHCP after the outage ends — no reboot"
echo "WAN-OUTAGE: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
