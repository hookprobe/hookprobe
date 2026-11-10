#!/usr/bin/env bash
# cm5-bcast-storm-check — metal test plan J11: rule 112 (broadcast storm) is per source device.
#   1. the bench Pi sends ordinary-rate IPv4 broadcasts (UDP to 10.99.0.255, 2 per second for 20 s): no rule 112;
#   2. it floods (50 per second for 15 s): rule 112 fires, attributed to the Pi's address;
# (client ARP never reaches the IDS — the AP proxies it — so the test uses IPv4 broadcasts, which do.)
#   3. Mission Control still answers the Pi afterwards (the limit self-reverts; only broadcasts are shed).
#   tools/diagnostics/cm5-bcast-storm-check.sh <owner-key-file> [mc] [pi] [pi-ip]
set -u -o pipefail
KEY="${1:?owner key}"; MC="${2:-https://192.168.200.146}"; PI="${3:-claude@10.200.0.4}"; PIIP="${4:-10.99.0.10}"
HERE=$(cd "$(dirname "$0")" && pwd)
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
J=$(mktemp); trap 'rm -f "$J"' EXIT
storms() {
  curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
  curl -sk -m 10 -b "$J" "$MC/api/detections?limit=300" | python3 -c 'import json,sys
d=[x for x in json.load(sys.stdin).get("detections",[]) if x.get("rule_id")==1200112]
print(len(d), " ".join(sorted({x.get("src_ip") or "-" for x in d})))' 2>/dev/null
}
bcast() {   # <count> <interval-s>: UDP broadcasts to the LAN (port 9, discard) from the Pi's wlan0 address
  ssh -o BatchMode=yes "$PI" "python3 -c \"import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
s.bind(('$PIIP',0))
for i in range($1): s.sendto(b'hq-j11',('10.99.0.255',9)); time.sleep($2)\"" >/dev/null 2>&1
}
"$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1
b0=$(storms); echo "  before: $b0"
bcast 40 0.5
sleep 3; b1=$(storms); echo "  after 2 per s: $b1"
[ "${b1%% *}" = "${b0%% *}" ]; chk $? "ordinary-rate broadcasts (2 per s) never raise rule 112"
bcast 750 0.02
sleep 3; b2=$(storms); echo "  after 50 per s: $b2"
[ "${b2%% *}" -gt "${b1%% *}" ]; chk $? "a broadcast flood raises rule 112"
grep -qw "$PIIP" <<<"${b2#* }"; chk $? "the storm is attributed to the flooding device ($PIIP)"
sleep 12
code=$(ssh -o BatchMode=yes "$PI" "curl -sk -o /dev/null -m 8 -w '%{http_code}' https://10.99.0.1/api/health" 2>/dev/null)
[ "$code" = 200 ] || [ "$code" = 401 ]; chk $? "Mission Control answers the device after the flood (HTTP $code)"
echo "BCAST-STORM: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
