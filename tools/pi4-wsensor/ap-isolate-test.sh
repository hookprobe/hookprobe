#!/usr/bin/env bash
# ap_isolate test (A-02). Run ON the Pi, from its wlan0 client of HookProbe-Setup-R3Q1.
# ap_isolate isolates CLIENTS on the same SSID from each other, so this needs a SECOND client
# (phone/laptop) joined to the SAME SSID. From our client we try to reach that peer:
#   ap_isolate ON  -> peer unreachable (PASS: AP blocks client-to-client)
#   ap_isolate OFF -> peer reachable  (FAIL: clients can talk directly)
# Receive/normal-traffic only; no injection.
# Usage:  ap-isolate-test.sh [peer_ip]      (auto-discovers a peer on 10.99.0.0/24 if omitted)
set -uo pipefail
export PATH=$PATH:/usr/sbin:/sbin
IF=wlan0
me=$(ip -4 -o addr show "$IF" | awk '{print $4}' | cut -d/ -f1)
gw=$(ip -4 route show default dev "$IF" | awk '{print $3; exit}')
[ -n "$me" ] || { echo "wlan0 has no IPv4 — is it associated to the SSID?"; exit 2; }
ssid=$(iw dev "$IF" link | awk -F': ' '/SSID/{print $2}')
echo "our client: $me on \"$ssid\" (gw $gw)"

peer=${1:-}
if [ -z "$peer" ]; then
  echo "discovering a second client on ${me%.*}.0/24 ..."
  for h in $(seq 2 120); do ip="${me%.*}.$h"; [ "$ip" = "$me" ] && continue; [ "$ip" = "$gw" ] && continue
    ping -c1 -W1 -I "$IF" "$ip" >/dev/null 2>&1 && { peer=$ip; break; }
  done
fi
[ -n "$peer" ] || { echo "NO SECOND CLIENT FOUND. Join a phone/laptop to \"$ssid\" and re-run (or pass its IP)."; exit 3; }
echo "peer client: $peer"

icmp=FAIL; ping -c2 -W2 -I "$IF" "$peer" >/dev/null 2>&1 && icmp=OK
open=""
for p in 80 443 22 53 8080; do timeout 3 bash -c "echo >/dev/tcp/$peer/$p" 2>/dev/null && open="$open $p"; done
echo "peer ICMP: $icmp ; peer TCP open:${open:- none}"
if [ "$icmp" = OK ] || [ -n "$open" ]; then
  echo "RESULT: ap_isolate appears OFF — clients can reach each other (client-to-client NOT blocked)."
else
  echo "RESULT: ap_isolate appears ON — peer is a client but unreachable from us (client isolation works)."
fi
