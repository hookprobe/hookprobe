#!/usr/bin/env bash
# cm5-intrabss-check — G10: does station-to-station Wi-Fi traffic on the CM5 AP pass THROUGH heqk (where the IDS
# sees it), or does the radio firmware bridge it directly (an IDS bypass)?
#
# The bench Pi has two Wi-Fi adapters. Station A = the adapter NetworkManager keeps on the CM5 AP. Station B = the
# other adapter, moved into its own network namespace (otherwise Linux would deliver A<->B locally and nothing
# would cross the air), joined to the same AP with its own wpa_supplicant and a DHCP lease from heqk (busybox
# udhcpc) — heqk only relays for stations whose MAC and IP are a lease it handed out. B then pings A and
# opens TCP to A:4444 (the C2-port signature). Verdict from the device's own view (Mission Control):
#   - a 4444 detection from B's address  -> intra-BSS traffic goes through heqk (IDS sees it)       PASS
#   - B reaches A but no detection        -> the firmware bridged it (IDS bypass)                    FAIL
#   - B cannot reach A at all             -> isolation enforced and heqk does not hairpin LAN<->LAN  INFO
#
#   PI_SUDO_FILE=<0600 file> tools/diagnostics/cm5-intrabss-check.sh <owner-key-file> [pi] [mc]
# The PSK is read from NetworkManager on the Pi into a 0600 file under /run and shredded — never printed.
set -u -o pipefail
KEY="${1:?owner key file}"
PI="${2:-claude@10.200.0.4}"
MC="${3:-https://192.168.200.146}"
[ -f "${PI_SUDO_FILE:-}" ] || { echo "PI_SUDO_FILE (0600) required" >&2; exit 2; }

REMOTE=$(cat <<'EOS'
set -u
A_IF=$(ip route | awk '/^default via 10.99.0.1/ {print $5; exit}')
[ -n "$A_IF" ] || { echo "RESULT no-station-A"; exit 0; }
A_IP=$(ip -4 -br addr show "$A_IF" | awk '{print $3}' | cut -d/ -f1)
B_IF=$( [ "$A_IF" = wlan0 ] && echo wlan1 || echo wlan0 )
B_PHY=$(basename "$(readlink /sys/class/net/$B_IF/phy80211)")
CON=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$A_IF" '$2==d {print $1; exit}')
SSID=$(nmcli -s -g 802-11-wireless.ssid con show "$CON")
CONF=$(mktemp -p /run hqbss.XXXXXX); chmod 600 "$CONF"
{ echo 'ctrl_interface=/run/hqbss-wpa'; echo 'network={'; printf ' ssid="%s"\n' "$SSID"; printf ' psk="%s"\n' "$(nmcli -s -g 802-11-wireless-security.psk con show "$CON")"; echo ' key_mgmt=WPA-PSK'; echo '}'; } > "$CONF"
cleanup() {
  ip netns pids hqbss 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 1
  ip netns exec hqbss iw phy "$B_PHY" set netns 1 2>/dev/null
  ip netns del hqbss 2>/dev/null
  nmcli dev set "$B_IF" managed yes 2>/dev/null
  shred -u "$CONF" 2>/dev/null; rm -rf /run/hqbss-wpa
}
trap cleanup EXIT
nmcli dev set "$B_IF" managed no
ip netns add hqbss
iw phy "$B_PHY" set netns name hqbss
ip netns exec hqbss ip link set lo up
ip netns exec hqbss ip link set "$B_IF" up
ip netns exec hqbss wpa_supplicant -B -D nl80211 -i "$B_IF" -c "$CONF" >/dev/null
# wait for the 4-way handshake (COMPLETED), not just association — DHCP before the keys are set is lost
st=""
for _ in $(seq 1 30); do st=$(ip netns exec hqbss wpa_cli -p /run/hqbss-wpa -i "$B_IF" status 2>/dev/null | sed -n 's/^wpa_state=//p'); [ "$st" = COMPLETED ] && break; sleep 1; done
[ "$st" = COMPLETED ] || { echo "RESULT b-not-keyed ($st)"; exit 0; }
# no udhcpc hook (/run may be noexec): take the address from its log line and apply it here
B_IP=$(ip netns exec hqbss busybox udhcpc -i "$B_IF" -n -q -t 8 -T 2 -s /bin/true 2>&1 | sed -n 's/.*lease of \([0-9.]*\) obtained.*/\1/p' | tail -1)
[ -n "$B_IP" ] && ip netns exec hqbss ip addr add "$B_IP/24" dev "$B_IF"
B_IP=$(ip netns exec hqbss ip -4 -br addr show "$B_IF" | awk '{print $3}' | cut -d/ -f1)
[ -n "$B_IP" ] || { echo "RESULT b-no-lease"; exit 0; }
sleep 1
echo "A=$A_IF/$A_IP B=$B_IF/$B_PHY/$B_IP"
echo "BIP=$B_IP"
if ip netns exec hqbss ping -c 4 -W 2 "$A_IP" >/dev/null; then echo "PING ok"; else echo "PING fail"; fi
# IPv6 link-local station -> station (what mDNS AAAA records point at)
A_LL=$(ip -6 addr show dev "$A_IF" scope link | awk '/inet6/ {print $2; exit}' | cut -d/ -f1)
# B's link-local must have finished duplicate-address detection first (a tentative address cannot source pings)
for _ in $(seq 1 10); do ip netns exec hqbss ip -6 addr show dev "$B_IF" tentative | grep -q inet6 || break; sleep 1; done
P6=fail
for _ in 1 2 3; do [ -n "$A_LL" ] && ip netns exec hqbss ping -6 -c 3 -W 2 "$A_LL%$B_IF" >/dev/null && { P6=ok; break; }; sleep 1; done
echo "PING6 $P6"
for _ in 1 2 3; do ip netns exec hqbss timeout 2 bash -c "</dev/tcp/$A_IP/4444" 2>/dev/null; done
# multicast discovery (SSDP group 239.255.255.250:1900): does B's announcement reach A?
python3 - "$A_IP" > /run/hqbss-mc.out 2>&1 <<'PY' &
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 1900))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack("4s4s", socket.inet_aton("239.255.255.250"), socket.inet_aton(sys.argv[1])))
s.settimeout(8)
try:
    while True:
        d, a = s.recvfrom(2048)
        if b"hqbss-probe" in d:
            print("MCAST got from", a[0]); break
except Exception:
    print("MCAST none")
PY
sleep 1
ip netns exec hqbss python3 - "$B_IP" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(sys.argv[1]))
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
for _ in range(4):
    s.sendto(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: hqbss-probe\r\n\r\n", ("239.255.255.250", 1900))
    time.sleep(0.5)
PY
wait
cat /run/hqbss-mc.out; rm -f /run/hqbss-mc.out
echo "RESULT ran"
EOS
)
# send the sudo password only when sudo asks for one (otherwise bash would read it as a command)
if ssh -o BatchMode=yes "$PI" 'sudo -n true' 2>/dev/null; then
  OUT=$(echo "$REMOTE" | ssh -o BatchMode=yes "$PI" "sudo -n bash -s" 2>&1 | grep -E "^(A=|BIP=|PING|PING6|MCAST|RESULT)")
else
  OUT=$( (cat "$PI_SUDO_FILE"; echo "$REMOTE") | ssh -o BatchMode=yes "$PI" "sudo -S -p '' bash -s" 2>&1 | grep -E "^(A=|BIP=|PING|PING6|MCAST|RESULT)")
fi
echo "$OUT" | sed 's/^/  /'
grep -q "RESULT ran" <<<"$OUT" || { echo "INTRA-BSS: INCONCLUSIVE (setup)"; exit 2; }
B_IP=$(sed -n 's/^BIP=//p' <<<"$OUT")
sleep 3
J=$(mktemp); trap 'rm -f "$J"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
D=$(curl -sk -m 10 -b "$J" "$MC/api/detections?limit=200")
if grep -q "\"rule_id\":1200001[^}]*\"src_ip\":\"$B_IP\"" <<<"$D"; then
  echo "INTRA-BSS: PASS — station-to-station traffic went through heqk (4444 detection from $B_IP)"
  rc=0
  echo "  relay counters: $(curl -sk -m 10 -b "$J" "$MC/api/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("lan_relay"))' 2>/dev/null)"
  if grep -q "MCAST got" <<<"$OUT"; then echo "INTRA-BSS-MCAST: PASS — B's SSDP announcement reached A (discovery relay)"; else echo "INTRA-BSS-MCAST: FAIL — B's SSDP announcement never reached A"; rc=4; fi
  if grep -q "PING6 ok" <<<"$OUT"; then echo "INTRA-BSS-V6: PASS — B reached A's IPv6 link-local address through heqk"; else echo "INTRA-BSS-V6: FAIL — no IPv6 station-to-station"; rc=5; fi
  exit $rc
elif grep -q "PING ok" <<<"$OUT"; then
  echo "INTRA-BSS: FAIL — B reached A but heqk never saw it: the firmware bridged it (IDS bypass)"; exit 1
else
  echo "INTRA-BSS: INFO — B cannot reach A: isolation enforced, heqk does not forward LAN<->LAN"; exit 3
fi
