#!/usr/bin/env bash
# vrf-g19-e2e.sh — prove deploy/setup-vrf-g19.nft + superpop-net.sh against a drop-policy hookprobe_vrf,
# unprivileged (`unshare -Urnm`), with no effect on the host.
#   "a1"   = this namespace: enp0s6 (uplink → inet), hqpop0 (stands in for the PoP TUN; a veth to netns dev)
#   "inet" = netns: the public internet (1.1.1.1, 203.0.113.10) + VCN/metadata look-alikes (10.0.1.1, 169.254.169.254)
#   "dev"  = netns: a tunnelled device at 198.18.0.2 (what the PoP would write into the TUN)
# The firewall is the hookprobe_vrf skeleton (policy drop on input + forward, established, the live UDP ports)
# with the G19 lines inserted exactly where setup-vrf-g19.nft says.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SNIP="${VRF_SNIP:-$HERE/../setup-vrf-g19.nft}"
NETSH="$HERE/../../superpop-net.sh"
if [ "${VRF_E2E_INNER:-0}" != 1 ]; then exec env VRF_E2E_INNER=1 unshare -Urnm --propagation private bash "$0" "$@"; fi

pass=0 fail=0
ok()  { echo "ok   $*"; pass=$((pass+1)); }
bad() { echo "FAIL $*"; fail=$((fail+1)); }
mount -t tmpfs none /run; mkdir -p /run/netns; ip link set lo up
sysctl -qw net.ipv4.ip_forward=1

ip netns add inet; ip netns add dev
ip link add enp0s6 type veth peer name i0; ip link set i0 netns inet
ip addr add 10.0.1.110/24 dev enp0s6; ip link set enp0s6 up
ip netns exec inet bash -c "ip link set lo up; ip addr add 10.0.1.1/24 dev i0; ip link set i0 up
  for a in 1.1.1.1 203.0.113.10 169.254.169.254; do ip addr add \$a/32 dev lo; done"
ip route add default via 10.0.1.1
ip link add hqpop0 type veth peer name d0; ip link set d0 netns dev; ip link set hqpop0 up
ip netns exec dev bash -c "ip link set lo up; ip addr add 198.18.0.2/32 dev d0; ip link set d0 up
  ip route add 198.18.0.1/32 dev d0; ip route add default via 198.18.0.1"

# hookprobe_vrf skeleton + the snippet's three blocks, at the documented positions
blk() { awk -v want="$1" '/^# ---- /{on=(index($0,want)>0); next} on && /^ +[a-z]/' "$SNIP"; }
FWD=$(blk "chain forward"); IN_EARLY=$(blk "AFTER \`iif lo accept\`"); IN_PORTS=$(blk "UDP service ports")
[ -n "$FWD" ] && [ -n "$IN_EARLY" ] && [ -n "$IN_PORTS" ] || { echo "FAIL could not extract the snippet blocks"; exit 1; }
nft -f - <<EOF
table inet hookprobe_vrf {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
$FWD
    ip saddr 172.30.0.0/24 oifname != "cni-podman*" accept
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
$IN_EARLY
    ct state established,related accept
    tcp dport 8443 accept
    udp dport { 500, 4500 } accept
$IN_PORTS
    udp dport 53 accept
    ct state invalid drop
  }
}
EOF
ok "hookprobe_vrf + G19 snippet loads"

"$NETSH" hqpop0 enp0s6 198.18.0.0/15 198.18.0.1 >/dev/null && ok "superpop-net.sh applies next to hookprobe_vrf" || bad "superpop-net.sh"

LOG=$(mktemp -d)
listen() { # <netns|-> <ip> <port> <tag>
  local pre=(); [ "$1" != - ] && pre=(ip netns exec "$1")
  "${pre[@]}" python3 -I -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('$2',$3))
while True:
  d,a=s.recvfrom(256); open('$LOG/$4','a').write(a[0]+'\n'); s.sendto(b'pong',a)" & PIDS+=($!)
}
PIDS=()
listen inet 1.1.1.1 53 dns
listen inet 203.0.113.10 9 web
listen inet 10.0.1.1 9 vcn
listen inet 169.254.169.254 80 meta
listen - 0.0.0.0 53 hostdns
listen - 0.0.0.0 7654 pophs
listen - 0.0.0.0 7655 popdata
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
sleep 0.5
send() { ip netns exec "$1" python3 -I -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1.5); s.sendto(b'x',('$2',$3))
try: s.recvfrom(64); print('reply')
except Exception: print('none')"; }

[ "$(send dev 1.1.1.1 53)" = reply ] && ok "device → internet DNS (1.1.1.1) works, reply returns" || bad "device → 1.1.1.1"
[ "$(send dev 203.0.113.10 9)" = reply ] && ok "device → internet host works" || bad "device → internet host"
grep -qx 10.0.1.110 "$LOG/web" && ok "device traffic masqueraded to the A1 address" || bad "no masquerade (saw: $(cat "$LOG/web" 2>/dev/null))"
send dev 10.0.1.1 9 >/dev/null;          [ -s "$LOG/vcn" ]     && bad "device reached the VCN" || ok "device → VCN (10.0.0.0/8) dropped"
send dev 169.254.169.254 80 >/dev/null;  [ -s "$LOG/meta" ]    && bad "device reached OCI metadata" || ok "device → metadata service dropped"
send dev 198.18.0.1 53 >/dev/null;       [ -s "$LOG/hostdns" ] && bad "device reached a host service" || ok "device → A1 host services dropped"
[ "$(send inet 10.0.1.110 7654)" = reply ] && ok "internet → PoP handshake port 7654 accepted" || bad "7654 not reachable"
[ "$(send inet 10.0.1.110 7655)" = reply ] && ok "internet → PoP data port 7655 accepted" || bad "7655 not reachable"
[ "$(send inet 10.0.1.110 7656)" = none ]  && ok "internet → other UDP ports still dropped" || bad "7656 reachable"

echo "vrf-g19-e2e: $pass passed, $fail failed"; [ "$fail" = 0 ]
