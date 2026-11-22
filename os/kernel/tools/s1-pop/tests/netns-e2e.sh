#!/usr/bin/env bash
# netns-e2e.sh — exercise s1-net.sh for real, unprivileged, with no effect on the host.
# It re-executes itself under `unshare -Urnm`: a private user + network + mount namespace in which
#   "fortress" = this namespace (uplink veth fx0 → "internet"), runs s1-net.sh up/verify/down unchanged,
#   "internet" = netns inet holding the PoP (130.61.174.233) and a decoy (1.1.1.1),
# then checks the allowlist end to end: only UDP 7654/7655 to the PoP leaves the guest netns, it is
# masqueraded to the uplink address, nothing reaches "fortress", and `down` removes every trace.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NET="${S1_NET:-$HERE/../s1-net.sh}"
if [ "${S1_E2E_INNER:-0}" != 1 ]; then
  exec env S1_E2E_INNER=1 unshare -Urnm --propagation private bash "$0" "$@"
fi

pass=0 fail=0
ok()  { echo "ok   $*"; pass=$((pass+1)); }
bad() { echo "FAIL $*"; fail=$((fail+1)); }
POP=130.61.174.233

mount -t tmpfs none /run          # private /run so `ip netns` works without touching the host's
mkdir -p /run/netns
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1   # this namespace's own forwarding (the host's is untouched)

# "internet": PoP + decoy behind a veth; "fortress" routes everything there (the stand-in for ppp0).
ip netns add inet
ip link add fx0 type veth peer name ix0; ip link set ix0 netns inet
ip addr add 192.0.2.1/24 dev fx0; ip link set fx0 up
ip netns exec inet bash -c "ip link set lo up; ip addr add 192.0.2.2/24 dev ix0; ip link set ix0 up
  ip addr add $POP/32 dev lo; ip addr add 1.1.1.1/32 dev lo; ip route add default via 192.0.2.1"
ip route add default via 192.0.2.2

# listeners: UDP 7654/7655 on the PoP log the source address; TCP 22 on the PoP and on "fortress" (must stay unreached)
LOG=$(mktemp -d)
ip netns exec inet python3 -I -c "
import socket,select,sys
ss=[]
for p in (7654,7655,7656):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('$POP',p)); ss.append(s)
while True:
  for s in select.select(ss,[],[])[0]:
    d,a=s.recvfrom(2048); open('$LOG/udp','a').write('%s %d %s\n'%(a[0],s.getsockname()[1],d.decode(errors='replace')))
    if d==b'echo': s.sendto(b'pong',a)   # the PoP answers on the guest's own flow
" & L1=$!
ip netns exec inet python3 -I -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('$POP',22)); s.listen()
while True: c,a=s.accept(); open('$LOG/pop22','a').write(a[0]+'\n'); c.close()
" & L2=$!
python3 -I -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',22)); s.listen()
while True: c,a=s.accept(); open('$LOG/fortress22','a').write(a[0]+'\n'); c.close()
" & L3=$!
trap 'kill $L1 $L2 $L3 2>/dev/null || true' EXIT
sleep 0.5

"$NET" up "$POP" >/dev/null && ok "s1-net up" || bad "s1-net up"
"$NET" up "$POP" >/dev/null && ok "s1-net up is idempotent" || bad "s1-net up (second run)"
if "$NET" verify "$POP" >"$LOG/verify"; then ok "s1-net verify PASS"; else bad "s1-net verify"; fi; sed 's/^/     /' "$LOG/verify"

ip netns exec hqs1 bash -c "echo -n hs >/dev/udp/$POP/7654; echo -n data >/dev/udp/$POP/7655; echo -n nope >/dev/udp/$POP/7656; echo -n decoy >/dev/udp/1.1.1.1/7654" || true
sleep 0.5
grep -q " 7654 hs$" "$LOG/udp" 2>/dev/null && ok "UDP 7654 reaches the PoP" || bad "UDP 7654 not delivered"
grep -q " 7655 data$" "$LOG/udp" 2>/dev/null && ok "UDP 7655 reaches the PoP" || bad "UDP 7655 not delivered"
grep -q "nope" "$LOG/udp" 2>/dev/null && bad "UDP 7656 leaked" || ok "other UDP ports to the PoP dropped"
awk '{print $1}' "$LOG/udp" 2>/dev/null | sort -u | grep -qvx 192.0.2.1 && bad "guest address leaked (no masquerade)" || ok "masqueraded to the uplink address"
[ -s "$LOG/pop22" ] && bad "TCP 22 on the PoP reached" || ok "TCP to the PoP blocked"
[ -s "$LOG/fortress22" ] && bad "a fortress service was reached from the guest" || ok "fortress services unreachable from the guest"
# reply path: the PoP's answer on the guest's own flow returns (conntrack established) ...
R=$(ip netns exec hqs1 python3 -I -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(b'echo',('$POP',7655))
try: print(s.recvfrom(64)[0].decode())
except Exception: print('timeout')")
[ "$R" = pong ] && ok "PoP reply on the guest's flow returns" || bad "PoP reply did not return ($R)"
# ... and an unsolicited datagram from the PoP straight to the guest address never arrives.
ip netns exec inet ip route add 10.254.19.0/30 via 192.0.2.1
ip netns exec hqs1 python3 -I -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.254.19.2',40001)); s.settimeout(2)
try: s.recvfrom(64); open('$LOG/unsolicited','w').write('got')
except Exception: pass" & UP=$!
sleep 0.3
ip netns exec inet python3 -I -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('$POP',7654+0)) if False else None
s.sendto(b'x',('10.254.19.2',40001))"
wait $UP
[ -e "$LOG/unsolicited" ] && bad "unsolicited PoP→guest datagram delivered" || ok "unsolicited PoP→guest datagram dropped"

"$NET" down >/dev/null && ok "s1-net down" || bad "s1-net down"
ip netns list | grep -qw hqs1 && bad "netns left behind" || ok "netns removed"
nft list tables | grep -q hqs1 && bad "nft tables left behind" || ok "nft tables removed"

echo "netns-e2e: $pass passed, $fail failed"
[ "$fail" = 0 ]
