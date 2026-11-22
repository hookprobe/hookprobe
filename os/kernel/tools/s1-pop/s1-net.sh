#!/usr/bin/env bash
# s1-net.sh — the dedicated, restricted network for the S1 QEMU guest on the test host (G19 super-PoP interop).
#
#   sudo s1-net.sh up      <POP_IP>   create netns + veth + nftables allowlist (idempotent)
#   sudo s1-net.sh verify  <POP_IP>   prove the allowlist: only POP_IP UDP 7654/7655 leaves; nothing reaches the host
#   sudo s1-net.sh down               remove everything this script created
#
# Operator decision 2026-11-22 (Decision 2): an isolated guest on the test host, a dedicated restricted interface,
# outbound endpoint allowlisting, host firewall restrictions, and the host's live uplink untouched.
# POP_IP (argument or S1_POP_IP) is the PoP's public IPv4 address; there is deliberately no default.
#
# What it touches, and nothing else:
#   * netns `hqs1`, veth `hqs1-h` (host, 10.254.19.1/30) <-> `hqs1-g` (netns, 10.254.19.2/30), IPv6 off inside
#   * nft tables `inet hqs1` (forward + input filter) and `ip hqs1_nat` (masquerade of 10.254.19.2 → POP_IP only)
# It does NOT touch the uplink (e.g. PPPoE), routes, other nft/iptables tables, or ip_forward (it refuses to
# run if forwarding is off rather than turning it on).
set -euo pipefail

NS=hqs1 VH=hqs1-h VG=hqs1-g HOST_IP=10.254.19.1 GUEST_IP=10.254.19.2 PLEN=30
POP_IP="${2:-${S1_POP_IP:-}}"                  # the PoP's own address — a proxied hostname cannot carry this UDP
PORTS="7654, 7655"                             # G19 handshake, G19 data

die() { echo "s1-net: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root (sudo)"
need_pop() {
  [ -n "$POP_IP" ] || die "POP_IP required (argument or S1_POP_IP)"
  [[ "$POP_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "POP_IP must be an IPv4 literal (POLICY 'tunnel pop' is IPv4-only)"
}

up() {
  need_pop
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || die "net.ipv4.ip_forward=0 — refusing to change host routing; enable it yourself if intended"
  ip netns list | grep -qw "$NS" || ip netns add "$NS"
  if ! ip link show "$VH" >/dev/null 2>&1; then
    ip link add "$VH" type veth peer name "$VG"
    ip link set "$VG" netns "$NS"
  fi
  ip addr replace "$HOST_IP/$PLEN" dev "$VH"; ip link set "$VH" up
  ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  ip netns exec "$NS" ip addr replace "$GUEST_IP/$PLEN" dev "$VG"
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip link set "$VG" up
  ip netns exec "$NS" ip route replace default via "$HOST_IP"
  # A drop in any base chain is final, so these drops hold even if another table accepts the same packet.
  nft -f - <<EOF
table inet hqs1
delete table inet hqs1
table inet hqs1 {
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "$VH" ip saddr $GUEST_IP ip daddr $POP_IP udp dport { $PORTS } counter accept comment "S1: G19 to the test PoP only"
    iifname "$VH" counter drop comment "S1: everything else from the guest"
    oifname "$VH" ip saddr $POP_IP ct state established counter accept comment "S1: PoP replies"
    oifname "$VH" counter drop comment "S1: nothing unsolicited into the guest"
  }
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "$VH" counter drop comment "S1: the guest never reaches host services"
  }
}
table ip hqs1_nat
delete table ip hqs1_nat
table ip hqs1_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $GUEST_IP ip daddr $POP_IP counter masquerade comment "S1: egress via the default route (uplink untouched)"
  }
}
EOF
  echo "s1-net: up — netns $NS ($GUEST_IP) → only $POP_IP udp {$PORTS}"
}

verify() {
  need_pop; local fail=0
  ip netns list | grep -qw "$NS" || die "netns $NS missing — run 'up' first"
  # Only connectionless probes and short timeouts: nothing here can disturb the host.
  probe() { ip netns exec "$NS" timeout 3 bash -c "$1" >/dev/null 2>&1; }
  probe "echo >/dev/tcp/1.1.1.1/443"            && { echo "FAIL: TCP 1.1.1.1:443 reachable"; fail=1; } || echo "ok   TCP to the internet blocked"
  probe "ping -c1 -W2 1.1.1.1"                   && { echo "FAIL: ICMP to the internet"; fail=1; }     || echo "ok   ICMP to the internet blocked"
  probe "ping -c1 -W2 $HOST_IP"                  && { echo "FAIL: guest reaches the host"; fail=1; }  || echo "ok   guest cannot reach the host ($HOST_IP)"
  probe "echo >/dev/tcp/$HOST_IP/22"             && { echo "FAIL: host sshd reachable"; fail=1; } || echo "ok   host services unreachable"
  probe "echo >/dev/tcp/$POP_IP/22"              && { echo "FAIL: PoP TCP/22 reachable"; fail=1; }    || echo "ok   PoP non-G19 ports blocked"
  probe "ping6 -c1 -W2 2606:4700:4700::1111"     && { echo "FAIL: IPv6 egress"; fail=1; }             || echo "ok   IPv6 off"
  # The allowed path: send one UDP datagram to the PoP's handshake port and check the accept counter moved.
  local before after
  before=$(nft -j list chain inet hqs1 forward | grep -o '"packets": [0-9]*' | head -1 | grep -o '[0-9]*$')
  ip netns exec "$NS" bash -c "echo -n s1-verify >/dev/udp/$POP_IP/7654" 2>/dev/null || true
  sleep 1
  after=$(nft -j list chain inet hqs1 forward | grep -o '"packets": [0-9]*' | head -1 | grep -o '[0-9]*$')
  [ "${after:-0}" -gt "${before:-0}" ] && echo "ok   UDP $POP_IP:7654 forwarded (accept counter $before→$after)" \
    || { echo "FAIL: UDP to $POP_IP:7654 not forwarded — another firewall may drop it (check: nft list ruleset; iptables -S FORWARD)"; fail=1; }
  [ "$fail" = 0 ] && echo "s1-net: verify PASS" || { echo "s1-net: verify FAIL"; exit 1; }
}

down() {
  nft delete table inet hqs1 2>/dev/null || true
  nft delete table ip hqs1_nat 2>/dev/null || true
  ip link del "$VH" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  echo "s1-net: down"
}

case "${1:-}" in up) up ;; verify) verify ;; down) down ;; *) sed -n '2,8p' "$0"; exit 2 ;; esac
