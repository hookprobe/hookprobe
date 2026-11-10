#!/usr/bin/env bash
# superpop-net.sh — host networking for the G19 super-PoP (run as root, after `superpop run` created the TUN).
#   superpop-net.sh [tun=hqpop0] [wan-if=<default-route interface>] [pool=100.64.0.0/10] [gw=100.64.0.1]
# Idempotent: re-running replaces the `superpop` nftables tables.
#   * TUN address + MTU (matches the PoP's advertised inner MTU, 1380)
#   * IPv4 forwarding
#   * forward policy: tunnel → internet only; never device → device; return traffic only (established)
#   * NAT (masquerade) of the inner pool out of the WAN interface
#   * TCP MSS clamp on tunnel traffic (belt and braces; devices clamp too)
set -euo pipefail
TUN="${1:-hqpop0}"
WAN="${2:-$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
POOL="${3:-100.64.0.0/10}"
GW="${4:-100.64.0.1}"
PLEN="${POOL#*/}"
[ -n "$WAN" ] || { echo "superpop-net: no WAN interface (pass it as the 2nd argument)" >&2; exit 2; }
ip link show "$TUN" >/dev/null 2>&1 || { echo "superpop-net: $TUN does not exist — start 'superpop run' first" >&2; exit 2; }

ip addr replace "$GW/$PLEN" dev "$TUN"
ip link set "$TUN" mtu 1380 up
sysctl -qw net.ipv4.ip_forward=1

nft -f - <<EOF
table inet superpop
delete table inet superpop
table inet superpop {
  chain forward {
    type filter hook forward priority 0; policy accept;
    iifname "$TUN" ip daddr $POOL counter drop comment "no device-to-device through the PoP"
    iifname "$TUN" oifname "$WAN" tcp flags syn tcp option maxseg size set rt mtu
    iifname "$TUN" oifname "$WAN" counter accept
    iifname "$WAN" oifname "$TUN" ct state established,related counter accept
    oifname "$TUN" counter drop comment "nothing unsolicited into the tunnel"
  }
}
table ip superpop_nat
delete table ip superpop_nat
table ip superpop_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $POOL oifname "$WAN" counter masquerade
  }
}
EOF
echo "superpop-net: $TUN $GW/$PLEN up (mtu 1380), forwarding on, NAT $POOL → $WAN"
