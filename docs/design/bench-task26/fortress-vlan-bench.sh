#!/usr/bin/env bash
# task #26 bench on fortress port 4 (enp4s0): VLAN 100 = internet (DHCP + NAT), VLAN 200 = management.
# setup:    takes enp4s0 OUT of the OVS bridge FTS, adds enp4s0.100 / enp4s0.200, a DNS-less dnsmasq
#           for DHCP on VLAN 100, and masquerade in its own nft table `hqbench`.
# teardown: removes all of it and puts enp4s0 back into FTS exactly as before (untagged, no trunks).
set -euo pipefail
P=enp4s0
case "${1:-}" in
setup)
  ovs-vsctl --if-exists del-port FTS $P
  ip link set $P up
  ip link add link $P name $P.100 type vlan id 100
  ip link add link $P name $P.200 type vlan id 200
  ip addr add 10.100.0.1/24 dev $P.100
  ip addr add 192.168.200.1/24 dev $P.200
  ip link set $P.100 up; ip link set $P.200 up
  mkdir -p /run/hqbench
  # DHCP on BOTH VLANs (VLAN 200 too, for a `mgmt=dhcp` image); each subnet its own range + router.
  dnsmasq --conf-file=/dev/null --port=0 --interface=$P.100 --interface=$P.200 --bind-interfaces --except-interface=lo \
    --dhcp-range=set:v100,10.100.0.50,10.100.0.150,10m --dhcp-option=tag:v100,option:router,10.100.0.1 \
    --dhcp-range=set:v200,192.168.200.100,192.168.200.150,10m --dhcp-option=tag:v200,option:router,192.168.200.1 \
    --dhcp-option=option:dns-server,1.1.1.1,8.8.8.8 --dhcp-leasefile=/run/hqbench/leases \
    --pid-file=/run/hqbench/dnsmasq.pid --log-dhcp --log-facility=/run/hqbench/dnsmasq.log
  nft add table ip hqbench
  nft add chain ip hqbench post '{ type nat hook postrouting priority srcnat; policy accept; }'
  nft add rule ip hqbench post ip saddr '{ 10.100.0.0/24, 192.168.200.0/24 }' oifname != '{ "enp4s0.100", "enp4s0.200" }' masquerade
  echo "bench up: $P.100 10.100.0.1/24 (DHCP .50-.150), $P.200 192.168.200.1/24"
  ;;
teardown)
  [ -f /run/hqbench/dnsmasq.pid ] && kill "$(cat /run/hqbench/dnsmasq.pid)" 2>/dev/null || true
  nft delete table ip hqbench 2>/dev/null || true
  ip link del $P.100 2>/dev/null || true
  ip link del $P.200 2>/dev/null || true
  ovs-vsctl --may-exist add-port FTS $P
  echo "bench down: $P back in FTS"; ovs-vsctl list port $P | grep -E '^(name|tag|trunks) '
  ;;
*) echo "usage: $0 setup|teardown"; exit 2 ;;
esac
