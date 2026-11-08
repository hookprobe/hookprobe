#!/usr/bin/env bash
# task #26 bench on fortress port 4 (enp4s0): VLAN 100 = internet (DHCP + NAT), VLAN 200 = management.
# setup:    takes enp4s0 OUT of the OVS bridge FTS, adds enp4s0.100 / enp4s0.200, a DNS-less dnsmasq
#           for DHCP on VLAN 100, and masquerade in its own nft table `hqbench`.
# v6up:     G17 bench — IPv6 router on VLAN 100: 2001:db8:100::1/64 (documentation space, never routed
#           outward), radvd RA (M=1, the /64 on-link + SLAAC), kea DHCPv6 delegating /60s from
#           2001:db8:ff00::/48, and a route for each delegated prefix back to the client (kea hook-free:
#           the route is added by `v6route` from the lease file). Requires radvd + kea-dhcp6 (services
#           disabled; they only ever run from here).
# v6down:   stops radvd / kea and removes the IPv6 address.
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
v6up)
  mkdir -p /run/hqbench
  # keep_addr_on_down: a port down/up (the late-link test) must not flush the bench address
  sysctl -qw "net/ipv6/conf/$P.100/accept_ra=0" "net/ipv6/conf/$P.100/forwarding=1" "net/ipv6/conf/$P.100/keep_addr_on_down=1"
  ip -6 addr replace 2001:db8:100::1/64 dev $P.100
  cat > /run/hqbench/radvd.conf <<CONF
interface $P.100 {
  AdvSendAdvert on; MinRtrAdvInterval 5; MaxRtrAdvInterval 15; AdvManagedFlag on; AdvOtherConfigFlag on;
  prefix 2001:db8:100::/64 { AdvOnLink on; AdvAutonomous on; };
};
CONF
  radvd -C /run/hqbench/radvd.conf -p /run/hqbench/radvd.pid -m logfile -l /run/hqbench/radvd.log
  # kea-dhcp6 is AppArmor-confined to fixed paths: config under /etc/kea (own subdir, the package config is
  # untouched), pid /run/kea/<config-basename>.kea-dhcp6.pid, lock /run/lock/kea, leases /var/lib/kea.
  mkdir -p /etc/kea/hqbench /run/kea /run/lock/kea /var/lib/kea /var/log/kea
  cat > /etc/kea/hqbench/kea-dhcp6.conf <<CONF
{ "Dhcp6": {
    "interfaces-config": { "interfaces": [ "$P.100" ] },
    "lease-database": { "type": "memfile", "persist": true, "name": "/var/lib/kea/kea-leases6.csv" },
    "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea6-ctrl-socket" },
    "preferred-lifetime": 1800, "valid-lifetime": 3600, "renew-timer": 900, "rebind-timer": 1440,
    "subnet6": [ { "id": 1, "subnet": "2001:db8:100::/64", "interface": "$P.100",
        "pd-pools": [ { "prefix": "2001:db8:ff00::", "prefix-len": 48, "delegated-len": 60 } ] } ],
    "loggers": [ { "name": "kea-dhcp6", "output_options": [ { "output": "/var/log/kea/kea-dhcp6.log" } ], "severity": "INFO" } ]
} }
CONF
  # Run it exactly like the package unit does (User=_kea + CAP_NET_BIND_SERVICE), as a transient unit.
  chmod 755 /etc/kea/hqbench; chmod 644 /etc/kea/hqbench/kea-dhcp6.conf
  systemctl stop hqbench-kea6 2>/dev/null || true; systemctl reset-failed hqbench-kea6 2>/dev/null || true
  systemd-run --quiet --unit=hqbench-kea6 -p User=_kea -p AmbientCapabilities=CAP_NET_BIND_SERVICE \
    -p Environment=KEA_LOCKFILE_DIR=/run/lock/kea -p Environment=KEA_PIDFILE_DIR=/run/kea \
    /usr/sbin/kea-dhcp6 -c /etc/kea/hqbench/kea-dhcp6.conf
  echo "v6 bench up: $P.100 2001:db8:100::1/64, RA every 5-15 s (M=1), PD /60 from 2001:db8:ff00::/48"
  ;;
v6route)
  # route every delegated prefix in the kea lease file to the client's link-local next hop
  [ -f /var/lib/kea/kea-leases6.csv ] || { echo "no leases"; exit 0; }
  awk -F, 'NR>1 && $7==2 {print $1"/"$9}' /var/lib/kea/kea-leases6.csv | sort -u | while read -r pfx; do
    # the client's link-local: a neighbour that is not one of our own addresses (OVS mirrors can echo ours)
    own=$(ip -6 addr show dev $P.100 | awk '/inet6/ {sub("/.*","",$2); print $2}')
    nh=$(ip -6 neigh show dev $P.100 | awk '/^fe80::/ && !/router/ {print $1}' | grep -vxF "$own" | head -1)
    [ -n "$nh" ] && ip -6 route replace "$pfx" via "$nh" dev $P.100 && echo "route $pfx via $nh"
  done
  ;;
v6down)
  [ -f /run/hqbench/radvd.pid ] && kill "$(cat /run/hqbench/radvd.pid)" 2>/dev/null || true
  systemctl stop hqbench-kea6 2>/dev/null || true; systemctl reset-failed hqbench-kea6 2>/dev/null || true
  ip -6 addr del 2001:db8:100::1/64 dev $P.100 2>/dev/null || true
  rm -rf /etc/kea/hqbench
  ip -6 route flush proto boot dev $P.100 2>/dev/null || true
  echo "v6 bench down"
  ;;
teardown)
  "$0" v6down 2>/dev/null || true
  [ -f /run/hqbench/dnsmasq.pid ] && kill "$(cat /run/hqbench/dnsmasq.pid)" 2>/dev/null || true
  nft delete table ip hqbench 2>/dev/null || true
  ip link del $P.100 2>/dev/null || true
  ip link del $P.200 2>/dev/null || true
  ovs-vsctl --may-exist add-port FTS $P
  echo "bench down: $P back in FTS"; ovs-vsctl list port $P | grep -E '^(name|tag|trunks) '
  ;;
*) echo "usage: $0 setup|v6up|v6route|v6down|teardown"; exit 2 ;;
esac
