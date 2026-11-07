#!/bin/bash
#
# wan-pppoe-setup.sh — Fortress fiber WAN: PPPoE + IPv6-PD + LAN RA + WAN firewall
#
# Reproduces, idempotently, the full direct-fiber WAN stack that was originally
# built live during the Digi ISP migration (see
# products/fortress/docs/WAN-PPPOE-IPV6-VALIDATION.md). Run this when the ONT
# Ethernet is wired straight into the Fortress WAN NIC (Kaon/ISP CPE bypassed),
# instead of the default DHCP-on-NIC WAN.
#
# Sets up:
#   1. PPPoE client on the WAN NIC          -> fts-pppoe.service (ppp0)
#   2. DHCPv6-PD retry client               -> fts-dhcp6c.service (delegated /56)
#   3. LAN IPv6 RA/SLAAC via dnsmasq        -> /etc/dnsmasq.d/fts-ipv6.conf
#   4. IPv6 forwarding + accept_ra sysctls  -> /etc/sysctl.d/99-fortress-ipv6-lan.conf
#   5. PPP reconnect persistence hook       -> /etc/ppp/ip-up.d/60-fts-ipv6
#   6. WAN INPUT/FORWARD firewall           -> fts-wanguard.service (nft)
#   7. RA-guard is applied by ovs-post-setup.sh (LAN bridge OpenFlow)
#
# Secrets (PPPoE password, ISP DUID) live ONLY in the config file below and in
# /etc — they are never committed to the repo. Edit the config, then run:
#
#   sudo ./wan-pppoe-setup.sh /etc/hookprobe/wan-pppoe.conf
#   sudo ./wan-pppoe-setup.sh --uninstall
#
set -euo pipefail

CONFIG="${1:-/etc/hookprobe/wan-pppoe.conf}"

# ---- defaults (override in the config file) --------------------------------
WAN_NIC="enp1s0"          # NIC the ONT/fiber is plugged into
LAN_BRIDGE="FTS"          # OVS LAN bridge that gets the delegated /64
PPPOE_USER=""             # ISP PPPoE username (REQUIRED)
PPPOE_PASS=""             # ISP PPPoE password (REQUIRED)
PPPOE_MTU="1492"          # PPPoE MTU (1492 typical; MSS clamped to PMTU)
PD_SLA_LEN="8"            # subnet bits: /56 delegation + 8 = /64 on the bridge
                          #   /60 -> 4, /62 -> 2
PD_DUID=""                # optional: force this DHCPv6 DUID hex (e.g. the old
                          #   CPE's DUID so the ISP re-issues the same prefix).
                          #   Empty = let dhcp6c generate its own DUID-LLT.
BACKUP_IFACE="wwan0"      # LTE/backup WAN (used by wanguard match set)

log()  { echo "[wan-pppoe] $*"; }
die()  { echo "[wan-pppoe] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

# ---------------------------------------------------------------------------
uninstall() {
    log "Uninstalling PPPoE/IPv6 WAN stack..."
    systemctl disable --now fts-dhcp6c.service fts-pppoe.service fts-wanguard.service 2>/dev/null || true
    rm -f /etc/systemd/system/fts-pppoe.service \
          /etc/systemd/system/fts-dhcp6c.service \
          /etc/systemd/system/fts-wanguard.service \
          /etc/wide-dhcpv6/dhcp6c.conf \
          /etc/dnsmasq.d/fts-ipv6.conf \
          /etc/sysctl.d/99-fortress-ipv6-lan.conf \
          /etc/ppp/ip-up.d/60-fts-ipv6 \
          /etc/ppp/peers/ftth \
          /etc/NetworkManager/conf.d/99-fts-pppoe-${WAN_NIC}.conf
    nft delete table inet fortress_wanguard 2>/dev/null || true
    systemctl daemon-reload
    systemctl reload NetworkManager 2>/dev/null || true
    systemctl restart dnsmasq 2>/dev/null || true
    log "Done. (WAN NIC left unmanaged; re-enable in NetworkManager if reverting to DHCP WAN.)"
    exit 0
}
[ "${1:-}" = "--uninstall" ] && uninstall

# ---------------------------------------------------------------------------
[ -f "$CONFIG" ] || die "config not found: $CONFIG (copy wan-pppoe.conf.example)"
# shellcheck disable=SC1090
. "$CONFIG"
[ -n "$PPPOE_USER" ] || die "PPPOE_USER not set in $CONFIG"
[ -n "$PPPOE_PASS" ] || die "PPPOE_PASS not set in $CONFIG"

log "WAN NIC=$WAN_NIC  bridge=$LAN_BRIDGE  user=$PPPOE_USER  sla-len=$PD_SLA_LEN"

# 1) PPPoE -------------------------------------------------------------------
log "[1/6] PPPoE peer + service on $WAN_NIC"
install -d -m 755 /etc/ppp/peers
cat > /etc/ppp/peers/ftth <<EOF
plugin rp-pppoe.so
nic-${WAN_NIC}
user ${PPPOE_USER}
mtu ${PPPOE_MTU}
mru ${PPPOE_MTU}
noauth
nodefaultroute
persist
maxfail 0
lcp-echo-interval 20
lcp-echo-failure 3
+ipv6
EOF
chmod 600 /etc/ppp/peers/ftth

# chap/pap secrets (600 root) — credential lives here + in config only
for sec in chap-secrets pap-secrets; do
    touch "/etc/ppp/$sec"; chmod 600 "/etc/ppp/$sec"
    # replace any prior line for this user, then append
    grep -v "^\"\?${PPPOE_USER}\b" "/etc/ppp/$sec" > "/etc/ppp/$sec.tmp" 2>/dev/null || true
    mv "/etc/ppp/$sec.tmp" "/etc/ppp/$sec"
    echo "\"${PPPOE_USER}\" * \"${PPPOE_PASS}\"" >> "/etc/ppp/$sec"
    chmod 600 "/etc/ppp/$sec"
done

# keep NetworkManager off the WAN NIC (pppd owns it)
install -d -m 755 /etc/NetworkManager/conf.d
cat > "/etc/NetworkManager/conf.d/99-fts-pppoe-${WAN_NIC}.conf" <<EOF
[keyfile]
unmanaged-devices=interface-name:${WAN_NIC}
EOF

cat > /etc/systemd/system/fts-pppoe.service <<EOF
[Unit]
Description=Fortress PPPoE WAN (ftth) on ${WAN_NIC}
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStartPre=-/usr/bin/nmcli device set ${WAN_NIC} managed no
ExecStartPre=/sbin/ip link set ${WAN_NIC} up
ExecStart=/usr/sbin/pppd call ftth nodetach
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

# 2) DHCPv6-PD retry client --------------------------------------------------
log "[2/6] DHCPv6-PD client (dhcp6c) -> /64 onto $LAN_BRIDGE"
install -d -m 755 /etc/wide-dhcpv6
cat > /etc/wide-dhcpv6/dhcp6c.conf <<EOF
# Fortress DHCPv6-PD client (WIDE dhcp6c) on the fiber PPPoE WAN.
# Runs as a retry daemon (fts-dhcp6c.service): keeps soliciting until the ISP
# answers DHCPv6, then auto-delegates the first /64 of the PD to ${LAN_BRIDGE}.
interface ppp0 {
    send ia-na 0;
    send ia-pd 0;
    send rapid-commit;
    request domain-name-servers;
};

id-assoc na 0 {
};

# sla-len ${PD_SLA_LEN} assumes a /$((64 - PD_SLA_LEN)) delegation
# (/$((64 - PD_SLA_LEN)) + ${PD_SLA_LEN} = /64 on the bridge).
id-assoc pd 0 {
    prefix-interface ${LAN_BRIDGE} {
        sla-id 0;
        sla-len ${PD_SLA_LEN};
    };
};
EOF

# optional: force a specific DUID so the ISP re-issues the same prefix.
# WIDE dhcp6c duid file = 2-byte little-endian length + raw DUID bytes.
if [ -n "$PD_DUID" ]; then
    install -d -m 755 /var/lib/dhcpv6
    duid_len=$(( ${#PD_DUID} / 2 ))
    printf "$(printf '\\x%02x\\x%02x' $((duid_len & 0xff)) $(((duid_len >> 8) & 0xff)))" > /var/lib/dhcpv6/dhcp6c_duid
    # shellcheck disable=SC2059
    printf "$(echo "$PD_DUID" | sed 's/\(..\)/\\x\1/g')" >> /var/lib/dhcpv6/dhcp6c_duid
    log "      forced DUID $PD_DUID (${duid_len} bytes)"
fi

cat > /etc/systemd/system/fts-dhcp6c.service <<'EOF'
[Unit]
Description=Fortress DHCPv6-PD client (WIDE dhcp6c) on ppp0 - retry daemon
After=fts-pppoe.service fts-wanguard.service
Wants=fts-pppoe.service
[Service]
Type=simple
# -f foreground so systemd supervises; dhcp6c retransmits SOLICIT per RFC 8415
# indefinitely while no server answers, so this IS the retry loop.
ExecStart=/usr/sbin/dhcp6c -f -c /etc/wide-dhcpv6/dhcp6c.conf ppp0
Restart=always
RestartSec=15
[Install]
WantedBy=multi-user.target
EOF

# 3) LAN IPv6 RA/SLAAC via dnsmasq ------------------------------------------
log "[3/6] dnsmasq RA/SLAAC on $LAN_BRIDGE"
cat > /etc/dnsmasq.d/fts-ipv6.conf <<EOF
# LAN IPv6 — RA + SLAAC on the ${LAN_BRIDGE} bridge.
# constructor:${LAN_BRIDGE} tracks the GUA dhcp6c assigns, so RA auto-follows
# the delegated prefix across reconnects. ra-stateless = clients SLAAC their
# address; dnsmasq answers stateless DHCPv6 + RDNSS (LAN v6 DNS via the box).
# M-bit off (Android-compatible).
enable-ra
dhcp-range=::,constructor:${LAN_BRIDGE},ra-stateless
EOF

# 4) sysctls -----------------------------------------------------------------
log "[4/6] IPv6 forwarding + accept_ra sysctls"
cat > /etc/sysctl.d/99-fortress-ipv6-lan.conf <<'EOF'
# HookProbe LAN IPv6: route the delegated prefix to LAN clients.
net.ipv6.conf.all.forwarding = 1
# Keep accepting the ISP RA (default route) on the WAN PPP link even with
# forwarding on. ppp0 is recreated on reconnect, so this is ALSO reapplied by
# /etc/ppp/ip-up.d/60-fts-ipv6.
net.ipv6.conf.ppp0.accept_ra = 2
EOF
sysctl -p /etc/sysctl.d/99-fortress-ipv6-lan.conf >/dev/null 2>&1 || true

# 5) PPP reconnect hook ------------------------------------------------------
log "[5/6] PPP ip-up reconnect hook"
install -d -m 755 /etc/ppp/ip-up.d
cat > /etc/ppp/ip-up.d/60-fts-ipv6 <<'EOF'
#!/bin/sh
# HookProbe: keep WAN/LAN IPv6 working across PPP reconnects. pppd recreates
# ppp0 each connect, losing per-iface accept_ra and the dhcp6c binding.
IFACE="${PPP_IFACE:-$1}"
case "$IFACE" in
  ppp*)
    sysctl -w "net.ipv6.conf.$IFACE.accept_ra=2" >/dev/null 2>&1
    systemctl try-restart fts-dhcp6c.service >/dev/null 2>&1
    ;;
esac
exit 0
EOF
chmod 755 /etc/ppp/ip-up.d/60-fts-ipv6

# 6) WAN firewall ------------------------------------------------------------
log "[6/6] WAN guard (nft) — default-deny inbound on PPP/LTE (v4 + v6)"
install -d -m 755 /etc/hookprobe
cat > /etc/hookprobe/wanguard.nft <<EOF
# inet family => covers IPv4 AND IPv6. Public IPv6 has no NAT, so default-deny
# inbound is mandatory: every LAN device is globally routable otherwise.
table inet fortress_wanguard {
    chain input {
        type filter hook input priority -10; policy accept;
        iifname "lo" accept
        ct state established,related accept
        # DHCPv6 server->client replies (so IPv6-PD on ppp0 works)
        iifname { "ppp0", "${BACKUP_IFACE}" } udp sport 547 udp dport 546 accept
        iifname { "ppp0", "${BACKUP_IFACE}" } ct state invalid drop
        iifname { "ppp0", "${BACKUP_IFACE}" } ct state new counter drop
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
        ct state established,related accept
        iifname { "ppp0", "${BACKUP_IFACE}" } ct state invalid drop
        iifname { "ppp0", "${BACKUP_IFACE}" } ct state new counter drop
    }
    chain mssclamp {
        # PPPoE MTU ${PPPOE_MTU}: clamp forwarded TCP MSS to PMTU
        type filter hook forward priority mangle; policy accept;
        oifname "ppp0" tcp flags syn tcp option maxseg size set rt mtu
    }
}
EOF
cat > /etc/systemd/system/fts-wanguard.service <<'EOF'
[Unit]
Description=Fortress WAN guard (drop unsolicited inbound on ppp0/wwan0)
After=network-pre.target
Before=fts-pppoe.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/hookprobe/wanguard.nft
ExecStop=-/usr/sbin/nft delete table inet fortress_wanguard
[Install]
WantedBy=multi-user.target
EOF

# ---- enable + start --------------------------------------------------------
log "Enabling services..."
systemctl daemon-reload
systemctl reload NetworkManager 2>/dev/null || true
systemctl enable --now fts-wanguard.service
systemctl enable --now fts-pppoe.service
systemctl enable --now fts-dhcp6c.service
systemctl restart dnsmasq 2>/dev/null || true

log "Done. Verify: ip -br addr show ppp0 ; ip -6 addr show $LAN_BRIDGE | grep global"
log "RA-guard for the LAN bridge is applied by ovs-post-setup.sh (re-run it if needed)."
