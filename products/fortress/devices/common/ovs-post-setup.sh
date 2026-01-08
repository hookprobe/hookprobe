#!/bin/bash
#
# ovs-post-setup.sh - OVS Post-Netplan Configuration
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This script runs AFTER netplan has created the OVS bridge and VLAN interfaces.
# It configures things netplan cannot handle:
#   - OpenFlow rules for traffic flow
#   - Port VLAN tagging (access/trunk modes)
#   - Cross-band multicast reflection for WiFi
#   - Legacy br-wifi cleanup (direct OVS mode)
#
# The heavy lifting (bridge creation, VLAN interfaces, IP assignment) is done
# by netplan/systemd-networkd for reliability and speed.
#
# Usage:
#   ./ovs-post-setup.sh setup
#   ./ovs-post-setup.sh status
#
# Version: 5.0.0
# License: AGPL-3.0
#

set -e

# ============================================================
# CONFIGURATION
# ============================================================

STATE_DIR="/var/lib/fortress"
CONFIG_DIR="/etc/hookprobe"
NETPLAN_STATE="$STATE_DIR/netplan-config.conf"
VLAN_STATE="$STATE_DIR/vlan-config.conf"
FORTRESS_CONF="$CONFIG_DIR/fortress.conf"

# Load configuration from fortress.conf (primary source after install)
if [ -f "$FORTRESS_CONF" ]; then
    # shellcheck source=/dev/null
    source "$FORTRESS_CONF"
fi

# Load configuration from netplan state (may have additional details)
if [ -f "$NETPLAN_STATE" ]; then
    # shellcheck source=/dev/null
    source "$NETPLAN_STATE"
fi

# Fallback to vlan-config.conf for backwards compatibility
if [ -f "$VLAN_STATE" ] && [ -z "${LAN_MASK:-}" ]; then
    # shellcheck source=/dev/null
    source "$VLAN_STATE"
fi

# Map LAN_SUBNET_MASK to LAN_MASK for compatibility
# (fortress.conf uses LAN_SUBNET_MASK, netplan-config.conf uses LAN_MASK)
if [ -n "${LAN_SUBNET_MASK:-}" ] && [ -z "${LAN_MASK:-}" ]; then
    LAN_MASK="$LAN_SUBNET_MASK"
fi

# Defaults
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
GATEWAY_LAN="${GATEWAY_LAN:-10.200.0.1}"
LAN_MASK="${LAN_MASK:-24}"

# FLAT BRIDGE ARCHITECTURE (no VLANs)
# IP is assigned directly to FTS bridge's internal port
# OpenFlow rules handle NAC (Network Access Control)
# This simplifies the network and reduces packet processing overhead

# Container network
CONTAINER_SUBNET="${CONTAINER_SUBNET:-172.20.200.0/24}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[OVS]${NC} $*"; }
log_success() { echo -e "${GREEN}[OVS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[OVS]${NC} $*"; }
log_error() { echo -e "${RED}[OVS]${NC} $*"; }
log_section() { echo -e "\n${CYAN}═══ $* ═══${NC}"; }

# ============================================================
# WAIT FOR NETPLAN
# ============================================================

wait_for_bridge() {
    log_info "Waiting for OVS bridge $OVS_BRIDGE..."

    local count=0
    while [ $count -lt 30 ]; do
        if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
            log_success "Bridge $OVS_BRIDGE is ready"
            return 0
        fi
        sleep 0.5
        count=$((count + 1))
    done

    log_error "Bridge $OVS_BRIDGE not found after 15 seconds"
    return 1
}

# ============================================================
# BRING UP VLAN INTERFACES
# ============================================================
# Creates VLAN interfaces as OVS internal ports with proper tagging.
# This is the ONLY correct approach for OVS bridges.
#
# IMPORTANT: Netplan's vlans: section creates Linux VLAN sub-interfaces
# (8021q), which DON'T work correctly with OVS bridges. We must use
# OVS internal ports with VLAN tags instead.

# Helper to check if interface is an OVS internal port
is_ovs_internal_port() {
    local iface="$1"
    local iface_type
    iface_type=$(ovs-vsctl get interface "$iface" type 2>/dev/null | tr -d '"') || return 1
    [ "$iface_type" = "internal" ]
}

# Helper to create/ensure OVS internal port for VLAN
ensure_ovs_vlan_port() {
    local port_name="$1"
    local vlan_tag="$2"
    local gateway_ip="$3"
    local netmask="$4"

    # Check if interface exists
    if ip link show "$port_name" &>/dev/null; then
        # Interface exists - check if it's an OVS internal port
        if is_ovs_internal_port "$port_name"; then
            log_info "$port_name: OVS internal port exists"
        else
            # It's NOT an OVS internal port (likely a Linux VLAN from netplan)
            # We need to delete it and recreate as OVS internal port
            log_warn "$port_name: Not an OVS internal port - recreating..."

            # Bring down and delete the Linux VLAN interface
            ip link set "$port_name" down 2>/dev/null || true
            ip link delete "$port_name" 2>/dev/null || true

            # Small delay to let kernel cleanup
            sleep 0.5

            # Create as OVS internal port
            log_info "Creating $port_name as OVS internal port (VLAN $vlan_tag)..."
            ovs-vsctl add-port "$OVS_BRIDGE" "$port_name" \
                tag="$vlan_tag" \
                -- set interface "$port_name" type=internal
        fi
    else
        # Interface doesn't exist - create it as OVS internal port
        # First check if it's already an OVS port (might just be down)
        if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${port_name}$"; then
            log_info "$port_name: OVS port exists, ensuring internal type..."
            ovs-vsctl set interface "$port_name" type=internal 2>/dev/null || true
        else
            log_info "Creating $port_name as OVS internal port (VLAN $vlan_tag)..."
            ovs-vsctl add-port "$OVS_BRIDGE" "$port_name" \
                tag="$vlan_tag" \
                -- set interface "$port_name" type=internal
        fi
    fi

    # Wait for interface to appear (OVS needs a moment)
    local wait_count=0
    while [ $wait_count -lt 20 ]; do
        if ip link show "$port_name" &>/dev/null; then
            break
        fi
        sleep 0.2
        wait_count=$((wait_count + 1))
    done

    if ! ip link show "$port_name" &>/dev/null; then
        log_error "Failed to create $port_name interface"
        return 1
    fi

    # Bring interface UP
    ip link set "$port_name" up

    # Assign IP if not present
    if ! ip addr show "$port_name" 2>/dev/null | grep -q "${gateway_ip}/"; then
        log_info "Assigning ${gateway_ip}/${netmask} to $port_name..."
        ip addr add "${gateway_ip}/${netmask}" dev "$port_name" 2>/dev/null || {
            log_warn "IP may already be assigned to $port_name"
        }
    fi

    # Verify
    if ip addr show "$port_name" 2>/dev/null | grep -q "${gateway_ip}/"; then
        log_success "$port_name: UP with IP ${gateway_ip}/${netmask}"
        return 0
    else
        log_error "$port_name: Failed to assign IP ${gateway_ip}/${netmask}"
        return 1
    fi
}

setup_bridge_gateway() {
    log_section "Setting Up Bridge Gateway"

    local gateway_lan="${GATEWAY_LAN:-10.200.0.1}"
    local lan_mask="${LAN_MASK:-24}"

    # FLAT BRIDGE ARCHITECTURE
    # OVS bridge has a default internal port with the same name (FTS)
    # We assign the gateway IP directly to this port
    # No VLAN tagging overhead - pure Layer 2 switching with OpenFlow NAC

    # Ensure the OVS bridge is UP
    if ip link show "$OVS_BRIDGE" &>/dev/null; then
        if ! ip link show "$OVS_BRIDGE" | grep -q "state UP"; then
            log_info "Bringing bridge $OVS_BRIDGE UP..."
            ip link set "$OVS_BRIDGE" up
        fi
    else
        log_error "Bridge $OVS_BRIDGE does not exist!"
        return 1
    fi

    # Assign gateway IP directly to the FTS bridge's internal port
    # This is the correct way to give OVS bridge an IP (via its internal port)
    if ! ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -q "${gateway_lan}/"; then
        log_info "Assigning ${gateway_lan}/${lan_mask} to $OVS_BRIDGE..."
        ip addr add "${gateway_lan}/${lan_mask}" dev "$OVS_BRIDGE" 2>/dev/null || {
            log_warn "IP may already be assigned to $OVS_BRIDGE"
        }
    fi

    # Verify IP assignment
    if ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -q "${gateway_lan}/"; then
        log_success "$OVS_BRIDGE: UP with IP ${gateway_lan}/${lan_mask} (flat bridge)"

        # Enable Proxy ARP PVLAN for ap_isolate=1 D2D support
        # With ap_isolate=1, WiFi blocks direct client-to-client at wireless layer.
        # Proxy ARP makes gateway respond to ALL ARP requests, so clients send
        # traffic to gateway MAC. Gateway can then forward to destination.
        # This enables D2D for smart_home/full_access while respecting policy blocks.
        sysctl -w "net.ipv4.conf.${OVS_BRIDGE}.proxy_arp_pvlan=1" >/dev/null 2>&1 || true
        sysctl -w "net.ipv4.conf.all.proxy_arp_pvlan=1" >/dev/null 2>&1 || true
        log_info "  Proxy ARP PVLAN enabled for ap_isolate=1 D2D"

        return 0
    else
        log_error "$OVS_BRIDGE: Failed to assign IP ${gateway_lan}/${lan_mask}"
        return 1
    fi
}

# ============================================================
# OPENFLOW RULES
# ============================================================

configure_openflow() {
    log_section "Configuring OpenFlow Rules"

    # IMPORTANT: Keep standalone mode for now - secure mode requires careful
    # flow management and breaks connectivity if rules aren't perfect.
    # NAC enforcement is done via nftables instead (network-filter-manager.sh)
    # which operates at a higher layer and doesn't have these issues.
    ovs-vsctl set-fail-mode "$OVS_BRIDGE" standalone 2>/dev/null || true

    # Disable multicast snooping - CRITICAL for HomeKit, HomePod, AirPlay, Chromecast
    # When enabled, OVS may block multicast if IGMP isn't properly handled
    ovs-vsctl set bridge "$OVS_BRIDGE" mcast_snooping_enable=false 2>/dev/null || true

    # Clear existing flows
    ovs-ofctl del-flows "$OVS_BRIDGE" 2>/dev/null || true

    # Priority 65535: EAPOL frames for 802.1X/WPA authentication (HIGHEST PRIORITY)
    # dl_type=0x888e is the EtherType for EAPOL (Extensible Authentication Protocol over LAN)
    # Without this, WPA handshakes fail and clients cannot authenticate
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=65535,dl_type=0x888e,actions=NORMAL"

    # Priority 1000: Allow ARP (essential for L2 connectivity)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=1000,arp,actions=NORMAL"

    # Priority 900: Allow DHCP (essential for client IP assignment)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=900,udp,tp_dst=67,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=900,udp,tp_dst=68,actions=NORMAL"

    # Priority 800: Allow DNS
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=800,udp,tp_dst=53,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=800,tcp,tp_dst=53,actions=NORMAL"

    # Priority 800: Allow mDNS/Bonjour (essential for Apple ecosystem, Chromecast, etc.)
    # mDNS uses multicast 224.0.0.251:5353 for device discovery
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=800,udp,tp_dst=5353,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=800,udp,tp_src=5353,actions=NORMAL"

    # Priority 700: Allow multicast traffic (SSDP, IGMP, etc.)
    # Required for device discovery, AirPlay, HomeKit, smart home protocols
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=700,ip,nw_dst=224.0.0.0/4,actions=NORMAL"

    # Priority 700: Allow IPv6 multicast (essential for HomeKit, HomePod, AirPlay)
    # IPv6 multicast uses Ethernet addresses starting with 33:33:xx:xx:xx:xx
    # This covers ff02::fb (mDNS), ff02::1 (all-nodes), ff02::2 (all-routers)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=700,dl_dst=33:33:00:00:00:00/ff:ff:00:00:00:00,actions=NORMAL"

    # Priority 700: Allow all IPv6 traffic (HomeKit, AirPlay heavily use IPv6)
    # dl_type=0x86dd is IPv6
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=700,ipv6,actions=NORMAL"

    # Priority 600: Allow ICMPv6 (Neighbor Discovery Protocol - essential for IPv6)
    # Without NDP, IPv6 devices cannot discover each other
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=600,icmp6,actions=NORMAL"

    # Priority 500: Permissive rules for LAN traffic (10.200.0.0/16)
    # Broader /16 handles any user-configured subnet mask (/29 to /22)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_src=10.200.0.0/16,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_dst=10.200.0.0/16,actions=NORMAL"

    # ================================================================
    # D2D HAIRPIN RULES FOR ap_isolate=1 SUPPORT
    # ================================================================
    #
    # With ap_isolate=1, WiFi blocks direct client-to-client at wireless layer.
    # Traffic still reaches OVS bridge. These rules hairpin it back (in_port action)
    # so OVS can enforce policy while still allowing D2D for permitted devices.
    #
    # Policy enforcement order (higher priority = matches first):
    # - QUARANTINE: blocked at priority 1000 (never reaches hairpin)
    # - INTERNET_ONLY: blocked at priority 700 (never reaches hairpin)
    # - SMART_HOME/FULL_ACCESS: allowed, reaches hairpin at 501-505
    #
    # Actions: in_port sends back to same WiFi interface, normal forwards elsewhere
    # ================================================================
    local wifi_24_iface="${WIFI_24GHZ_IFACE:-wlan_24ghz}"
    local wifi_5_iface="${WIFI_5GHZ_IFACE:-wlan_5ghz}"

    for wifi_iface in "$wifi_24_iface" "$wifi_5_iface"; do
        if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${wifi_iface}$"; then
            # Priority 505: mDNS hairpin (224.0.0.251:5353) - AirPlay, HomeKit discovery
            ovs-ofctl add-flow "$OVS_BRIDGE" \
                "priority=505,udp,in_port=${wifi_iface},nw_dst=224.0.0.251,tp_dst=5353,actions=in_port,normal"

            # Priority 505: IPv6 mDNS hairpin (ff02::fb) - HomeKit, Matter
            ovs-ofctl add-flow "$OVS_BRIDGE" \
                "priority=505,udp6,in_port=${wifi_iface},ipv6_dst=ff02::fb,tp_dst=5353,actions=in_port,normal"

            # Priority 504: SSDP hairpin (239.255.255.250:1900) - Chromecast, UPnP
            ovs-ofctl add-flow "$OVS_BRIDGE" \
                "priority=504,udp,in_port=${wifi_iface},nw_dst=239.255.255.250,tp_dst=1900,actions=in_port,normal"

            # Priority 503: ARP hairpin - essential for D2D MAC resolution
            ovs-ofctl add-flow "$OVS_BRIDGE" \
                "priority=503,arp,in_port=${wifi_iface},actions=in_port,normal"

            # Priority 502: IPv6 NDP hairpin - essential for IPv6 D2D
            ovs-ofctl add-flow "$OVS_BRIDGE" \
                "priority=502,icmp6,in_port=${wifi_iface},actions=in_port,normal"

            # Priority 501: Unicast IP hairpin (LAN subnet) - actual D2D traffic
            ovs-ofctl add-flow "$OVS_BRIDGE" \
                "priority=501,ip,in_port=${wifi_iface},nw_dst=10.200.0.0/16,actions=in_port,normal"

            log_info "  D2D hairpin enabled for ${wifi_iface} (mDNS, SSDP, ARP, NDP, IP)"
        fi
    done

    # Priority 500: Allow container network traffic (172.20.0.0/16)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_src=172.20.0.0/16,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_dst=172.20.0.0/16,actions=NORMAL"

    # Priority 0: Default - normal L2 switching
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=0,actions=NORMAL"

    log_success "OpenFlow rules configured"
    log_info "  EAPOL (WPA auth): priority 65535"
    log_info "  ARP, DHCP, DNS, mDNS: priority 800-1000"
    log_info "  IPv4/IPv6 multicast (HomeKit, AirPlay): priority 700"
    log_info "  D2D hairpin (WiFi ap_isolate=1): priority 501-505"
    log_info "    ├─ mDNS (AirPlay/HomeKit): 505"
    log_info "    ├─ SSDP (Chromecast/UPnP): 504"
    log_info "    ├─ ARP (MAC resolution): 503"
    log_info "    ├─ ICMPv6/NDP: 502"
    log_info "    └─ Unicast IP: 501"
    log_info "  LAN (10.200.0.0/16): priority 500"
    log_info "  Containers (172.20.0.0/16): priority 500"
}

# ============================================================
# ============================================================
# CROSS-BAND MULTICAST REFLECTION
# ============================================================
#
# With direct OVS integration, multicast/mDNS traffic doesn't
# automatically bridge between 2.4GHz and 5GHz WiFi bands
# because OVS uses per-port MAC learning.
#
# These rules explicitly reflect multicast traffic between WiFi bands
# to enable device discovery (HomeKit, AirPlay, Chromecast, etc.).
#
# Priority 400: Below base allow (500), above default (0)
#
# ============================================================

setup_multicast_reflection() {
    log_section "Cross-Band Multicast Reflection"

    # Get OVS port numbers for WiFi interfaces
    local wifi_24_port wifi_5_port
    wifi_24_port=$(ovs-vsctl get interface wlan_24ghz ofport 2>/dev/null | tr -d '"') || wifi_24_port=""
    wifi_5_port=$(ovs-vsctl get interface wlan_5ghz ofport 2>/dev/null | tr -d '"') || wifi_5_port=""

    # Validate port numbers
    if [ -z "$wifi_24_port" ] || [ "$wifi_24_port" = "-1" ]; then
        log_warn "wlan_24ghz port not found in OVS - multicast reflection skipped"
        return 0
    fi

    if [ -z "$wifi_5_port" ] || [ "$wifi_5_port" = "-1" ]; then
        log_warn "wlan_5ghz port not found in OVS - multicast reflection skipped"
        return 0
    fi

    log_info "Setting up cross-band multicast reflection"
    log_info "  wlan_24ghz port: $wifi_24_port"
    log_info "  wlan_5ghz port: $wifi_5_port"

    # Clear any existing multicast reflection rules
    ovs-ofctl del-flows "$OVS_BRIDGE" "priority=400" 2>/dev/null || true

    # IPv4 mDNS (224.0.0.251:5353) - Bonjour/Zeroconf discovery
    # Reflect from 2.4GHz to 5GHz and vice versa
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$wifi_24_port,nw_dst=224.0.0.251,tp_dst=5353,actions=output:$wifi_5_port,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$wifi_5_port,nw_dst=224.0.0.251,tp_dst=5353,actions=output:$wifi_24_port,NORMAL"

    # IPv6 mDNS (ff02::fb) - HomeKit, AirPlay, Matter
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp6,in_port=$wifi_24_port,ipv6_dst=ff02::fb,tp_dst=5353,actions=output:$wifi_5_port,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp6,in_port=$wifi_5_port,ipv6_dst=ff02::fb,tp_dst=5353,actions=output:$wifi_24_port,NORMAL"

    # SSDP/UPnP (239.255.255.250:1900) - Chromecast, Roku, smart TVs
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$wifi_24_port,nw_dst=239.255.255.250,tp_dst=1900,actions=output:$wifi_5_port,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$wifi_5_port,nw_dst=239.255.255.250,tp_dst=1900,actions=output:$wifi_24_port,NORMAL"

    # IPv6 All-Nodes multicast (ff02::1) - Neighbor Discovery, router advertisements
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,ipv6,in_port=$wifi_24_port,ipv6_dst=ff02::1,actions=output:$wifi_5_port,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,ipv6,in_port=$wifi_5_port,ipv6_dst=ff02::1,actions=output:$wifi_24_port,NORMAL"

    log_success "Cross-band multicast reflection configured"
    log_info "  mDNS (224.0.0.251, ff02::fb): 2.4GHz <-> 5GHz"
    log_info "  SSDP (239.255.255.250): 2.4GHz <-> 5GHz"
    log_info "  IPv6 NDP (ff02::1): 2.4GHz <-> 5GHz"
}

# ============================================================
# PORT CONFIGURATION (FLAT BRIDGE - NO VLAN TAGGING)
# ============================================================

configure_bridge_ports() {
    log_section "Configuring Bridge Ports (Flat Mode)"

    # FLAT BRIDGE ARCHITECTURE
    # All ports are untagged (no VLAN overhead)
    # OpenFlow rules handle NAC (Network Access Control)

    # Get all ports
    local ports
    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null) || return 0

    for port in $ports; do
        # Skip the bridge's internal port (FTS itself)
        [[ "$port" == "$OVS_BRIDGE" ]] && continue

        # Clear any existing VLAN tags - flat bridge mode
        ovs-vsctl remove port "$port" tag 2>/dev/null || true
        ovs-vsctl remove port "$port" vlan_mode 2>/dev/null || true

        log_info "Port $port: untagged (flat bridge)"
    done

    log_success "Bridge ports configured (flat mode - no VLAN tagging)"
    log_info "  All traffic flows at L2 with OpenFlow NAC"
}

# ============================================================
# AVAHI CONFIGURATION (FOR ECOSYSTEM BUBBLE MDNS)
# ============================================================
#
# The PresenceSensor uses Python's zeroconf library to detect Apple/Google
# ecosystem devices via mDNS announcements. However, avahi-daemon by default
# has exclusive bind on port 5353, blocking zeroconf.
#
# Solution: Configure avahi-daemon to allow other mDNS stacks to coexist.
# This enables Ecosystem Bubble detection for HomeKit/AirPlay device grouping.
#
# ============================================================

setup_avahi_coexistence() {
    log_section "Avahi mDNS Coexistence"

    local avahi_conf="/etc/avahi/avahi-daemon.conf"

    if [ ! -f "$avahi_conf" ]; then
        log_warn "Avahi not installed - mDNS ecosystem detection may not work"
        return 0
    fi

    # Check if already configured
    if grep -q "^disallow-other-stacks=no" "$avahi_conf" 2>/dev/null; then
        log_info "Avahi already configured for coexistence"
        return 0
    fi

    log_info "Configuring Avahi for mDNS coexistence..."

    # Backup original
    cp "$avahi_conf" "${avahi_conf}.backup-$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    # Update configuration
    if grep -q "^disallow-other-stacks=" "$avahi_conf" 2>/dev/null; then
        # Replace existing setting
        sed -i 's/^disallow-other-stacks=.*/disallow-other-stacks=no/' "$avahi_conf"
    elif grep -q "^\[server\]" "$avahi_conf" 2>/dev/null; then
        # Add after [server] section
        sed -i '/^\[server\]/a disallow-other-stacks=no' "$avahi_conf"
    else
        # Append to end
        echo "" >> "$avahi_conf"
        echo "[server]" >> "$avahi_conf"
        echo "disallow-other-stacks=no" >> "$avahi_conf"
    fi

    # Enable reflector for cross-interface mDNS (WiFi ↔ wired devices)
    if grep -q "^enable-reflector=" "$avahi_conf" 2>/dev/null; then
        sed -i 's/^enable-reflector=.*/enable-reflector=yes/' "$avahi_conf"
    elif grep -q "^\[reflector\]" "$avahi_conf" 2>/dev/null; then
        sed -i '/^\[reflector\]/a enable-reflector=yes' "$avahi_conf"
    else
        echo "" >> "$avahi_conf"
        echo "[reflector]" >> "$avahi_conf"
        echo "enable-reflector=yes" >> "$avahi_conf"
    fi

    # Restart avahi-daemon to apply changes
    if systemctl is-active --quiet avahi-daemon 2>/dev/null; then
        systemctl restart avahi-daemon 2>/dev/null || true
        log_info "Restarted avahi-daemon with new configuration"
    fi

    log_success "Avahi configured for mDNS coexistence"
}

# ============================================================
# WIFI BRIDGE CLEANUP (LEGACY INFRASTRUCTURE REMOVAL)
# ============================================================
#
# Fortress uses direct OVS integration via hostapd-ovs.
# This function cleans up any legacy br-wifi/veth infrastructure
# from previous installations.
#
# Traffic flow: WiFi → OVS (FTS) directly → OpenFlow policy
# No intermediate Linux bridge - best performance
#
# ============================================================

cleanup_legacy_wifi_bridge() {
    log_section "WiFi Configuration (Direct OVS Mode)"

    local br_wifi="br-wifi"
    local veth_br="veth-wifi-a"
    local veth_ovs="veth-wifi-b"

    # Cleanup legacy br-wifi infrastructure if present
    if ip link show "$br_wifi" &>/dev/null || ip link show "$veth_br" &>/dev/null; then
        log_info "Removing legacy br-wifi infrastructure..."

        # Remove veth from OVS
        if ovs-vsctl port-to-br "$veth_ovs" &>/dev/null 2>&1; then
            ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$veth_ovs" 2>/dev/null || true
            log_info "  Removed $veth_ovs from OVS"
        fi

        # Delete veth pair
        if ip link show "$veth_br" &>/dev/null; then
            ip link delete "$veth_br" 2>/dev/null || true
            log_info "  Deleted veth pair"
        fi

        # Delete br-wifi
        if ip link show "$br_wifi" &>/dev/null; then
            ip link set "$br_wifi" down 2>/dev/null || true
            ip link delete "$br_wifi" 2>/dev/null || true
            log_info "  Deleted br-wifi bridge"
        fi

        # Remove legacy helper script
        rm -f /usr/local/bin/fts-wifi-bridge-helper.sh 2>/dev/null || true

        log_success "Legacy br-wifi infrastructure removed"
    else
        log_info "No legacy infrastructure to clean up"
    fi

    # WiFi interfaces will be added to OVS directly by hostapd-ovs using bridge=FTS
    # The multicast reflection rules (priority 400) handle cross-band mDNS
    log_success "Direct OVS mode: WiFi → OVS ($OVS_BRIDGE) → OpenFlow policy"
}

# ============================================================
# TRAFFIC MIRROR (FOR IDS/NSM CAPTURE)
# ============================================================
#
# Creates an OVS mirror port that receives a copy of ALL traffic.
# This is the PROPER way to capture traffic on an OVS bridge.
#
# IMPORTANT: IDS/NSM tools (Suricata, Zeek) should capture from
# FTS-mirror, NOT directly from FTS. Direct AF_PACKET capture on
# an OVS bridge causes:
#   1. Packet loss (competes with OVS datapath)
#   2. Promiscuous mode conflicts
#   3. CPU starvation
#
# The mirror port receives a copy of traffic, which doesn't
# interfere with OVS switching operations.
#
# ============================================================

setup_traffic_mirror() {
    log_section "Traffic Mirror Port (for IDS/NSM)"

    local mirror_port="FTS-mirror"

    # Check if mirror port already exists
    if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${mirror_port}$"; then
        # Ensure it's an internal port
        local iface_type
        iface_type=$(ovs-vsctl get interface "$mirror_port" type 2>/dev/null | tr -d '"') || true
        if [ "$iface_type" = "internal" ]; then
            log_info "$mirror_port: OVS internal port exists"
        else
            log_warn "$mirror_port: Recreating as internal port..."
            ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$mirror_port"
            ovs-vsctl add-port "$OVS_BRIDGE" "$mirror_port" \
                -- set interface "$mirror_port" type=internal
        fi
    else
        # Create mirror port
        log_info "Creating $mirror_port as OVS internal port..."
        ovs-vsctl add-port "$OVS_BRIDGE" "$mirror_port" \
            -- set interface "$mirror_port" type=internal
    fi

    # Wait for interface to appear
    local wait_count=0
    while [ $wait_count -lt 20 ]; do
        if ip link show "$mirror_port" &>/dev/null; then
            break
        fi
        sleep 0.2
        wait_count=$((wait_count + 1))
    done

    if ! ip link show "$mirror_port" &>/dev/null; then
        log_error "Failed to create $mirror_port interface"
        return 1
    fi

    # Bring interface UP (no IP needed - just for capture)
    ip link set "$mirror_port" up

    # Clear any existing mirrors
    ovs-vsctl --if-exists clear bridge "$OVS_BRIDGE" mirrors

    # Create mirror that copies ALL traffic to the mirror port
    log_info "Configuring OVS mirror to copy all traffic..."
    ovs-vsctl -- set bridge "$OVS_BRIDGE" mirrors=@m \
        -- --id=@p get port "$mirror_port" \
        -- --id=@m create mirror name=ids-capture select-all=true output-port=@p

    # Verify mirror is active
    if ovs-vsctl list mirror 2>/dev/null | grep -q "ids-capture"; then
        log_success "Traffic mirror configured: $mirror_port"
        log_info "  IDS/NSM tools should capture from: $mirror_port"
        log_info "  This avoids packet loss from direct bridge capture"
    else
        log_error "Failed to configure traffic mirror"
        return 1
    fi

    return 0
}

# ============================================================
# STATUS
# ============================================================

show_status() {
    log_section "OVS Post-Setup Status"

    echo -e "\n${CYAN}OpenFlow Rules:${NC}"
    ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | head -20 || echo "  (none)"

    echo -e "\n${CYAN}Port VLAN Tags:${NC}"
    for port in $(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null); do
        local tag mode
        tag=$(ovs-vsctl get port "$port" tag 2>/dev/null || echo "none")
        mode=$(ovs-vsctl get port "$port" vlan_mode 2>/dev/null || echo "default")
        echo "  $port: tag=$tag mode=$mode"
    done

    echo -e "\n${CYAN}Bridge Gateway (Flat Mode):${NC}"
    local fts_ip
    fts_ip=$(ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -oP "inet \K[0-9./]+" | head -1)
    if [ -n "$fts_ip" ]; then
        echo "  $OVS_BRIDGE: $fts_ip (gateway)"
    else
        echo "  $OVS_BRIDGE: NO IP (gateway not configured)"
    fi

    echo -e "\n${CYAN}Traffic Mirror (IDS/NSM Capture):${NC}"
    if ip link show FTS-mirror &>/dev/null; then
        local mirror_state
        mirror_state=$(ip link show FTS-mirror 2>/dev/null | grep -oE "state \w+" | awk '{print $2}')
        echo "  FTS-mirror: $mirror_state"
        # Check if mirroring is active
        if ovs-vsctl list mirror 2>/dev/null | grep -q "ids-capture"; then
            echo "  OVS Mirror: ACTIVE (ids-capture)"
            echo "  Suricata/Zeek should use: CAPTURE_INTERFACE=FTS-mirror"
        else
            echo -e "  ${YELLOW}OVS Mirror: NOT CONFIGURED${NC}"
            echo "  Run: ./ovs-post-setup.sh setup"
        fi
    else
        echo -e "  ${RED}FTS-mirror: NOT FOUND${NC}"
        echo "  AIOCHI containers may cause packet loss!"
        echo "  Run: ./ovs-post-setup.sh setup"
    fi

    echo -e "\n${CYAN}WiFi (Direct OVS Integration):${NC}"
    # Check for WiFi interfaces directly on OVS
    local wifi_found=false
    for wlan_if in wlan_24ghz wlan_5ghz; do
        if ovs-vsctl port-to-br "$wlan_if" 2>/dev/null | grep -q "$OVS_BRIDGE"; then
            local port_num
            port_num=$(ovs-vsctl get interface "$wlan_if" ofport 2>/dev/null || echo "?")
            echo -e "  ${GREEN}✓${NC} $wlan_if → OVS ($OVS_BRIDGE) port $port_num"
            wifi_found=true
        fi
    done
    if [ "$wifi_found" = "false" ]; then
        echo "  WiFi interfaces not yet added to OVS"
        echo "  (hostapd will add them on start via bridge=FTS)"
    fi
    # Check for legacy br-wifi (should not exist)
    if ip link show br-wifi &>/dev/null; then
        echo -e "  ${YELLOW}⚠${NC} Legacy br-wifi detected - run cleanup"
    fi

    # Container Network Validation
    echo -e "\n${CYAN}Container Network:${NC}"
    if command -v podman &>/dev/null; then
        # Check podman network
        local network_name="containers_fts-internal"
        if podman network exists "$network_name" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} Network: $network_name exists"
            local subnet gateway
            subnet=$(podman network inspect "$network_name" 2>/dev/null | grep -o '"subnet": "[^"]*"' | head -1 | cut -d'"' -f4)
            gateway=$(podman network inspect "$network_name" 2>/dev/null | grep -o '"gateway": "[^"]*"' | head -1 | cut -d'"' -f4)
            [ -n "$subnet" ] && echo "    Subnet: $subnet"
            [ -n "$gateway" ] && echo "    Gateway: $gateway"
        else
            echo -e "  ${RED}✗${NC} Network: $network_name MISSING"
            echo "    Run: podman network create --driver bridge --subnet 172.20.200.0/24 --gateway 172.20.200.1 $network_name"
        fi

        # Check core containers
        echo -e "\n${CYAN}Core Containers:${NC}"
        local core_containers="fts-postgres fts-redis fts-web fts-qsecbit fts-dnsxai fts-dfs"
        local all_healthy=true
        for container in $core_containers; do
            local status
            status=$(podman inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
            local health=""
            if [ "$status" = "running" ]; then
                health=$(podman inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "")
                if [ "$health" = "healthy" ]; then
                    echo -e "  ${GREEN}✓${NC} $container: running (healthy)"
                elif [ -n "$health" ]; then
                    echo -e "  ${YELLOW}⚠${NC} $container: running ($health)"
                    all_healthy=false
                else
                    echo -e "  ${GREEN}✓${NC} $container: running"
                fi
            else
                echo -e "  ${RED}✗${NC} $container: $status"
                all_healthy=false
            fi
        done

        # Check fts-web network interface (critical for web UI access)
        echo -e "\n${CYAN}Web Container Network:${NC}"
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^fts-web$"; then
            # Use podman inspect (always works) instead of ip addr (may not be in container)
            local web_ip
            web_ip=$(podman inspect fts-web --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
            if [ -n "$web_ip" ]; then
                echo -e "  ${GREEN}✓${NC} fts-web network: $web_ip"

                # Test web UI health
                if curl -sk "https://localhost:${WEB_PORT:-8443}/health" --max-time 3 2>/dev/null | grep -q "healthy"; then
                    echo -e "  ${GREEN}✓${NC} Web UI health check: OK"
                else
                    echo -e "  ${YELLOW}⚠${NC} Web UI health check: not responding (may still be starting)"
                fi
            else
                # Fallback: check if container is running at all
                if podman inspect fts-web --format '{{.State.Running}}' 2>/dev/null | grep -q "true"; then
                    echo -e "  ${YELLOW}⚠${NC} fts-web running but network info unavailable"
                else
                    echo -e "  ${RED}✗${NC} fts-web not running properly!"
                    all_healthy=false
                fi
            fi
        else
            echo -e "  ${RED}✗${NC} fts-web container not running"
            all_healthy=false
        fi

        # Summary
        echo ""
        if [ "$all_healthy" = true ]; then
            echo -e "${GREEN}Container network: HEALTHY${NC}"
        else
            echo -e "${RED}Container network: ISSUES DETECTED${NC}"
            echo "  Run: sudo /opt/hookprobe/fortress/fortress-recover.sh"
        fi
    else
        echo "  Podman not installed"
    fi
}

# ============================================================
# MAIN
# ============================================================

main() {
    local action="${1:-setup}"

    case "$action" in
        setup|configure)
            wait_for_bridge || exit 1
            setup_bridge_gateway  # CRITICAL: Assign IP to FTS bridge first
            configure_openflow
            configure_bridge_ports

            # Cross-band multicast reflection for hostapd-ovs mode
            # Enables mDNS/SSDP discovery between 2.4GHz and 5GHz WiFi bands
            setup_multicast_reflection || log_warn "Multicast reflection setup had issues (non-fatal)"

            # Avahi mDNS coexistence for Ecosystem Bubble detection
            # Enables HomeKit/AirPlay device grouping via PresenceSensor
            setup_avahi_coexistence || log_warn "Avahi setup had issues (non-fatal)"

            # WiFi bridge for SDN Autopilot (ap_isolate=1 + hairpin mDNS)
            # Allows full OVS control over WiFi traffic including device-to-device
            cleanup_legacy_wifi_bridge || log_warn "WiFi cleanup had issues (non-fatal)"

            # Traffic mirror for IDS/NSM capture (AIOCHI Suricata/Zeek)
            # Creates FTS-mirror port - proper way to capture without packet loss
            setup_traffic_mirror || log_warn "Traffic mirror setup had issues (non-fatal)"

            log_section "OVS Post-Setup Complete"
            log_success "VLAN interfaces, OpenFlow rules, port tags, WiFi bridge, and traffic mirror configured"
            ;;

        status)
            show_status
            ;;

        openflow)
            wait_for_bridge || exit 1
            configure_openflow
            ;;

        gateway)
            # Configure gateway IP on FTS bridge
            wait_for_bridge || exit 1
            setup_bridge_gateway
            configure_bridge_ports
            ;;

        ports)
            # Configure bridge ports (flat mode - no VLAN tags)
            wait_for_bridge || exit 1
            configure_bridge_ports
            ;;

        *)
            echo "Usage: $0 {setup|status|openflow|gateway|ports}"
            echo ""
            echo "Flat Bridge Architecture - OpenFlow NAC"
            echo "  setup     - Full setup (gateway + openflow + ports)"
            echo "  status    - Show bridge status"
            echo "  openflow  - Configure OpenFlow rules"
            echo "  gateway   - Setup gateway IP on FTS bridge"
            echo "  ports     - Configure ports (flat mode)"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
