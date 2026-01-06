#!/bin/bash
#
# ovs-post-setup.sh - OVS Post-Netplan Configuration
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This script runs AFTER netplan has created the OVS bridge and VLAN interfaces.
# It configures things netplan cannot handle:
#   - OpenFlow rules for traffic flow
#   - Port VLAN tagging (access/trunk modes)
#   - Container network bridge (veth to VLAN 200)
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

    # Priority 500: Allow container network traffic (172.20.0.0/16)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_src=172.20.0.0/16,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=500,ip,nw_dst=172.20.0.0/16,actions=NORMAL"

    # Priority 0: Default - normal L2 switching
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=0,actions=NORMAL"

    log_success "OpenFlow rules configured"
    log_info "  ARP, DHCP, DNS, mDNS: priority 800-1000"
    log_info "  IPv4/IPv6 multicast (HomeKit, AirPlay): priority 700"
    log_info "  LAN (10.200.0.0/16): priority 500"
    log_info "  Containers (172.20.0.0/16): priority 500"
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

    # Also enable reflector for cross-interface mDNS (br-wifi ↔ FTS bridge)
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
# WIFI BRIDGE (SDN AUTOPILOT WITH BRIDGE PORT ISOLATION)
# ============================================================
#
# Architecture:
#   WiFi clients → hostapd (ap_isolate=0) → br-wifi → veth → OVS
#
# Key: We use BRIDGE PORT ISOLATION instead of ap_isolate=1:
#   - wlan interfaces: isolated=on (can ONLY talk to non-isolated ports)
#   - veth-wifi-a: isolated=off (the "uplink" to OVS)
#
# This forces ALL WiFi traffic through OVS for NAC policy enforcement,
# while allowing device-to-device (D2D) for policies that permit it:
#   - internet_only: OVS blocks LAN traffic (no D2D)
#   - smart_home/full_access: OVS allows LAN traffic (D2D works)
#
# Traffic flow (D2D allowed):
#   1. iPhone sends AirPlay to HomePod (both on wlan_24ghz)
#   2. wlan_24ghz is isolated → traffic MUST go to veth-wifi-a
#   3. veth-wifi-a → veth-wifi-b → OVS
#   4. OVS checks NAC policy: iPhone is smart_home → ALLOW
#   5. OVS forwards back to veth-wifi-b → veth-wifi-a
#   6. veth-wifi-a is non-isolated → can reach wlan_24ghz → HomePod
#
# Traffic flow (D2D blocked):
#   1. Guest phone sends to HomePod
#   2. wlan → veth → OVS
#   3. OVS checks NAC policy: Guest is internet_only → DROP
#   4. Traffic blocked at OVS layer
#
# ============================================================

setup_wifi_bridge() {
    log_section "WiFi Bridge for SDN Autopilot"

    local br_wifi="br-wifi"
    local veth_br="veth-wifi-a"   # Linux bridge side
    local veth_ovs="veth-wifi-b"  # OVS side

    # Clean up orphan veth interfaces that may have accumulated
    # These can appear from failed setup attempts or network changes
    # Pattern: veth0@enp1s0, veth1@enp1s0, etc. (NOT veth-wifi-a)
    cleanup_orphan_veths() {
        local members
        members=$(bridge link show master "$br_wifi" 2>/dev/null | awk '{print $2}' | tr -d ':')
        for member in $members; do
            # Extract base name (veth0 from veth0@enp1s0)
            local base_name="${member%%@*}"
            # Only remove numbered veths (veth0, veth1, etc.) not our veth-wifi-a
            if [[ "$base_name" =~ ^veth[0-9]+$ ]]; then
                log_info "Removing orphan veth: $base_name"
                ip link set "$base_name" nomaster 2>/dev/null || true
                ip link delete "$base_name" 2>/dev/null || true
            fi
        done
    }

    # Create Linux bridge if not exists
    if ! ip link show "$br_wifi" &>/dev/null; then
        log_info "Creating WiFi bridge $br_wifi..."
        ip link add "$br_wifi" type bridge
        # Set STP off for faster convergence
        ip link set "$br_wifi" type bridge stp_state 0
        # Set forward delay to 0
        echo 0 > "/sys/class/net/$br_wifi/bridge/forward_delay" 2>/dev/null || true
    else
        # Bridge exists, cleanup orphan interfaces
        cleanup_orphan_veths
    fi

    # Bring up the bridge
    ip link set "$br_wifi" up

    # Create veth pair if not exists
    if ! ip link show "$veth_br" &>/dev/null; then
        log_info "Creating veth pair $veth_br <-> $veth_ovs..."
        ip link add "$veth_br" type veth peer name "$veth_ovs"
    fi

    # Add veth_br to Linux bridge
    if ! ip link show master "$br_wifi" | grep -q "$veth_br"; then
        ip link set "$veth_br" master "$br_wifi" 2>/dev/null || true
    fi

    # Bring up veth interfaces
    ip link set "$veth_br" up
    ip link set "$veth_ovs" up

    # Add veth_ovs to OVS (flat bridge - no VLAN tagging)
    if ovs-vsctl port-to-br "$veth_ovs" &>/dev/null; then
        local current_br
        current_br=$(ovs-vsctl port-to-br "$veth_ovs" 2>/dev/null || true)
        if [ "$current_br" = "$OVS_BRIDGE" ]; then
            # Clear any VLAN tags (flat bridge mode)
            ovs-vsctl remove port "$veth_ovs" tag 2>/dev/null || true
            log_info "$veth_ovs already on $OVS_BRIDGE (flat mode)"
        else
            ovs-vsctl --if-exists del-port "$current_br" "$veth_ovs"
            ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" || true
            log_info "Moved $veth_ovs to $OVS_BRIDGE (flat mode)"
        fi
    else
        ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" 2>/dev/null || {
            ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$veth_ovs"
            ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" || true
        }
        log_info "Added $veth_ovs to $OVS_BRIDGE (flat mode)"
    fi

    # ============================================================
    # BRIDGE PORT ISOLATION - Forces ALL traffic through OVS
    # ============================================================
    # Instead of ap_isolate=1 (which blocks at WiFi driver level),
    # we use bridge port isolation:
    #   - wlan interfaces: isolated=on (can ONLY reach non-isolated ports)
    #   - veth-wifi-a: isolated=off (the "uplink" to OVS)
    #
    # This forces ALL WiFi traffic through: wlan → veth → OVS
    # OVS then applies NAC policies to allow/block based on device policy.
    # ============================================================

    if command -v bridge &>/dev/null; then
        # veth-wifi-a is NON-ISOLATED (the uplink - traffic must go here)
        bridge link set dev "$veth_br" isolated off 2>/dev/null || true
        # Enable hairpin on veth for return traffic from OVS
        bridge link set dev "$veth_br" hairpin on 2>/dev/null || true
        log_info "Set $veth_br: isolated=off, hairpin=on (OVS uplink)"

        # WiFi interfaces are ISOLATED (can only reach veth)
        for wlan_if in $(ls /sys/class/net/ 2>/dev/null | grep -E "^wlan|^wlp|^wlx"); do
            if ip link show master "$br_wifi" 2>/dev/null | grep -q "$wlan_if"; then
                bridge link set dev "$wlan_if" isolated on 2>/dev/null || true
                log_info "Set $wlan_if: isolated=on (traffic forced through OVS)"
            fi
        done
        # Also handle stable-named interfaces
        for wlan_if in wlan_24ghz wlan_5ghz; do
            if ip link show master "$br_wifi" 2>/dev/null | grep -q "$wlan_if"; then
                bridge link set dev "$wlan_if" isolated on 2>/dev/null || true
                log_info "Set $wlan_if: isolated=on (traffic forced through OVS)"
            fi
        done
    else
        log_warn "bridge command not found - port isolation won't work"
        log_warn "D2D may bypass OVS policy enforcement"
    fi

    log_success "WiFi bridge configured for SDN Autopilot"
    log_info "  Bridge: $br_wifi → $veth_br ↔ $veth_ovs → OVS ($OVS_BRIDGE)"
    log_info "  WiFi ports: isolated (forces traffic through OVS)"
    log_info "  veth uplink: non-isolated + hairpin (returns traffic)"
    log_info "  NAC policies enforced at OVS layer"
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

    echo -e "\n${CYAN}WiFi Bridge (SDN Autopilot):${NC}"
    if ip link show br-wifi &>/dev/null; then
        local br_state
        br_state=$(ip link show br-wifi 2>/dev/null | grep -oE "state \w+" | awk '{print $2}')
        echo "  br-wifi: $br_state"
        echo "  Members:"
        # Check each interface in the bridge
        for dev in $(bridge link show master br-wifi 2>/dev/null | awk '{print $2}' | tr -d ':'); do
            local hairpin_status
            local base_dev="${dev%%@*}"
            # Check hairpin using /sys/class/net (more reliable than bridge -d)
            if [ -f "/sys/class/net/$base_dev/brport/hairpin_mode" ]; then
                local hp_val
                hp_val=$(cat "/sys/class/net/$base_dev/brport/hairpin_mode" 2>/dev/null)
                if [ "$hp_val" = "1" ]; then
                    hairpin_status="hairpin on"
                else
                    hairpin_status="hairpin off"
                fi
            else
                hairpin_status="hairpin n/a"
            fi
            echo "    $dev ($hairpin_status)"
        done
        echo "  veth-wifi-b → OVS:"
        # Check OVS connection - may require root
        local veth_tag
        veth_tag=$(ovs-vsctl get port veth-wifi-b tag 2>/dev/null)
        if [ -n "$veth_tag" ]; then
            echo "  VLAN tag: $veth_tag"
        else
            # Could be permission issue or not connected
            if ovs-vsctl port-to-br veth-wifi-b 2>/dev/null | grep -q "$OVS_BRIDGE"; then
                echo "  Connected (run as root for VLAN details)"
            else
                echo "  (not connected)"
            fi
        fi
    else
        echo "  (not configured)"
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

            # Avahi mDNS coexistence for Ecosystem Bubble detection
            # Enables HomeKit/AirPlay device grouping via PresenceSensor
            setup_avahi_coexistence || log_warn "Avahi setup had issues (non-fatal)"

            # WiFi bridge for SDN Autopilot (ap_isolate=1 + hairpin mDNS)
            # Allows full OVS control over WiFi traffic including device-to-device
            setup_wifi_bridge || log_warn "WiFi bridge setup had issues (non-fatal)"

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
