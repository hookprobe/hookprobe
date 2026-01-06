#!/bin/bash
# ============================================================
# HookProbe Fortress Network Bridge Manager
# ============================================================
#
# Creates and manages the FTS bridge for Fortress deployments.
# FTS is a Layer 2 OVS switch - NO IP on bridge itself.
#
# Network Architecture:
#   WAN (Primary):   enp1s0, eth0, etc. → DHCP from ISP
#   WAN (Failover):  wwp0s20f0u4, wwan0 → LTE modem
#   FTS Bridge:      Layer 2 OVS switch (NO IP)
#   vlan100:         LAN clients + WiFi (10.200.0.1/XX - user configurable)
#
# The FTS bridge handles layer 2 switching and VLAN tagging.
# IP address is assigned to vlan100 interface.
# DHCP/DNS services bind to vlan100 (not the bridge).
# NOTE: MGMT VLAN (vlan200) removed - access control via OpenFlow fingerprint policies
#
# Version: 5.1.0
# License: AGPL-3.0
#
# ============================================================

set -e

LOG_TAG="fts-bridge"

log_info() {
    logger -t "$LOG_TAG" -p user.info "$1" 2>/dev/null || true
    echo "[INFO] $1"
}

log_warn() {
    logger -t "$LOG_TAG" -p user.warning "$1" 2>/dev/null || true
    echo "[WARN] $1"
}

log_error() {
    logger -t "$LOG_TAG" -p user.err "$1" 2>/dev/null || true
    echo "[ERROR] $1"
}

log_success() {
    logger -t "$LOG_TAG" -p user.notice "$1" 2>/dev/null || true
    echo "[OK] $1"
}

# Configuration
# NOTE: FTS bridge is Layer 2 only - NO IP on bridge itself
# IP is assigned to vlan100 (LAN) - access control via OpenFlow fingerprint policies
BRIDGE_NAME="${FORTRESS_BRIDGE_NAME:-FTS}"
VLAN_LAN_IP="${FORTRESS_VLAN_LAN_IP:-10.200.0.1}"
VLAN_LAN_MASK="${FORTRESS_VLAN_LAN_MASK:-24}"

# State directory
STATE_DIR="/var/lib/fortress/bridge"

# ============================================================
# Bridge Creation
# ============================================================

create_bridge() {
    # Create the FTS bridge if it doesn't exist
    # NOTE: FTS bridge is Layer 2 only - NO IP on bridge
    # IP is assigned to vlan100 interface
    #
    # Args:
    #   $1 - Bridge name (optional, defaults to FTS)

    local bridge="${1:-$BRIDGE_NAME}"

    log_info "Creating bridge: $bridge (Layer 2 - no IP)"

    # Check if bridge already exists
    if ip link show "$bridge" &>/dev/null; then
        log_info "Bridge $bridge already exists"
    else
        # Create bridge
        ip link add name "$bridge" type bridge 2>/dev/null || {
            log_error "Failed to create bridge $bridge"
            return 1
        }
        log_success "Bridge $bridge created"
    fi

    # Configure bridge - bring up without IP
    ip link set "$bridge" up 2>/dev/null || true

    # NOTE: NO IP assigned to bridge - IP goes on vlan100
    log_info "Bridge $bridge is Layer 2 only (no IP)"
    log_info "IP will be assigned to vlan100 ($VLAN_LAN_IP/$VLAN_LAN_MASK)"

    # Disable STP (not needed for small networks)
    if [ -f "/sys/class/net/$bridge/bridge/stp_state" ]; then
        echo 0 > "/sys/class/net/$bridge/bridge/stp_state" 2>/dev/null || true
    fi

    # Set forward delay to 0 for faster convergence
    if [ -f "/sys/class/net/$bridge/bridge/forward_delay" ]; then
        echo 0 > "/sys/class/net/$bridge/bridge/forward_delay" 2>/dev/null || true
    fi

    # Save state
    mkdir -p "$STATE_DIR"
    echo "$bridge" > "$STATE_DIR/bridge_name"

    log_success "Bridge $bridge configured (Layer 2)"
    return 0
}

delete_bridge() {
    # Delete the LAN bridge

    local bridge="${1:-$BRIDGE_NAME}"

    log_info "Deleting bridge: $bridge"

    # Remove all interfaces from bridge first
    for iface in $(ls /sys/class/net/"$bridge"/brif 2>/dev/null); do
        ip link set "$iface" nomaster 2>/dev/null || true
    done

    # Delete bridge
    ip link set "$bridge" down 2>/dev/null || true
    ip link delete "$bridge" type bridge 2>/dev/null || true

    log_success "Bridge $bridge deleted"
}

# ============================================================
# Interface Management
# ============================================================

add_interface_to_bridge() {
    # Add an interface to the bridge
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Bridge name (optional)

    local iface="$1"
    local bridge="${2:-$BRIDGE_NAME}"

    if [ -z "$iface" ]; then
        log_error "Interface name required"
        return 1
    fi

    # Check if interface exists
    if [ ! -d "/sys/class/net/$iface" ]; then
        log_error "Interface $iface does not exist"
        return 1
    fi

    # Check if bridge exists
    if [ ! -d "/sys/class/net/$bridge" ]; then
        log_error "Bridge $bridge does not exist"
        return 1
    fi

    # Check if already in bridge
    if [ -d "/sys/class/net/$bridge/brif/$iface" ]; then
        log_info "$iface already in bridge $bridge"
        return 0
    fi

    log_info "Adding $iface to bridge $bridge"

    # Bring interface up
    ip link set "$iface" up 2>/dev/null || true

    # Remove any IP from the interface (bridge will handle IP)
    ip addr flush dev "$iface" 2>/dev/null || true

    # Add to bridge
    ip link set "$iface" master "$bridge" 2>/dev/null || {
        log_error "Failed to add $iface to $bridge"
        return 1
    }

    log_success "$iface added to bridge $bridge"
    return 0
}

remove_interface_from_bridge() {
    # Remove an interface from the bridge

    local iface="$1"

    if [ -z "$iface" ]; then
        log_error "Interface name required"
        return 1
    fi

    log_info "Removing $iface from bridge"

    ip link set "$iface" nomaster 2>/dev/null || true

    log_success "$iface removed from bridge"
}

# ============================================================
# Automatic Interface Assignment
# ============================================================

setup_lan_bridge() {
    # Automatically set up LAN bridge with detected interfaces
    #
    # Uses FORTRESS_* variables from detect-hardware.sh:
    #   FORTRESS_WAN_IFACE - Primary WAN (excluded from bridge)
    #   FORTRESS_LAN_IFACES - LAN interfaces (added to bridge)
    #
    # Args:
    #   $1 - WAN interface to exclude (optional)
    #   $2 - LTE interface to exclude (optional)

    local wan_exclude="${1:-$FORTRESS_WAN_IFACE}"
    local lte_exclude="${2:-$LTE_INTERFACE}"

    log_info "Setting up LAN bridge..."
    log_info "  Excluding WAN: ${wan_exclude:-none}"
    log_info "  Excluding LTE: ${lte_exclude:-none}"

    # Create bridge
    create_bridge

    # Get all ethernet interfaces
    local eth_ifaces=()
    for iface in /sys/class/net/*; do
        [ -d "$iface" ] || continue
        local name=$(basename "$iface")

        # Skip special interfaces
        case "$name" in
            lo|$BRIDGE_NAME|ovs-*|veth*|docker*|br-*)
                continue
                ;;
        esac

        # Skip WAN interface
        [ "$name" = "$wan_exclude" ] && continue

        # Skip LTE interface
        [ "$name" = "$lte_exclude" ] && continue

        # Skip WWAN interfaces (LTE modems)
        case "$name" in
            wwan*|wwp*)
                continue
                ;;
        esac

        # Skip wireless interfaces (handled separately by hostapd)
        if [ -d "$iface/wireless" ] || [ -L "$iface/phy80211" ]; then
            log_info "  Skipping WiFi: $name (managed by hostapd)"
            continue
        fi

        # Check if it's an ethernet interface
        local driver
        driver=$(readlink -f "$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "")

        # Add if it looks like ethernet
        if [ -n "$driver" ] || [[ "$name" =~ ^(eth|enp|eno|ens) ]]; then
            eth_ifaces+=("$name")
        fi
    done

    # Add LAN interfaces to bridge
    if [ -n "$FORTRESS_LAN_IFACES" ]; then
        for iface in $FORTRESS_LAN_IFACES; do
            add_interface_to_bridge "$iface"
        done
    else
        # Fallback: add detected ethernet interfaces
        for iface in "${eth_ifaces[@]}"; do
            add_interface_to_bridge "$iface"
        done
    fi

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # Show bridge status
    show_bridge_status

    log_success "LAN bridge setup complete"
}

# ============================================================
# NetworkManager Integration
# ============================================================

configure_nm_bridge() {
    # Create bridge using NetworkManager
    # NOTE: FTS bridge is Layer 2 only - no IP on bridge
    #
    # This is an alternative to the manual bridge creation
    # when NetworkManager is managing the network

    local bridge="${1:-$BRIDGE_NAME}"
    local lan_ifaces="${2:-$FORTRESS_LAN_IFACES}"

    if ! command -v nmcli &>/dev/null; then
        log_warn "NetworkManager not available"
        return 1
    fi

    log_info "Creating bridge via NetworkManager: $bridge (Layer 2 - no IP)"

    # Delete existing bridge connection
    nmcli con delete "$bridge" 2>/dev/null || true

    # Create bridge without IP (Layer 2 only)
    nmcli con add type bridge ifname "$bridge" con-name "$bridge" \
        ipv4.method disabled \
        ipv6.method disabled \
        bridge.stp no \
        bridge.forward-delay 0 \
        2>/dev/null || {
        log_error "Failed to create nmcli bridge"
        return 1
    }

    # Add slave interfaces
    for iface in $lan_ifaces; do
        local slave_name="${bridge}-slave-${iface}"

        # Delete existing slave
        nmcli con delete "$slave_name" 2>/dev/null || true

        # Create slave
        nmcli con add type bridge-slave ifname "$iface" master "$bridge" con-name "$slave_name" \
            2>/dev/null || {
            log_warn "Failed to add $iface as bridge slave"
        }
    done

    # Activate bridge
    nmcli con up "$bridge" 2>/dev/null || true

    log_success "NetworkManager bridge created: $bridge (Layer 2)"
    log_info "IP should be assigned to vlan100, not the bridge"
}

# ============================================================
# Netplan Integration
# ============================================================

generate_netplan_bridge() {
    # Generate netplan configuration for the bridge
    # NOTE: FTS bridge is Layer 2 only - no IP on bridge
    # IP is assigned to vlan100
    #
    # Args:
    #   $1 - Output file path

    local output_file="${1:-/etc/netplan/60-fts-bridge.yaml}"
    local wan_iface="${FORTRESS_WAN_IFACE:-eth0}"
    local lan_ifaces="${FORTRESS_LAN_IFACES:-eth1}"

    log_info "Generating netplan bridge configuration..."

    mkdir -p "$(dirname "$output_file")"

    cat > "$output_file" << NETPLANEOF
# HookProbe Fortress Bridge Configuration
# Generated: $(date -Iseconds)
#
# WAN: $wan_iface (DHCP)
# LAN Bridge: $BRIDGE_NAME ($lan_ifaces) - Layer 2 only, no IP
# IP: vlan100 ($VLAN_LAN_IP/$VLAN_LAN_MASK)
#
network:
  version: 2
  renderer: networkd

  ethernets:
    # WAN Interface
    $wan_iface:
      dhcp4: true
      dhcp6: false
      optional: true
NETPLANEOF

    # Add LAN interfaces
    for iface in $lan_ifaces; do
        cat >> "$output_file" << LANEOF

    # LAN Interface (bridged)
    $iface:
      dhcp4: false
      dhcp6: false
      optional: true
LANEOF
    done

    # Add bridge definition - NO IP (Layer 2 only)
    cat >> "$output_file" << BRIDGEEOF

  bridges:
    $BRIDGE_NAME:
      interfaces:
BRIDGEEOF

    for iface in $lan_ifaces; do
        echo "        - $iface" >> "$output_file"
    done

    cat >> "$output_file" << BRIDGECFGEOF
      # NO IP on bridge - Layer 2 only
      # IP is assigned to vlan100
      dhcp4: false
      dhcp6: false
      parameters:
        stp: false
        forward-delay: 0
BRIDGECFGEOF

    chmod 644 "$output_file"
    log_success "Generated netplan config: $output_file"
    log_info "Note: IP should be assigned to vlan100, not the bridge"

    # Suggest applying
    echo ""
    echo "To apply:"
    echo "  sudo netplan apply"
}

# ============================================================
# DHCP Server Setup (dnsmasq)
# ============================================================

configure_dnsmasq_bridge() {
    # Configure dnsmasq for DHCP on vlan100 (LAN VLAN)
    # NOTE: FTS bridge is Layer 2 only - DHCP binds to vlan100
    #
    # Uses setup-dhcp.sh for the main configuration.
    # This function is for fallback/manual setup only.

    local config_file="/etc/dnsmasq.d/fts-bridge.conf"
    local dhcp_start="${FORTRESS_DHCP_START:-}"
    local dhcp_end="${FORTRESS_DHCP_END:-}"
    local dhcp_lease="${FORTRESS_DHCP_LEASE:-12h}"
    local subnet_mask="${VLAN_LAN_MASK:-24}"
    local gateway="${VLAN_LAN_IP:-10.200.0.1}"
    local dhcp_iface="vlan100"

    # Calculate DHCP range based on subnet mask if not explicitly set
    # CRITICAL: Wrong defaults cause DHCP failures on small subnets!
    if [ -z "$dhcp_start" ] || [ -z "$dhcp_end" ]; then
        case "$subnet_mask" in
            29) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.6" ;;
            28) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.14" ;;
            27) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.30" ;;
            26) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.62" ;;
            25) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.126" ;;
            24) dhcp_start="10.200.0.100"; dhcp_end="10.200.0.200" ;;
            *)  dhcp_start="10.200.0.100"; dhcp_end="10.200.1.200" ;;
        esac
    fi

    log_info "Configuring dnsmasq for DHCP on $dhcp_iface..."
    log_info "  Subnet: /${subnet_mask}, DHCP range: ${dhcp_start} - ${dhcp_end}"
    log_info "  Gateway: $gateway"

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << DNSMASQEOF
# HookProbe Fortress DHCP Configuration
# Generated: $(date -Iseconds)
#
# NOTE: DHCP binds to vlan100 (FTS bridge is Layer 2 only)

# Interface binding - vlan100 (NOT the FTS bridge)
interface=$dhcp_iface
bind-dynamic

# DHCP range
dhcp-range=$dhcp_start,$dhcp_end,$dhcp_lease

# Gateway (vlan100 IP)
dhcp-option=3,$gateway

# DNS (vlan100 IP)
dhcp-option=6,$gateway

# Domain
domain=hookprobe.local
local=/hookprobe.local/

# Logging
log-dhcp
log-queries

# Cache
cache-size=1000
DNSMASQEOF

    chmod 644 "$config_file"
    log_success "dnsmasq config created: $config_file"

    # Restart dnsmasq if running
    if systemctl is-active dnsmasq &>/dev/null; then
        systemctl restart dnsmasq 2>/dev/null || true
    fi
}

configure_dnsmasq_bridge_custom() {
    # Configure dnsmasq for DHCP on vlan100 with custom parameters
    # NOTE: FTS bridge is Layer 2 only - DHCP binds to vlan100
    #
    # Args:
    #   $1 - Gateway IP (vlan100 IP)
    #   $2 - DHCP range start
    #   $3 - DHCP range end
    #   $4 - Lease time (optional, default 12h)

    local gateway="${1:-$VLAN_LAN_IP}"
    local dhcp_start="${2:-10.200.0.100}"
    local dhcp_end="${3:-10.200.0.200}"
    local dhcp_lease="${4:-12h}"
    local dhcp_iface="vlan100"
    local config_file="/etc/dnsmasq.d/fts-bridge.conf"

    log_info "Configuring dnsmasq for DHCP on $dhcp_iface..."
    log_info "  Gateway:    $gateway"
    log_info "  DHCP range: $dhcp_start - $dhcp_end"

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << DNSMASQEOF
# HookProbe Fortress DHCP Configuration
# Generated: $(date -Iseconds)
#
# NOTE: DHCP binds to vlan100 (FTS bridge is Layer 2 only)

# Interface binding - vlan100 (NOT the FTS bridge)
interface=$dhcp_iface
bind-dynamic

# DHCP range
dhcp-range=$dhcp_start,$dhcp_end,$dhcp_lease

# Gateway (vlan100 IP)
dhcp-option=3,$gateway

# DNS (vlan100 IP)
dhcp-option=6,$gateway

# Domain
domain=hookprobe.local
local=/hookprobe.local/

# Logging
log-dhcp
log-queries

# Cache
cache-size=1000
DNSMASQEOF

    chmod 644 "$config_file"
    log_success "dnsmasq config created: $config_file"

    # Restart dnsmasq if running
    if systemctl is-active dnsmasq &>/dev/null; then
        systemctl restart dnsmasq 2>/dev/null || true
    fi
}

# ============================================================
# NAT/Masquerade Setup
# ============================================================

setup_nat() {
    # Configure NAT masquerading for LAN -> WAN

    local wan_iface="${1:-$FORTRESS_WAN_IFACE}"

    if [ -z "$wan_iface" ]; then
        log_error "WAN interface required for NAT"
        return 1
    fi

    log_info "Setting up NAT (masquerade) on $wan_iface..."

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # Add iptables masquerade rule
    iptables -t nat -C POSTROUTING -o "$wan_iface" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$wan_iface" -j MASQUERADE

    # Allow forwarding from bridge to WAN
    iptables -C FORWARD -i "$BRIDGE_NAME" -o "$wan_iface" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$BRIDGE_NAME" -o "$wan_iface" -j ACCEPT

    # Allow established connections back
    iptables -C FORWARD -i "$wan_iface" -o "$BRIDGE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$wan_iface" -o "$BRIDGE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT

    log_success "NAT configured on $wan_iface"
}

# ============================================================
# Status and Info
# ============================================================

show_bridge_status() {
    # Display bridge status
    # NOTE: FTS bridge is Layer 2 only - IP on vlan100

    local bridge="${1:-$BRIDGE_NAME}"

    echo ""
    echo "Bridge Status: $bridge (Layer 2 - no IP)"
    echo "═══════════════════════════════════════════════════"

    if [ ! -d "/sys/class/net/$bridge" ]; then
        echo "  Bridge does not exist"
        return 1
    fi

    # Bridge info
    local bridge_state
    bridge_state=$(cat "/sys/class/net/$bridge/operstate" 2>/dev/null || echo "unknown")

    echo "  Mode:       Layer 2 switch (no IP)"
    echo "  State:      $bridge_state"

    # Show VLAN IP if available
    if ip link show vlan100 &>/dev/null; then
        local vlan100_ip
        vlan100_ip=$(ip addr show vlan100 2>/dev/null | grep "inet " | awk '{print $2}')
        echo "  vlan100 IP: ${vlan100_ip:-not set} (LAN clients)"
    fi

    # List bridge members
    echo ""
    echo "Bridge Members:"
    local member_count=0
    for iface in /sys/class/net/"$bridge"/brif/*; do
        if [ -d "$iface" ]; then
            local name=$(basename "$iface")
            local state
            state=$(cat "/sys/class/net/$name/operstate" 2>/dev/null || echo "unknown")
            local mac
            mac=$(cat "/sys/class/net/$name/address" 2>/dev/null || echo "")
            echo "  - $name (state: $state, MAC: $mac)"
            ((member_count++))
        fi
    done 2>/dev/null

    if [ "$member_count" -eq 0 ]; then
        echo "  (no members)"
    fi

    echo ""
}

# ============================================================
# Main Entry Point
# ============================================================

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "FTS Bridge Manager - Layer 2 OVS bridge for Fortress"
    echo ""
    echo "Network Architecture:"
    echo "  FTS Bridge:  Layer 2 switch (no IP)"
    echo "  vlan100:     LAN clients + WiFi (10.200.0.1/XX)"
    echo "  Note: Access control via OpenFlow fingerprint policies"
    echo ""
    echo "Commands:"
    echo "  create [name]             - Create Layer 2 bridge"
    echo "  delete [name]             - Delete bridge"
    echo "  add <iface> [bridge]      - Add interface to bridge"
    echo "  remove <iface>            - Remove interface from bridge"
    echo "  setup                     - Auto-setup LAN bridge"
    echo "  status [bridge]           - Show bridge status"
    echo "  netplan [output_file]     - Generate netplan config"
    echo "  dnsmasq                   - Configure dnsmasq DHCP on vlan100"
    echo "  nat <wan_iface>           - Setup NAT masquerade"
    echo ""
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        create)
            create_bridge "$2"
            ;;
        delete)
            delete_bridge "$2"
            ;;
        add)
            add_interface_to_bridge "$2" "$3"
            ;;
        remove)
            remove_interface_from_bridge "$2"
            ;;
        setup)
            setup_lan_bridge "$2" "$3"
            ;;
        status)
            show_bridge_status "$2"
            ;;
        netplan)
            generate_netplan_bridge "$2"
            ;;
        dnsmasq)
            configure_dnsmasq_bridge
            ;;
        nat)
            setup_nat "$2"
            ;;
        *)
            usage
            ;;
    esac
fi
