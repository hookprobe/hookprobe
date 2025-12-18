#!/bin/bash
# ============================================================
# HookProbe Fortress Network Bridge Manager
# ============================================================
#
# Creates and manages the LAN bridge for Fortress deployments.
# Combines LAN Ethernet interfaces and WiFi AP into a single
# bridged network segment.
#
# Network Architecture:
#   WAN (Primary):   enp1s0, eth0, etc. → DHCP from ISP
#   WAN (Failover):  wwp0s20f0u4, wwan0 → LTE modem
#   LAN Bridge:      br-lan → All other interfaces + WiFi AP
#
# Version: 5.0.0
# License: AGPL-3.0
#
# ============================================================

set -e

LOG_TAG="fortress-bridge"

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
BRIDGE_NAME="${FORTRESS_BRIDGE_NAME:-fortress}"
BRIDGE_IP="${FORTRESS_BRIDGE_IP:-10.200.0.1}"
BRIDGE_NETMASK="${FORTRESS_BRIDGE_NETMASK:-24}"
BRIDGE_NETWORK="${FORTRESS_BRIDGE_NETWORK:-10.200.0.0/24}"

# State directory
STATE_DIR="/var/lib/fortress/bridge"

# ============================================================
# Bridge Creation
# ============================================================

create_bridge() {
    # Create the LAN bridge if it doesn't exist
    #
    # Args:
    #   $1 - Bridge name (optional, defaults to br-lan)
    #   $2 - Bridge IP (optional, defaults to 10.200.0.1)

    local bridge="${1:-$BRIDGE_NAME}"
    local bridge_ip="${2:-$BRIDGE_IP}"

    log_info "Creating bridge: $bridge"

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

    # Configure bridge
    ip link set "$bridge" up 2>/dev/null || true

    # Set bridge IP if not already set
    if ! ip addr show "$bridge" 2>/dev/null | grep -q "$bridge_ip"; then
        ip addr add "${bridge_ip}/${BRIDGE_NETMASK}" dev "$bridge" 2>/dev/null || true
        log_info "Bridge IP set: ${bridge_ip}/${BRIDGE_NETMASK}"
    fi

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
    echo "$bridge_ip" > "$STATE_DIR/bridge_ip"

    log_success "Bridge $bridge configured"
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
    #
    # This is an alternative to the manual bridge creation
    # when NetworkManager is managing the network

    local bridge="${1:-$BRIDGE_NAME}"
    local bridge_ip="${2:-$BRIDGE_IP}"
    local lan_ifaces="${3:-$FORTRESS_LAN_IFACES}"

    if ! command -v nmcli &>/dev/null; then
        log_warn "NetworkManager not available"
        return 1
    fi

    log_info "Creating bridge via NetworkManager: $bridge"

    # Delete existing bridge connection
    nmcli con delete "$bridge" 2>/dev/null || true

    # Create bridge
    nmcli con add type bridge ifname "$bridge" con-name "$bridge" \
        ipv4.addresses "${bridge_ip}/${BRIDGE_NETMASK}" \
        ipv4.method manual \
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

    log_success "NetworkManager bridge created: $bridge"
}

# ============================================================
# Netplan Integration
# ============================================================

generate_netplan_bridge() {
    # Generate netplan configuration for the bridge
    #
    # Args:
    #   $1 - Output file path

    local output_file="${1:-/etc/netplan/60-fortress-bridge.yaml}"
    local wan_iface="${FORTRESS_WAN_IFACE:-eth0}"
    local lan_ifaces="${FORTRESS_LAN_IFACES:-eth1}"

    log_info "Generating netplan bridge configuration..."

    mkdir -p "$(dirname "$output_file")"

    cat > "$output_file" << NETPLANEOF
# HookProbe Fortress Bridge Configuration
# Generated: $(date -Iseconds)
#
# WAN: $wan_iface (DHCP)
# LAN Bridge: $BRIDGE_NAME ($lan_ifaces)
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

    # Add bridge definition
    cat >> "$output_file" << BRIDGEEOF

  bridges:
    $BRIDGE_NAME:
      interfaces:
BRIDGEEOF

    for iface in $lan_ifaces; do
        echo "        - $iface" >> "$output_file"
    done

    cat >> "$output_file" << BRIDGECFGEOF
      addresses:
        - ${BRIDGE_IP}/${BRIDGE_NETMASK}
      dhcp4: false
      parameters:
        stp: false
        forward-delay: 0
BRIDGECFGEOF

    chmod 644 "$output_file"
    log_success "Generated netplan config: $output_file"

    # Suggest applying
    echo ""
    echo "To apply:"
    echo "  sudo netplan apply"
}

# ============================================================
# DHCP Server Setup (dnsmasq)
# ============================================================

configure_dnsmasq_bridge() {
    # Configure dnsmasq for DHCP on the bridge

    local config_file="/etc/dnsmasq.d/fortress-bridge.conf"
    local dhcp_start="${FORTRESS_DHCP_START:-10.200.0.100}"
    local dhcp_end="${FORTRESS_DHCP_END:-10.200.0.200}"
    local dhcp_lease="${FORTRESS_DHCP_LEASE:-12h}"

    log_info "Configuring dnsmasq for bridge DHCP..."

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << DNSMASQEOF
# HookProbe Fortress DHCP Configuration
# Generated: $(date -Iseconds)

# Interface binding
interface=$BRIDGE_NAME
bind-interfaces

# DHCP range
dhcp-range=$dhcp_start,$dhcp_end,$dhcp_lease

# Gateway (this device)
dhcp-option=3,$BRIDGE_IP

# DNS (this device)
dhcp-option=6,$BRIDGE_IP

# Domain
domain=fortress.local
local=/fortress.local/

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
    # Configure dnsmasq for DHCP on the bridge with custom parameters
    #
    # Args:
    #   $1 - Bridge name
    #   $2 - Bridge IP (gateway)
    #   $3 - DHCP range start
    #   $4 - DHCP range end
    #   $5 - Lease time (optional, default 12h)

    local bridge="${1:-$BRIDGE_NAME}"
    local bridge_ip="${2:-$BRIDGE_IP}"
    local dhcp_start="${3:-10.200.0.100}"
    local dhcp_end="${4:-10.200.0.200}"
    local dhcp_lease="${5:-12h}"
    local config_file="/etc/dnsmasq.d/fortress-bridge.conf"

    log_info "Configuring dnsmasq for bridge DHCP..."
    log_info "  Bridge:     $bridge"
    log_info "  Gateway:    $bridge_ip"
    log_info "  DHCP range: $dhcp_start - $dhcp_end"

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << DNSMASQEOF
# HookProbe Fortress DHCP Configuration
# Generated: $(date -Iseconds)

# Interface binding
interface=$bridge
bind-interfaces

# DHCP range
dhcp-range=$dhcp_start,$dhcp_end,$dhcp_lease

# Gateway (this device)
dhcp-option=3,$bridge_ip

# DNS (this device)
dhcp-option=6,$bridge_ip

# Domain
domain=fortress.local
local=/fortress.local/

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

    local bridge="${1:-$BRIDGE_NAME}"

    echo ""
    echo "Bridge Status: $bridge"
    echo "═══════════════════════════════════════════════════"

    if [ ! -d "/sys/class/net/$bridge" ]; then
        echo "  Bridge does not exist"
        return 1
    fi

    # Bridge info
    local bridge_ip
    bridge_ip=$(ip addr show "$bridge" 2>/dev/null | grep "inet " | awk '{print $2}')
    local bridge_state
    bridge_state=$(cat "/sys/class/net/$bridge/operstate" 2>/dev/null || echo "unknown")

    echo "  IP Address: ${bridge_ip:-not set}"
    echo "  State:      $bridge_state"

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
    echo "Commands:"
    echo "  create [name] [ip]        - Create bridge"
    echo "  delete [name]             - Delete bridge"
    echo "  add <iface> [bridge]      - Add interface to bridge"
    echo "  remove <iface>            - Remove interface from bridge"
    echo "  setup                     - Auto-setup LAN bridge"
    echo "  status [bridge]           - Show bridge status"
    echo "  netplan [output_file]     - Generate netplan config"
    echo "  dnsmasq                   - Configure dnsmasq DHCP"
    echo "  nat <wan_iface>           - Setup NAT masquerade"
    echo ""
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        create)
            create_bridge "$2" "$3"
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
