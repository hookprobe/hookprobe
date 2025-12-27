#!/bin/bash
#
# setup-dhcp.sh - Configure DHCP for Fortress OVS VLAN network
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Network Architecture:
#   FTS Bridge: Layer 2 OVS switch (NO IP)
#   vlan100: LAN clients + WiFi (IP: 10.200.0.1/XX)
#   vlan200: Management (IP: 10.200.100.1/30)
#
# DHCP listens on vlan100 (VLAN mode) or FTS (filter mode)
# DHCP range is calculated based on user's subnet size
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================
# Configuration (from environment or defaults)
# ============================================

# Network mode: "vlan" or "filter"
# vlan: IP on vlan100/vlan200, FTS bridge has no IP
# filter: IP on FTS bridge directly (simpler but less isolation)
NETWORK_MODE="${NETWORK_MODE:-vlan}"

# OVS Bridge name
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"

# LAN configuration
LAN_GATEWAY="${LAN_GATEWAY:-10.200.0.1}"
LAN_SUBNET_MASK="${LAN_SUBNET_MASK:-24}"

# VLAN interfaces
VLAN_LAN="${VLAN_LAN:-vlan100}"
VLAN_MGMT="${VLAN_MGMT:-vlan200}"

# MGMT configuration (fixed /30)
MGMT_GATEWAY="${MGMT_GATEWAY:-10.200.100.1}"
MGMT_SUBNET_MASK="30"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[DHCP]${NC} $*"; }
log_success() { echo -e "${GREEN}[DHCP]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[DHCP]${NC} $*"; }
log_error() { echo -e "${RED}[DHCP]${NC} $*"; }

# ============================================
# DHCP Range Calculation
# ============================================

# Calculate DHCP range based on subnet mask
# Returns: "start_ip,end_ip,netmask"
calculate_dhcp_range() {
    local subnet_mask="${1:-24}"
    local base_ip="10.200.0"

    case "$subnet_mask" in
        29)
            # /29 = 8 IPs (6 usable: .1 is gateway, .0 and .7 reserved)
            echo "${base_ip}.2,${base_ip}.6,255.255.255.248"
            ;;
        28)
            # /28 = 16 IPs (14 usable)
            echo "${base_ip}.2,${base_ip}.14,255.255.255.240"
            ;;
        27)
            # /27 = 32 IPs (30 usable) - reserve .1-.9 for static
            echo "${base_ip}.10,${base_ip}.30,255.255.255.224"
            ;;
        26)
            # /26 = 64 IPs (62 usable) - reserve .1-.9 for static
            echo "${base_ip}.10,${base_ip}.62,255.255.255.192"
            ;;
        25)
            # /25 = 128 IPs (126 usable) - reserve .1-.9 for static
            echo "${base_ip}.10,${base_ip}.126,255.255.255.128"
            ;;
        24)
            # /24 = 256 IPs (254 usable) - reserve .1-.99 for static
            echo "${base_ip}.100,${base_ip}.200,255.255.255.0"
            ;;
        23)
            # /23 = 512 IPs (510 usable) - reserve .1-.99 for static
            echo "${base_ip}.100,10.200.1.200,255.255.254.0"
            ;;
        *)
            # Default to /24
            log_warn "Unknown subnet mask /$subnet_mask, defaulting to /24"
            echo "${base_ip}.100,${base_ip}.200,255.255.255.0"
            ;;
    esac
}

# Get DHCP interface based on network mode
get_dhcp_interface() {
    if [ "$NETWORK_MODE" = "vlan" ]; then
        echo "$VLAN_LAN"
    else
        echo "$OVS_BRIDGE"
    fi
}

# ============================================
# Diagnosis
# ============================================

diagnose() {
    echo "========================================"
    echo "Fortress DHCP Diagnosis"
    echo "========================================"
    echo ""

    # Show configuration
    echo "1. CONFIGURATION:"
    echo "   Network Mode:    $NETWORK_MODE"
    echo "   OVS Bridge:      $OVS_BRIDGE"
    echo "   DHCP Interface:  $(get_dhcp_interface)"
    echo "   LAN Gateway:     $LAN_GATEWAY/$LAN_SUBNET_MASK"
    if [ "$NETWORK_MODE" = "vlan" ]; then
        echo "   VLAN LAN:        $VLAN_LAN"
        echo "   VLAN MGMT:       $VLAN_MGMT"
        echo "   MGMT Gateway:    $MGMT_GATEWAY/$MGMT_SUBNET_MASK"
    fi
    echo ""

    # Check dnsmasq status
    echo "2. DNSMASQ SERVICE STATUS:"
    if systemctl is-active dnsmasq &>/dev/null; then
        echo "   [OK] dnsmasq is running"
    else
        echo "   [FAIL] dnsmasq is NOT running"
        systemctl status dnsmasq 2>&1 | head -10 | sed 's/^/   /'
    fi
    echo ""

    # Check listening ports
    echo "3. DHCP LISTENING PORTS (UDP 67):"
    if command -v ss &>/dev/null; then
        ss -ulnp | grep ":67 " | sed 's/^/   /' || echo "   No DHCP server listening on port 67"
    fi
    echo ""

    # Check DHCP interface
    local dhcp_iface
    dhcp_iface=$(get_dhcp_interface)
    echo "4. DHCP INTERFACE STATUS ($dhcp_iface):"
    if ip link show "$dhcp_iface" &>/dev/null; then
        local ip
        ip=$(ip -4 addr show "$dhcp_iface" 2>/dev/null | grep "inet " | awk '{print $2}')
        local state
        state=$(ip link show "$dhcp_iface" | grep -oP 'state \K\S+')
        if [ -n "$ip" ]; then
            echo "   [OK] $dhcp_iface: $ip ($state)"
        else
            echo "   [WARN] $dhcp_iface: NO IP ($state)"
        fi
    else
        echo "   [MISSING] $dhcp_iface does not exist"
    fi
    echo ""

    # Check FTS bridge
    echo "5. FTS BRIDGE STATUS:"
    if ip link show "$OVS_BRIDGE" &>/dev/null; then
        local bridge_ip
        bridge_ip=$(ip -4 addr show "$OVS_BRIDGE" 2>/dev/null | grep "inet " | awk '{print $2}')
        local bridge_state
        bridge_state=$(ip link show "$OVS_BRIDGE" | grep -oP 'state \K\S+')
        if [ -n "$bridge_ip" ]; then
            echo "   $OVS_BRIDGE: $bridge_ip ($bridge_state)"
            if [ "$NETWORK_MODE" = "vlan" ]; then
                echo "   [WARN] In VLAN mode, FTS should have NO IP"
            fi
        else
            echo "   $OVS_BRIDGE: NO IP ($bridge_state)"
            if [ "$NETWORK_MODE" = "vlan" ]; then
                echo "   [OK] Correct - FTS has no IP in VLAN mode"
            fi
        fi
    else
        echo "   [MISSING] $OVS_BRIDGE bridge does not exist"
    fi
    echo ""

    # Check VLAN interfaces (if in VLAN mode)
    if [ "$NETWORK_MODE" = "vlan" ]; then
        echo "6. VLAN INTERFACE STATUS:"
        for iface in "$VLAN_LAN" "$VLAN_MGMT"; do
            if ip link show "$iface" &>/dev/null; then
                local ip
                ip=$(ip -4 addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}')
                local state
                state=$(ip link show "$iface" | grep -oP 'state \K\S+')
                if [ -n "$ip" ]; then
                    echo "   [OK] $iface: $ip ($state)"
                else
                    echo "   [WARN] $iface: NO IP ($state)"
                fi
            else
                echo "   [MISSING] $iface does not exist"
            fi
        done
        echo ""
    fi

    # Check dnsmasq config
    echo "7. DNSMASQ CONFIGURATION:"
    if [ -f /etc/dnsmasq.d/fortress.conf ]; then
        echo "   [OK] /etc/dnsmasq.d/fortress.conf exists"
        echo "   Interface:"
        grep "^interface=" /etc/dnsmasq.d/fortress.conf | sed 's/^/      /'
        echo "   DHCP range:"
        grep "^dhcp-range=" /etc/dnsmasq.d/fortress.conf | sed 's/^/      /'
    else
        echo "   [FAIL] /etc/dnsmasq.d/fortress.conf not found"
    fi
    echo ""

    # Recent DHCP logs
    echo "8. RECENT DHCP LOG ENTRIES:"
    if [ -f /var/log/dnsmasq.log ]; then
        tail -10 /var/log/dnsmasq.log | sed 's/^/   /'
    else
        journalctl -u dnsmasq --no-pager -n 10 2>/dev/null | sed 's/^/   /' || echo "   No logs available"
    fi
    echo ""
}

# ============================================
# Installation
# ============================================

install_dnsmasq() {
    log_info "Installing dnsmasq..."

    if command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y dnsmasq
    elif command -v dnf &>/dev/null; then
        dnf install -y dnsmasq
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm dnsmasq
    else
        log_error "Unknown package manager"
        return 1
    fi

    log_success "dnsmasq installed"
}

# ============================================
# Configuration
# ============================================

configure() {
    log_info "Configuring DHCP for Fortress..."
    log_info "  Network Mode:   $NETWORK_MODE"
    log_info "  Subnet:         /$LAN_SUBNET_MASK"

    # Ensure dnsmasq is installed
    if ! command -v dnsmasq &>/dev/null; then
        install_dnsmasq
    fi

    # Backup existing config
    if [ -f /etc/dnsmasq.conf ] && [ ! -f /etc/dnsmasq.conf.backup ]; then
        cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
        log_info "Backed up existing config to /etc/dnsmasq.conf.backup"
    fi

    # Create config directory
    mkdir -p /etc/dnsmasq.d

    # Ensure main config includes conf-dir
    if ! grep -q "^conf-dir=/etc/dnsmasq.d" /etc/dnsmasq.conf 2>/dev/null; then
        echo "conf-dir=/etc/dnsmasq.d/,*.conf" >> /etc/dnsmasq.conf
        log_info "Added conf-dir to /etc/dnsmasq.conf"
    fi

    # Generate Fortress DHCP config
    generate_dhcp_config

    # Create directories
    mkdir -p /var/lib/dnsmasq
    chown dnsmasq:dnsmasq /var/lib/dnsmasq 2>/dev/null || true
    touch /var/log/dnsmasq.log
    chown dnsmasq:dnsmasq /var/log/dnsmasq.log 2>/dev/null || true

    # Test config
    log_info "Testing dnsmasq configuration..."
    if dnsmasq --test; then
        log_success "Configuration is valid"
    else
        log_error "Configuration has errors"
        return 1
    fi

    # Restart dnsmasq
    log_info "Restarting dnsmasq..."
    systemctl restart dnsmasq
    systemctl enable dnsmasq

    # Verify it's running
    sleep 2
    if systemctl is-active dnsmasq &>/dev/null; then
        log_success "dnsmasq is running"
    else
        log_error "dnsmasq failed to start"
        journalctl -u dnsmasq --no-pager -n 20
        return 1
    fi

    # Open firewall
    open_firewall

    log_success "DHCP configuration complete!"
}

generate_dhcp_config() {
    local config_file="/etc/dnsmasq.d/fortress.conf"
    local dhcp_iface
    dhcp_iface=$(get_dhcp_interface)

    # Calculate DHCP range
    local dhcp_range
    dhcp_range=$(calculate_dhcp_range "$LAN_SUBNET_MASK")
    local dhcp_start="${dhcp_range%%,*}"
    local dhcp_rest="${dhcp_range#*,}"
    local dhcp_end="${dhcp_rest%%,*}"
    local dhcp_netmask="${dhcp_rest##*,}"

    log_info "Generating DHCP config:"
    log_info "  Interface:  $dhcp_iface"
    log_info "  Gateway:    $LAN_GATEWAY"
    log_info "  DHCP Range: $dhcp_start - $dhcp_end"
    log_info "  Netmask:    $dhcp_netmask"

    cat > "$config_file" << EOF
# HookProbe Fortress DHCP Configuration
# Generated: $(date -Iseconds)
#
# Network Mode: $NETWORK_MODE
# LAN Subnet: 10.200.0.0/$LAN_SUBNET_MASK
#
# Network Architecture:
#   FTS Bridge: Layer 2 OVS switch (NO IP)
#   vlan100: LAN clients + WiFi
#   vlan200: Management network
#

# ============================================
# General settings
# ============================================
domain-needed
bogus-priv
no-resolv
no-poll

# Upstream DNS (fallback if dnsXai unavailable)
server=1.1.1.1
server=8.8.8.8

# Forward to dnsXai container first (port 5353)
server=127.0.0.1#5353

# Local domain
local=/fortress.local/
domain=fortress.local
expand-hosts
no-hosts

# DHCP authoritative mode
dhcp-authoritative
dhcp-rapid-commit

# Performance
cache-size=2000
neg-ttl=60
min-cache-ttl=300

# ============================================
# Interface binding
# ============================================
# Mode: $NETWORK_MODE
# Interface: $dhcp_iface
interface=$dhcp_iface
bind-dynamic

# ============================================
# DHCP Configuration (/$LAN_SUBNET_MASK)
# ============================================
# Range: $dhcp_start - $dhcp_end
# Netmask: $dhcp_netmask
# Lease: 12 hours
dhcp-range=lan,$dhcp_start,$dhcp_end,$dhcp_netmask,12h

# Gateway (Fortress)
dhcp-option=lan,3,$LAN_GATEWAY

# DNS (Fortress - dnsXai filtering)
dhcp-option=lan,6,$LAN_GATEWAY

# Domain search
dhcp-option=lan,15,fortress.local
dhcp-option=lan,119,fortress.local

# ============================================
# Lease database and event handling
# ============================================
dhcp-leasefile=/var/lib/dnsmasq/fortress.leases
dhcp-script=/opt/hookprobe/fortress/bin/dhcp-event.sh

# ============================================
# Device type identification
# ============================================
dhcp-vendorclass=set:apple,Apple
dhcp-vendorclass=set:android,android
dhcp-vendorclass=set:windows,MSFT
dhcp-vendorclass=set:linux,Linux

# ============================================
# Logging
# ============================================
log-facility=/var/log/dnsmasq.log
log-dhcp
log-async=25
quiet-dhcp

# ============================================
# DNS Security
# ============================================
stop-dns-rebind
rebind-localhost-ok
EOF

    chmod 644 "$config_file"
    log_success "Generated $config_file"
}

open_firewall() {
    log_info "Opening firewall for DHCP..."

    local dhcp_iface
    dhcp_iface=$(get_dhcp_interface)

    # Accept DHCP on DHCP interface and WiFi interfaces
    for iface in "$dhcp_iface" wlan0 wlp6s0; do
        if ip link show "$iface" &>/dev/null; then
            # Allow DHCP (UDP 67/68)
            iptables -I INPUT -i "$iface" -p udp --dport 67 -j ACCEPT 2>/dev/null || true
            iptables -I INPUT -i "$iface" -p udp --dport 68 -j ACCEPT 2>/dev/null || true
            # Allow DNS (UDP/TCP 53)
            iptables -I INPUT -i "$iface" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
            iptables -I INPUT -i "$iface" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
        fi
    done

    log_success "Firewall rules added"
}

# ============================================
# Quick Fix
# ============================================

quickfix() {
    log_info "Attempting quick fix..."

    # 1. Ensure dnsmasq is installed and configured
    if [ ! -f /etc/dnsmasq.d/fortress.conf ]; then
        configure
        return
    fi

    # 2. Restart dnsmasq
    systemctl restart dnsmasq

    # 3. Open firewall
    open_firewall

    # 4. Diagnose
    diagnose
}

# ============================================
# Usage
# ============================================

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  diagnose   - Show DHCP diagnostic information"
    echo "  configure  - Generate and install dnsmasq configuration"
    echo "  quickfix   - Quick fix common DHCP issues"
    echo "  firewall   - Open firewall for DHCP/DNS"
    echo ""
    echo "Environment Variables:"
    echo "  NETWORK_MODE     - 'vlan' (default) or 'filter'"
    echo "  LAN_SUBNET_MASK  - Subnet size: 29, 28, 27, 26, 25, 24, 23 (default: 24)"
    echo "  LAN_GATEWAY      - Gateway IP (default: 10.200.0.1)"
    echo "  OVS_BRIDGE       - OVS bridge name (default: FTS)"
    echo "  VLAN_LAN         - LAN VLAN interface (default: vlan100)"
    echo "  VLAN_MGMT        - Management VLAN interface (default: vlan200)"
    echo ""
    echo "DHCP Range by Subnet:"
    echo "  /29  →  10.200.0.2 - 10.200.0.6      (6 devices)"
    echo "  /28  →  10.200.0.2 - 10.200.0.14     (14 devices)"
    echo "  /27  →  10.200.0.10 - 10.200.0.30    (30 devices)"
    echo "  /26  →  10.200.0.10 - 10.200.0.62    (62 devices)"
    echo "  /25  →  10.200.0.10 - 10.200.0.126   (126 devices)"
    echo "  /24  →  10.200.0.100 - 10.200.0.200  (254 devices)"
    echo "  /23  →  10.200.0.100 - 10.200.1.200  (510 devices)"
    echo ""
    echo "Quick Start:"
    echo "  # Default /24 subnet, VLAN mode"
    echo "  $0 configure"
    echo ""
    echo "  # Small business with /27 subnet"
    echo "  LAN_SUBNET_MASK=27 $0 configure"
    echo ""
    echo "  # Filter mode (simpler, less isolation)"
    echo "  NETWORK_MODE=filter $0 configure"
    echo ""
}

# ============================================
# Load configuration from fortress state file
# ============================================

load_state() {
    local state_file="/etc/hookprobe/fortress-state.json"
    if [ -f "$state_file" ]; then
        # Load values from state file if not already set via environment
        if [ -z "${NETWORK_MODE:-}" ] || [ "$NETWORK_MODE" = "vlan" ]; then
            local mode
            mode=$(python3 -c "import json; print(json.load(open('$state_file')).get('network_mode', 'vlan'))" 2>/dev/null || echo "vlan")
            NETWORK_MODE="${NETWORK_MODE:-$mode}"
        fi
        if [ -z "${LAN_SUBNET_MASK:-}" ] || [ "$LAN_SUBNET_MASK" = "24" ]; then
            local mask
            mask=$(python3 -c "import json; s=json.load(open('$state_file')).get('lan_subnet', '10.200.0.0/24'); print(s.split('/')[1])" 2>/dev/null || echo "24")
            LAN_SUBNET_MASK="${LAN_SUBNET_MASK:-$mask}"
        fi
        if [ -z "${LAN_GATEWAY:-}" ] || [ "$LAN_GATEWAY" = "10.200.0.1" ]; then
            local gw
            gw=$(python3 -c "import json; print(json.load(open('$state_file')).get('lan_gateway', '10.200.0.1'))" 2>/dev/null || echo "10.200.0.1")
            LAN_GATEWAY="${LAN_GATEWAY:-$gw}"
        fi
    fi
}

# ============================================
# Main
# ============================================

# Load state on startup
load_state

case "${1:-}" in
    diagnose|diag|status)
        diagnose
        ;;
    configure|setup|install)
        configure
        ;;
    quickfix|fix)
        quickfix
        ;;
    firewall|fw)
        open_firewall
        ;;
    *)
        usage
        ;;
esac
