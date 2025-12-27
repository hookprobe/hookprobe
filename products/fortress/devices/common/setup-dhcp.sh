#!/bin/bash
#
# setup-dhcp.sh - Configure DHCP for Fortress OVS network
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Sets up dnsmasq to provide DHCP on the FTS bridge interface
# Segment VLANs (10-99) share the LAN subnet - segmentation via OpenFlow
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# OVS Bridge name (FTS = abbreviation for Fortress)
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"

# Network configuration (matches config.py defaults)
LAN_GATEWAY="${LAN_GATEWAY:-10.200.0.1}"
LAN_SUBNET="${LAN_SUBNET:-10.200.0.0/24}"

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

# ========================================
# Diagnosis
# ========================================

diagnose() {
    echo "========================================"
    echo "Fortress DHCP Diagnosis"
    echo "========================================"
    echo ""

    # Check dnsmasq status
    echo "1. DNSMASQ SERVICE STATUS:"
    if systemctl is-active dnsmasq &>/dev/null; then
        echo "   [OK] dnsmasq is running"
    else
        echo "   [FAIL] dnsmasq is NOT running"
        systemctl status dnsmasq 2>&1 | head -10 | sed 's/^/   /'
    fi
    echo ""

    # Check listening ports
    echo "2. DHCP LISTENING PORTS (UDP 67):"
    if command -v ss &>/dev/null; then
        ss -ulnp | grep ":67 " | sed 's/^/   /' || echo "   No DHCP server listening on port 67"
    elif command -v netstat &>/dev/null; then
        netstat -ulnp | grep ":67 " | sed 's/^/   /' || echo "   No DHCP server listening on port 67"
    fi
    echo ""

    # Check FTS bridge interface
    echo "3. FTS BRIDGE STATUS:"
    if ip link show "$OVS_BRIDGE" &>/dev/null; then
        local ip
        ip=$(ip -4 addr show "$OVS_BRIDGE" 2>/dev/null | grep "inet " | awk '{print $2}')
        local state
        state=$(ip link show "$OVS_BRIDGE" | grep -oP 'state \K\S+')
        if [ -n "$ip" ]; then
            echo "   [OK] $OVS_BRIDGE: $ip ($state)"
        else
            echo "   [WARN] $OVS_BRIDGE: NO IP ($state)"
        fi
    else
        echo "   [MISSING] $OVS_BRIDGE bridge does not exist"
    fi
    echo ""

    # Check OVS status
    echo "4. OVS BRIDGE PORTS:"
    if command -v ovs-vsctl &>/dev/null; then
        echo "   Bridge: $OVS_BRIDGE"
        ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | sed 's/^/      /' || echo "      No ports configured"
    else
        echo "   [WARN] ovs-vsctl not available"
    fi
    echo ""

    # Check WiFi bridge membership
    echo "5. WIFI INTERFACES:"
    for iface in wlan0 wlp6s0; do
        if ip link show "$iface" &>/dev/null; then
            local master
            master=$(ip link show "$iface" 2>/dev/null | grep -oP 'master \K\S+' || echo "none")
            local state
            state=$(ip link show "$iface" | grep -oP 'state \K\S+')
            echo "   $iface: master=$master, state=$state"

            # Check if in OVS
            if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${iface}$"; then
                local vlan
                vlan=$(ovs-vsctl get port "$iface" tag 2>/dev/null || echo "trunk")
                echo "      -> In OVS $OVS_BRIDGE bridge, VLAN=$vlan"
            fi
        fi
    done
    echo ""

    # Check dnsmasq config
    echo "6. DNSMASQ CONFIGURATION:"
    if [ -f /etc/dnsmasq.d/fortress.conf ]; then
        echo "   [OK] /etc/dnsmasq.d/fortress.conf exists"
        echo "   Interfaces configured:"
        grep "^interface=" /etc/dnsmasq.d/fortress.conf | sed 's/^/      /'
        echo "   DHCP ranges:"
        grep "^dhcp-range=" /etc/dnsmasq.d/fortress.conf | sed 's/^/      /'
    elif [ -f /etc/dnsmasq.conf ]; then
        echo "   [WARN] Using /etc/dnsmasq.conf (may not be configured for Fortress)"
        grep -E "^(interface|dhcp-range)=" /etc/dnsmasq.conf 2>/dev/null | head -10 | sed 's/^/      /'
    else
        echo "   [FAIL] No dnsmasq configuration found"
    fi
    echo ""

    # Check firewall
    echo "7. FIREWALL (DHCP UDP 67/68):"
    if command -v iptables &>/dev/null; then
        local dhcp_rules
        dhcp_rules=$(iptables -L INPUT -n 2>/dev/null | grep -E "(67|68|dhcp)" | wc -l)
        if [ "$dhcp_rules" -gt 0 ]; then
            echo "   DHCP-related rules found:"
            iptables -L INPUT -n 2>/dev/null | grep -E "(67|68)" | sed 's/^/      /'
        else
            echo "   No specific DHCP rules (check if INPUT policy allows UDP 67/68)"
        fi
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

# ========================================
# Installation
# ========================================

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

# ========================================
# Configuration
# ========================================

configure() {
    log_info "Configuring DHCP for Fortress..."

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

    # Copy Fortress DHCP config
    if [ -f "$SCRIPT_DIR/dnsmasq-fortress.conf" ]; then
        cp "$SCRIPT_DIR/dnsmasq-fortress.conf" /etc/dnsmasq.d/fortress.conf
        log_success "Installed /etc/dnsmasq.d/fortress.conf"
    else
        log_error "dnsmasq-fortress.conf not found in $SCRIPT_DIR"
        return 1
    fi

    # Create log file
    touch /var/log/dnsmasq.log
    chown dnsmasq:dnsmasq /var/log/dnsmasq.log 2>/dev/null || true

    # Create lease directory
    mkdir -p /var/lib/dnsmasq
    chown dnsmasq:dnsmasq /var/lib/dnsmasq 2>/dev/null || true

    # Ensure FTS bridge has IP
    ensure_bridge_ip

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

ensure_bridge_ip() {
    log_info "Ensuring FTS bridge has IP..."

    if ip link show "$OVS_BRIDGE" &>/dev/null; then
        # Check if IP is set
        if ! ip addr show "$OVS_BRIDGE" 2>/dev/null | grep -q "${LAN_GATEWAY%/*}"; then
            log_info "  Adding $LAN_GATEWAY/24 to $OVS_BRIDGE"
            ip addr add "${LAN_GATEWAY}/24" dev "$OVS_BRIDGE" 2>/dev/null || true
        fi
        ip link set "$OVS_BRIDGE" up 2>/dev/null || true
        log_success "  FTS bridge is configured with $LAN_GATEWAY"
    else
        log_warn "  FTS bridge does not exist yet - will be created during install"
    fi
}

open_firewall() {
    log_info "Opening firewall for DHCP..."

    # Accept DHCP on FTS bridge and WiFi interfaces
    for iface in "$OVS_BRIDGE" wlan0 wlp6s0; do
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

# ========================================
# Quick Fix
# ========================================

quickfix() {
    log_info "Attempting quick fix..."

    # 1. Ensure dnsmasq is installed and configured
    if [ ! -f /etc/dnsmasq.d/fortress.conf ]; then
        configure
        return
    fi

    # 2. Ensure FTS bridge has IP
    ensure_bridge_ip

    # 3. Restart dnsmasq
    systemctl restart dnsmasq

    # 4. Open firewall
    open_firewall

    # 5. Diagnose
    diagnose
}

# ========================================
# Usage
# ========================================

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  diagnose   - Show DHCP diagnostic information"
    echo "  configure  - Install and configure dnsmasq for Fortress"
    echo "  quickfix   - Quick fix common DHCP issues"
    echo "  firewall   - Open firewall for DHCP/DNS"
    echo ""
    echo "Environment Variables:"
    echo "  OVS_BRIDGE   - OVS bridge name (default: FTS)"
    echo "  LAN_GATEWAY  - Gateway IP (default: 10.200.0.1)"
    echo "  LAN_SUBNET   - LAN subnet (default: 10.200.0.0/24)"
    echo ""
    echo "Quick Start:"
    echo "  $0 configure    # First time setup"
    echo "  $0 diagnose     # Debug issues"
    echo ""
}

# Main
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
