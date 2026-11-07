#!/bin/bash
#
# setup-avahi.sh - Configure Avahi daemon for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Configures Avahi (mDNS/Bonjour) to:
#   - Only operate on LAN interface (FTS bridge)
#   - Prevent ghost name collisions with dnsmasq
#   - Disable mDNS reflection between interfaces
#   - Support Apple device discovery (AirPlay, AirDrop, etc.)
#
# Ghost Name Collision Fix:
#   The classic "device (2), device (3)" incrementing bug happens when:
#   1. Avahi probes for hostname uniqueness on mDNS
#   2. dnsmasq (incorrectly) responds to .local queries
#   3. Avahi sees its own name "in use" and increments
#
#   Solution: server=/local/# in dnsmasq + proper Avahi config here
#
# Version: 1.0.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
HOSTNAME="${HOSTNAME:-hookprobe-fortress}"
LAN_INTERFACE="${LAN_INTERFACE:-FTS}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[AVAHI]${NC} $*"; }
log_success() { echo -e "${GREEN}[AVAHI]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[AVAHI]${NC} $*"; }
log_error() { echo -e "${RED}[AVAHI]${NC} $*"; }

# ============================================
# Installation
# ============================================

install_avahi() {
    log_info "Installing Avahi daemon..."

    if command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y avahi-daemon avahi-utils libnss-mdns
    elif command -v dnf &>/dev/null; then
        dnf install -y avahi avahi-tools nss-mdns
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm avahi nss-mdns
    else
        log_error "Unknown package manager"
        return 1
    fi

    log_success "Avahi installed"
}

# ============================================
# Configuration
# ============================================

configure() {
    log_info "Configuring Avahi daemon for Fortress..."
    log_info "  Hostname:      $HOSTNAME"
    log_info "  LAN Interface: $LAN_INTERFACE"

    # Ensure avahi is installed
    if ! command -v avahi-daemon &>/dev/null; then
        install_avahi
    fi

    # Backup existing config
    if [ -f /etc/avahi/avahi-daemon.conf ] && [ ! -f /etc/avahi/avahi-daemon.conf.backup ]; then
        cp /etc/avahi/avahi-daemon.conf /etc/avahi/avahi-daemon.conf.backup
        log_info "Backed up existing config"
    fi

    # Generate Avahi configuration
    generate_avahi_config

    # Restart Avahi
    log_info "Restarting Avahi daemon..."
    systemctl restart avahi-daemon
    systemctl enable avahi-daemon

    # Verify
    sleep 2
    if systemctl is-active avahi-daemon &>/dev/null; then
        log_success "Avahi daemon running"
    else
        log_error "Avahi daemon failed to start"
        journalctl -u avahi-daemon --no-pager -n 20
        return 1
    fi

    log_success "Avahi configuration complete!"
}

generate_avahi_config() {
    local config_file="/etc/avahi/avahi-daemon.conf"

    # Build deny-interfaces list (everything except LAN)
    # Common interfaces to block: WAN, loopback, container networks
    local deny_interfaces="lo"

    # Add common WAN interface names
    for iface in eth0 enp1s0 enp2s0 eno1 wan0 ppp0; do
        if ip link show "$iface" &>/dev/null 2>&1; then
            deny_interfaces="$deny_interfaces,$iface"
        fi
    done

    # Add container network interfaces
    for iface in podman0 docker0 cni0 veth; do
        deny_interfaces="$deny_interfaces,$iface"
    done

    log_info "Generating Avahi config..."
    log_info "  Allow: $LAN_INTERFACE"
    log_info "  Deny:  $deny_interfaces"

    cat > "$config_file" << EOF
# ============================================================================
# HookProbe Fortress - Avahi Daemon Configuration
# Generated: $(date -Iseconds)
#
# Purpose: mDNS/Bonjour service discovery for Apple devices
#
# GHOST NAME COLLISION FIX:
#   This config, combined with server=/local/# in dnsmasq, prevents
#   the hostname incrementing bug (device → device (2) → device (3))
#
# Key settings:
#   - allow-interfaces: Only LAN (FTS bridge)
#   - disallow-other-stacks: Prevent conflicts with other mDNS implementations
#   - enable-reflector=no: Prevent mDNS packet reflection
# ============================================================================

[server]
# Hostname for this machine (without .local suffix)
host-name=$HOSTNAME

# Enable IPv4 mDNS, disable IPv6 (simpler config)
use-ipv4=yes
use-ipv6=no

# Enable D-Bus interface for service registration
enable-dbus=yes

# CRITICAL: Only allow mDNS on LAN interface
# This prevents Avahi from seeing its own packets reflected on other interfaces
allow-interfaces=$LAN_INTERFACE

# Block interfaces where mDNS should NOT operate
deny-interfaces=$deny_interfaces

# CRITICAL: Disallow other mDNS stacks
# Ensures Avahi is the sole mDNS handler, preventing internal conflicts
disallow-other-stacks=yes

# Rate limiting to prevent mDNS storms
ratelimit-interval-usec=1000000
ratelimit-burst=1000

# Check for changes in /etc/avahi/services
check-response-ttl=no
use-iff-running=no

[wide-area]
# Disable wide-area mDNS (not needed for local network)
enable-wide-area=no

[publish]
# Publish our presence on mDNS
publish-addresses=yes
publish-hinfo=yes
publish-workstation=no
publish-domain=yes

# Do NOT publish DNS servers from resolv.conf
# This would cause dnsmasq addresses to appear in mDNS
publish-resolv-conf-dns-servers=no

# IPv6 settings
publish-aaaa-on-ipv4=no

[reflector]
# CRITICAL: Disable mDNS reflection between interfaces
# Reflection causes Avahi to see its own packets as coming from another device
enable-reflector=no
reflect-ipv=no

[rlimits]
# Resource limits for security
rlimit-core=0
rlimit-data=4194304
rlimit-fsize=0
rlimit-nofile=768
rlimit-stack=4194304
rlimit-nproc=3
EOF

    chmod 644 "$config_file"
    log_success "Generated $config_file"
}

# ============================================
# Diagnosis
# ============================================

diagnose() {
    echo "========================================"
    echo "Fortress Avahi/mDNS Diagnosis"
    echo "========================================"
    echo ""

    # Check Avahi service
    echo "1. AVAHI SERVICE STATUS:"
    if systemctl is-active avahi-daemon &>/dev/null; then
        echo "   [OK] avahi-daemon is running"
    else
        echo "   [FAIL] avahi-daemon is NOT running"
    fi
    echo ""

    # Check hostname
    echo "2. HOSTNAME CONFIGURATION:"
    echo "   System hostname: $(hostname)"
    echo "   Avahi hostname:  $(avahi-resolve -n "$(hostname).local" 2>/dev/null | awk '{print $1}' || echo 'NOT RESOLVING')"

    # Check for ghost name increment
    local current_host
    current_host=$(hostname)
    if echo "$current_host" | grep -qE '\([0-9]+\)$'; then
        echo "   [WARN] GHOST NAME DETECTED: hostname has increment suffix!"
        echo "   [WARN] This indicates a collision was detected."
    else
        echo "   [OK] No ghost name increment detected"
    fi
    echo ""

    # Check Avahi config
    echo "3. AVAHI CONFIGURATION:"
    if [ -f /etc/avahi/avahi-daemon.conf ]; then
        echo "   [OK] /etc/avahi/avahi-daemon.conf exists"
        echo "   allow-interfaces: $(grep "^allow-interfaces" /etc/avahi/avahi-daemon.conf | cut -d= -f2)"
        echo "   disallow-other-stacks: $(grep "^disallow-other-stacks" /etc/avahi/avahi-daemon.conf | cut -d= -f2)"
        echo "   enable-reflector: $(grep "^enable-reflector" /etc/avahi/avahi-daemon.conf | cut -d= -f2)"
    else
        echo "   [FAIL] /etc/avahi/avahi-daemon.conf not found"
    fi
    echo ""

    # Check dnsmasq .local handling
    echo "4. DNSMASQ .LOCAL HANDLING:"
    local dnsmasq_local_fix=false
    for conf in /etc/dnsmasq.d/*.conf /etc/dnsmasq.conf; do
        if grep -q "^server=/local/#" "$conf" 2>/dev/null; then
            echo "   [OK] server=/local/# found in $conf"
            dnsmasq_local_fix=true
            break
        fi
    done
    if [ "$dnsmasq_local_fix" = false ]; then
        echo "   [FAIL] server=/local/# NOT FOUND - dnsmasq may interfere with mDNS!"
        echo "   [FIX] Add 'server=/local/#' to /etc/dnsmasq.d/fortress.conf"
    fi
    echo ""

    # Check for mDNS collision test
    echo "5. mDNS COLLISION TEST:"
    echo "   Testing if dnsmasq responds to .local queries..."
    local dns_response
    dns_response=$(dig +short "$(hostname).local" @127.0.0.1 2>/dev/null || echo "")
    if [ -z "$dns_response" ]; then
        echo "   [OK] dnsmasq correctly ignoring .local queries"
    else
        echo "   [FAIL] dnsmasq is responding to .local: $dns_response"
        echo "   [FIX] This causes ghost name collisions!"
    fi
    echo ""

    # List mDNS services
    echo "6. ACTIVE mDNS SERVICES:"
    if command -v avahi-browse &>/dev/null; then
        timeout 3 avahi-browse -apt 2>/dev/null | head -10 | sed 's/^/   /' || echo "   No services found"
    else
        echo "   avahi-browse not installed"
    fi
    echo ""
}

# ============================================
# Ghost Name Fix
# ============================================

fix_ghost_names() {
    log_info "Fixing ghost name collision..."

    # Stop services
    systemctl stop avahi-daemon 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true

    # Clear Avahi cache
    rm -rf /var/cache/avahi-daemon/* 2>/dev/null || true
    rm -f /var/run/avahi-daemon/*.cache 2>/dev/null || true
    log_info "Cleared Avahi cache"

    # Fix hostname if it has increment suffix
    local current_host
    current_host=$(hostname)
    if echo "$current_host" | grep -qE ' ?\([0-9]+\)$'; then
        local clean_host
        clean_host=$(echo "$current_host" | sed 's/ *([0-9]*)$//')
        log_info "Removing ghost suffix: '$current_host' -> '$clean_host'"
        hostnamectl set-hostname "$clean_host" --static
        hostnamectl set-hostname "$clean_host" --pretty
    fi

    # Ensure dnsmasq has server=/local/# fix
    local fixed=false
    for conf in /etc/dnsmasq.d/fortress.conf /etc/dnsmasq.d/fts-vlan.conf; do
        if [ -f "$conf" ] && ! grep -q "^server=/local/#" "$conf"; then
            # Add fix at top of file
            sed -i '1i # Ghost Name Fix: Ignore .local queries (mDNS only)\nserver=/local/#\n' "$conf"
            log_info "Added server=/local/# to $conf"
            fixed=true
            break
        fi
    done

    # Configure Avahi
    configure

    # Restart dnsmasq
    systemctl start dnsmasq
    log_info "dnsmasq restarted"

    # Verify fix
    sleep 2
    diagnose
}

# ============================================
# Usage
# ============================================

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  configure  - Install and configure Avahi daemon"
    echo "  diagnose   - Show Avahi/mDNS diagnostic information"
    echo "  fix        - Fix ghost name collision issues"
    echo ""
    echo "Environment Variables:"
    echo "  HOSTNAME       - Hostname for mDNS (default: hookprobe-fortress)"
    echo "  LAN_INTERFACE  - LAN interface for mDNS (default: FTS)"
    echo ""
    echo "Ghost Name Collision Fix:"
    echo "  If devices show 'device (2)', 'device (3)', etc. run:"
    echo "    $0 fix"
    echo ""
    echo "  This will:"
    echo "    1. Add server=/local/# to dnsmasq (ignore .local queries)"
    echo "    2. Configure Avahi to only use LAN interface"
    echo "    3. Disable mDNS reflection between interfaces"
    echo "    4. Clear stale mDNS caches"
    echo ""
}

# ============================================
# Main
# ============================================

case "${1:-}" in
    configure|setup|install)
        configure
        ;;
    diagnose|diag|status)
        diagnose
        ;;
    fix|repair)
        fix_ghost_names
        ;;
    *)
        usage
        ;;
esac
