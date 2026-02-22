#!/bin/bash
#
# HookProbe VRF Network Setup
# Creates isolated network segments for multi-tenant deployment
#
# This script sets up Virtual Routing and Forwarding (VRF) to isolate:
#   - hookprobe.com (public website) - VRF hp-public
#   - MSSP Dashboard (mssp.hookprobe.com) - VRF hp-mssp
#   - IDS/Monitoring - VRF hp-ids
#
# Usage:
#   ./setup-vrf.sh setup    # Create VRF networks
#   ./setup-vrf.sh cleanup  # Remove VRF networks
#   ./setup-vrf.sh status   # Show current status
#
# Requirements:
#   - Linux kernel >= 4.3 (VRF support)
#   - iproute2 >= 4.4
#   - nftables
#   - podman
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Network configuration
VRF_PUBLIC_TABLE=100
VRF_MSSP_TABLE=200
VRF_IDS_TABLE=300

NET_PUBLIC_SUBNET="172.30.0.0/24"
NET_PUBLIC_GW="172.30.0.1"

NET_MSSP_SUBNET="172.31.0.0/24"
NET_MSSP_GW="172.31.0.1"

NET_IDS_SUBNET="172.33.0.0/24"
NET_IDS_GW="172.33.0.1"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $*"; }

# =============================================================
# PREREQUISITE CHECKS
# =============================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_dependencies() {
    log_step "Checking dependencies..."

    local missing=()

    # Check kernel version for VRF support (4.3+)
    local kernel_major kernel_minor
    kernel_major=$(uname -r | cut -d. -f1)
    kernel_minor=$(uname -r | cut -d. -f2)

    if [[ $kernel_major -lt 4 ]] || { [[ $kernel_major -eq 4 ]] && [[ $kernel_minor -lt 3 ]]; }; then
        log_error "Kernel $(uname -r) does not support VRF. Minimum: 4.3"
        exit 1
    fi

    # Check for required commands
    for cmd in ip nft podman tc; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing[*]}"
        log_info "Install with: apt-get install -y iproute2 nftables podman"
        exit 1
    fi

    # Test VRF support
    if ! ip link add test-vrf-check type vrf table 999 2>/dev/null; then
        log_error "VRF not supported. Check kernel configuration."
        exit 1
    fi
    ip link del test-vrf-check 2>/dev/null || true

    log_info "All dependencies satisfied"
}

# =============================================================
# VRF SETUP
# =============================================================

create_vrfs() {
    log_step "Creating VRF instances..."

    # VRF for hookprobe.com (public website)
    if ! ip link show vrf-hp-public &>/dev/null; then
        ip link add vrf-hp-public type vrf table $VRF_PUBLIC_TABLE
        ip link set vrf-hp-public up
        log_info "Created vrf-hp-public (routing table $VRF_PUBLIC_TABLE)"
    else
        log_warn "vrf-hp-public already exists"
    fi

    # VRF for MSSP/Fortress (security platform)
    if ! ip link show vrf-hp-mssp &>/dev/null; then
        ip link add vrf-hp-mssp type vrf table $VRF_MSSP_TABLE
        ip link set vrf-hp-mssp up
        log_info "Created vrf-hp-mssp (routing table $VRF_MSSP_TABLE)"
    else
        log_warn "vrf-hp-mssp already exists"
    fi

    # VRF for IDS (monitoring)
    if ! ip link show vrf-hp-ids &>/dev/null; then
        ip link add vrf-hp-ids type vrf table $VRF_IDS_TABLE
        ip link set vrf-hp-ids up
        log_info "Created vrf-hp-ids (routing table $VRF_IDS_TABLE)"
    else
        log_warn "vrf-hp-ids already exists"
    fi
}

create_mirror_interface() {
    log_step "Creating traffic mirror interface..."

    if ! ip link show dummy-mirror &>/dev/null; then
        ip link add dummy-mirror type dummy
        ip link set dummy-mirror up
        ip link set dummy-mirror promisc on
        log_info "Created dummy-mirror interface (promiscuous mode)"
    else
        log_warn "dummy-mirror already exists"
    fi
}

setup_tc_mirror() {
    log_step "Setting up TC traffic mirroring..."

    # Find the primary WAN interface
    local wan_iface
    wan_iface=$(ip route | grep default | awk '{print $5}' | head -1)

    if [[ -z "$wan_iface" ]]; then
        log_warn "No default route found, skipping TC mirror setup"
        return
    fi

    log_info "WAN interface detected: $wan_iface"

    # Remove existing qdiscs (ignore errors if not present)
    tc qdisc del dev "$wan_iface" ingress 2>/dev/null || true

    # Add clsact qdisc (supports both ingress and egress)
    tc qdisc add dev "$wan_iface" clsact 2>/dev/null || {
        # Fallback: remove existing and re-add
        tc qdisc del dev "$wan_iface" clsact 2>/dev/null
        tc qdisc add dev "$wan_iface" clsact
    }

    # Mirror ingress (inbound) traffic to dummy-mirror
    tc filter add dev "$wan_iface" ingress \
        matchall action mirred egress mirror dev dummy-mirror

    # Mirror egress (outbound) traffic to dummy-mirror
    # Required for bidirectional protocol analysis (HTTP, DNS, TLS)
    tc filter add dev "$wan_iface" egress \
        matchall action mirred egress mirror dev dummy-mirror

    log_info "TC mirroring configured: $wan_iface -> dummy-mirror (ingress + egress)"
}

# =============================================================
# PODMAN NETWORKS
# =============================================================

create_podman_networks() {
    log_step "Creating Podman networks..."

    # hp-public-net (hookprobe.com website)
    if ! podman network exists hp-public-net 2>/dev/null; then
        podman network create \
            --driver bridge \
            --subnet "$NET_PUBLIC_SUBNET" \
            --gateway "$NET_PUBLIC_GW" \
            --label "vrf=hp-public" \
            --label "purpose=hookprobe.com website" \
            hp-public-net
        log_info "Created hp-public-net ($NET_PUBLIC_SUBNET)"
    else
        log_warn "hp-public-net already exists"
    fi

    # hp-mssp-net (MSSP Dashboard) - internal only
    if ! podman network exists hp-mssp-net 2>/dev/null; then
        podman network create \
            --driver bridge \
            --subnet "$NET_MSSP_SUBNET" \
            --gateway "$NET_MSSP_GW" \
            --internal \
            --label "vrf=hp-mssp" \
            --label "purpose=MSSP/Fortress Dashboard" \
            hp-mssp-net
        log_info "Created hp-mssp-net ($NET_MSSP_SUBNET) [internal]"
    else
        log_warn "hp-mssp-net already exists"
    fi

    # hp-ids-net (IDS/monitoring) - internal only
    if ! podman network exists hp-ids-net 2>/dev/null; then
        podman network create \
            --driver bridge \
            --subnet "$NET_IDS_SUBNET" \
            --gateway "$NET_IDS_GW" \
            --internal \
            --label "vrf=hp-ids" \
            --label "purpose=IDS and monitoring" \
            hp-ids-net
        log_info "Created hp-ids-net ($NET_IDS_SUBNET) [internal]"
    else
        log_warn "hp-ids-net already exists"
    fi
}

# =============================================================
# FIREWALL (nftables)
# =============================================================

apply_firewall() {
    log_step "Applying nftables firewall rules..."

    mkdir -p /etc/nftables.d

    cat > /etc/nftables.d/hookprobe-vrf.nft << 'NFTABLES'
#!/usr/sbin/nft -f
#
# HookProbe VRF Network Firewall Rules
# Auto-generated by setup-vrf.sh
#
# NOTE: Rootless podman uses rootlessport userspace process.
# Do NOT add kernel-level DNAT/prerouting rules for mapped ports -
# they intercept packets before rootlessport and blackhole traffic.
#

# Clear existing hookprobe rules (preserve system rules)
table inet hookprobe_vrf
delete table inet hookprobe_vrf

table inet hookprobe_vrf {
    # =========================================
    # Forward Chain - VRF Isolation
    # =========================================
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # Same-subnet communication (internal) - must be before egress rules
        ip saddr 172.30.0.0/24 ip daddr 172.30.0.0/24 accept
        ip saddr 172.31.0.0/24 ip daddr 172.31.0.0/24 accept
        ip saddr 172.33.0.0/24 ip daddr 172.33.0.0/24 accept

        # hp-public (172.30.0.0/24) -> WAN (full internet)
        ip saddr 172.30.0.0/24 oifname != "cni-podman*" accept

        # hp-mssp (172.31.0.0/24) -> WAN (limited: DNS, HTTPS for API)
        ip saddr 172.31.0.0/24 udp dport 53 oifname != "cni-podman*" accept
        ip saddr 172.31.0.0/24 tcp dport 53 oifname != "cni-podman*" accept
        ip saddr 172.31.0.0/24 tcp dport 443 oifname != "cni-podman*" accept

        # hp-ids (172.33.0.0/24) -> BLOCKED (no egress beyond subnet)
        ip saddr 172.33.0.0/24 drop

        # Cross-VRF: BLOCKED with logging
        ip saddr 172.30.0.0/24 ip daddr 172.31.0.0/24 log prefix "[VRF pub>mssp] " drop
        ip saddr 172.30.0.0/24 ip daddr 172.33.0.0/24 log prefix "[VRF pub>ids] " drop
        ip saddr 172.31.0.0/24 ip daddr 172.30.0.0/24 log prefix "[VRF mssp>pub] " drop
        ip saddr 172.31.0.0/24 ip daddr 172.33.0.0/24 log prefix "[VRF mssp>ids] " drop

        # Default drop with logging
        log prefix "[VRF DROP] "
    }

    # =========================================
    # Input Chain - Host Protection
    # =========================================
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback (critical for rootless podman, ClickHouse, inter-container comms)
        iif lo accept

        # Established connections
        ct state established,related accept

        # SSH (rate limited)
        tcp dport 22 ct state new limit rate 10/minute accept

        # HTTP/HTTPS (rootless podman rootlessport binds on host)
        tcp dport { 80, 443 } accept

        # ClickHouse (IDS analytics - host network mode)
        tcp dport { 8123, 9000 } accept

        # Fortress/MSSP Dashboard
        tcp dport 8443 accept

        # DNS
        udp dport 53 accept
        tcp dport 53 accept

        # ICMP
        icmp type echo-request limit rate 5/second accept
        icmpv6 type echo-request limit rate 5/second accept

        # Invalid packets
        ct state invalid drop
    }

    # =========================================
    # Output Chain - Allow all from host
    # =========================================
    chain output {
        type filter hook output priority 0; policy accept;
    }

    # NOTE: No prerouting/postrouting NAT chains.
    # Rootless podman uses rootlessport for port mapping in userspace.
    # IDS containers use host network mode (no NAT needed).
}

# =========================================
# Rate Limiting Table
# =========================================
table inet hookprobe_ratelimit
delete table inet hookprobe_ratelimit

table inet hookprobe_ratelimit {
    chain input {
        type filter hook input priority -10;

        # SYN flood protection
        tcp flags syn limit rate 100/second burst 50 packets accept
        tcp flags syn counter drop

        # Connection rate limit
        ct state new limit rate over 200/second burst 100 packets drop
    }
}
NFTABLES

    # Apply rules
    nft -f /etc/nftables.d/hookprobe-vrf.nft
    log_info "Firewall rules applied"

    # Add to nftables.conf if not already included
    if ! grep -q "hookprobe-vrf.nft" /etc/nftables.conf 2>/dev/null; then
        echo 'include "/etc/nftables.d/hookprobe-vrf.nft"' >> /etc/nftables.conf
        log_info "Added rules to /etc/nftables.conf for persistence"
    fi
}

# =============================================================
# SYSCTL SETTINGS
# =============================================================

apply_sysctl() {
    log_step "Applying sysctl settings..."

    cat > /etc/sysctl.d/99-hookprobe-vrf.conf << 'EOF'
# HookProbe VRF Network Settings
# Auto-generated by setup-vrf.sh

# Enable IP forwarding
net.ipv4.ip_forward = 1

# Reverse path filtering (strict mode)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# SYN cookies (DoS protection)
net.ipv4.tcp_syncookies = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Connection tracking limits
net.netfilter.nf_conntrack_max = 131072

# TCP hardening
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

    # Load nf_conntrack module (may not be loaded at early boot)
    modprobe nf_conntrack 2>/dev/null || true

    sysctl -p /etc/sysctl.d/99-hookprobe-vrf.conf 2>&1 | grep -v "cannot stat" || true
    log_info "Sysctl settings applied"
}

# =============================================================
# CLEANUP
# =============================================================

cleanup() {
    log_step "Cleaning up VRF network setup..."

    # Remove Podman networks
    log_info "Removing Podman networks..."
    podman network rm hp-public-net 2>/dev/null || true
    podman network rm hp-mssp-net 2>/dev/null || true
    podman network rm hp-ids-net 2>/dev/null || true

    # Remove VRFs
    log_info "Removing VRF instances..."
    ip link del vrf-hp-public 2>/dev/null || true
    ip link del vrf-hp-mssp 2>/dev/null || true
    ip link del vrf-hp-ids 2>/dev/null || true

    # Remove mirror interface
    log_info "Removing mirror interface..."
    ip link del dummy-mirror 2>/dev/null || true

    # Remove TC rules
    log_info "Removing TC mirror rules..."
    local wan_iface
    wan_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    [[ -n "$wan_iface" ]] && tc qdisc del dev "$wan_iface" ingress 2>/dev/null || true

    # Remove firewall rules
    log_info "Removing firewall rules..."
    nft delete table inet hookprobe_vrf 2>/dev/null || true
    nft delete table inet hookprobe_ratelimit 2>/dev/null || true
    rm -f /etc/nftables.d/hookprobe-vrf.nft

    # Remove sysctl settings
    log_info "Removing sysctl settings..."
    rm -f /etc/sysctl.d/99-hookprobe-vrf.conf

    log_info "Cleanup complete"
}

# =============================================================
# STATUS
# =============================================================

show_status() {
    echo ""
    echo "========================================"
    echo "HookProbe VRF Network Status"
    echo "========================================"
    echo ""

    echo "VRF Instances:"
    echo "-------------"
    ip vrf show 2>/dev/null || echo "  No VRF instances found"
    echo ""

    echo "Podman Networks:"
    echo "----------------"
    podman network ls --filter "label=vrf" 2>/dev/null || echo "  No VRF networks found"
    echo ""

    echo "Mirror Interface:"
    echo "-----------------"
    if ip link show dummy-mirror &>/dev/null; then
        ip -br link show dummy-mirror
    else
        echo "  dummy-mirror not found"
    fi
    echo ""

    echo "TC Mirror Rules:"
    echo "----------------"
    local wan_iface
    wan_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -n "$wan_iface" ]]; then
        tc filter show dev "$wan_iface" ingress 2>/dev/null || echo "  No TC rules"
    fi
    echo ""

    echo "Firewall Rules:"
    echo "---------------"
    if nft list table inet hookprobe_vrf &>/dev/null; then
        echo "  hookprobe_vrf table: ACTIVE"
    else
        echo "  hookprobe_vrf table: NOT FOUND"
    fi
    echo ""

    echo "Running Containers:"
    echo "-------------------"
    podman ps --format "table {{.Names}}\t{{.Networks}}\t{{.Status}}" 2>/dev/null || echo "  No containers"
    echo ""
}

# =============================================================
# MAIN
# =============================================================

setup() {
    log_info "Starting HookProbe VRF Network Setup"
    echo ""

    check_root
    check_dependencies

    echo ""
    create_vrfs
    create_mirror_interface
    setup_tc_mirror
    create_podman_networks
    apply_sysctl
    apply_firewall

    echo ""
    log_info "=========================================="
    log_info "VRF Network Setup Complete!"
    log_info "=========================================="
    echo ""
    log_info "Networks created:"
    log_info "  - hp-public-net  ($NET_PUBLIC_SUBNET)  hookprobe.com"
    log_info "  - hp-mssp-net    ($NET_MSSP_SUBNET)  MSSP/Fortress Dashboard"
    log_info "  - hp-ids-net     ($NET_IDS_SUBNET)  IDS/Monitoring"
    echo ""
    log_info "Traffic mirroring: WAN -> dummy-mirror -> NAPSE/Aegis"
    echo ""
    log_info "Next steps:"
    log_info "  1. Start IDS stack:"
    log_info "     cd $PROJECT_ROOT/core/napse && podman-compose -f podman-compose.ids.yml up -d"
    echo ""
    log_info "  2. Verify isolation:"
    log_info "     ./setup-vrf.sh status"
    echo ""
}

# Handle arguments
case "${1:-help}" in
    setup|install)
        setup
        ;;
    cleanup|remove|uninstall)
        check_root
        cleanup
        ;;
    status)
        show_status
        ;;
    *)
        echo "HookProbe VRF Network Setup"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  setup    - Create VRF networks and firewall rules"
        echo "  cleanup  - Remove all VRF configuration"
        echo "  status   - Show current VRF network status"
        echo ""
        exit 1
        ;;
esac
