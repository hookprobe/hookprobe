#!/bin/bash
#
# HookProbe IDS Traffic Mirroring Setup
# ======================================
#
# This script sets up passive traffic mirroring for IDS analysis
# without introducing latency or packet loss on the primary data path.
#
# Architecture:
#   +---------------------------------------------------------+
#   |                      HOST NETWORK                        |
#   |                                                          |
#   |  WAN (eth0/enp0s6)   Podman Bridge   WireGuard (wg0)   |
#   |       |                   |               |              |
#   |       v                   v               v              |
#   |  +------------------------------------------------------+
#   |  |          TC clsact (ingress+egress)                   |
#   |  |          action: mirred egress mirror                 |
#   |  |          (NON-BLOCKING - traffic continues normally)  |
#   |  +------------------------+------------------------------+
#   |                           |                               |
#   |                           v                               |
#   |                   +---------------+                       |
#   |                   | dummy-mirror  |                       |
#   |                   | (promiscuous) |                       |
#   |                   +-------+-------+                       |
#   |                           |                               |
#   |             +-------------+-------------+                 |
#   |             v             v             v                 |
#   |          NAPSE/Aegis    XDP/eBPF    HYDRA SENTINEL       |
#   |        (AF_PACKET)     (optional)   (analysis)           |
#   +---------------------------------------------------------+
#
# Why this doesn't cause latency:
#   - TC mirred uses "mirror" action, not "redirect"
#   - Mirror copies packets to dummy interface after normal processing
#   - Original packets continue through the network stack unchanged
#   - No synchronous waiting for IDS processing
#
# Usage:
#   ./setup-ids-mirror.sh setup    # Configure mirroring
#   ./setup-ids-mirror.sh cleanup  # Remove mirroring
#   ./setup-ids-mirror.sh status   # Show current status
#   ./setup-ids-mirror.sh test     # Test mirroring is working
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
MIRROR_IFACE="dummy-mirror"
MIRROR_MTU=9000  # Match WAN MTU for jumbo frames

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $*"; }
log_detail() { echo -e "${CYAN}  ->${NC} $*"; }

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_dependencies() {
    log_step "Checking dependencies..."

    local missing=()
    for cmd in ip tc modprobe; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing[*]}"
        exit 1
    fi

    # Ensure dummy module is loaded
    modprobe dummy 2>/dev/null || true

    log_info "Dependencies satisfied"
}

get_wan_interface() {
    local wan_iface
    wan_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    echo "$wan_iface"
}

get_podman_bridges() {
    # Find all Podman/CNI bridge interfaces
    ip link show type bridge 2>/dev/null | grep -oP '^\d+: \K[^:@]+' | grep -E "(cni-|podman|hookprobe)" || true
}

get_wireguard_interfaces() {
    # Find all WireGuard interfaces
    ip link show type wireguard 2>/dev/null | grep -oP '^\d+: \K[^:@]+' || true
}

# =============================================================================
# MIRROR INTERFACE SETUP
# =============================================================================

create_mirror_interface() {
    log_step "Creating mirror interface..."

    if ip link show "$MIRROR_IFACE" &>/dev/null; then
        log_warn "$MIRROR_IFACE already exists, reconfiguring..."
        ip link set "$MIRROR_IFACE" down 2>/dev/null || true
    else
        ip link add "$MIRROR_IFACE" type dummy
        log_detail "Created $MIRROR_IFACE (dummy interface)"
    fi

    # Configure interface
    ip link set "$MIRROR_IFACE" mtu "$MIRROR_MTU"
    ip link set "$MIRROR_IFACE" up
    ip link set "$MIRROR_IFACE" promisc on

    # Disable GRO/GSO/TSO offloading for accurate packet capture
    ethtool -K "$MIRROR_IFACE" gro off gso off tso off 2>/dev/null || true

    log_info "$MIRROR_IFACE configured (MTU: $MIRROR_MTU, promiscuous: on)"
}

# =============================================================================
# TC MIRRORING SETUP
# =============================================================================

setup_tc_mirror_for_interface() {
    local iface="$1"
    local direction="${2:-both}"  # ingress, egress, or both

    if ! ip link show "$iface" &>/dev/null; then
        log_warn "Interface $iface does not exist, skipping"
        return
    fi

    log_detail "Configuring TC mirror on $iface ($direction)..."

    # Remove existing qdiscs (ignore errors)
    tc qdisc del dev "$iface" clsact 2>/dev/null || true
    tc qdisc del dev "$iface" ingress 2>/dev/null || true

    # Add clsact qdisc (supports both ingress and egress)
    tc qdisc add dev "$iface" clsact

    # Add ingress mirror filter
    if [[ "$direction" == "ingress" || "$direction" == "both" ]]; then
        tc filter add dev "$iface" ingress \
            prio 1 \
            matchall \
            action mirred egress mirror dev "$MIRROR_IFACE"
        log_detail "  Ingress mirror: $iface -> $MIRROR_IFACE"
    fi

    # Add egress mirror filter
    if [[ "$direction" == "egress" || "$direction" == "both" ]]; then
        tc filter add dev "$iface" egress \
            prio 1 \
            matchall \
            action mirred egress mirror dev "$MIRROR_IFACE"
        log_detail "  Egress mirror: $iface -> $MIRROR_IFACE"
    fi
}

setup_wan_mirroring() {
    log_step "Setting up WAN interface mirroring..."

    local wan_iface
    wan_iface=$(get_wan_interface)

    if [[ -z "$wan_iface" ]]; then
        log_warn "No WAN interface found (no default route)"
        return
    fi

    log_info "WAN interface: $wan_iface"

    # Mirror both ingress and egress on WAN
    setup_tc_mirror_for_interface "$wan_iface" "both"

    log_info "WAN mirroring configured: $wan_iface <-> $MIRROR_IFACE"
}

setup_podman_mirroring() {
    log_step "Setting up Podman bridge mirroring..."

    local bridges
    bridges=$(get_podman_bridges)

    if [[ -z "$bridges" ]]; then
        log_warn "No Podman bridges found"
        return
    fi

    while IFS= read -r bridge; do
        [[ -z "$bridge" ]] && continue
        setup_tc_mirror_for_interface "$bridge" "both"
    done <<< "$bridges"

    log_info "Podman bridge mirroring configured"
}

setup_wireguard_mirroring() {
    log_step "Setting up WireGuard mirroring..."

    local wg_ifaces
    wg_ifaces=$(get_wireguard_interfaces)

    if [[ -z "$wg_ifaces" ]]; then
        log_warn "No WireGuard interfaces found"
        return
    fi

    while IFS= read -r wg_iface; do
        [[ -z "$wg_iface" ]] && continue
        setup_tc_mirror_for_interface "$wg_iface" "both"
    done <<< "$wg_ifaces"

    log_info "WireGuard mirroring configured"
}

# =============================================================================
# OPTIONAL: XDP PASSIVE INSPECTION HOOK
# =============================================================================

setup_xdp_hook() {
    log_step "Checking XDP support..."

    # Check if XDP is supported
    if ! ip link show "$MIRROR_IFACE" 2>/dev/null | grep -q xdp; then
        log_warn "XDP not available for passive inspection"
        return
    fi

    # XDP program path (if exists)
    local xdp_prog="$PROJECT_ROOT/core/napse/xdp/hookprobe_xdp_pass.o"

    if [[ -f "$xdp_prog" ]]; then
        log_detail "Loading XDP passive inspector..."
        ip link set dev "$MIRROR_IFACE" xdp obj "$xdp_prog" sec xdp_pass 2>/dev/null || {
            log_warn "Failed to load XDP program (optional)"
        }
    else
        log_detail "XDP program not found at $xdp_prog (optional feature)"
    fi
}

# =============================================================================
# SYSCTL OPTIMIZATION
# =============================================================================

apply_capture_sysctl() {
    log_step "Applying capture optimizations..."

    # Create sysctl config for IDS capture optimization
    cat > /etc/sysctl.d/99-hookprobe-ids-mirror.conf << 'EOF'
# HookProbe IDS Mirror Optimization
# =================================

# Increase socket receive buffer for high-throughput capture
net.core.rmem_max = 134217728
net.core.rmem_default = 16777216

# Increase socket send buffer
net.core.wmem_max = 134217728
net.core.wmem_default = 16777216

# Increase netdev budget (packets processed per NAPI poll)
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# Increase backlog queue
net.core.netdev_max_backlog = 100000

# Ring buffer size
net.core.optmem_max = 40960

# Disable reverse path filtering on mirror interface
net.ipv4.conf.dummy-mirror.rp_filter = 0
net.ipv4.conf.dummy-mirror.accept_local = 1
EOF

    sysctl -p /etc/sysctl.d/99-hookprobe-ids-mirror.conf >/dev/null 2>&1 || {
        log_warn "Some sysctl settings may not have applied"
    }

    log_info "Capture optimizations applied"
}

# =============================================================================
# CLEANUP
# =============================================================================

cleanup() {
    log_step "Cleaning up IDS mirror configuration..."

    # Remove TC filters from all interfaces
    local wan_iface
    wan_iface=$(get_wan_interface)

    if [[ -n "$wan_iface" ]]; then
        tc qdisc del dev "$wan_iface" clsact 2>/dev/null || true
        tc qdisc del dev "$wan_iface" ingress 2>/dev/null || true
        log_detail "Removed TC from $wan_iface"
    fi

    # Remove from Podman bridges
    local bridges
    bridges=$(get_podman_bridges)
    while IFS= read -r bridge; do
        [[ -z "$bridge" ]] && continue
        tc qdisc del dev "$bridge" clsact 2>/dev/null || true
        log_detail "Removed TC from $bridge"
    done <<< "$bridges"

    # Remove from WireGuard
    local wg_ifaces
    wg_ifaces=$(get_wireguard_interfaces)
    while IFS= read -r wg_iface; do
        [[ -z "$wg_iface" ]] && continue
        tc qdisc del dev "$wg_iface" clsact 2>/dev/null || true
        log_detail "Removed TC from $wg_iface"
    done <<< "$wg_ifaces"

    # Remove XDP if attached
    if ip link show "$MIRROR_IFACE" 2>/dev/null | grep -q xdp; then
        ip link set dev "$MIRROR_IFACE" xdp off 2>/dev/null || true
        log_detail "Removed XDP from $MIRROR_IFACE"
    fi

    # Remove mirror interface
    if ip link show "$MIRROR_IFACE" &>/dev/null; then
        ip link del "$MIRROR_IFACE"
        log_detail "Removed $MIRROR_IFACE"
    fi

    # Remove sysctl config
    rm -f /etc/sysctl.d/99-hookprobe-ids-mirror.conf

    log_info "Cleanup complete"
}

# =============================================================================
# STATUS
# =============================================================================

show_status() {
    echo ""
    echo "========================================"
    echo "HookProbe IDS Mirror Status"
    echo "========================================"
    echo ""

    echo "Mirror Interface:"
    echo "-----------------"
    if ip link show "$MIRROR_IFACE" &>/dev/null; then
        ip -br link show "$MIRROR_IFACE"
        echo ""
        echo "  Statistics:"
        ip -s link show "$MIRROR_IFACE" | grep -A2 "RX:" | head -4
    else
        echo "  $MIRROR_IFACE: NOT FOUND"
    fi
    echo ""

    echo "TC Mirror Rules:"
    echo "----------------"

    local wan_iface
    wan_iface=$(get_wan_interface)
    if [[ -n "$wan_iface" ]]; then
        echo "  WAN ($wan_iface):"
        tc filter show dev "$wan_iface" ingress 2>/dev/null | grep -q mirred && echo "    OK Ingress mirror active" || echo "    -- Ingress mirror not configured"
        tc filter show dev "$wan_iface" egress 2>/dev/null | grep -q mirred && echo "    OK Egress mirror active" || echo "    -- Egress mirror not configured"
    fi

    local bridges
    bridges=$(get_podman_bridges)
    if [[ -n "$bridges" ]]; then
        while IFS= read -r bridge; do
            [[ -z "$bridge" ]] && continue
            echo "  Bridge ($bridge):"
            tc filter show dev "$bridge" ingress 2>/dev/null | grep -q mirred && echo "    OK Ingress mirror active" || echo "    -- Not mirrored"
        done <<< "$bridges"
    fi

    local wg_ifaces
    wg_ifaces=$(get_wireguard_interfaces)
    if [[ -n "$wg_ifaces" ]]; then
        while IFS= read -r wg_iface; do
            [[ -z "$wg_iface" ]] && continue
            echo "  WireGuard ($wg_iface):"
            tc filter show dev "$wg_iface" ingress 2>/dev/null | grep -q mirred && echo "    OK Ingress mirror active" || echo "    -- Not mirrored"
        done <<< "$wg_ifaces"
    fi
    echo ""

    echo "IDS Containers:"
    echo "---------------"
    podman ps --filter "name=ids-" --format "  {{.Names}}: {{.Status}}" 2>/dev/null || echo "  No IDS containers running"
    echo ""
}

# =============================================================================
# TEST
# =============================================================================

test_mirroring() {
    log_step "Testing traffic mirroring..."

    if ! ip link show "$MIRROR_IFACE" &>/dev/null; then
        log_error "$MIRROR_IFACE does not exist. Run setup first."
        exit 1
    fi

    # Get initial RX packet count
    local rx_before
    rx_before=$(ip -s link show "$MIRROR_IFACE" | grep -A1 "RX:" | tail -1 | awk '{print $1}')

    log_detail "RX packets before: $rx_before"

    # Generate some traffic
    log_detail "Generating test traffic..."
    ping -c 3 8.8.8.8 >/dev/null 2>&1 || true
    curl -s --connect-timeout 2 https://hookprobe.com >/dev/null 2>&1 || true

    sleep 1

    # Get final RX packet count
    local rx_after
    rx_after=$(ip -s link show "$MIRROR_IFACE" | grep -A1 "RX:" | tail -1 | awk '{print $1}')

    log_detail "RX packets after: $rx_after"

    local packets_mirrored=$((rx_after - rx_before))

    if [[ $packets_mirrored -gt 0 ]]; then
        log_info "Traffic mirroring is WORKING ($packets_mirrored packets captured)"
    else
        log_error "Traffic mirroring may NOT be working (0 packets captured)"
        log_detail "Check TC filters and interface status"
        exit 1
    fi
}

# =============================================================================
# MAIN
# =============================================================================

setup() {
    log_info "Starting HookProbe IDS Mirror Setup"
    echo ""

    check_root
    check_dependencies

    echo ""
    create_mirror_interface
    setup_wan_mirroring
    setup_podman_mirroring
    setup_wireguard_mirroring
    apply_capture_sysctl
    setup_xdp_hook

    echo ""
    log_info "========================================"
    log_info "IDS Traffic Mirroring Setup Complete!"
    log_info "========================================"
    echo ""
    log_info "All traffic is now mirrored to: $MIRROR_IFACE"
    log_info "NAPSE/Aegis can capture from this interface."
    echo ""
    log_info "Next steps:"
    log_info "  1. Start IDS stack:"
    log_info "     cd $PROJECT_ROOT/core/napse && podman-compose -f podman-compose.ids.yml up -d"
    echo ""
    log_info "  2. Verify mirroring:"
    log_info "     $0 test"
    echo ""
    log_info "  3. Check status:"
    log_info "     $0 status"
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
    test)
        check_root
        test_mirroring
        ;;
    *)
        echo "HookProbe IDS Traffic Mirroring Setup"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  setup    - Configure traffic mirroring to dummy-mirror"
        echo "  cleanup  - Remove all mirroring configuration"
        echo "  status   - Show current mirroring status"
        echo "  test     - Test if mirroring is working"
        echo ""
        echo "Architecture:"
        echo "  - Uses TC mirred (mirror action) - non-blocking"
        echo "  - All interfaces mirrored to dummy-mirror"
        echo "  - NAPSE/Aegis captures from dummy-mirror"
        echo "  - Zero latency impact on production traffic"
        echo ""
        exit 1
        ;;
esac
