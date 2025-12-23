#!/bin/bash
#
# filter-mode-network.sh - Filter Mode Network Configuration for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Restores network configuration after reboot for filter mode:
# - VLAN 200 management interface (IP address)
# - Port VLAN tags for consistent traffic flow
# - OVS permissive settings for WiFi
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================
# CONFIGURATION
# ============================================================

# OVS Bridge name
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"

# VLAN Configuration
VLAN_LAN=100
VLAN_MGMT=200

# Management network
GATEWAY_MGMT="10.200.100.1"
SUBNET_MGMT="10.200.100.0/30"

# State file from installation
STATE_FILE="/var/lib/fortress/network-state.conf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[NET]${NC} $*"; }
log_success() { echo -e "${GREEN}[NET]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[NET]${NC} $*"; }
log_error() { echo -e "${RED}[NET]${NC} $*"; }

# ============================================================
# LOAD STATE
# ============================================================

load_state() {
    if [ -f "$STATE_FILE" ]; then
        # shellcheck source=/dev/null
        source "$STATE_FILE"
        log_info "Loaded state from $STATE_FILE"
    fi
}

# ============================================================
# VLAN 200 MANAGEMENT INTERFACE
# ============================================================

setup_mgmt_vlan() {
    log_info "Configuring VLAN 200 management interface..."

    # Check if vlan200 port exists on bridge
    if ! ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^vlan${VLAN_MGMT}$"; then
        log_info "  Creating vlan${VLAN_MGMT} internal port..."
        ovs-vsctl add-port "$OVS_BRIDGE" "vlan${VLAN_MGMT}" \
            tag="$VLAN_MGMT" \
            -- set interface "vlan${VLAN_MGMT}" type=internal
    else
        # Ensure correct tag
        ovs-vsctl set port "vlan${VLAN_MGMT}" tag="$VLAN_MGMT"
    fi

    # Bring interface up
    ip link set "vlan${VLAN_MGMT}" up 2>/dev/null || {
        log_warn "  Could not bring vlan${VLAN_MGMT} up"
        return 1
    }

    # Add IP address if not present
    if ! ip addr show "vlan${VLAN_MGMT}" 2>/dev/null | grep -q "$GATEWAY_MGMT"; then
        ip addr add "${GATEWAY_MGMT}/30" dev "vlan${VLAN_MGMT}" 2>/dev/null || {
            log_warn "  Could not add IP to vlan${VLAN_MGMT}"
            return 1
        }
        log_success "  vlan${VLAN_MGMT}: ${GATEWAY_MGMT}/30"
    else
        log_info "  vlan${VLAN_MGMT} already has IP ${GATEWAY_MGMT}/30"
    fi

    return 0
}

# ============================================================
# PORT VLAN CONFIGURATION
# ============================================================

configure_port_vlans() {
    log_info "Configuring port VLANs for traffic flow..."

    # In FILTER MODE: Keep all ports UNTAGGED for simple L2 operation
    # This allows normal traffic flow between WiFi, LAN, and the FTS gateway
    # Only MGMT trunk port has VLANs for admin access
    #
    # Traffic flow:
    # - WiFi clients → untagged → FTS bridge → NAT → WAN
    # - LAN clients → untagged → FTS bridge → NAT → WAN
    # - Admin on MGMT port (VLAN 200 tagged) → vlan200 interface → admin access

    # Get all ports on bridge
    local ports
    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null)

    for port in $ports; do
        # Skip internal VLAN interfaces (vlan100, vlan200)
        [[ "$port" =~ ^vlan[0-9]+$ ]] && continue

        # Skip the main internal interface (FTS, FTS-mirror)
        [[ "$port" = "FTS" ]] && continue
        [[ "$port" = "FTS-mirror" ]] && continue

        # Get current settings
        local current_tag trunks
        current_tag=$(ovs-vsctl get port "$port" tag 2>/dev/null || echo "[]")
        trunks=$(ovs-vsctl get port "$port" trunks 2>/dev/null || echo "[]")

        # Check if this is the MGMT trunk port (has trunks configured)
        if [ "$trunks" != "[]" ]; then
            # This is a trunk port (MGMT) - ensure it's configured correctly
            # It should only have VLAN 200 in trunks, no tag (untagged traffic flows normally)
            log_info "  $port: MGMT trunk port (VLANs: $trunks)"

            # Fix incorrect MGMT port config: remove tag if set (allows untagged traffic)
            if [ "$current_tag" != "[]" ]; then
                log_info "    Fixing: removing tag=$current_tag (untagged traffic should flow)"
                ovs-vsctl remove port "$port" tag "$current_tag" 2>/dev/null || true
                ovs-vsctl remove port "$port" vlan_mode 2>/dev/null || true
            fi

            # Ensure trunks only includes VLAN 200 (not 100)
            if [[ "$trunks" == *"100"* ]]; then
                log_info "    Fixing: setting trunks to only VLAN 200"
                ovs-vsctl set port "$port" trunks=200 2>/dev/null || true
            fi
            continue
        fi

        # For all other ports (WiFi, LAN, container veths): ensure they're UNTAGGED
        # This is critical for filter mode - all traffic should flow freely to FTS gateway
        if [ "$current_tag" != "[]" ]; then
            # Port has a VLAN tag - remove it for untagged operation
            log_info "  $port: removing VLAN tag (was $current_tag) → untagged"
            ovs-vsctl remove port "$port" tag "$current_tag" 2>/dev/null || true
            ovs-vsctl remove port "$port" vlan_mode 2>/dev/null || true
        else
            log_info "  $port: untagged (OK)"
        fi
    done

    log_success "All ports configured for untagged operation (filter mode)"
}

# ============================================================
# OVS FLOW CONFIGURATION
# ============================================================

configure_ovs_flows() {
    log_info "Configuring OVS for permissive WiFi traffic..."

    # Set fail-mode to standalone (allows normal L2 switching without controller)
    local current_fail_mode
    current_fail_mode=$(ovs-vsctl get-fail-mode "$OVS_BRIDGE" 2>/dev/null || echo "")

    if [ "$current_fail_mode" != "standalone" ]; then
        ovs-vsctl set-fail-mode "$OVS_BRIDGE" standalone 2>/dev/null || true
        log_success "  OVS fail-mode set to standalone (L2 switching enabled)"
    fi

    # Ensure normal forwarding is in place
    # Delete any restrictive flows that might block traffic
    ovs-ofctl del-flows "$OVS_BRIDGE" 2>/dev/null || true

    # Add default NORMAL action (standard L2 switching)
    ovs-ofctl add-flow "$OVS_BRIDGE" "priority=0,actions=NORMAL" 2>/dev/null || true
    log_success "  OVS flows configured for normal L2 switching"
}

# ============================================================
# VERIFY CONNECTIVITY
# ============================================================

verify_setup() {
    log_info "Verifying network setup..."

    local errors=0

    # Check vlan200 interface
    if ip link show "vlan${VLAN_MGMT}" 2>/dev/null | grep -q "state UP"; then
        log_success "  vlan${VLAN_MGMT}: UP"
    else
        log_warn "  vlan${VLAN_MGMT}: DOWN"
        errors=$((errors + 1))
    fi

    # Check vlan200 IP
    if ip addr show "vlan${VLAN_MGMT}" 2>/dev/null | grep -q "$GATEWAY_MGMT"; then
        log_success "  vlan${VLAN_MGMT} IP: $GATEWAY_MGMT"
    else
        log_warn "  vlan${VLAN_MGMT} IP: missing"
        errors=$((errors + 1))
    fi

    # Check FTS bridge internal interface
    if ip addr show "FTS" 2>/dev/null | grep -q "10.200.0.1"; then
        log_success "  FTS: 10.200.0.1 (LAN gateway)"
    else
        log_warn "  FTS: no IP or wrong IP"
        errors=$((errors + 1))
    fi

    # Check OVS fail-mode
    local fail_mode
    fail_mode=$(ovs-vsctl get-fail-mode "$OVS_BRIDGE" 2>/dev/null || echo "unknown")
    log_info "  OVS fail-mode: $fail_mode"

    return $errors
}

# ============================================================
# SAVE STATE
# ============================================================

save_state() {
    mkdir -p "$(dirname "$STATE_FILE")"

    cat > "$STATE_FILE" << EOF
# Fortress Network State
# Generated: $(date)

OVS_BRIDGE=$OVS_BRIDGE
VLAN_LAN=$VLAN_LAN
VLAN_MGMT=$VLAN_MGMT
GATEWAY_MGMT=$GATEWAY_MGMT
NETWORK_MODE=filter
EOF

    log_info "State saved to $STATE_FILE"
}

# ============================================================
# STATUS
# ============================================================

show_status() {
    echo -e "\n${CYAN}=== Fortress Network Status ===${NC}\n"

    echo -e "${CYAN}OVS Bridge:${NC}"
    ovs-vsctl show

    echo -e "\n${CYAN}Port VLAN Tags:${NC}"
    for port in $(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null); do
        local tag trunks mode
        tag=$(ovs-vsctl get port "$port" tag 2>/dev/null || echo "none")
        trunks=$(ovs-vsctl get port "$port" trunks 2>/dev/null || echo "[]")
        mode=$(ovs-vsctl get port "$port" vlan_mode 2>/dev/null || echo "default")
        echo "  $port: tag=$tag trunks=$trunks mode=$mode"
    done

    echo -e "\n${CYAN}VLAN Interfaces:${NC}"
    ip -br addr show | grep -E "vlan[0-9]+|FTS" || echo "  (none)"

    echo -e "\n${CYAN}OVS Flows:${NC}"
    ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | head -5 || echo "  (error)"
}

# ============================================================
# MAIN
# ============================================================

main() {
    local action="${1:-setup}"

    case "$action" in
        setup|configure)
            log_info "Starting filter mode network configuration..."

            load_state

            # Check OVS is running
            if ! ovs-vsctl show &>/dev/null; then
                log_error "OVS not running - cannot configure network"
                exit 1
            fi

            # Setup VLAN 200 management interface
            setup_mgmt_vlan || true

            # Configure port VLANs
            configure_port_vlans

            # Configure OVS for permissive traffic
            configure_ovs_flows

            # Save state
            save_state

            # Verify setup
            echo ""
            verify_setup

            log_success "\nFilter mode network configuration complete"
            ;;

        status)
            show_status
            ;;

        *)
            echo "Usage: $0 {setup|status}"
            echo ""
            echo "Commands:"
            echo "  setup   - Configure network (run at boot)"
            echo "  status  - Show current network status"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
