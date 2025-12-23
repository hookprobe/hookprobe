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
NETPLAN_STATE="$STATE_DIR/netplan-config.conf"
VLAN_STATE="$STATE_DIR/vlan-config.conf"

# Load configuration from netplan state or defaults
if [ -f "$NETPLAN_STATE" ]; then
    # shellcheck source=/dev/null
    source "$NETPLAN_STATE"
fi

# Fallback to vlan-config.conf for backwards compatibility
if [ -f "$VLAN_STATE" ] && [ -z "${LAN_MASK:-}" ]; then
    # shellcheck source=/dev/null
    source "$VLAN_STATE"
fi

# Defaults
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
VLAN_LAN="${VLAN_LAN:-100}"
VLAN_MGMT="${VLAN_MGMT:-200}"
GATEWAY_MGMT="${GATEWAY_MGMT:-10.200.100.1}"

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
# OPENFLOW RULES
# ============================================================

configure_openflow() {
    log_section "Configuring OpenFlow Rules"

    # Set OVS to standalone mode (normal L2 switching without controller)
    ovs-vsctl set-fail-mode "$OVS_BRIDGE" standalone 2>/dev/null || true

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
    log_info "  ARP, DHCP, DNS: priority 800-1000"
    log_info "  LAN (10.200.0.0/16): priority 500"
    log_info "  Containers (172.20.0.0/16): priority 500"
}

# ============================================================
# PORT VLAN TAGGING
# ============================================================

detect_trunk_port() {
    # Auto-detect management/trunk port (last ethernet port on bridge)
    local ports ethernet_ports=()

    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null) || return

    for port in $ports; do
        # Skip internal VLAN interfaces
        [[ "$port" =~ ^vlan[0-9]+$ ]] && continue
        # Skip veth pairs
        [[ "$port" =~ ^veth ]] && continue
        # Skip WiFi
        [[ "$port" =~ ^wlan|^wlp|^wlx ]] && continue

        ethernet_ports+=("$port")
    done

    # Sort and get last one (typically enp4s0 on 4-port box)
    if [ ${#ethernet_ports[@]} -gt 0 ]; then
        printf '%s\n' "${ethernet_ports[@]}" | sort -V | tail -1
    fi
}

configure_port_vlans() {
    log_section "Configuring Port VLAN Tags"

    # Detect trunk port
    local trunk_port
    trunk_port=$(detect_trunk_port)
    [ -n "$trunk_port" ] && log_info "Detected trunk port: $trunk_port"

    # Get all ports
    local ports
    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null) || return 0

    for port in $ports; do
        # Skip internal VLAN interfaces (created by netplan)
        [[ "$port" =~ ^vlan[0-9]+$ ]] && continue

        # Skip veth pairs (handled separately)
        [[ "$port" =~ ^veth ]] && continue

        case "$port" in
            # WiFi interfaces - VLAN 100 (LAN) access mode
            wlan*|wlp*|wlx*)
                log_info "WiFi $port → VLAN $VLAN_LAN (access)"
                ovs-vsctl set port "$port" tag="$VLAN_LAN" vlan_mode=access 2>/dev/null || true
                ;;

            *)
                if [ "$port" = "$trunk_port" ]; then
                    # Trunk port - carries both VLANs
                    log_info "TRUNK $port → Native $VLAN_LAN + Tagged $VLAN_MGMT"
                    ovs-vsctl set port "$port" \
                        trunks="$VLAN_LAN,$VLAN_MGMT" \
                        vlan_mode=native-untagged \
                        tag="$VLAN_LAN" 2>/dev/null || true
                else
                    # Regular LAN port - VLAN 100 access
                    log_info "LAN $port → VLAN $VLAN_LAN (access)"
                    ovs-vsctl set port "$port" tag="$VLAN_LAN" vlan_mode=access 2>/dev/null || true
                fi
                ;;
        esac
    done

    log_success "Port VLAN configuration complete"
}

# ============================================================
# CONTAINER BRIDGE (VETH TO VLAN 200)
# ============================================================

setup_container_veth() {
    log_section "Container Network Bridge"

    local veth_host="veth-mgmt-host"
    local veth_ovs="veth-mgmt-ovs"

    # Create veth pair if not exists
    if ! ip link show "$veth_host" &>/dev/null; then
        log_info "Creating veth pair..."
        ip link add "$veth_host" type veth peer name "$veth_ovs"
    fi

    # Add OVS side to bridge with VLAN 200
    if ! ovs-vsctl list-ports "$OVS_BRIDGE" | grep -q "^${veth_ovs}$"; then
        ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_MGMT"
        log_info "Added $veth_ovs to $OVS_BRIDGE with VLAN $VLAN_MGMT"
    else
        ovs-vsctl set port "$veth_ovs" tag="$VLAN_MGMT" 2>/dev/null || true
    fi

    # Bring up interfaces
    ip link set "$veth_host" up
    ip link set "$veth_ovs" up

    # Host side IP for routing
    if ! ip addr show "$veth_host" | grep -q "10.200.100.254"; then
        ip addr add "10.200.100.254/24" dev "$veth_host" 2>/dev/null || true
    fi

    log_success "Container veth bridge configured"
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

    echo -e "\n${CYAN}VLAN Interfaces:${NC}"
    ip -br addr show | grep -E "vlan[0-9]+" || echo "  (none)"

    echo -e "\n${CYAN}Container veth:${NC}"
    ip -br addr show | grep -E "veth-mgmt" || echo "  (none)"
}

# ============================================================
# MAIN
# ============================================================

main() {
    local action="${1:-setup}"

    case "$action" in
        setup|configure)
            wait_for_bridge || exit 1
            configure_openflow
            configure_port_vlans
            setup_container_veth

            log_section "OVS Post-Setup Complete"
            log_success "OpenFlow rules and port VLAN tags configured"
            ;;

        status)
            show_status
            ;;

        openflow)
            wait_for_bridge || exit 1
            configure_openflow
            ;;

        vlans)
            wait_for_bridge || exit 1
            configure_port_vlans
            ;;

        *)
            echo "Usage: $0 {setup|status|openflow|vlans}"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
