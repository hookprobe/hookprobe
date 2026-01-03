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
VLAN_LAN="${VLAN_LAN:-100}"
VLAN_MGMT="${VLAN_MGMT:-200}"
GATEWAY_LAN="${GATEWAY_LAN:-10.200.0.1}"
GATEWAY_MGMT="${GATEWAY_MGMT:-10.200.100.1}"
LAN_MASK="${LAN_MASK:-24}"

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
# After reboot, OVS restores ports from OVSDB but IP addresses
# and link UP state are NOT persisted. This function ensures
# VLAN interfaces are UP with correct IP addresses.

bring_up_vlan_interfaces() {
    log_section "Bringing Up VLAN Interfaces"

    local gateway_lan="${GATEWAY_LAN:-10.200.0.1}"
    local gateway_mgmt="${GATEWAY_MGMT:-10.200.100.1}"
    local lan_mask="${LAN_MASK:-24}"

    # First, ensure the OVS bridge itself is UP
    if ip link show "$OVS_BRIDGE" &>/dev/null; then
        if ! ip link show "$OVS_BRIDGE" | grep -q "state UP"; then
            log_info "Bringing bridge $OVS_BRIDGE UP..."
            ip link set "$OVS_BRIDGE" up
        fi
    fi

    # VLAN 100 (LAN) - Check if interface exists (either as OVS internal or netplan VLAN)
    local vlan_lan="vlan${VLAN_LAN}"
    if ip link show "$vlan_lan" &>/dev/null; then
        # Bring interface UP if DOWN
        if ! ip link show "$vlan_lan" | grep -q "state UP"; then
            log_info "Bringing $vlan_lan UP..."
            ip link set "$vlan_lan" up
        fi

        # Assign IP if not present
        if ! ip addr show "$vlan_lan" 2>/dev/null | grep -q "${gateway_lan}/"; then
            log_info "Assigning ${gateway_lan}/${lan_mask} to $vlan_lan..."
            ip addr add "${gateway_lan}/${lan_mask}" dev "$vlan_lan" 2>/dev/null || {
                log_warn "IP may already be assigned to $vlan_lan"
            }
        fi
        log_success "$vlan_lan: UP with IP ${gateway_lan}/${lan_mask}"
    else
        # Interface doesn't exist - create it as OVS internal port
        log_info "Creating $vlan_lan as OVS internal port..."
        if ! ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${vlan_lan}$"; then
            ovs-vsctl add-port "$OVS_BRIDGE" "$vlan_lan" \
                tag="$VLAN_LAN" \
                -- set interface "$vlan_lan" type=internal
        fi
        ip link set "$vlan_lan" up
        ip addr add "${gateway_lan}/${lan_mask}" dev "$vlan_lan" 2>/dev/null || true
        log_success "Created $vlan_lan with IP ${gateway_lan}/${lan_mask}"
    fi

    # VLAN 200 (MGMT) - Same process
    local vlan_mgmt="vlan${VLAN_MGMT}"
    if ip link show "$vlan_mgmt" &>/dev/null; then
        # Bring interface UP if DOWN
        if ! ip link show "$vlan_mgmt" | grep -q "state UP"; then
            log_info "Bringing $vlan_mgmt UP..."
            ip link set "$vlan_mgmt" up
        fi

        # Assign IP if not present (MGMT is always /30)
        if ! ip addr show "$vlan_mgmt" 2>/dev/null | grep -q "${gateway_mgmt}/"; then
            log_info "Assigning ${gateway_mgmt}/30 to $vlan_mgmt..."
            ip addr add "${gateway_mgmt}/30" dev "$vlan_mgmt" 2>/dev/null || {
                log_warn "IP may already be assigned to $vlan_mgmt"
            }
        fi
        log_success "$vlan_mgmt: UP with IP ${gateway_mgmt}/30"
    else
        # Interface doesn't exist - create it as OVS internal port
        log_info "Creating $vlan_mgmt as OVS internal port..."
        if ! ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${vlan_mgmt}$"; then
            ovs-vsctl add-port "$OVS_BRIDGE" "$vlan_mgmt" \
                tag="$VLAN_MGMT" \
                -- set interface "$vlan_mgmt" type=internal
        fi
        ip link set "$vlan_mgmt" up
        ip addr add "${gateway_mgmt}/30" dev "$vlan_mgmt" 2>/dev/null || true
        log_success "Created $vlan_mgmt with IP ${gateway_mgmt}/30"
    fi

    # Verify interfaces are ready
    local ready=true
    if ! ip addr show "$vlan_lan" 2>/dev/null | grep -q "${gateway_lan}/"; then
        log_error "$vlan_lan: IP not configured!"
        ready=false
    fi
    if ! ip addr show "$vlan_mgmt" 2>/dev/null | grep -q "${gateway_mgmt}/"; then
        log_error "$vlan_mgmt: IP not configured!"
        ready=false
    fi

    if [ "$ready" = true ]; then
        log_success "All VLAN interfaces ready"
        return 0
    else
        log_error "Some VLAN interfaces failed to configure"
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

    # Add OVS side to bridge with VLAN 200 (idempotent)
    # Check if port exists using port-to-br (more reliable than --if-exists get)
    if ovs-vsctl port-to-br "$veth_ovs" &>/dev/null; then
        # Port exists in some bridge - ensure it's on our bridge with correct VLAN
        local current_br
        current_br=$(ovs-vsctl port-to-br "$veth_ovs" 2>/dev/null || true)
        if [ "$current_br" = "$OVS_BRIDGE" ]; then
            ovs-vsctl set port "$veth_ovs" tag="$VLAN_MGMT" 2>/dev/null || true
            log_info "$veth_ovs already on $OVS_BRIDGE, ensured VLAN $VLAN_MGMT"
        else
            # Port on wrong bridge - move it
            ovs-vsctl --if-exists del-port "$current_br" "$veth_ovs"
            ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_MGMT" || true
            log_info "Moved $veth_ovs to $OVS_BRIDGE with VLAN $VLAN_MGMT"
        fi
    else
        # Port doesn't exist in OVS - add it
        ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_MGMT" 2>/dev/null || {
            # Might fail if interface not ready, try to recover
            ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$veth_ovs"
            ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_MGMT" || true
        }
        log_info "Added $veth_ovs to $OVS_BRIDGE with VLAN $VLAN_MGMT"
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
# WIFI BRIDGE (FOR SDN AUTOPILOT WITH AP_ISOLATE=1)
# ============================================================
#
# Architecture:
#   WiFi clients → hostapd (ap_isolate=1) → br-wifi → veth → OVS
#
# With ap_isolate=1, hostapd forces ALL client traffic through the bridge.
# This gives OVS full visibility and control for NAC policy enforcement.
# mDNS reflection is handled by hairpin mode on br-wifi, allowing HomeKit
# devices with policy=normal to discover each other.
#
# Traffic flow:
#   1. WiFi client sends mDNS (or any packet)
#   2. hostapd forwards to br-wifi (because ap_isolate=1)
#   3. br-wifi forwards to veth-wifi-a → veth-wifi-b → OVS
#   4. OVS applies NAC policies (allow/block based on device policy)
#   5. If allowed, OVS forwards back to veth-wifi-b → veth-wifi-a → br-wifi
#   6. br-wifi hairpin reflects back to wlan interfaces
#   7. hostapd broadcasts to WiFi clients
#
# ============================================================

setup_wifi_bridge() {
    log_section "WiFi Bridge for SDN Autopilot"

    local br_wifi="br-wifi"
    local veth_br="veth-wifi-a"   # Linux bridge side
    local veth_ovs="veth-wifi-b"  # OVS side

    # Create Linux bridge if not exists
    if ! ip link show "$br_wifi" &>/dev/null; then
        log_info "Creating WiFi bridge $br_wifi..."
        ip link add "$br_wifi" type bridge
        # Set STP off for faster convergence
        ip link set "$br_wifi" type bridge stp_state 0
        # Set forward delay to 0
        echo 0 > "/sys/class/net/$br_wifi/bridge/forward_delay" 2>/dev/null || true
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

    # Add veth_ovs to OVS with VLAN 100 (LAN)
    if ovs-vsctl port-to-br "$veth_ovs" &>/dev/null; then
        local current_br
        current_br=$(ovs-vsctl port-to-br "$veth_ovs" 2>/dev/null || true)
        if [ "$current_br" = "$OVS_BRIDGE" ]; then
            ovs-vsctl set port "$veth_ovs" tag="$VLAN_LAN" 2>/dev/null || true
            log_info "$veth_ovs already on $OVS_BRIDGE, ensured VLAN $VLAN_LAN"
        else
            ovs-vsctl --if-exists del-port "$current_br" "$veth_ovs"
            ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_LAN" || true
            log_info "Moved $veth_ovs to $OVS_BRIDGE with VLAN $VLAN_LAN"
        fi
    else
        ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_LAN" 2>/dev/null || {
            ovs-vsctl --if-exists del-port "$OVS_BRIDGE" "$veth_ovs"
            ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_LAN" || true
        }
        log_info "Added $veth_ovs to $OVS_BRIDGE with VLAN $VLAN_LAN"
    fi

    # Enable hairpin mode on veth for mDNS reflection
    # This allows packets to go back out the same port they came in on
    if command -v bridge &>/dev/null; then
        bridge link set dev "$veth_br" hairpin on 2>/dev/null || true
        log_info "Enabled hairpin mode on $veth_br for mDNS reflection"
    else
        log_warn "bridge command not found - hairpin may not work"
    fi

    # Also enable hairpin on any WiFi interfaces that get added to br-wifi
    # hostapd will add wlan interfaces when it starts with bridge=br-wifi
    for wlan_if in $(ls /sys/class/net/ 2>/dev/null | grep -E "^wlan|^wlp|^wlx"); do
        if ip link show master "$br_wifi" 2>/dev/null | grep -q "$wlan_if"; then
            bridge link set dev "$wlan_if" hairpin on 2>/dev/null || true
            log_info "Enabled hairpin mode on $wlan_if"
        fi
    done

    log_success "WiFi bridge configured for SDN Autopilot"
    log_info "  Bridge: $br_wifi → $veth_br ↔ $veth_ovs → OVS ($OVS_BRIDGE)"
    log_info "  NAC policies enforced at OVS layer"
    log_info "  mDNS reflection via hairpin mode"
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

    echo -e "\n${CYAN}WiFi Bridge (SDN Autopilot):${NC}"
    if ip link show br-wifi &>/dev/null; then
        echo "  br-wifi: UP"
        echo "  Members:"
        bridge link show master br-wifi 2>/dev/null | while read -r line; do
            local dev hairpin
            dev=$(echo "$line" | awk '{print $2}' | tr -d ':')
            hairpin=$(bridge link show dev "$dev" 2>/dev/null | grep -o "hairpin on" || echo "hairpin off")
            echo "    $dev ($hairpin)"
        done
        echo "  veth-wifi-b → OVS:"
        ovs-vsctl get port veth-wifi-b tag 2>/dev/null && echo "" || echo "  (not connected)"
    else
        echo "  (not configured)"
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
            bring_up_vlan_interfaces  # CRITICAL: Bring up VLANs with IPs first
            configure_openflow
            configure_port_vlans

            # Container veth is optional - don't fail if it doesn't work
            # Containers use podman's internal network as primary
            setup_container_veth || log_warn "Container veth setup had issues (non-fatal)"

            # WiFi bridge for SDN Autopilot (ap_isolate=1 + hairpin mDNS)
            # Allows full OVS control over WiFi traffic including device-to-device
            setup_wifi_bridge || log_warn "WiFi bridge setup had issues (non-fatal)"

            log_section "OVS Post-Setup Complete"
            log_success "VLAN interfaces, OpenFlow rules, port tags, and WiFi bridge configured"
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
            bring_up_vlan_interfaces
            configure_port_vlans
            ;;

        bring-up-vlans)
            # Standalone command to just bring up VLAN interfaces
            wait_for_bridge || exit 1
            bring_up_vlan_interfaces
            ;;

        *)
            echo "Usage: $0 {setup|status|openflow|vlans|bring-up-vlans}"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
