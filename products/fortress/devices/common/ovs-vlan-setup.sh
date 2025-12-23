#!/bin/bash
#
# ovs-vlan-setup.sh - OVS VLAN Configuration for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Configures Open vSwitch with VLAN segmentation:
#   VLAN 100 (LAN)  - 10.200.0.0/xx (user-configurable via LAN_SUBNET_MASK)
#   VLAN 200 (MGMT) - 10.200.100.0/30 (minimal - gateway + 1 admin device)
#
# Port Configuration:
#   - WiFi interfaces: Access mode, VLAN 100
#   - LAN ethernet:    Access mode, VLAN 100
#   - MGMT ethernet:   Trunk mode, native VLAN 100, tagged VLAN 200
#   - Container veth:  Access mode, VLAN 200
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================
# CONFIGURATION
# ============================================================

# VLAN IDs
VLAN_LAN=100
VLAN_MGMT=200

# LAN Subnet - use configured mask from environment or default to /24
# LAN_SUBNET_MASK is set by install-container.sh based on user input
LAN_MASK="${LAN_SUBNET_MASK:-24}"

# Calculate LAN DHCP ranges based on subnet mask
GATEWAY_LAN="10.200.0.1"
case "$LAN_MASK" in
    29) # /29 = 6 usable hosts
        SUBNET_LAN="10.200.0.0/29"
        NETMASK_LAN="255.255.255.248"
        DHCP_START_LAN="10.200.0.2"
        DHCP_END_LAN="10.200.0.6"
        ;;
    28) # /28 = 14 usable hosts
        SUBNET_LAN="10.200.0.0/28"
        NETMASK_LAN="255.255.255.240"
        DHCP_START_LAN="10.200.0.2"
        DHCP_END_LAN="10.200.0.14"
        ;;
    27) # /27 = 30 usable hosts
        SUBNET_LAN="10.200.0.0/27"
        NETMASK_LAN="255.255.255.224"
        DHCP_START_LAN="10.200.0.10"
        DHCP_END_LAN="10.200.0.30"
        ;;
    26) # /26 = 62 usable hosts
        SUBNET_LAN="10.200.0.0/26"
        NETMASK_LAN="255.255.255.192"
        DHCP_START_LAN="10.200.0.10"
        DHCP_END_LAN="10.200.0.62"
        ;;
    25) # /25 = 126 usable hosts
        SUBNET_LAN="10.200.0.0/25"
        NETMASK_LAN="255.255.255.128"
        DHCP_START_LAN="10.200.0.10"
        DHCP_END_LAN="10.200.0.126"
        ;;
    23) # /23 = 510 usable hosts
        SUBNET_LAN="10.200.0.0/23"
        NETMASK_LAN="255.255.254.0"
        DHCP_START_LAN="10.200.0.100"
        DHCP_END_LAN="10.200.1.200"
        ;;
    *) # Default /24 = 254 usable hosts
        SUBNET_LAN="10.200.0.0/24"
        NETMASK_LAN="255.255.255.0"
        DHCP_START_LAN="10.200.0.100"
        DHCP_END_LAN="10.200.0.200"
        LAN_MASK=24
        ;;
esac

# Management VLAN - /30 by default (gateway + 1 admin device)
# This is intentionally small - management should be restricted
SUBNET_MGMT="10.200.100.0/30"
NETMASK_MGMT="255.255.255.252"
GATEWAY_MGMT="10.200.100.1"
DHCP_START_MGMT="10.200.100.2"
DHCP_END_MGMT="10.200.100.2"  # Only 1 DHCP address (admin workstation)

# Container network (podman)
CONTAINER_SUBNET="172.20.200.0/24"
CONTAINER_GATEWAY="172.20.200.1"

# Web container address (from podman-compose.yml)
WEB_CONTAINER_IP="172.20.200.20"
WEB_PORT="${WEB_PORT:-8443}"

# OVS Bridge name
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"

# WAN interface - detect from environment or default route
WAN_INTERFACE="${WAN_INTERFACE:-${NET_WAN_IFACE:-}}"
if [ -z "$WAN_INTERFACE" ]; then
    WAN_INTERFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
fi

# State directory
STATE_DIR="/var/lib/fortress"
VLAN_STATE_FILE="$STATE_DIR/vlan-config.conf"

# Load saved state if exists (for persistence after reboot)
if [ -f "$VLAN_STATE_FILE" ]; then
    # shellcheck source=/dev/null
    source "$VLAN_STATE_FILE"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[VLAN]${NC} $*"; }
log_success() { echo -e "${GREEN}[VLAN]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[VLAN]${NC} $*"; }
log_error() { echo -e "${RED}[VLAN]${NC} $*"; }
log_section() { echo -e "\n${CYAN}═══ $* ═══${NC}"; }

# ============================================================
# PREREQUISITES CHECK
# ============================================================

check_prerequisites() {
    log_section "Checking Prerequisites"

    # Check for OVS
    if ! command -v ovs-vsctl &>/dev/null; then
        log_error "Open vSwitch not installed. Install with: apt install openvswitch-switch"
        return 1
    fi

    # Check OVS service
    if ! systemctl is-active --quiet openvswitch-switch; then
        log_warn "OVS not running, starting..."
        systemctl start openvswitch-switch
    fi

    # Check for bridge
    if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_error "OVS bridge $OVS_BRIDGE does not exist"
        log_info "Create it first with bridge-manager.sh"
        return 1
    fi

    # Create state directory
    mkdir -p "$STATE_DIR"

    log_success "Prerequisites satisfied"
    return 0
}

# ============================================================
# VLAN INTERNAL INTERFACES
# ============================================================

setup_vlan_interfaces() {
    # Create internal OVS interfaces for each VLAN
    # These allow the host to participate in each VLAN

    log_section "Setting Up VLAN Interfaces"

    # VLAN 100 - LAN
    log_info "Creating VLAN $VLAN_LAN (LAN) interface..."
    if ! ovs-vsctl list-ports "$OVS_BRIDGE" | grep -q "^vlan${VLAN_LAN}$"; then
        ovs-vsctl add-port "$OVS_BRIDGE" "vlan${VLAN_LAN}" \
            tag="$VLAN_LAN" \
            -- set interface "vlan${VLAN_LAN}" type=internal
    else
        # Ensure correct tag
        ovs-vsctl set port "vlan${VLAN_LAN}" tag="$VLAN_LAN"
    fi

    # Configure IP with correct subnet mask
    ip link set "vlan${VLAN_LAN}" up
    if ! ip addr show "vlan${VLAN_LAN}" | grep -q "$GATEWAY_LAN"; then
        ip addr add "$GATEWAY_LAN/${LAN_MASK}" dev "vlan${VLAN_LAN}"
    fi
    log_success "  vlan${VLAN_LAN}: $GATEWAY_LAN/${LAN_MASK} (LAN gateway)"

    # VLAN 200 - Management
    log_info "Creating VLAN $VLAN_MGMT (MGMT) interface..."
    if ! ovs-vsctl list-ports "$OVS_BRIDGE" | grep -q "^vlan${VLAN_MGMT}$"; then
        ovs-vsctl add-port "$OVS_BRIDGE" "vlan${VLAN_MGMT}" \
            tag="$VLAN_MGMT" \
            -- set interface "vlan${VLAN_MGMT}" type=internal
    else
        ovs-vsctl set port "vlan${VLAN_MGMT}" tag="$VLAN_MGMT"
    fi

    # Configure IP with /30 mask (gateway + 1 admin device)
    ip link set "vlan${VLAN_MGMT}" up
    if ! ip addr show "vlan${VLAN_MGMT}" | grep -q "$GATEWAY_MGMT"; then
        ip addr add "$GATEWAY_MGMT/30" dev "vlan${VLAN_MGMT}"
    fi
    log_success "  vlan${VLAN_MGMT}: $GATEWAY_MGMT/30 (Management gateway)"
}

# ============================================================
# PORT VLAN ASSIGNMENT
# ============================================================

detect_trunk_port() {
    # Auto-detect which physical ethernet port should be the trunk port
    # Logic: The last physical ethernet port on the bridge is used for management
    # This allows admin to plug into the last port for VLAN 200 access

    local ports
    local ethernet_ports=()

    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null)

    for port in $ports; do
        # Skip internal VLAN interfaces
        [[ "$port" =~ ^vlan[0-9]+$ ]] && continue
        # Skip veth pairs
        [[ "$port" =~ ^veth ]] && continue
        # Skip WiFi interfaces
        [[ "$port" =~ ^wlan|^wlp|^wlx ]] && continue

        # This is a physical ethernet port
        ethernet_ports+=("$port")
    done

    # Sort ports by name (enp1s0, enp2s0, enp3s0, enp4s0 -> last is enp4s0)
    # The last one becomes the trunk port for management access
    if [ ${#ethernet_ports[@]} -gt 0 ]; then
        # Sort and get the last one
        local sorted
        sorted=$(printf '%s\n' "${ethernet_ports[@]}" | sort -V | tail -1)
        echo "$sorted"
    fi
}

configure_port_vlans() {
    # Assign VLAN tags to physical ports

    log_section "Configuring Port VLANs"

    # Auto-detect trunk port if not explicitly set
    if [ -z "$MGMT_INTERFACE" ]; then
        MGMT_INTERFACE=$(detect_trunk_port)
        if [ -n "$MGMT_INTERFACE" ]; then
            log_info "Auto-detected trunk port: $MGMT_INTERFACE"
        fi
    fi

    # Get current ports on bridge
    local ports
    ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null)

    for port in $ports; do
        # Skip internal VLAN interfaces
        if [[ "$port" =~ ^vlan[0-9]+$ ]]; then
            continue
        fi

        # Skip veth pairs (container bridge)
        if [[ "$port" =~ ^veth ]]; then
            continue
        fi

        # Determine port type and assign VLAN
        case "$port" in
            # WiFi interfaces - VLAN 100 (LAN)
            wlan*|wlp*|wlx*)
                log_info "WiFi port $port → VLAN $VLAN_LAN (access)"
                ovs-vsctl set port "$port" tag="$VLAN_LAN" vlan_mode=access
                ;;

            # Check if this is the management/trunk port
            *)
                if [ "$port" = "$MGMT_INTERFACE" ] && [ -n "$MGMT_INTERFACE" ]; then
                    # Management port - trunk mode (carries both VLANs)
                    log_info "TRUNK port $port → Native VLAN $VLAN_LAN + Tagged VLAN $VLAN_MGMT"
                    ovs-vsctl set port "$port" \
                        trunks="$VLAN_LAN,$VLAN_MGMT" \
                        vlan_mode=native-untagged \
                        tag="$VLAN_LAN"
                else
                    # Regular LAN port - VLAN 100 access
                    log_info "LAN port $port → VLAN $VLAN_LAN (access)"
                    ovs-vsctl set port "$port" tag="$VLAN_LAN" vlan_mode=access
                fi
                ;;
        esac
    done

    log_success "Port VLAN configuration complete"
}

# ============================================================
# CONTAINER NETWORK BRIDGE (VETH TO VLAN 200)
# ============================================================

setup_container_veth() {
    # Create veth pair to connect podman container network to VLAN 200
    #
    # This allows containers to be accessible from the management VLAN
    # while remaining isolated from the LAN VLAN

    log_section "Setting Up Container Network Bridge"

    local veth_host="veth-mgmt-host"
    local veth_ovs="veth-mgmt-ovs"

    # Check if veth already exists
    if ip link show "$veth_host" &>/dev/null; then
        log_info "veth pair already exists, checking configuration..."
    else
        log_info "Creating veth pair for container bridge..."
        ip link add "$veth_host" type veth peer name "$veth_ovs"
    fi

    # Add OVS side to bridge with VLAN 200 tag
    if ! ovs-vsctl list-ports "$OVS_BRIDGE" | grep -q "^${veth_ovs}$"; then
        ovs-vsctl add-port "$OVS_BRIDGE" "$veth_ovs" tag="$VLAN_MGMT"
        log_info "Added $veth_ovs to $OVS_BRIDGE with VLAN $VLAN_MGMT"
    else
        ovs-vsctl set port "$veth_ovs" tag="$VLAN_MGMT"
    fi

    # Bring up interfaces
    ip link set "$veth_host" up
    ip link set "$veth_ovs" up

    # The host side provides a secondary path between management VLAN and containers
    # Using /24 netmask on veth for routing even though MGMT VLAN uses /30 for actual clients
    if ! ip addr show "$veth_host" | grep -q "10.200.100.254"; then
        ip addr add "10.200.100.254/24" dev "$veth_host"
    fi

    # NOTE: Route to container network is NOT added here
    # The container network (172.20.200.0/24) is managed by podman and the
    # route is automatically created when podman-compose starts containers.
    # DNAT rules in nftables handle forwarding from MGMT VLAN to containers.

    log_success "Container veth bridge configured"
    log_info "  $veth_ovs → OVS ($OVS_BRIDGE) VLAN $VLAN_MGMT"
    log_info "  $veth_host → Host (10.200.100.254)"
    log_info "  Route: $CONTAINER_SUBNET via $GATEWAY_MGMT"
}

# ============================================================
# DHCP CONFIGURATION FOR DUAL SUBNETS
# ============================================================

configure_dhcp() {
    # Configure dnsmasq for dual-subnet DHCP

    log_section "Configuring DHCP for VLANs"

    local dhcp_conf="/etc/dnsmasq.d/fortress-vlans.conf"

    # Remove conflicting filter-mode config if it exists
    # (fts-ovs.conf is for filter mode, not VLAN mode)
    if [ -f "/etc/dnsmasq.d/fts-ovs.conf" ]; then
        log_info "Removing conflicting filter-mode config (fts-ovs.conf)..."
        rm -f /etc/dnsmasq.d/fts-ovs.conf
    fi

    # Also remove any other fortress configs that might conflict
    if [ -f "/etc/dnsmasq.d/fortress-bridge.conf" ]; then
        rm -f /etc/dnsmasq.d/fortress-bridge.conf
    fi

    # Wait for VLAN interfaces to be up
    local wait_count=0
    while [ $wait_count -lt 10 ]; do
        if ip link show vlan${VLAN_LAN} 2>/dev/null | grep -q "state UP" && \
           ip link show vlan${VLAN_MGMT} 2>/dev/null | grep -q "state UP"; then
            break
        fi
        log_info "Waiting for VLAN interfaces to come up..."
        sleep 1
        wait_count=$((wait_count + 1))
    done

    cat > "$dhcp_conf" << EOF
# Fortress VLAN DHCP Configuration
# Generated by ovs-vlan-setup.sh
# $(date)

# Bind only to specified interfaces
bind-interfaces
except-interface=lo

# Don't read /etc/resolv.conf
no-resolv
no-poll

# ============================================================
# VLAN 100 - LAN (${SUBNET_LAN})
# ============================================================
interface=vlan${VLAN_LAN}
dhcp-range=vlan${VLAN_LAN},${DHCP_START_LAN},${DHCP_END_LAN},${NETMASK_LAN},12h
dhcp-option=vlan${VLAN_LAN},3,${GATEWAY_LAN}
dhcp-option=vlan${VLAN_LAN},6,${GATEWAY_LAN}

# ============================================================
# VLAN 200 - Management (${SUBNET_MGMT})
# ============================================================
interface=vlan${VLAN_MGMT}
dhcp-range=vlan${VLAN_MGMT},${DHCP_START_MGMT},${DHCP_END_MGMT},${NETMASK_MGMT},12h
dhcp-option=vlan${VLAN_MGMT},3,${GATEWAY_MGMT}
dhcp-option=vlan${VLAN_MGMT},6,${GATEWAY_MGMT}

# ============================================================
# DNS Settings
# ============================================================
# Use dnsXai container for DNS (if available on port 5353)
server=127.0.0.1#5353

# Fallback upstream DNS servers
server=1.1.1.1
server=8.8.8.8

# DNS cache
cache-size=1000

# Logging
log-dhcp
log-queries

# Local domain
domain=fortress.local
local=/fortress.local/

# Static entries for management access
address=/fortress.local/${GATEWAY_MGMT}
address=/admin.fortress.local/${GATEWAY_MGMT}
EOF

    log_success "DHCP configuration written to $dhcp_conf"

    # Ensure dnsmasq is enabled and restart
    if systemctl is-enabled --quiet dnsmasq 2>/dev/null; then
        systemctl restart dnsmasq
        log_success "dnsmasq restarted"
    else
        # Enable and start dnsmasq
        systemctl enable dnsmasq 2>/dev/null || true
        systemctl start dnsmasq 2>/dev/null || {
            log_warn "Could not start dnsmasq - DHCP may not work"
        }
        if systemctl is-active --quiet dnsmasq; then
            log_success "dnsmasq started"
        fi
    fi

    # Verify dnsmasq is listening
    sleep 1
    if ss -uln 2>/dev/null | grep -q ":67 " || netstat -uln 2>/dev/null | grep -q ":67 "; then
        log_success "DHCP server listening on port 67"
    else
        log_warn "DHCP server may not be listening - check dnsmasq logs"
    fi
}

# ============================================================
# NFTABLES FIREWALL RULES
# ============================================================

configure_firewall() {
    # Configure nftables for inter-VLAN isolation

    log_section "Configuring Inter-VLAN Firewall"

    local nft_conf="/etc/nftables.d/fortress-vlans.nft"
    mkdir -p /etc/nftables.d

    # Determine WAN interface for firewall rules
    local wan_iface="${WAN_INTERFACE:-eth0}"
    log_info "Using WAN interface: $wan_iface"

    cat > "$nft_conf" << EOF
#!/usr/sbin/nft -f
#
# Fortress VLAN Firewall Rules
# Generated by ovs-vlan-setup.sh
# WAN Interface: ${wan_iface}
#

# Delete table if exists (for clean reload)
table inet fortress_vlan
delete table inet fortress_vlan

table inet fortress_vlan {
    # MAC sets for access control
    set admin_macs {
        type ether_addr
        flags interval
        comment "MACs allowed to access management VLAN"
    }

    # Input chain - gateway services (DHCP, DNS, ping)
    chain input {
        type filter hook input priority 0; policy accept;

        # Allow established/related
        ct state established,related accept

        # Allow ICMP ping on all VLAN interfaces
        iifname { "vlan100", "vlan200" } icmp type echo-request accept

        # Allow DHCP on VLAN interfaces (gateway is DHCP server)
        iifname { "vlan100", "vlan200" } udp dport 67 accept

        # Allow DNS on VLAN interfaces (gateway is DNS forwarder)
        iifname { "vlan100", "vlan200" } udp dport 53 accept
        iifname { "vlan100", "vlan200" } tcp dport 53 accept

        # Allow SSH on management VLAN only
        iifname "vlan200" tcp dport 22 accept

        # Allow web admin on management VLAN only
        iifname "vlan200" tcp dport { 8443, 443, 80 } accept
    }

    # Forward chain - inter-VLAN routing control
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # ============================================================
        # ISOLATION RULES - Block internal network cross-traffic
        # These MUST come first before accept rules
        # ============================================================

        # LAN → Management VLAN: DENY (clients can't access admin network)
        ip saddr ${SUBNET_LAN} ip daddr ${SUBNET_MGMT} drop

        # LAN → Container network: DENY (clients can't access containers directly)
        ip saddr ${SUBNET_LAN} ip daddr ${CONTAINER_SUBNET} drop

        # Containers → LAN: DENY (containers can't initiate to clients)
        ip saddr ${CONTAINER_SUBNET} ip daddr ${SUBNET_LAN} drop

        # ============================================================
        # ALLOW RULES - Everything not blocked above is allowed
        # Routing table determines where traffic goes
        # ============================================================

        # LAN → Internet: ALLOW (anything not going to internal networks)
        ip saddr ${SUBNET_LAN} accept

        # Management → anywhere: ALLOW (admin has full access)
        ip saddr ${SUBNET_MGMT} accept

        # Containers → Internet + Management: ALLOW
        ip saddr ${CONTAINER_SUBNET} accept
    }

    # ============================================================
    # NOTE: No DNAT needed for web access with rootless podman
    # ============================================================
    # With rootless podman + port publishing (-p 8443:8443), the web container
    # is accessible directly on the host's IP addresses. VLAN 200 clients
    # connect to 10.200.100.1:8443 which is handled by podman's port forward.
    #
    # The input chain above already allows tcp dport { 8443, 443, 80 } on vlan200.

    # NAT - masquerade all internal traffic going out
    # Don't restrict to specific WAN interface - let routing decide
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        # Masquerade all internal traffic (except to other internal networks)
        # This allows NAT to work regardless of WAN interface name
        ip saddr ${SUBNET_LAN} ip daddr != { ${SUBNET_LAN}, ${SUBNET_MGMT}, ${CONTAINER_SUBNET} } masquerade
        ip saddr ${SUBNET_MGMT} ip daddr != { ${SUBNET_LAN}, ${SUBNET_MGMT}, ${CONTAINER_SUBNET} } masquerade
        ip saddr ${CONTAINER_SUBNET} ip daddr != { ${SUBNET_LAN}, ${SUBNET_MGMT}, ${CONTAINER_SUBNET} } masquerade
    }
}
EOF

    log_success "Firewall rules written to $nft_conf"

    # Apply rules
    if command -v nft &>/dev/null; then
        if nft -f "$nft_conf" 2>&1; then
            log_success "nftables rules applied successfully"
        else
            log_warn "Could not apply nftables rules directly"
            log_info "Rules will be applied on next nftables restart"
        fi
    fi

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-fortress-forward.conf

    log_success "IP forwarding enabled"
}

# ============================================================
# SAVE STATE
# ============================================================

save_state() {
    log_section "Saving VLAN Configuration"

    cat > "$VLAN_STATE_FILE" << EOF
# Fortress VLAN Configuration State
# Generated: $(date)

VLAN_LAN=$VLAN_LAN
VLAN_MGMT=$VLAN_MGMT

SUBNET_LAN=$SUBNET_LAN
GATEWAY_LAN=$GATEWAY_LAN

SUBNET_MGMT=$SUBNET_MGMT
GATEWAY_MGMT=$GATEWAY_MGMT

CONTAINER_SUBNET=$CONTAINER_SUBNET

MGMT_INTERFACE=${MGMT_INTERFACE:-}
MGMT_ENABLED=${MGMT_ENABLED:-false}

WAN_INTERFACE=${WAN_INTERFACE:-}

OVS_BRIDGE=$OVS_BRIDGE
EOF

    log_success "Configuration saved to $VLAN_STATE_FILE"
}

# ============================================================
# STATUS / DEBUG
# ============================================================

show_status() {
    log_section "VLAN Status"

    echo -e "\n${CYAN}OVS Bridge:${NC}"
    ovs-vsctl show

    echo -e "\n${CYAN}Port VLAN Tags:${NC}"
    for port in $(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null); do
        local tag mode
        tag=$(ovs-vsctl get port "$port" tag 2>/dev/null || echo "none")
        mode=$(ovs-vsctl get port "$port" vlan_mode 2>/dev/null || echo "default")
        echo "  $port: tag=$tag mode=$mode"
    done

    echo -e "\n${CYAN}VLAN Interfaces:${NC}"
    ip -br addr show | grep -E "vlan[0-9]+" || echo "  (none)"

    echo -e "\n${CYAN}Routes:${NC}"
    ip route show | grep -E "10.200|172.20" || echo "  (none)"

    echo -e "\n${CYAN}DHCP Leases:${NC}"
    cat /var/lib/misc/dnsmasq.leases 2>/dev/null || echo "  (none)"
}

# ============================================================
# CLEANUP
# ============================================================

cleanup_vlans() {
    log_section "Cleaning Up VLAN Configuration"

    # Remove VLAN interfaces
    for vlan_if in vlan${VLAN_LAN} vlan${VLAN_MGMT}; do
        if ovs-vsctl list-ports "$OVS_BRIDGE" | grep -q "^${vlan_if}$"; then
            ovs-vsctl del-port "$OVS_BRIDGE" "$vlan_if"
            log_info "Removed $vlan_if from $OVS_BRIDGE"
        fi
    done

    # Remove veth pair
    if ip link show veth-mgmt-host &>/dev/null; then
        ip link del veth-mgmt-host
        log_info "Removed veth-mgmt pair"
    fi

    # Clear VLAN tags from ports
    for port in $(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null); do
        ovs-vsctl remove port "$port" tag 2>/dev/null || true
        ovs-vsctl remove port "$port" trunks 2>/dev/null || true
        ovs-vsctl remove port "$port" vlan_mode 2>/dev/null || true
    done

    # Remove config files
    rm -f /etc/dnsmasq.d/fortress-vlans.conf
    rm -f /etc/nftables.d/fortress-vlans.nft
    rm -f "$VLAN_STATE_FILE"

    log_success "VLAN configuration cleaned up"
}

# ============================================================
# MAIN
# ============================================================

main() {
    local action="${1:-setup}"

    case "$action" in
        setup|configure)
            check_prerequisites || exit 1
            setup_vlan_interfaces
            configure_port_vlans
            setup_container_veth
            configure_dhcp
            configure_firewall
            save_state

            log_section "VLAN Setup Complete"
            log_success "VLAN 100 (LAN):  $SUBNET_LAN → Gateway $GATEWAY_LAN"
            log_success "VLAN 200 (MGMT): $SUBNET_MGMT → Gateway $GATEWAY_MGMT"
            if [ -n "$MGMT_INTERFACE" ]; then
                log_success "Management Port: $MGMT_INTERFACE (trunk mode)"
            fi
            log_info ""
            log_info "Access web UI:"
            log_info "  From MGMT VLAN: https://$GATEWAY_MGMT:8443"
            log_info "  Via Cloudflare: https://fortress.yourdomain.com"
            ;;

        status)
            show_status
            ;;

        cleanup|remove)
            cleanup_vlans
            ;;

        install-service)
            # Install systemd service for boot persistence
            log_section "Installing Systemd Service"

            local service_src
            service_src="$(dirname "${BASH_SOURCE[0]}")/../../systemd/fortress-vlan.service"

            if [ ! -f "$service_src" ]; then
                # Try installed location
                service_src="/opt/hookprobe/products/fortress/systemd/fortress-vlan.service"
            fi

            if [ ! -f "$service_src" ]; then
                log_error "Service file not found"
                exit 1
            fi

            cp "$service_src" /etc/systemd/system/fortress-vlan.service
            systemctl daemon-reload
            systemctl enable fortress-vlan.service
            log_success "Service installed and enabled for boot"
            log_info "VLAN configuration will persist after reboot"
            ;;

        *)
            echo "Usage: $0 {setup|status|cleanup|install-service}"
            echo ""
            echo "Commands:"
            echo "  setup           - Configure OVS VLANs (VLAN 100 LAN, VLAN 200 MGMT)"
            echo "  status          - Show current VLAN configuration"
            echo "  cleanup         - Remove VLAN configuration"
            echo "  install-service - Install systemd service for boot persistence"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
