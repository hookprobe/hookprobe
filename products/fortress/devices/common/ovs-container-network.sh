#!/bin/bash
#
# ovs-container-network.sh - OVS Network Manager for Fortress Containers
#
# Creates an OVS-based network fabric for container isolation with:
#   - OpenFlow-controlled traffic between tiers
#   - VXLAN tunnels for mesh connectivity (VNI + PSK)
#   - Traffic mirroring to QSecBit for analysis
#   - Per-tier internet isolation
#
# Network Tiers (FTS = abbreviation for "fortress"):
#   - FTS-data      (172.20.200.0/24)      - NO internet - postgres, redis
#   - FTS-services  (172.20.201.0/24)      - internet OK - web, dnsxai, dfs
#   - FTS-ml        (172.20.202.0/24)      - NO internet - lstm-trainer
#   - FTS-mgmt      (172.20.203.0/24)      - NO internet - grafana, victoria
#   - FTS-lan       (10.200.0.0/MASK)      - LAN clients + WiFi AP
#
# LAN subnet is configurable via LAN_SUBNET_MASK environment variable
# Supports /23 (510 devices) to /29 (6 devices), default is /23
#
# Version: 5.5.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================
# CONFIGURATION
# ============================================================

# OVS Bridge
# Using "FTS" (abbreviation for Fortress) to keep interface names short
# Linux IFNAMSIZ limit is 15 chars, so "FTS-" (6 chars) leaves 9 for tier names
OVS_BRIDGE="${OVS_BRIDGE:-FTS}"

# LAN subnet configuration (can be overridden by environment)
# Supports /23 to /29 - defaults to /23 for maximum flexibility
LAN_SUBNET_MASK="${LAN_SUBNET_MASK:-23}"
LAN_BASE_IP="10.200.0.1"

# Calculate LAN CIDR based on subnet mask
get_lan_cidr() {
    case "$LAN_SUBNET_MASK" in
        29) echo "10.200.0.0/29" ;;
        28) echo "10.200.0.0/28" ;;
        27) echo "10.200.0.0/27" ;;
        26) echo "10.200.0.0/26" ;;
        25) echo "10.200.0.0/25" ;;
        24) echo "10.200.0.0/24" ;;
        23) echo "10.200.0.0/23" ;;
        *)  echo "10.200.0.0/23" ;;  # Default to /23
    esac
}

# Container network tiers (OVS internal ports)
# NOTE: Interface names must be <= 15 chars (Linux IFNAMSIZ limit)
# With "FTS-" prefix (6 chars), tier names can be up to 9 chars
declare -A TIER_CONFIG=(
    ["data"]="172.20.200.1/24:false"      # gateway:internet_allowed
    ["services"]="172.20.201.1/24:true"   # web, dnsxai, dfs
    ["ml"]="172.20.202.1/24:false"
    ["mgmt"]="172.20.203.1/24:false"
    ["lan"]="${LAN_BASE_IP}/${LAN_SUBNET_MASK}:true"  # LAN clients need NAT
)

# Container IP assignments (must match podman-compose.yml)
# All containers on single 172.20.200.0/24 network managed by podman-compose
declare -A CONTAINER_IPS=(
    # Data tier
    ["postgres"]="172.20.200.10"
    ["redis"]="172.20.200.11"
    # Services tier (web, dns, wifi intelligence)
    ["web"]="172.20.200.20"
    ["dnsxai"]="172.20.200.21"
    ["dfs"]="172.20.200.22"
    # Monitoring tier
    ["grafana"]="172.20.200.30"
    ["victoria"]="172.20.200.31"
    # ML tier
    ["lstm-trainer"]="172.20.200.40"
    # Optional services
    ["n8n"]="172.20.200.50"
    ["clickhouse"]="172.20.200.51"
    ["cloudflared"]="172.20.200.60"
)

# VXLAN Configuration (VNI:UDP_PORT)
declare -A VXLAN_CONFIG=(
    ["mesh-core"]="1000:4789"
    ["mesh-threat"]="1001:4790"
    ["mssp-uplink"]="2000:4800"
)

# OpenFlow table assignments
OF_TABLE_INGRESS=0
OF_TABLE_TIER_ISOLATION=10
OF_TABLE_INTERNET_CONTROL=20
OF_TABLE_MIRROR=30
OF_TABLE_OUTPUT=40

# State directory
STATE_DIR="/var/lib/fortress/ovs"

# VXLAN PSK file location
VXLAN_PSK_FILE="/etc/hookprobe/secrets/vxlan_psk"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[OVS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[OVS]${NC} $1"; }
log_error() { echo -e "${RED}[OVS]${NC} $1"; }
log_section() { echo -e "\n${CYAN}═══ $1 ═══${NC}"; }

# ============================================================
# OVS BRIDGE SETUP
# ============================================================

check_ovs_installed() {
    if ! command -v ovs-vsctl &>/dev/null; then
        log_error "Open vSwitch not installed"
        log_info "Install with: apt-get install openvswitch-switch"
        return 1
    fi

    if ! systemctl is-active openvswitch-switch &>/dev/null; then
        log_info "Starting Open vSwitch..."
        systemctl start openvswitch-switch
        systemctl enable openvswitch-switch
    fi

    return 0
}

create_ovs_bridge() {
    log_section "Creating OVS Bridge"

    # Check if bridge exists
    if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_info "Bridge $OVS_BRIDGE already exists"
    else
        log_info "Creating bridge: $OVS_BRIDGE"
        ovs-vsctl add-br "$OVS_BRIDGE"

        # Enable OpenFlow 1.3+
        ovs-vsctl set bridge "$OVS_BRIDGE" \
            protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14,OpenFlow15

        # Note: We do NOT set datapath_type=system as it requires full kernel OVS
        # module support for internal ports. The default datapath works more reliably.
        # If you need kernel datapath for performance, ensure openvswitch kernel
        # module is loaded and compatible: modprobe openvswitch

        # Enable STP for loop prevention (optional, disable for faster convergence)
        ovs-vsctl set bridge "$OVS_BRIDGE" stp_enable=false
    fi

    # Bring bridge up
    ip link set "$OVS_BRIDGE" up

    log_info "Bridge $OVS_BRIDGE created with OpenFlow 1.3+"
}

# ============================================================
# TIER INTERNAL PORTS
# ============================================================

create_tier_ports() {
    log_section "Creating Tier Internal Ports"

    # Check if OVS kernel module supports internal ports
    # This is required for type=internal ports to work
    if ! lsmod | grep -q "^openvswitch"; then
        log_warn "OVS kernel module not loaded. Attempting to load..."
        modprobe openvswitch 2>/dev/null || true
        sleep 1
    fi

    for tier in "${!TIER_CONFIG[@]}"; do
        local config="${TIER_CONFIG[$tier]}"
        local gateway="${config%%:*}"
        local port_name="${OVS_BRIDGE}-${tier}"

        # Create internal port if not exists
        if ! ovs-vsctl port-to-br "$port_name" &>/dev/null; then
            log_info "Creating internal port: $port_name ($gateway)"

            # Try to create internal port - capture any errors for diagnostics
            local ovs_error
            if ! ovs_error=$(ovs-vsctl add-port "$OVS_BRIDGE" "$port_name" \
                -- set interface "$port_name" type=internal 2>&1); then

                log_error "Failed to create OVS internal port: $port_name"
                log_error "OVS error: $ovs_error"
                log_error "This usually means the OVS kernel module is not loaded or incompatible."
                log_error "Try: modprobe openvswitch"
                log_error "Or check: dmesg | grep -i openvswitch"
                log_error ""
                log_error "Alternative: Use Linux bridge instead of OVS for simpler setups."
                log_error "See: products/fortress/devices/common/bridge-manager.sh"
                return 1
            fi

            # Verify port was added to OVS
            if ! ovs-vsctl port-to-br "$port_name" &>/dev/null; then
                log_error "OVS port $port_name not found after creation"
                log_error "OVS ports: $(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null)"
                return 1
            fi

            # Give OVS time to create the kernel interface
            # This is especially important when creating multiple ports rapidly
            sleep 2

            # Check for OVS interface errors
            local ovs_iface_error
            ovs_iface_error=$(ovs-vsctl get interface "$port_name" error 2>/dev/null || echo "")
            if [ -n "$ovs_iface_error" ] && [ "$ovs_iface_error" != '[]' ] && [ "$ovs_iface_error" != '""' ]; then
                log_error "OVS interface error for $port_name: $ovs_iface_error"
            fi
        fi

        # Assign IP to internal port
        # Wait for OVS to create the kernel interface (can take a moment)
        local retries=20
        while [ $retries -gt 0 ]; do
            # Check if interface exists in kernel
            if ip link show "$port_name" &>/dev/null; then
                ip link set "$port_name" up 2>/dev/null && break
            fi
            retries=$((retries - 1))
            if [ $retries -eq 0 ]; then
                log_error "Failed to bring up port: $port_name"
                log_error "Interface not found in kernel after 10 seconds"
                log_error "OVS interface error: $(ovs-vsctl get interface "$port_name" error 2>/dev/null || echo 'none')"
                log_error "OVS interface ofport: $(ovs-vsctl get interface "$port_name" ofport 2>/dev/null || echo 'none')"
                log_error "OVS ports on bridge: $(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | tr '\n' ' ')"
                log_error "Kernel interfaces: $(ip link show 2>/dev/null | grep -E "^[0-9]+:" | head -20)"
                return 1
            fi
            sleep 0.5
        done

        # Remove existing IPs and set new one
        ip addr flush dev "$port_name" 2>/dev/null || true
        ip addr add "$gateway" dev "$port_name" 2>/dev/null || true

        # Get port number for OpenFlow rules
        local ofport
        ofport=$(ovs-vsctl get interface "$port_name" ofport 2>/dev/null || echo "?")

        log_info "  Port $port_name: ofport=$ofport, gateway=$gateway"
    done
}

# ============================================================
# PHYSICAL INTERFACE INTEGRATION
# ============================================================

add_lan_interface() {
    local iface="$1"

    if [ -z "$iface" ]; then
        log_warn "No LAN interface specified"
        return 1
    fi

    # Check if interface exists
    if [ ! -d "/sys/class/net/$iface" ]; then
        log_error "Interface $iface does not exist"
        return 1
    fi

    # Check if already in bridge
    if ovs-vsctl port-to-br "$iface" 2>/dev/null | grep -q "$OVS_BRIDGE"; then
        log_info "Interface $iface already in bridge"
        return 0
    fi

    log_info "Adding LAN interface: $iface"

    # Remove any existing IP
    ip addr flush dev "$iface" 2>/dev/null || true

    # Add to OVS bridge
    ovs-vsctl add-port "$OVS_BRIDGE" "$iface"

    # Bring up
    ip link set "$iface" up

    # Tag as LAN port (for OpenFlow rules)
    local ofport
    ofport=$(ovs-vsctl get interface "$iface" ofport)

    log_info "  Interface $iface added: ofport=$ofport"
}

add_wifi_interface() {
    local iface="$1"

    if [ -z "$iface" ]; then
        log_warn "No WiFi interface specified"
        return 1
    fi

    # WiFi AP interface is added by hostapd with bridge= directive
    # We just need to ensure it's configured correctly

    log_info "WiFi AP interface $iface will be bridged by hostapd"
    log_info "  Ensure hostapd.conf has: bridge=$OVS_BRIDGE"
}

# ============================================================
# OPENFLOW RULES - TIER ISOLATION
# ============================================================

install_openflow_rules() {
    log_section "Installing OpenFlow Rules"

    # Get dynamic LAN CIDR based on configured subnet
    local lan_cidr
    lan_cidr=$(get_lan_cidr)
    log_info "LAN CIDR: $lan_cidr (configurable via LAN_SUBNET_MASK=$LAN_SUBNET_MASK)"

    # Clear existing flows
    ovs-ofctl del-flows "$OVS_BRIDGE"

    # === TABLE 0: INGRESS CLASSIFICATION ===
    log_info "Table 0: Ingress classification"

    # ARP - allow all (needed for connectivity)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=1000,arp,actions=NORMAL"

    # DHCP - allow (needed for LAN clients)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=900,udp,tp_dst=67,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=900,udp,tp_dst=68,actions=NORMAL"

    # DNS - allow to gateway (dnsmasq handles DNS and forwards to dnsXai or fallback)
    # Don't redirect directly to dnsXai - let dnsmasq handle with fallback capability
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=800,udp,nw_src=${lan_cidr},tp_dst=53,actions=NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=800,tcp,nw_src=${lan_cidr},tp_dst=53,actions=NORMAL"

    # LAN traffic to external destinations - allow through (will be NAT'd by iptables/nftables)
    # Use broader /16 to handle any LAN subnet configuration mismatch
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=500,ip,nw_src=10.200.0.0/16,actions=NORMAL"

    # Also allow return traffic to LAN
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=500,ip,nw_dst=10.200.0.0/16,actions=NORMAL"

    # All other traffic - continue to tier isolation (for container network control)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=1,actions=resubmit(,$OF_TABLE_TIER_ISOLATION)"

    # === TABLE 10: TIER ISOLATION ===
    log_info "Table 10: Tier isolation"

    # Data tier - can only talk within tier and to web (for DB queries)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=100,ip,nw_src=172.20.200.0/24,nw_dst=172.20.200.0/24,actions=resubmit(,$OF_TABLE_OUTPUT)"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=100,ip,nw_src=172.20.200.0/24,nw_dst=${CONTAINER_IPS[web]},actions=resubmit(,$OF_TABLE_OUTPUT)"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=100,ip,nw_src=${CONTAINER_IPS[web]},nw_dst=172.20.200.0/24,actions=resubmit(,$OF_TABLE_OUTPUT)"

    # Services tier - full access (internet handled in next table)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=100,ip,nw_src=172.20.201.0/24,actions=resubmit(,$OF_TABLE_INTERNET_CONTROL)"

    # ML tier - internal only
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=100,ip,nw_src=172.20.202.0/24,nw_dst=172.20.0.0/16,actions=resubmit(,$OF_TABLE_OUTPUT)"

    # Mgmt tier - can query services (Victoria for Grafana dashboards)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=100,ip,nw_src=172.20.203.0/24,nw_dst=172.20.0.0/16,actions=resubmit(,$OF_TABLE_OUTPUT)"

    # LAN tier - can reach services and internet (dynamic CIDR)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=100,ip,nw_src=${lan_cidr},actions=resubmit(,$OF_TABLE_INTERNET_CONTROL)"

    # Default: allow within same /16
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=10,ip,nw_dst=10.0.0.0/8,actions=resubmit(,$OF_TABLE_OUTPUT)"

    # Drop everything else (tier isolation)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_TIER_ISOLATION,priority=1,actions=drop"

    # === TABLE 20: INTERNET CONTROL ===
    log_info "Table 20: Internet access control"

    # Services tier - allow internet
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INTERNET_CONTROL,priority=100,ip,nw_src=172.20.201.0/24,actions=resubmit(,$OF_TABLE_MIRROR)"

    # LAN - allow internet (will be NATed) - dynamic CIDR
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INTERNET_CONTROL,priority=100,ip,nw_src=${lan_cidr},actions=resubmit(,$OF_TABLE_MIRROR)"

    # Block internet for other tiers
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INTERNET_CONTROL,priority=10,ip,nw_dst=10.0.0.0/8,actions=resubmit(,$OF_TABLE_OUTPUT)"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INTERNET_CONTROL,priority=1,actions=drop"

    # === TABLE 30: MIRROR (for QSecBit) ===
    log_info "Table 30: Traffic mirroring"

    # Continue to output (mirroring configured separately)
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_MIRROR,priority=1,actions=resubmit(,$OF_TABLE_OUTPUT)"

    # === TABLE 40: OUTPUT ===
    log_info "Table 40: Output"

    # Normal L2 forwarding
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_OUTPUT,priority=1,actions=NORMAL"

    log_info "OpenFlow rules installed"
}

# ============================================================
# TRAFFIC MIRRORING FOR QSECBIT
# ============================================================

setup_traffic_mirror() {
    log_section "Setting Up Traffic Mirror for QSecBit"

    local mirror_port="${OVS_BRIDGE}-mirror"

    # Create mirror port if not exists
    if ! ovs-vsctl port-to-br "$mirror_port" &>/dev/null; then
        log_info "Creating mirror port: $mirror_port"
        ovs-vsctl add-port "$OVS_BRIDGE" "$mirror_port" \
            -- set interface "$mirror_port" type=internal
    fi

    ip link set "$mirror_port" up

    # Get mirror port number
    local mirror_ofport
    mirror_ofport=$(ovs-vsctl get interface "$mirror_port" ofport)

    # Clear existing mirrors
    ovs-vsctl clear bridge "$OVS_BRIDGE" mirrors 2>/dev/null || true

    # Create mirror - copy ALL traffic to mirror port
    ovs-vsctl -- set bridge "$OVS_BRIDGE" mirrors=@m \
        -- --id=@p get port "$mirror_port" \
        -- --id=@m create mirror name=qsecbit-tap select-all=true output-port=@p

    log_info "Traffic mirror configured: all traffic → $mirror_port (ofport=$mirror_ofport)"
    log_info "QSecBit container should bind to: $mirror_port"
}

# ============================================================
# VXLAN TUNNELS FOR MESH
# ============================================================

setup_vxlan_tunnels() {
    log_section "Setting Up VXLAN Tunnels"

    # Generate PSK if not exists
    if [ ! -f "$VXLAN_PSK_FILE" ]; then
        mkdir -p "$(dirname "$VXLAN_PSK_FILE")"
        openssl rand -base64 32 > "$VXLAN_PSK_FILE"
        chmod 600 "$VXLAN_PSK_FILE"
        log_info "Generated VXLAN PSK"
    fi

    local psk
    psk=$(cat "$VXLAN_PSK_FILE")

    for tunnel in "${!VXLAN_CONFIG[@]}"; do
        local config="${VXLAN_CONFIG[$tunnel]}"
        local vni="${config%%:*}"
        local port="${config##*:}"
        local tunnel_name="vxlan-${tunnel}"

        # Remove existing tunnel
        ovs-vsctl del-port "$OVS_BRIDGE" "$tunnel_name" 2>/dev/null || true

        log_info "VXLAN tunnel $tunnel_name: VNI=$vni, UDP=$port"
        log_info "  (Remote endpoint configured dynamically via mesh discovery)"

        # Note: VXLAN tunnels are added dynamically when peers are discovered
        # This creates the configuration template
        cat > "$STATE_DIR/vxlan-${tunnel}.conf" << EOF
# VXLAN Tunnel: $tunnel
VNI=$vni
UDP_PORT=$port
PSK_HASH=$(echo -n "$psk" | sha256sum | cut -d' ' -f1)
# Remote endpoints added by mesh discovery
EOF
    done

    log_info "VXLAN configuration saved to $STATE_DIR/"
}

add_vxlan_peer() {
    local tunnel_name="$1"
    local remote_ip="$2"
    local vni="$3"
    local udp_port="${4:-4789}"

    if [ -z "$tunnel_name" ] || [ -z "$remote_ip" ] || [ -z "$vni" ]; then
        log_error "Usage: add_vxlan_peer <name> <remote_ip> <vni> [udp_port]"
        return 1
    fi

    local port_name="vxlan-$tunnel_name"

    # Remove existing if present
    ovs-vsctl del-port "$OVS_BRIDGE" "$port_name" 2>/dev/null || true

    # Add VXLAN tunnel
    ovs-vsctl add-port "$OVS_BRIDGE" "$port_name" \
        -- set interface "$port_name" type=vxlan \
        options:remote_ip="$remote_ip" \
        options:key="$vni" \
        options:dst_port="$udp_port"

    log_info "VXLAN peer added: $port_name → $remote_ip (VNI=$vni)"
}

# ============================================================
# SFLOW/IPFIX EXPORT
# ============================================================

setup_flow_export() {
    log_section "Setting Up Flow Export"

    # sFlow to QSecBit (sampled flow data)
    ovs-vsctl -- --id=@s create sflow \
        agent="$OVS_BRIDGE" \
        target=\"127.0.0.1:6343\" \
        header=128 \
        sampling=64 \
        polling=10 \
        -- set bridge "$OVS_BRIDGE" sflow=@s 2>/dev/null || {
        log_warn "sFlow configuration failed (may already exist)"
    }

    # IPFIX to QSecBit (detailed flow records)
    ovs-vsctl -- --id=@i create ipfix \
        targets=\"127.0.0.1:4739\" \
        obs_domain_id=1 \
        obs_point_id=1 \
        cache_active_timeout=60 \
        -- set bridge "$OVS_BRIDGE" ipfix=@i 2>/dev/null || {
        log_warn "IPFIX configuration failed (may already exist)"
    }

    log_info "Flow export configured:"
    log_info "  sFlow  → 127.0.0.1:6343 (sampling=64)"
    log_info "  IPFIX  → 127.0.0.1:4739 (timeout=60s)"
}

# ============================================================
# QOS / RATE LIMITING
# ============================================================

setup_qos_meters() {
    log_section "Setting Up QoS Meters"

    # Create meters for rate limiting
    # Meter 1: Suspicious device rate limit (1 Mbps)
    ovs-ofctl add-meter "$OVS_BRIDGE" \
        "meter=1,kbps,band=type=drop,rate=1000" 2>/dev/null || true

    # Meter 2: Guest network rate limit (10 Mbps)
    ovs-ofctl add-meter "$OVS_BRIDGE" \
        "meter=2,kbps,band=type=drop,rate=10000" 2>/dev/null || true

    # Meter 3: Container rate limit (100 Mbps)
    ovs-ofctl add-meter "$OVS_BRIDGE" \
        "meter=3,kbps,band=type=drop,rate=100000" 2>/dev/null || true

    log_info "QoS meters created:"
    log_info "  Meter 1: 1 Mbps (suspicious)"
    log_info "  Meter 2: 10 Mbps (guest)"
    log_info "  Meter 3: 100 Mbps (container)"
}

# Rate limit a specific IP
rate_limit_ip() {
    local ip="$1"
    local meter="${2:-1}"

    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=2000,ip,nw_src=$ip,actions=meter:$meter,resubmit(,$OF_TABLE_TIER_ISOLATION)"

    log_info "Rate limited $ip with meter $meter"
}

# Block an IP immediately
block_ip() {
    local ip="$1"

    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "table=$OF_TABLE_INGRESS,priority=3000,ip,nw_src=$ip,actions=drop"

    log_info "Blocked IP: $ip"
}

# ============================================================
# NAT SETUP
# ============================================================

setup_nat() {
    local wan_iface="$1"

    if [ -z "$wan_iface" ]; then
        log_error "WAN interface required for NAT"
        return 1
    fi

    log_section "Setting Up NAT"

    # Get dynamic LAN CIDR
    local lan_cidr
    lan_cidr=$(get_lan_cidr)

    # Enable IP forwarding with verification
    log_info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-fts-forward.conf
    sysctl -p /etc/sysctl.d/99-fts-forward.conf >/dev/null 2>&1 || true

    # Verify IP forwarding is enabled
    local forward_status
    forward_status=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [ "$forward_status" != "1" ]; then
        log_warn "IP forwarding not enabled, forcing..."
        echo 1 > /proc/sys/net/ipv4/ip_forward
    fi
    log_info "IP forwarding: enabled"

    # NAT for LAN clients via specific WAN interface
    iptables -t nat -C POSTROUTING -s "${lan_cidr}" -o "$wan_iface" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${lan_cidr}" -o "$wan_iface" -j MASQUERADE

    # Fallback NAT rule: NAT any LAN traffic going to non-LAN destinations
    # This ensures NAT works even if routing changes (e.g., failover to WWAN)
    iptables -t nat -C POSTROUTING -s "${lan_cidr}" ! -d "${lan_cidr}" ! -o "$OVS_BRIDGE" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${lan_cidr}" ! -d "${lan_cidr}" ! -o "$OVS_BRIDGE" -j MASQUERADE

    # NAT for services tier (dnsxai needs upstream DNS)
    iptables -t nat -C POSTROUTING -s 172.20.201.0/24 -o "$wan_iface" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 172.20.201.0/24 -o "$wan_iface" -j MASQUERADE

    # Fallback NAT for services tier
    iptables -t nat -C POSTROUTING -s 172.20.201.0/24 ! -d 172.20.0.0/16 ! -o "$OVS_BRIDGE" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 172.20.201.0/24 ! -d 172.20.0.0/16 ! -o "$OVS_BRIDGE" -j MASQUERADE

    # Allow forwarding from LAN to WAN (specific interface)
    iptables -C FORWARD -i "$OVS_BRIDGE" -o "$wan_iface" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$OVS_BRIDGE" -o "$wan_iface" -j ACCEPT

    iptables -C FORWARD -i "$wan_iface" -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$wan_iface" -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow forwarding from LAN to any external interface (for failover/multi-WAN)
    iptables -C FORWARD -i "$OVS_BRIDGE" ! -o "$OVS_BRIDGE" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$OVS_BRIDGE" ! -o "$OVS_BRIDGE" -j ACCEPT

    iptables -C FORWARD ! -i "$OVS_BRIDGE" -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD ! -i "$OVS_BRIDGE" -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # DNAT rules for LAN access to container services
    # Web UI: LAN clients (10.200.0.0/xx) -> web container (172.20.200.20:8443)
    local web_port="${WEB_PORT:-8443}"
    local web_ip="${CONTAINER_IPS[web]}"
    iptables -t nat -C PREROUTING -i "$OVS_BRIDGE" -p tcp --dport "$web_port" -j DNAT --to-destination "${web_ip}:${web_port}" 2>/dev/null || \
        iptables -t nat -A PREROUTING -i "$OVS_BRIDGE" -p tcp --dport "$web_port" -j DNAT --to-destination "${web_ip}:${web_port}"

    # Allow forwarding to container network for DNAT'd traffic
    # All containers are on 172.20.200.0/24 as defined in podman-compose.yml
    iptables -C FORWARD -i "$OVS_BRIDGE" -d 172.20.200.0/24 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$OVS_BRIDGE" -d 172.20.200.0/24 -j ACCEPT

    iptables -C FORWARD -s 172.20.200.0/24 -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -s 172.20.200.0/24 -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT

    log_info "NAT configured for LAN (${lan_cidr}) and Containers (172.20.200.0/24)"
    log_info "DNAT configured for web UI access on port $web_port → ${web_ip}"
}

# ============================================================
# DHCP CONFIGURATION
# ============================================================

setup_dhcp() {
    log_section "Setting Up DHCP"

    local lan_port="${OVS_BRIDGE}-lan"
    local config_file="/etc/dnsmasq.d/fts-ovs.conf"

    # Calculate DHCP range based on subnet mask
    # CRITICAL: Must calculate before using defaults - wrong defaults cause DHCP failures!
    local dhcp_start="${LAN_DHCP_START:-}"
    local dhcp_end="${LAN_DHCP_END:-}"
    local subnet_mask="${LAN_SUBNET_MASK:-24}"

    # Calculate sensible defaults based on subnet mask if not explicitly set
    if [ -z "$dhcp_start" ] || [ -z "$dhcp_end" ]; then
        case "$subnet_mask" in
            29) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.6" ;;      # 6 usable IPs
            28) dhcp_start="10.200.0.2"; dhcp_end="10.200.0.14" ;;     # 14 usable IPs
            27) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.30" ;;    # 30 usable IPs
            26) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.62" ;;    # 62 usable IPs
            25) dhcp_start="10.200.0.10"; dhcp_end="10.200.0.126" ;;   # 126 usable IPs
            24) dhcp_start="10.200.0.100"; dhcp_end="10.200.0.200" ;;  # 254 usable IPs
            *)  dhcp_start="10.200.0.100"; dhcp_end="10.200.1.200" ;;  # /23 or larger
        esac
        log_info "DHCP range calculated for /${subnet_mask}: ${dhcp_start} - ${dhcp_end}"
    fi

    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << EOF
# HookProbe Fortress DHCP Configuration (OVS)
# Generated: $(date -Iseconds)
# LAN Subnet: $(get_lan_cidr)

# Bind to OVS bridge (where the LAN IP is assigned)
interface=${OVS_BRIDGE}

# Use bind-dynamic instead of bind-interfaces
# This allows dnsmasq to wait for interface to appear (critical for boot order)
bind-dynamic

# Don't read /etc/resolv.conf - use our explicit servers
no-resolv
no-poll

# LAN DHCP range (configured for /${subnet_mask} subnet)
dhcp-range=${dhcp_start},${dhcp_end},12h

# Gateway (this device via OVS bridge)
dhcp-option=3,10.200.0.1

# DNS (clients query dnsmasq on gateway)
dhcp-option=6,10.200.0.1

# Domain
domain=hookprobe.local
local=/hookprobe.local/

# Logging
log-dhcp

# Cache
cache-size=1000

# Forward DNS to dnsXai container (published on host port 5353)
server=127.0.0.1#5353

# Fallback upstream DNS servers (used if dnsXai is unreachable)
server=1.1.1.1
server=8.8.8.8
EOF

    chmod 644 "$config_file"

    # Restart dnsmasq
    systemctl restart dnsmasq 2>/dev/null || true

    log_info "DHCP configured on $lan_port (range: ${dhcp_start} - ${dhcp_end})"
}

# ============================================================
# STATUS AND DIAGNOSTICS
# ============================================================

show_status() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  HookProbe Fortress - OVS Network Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        echo "  Bridge $OVS_BRIDGE: NOT CONFIGURED"
        return 1
    fi

    echo "Bridge: $OVS_BRIDGE"
    echo ""

    echo "Ports:"
    ovs-vsctl list-ports "$OVS_BRIDGE" | while read -r port; do
        local ofport type
        ofport=$(ovs-vsctl get interface "$port" ofport 2>/dev/null || echo "?")
        type=$(ovs-vsctl get interface "$port" type 2>/dev/null | tr -d '"' || echo "system")
        printf "  %-20s ofport=%-4s type=%s\n" "$port" "$ofport" "$type"
    done
    echo ""

    echo "OpenFlow Tables:"
    echo "  Table 0:  Ingress Classification"
    echo "  Table 10: Tier Isolation"
    echo "  Table 20: Internet Control"
    echo "  Table 30: Traffic Mirror"
    echo "  Table 40: Output"
    echo ""

    echo "Flow Statistics:"
    ovs-ofctl dump-aggregate "$OVS_BRIDGE" 2>/dev/null | head -5
    echo ""

    echo "Mirrors:"
    ovs-vsctl list mirror 2>/dev/null | grep -E "name|select|output" | head -10
    echo ""
}

show_flows() {
    echo "OpenFlow Rules:"
    echo ""
    ovs-ofctl dump-flows "$OVS_BRIDGE" --no-stats 2>/dev/null | \
        sed 's/cookie=[^,]*,//' | \
        sort -t',' -k1
}

# ============================================================
# FULL INITIALIZATION
# ============================================================

init_ovs_network() {
    log_section "Initializing OVS Container Network"

    mkdir -p "$STATE_DIR"

    check_ovs_installed || return 1
    create_ovs_bridge
    create_tier_ports
    install_openflow_rules
    setup_traffic_mirror
    setup_vxlan_tunnels
    setup_flow_export
    setup_qos_meters

    log_info "OVS network initialized"
    log_info "Next steps:"
    log_info "  1. Add LAN interfaces: $0 add-lan <iface>"
    log_info "  2. Setup NAT: $0 nat <wan_iface>"
    log_info "  3. Setup DHCP: $0 dhcp"

    # Save state
    echo "INITIALIZED=$(date -Iseconds)" > "$STATE_DIR/state"
}

# Initialize OVS for podman-compose mode
# Skips creating container tier internal ports since podman-compose creates its own networks
# with those IPs (172.20.200.0/24, etc). However, we MUST create the LAN gateway IP
# for WiFi/LAN clients to connect.
init_ovs_network_podman() {
    log_section "Initializing OVS for Podman Mode"

    mkdir -p "$STATE_DIR"

    check_ovs_installed || return 1
    create_ovs_bridge

    # Skip container tier ports (data, services, ml, mgmt) - podman-compose manages those
    log_info "Skipping container tier ports (podman-compose manages container networks)"

    # BUT we must create the LAN gateway IP for WiFi/LAN clients
    # The OVS bridge itself acts as the gateway for the LAN subnet
    setup_lan_gateway

    install_openflow_rules
    setup_traffic_mirror
    setup_vxlan_tunnels
    setup_flow_export
    setup_qos_meters

    log_info "OVS network initialized (podman mode)"
    log_info "  LAN gateway: ${LAN_BASE_IP}/${LAN_SUBNET_MASK} on ${OVS_BRIDGE}"
    log_info "  Container networks will be created by podman-compose"

    # Save state
    echo "INITIALIZED=$(date -Iseconds)" > "$STATE_DIR/state"
    echo "MODE=podman" >> "$STATE_DIR/state"
}

# Ensure FTS bridge is up (NO IP - Layer 2 only)
# IPs are assigned to vlan100/vlan200, not FTS bridge
setup_lan_gateway() {
    log_section "Setting Up FTS Bridge"

    # FTS bridge is Layer 2 only - NO IP
    # IPs are on vlan100 (LAN) and vlan200 (MGMT)
    log_info "FTS bridge is Layer 2 only (no IP)"
    log_info "IPs will be assigned to vlan100 and vlan200"

    # Ensure bridge is up
    ip link set "$OVS_BRIDGE" up 2>/dev/null || true

    log_info "FTS bridge is up"
}

cleanup_ovs_network() {
    log_section "Cleaning Up OVS Network"

    # Remove mirrors
    ovs-vsctl clear bridge "$OVS_BRIDGE" mirrors 2>/dev/null || true
    ovs-vsctl clear bridge "$OVS_BRIDGE" sflow 2>/dev/null || true
    ovs-vsctl clear bridge "$OVS_BRIDGE" ipfix 2>/dev/null || true

    # Delete bridge
    ovs-vsctl del-br "$OVS_BRIDGE" 2>/dev/null || true

    # Remove NAT rules for all possible LAN subnet sizes
    # Try to remove each possible CIDR to ensure cleanup works regardless of configuration
    for mask in 23 24 25 26 27 28 29; do
        iptables -t nat -D POSTROUTING -s "10.200.0.0/${mask}" -j MASQUERADE 2>/dev/null || true
        # Also remove fallback NAT rules
        iptables -t nat -D POSTROUTING -s "10.200.0.0/${mask}" ! -d "10.200.0.0/${mask}" ! -o "$OVS_BRIDGE" -j MASQUERADE 2>/dev/null || true
    done
    # Remove container network NAT rules (both old 201.x and new 200.x subnets)
    for subnet in 172.20.200.0/24 172.20.201.0/24; do
        iptables -t nat -D POSTROUTING -s "$subnet" -j MASQUERADE 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s "$subnet" ! -d 172.20.0.0/16 ! -o "$OVS_BRIDGE" -j MASQUERADE 2>/dev/null || true
    done

    # Remove DNAT rules for web UI access (both old and new container IPs)
    iptables -t nat -D PREROUTING -i "$OVS_BRIDGE" -p tcp --dport 8443 -j DNAT --to-destination 172.20.200.20:8443 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$OVS_BRIDGE" -p tcp --dport 8443 -j DNAT --to-destination 172.20.201.10:8443 2>/dev/null || true

    # Remove FORWARD rules for container networks (both old and new subnets)
    for subnet in 172.20.200.0/24 172.20.201.0/24; do
        iptables -D FORWARD -i "$OVS_BRIDGE" -d "$subnet" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -s "$subnet" -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    done

    # Remove generic forwarding rules
    iptables -D FORWARD -i "$OVS_BRIDGE" ! -o "$OVS_BRIDGE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD ! -i "$OVS_BRIDGE" -o "$OVS_BRIDGE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Remove DHCP config
    rm -f /etc/dnsmasq.d/fts-ovs.conf
    systemctl restart dnsmasq 2>/dev/null || true

    log_info "OVS network cleaned up"
}

# ============================================================
# PODMAN CNI INTEGRATION
# ============================================================

create_podman_networks() {
    log_section "Creating Podman Networks for OVS Integration"

    local cni_dir="/etc/cni/net.d"
    mkdir -p "$cni_dir"

    # For each tier, create a macvlan network attached to OVS internal port
    for tier in data services ml mgmt; do
        local port_name="${OVS_BRIDGE}-${tier}"
        local config="${TIER_CONFIG[$tier]}"
        local gateway="${config%%:*}"
        local subnet_ip="${gateway%/*}"
        local subnet_base="${subnet_ip%.*}.0"
        local network_name="fts-${tier}"

        # Ensure OVS port is up
        ip link set "$port_name" up 2>/dev/null || true

        # Remove existing Podman network if exists
        podman network rm -f "$network_name" 2>/dev/null || true

        # Create Podman network using macvlan driver attached to OVS port
        log_info "Creating network: $network_name (attached to $port_name)"

        # Create CNI config for macvlan attached to OVS internal port
        cat > "$cni_dir/fortress-${tier}.conflist" << EOF
{
    "cniVersion": "0.4.0",
    "name": "${network_name}",
    "plugins": [
        {
            "type": "macvlan",
            "master": "${port_name}",
            "mode": "bridge",
            "ipam": {
                "type": "static",
                "routes": [
                    {"dst": "0.0.0.0/0", "gw": "${subnet_ip}"}
                ]
            }
        }
    ]
}
EOF

        log_info "  CNI config: $cni_dir/fortress-${tier}.conflist"
    done

    # Special handling for LAN tier (client network, not for containers)
    log_info "LAN tier (fts-lan) is for client devices, not containers"

    log_info "Podman CNI networks created"
    log_info "Note: Containers should use --network=fortress-<tier> --ip=<static_ip>"
}

create_container_veths() {
    log_section "Creating Container veth Interfaces"

    # This function creates veth pairs for containers to connect to OVS
    # Called after containers start, before they need networking

    for container in "${!CONTAINER_IPS[@]}"; do
        local ip="${CONTAINER_IPS[$container]}"
        local tier=""

        # Determine tier from IP
        case "$ip" in
            172.20.200.*) tier="data" ;;
            172.20.201.*) tier="services" ;;
            172.20.202.*) tier="ml" ;;
            172.20.203.*) tier="mgmt" ;;
            *) continue ;;
        esac

        local veth_host="veth-${container}"
        local veth_cont="eth0"
        local port_name="${OVS_BRIDGE}-${tier}"

        # Skip if container not running
        if ! podman inspect "fts-${container}" &>/dev/null; then
            continue
        fi

        log_info "Connecting fortress-${container} to $port_name ($ip)"

        # Get container PID
        local pid
        pid=$(podman inspect -f '{{.State.Pid}}' "fts-${container}" 2>/dev/null) || continue

        # Create veth pair
        ip link add "$veth_host" type veth peer name "$veth_cont" 2>/dev/null || true

        # Add host end to OVS bridge
        ovs-vsctl add-port "$OVS_BRIDGE" "$veth_host" 2>/dev/null || true
        ip link set "$veth_host" up

        # Move container end to container namespace
        ip link set "$veth_cont" netns "$pid" 2>/dev/null || true

        # Configure container end
        nsenter -t "$pid" -n ip link set "$veth_cont" up 2>/dev/null || true
        nsenter -t "$pid" -n ip addr add "${ip}/24" dev "$veth_cont" 2>/dev/null || true

        # Set default route based on tier
        local gateway="${port_name%/*}"
        gateway="${TIER_CONFIG[$tier]}"
        gateway="${gateway%%:*}"
        gateway="${gateway%/*}"
        nsenter -t "$pid" -n ip route add default via "$gateway" 2>/dev/null || true
    done

    log_info "Container veth interfaces configured"
}

attach_container_to_ovs() {
    local container_name="$1"
    local ip="$2"
    local tier="$3"

    if [ -z "$container_name" ] || [ -z "$ip" ] || [ -z "$tier" ]; then
        log_error "Usage: attach_container_to_ovs <container_name> <ip> <tier>"
        return 1
    fi

    local veth_host="veth-${container_name}"
    local veth_cont="eth-ovs"
    local port_name="${OVS_BRIDGE}-${tier}"
    local config="${TIER_CONFIG[$tier]}"
    local gateway="${config%%:*}"
    gateway="${gateway%/*}"

    # Get container PID
    local pid
    pid=$(podman inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null) || {
        log_error "Container $container_name not found or not running"
        return 1
    }

    # Clean up any existing veth
    ip link del "$veth_host" 2>/dev/null || true
    ovs-vsctl del-port "$OVS_BRIDGE" "$veth_host" 2>/dev/null || true

    # Create veth pair
    ip link add "$veth_host" type veth peer name "$veth_cont"

    # Add host end to OVS bridge
    ovs-vsctl add-port "$OVS_BRIDGE" "$veth_host"
    ip link set "$veth_host" up

    # Move container end to container namespace
    ip link set "$veth_cont" netns "$pid"

    # Configure container end
    nsenter -t "$pid" -n ip link set "$veth_cont" up
    nsenter -t "$pid" -n ip addr add "${ip}/24" dev "$veth_cont"
    nsenter -t "$pid" -n ip route add default via "$gateway" 2>/dev/null || true

    log_info "Attached $container_name to OVS ($tier tier, IP: $ip)"
}

# ============================================================
# MAIN
# ============================================================

usage() {
    cat << EOF
Usage: $0 <command> [options]

Commands:
  init                    Initialize OVS network (bridge, tiers, flows)
  init-podman             Initialize for podman-compose (skip tier ports)
  cleanup                 Remove OVS network configuration
  add-lan <iface>         Add LAN interface to bridge
  add-wifi <iface>        Configure WiFi AP interface
  nat <wan_iface>         Setup NAT for internet access
  dhcp                    Configure DHCP server

  block <ip>              Block an IP address
  rate-limit <ip> [meter] Rate limit an IP (meter 1=1M, 2=10M, 3=100M)

  vxlan-peer <name> <ip> <vni> [port]  Add VXLAN peer

  podman-networks         Create Podman CNI networks for OVS tiers
  attach <container> <ip> <tier>  Attach running container to OVS
  connect-containers      Connect all fortress containers to OVS

  status                  Show network status
  flows                   Show OpenFlow rules

Examples:
  $0 init                           # Initialize OVS
  $0 add-lan eth1                   # Add LAN interface
  $0 nat eth0                       # Setup NAT
  $0 dhcp                           # Configure DHCP
  $0 podman-networks                # Create Podman CNI networks
  $0 attach fts-web 172.20.201.10 services
  $0 connect-containers             # Connect all containers
  $0 block 10.200.0.50              # Block IP
  $0 vxlan-peer mssp 203.0.113.1 2000

Container Network Tiers (FTS = abbreviation for "fortress"):
  data      172.20.200.0/24      postgres, redis (NO internet)
  services  172.20.201.0/24      web, dnsxai, dfs (internet OK)
  ml        172.20.202.0/24      lstm-trainer (NO internet)
  mgmt      172.20.203.0/24      grafana, victoria (NO internet)
  lan       10.200.0.0/MASK      WiFi/LAN clients (NAT to internet)

LAN Subnet Configuration:
  Export LAN_SUBNET_MASK before calling init/nat/dhcp commands.
  Supported values: 23 (510 devices), 24 (254), 25 (126), 26 (62), 27 (30), 28 (14), 29 (6)
  Example: LAN_SUBNET_MASK=24 $0 init

EOF
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        init)
            init_ovs_network
            ;;
        init-podman)
            init_ovs_network_podman
            ;;
        cleanup)
            cleanup_ovs_network
            ;;
        add-lan)
            add_lan_interface "$2"
            ;;
        add-wifi)
            add_wifi_interface "$2"
            ;;
        nat)
            setup_nat "$2"
            ;;
        dhcp)
            setup_dhcp
            ;;
        block)
            block_ip "$2"
            ;;
        rate-limit)
            rate_limit_ip "$2" "${3:-1}"
            ;;
        vxlan-peer)
            add_vxlan_peer "$2" "$3" "$4" "${5:-4789}"
            ;;
        podman-networks)
            create_podman_networks
            ;;
        attach)
            attach_container_to_ovs "$2" "$3" "$4"
            ;;
        connect-containers)
            create_container_veths
            ;;
        status)
            show_status
            ;;
        flows)
            show_flows
            ;;
        *)
            usage
            ;;
    esac
fi
