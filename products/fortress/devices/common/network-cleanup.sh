#!/bin/bash
#
# network-cleanup.sh - Clean up and consolidate Fortress network on OVS
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This script:
#   - Removes redundant Linux bridges
#   - Migrates WiFi interfaces to OVS fortress bridge
#   - Configures proper VLAN tagging for WiFi APs
#   - Sets up podman networking via OVS
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

# Configuration
OVS_BRIDGE="${FORTRESS_BRIDGE:-FTS}"
WIFI_24GHZ_VLAN="${WIFI_24GHZ_VLAN:-40}"  # Guest by default
WIFI_5GHZ_VLAN="${WIFI_5GHZ_VLAN:-30}"    # Staff by default
MANAGEMENT_VLAN="${MANAGEMENT_VLAN:-10}"
SUBNET_PREFIX="${FORTRESS_SUBNET:-10.250}"

# Load config from fortress.conf if available
FORTRESS_CONF="/etc/hookprobe/fortress.conf"
if [ -f "$FORTRESS_CONF" ]; then
    # shellcheck source=/dev/null
    source "$FORTRESS_CONF" 2>/dev/null || true
fi
# Always use VLAN mode (filter mode removed)
NETWORK_MODE="vlan"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[NETWORK]${NC} $*"; }
log_success() { echo -e "${GREEN}[NETWORK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[NETWORK]${NC} $*"; }
log_error() { echo -e "${RED}[NETWORK]${NC} $*"; }

# ========================================
# Detection Functions
# ========================================

# Get all WiFi interfaces
get_wifi_interfaces() {
    iw dev 2>/dev/null | grep "Interface" | awk '{print $2}' | sort -u
}

# Get WiFi interface frequency band
get_wifi_band() {
    local iface="$1"
    local freq

    freq=$(iw dev "$iface" info 2>/dev/null | grep "channel" | awk '{print $2}')

    if [ -z "$freq" ]; then
        # Not associated, check capabilities
        local phy
        phy=$(iw dev "$iface" info 2>/dev/null | grep wiphy | awk '{print $2}')
        if [ -n "$phy" ]; then
            if iw phy "phy$phy" info 2>/dev/null | grep -q "5180 MHz"; then
                # Has 5GHz capability - check interface name pattern
                if [[ "$iface" =~ wlp.*s0 ]] || [[ "$iface" =~ wlan1 ]]; then
                    echo "5ghz"
                    return
                fi
            fi
        fi
        echo "2.4ghz"
        return
    fi

    if [ "$freq" -ge 5000 ]; then
        echo "5ghz"
    else
        echo "2.4ghz"
    fi
}

# Get physical Ethernet interfaces (not virtual)
get_physical_ethernet() {
    for iface in /sys/class/net/*; do
        iface=$(basename "$iface")

        # Skip virtual interfaces
        [[ "$iface" =~ ^(lo|veth|br-|vlan|ovs|docker|podman|virbr|tun|tap) ]] && continue

        # Check if it's ethernet (has carrier file and is not wireless)
        if [ -f "/sys/class/net/$iface/carrier" ] && \
           [ ! -d "/sys/class/net/$iface/wireless" ]; then
            # Check if it has a physical device
            if [ -L "/sys/class/net/$iface/device" ]; then
                echo "$iface"
            fi
        fi
    done
}

# ========================================
# Cleanup Functions
# ========================================

# Remove redundant Linux bridges
remove_redundant_bridges() {
    log_info "Removing redundant Linux bridges..."

    local bridges=("br-mgmt" "br-pos" "br-staff" "br-guest" "br-iot")

    for br in "${bridges[@]}"; do
        if ip link show "$br" &>/dev/null; then
            log_info "  Removing $br"
            ip link set "$br" down 2>/dev/null || true
            ip link delete "$br" type bridge 2>/dev/null || true
        fi
    done

    log_success "Redundant bridges removed"
}

# Release WiFi interfaces from bridges (fortress or legacy br-lan)
release_wifi_from_bridge() {
    log_info "Releasing WiFi interfaces from bridges..."

    for iface in $(get_wifi_interfaces); do
        local master
        master=$(ip link show "$iface" 2>/dev/null | grep -oP 'master \K\S+')

        if [ "$master" = "fortress" ] || [ "$master" = "br-lan" ]; then
            log_info "  Releasing $iface from $master"
            ip link set "$iface" nomaster 2>/dev/null || true
        fi
    done

    # Remove fortress bridge if empty and exists
    if ip link show fortress &>/dev/null; then
        local slaves
        slaves=$(ip link show master fortress 2>/dev/null | wc -l)
        if [ "$slaves" -eq 0 ]; then
            log_info "  Removing empty fortress bridge"
            ip link set fortress down 2>/dev/null || true
            ip link delete fortress type bridge 2>/dev/null || true
        fi
    fi

    # Also cleanup legacy br-lan if it exists
    if ip link show br-lan &>/dev/null; then
        local slaves
        slaves=$(ip link show master br-lan 2>/dev/null | wc -l)
        if [ "$slaves" -eq 0 ]; then
            log_info "  Removing empty br-lan (legacy)"
            ip link set br-lan down 2>/dev/null || true
            ip link delete br-lan type bridge 2>/dev/null || true
        fi
    fi

    log_success "WiFi interfaces released"
}

# ========================================
# OVS Setup Functions
# ========================================

# Ensure OVS bridge exists
ensure_ovs_bridge() {
    log_info "Ensuring OVS bridge $OVS_BRIDGE exists..."

    if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_info "  Creating OVS bridge $OVS_BRIDGE"
        ovs-vsctl add-br "$OVS_BRIDGE"
    fi

    # Bring bridge up
    ip link set "$OVS_BRIDGE" up

    # VLAN mode: FTS bridge is Layer 2 only, no IP
    # IPs are on vlan100 (LAN) and vlan200 (MGMT)
    log_info "  VLAN mode: FTS bridge is Layer 2 only (IPs on vlan100/vlan200)"
    log_success "OVS bridge ready: $OVS_BRIDGE"
}

# Add WiFi interface to OVS with VLAN tagging
add_wifi_to_ovs() {
    local iface="$1"
    local vlan="$2"

    log_info "Adding $iface to OVS bridge with VLAN $vlan..."

    # Remove from any existing bridge first
    local master
    master=$(ip link show "$iface" 2>/dev/null | grep -oP 'master \K\S+')
    if [ -n "$master" ]; then
        ip link set "$iface" nomaster 2>/dev/null || true
    fi

    # Check if already in OVS
    if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${iface}$"; then
        log_info "  $iface already in OVS, updating VLAN tag"
        ovs-vsctl set port "$iface" tag="$vlan"
    else
        # Add to OVS with VLAN tag
        ovs-vsctl --may-exist add-port "$OVS_BRIDGE" "$iface" tag="$vlan"
    fi

    log_success "  $iface -> VLAN $vlan"
}

# Create VLAN internal ports
create_vlan_ports() {
    log_info "Creating VLAN internal ports..."

    local vlans=(
        "10:${SUBNET_PREFIX}.10.1/24"   # Management
        "20:${SUBNET_PREFIX}.20.1/24"   # POS
        "30:${SUBNET_PREFIX}.30.1/24"   # Staff
        "40:${SUBNET_PREFIX}.40.1/24"   # Guest
        "99:${SUBNET_PREFIX}.99.1/24"   # IoT
    )

    for vlan_info in "${vlans[@]}"; do
        local vlan_id="${vlan_info%%:*}"
        local vlan_ip="${vlan_info#*:}"
        local port_name="vlan${vlan_id}"

        # Create internal port if not exists
        if ! ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${port_name}$"; then
            log_info "  Creating $port_name"
            ovs-vsctl add-port "$OVS_BRIDGE" "$port_name" \
                -- set interface "$port_name" type=internal \
                -- set port "$port_name" tag="$vlan_id"
        fi

        # Configure IP
        ip link set "$port_name" up 2>/dev/null || true
        ip addr flush dev "$port_name" 2>/dev/null || true
        ip addr add "$vlan_ip" dev "$port_name" 2>/dev/null || true
    done

    log_success "VLAN ports created"
}

# Add physical Ethernet to OVS bridge
# LAN ports as simple access ports for direct bridge connectivity
add_ethernet_to_ovs() {
    log_info "Adding physical Ethernet interfaces to OVS..."

    for iface in $(get_physical_ethernet); do
        # Skip WAN interface (usually first one or has default route)
        if ip route show default 2>/dev/null | grep -q "dev $iface"; then
            log_info "  Skipping WAN interface: $iface"
            continue
        fi

        # Flush any existing IPs from the interface
        ip addr flush dev "$iface" 2>/dev/null || true

        # Bring interface up
        ip link set "$iface" up 2>/dev/null || true

        # Add to OVS bridge
        if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^${iface}$"; then
            log_info "  $iface already in OVS, updating config"
        else
            log_info "  Adding $iface to bridge"
            ovs-vsctl --may-exist add-port "$OVS_BRIDGE" "$iface"
        fi

        # Clear any VLAN settings - make it a simple access port
        # This ensures untagged traffic flows to/from the bridge
        # Clients get DHCP from main bridge (10.250.0.x)
        ovs-vsctl clear port "$iface" tag 2>/dev/null || true
        ovs-vsctl clear port "$iface" trunks 2>/dev/null || true
        ovs-vsctl clear port "$iface" vlan_mode 2>/dev/null || true

        log_info "  $iface added to bridge (direct access)"
    done

    log_success "Ethernet LAN interfaces configured"
}

# ========================================
# Podman Integration
# ========================================

# Create podman network using OVS
setup_podman_ovs_network() {
    log_info "Setting up Podman OVS integration..."

    # Create CNI config directory
    mkdir -p /etc/cni/net.d

    # Create OVS CNI config for each VLAN
    local vlans=(
        "management:10:${SUBNET_PREFIX}.10"
        "pos:20:${SUBNET_PREFIX}.20"
        "staff:30:${SUBNET_PREFIX}.30"
        "guest:40:${SUBNET_PREFIX}.40"
        "iot:99:${SUBNET_PREFIX}.99"
    )

    for vlan_info in "${vlans[@]}"; do
        local name="${vlan_info%%:*}"
        local rest="${vlan_info#*:}"
        local vlan_id="${rest%%:*}"
        local subnet="${rest#*:}"

        local config_file="/etc/cni/net.d/fortress-${name}.conflist"

        cat > "$config_file" << EOF
{
  "cniVersion": "0.4.0",
  "name": "fts-${name}",
  "plugins": [
    {
      "type": "ovs",
      "bridge": "${OVS_BRIDGE}",
      "vlan": ${vlan_id},
      "ipam": {
        "type": "host-local",
        "ranges": [
          [
            {
              "subnet": "${subnet}.0/24",
              "rangeStart": "${subnet}.100",
              "rangeEnd": "${subnet}.199",
              "gateway": "${subnet}.1"
            }
          ]
        ],
        "routes": [
          { "dst": "0.0.0.0/0" }
        ]
      }
    }
  ]
}
EOF
        log_info "  Created network config: fortress-${name}"
    done

    # Install OVS CNI plugin if not present
    if [ ! -f /opt/cni/bin/ovs ]; then
        log_warn "  OVS CNI plugin not found at /opt/cni/bin/ovs"
        log_info "  Install with: https://github.com/k8snetworkplumbingwg/ovs-cni"
    fi

    log_success "Podman OVS networks configured"
    echo ""
    log_info "To use Podman with OVS VLANs:"
    echo "  podman run --network fortress-management ...  # VLAN 10"
    echo "  podman run --network fortress-staff ...       # VLAN 30"
    echo "  podman run --network fortress-iot ...         # VLAN 99"
}

# Remove default podman network usage
disable_default_podman_network() {
    log_info "Configuring Podman to avoid default network..."

    # Create containers.conf override
    mkdir -p /etc/containers

    # Check if file exists and has our setting
    if [ -f /etc/containers/containers.conf ]; then
        if ! grep -q "default_network" /etc/containers/containers.conf; then
            cat >> /etc/containers/containers.conf << 'EOF'

# HookProbe Fortress: Use OVS networks by default
[network]
default_network = "fts-management"
EOF
        fi
    else
        cat > /etc/containers/containers.conf << 'EOF'
# HookProbe Fortress Container Configuration

[network]
# Use OVS networks by default instead of podman0
default_network = "fts-management"
EOF
    fi

    log_success "Podman default network configured"
}

# ========================================
# DHCP Server Setup (dnsmasq)
# ========================================

# Configure dnsmasq for VLAN-based DHCP
setup_dnsmasq_vlans() {
    log_info "Configuring dnsmasq for VLAN-based DHCP..."

    if ! command -v dnsmasq &>/dev/null; then
        log_warn "dnsmasq not installed, skipping DHCP setup"
        log_info "Install with: apt-get install dnsmasq"
        return 1
    fi

    # Create dnsmasq config directory
    mkdir -p /etc/dnsmasq.d

    # Create main Fortress dnsmasq config
    cat > /etc/dnsmasq.d/fts-vlans.conf << EOF
# HookProbe Fortress VLAN DHCP Configuration
# Generated: $(date -Iseconds)
#
# Each VLAN interface provides DHCP for its subnet

# Global settings
domain-needed
bogus-priv
no-resolv
no-poll

# Upstream DNS servers
server=1.1.1.1
server=8.8.8.8

# Local domain
domain=fortress.local
local=/fortress.local/

# Logging
log-dhcp
log-facility=/var/log/fts-dnsmasq.log

# Lease file
dhcp-leasefile=/var/lib/misc/fts-dnsmasq.leases

# VLAN 10 - Management (${SUBNET_PREFIX}.10.x)
interface=vlan10
dhcp-range=vlan10,${SUBNET_PREFIX}.10.100,${SUBNET_PREFIX}.10.200,255.255.255.0,12h
dhcp-option=vlan10,3,${SUBNET_PREFIX}.10.1
dhcp-option=vlan10,6,${SUBNET_PREFIX}.10.1,1.1.1.1

# VLAN 20 - POS (${SUBNET_PREFIX}.20.x)
interface=vlan20
dhcp-range=vlan20,${SUBNET_PREFIX}.20.100,${SUBNET_PREFIX}.20.200,255.255.255.0,12h
dhcp-option=vlan20,3,${SUBNET_PREFIX}.20.1
dhcp-option=vlan20,6,${SUBNET_PREFIX}.20.1,1.1.1.1

# VLAN 30 - Staff (${SUBNET_PREFIX}.30.x)
interface=vlan30
dhcp-range=vlan30,${SUBNET_PREFIX}.30.100,${SUBNET_PREFIX}.30.200,255.255.255.0,12h
dhcp-option=vlan30,3,${SUBNET_PREFIX}.30.1
dhcp-option=vlan30,6,${SUBNET_PREFIX}.30.1,1.1.1.1

# VLAN 40 - Guest (${SUBNET_PREFIX}.40.x)
interface=vlan40
dhcp-range=vlan40,${SUBNET_PREFIX}.40.100,${SUBNET_PREFIX}.40.200,255.255.255.0,12h
dhcp-option=vlan40,3,${SUBNET_PREFIX}.40.1
dhcp-option=vlan40,6,${SUBNET_PREFIX}.40.1,1.1.1.1

# VLAN 99 - IoT (${SUBNET_PREFIX}.99.x)
interface=vlan99
dhcp-range=vlan99,${SUBNET_PREFIX}.99.100,${SUBNET_PREFIX}.99.200,255.255.255.0,12h
dhcp-option=vlan99,3,${SUBNET_PREFIX}.99.1
dhcp-option=vlan99,6,${SUBNET_PREFIX}.99.1,1.1.1.1

# Also listen on main bridge for untagged traffic
interface=${OVS_BRIDGE}
dhcp-range=${OVS_BRIDGE},${SUBNET_PREFIX}.0.100,${SUBNET_PREFIX}.0.200,255.255.0.0,12h
dhcp-option=${OVS_BRIDGE},3,${SUBNET_PREFIX}.0.1
dhcp-option=${OVS_BRIDGE},6,${SUBNET_PREFIX}.0.1,1.1.1.1

# Bind only to specified interfaces
bind-interfaces
EOF

    # Create lease directory and file
    mkdir -p /var/lib/misc
    touch /var/lib/misc/fts-dnsmasq.leases

    # Create systemd service for fts-dnsmasq if not exists
    if [ ! -f /etc/systemd/system/fts-dnsmasq.service ]; then
        cat > /etc/systemd/system/fts-dnsmasq.service << 'SVCEOF'
[Unit]
Description=Fortress DHCP and DNS Server
After=network.target
Wants=network.target

[Service]
Type=forking
PIDFile=/run/fts-dnsmasq.pid
ExecStartPre=/usr/sbin/dnsmasq --test -C /etc/dnsmasq.d/fts-vlans.conf
ExecStart=/usr/sbin/dnsmasq -C /etc/dnsmasq.d/fts-vlans.conf --pid-file=/run/fts-dnsmasq.pid
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF
        systemctl daemon-reload 2>/dev/null || true
    fi

    # Stop conflicting dnsmasq instances
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl disable dnsmasq 2>/dev/null || true
    pkill -f "dnsmasq.*fts-bridge" 2>/dev/null || true

    # Enable and restart fts-dnsmasq
    systemctl enable fts-dnsmasq 2>/dev/null || true
    systemctl restart fts-dnsmasq 2>/dev/null || {
        log_warn "Failed to start fts-dnsmasq via systemd"
        # Try starting directly
        pkill dnsmasq 2>/dev/null || true
        sleep 1
        /usr/sbin/dnsmasq -C /etc/dnsmasq.d/fts-vlans.conf --pid-file=/run/fts-dnsmasq.pid &
    }

    # Verify dnsmasq is running
    sleep 2
    if pgrep -f "dnsmasq.*fts-vlans" >/dev/null; then
        log_success "dnsmasq DHCP server running"
    else
        log_error "dnsmasq failed to start - check /var/log/fts-dnsmasq.log"
        return 1
    fi

    log_success "DHCP configured for all VLANs"
}

# ========================================
# Hostapd Update
# ========================================

# Update hostapd configs to use OVS bridge
update_hostapd_configs() {
    log_info "Updating hostapd configs for OVS bridge..."

    local configs=(
        "/etc/hostapd/hostapd-24ghz.conf"
        "/etc/hostapd/hostapd-5ghz.conf"
    )

    for config in "${configs[@]}"; do
        if [ -f "$config" ]; then
            # Update bridge setting
            if grep -q "^bridge=" "$config"; then
                sed -i "s/^bridge=.*/bridge=${OVS_BRIDGE}/" "$config"
                log_info "  Updated $config: bridge=${OVS_BRIDGE}"
            else
                echo "bridge=${OVS_BRIDGE}" >> "$config"
                log_info "  Added bridge to $config"
            fi
        fi
    done

    log_success "Hostapd configs updated"
}

# ========================================
# Status Display
# ========================================

show_network_status() {
    echo ""
    echo "========================================"
    echo "Fortress Network Status"
    echo "========================================"
    echo ""

    echo "OVS Bridge: $OVS_BRIDGE"
    ovs-vsctl show 2>/dev/null | head -30
    echo ""

    echo "VLAN Interfaces:"
    for vlan in 10 20 30 40 99; do
        local iface="vlan${vlan}"
        if ip link show "$iface" &>/dev/null; then
            local ip
            ip=$(ip -4 addr show "$iface" 2>/dev/null | grep inet | awk '{print $2}')
            local state
            state=$(ip link show "$iface" 2>/dev/null | grep -oP 'state \K\S+')
            echo "  $iface: $ip ($state)"
        fi
    done
    echo ""

    echo "WiFi Interfaces:"
    for iface in $(get_wifi_interfaces); do
        local band
        band=$(get_wifi_band "$iface")
        local vlan
        vlan=$(ovs-vsctl get port "$iface" tag 2>/dev/null || echo "none")
        echo "  $iface: $band, VLAN=$vlan"
    done
    echo ""

    echo "DHCP Status:"
    if pgrep -f "dnsmasq" >/dev/null 2>&1; then
        echo "  dnsmasq: RUNNING (PID: $(pgrep -f dnsmasq | head -1))"
        if [ -f /etc/dnsmasq.d/fts-vlans.conf ]; then
            echo "  Config: /etc/dnsmasq.d/fts-vlans.conf"
            echo "  Listening on interfaces:"
            grep "^interface=" /etc/dnsmasq.d/fts-vlans.conf 2>/dev/null | sed 's/interface=/    - /'
        fi
        if [ -f /var/lib/misc/fts-dnsmasq.leases ]; then
            local lease_count
            lease_count=$(wc -l < /var/lib/misc/fts-dnsmasq.leases 2>/dev/null || echo "0")
            echo "  Active leases: $lease_count"
        fi
    else
        echo "  dnsmasq: NOT RUNNING"
    fi
    echo ""

    echo "OVS Flow Rules (MAC-to-VLAN):"
    ovs-ofctl dump-flows "$OVS_BRIDGE" 2>/dev/null | grep "dl_src=" | head -10
    echo ""
}

# ========================================
# Main Functions
# ========================================

cleanup_network() {
    log_info "Starting network cleanup..."
    echo ""

    # Step 1: Remove redundant bridges
    remove_redundant_bridges
    echo ""

    # Step 2: Release WiFi from bridges
    release_wifi_from_bridge
    echo ""

    # Step 3: Ensure OVS bridge
    ensure_ovs_bridge
    echo ""

    # Step 4: Create VLAN ports
    create_vlan_ports
    echo ""

    # Step 5: Add WiFi to OVS with proper VLANs
    for iface in $(get_wifi_interfaces); do
        local band
        band=$(get_wifi_band "$iface")
        local vlan

        if [ "$band" = "5ghz" ]; then
            vlan="$WIFI_5GHZ_VLAN"
        else
            vlan="$WIFI_24GHZ_VLAN"
        fi

        add_wifi_to_ovs "$iface" "$vlan"
    done
    echo ""

    # Step 6: Add Ethernet trunk ports
    add_ethernet_to_ovs
    echo ""

    # Step 7: Update hostapd configs
    update_hostapd_configs
    echo ""

    # Step 8: Configure DHCP server for VLANs
    setup_dnsmasq_vlans
    echo ""

    log_success "Network cleanup complete!"
}

setup_podman() {
    setup_podman_ovs_network
    echo ""
    disable_default_podman_network
}

full_setup() {
    cleanup_network
    echo ""
    setup_podman
    echo ""
    show_network_status
}

# ========================================
# Usage
# ========================================

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  cleanup       - Clean up redundant bridges and consolidate on OVS"
    echo "  podman        - Set up Podman OVS integration"
    echo "  dhcp          - Configure DHCP server for all VLANs"
    echo "  full          - Full cleanup + Podman + DHCP setup"
    echo "  status        - Show current network status"
    echo ""
    echo "Environment Variables:"
    echo "  FORTRESS_BRIDGE     - OVS bridge name (default: fortress)"
    echo "  WIFI_24GHZ_VLAN     - VLAN for 2.4GHz AP (default: 40 Guest)"
    echo "  WIFI_5GHZ_VLAN      - VLAN for 5GHz AP (default: 30 Staff)"
    echo "  FORTRESS_SUBNET     - Subnet prefix (default: 10.250)"
    echo ""
    echo "DHCP Ranges (per VLAN):"
    echo "  VLAN 10 (Management): ${SUBNET_PREFIX}.10.100-200"
    echo "  VLAN 20 (POS):        ${SUBNET_PREFIX}.20.100-200"
    echo "  VLAN 30 (Staff):      ${SUBNET_PREFIX}.30.100-200"
    echo "  VLAN 40 (Guest):      ${SUBNET_PREFIX}.40.100-200"
    echo "  VLAN 99 (IoT):        ${SUBNET_PREFIX}.99.100-200"
    echo "  Main bridge:          ${SUBNET_PREFIX}.0.100-200"
    echo ""
    echo "Examples:"
    echo "  $0 cleanup                      # Clean up network"
    echo "  $0 dhcp                         # Configure DHCP only"
    echo "  $0 full                         # Full setup"
    echo "  WIFI_5GHZ_VLAN=10 $0 cleanup    # 5GHz on Management VLAN"
    echo ""
}

# Main
case "${1:-}" in
    cleanup)
        cleanup_network
        ;;
    podman)
        setup_podman
        ;;
    dhcp)
        setup_dnsmasq_vlans
        ;;
    full)
        full_setup
        ;;
    status)
        show_network_status
        ;;
    *)
        usage
        ;;
esac
