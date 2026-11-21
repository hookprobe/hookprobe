#!/bin/bash
#
# interfaces.sh - Intel N100 Network Interface Detection and Configuration
# Part of HookProbe Fortress Device Profiles
#
# Detects and maps network interfaces on Intel N100/N150/N200/N305 mini-PCs
# Supports multi-port Ethernet (2-4 ports) with i225-V/i226-V NICs
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/profile.conf"

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# ============================================================
# INTERFACE DETECTION
# ============================================================

get_interface_driver() {
    # Get driver name for interface
    local iface="$1"
    local driver_path="/sys/class/net/$iface/device/driver"

    if [ -L "$driver_path" ]; then
        basename "$(readlink "$driver_path")"
    fi
}

get_interface_pci_id() {
    # Get PCI vendor:device ID
    local iface="$1"
    local vendor=$(cat "/sys/class/net/$iface/device/vendor" 2>/dev/null | sed 's/0x//')
    local device=$(cat "/sys/class/net/$iface/device/device" 2>/dev/null | sed 's/0x//')

    echo "$vendor:$device"
}

get_interface_speed() {
    # Get interface link speed capability
    local iface="$1"
    local speed

    # Try ethtool first
    if command -v ethtool &>/dev/null; then
        speed=$(ethtool "$iface" 2>/dev/null | grep "Speed:" | awk '{print $2}')
    fi

    # Fallback to sysfs
    if [ -z "$speed" ] && [ -f "/sys/class/net/$iface/speed" ]; then
        speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null)
        [ -n "$speed" ] && speed="${speed}Mb/s"
    fi

    echo "${speed:-Unknown}"
}

is_intel_i225() {
    # Check if interface is Intel i225-V 2.5GbE
    local iface="$1"
    local pci_id=$(get_interface_pci_id "$iface")

    # Intel i225 variants
    # 8086:15f2 - i225-IT
    # 8086:15f3 - i225-V (most common)
    # 8086:0d9f - i225-K
    # 8086:125b - i225-LM
    # 8086:125c - i225-LMVP

    case "$pci_id" in
        8086:15f2|8086:15f3|8086:0d9f|8086:125b|8086:125c)
            return 0
            ;;
    esac
    return 1
}

is_intel_i226() {
    # Check if interface is Intel i226-V 2.5GbE
    local iface="$1"
    local pci_id=$(get_interface_pci_id "$iface")

    # Intel i226 variants
    # 8086:125d - i226-LM
    # 8086:125e - i226-V

    case "$pci_id" in
        8086:125d|8086:125e)
            return 0
            ;;
    esac
    return 1
}

get_interface_pci_bus() {
    # Get PCI bus number for sorting interfaces
    local iface="$1"
    local pci_path

    if [ -L "/sys/class/net/$iface/device" ]; then
        pci_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)
        # Extract bus:slot.func from path like /sys/devices/pci0000:00/0000:00:1c.0/0000:01:00.0
        local bdf=$(basename "$pci_path" 2>/dev/null)
        # Extract just the bus number (first part before :)
        local bus=$(echo "$bdf" | cut -d':' -f2 | cut -d'.' -f1)
        echo "$bus"
    fi
}

# ============================================================
# INTERFACE MAPPING
# ============================================================

detect_intel_n100_interfaces() {
    # Detect and categorize interfaces on Intel N100 mini-PC
    #
    # Exports:
    #   FORTRESS_WAN_IFACE      - Primary WAN interface
    #   FORTRESS_LAN_IFACES     - Space-separated list of LAN interfaces
    #   FORTRESS_WIFI_IFACE     - WiFi interface (if present)
    #   FORTRESS_LTE_IFACE      - LTE interface (if present)

    log_info "Detecting interfaces on Intel N100..."

    local eth_interfaces=""
    local wifi_interface=""
    local lte_interface=""

    # Find all physical Ethernet interfaces and sort by PCI bus
    declare -A iface_bus_map

    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")

        # Skip virtual interfaces
        [[ "$name" == lo ]] && continue
        [[ "$name" == br* ]] && continue
        [[ "$name" == veth* ]] && continue
        [[ "$name" == docker* ]] && continue

        # Check if physical device
        [ ! -d "$iface/device" ] && continue

        # Check interface type
        if [ -d "$iface/wireless" ] || [ -d "$iface/phy80211" ]; then
            # WiFi interface
            wifi_interface="$name"
            log_info "  Found WiFi: $name ($(get_interface_driver "$name"))"

        elif [[ "$name" == wwan* ]] || [[ "$name" == wwp* ]]; then
            # LTE/WWAN interface
            lte_interface="$name"
            log_info "  Found LTE: $name"

        else
            # Potential Ethernet interface
            local devtype=$(cat "$iface/type" 2>/dev/null)
            if [ "$devtype" = "1" ]; then  # ARPHRD_ETHER
                local driver=$(get_interface_driver "$name")
                local bus=$(get_interface_pci_bus "$name")

                # Check if it's Intel 2.5GbE
                local speed_note=""
                if is_intel_i225 "$name" || is_intel_i226 "$name"; then
                    speed_note=" (2.5GbE)"
                fi

                iface_bus_map["$name"]="$bus"
                log_info "  Found Ethernet: $name [bus:$bus] ($driver)$speed_note"
            fi
        fi
    done

    # Sort Ethernet interfaces by PCI bus number
    local sorted_ifaces=""
    for iface in $(for k in "${!iface_bus_map[@]}"; do echo "${iface_bus_map[$k]}:$k"; done | sort -t: -k1 -n | cut -d: -f2); do
        sorted_ifaces="$sorted_ifaces $iface"
    done
    sorted_ifaces=$(echo "$sorted_ifaces" | xargs)

    # Assign roles based on port position
    # Convention: First port = WAN, remaining = LAN
    local wan_iface=""
    local lan_ifaces=""

    local first=true
    for iface in $sorted_ifaces; do
        if $first; then
            wan_iface="$iface"
            first=false
        else
            lan_ifaces="$lan_ifaces $iface"
        fi
    done
    lan_ifaces=$(echo "$lan_ifaces" | xargs)

    # Export variables
    export FORTRESS_WAN_IFACE="$wan_iface"
    export FORTRESS_LAN_IFACES="$lan_ifaces"
    export FORTRESS_WIFI_IFACE="$wifi_interface"
    export FORTRESS_LTE_IFACE="$lte_interface"
    export FORTRESS_ALL_ETH="$sorted_ifaces"

    log_success "Interface mapping complete"
    echo ""
    echo "  WAN Interface:  ${FORTRESS_WAN_IFACE:-none}"
    echo "  LAN Interfaces: ${FORTRESS_LAN_IFACES:-none}"
    echo "  WiFi Interface: ${FORTRESS_WIFI_IFACE:-none}"
    echo "  LTE Interface:  ${FORTRESS_LTE_IFACE:-none}"
    echo ""
}

# ============================================================
# INTERFACE CONFIGURATION
# ============================================================

configure_wan_interface() {
    # Configure WAN interface with DHCP or static IP
    local iface="${1:-$FORTRESS_WAN_IFACE}"
    local method="${2:-dhcp}"  # dhcp or static

    [ -z "$iface" ] && { log_warn "No WAN interface specified"; return 1; }

    log_info "Configuring WAN interface: $iface ($method)"

    # Ensure interface is up
    ip link set "$iface" up 2>/dev/null || true

    if [ "$method" = "dhcp" ]; then
        # Use dhclient or NetworkManager
        if command -v nmcli &>/dev/null; then
            # Check if connection exists
            local conn_name="fts-wan"
            nmcli connection delete "$conn_name" 2>/dev/null || true
            nmcli connection add type ethernet con-name "$conn_name" ifname "$iface" \
                ipv4.method auto ipv6.method auto 2>/dev/null
            nmcli connection up "$conn_name" 2>/dev/null || true
        elif command -v dhclient &>/dev/null; then
            dhclient -v "$iface" 2>/dev/null || true
        fi
    fi

    return 0
}

configure_lan_bridge() {
    # Create LAN bridge combining all LAN interfaces
    local bridge_name="${1:-FTS}"
    local lan_ifaces="${2:-$FORTRESS_LAN_IFACES}"

    [ -z "$lan_ifaces" ] && { log_warn "No LAN interfaces specified"; return 1; }

    log_info "Creating LAN bridge: $bridge_name with $lan_ifaces"

    # Create bridge using ip command
    ip link add name "$bridge_name" type bridge 2>/dev/null || true
    ip link set "$bridge_name" up

    # Add LAN interfaces to bridge
    for iface in $lan_ifaces; do
        ip link set "$iface" up
        ip link set "$iface" master "$bridge_name" 2>/dev/null || true
        log_info "  Added $iface to $bridge_name"
    done

    return 0
}

setup_intel_xdp() {
    # Configure XDP for Intel i225/i226 interfaces
    local iface="${1:-$FORTRESS_WAN_IFACE}"

    [ -z "$iface" ] && return 1

    # Check if interface supports XDP native mode
    if is_intel_i225 "$iface" || is_intel_i226 "$iface"; then
        log_info "Intel i225/i226 detected - XDP native mode supported"
        export FORTRESS_XDP_MODE="native"
    else
        log_info "XDP using generic mode"
        export FORTRESS_XDP_MODE="generic"
    fi

    return 0
}

# ============================================================
# INTERFACE PERSISTENCE
# ============================================================

generate_netplan_config() {
    # Generate netplan configuration for Ubuntu/Debian
    local config_file="/etc/netplan/60-fortress.yaml"

    log_info "Generating netplan configuration: $config_file"

    cat > "$config_file" << EOF
# HookProbe Fortress Network Configuration
# Generated by: fortress device profile (intel-n100)
# Do not edit manually - regenerate with: fts-network reconfigure

network:
  version: 2
  renderer: networkd

  ethernets:
    # WAN Interface - DHCP from upstream
    ${FORTRESS_WAN_IFACE}:
      dhcp4: true
      dhcp6: true
      optional: true

EOF

    # Add LAN interfaces
    for iface in $FORTRESS_LAN_IFACES; do
        cat >> "$config_file" << EOF
    # LAN Interface - Bridge member
    ${iface}:
      dhcp4: false
      dhcp6: false

EOF
    done

    # Add WiFi if present
    if [ -n "$FORTRESS_WIFI_IFACE" ]; then
        cat >> "$config_file" << EOF
  wifis:
    ${FORTRESS_WIFI_IFACE}:
      dhcp4: true
      optional: true
      access-points:
        # Configure via fts-wifi command
        "CONFIGURE_ME": {}

EOF
    fi

    # Add bridge configuration
    cat >> "$config_file" << EOF
  bridges:
    fortress:
      interfaces: [$(echo "$FORTRESS_LAN_IFACES" | tr ' ' ',')]
      addresses:
        - 10.250.0.1/24
      dhcp4: false
      parameters:
        stp: false
        forward-delay: 0
EOF

    log_success "Netplan configuration generated"
    return 0
}

save_interface_mapping() {
    # Save interface mapping to state file
    local state_file="/var/lib/fortress/interface-mapping.conf"

    mkdir -p "$(dirname "$state_file")"

    cat > "$state_file" << EOF
# Fortress Interface Mapping
# Generated: $(date -Iseconds)
# Device: $DEVICE_ID

FORTRESS_WAN_IFACE="$FORTRESS_WAN_IFACE"
FORTRESS_LAN_IFACES="$FORTRESS_LAN_IFACES"
FORTRESS_WIFI_IFACE="$FORTRESS_WIFI_IFACE"
FORTRESS_LTE_IFACE="$FORTRESS_LTE_IFACE"
FORTRESS_ALL_ETH="$FORTRESS_ALL_ETH"
FORTRESS_XDP_MODE="${FORTRESS_XDP_MODE:-generic}"
EOF

    log_success "Interface mapping saved to $state_file"
}

load_interface_mapping() {
    # Load saved interface mapping
    local state_file="/var/lib/fortress/interface-mapping.conf"

    if [ -f "$state_file" ]; then
        source "$state_file"
        return 0
    fi
    return 1
}

# ============================================================
# MAIN
# ============================================================

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    detect_intel_n100_interfaces
    setup_intel_xdp
    save_interface_mapping
fi
