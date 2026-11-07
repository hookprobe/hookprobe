#!/bin/bash
#
# detect-hardware.sh - Unified Hardware Detection Framework for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Detects hardware platform and selects appropriate device profile
# Targets: Intel N100/N150, Raspberry Pi CM5, Radxa Rock 5B, and similar
#
# Usage:
#   source detect-hardware.sh
#   detect_hardware
#   echo "Device: $FORTRESS_DEVICE_ID"
#
# Exports:
#   FORTRESS_DEVICE_ID      - Device identifier (e.g., "intel-n100", "rpi-cm5")
#   FORTRESS_DEVICE_NAME    - Human-readable name
#   FORTRESS_DEVICE_VENDOR  - Vendor name (Intel, Raspberry Pi, Radxa)
#   FORTRESS_CPU_MODEL      - CPU model string
#   FORTRESS_TOTAL_RAM_GB   - Total RAM in GB
#   FORTRESS_LAN_PORTS      - Number of LAN ports detected
#   FORTRESS_HAS_WIFI       - true/false for onboard WiFi
#   FORTRESS_HAS_LTE_SLOT   - true/false for mPCIe/M.2 LTE slot
#   FORTRESS_PROFILE_DIR    - Path to device profile directory
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVICES_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ============================================================
# DMI/SMBIOS DETECTION (Intel/x86 systems)
# ============================================================

get_dmi_info() {
    # Read DMI/SMBIOS information (requires root or readable sysfs)
    local field="$1"
    local path="/sys/class/dmi/id/$field"

    if [ -r "$path" ]; then
        cat "$path" 2>/dev/null | tr -d '\0' | xargs
    fi
}

detect_intel_cpu() {
    # Detect Intel CPU model from /proc/cpuinfo
    # Returns: CPU model name or empty string

    if [ -f /proc/cpuinfo ]; then
        grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d':' -f2 | xargs
    fi
}

is_intel_n100() {
    # Detect Intel N100 (Alder Lake-N)
    local cpu_model
    cpu_model=$(detect_intel_cpu)

    [[ "$cpu_model" == *"N100"* ]] && return 0

    # Check DMI for common N100 mini-PC vendors
    local product_name
    product_name=$(get_dmi_info "product_name")

    # Common N100 mini-PCs
    case "$product_name" in
        *"CWWK"*|*"Beelink"*|*"GMKtec"*|*"Trigkey"*|*"GEEKOM"*|*"MinisForum"*|*"SZBOX"*)
            if [[ "$cpu_model" == *"N100"* ]]; then
                return 0
            fi
            ;;
    esac

    return 1
}

is_intel_n150() {
    # Detect Intel N150 (Twin Lake)
    local cpu_model
    cpu_model=$(detect_intel_cpu)

    [[ "$cpu_model" == *"N150"* ]] && return 0
    return 1
}

is_intel_n200() {
    # Detect Intel N200 (Alder Lake-N)
    local cpu_model
    cpu_model=$(detect_intel_cpu)

    [[ "$cpu_model" == *"N200"* ]] && return 0
    return 1
}

is_intel_n305() {
    # Detect Intel N305 (Alder Lake-N, higher-end)
    local cpu_model
    cpu_model=$(detect_intel_cpu)

    [[ "$cpu_model" == *"N305"* ]] && return 0
    return 1
}

# ============================================================
# DEVICE TREE DETECTION (ARM/SBC systems)
# ============================================================

get_device_tree_model() {
    # Read device tree model (ARM devices)
    if [ -f /proc/device-tree/model ]; then
        tr -d '\0' < /proc/device-tree/model 2>/dev/null
    fi
}

get_device_tree_compatible() {
    # Read device tree compatible string
    if [ -f /proc/device-tree/compatible ]; then
        tr '\0' '\n' < /proc/device-tree/compatible 2>/dev/null | head -1
    fi
}

is_raspberry_pi_cm5() {
    # Detect Raspberry Pi Compute Module 5
    local model
    model=$(get_device_tree_model)

    [[ "$model" == *"Compute Module 5"* ]] && return 0
    [[ "$model" == *"CM5"* ]] && return 0

    # Check compatible string
    local compatible
    compatible=$(get_device_tree_compatible)
    [[ "$compatible" == *"bcm2712"* ]] && [[ "$model" == *"Compute"* ]] && return 0

    return 1
}

is_raspberry_pi_5() {
    # Detect Raspberry Pi 5 (non-CM version)
    local model
    model=$(get_device_tree_model)

    [[ "$model" == *"Raspberry Pi 5"* ]] && return 0
    return 1
}

is_radxa_rock5b() {
    # Detect Radxa Rock 5B
    local model
    model=$(get_device_tree_model)

    [[ "$model" == *"Radxa ROCK 5B"* ]] && return 0
    [[ "$model" == *"Rock 5B"* ]] && return 0

    # Check compatible string for RK3588
    local compatible
    compatible=$(get_device_tree_compatible)
    [[ "$compatible" == *"radxa,rock-5b"* ]] && return 0

    return 1
}

is_radxa_rock5a() {
    # Detect Radxa Rock 5A
    local model
    model=$(get_device_tree_model)

    [[ "$model" == *"Radxa ROCK 5A"* ]] && return 0
    [[ "$model" == *"Rock 5A"* ]] && return 0

    return 1
}

is_orange_pi_5() {
    # Detect Orange Pi 5
    local model
    model=$(get_device_tree_model)

    [[ "$model" == *"Orange Pi 5"* ]] && return 0
    return 1
}

# ============================================================
# NETWORK INTERFACE DETECTION
# ============================================================

count_ethernet_interfaces() {
    # Count physical Ethernet interfaces (excludes virtual, bridge, vlan)
    local count=0

    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")

        # Skip virtual interfaces
        [[ "$name" == lo ]] && continue
        [[ "$name" == br* ]] && continue
        [[ "$name" == veth* ]] && continue
        [[ "$name" == vlan* ]] && continue
        [[ "$name" == docker* ]] && continue
        [[ "$name" == podman* ]] && continue
        [[ "$name" == ovs-* ]] && continue
        [[ "$name" == vxlan* ]] && continue

        # Check if it's a physical device
        if [ -d "$iface/device" ]; then
            # Check if it's Ethernet (not wireless)
            if [ ! -d "$iface/wireless" ] && [ ! -d "$iface/phy80211" ]; then
                # Check if it's Ethernet type (not WWAN/LTE)
                local devtype
                devtype=$(cat "$iface/type" 2>/dev/null)
                if [ "$devtype" = "1" ]; then  # ARPHRD_ETHER = 1
                    count=$((count + 1))
                fi
            fi
        fi
    done

    echo "$count"
}

list_ethernet_interfaces() {
    # List physical Ethernet interface names
    local interfaces=""

    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")

        # Skip virtual interfaces
        [[ "$name" == lo ]] && continue
        [[ "$name" == br* ]] && continue
        [[ "$name" == veth* ]] && continue
        [[ "$name" == vlan* ]] && continue
        [[ "$name" == docker* ]] && continue
        [[ "$name" == podman* ]] && continue
        [[ "$name" == ovs-* ]] && continue

        # Check if it's a physical Ethernet device
        if [ -d "$iface/device" ] && [ ! -d "$iface/wireless" ]; then
            local devtype
            devtype=$(cat "$iface/type" 2>/dev/null)
            if [ "$devtype" = "1" ]; then
                interfaces="$interfaces $name"
            fi
        fi
    done

    echo "$interfaces" | xargs
}

has_onboard_wifi() {
    # Check for onboard WiFi adapter
    for iface in /sys/class/net/*; do
        if [ -d "$iface/wireless" ] || [ -d "$iface/phy80211" ]; then
            return 0
        fi
    done
    return 1
}

list_wifi_interfaces() {
    # List WiFi interface names
    local interfaces=""

    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")
        if [ -d "$iface/wireless" ] || [ -d "$iface/phy80211" ]; then
            interfaces="$interfaces $name"
        fi
    done

    echo "$interfaces" | xargs
}

# ============================================================
# MEMORY DETECTION
# ============================================================

get_total_ram_gb() {
    # Get total RAM in GB (rounded up)
    local ram_kb
    ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    echo $(( (ram_kb + 1048575) / 1048576 ))  # Round up to nearest GB
}

check_minimum_ram() {
    # Fortress requires minimum 16GB RAM
    local ram_gb
    ram_gb=$(get_total_ram_gb)

    if [ "$ram_gb" -lt 16 ]; then
        log_warn "Fortress recommends 16GB+ RAM (detected: ${ram_gb}GB)"
        return 1
    fi
    return 0
}

# ============================================================
# LTE/WWAN DETECTION
# ============================================================

detect_lte_modem() {
    # Detect LTE modems (USB or mPCIe)
    # Returns: modem info or empty

    local modems=""

    # Check for USB modems via lsusb
    if command -v lsusb &>/dev/null; then
        # Common LTE modem vendors
        # Quectel: 2c7c
        # Sierra Wireless: 1199
        # Huawei: 12d1
        # ZTE: 19d2
        # Fibocom: 2cb7
        # Telit: 1bc7

        local quectel=$(lsusb 2>/dev/null | grep -i "2c7c\|Quectel")
        local sierra=$(lsusb 2>/dev/null | grep -i "1199\|Sierra")
        local huawei=$(lsusb 2>/dev/null | grep -i "12d1.*Mobile\|12d1.*Modem")
        local fibocom=$(lsusb 2>/dev/null | grep -i "2cb7\|Fibocom")
        local telit=$(lsusb 2>/dev/null | grep -i "1bc7\|Telit")

        [ -n "$quectel" ] && modems="$modems quectel"
        [ -n "$sierra" ] && modems="$modems sierra"
        [ -n "$huawei" ] && modems="$modems huawei"
        [ -n "$fibocom" ] && modems="$modems fibocom"
        [ -n "$telit" ] && modems="$modems telit"
    fi

    # Check for WWAN interfaces
    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")
        # Common WWAN interface patterns
        if [[ "$name" == wwan* ]] || [[ "$name" == wwp* ]] || [[ "$name" == usb* ]]; then
            if [ -d "$iface/device" ]; then
                modems="$modems $name"
            fi
        fi
    done

    # Check ModemManager if available
    if command -v mmcli &>/dev/null; then
        local mm_modems
        mm_modems=$(mmcli -L 2>/dev/null | grep -c "Modem" || echo "0")
        if [ "$mm_modems" -gt 0 ]; then
            modems="$modems mm:$mm_modems"
        fi
    fi

    echo "$modems" | xargs
}

has_mpcie_slot() {
    # Heuristic check for mPCIe slot (common in mini-PCs)
    # This is device-specific and set by device profiles
    # Returns based on known device configurations

    # Intel N100/N150 mini-PCs often have mPCIe
    local product_name
    product_name=$(get_dmi_info "product_name")

    case "$product_name" in
        *"CWWK"*|*"Beelink"*|*"GMKtec"*|*"Trigkey"*|*"GEEKOM"*|*"MinisForum"*)
            return 0
            ;;
    esac

    # CM5 carrier boards may have mPCIe/M.2
    if is_raspberry_pi_cm5; then
        return 0  # Most CM5 carriers have expansion
    fi

    return 1
}

# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

detect_hardware() {
    # Main hardware detection - populates FORTRESS_* variables

    log_info "Detecting hardware platform..."

    # Initialize variables
    export FORTRESS_DEVICE_ID="unknown"
    export FORTRESS_DEVICE_NAME="Unknown Device"
    export FORTRESS_DEVICE_VENDOR="Unknown"
    export FORTRESS_CPU_MODEL=""
    export FORTRESS_TOTAL_RAM_GB=0
    export FORTRESS_LAN_PORTS=0
    export FORTRESS_HAS_WIFI=false
    export FORTRESS_HAS_LTE_SLOT=false
    export FORTRESS_LTE_MODEMS=""
    export FORTRESS_PROFILE_DIR=""
    export FORTRESS_ETH_INTERFACES=""
    export FORTRESS_WIFI_INTERFACES=""

    # Get basic info
    FORTRESS_CPU_MODEL=$(detect_intel_cpu)
    [ -z "$FORTRESS_CPU_MODEL" ] && FORTRESS_CPU_MODEL=$(get_device_tree_model)

    FORTRESS_TOTAL_RAM_GB=$(get_total_ram_gb)
    FORTRESS_LAN_PORTS=$(count_ethernet_interfaces)
    FORTRESS_ETH_INTERFACES=$(list_ethernet_interfaces)
    FORTRESS_WIFI_INTERFACES=$(list_wifi_interfaces)

    has_onboard_wifi && FORTRESS_HAS_WIFI=true
    has_mpcie_slot && FORTRESS_HAS_LTE_SLOT=true

    FORTRESS_LTE_MODEMS=$(detect_lte_modem)

    # Detect specific device
    if is_intel_n100; then
        FORTRESS_DEVICE_ID="intel-n100"
        FORTRESS_DEVICE_NAME="Intel N100 Mini-PC"
        FORTRESS_DEVICE_VENDOR="Intel"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/intel-n100"

    elif is_intel_n150; then
        FORTRESS_DEVICE_ID="intel-n150"
        FORTRESS_DEVICE_NAME="Intel N150 Mini-PC"
        FORTRESS_DEVICE_VENDOR="Intel"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/intel-n150"

    elif is_intel_n200; then
        FORTRESS_DEVICE_ID="intel-n200"
        FORTRESS_DEVICE_NAME="Intel N200 Mini-PC"
        FORTRESS_DEVICE_VENDOR="Intel"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/intel-n100"  # Use N100 profile

    elif is_intel_n305; then
        FORTRESS_DEVICE_ID="intel-n305"
        FORTRESS_DEVICE_NAME="Intel N305 Mini-PC"
        FORTRESS_DEVICE_VENDOR="Intel"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/intel-n100"  # Use N100 profile

    elif is_raspberry_pi_cm5; then
        FORTRESS_DEVICE_ID="rpi-cm5"
        FORTRESS_DEVICE_NAME="Raspberry Pi Compute Module 5"
        FORTRESS_DEVICE_VENDOR="Raspberry Pi"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/rpi-cm5"

    elif is_raspberry_pi_5; then
        FORTRESS_DEVICE_ID="rpi-5"
        FORTRESS_DEVICE_NAME="Raspberry Pi 5"
        FORTRESS_DEVICE_VENDOR="Raspberry Pi"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/rpi-cm5"  # Use CM5 profile

    elif is_radxa_rock5b; then
        FORTRESS_DEVICE_ID="radxa-rock5b"
        FORTRESS_DEVICE_NAME="Radxa Rock 5B"
        FORTRESS_DEVICE_VENDOR="Radxa"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/radxa-rock5b"

    elif is_radxa_rock5a; then
        FORTRESS_DEVICE_ID="radxa-rock5a"
        FORTRESS_DEVICE_NAME="Radxa Rock 5A"
        FORTRESS_DEVICE_VENDOR="Radxa"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/radxa-rock5b"  # Use Rock 5B profile

    elif is_orange_pi_5; then
        FORTRESS_DEVICE_ID="orange-pi-5"
        FORTRESS_DEVICE_NAME="Orange Pi 5"
        FORTRESS_DEVICE_VENDOR="Xunlong"
        FORTRESS_PROFILE_DIR="$DEVICES_DIR/radxa-rock5b"  # Similar RK3588

    else
        # Fallback: detect by architecture
        local arch=$(uname -m)
        case "$arch" in
            x86_64|amd64)
                FORTRESS_DEVICE_ID="generic-x86_64"
                FORTRESS_DEVICE_NAME="Generic x86_64 System"
                FORTRESS_DEVICE_VENDOR="Generic"
                FORTRESS_PROFILE_DIR="$DEVICES_DIR/intel-n100"  # Use Intel profile
                ;;
            aarch64|arm64)
                FORTRESS_DEVICE_ID="generic-arm64"
                FORTRESS_DEVICE_NAME="Generic ARM64 System"
                FORTRESS_DEVICE_VENDOR="Generic"
                FORTRESS_PROFILE_DIR="$DEVICES_DIR/rpi-cm5"  # Use ARM profile
                ;;
            *)
                FORTRESS_DEVICE_ID="unknown"
                FORTRESS_DEVICE_NAME="Unknown System"
                FORTRESS_DEVICE_VENDOR="Unknown"
                ;;
        esac
    fi

    # Export all variables
    export FORTRESS_DEVICE_ID FORTRESS_DEVICE_NAME FORTRESS_DEVICE_VENDOR
    export FORTRESS_CPU_MODEL FORTRESS_TOTAL_RAM_GB FORTRESS_LAN_PORTS
    export FORTRESS_HAS_WIFI FORTRESS_HAS_LTE_SLOT FORTRESS_LTE_MODEMS
    export FORTRESS_PROFILE_DIR FORTRESS_ETH_INTERFACES FORTRESS_WIFI_INTERFACES

    return 0
}

print_hardware_info() {
    # Pretty print detected hardware information

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Fortress - Hardware Detection${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Device:${NC}        $FORTRESS_DEVICE_NAME"
    echo -e "  ${GREEN}Device ID:${NC}     $FORTRESS_DEVICE_ID"
    echo -e "  ${GREEN}Vendor:${NC}        $FORTRESS_DEVICE_VENDOR"
    echo -e "  ${GREEN}CPU:${NC}           $FORTRESS_CPU_MODEL"
    echo -e "  ${GREEN}RAM:${NC}           ${FORTRESS_TOTAL_RAM_GB}GB"
    echo ""
    echo -e "  ${GREEN}Network:${NC}"
    echo -e "    LAN Ports:   $FORTRESS_LAN_PORTS ($FORTRESS_ETH_INTERFACES)"
    echo -e "    WiFi:        $([ "$FORTRESS_HAS_WIFI" = true ] && echo "Yes ($FORTRESS_WIFI_INTERFACES)" || echo "No")"
    echo -e "    LTE Slot:    $([ "$FORTRESS_HAS_LTE_SLOT" = true ] && echo "Yes" || echo "No")"
    [ -n "$FORTRESS_LTE_MODEMS" ] && echo -e "    LTE Modems:  $FORTRESS_LTE_MODEMS"
    echo ""
    echo -e "  ${GREEN}Profile:${NC}       $FORTRESS_PROFILE_DIR"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

validate_fortress_requirements() {
    # Validate that system meets Fortress requirements
    # Returns 0 if valid, 1 if not

    local errors=0

    echo ""
    log_info "Validating Fortress requirements..."

    # Check RAM (recommended 16GB+, minimum 8GB)
    if [ "$FORTRESS_TOTAL_RAM_GB" -lt 8 ]; then
        log_error "Insufficient RAM: ${FORTRESS_TOTAL_RAM_GB}GB (minimum 8GB, recommended 16GB+)"
        errors=$((errors + 1))
    elif [ "$FORTRESS_TOTAL_RAM_GB" -lt 16 ]; then
        log_warn "RAM: ${FORTRESS_TOTAL_RAM_GB}GB (recommended 16GB+ for full Fortress features)"
    else
        log_success "RAM: ${FORTRESS_TOTAL_RAM_GB}GB"
    fi

    # Check LAN ports (minimum 2 for WAN + LAN)
    if [ "$FORTRESS_LAN_PORTS" -lt 2 ]; then
        log_error "Insufficient LAN ports: $FORTRESS_LAN_PORTS (minimum 2 required)"
        errors=$((errors + 1))
    else
        log_success "LAN Ports: $FORTRESS_LAN_PORTS"
    fi

    # Check if device profile exists
    if [ -z "$FORTRESS_PROFILE_DIR" ] || [ ! -d "$FORTRESS_PROFILE_DIR" ]; then
        log_warn "No device profile found for: $FORTRESS_DEVICE_ID"
        log_warn "Using generic configuration"
    else
        log_success "Device Profile: $FORTRESS_DEVICE_ID"
    fi

    # Check for LTE modem if WAN failover desired
    if [ -z "$FORTRESS_LTE_MODEMS" ]; then
        log_info "No LTE modem detected (optional for WAN failover)"
    else
        log_success "LTE Modem: $FORTRESS_LTE_MODEMS"
    fi

    return $errors
}

# Run detection if executed directly
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    detect_hardware
    print_hardware_info
    validate_fortress_requirements
fi
