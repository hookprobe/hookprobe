#!/bin/bash
#
# wifi-band-allocator.sh - Runtime WiFi Band Detection and Interface Allocation
# Part of HookProbe Fortress - Small Business Security Gateway
#
# This script runs BEFORE hostapd to:
#   1. Wait for WiFi interfaces to be ready
#   2. Query each interface's PHY for band support
#   3. Allocate interfaces to bands (2.4GHz, 5GHz)
#   4. Update hostapd config files with correct interface names
#
# This solves the udev timing problem where we can't query frequencies
# during device enumeration.
#
# Usage:
#   ./wifi-band-allocator.sh allocate    # Detect bands and update hostapd configs
#   ./wifi-band-allocator.sh status      # Show current allocation
#   ./wifi-band-allocator.sh wait        # Wait for interfaces then allocate
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
STATE_DIR="/var/lib/fortress"
ALLOCATION_FILE="$STATE_DIR/wifi-band-allocation.conf"
HOSTAPD_DIR="/etc/hostapd"
HOSTAPD_24GHZ_CONF="$HOSTAPD_DIR/hostapd-24ghz.conf"
HOSTAPD_5GHZ_CONF="$HOSTAPD_DIR/hostapd-5ghz.conf"

# Interface wait settings
MAX_WAIT_SECONDS=30
POLL_INTERVAL=0.5

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[WIFI-ALLOC]${NC} $*"; }
log_success() { echo -e "${GREEN}[WIFI-ALLOC]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WIFI-ALLOC]${NC} $*"; }
log_error() { echo -e "${RED}[WIFI-ALLOC]${NC} $*"; }

# ============================================================
# INTERFACE DISCOVERY
# ============================================================

get_wifi_interfaces() {
    # Get list of WiFi interfaces from /sys/class/net
    local interfaces=()

    for iface_path in /sys/class/net/*; do
        [ -d "$iface_path" ] || continue
        local iface=$(basename "$iface_path")

        # Check if it's a WiFi interface
        if [ -d "$iface_path/wireless" ] || [ -L "$iface_path/phy80211" ]; then
            interfaces+=("$iface")
        fi
    done

    echo "${interfaces[@]}"
}

get_interface_phy() {
    # Get PHY name for interface
    local iface="$1"
    local phy_link="/sys/class/net/$iface/phy80211"

    if [ -L "$phy_link" ]; then
        basename "$(readlink -f "$phy_link")"
    fi
}

get_interface_mac() {
    local iface="$1"
    cat "/sys/class/net/$iface/address" 2>/dev/null | tr '[:lower:]' '[:upper:]'
}

# ============================================================
# BAND DETECTION
# ============================================================

detect_phy_bands() {
    # Detect which bands a PHY supports
    # Returns: "24ghz" "5ghz" "24ghz 5ghz" or empty
    local phy="$1"
    local bands=""

    # Get PHY info - use specific phy query, not global
    local phy_info
    phy_info=$(iw phy "$phy" info 2>/dev/null) || return 1

    # Check for 2.4GHz frequencies (2412-2484 MHz)
    if echo "$phy_info" | grep -qE "24[0-9][0-9] MHz"; then
        bands="24ghz"
    fi

    # Check for 5GHz frequencies (5180-5825 MHz)
    if echo "$phy_info" | grep -qE "5[0-9][0-9][0-9] MHz"; then
        bands="$bands${bands:+ }5ghz"
    fi

    # Check for 6GHz frequencies (5925-7125 MHz) - future use
    if echo "$phy_info" | grep -qE "(59[2-9][0-9]|6[0-9][0-9][0-9]|7[0-1][0-9][0-9]) MHz"; then
        bands="$bands${bands:+ }6ghz"
    fi

    echo "$bands"
}

detect_interface_bands() {
    # Detect bands for a specific interface
    local iface="$1"
    local phy

    phy=$(get_interface_phy "$iface")
    if [ -z "$phy" ]; then
        log_warn "Cannot determine PHY for $iface"
        return 1
    fi

    detect_phy_bands "$phy"
}

# ============================================================
# INTERFACE WAITING
# ============================================================

wait_for_wifi_interfaces() {
    # Wait for at least one WiFi interface to appear
    local waited=0

    log_info "Waiting for WiFi interfaces (max ${MAX_WAIT_SECONDS}s)..."

    while [ $waited -lt $MAX_WAIT_SECONDS ]; do
        local interfaces
        interfaces=$(get_wifi_interfaces)

        if [ -n "$interfaces" ]; then
            log_success "Found WiFi interfaces: $interfaces"
            return 0
        fi

        sleep $POLL_INTERVAL
        waited=$(echo "$waited + $POLL_INTERVAL" | bc)
    done

    log_error "No WiFi interfaces found after ${MAX_WAIT_SECONDS}s"
    return 1
}

wait_for_interface_ready() {
    # Wait for interface to be queryable (PHY info available)
    local iface="$1"
    local waited=0
    local max_wait=10

    while [ $waited -lt $max_wait ]; do
        local phy
        phy=$(get_interface_phy "$iface")

        if [ -n "$phy" ]; then
            # Try to query PHY info
            if iw phy "$phy" info &>/dev/null; then
                return 0
            fi
        fi

        sleep 0.5
        waited=$((waited + 1))
    done

    return 1
}

# ============================================================
# BAND ALLOCATION
# ============================================================

allocate_interfaces_to_bands() {
    # Allocate WiFi interfaces to bands
    # Strategy:
    #   1. Prefer dedicated single-band radios for each band
    #   2. Fall back to dual-band radio if only one available
    #   3. Never assign same physical radio to both bands

    log_info "Allocating WiFi interfaces to bands..."

    mkdir -p "$STATE_DIR"

    local interfaces
    interfaces=$(get_wifi_interfaces)

    if [ -z "$interfaces" ]; then
        log_error "No WiFi interfaces available"
        return 1
    fi

    # Arrays to track candidates
    local -a only_24ghz=()
    local -a only_5ghz=()
    local -a dual_band=()
    local -A iface_bands
    local -A iface_phy
    local -A iface_mac

    # Analyze each interface
    for iface in $interfaces; do
        log_info "Analyzing $iface..."

        # Wait for interface to be ready
        if ! wait_for_interface_ready "$iface"; then
            log_warn "  Interface $iface not ready, skipping"
            continue
        fi

        local phy mac bands
        phy=$(get_interface_phy "$iface")
        mac=$(get_interface_mac "$iface")
        bands=$(detect_interface_bands "$iface")

        log_info "  PHY: $phy, MAC: $mac, Bands: ${bands:-none}"

        iface_phy["$iface"]="$phy"
        iface_mac["$iface"]="$mac"
        iface_bands["$iface"]="$bands"

        case "$bands" in
            "24ghz")
                only_24ghz+=("$iface")
                ;;
            "5ghz")
                only_5ghz+=("$iface")
                ;;
            "24ghz 5ghz"|"24ghz 5ghz 6ghz")
                dual_band+=("$iface")
                ;;
            *)
                log_warn "  Unknown band configuration: $bands"
                ;;
        esac
    done

    # Allocate based on what we found
    local alloc_24ghz=""
    local alloc_5ghz=""

    # Strategy 1: Use dedicated single-band radios if available
    if [ ${#only_24ghz[@]} -gt 0 ]; then
        alloc_24ghz="${only_24ghz[0]}"
        log_info "Allocated ${alloc_24ghz} for 2.4GHz (dedicated single-band)"
    fi

    if [ ${#only_5ghz[@]} -gt 0 ]; then
        alloc_5ghz="${only_5ghz[0]}"
        log_info "Allocated ${alloc_5ghz} for 5GHz (dedicated single-band)"
    fi

    # Strategy 2: Fill gaps with dual-band radios
    if [ -z "$alloc_24ghz" ] && [ ${#dual_band[@]} -gt 0 ]; then
        alloc_24ghz="${dual_band[0]}"
        log_info "Allocated ${alloc_24ghz} for 2.4GHz (dual-band radio)"
    fi

    if [ -z "$alloc_5ghz" ]; then
        # Find a dual-band radio not already used for 2.4GHz
        for iface in "${dual_band[@]}"; do
            if [ "$iface" != "$alloc_24ghz" ]; then
                alloc_5ghz="$iface"
                log_info "Allocated ${alloc_5ghz} for 5GHz (dual-band radio)"
                break
            fi
        done

        # If no separate radio available, use same dual-band radio
        if [ -z "$alloc_5ghz" ] && [ -n "$alloc_24ghz" ]; then
            # Check if the 2.4GHz interface also supports 5GHz
            if [[ "${iface_bands[$alloc_24ghz]}" == *"5ghz"* ]]; then
                alloc_5ghz="$alloc_24ghz"
                log_warn "Using same dual-band radio for both bands (${alloc_5ghz})"
                log_warn "  Only one band can be active at a time with single radio"
            fi
        fi
    fi

    # Save allocation
    cat > "$ALLOCATION_FILE" << EOF
# WiFi Band Allocation
# Generated: $(date -Iseconds)
# This file is auto-generated by wifi-band-allocator.sh
# Do not edit manually - changes will be overwritten

WIFI_24GHZ_IFACE="${alloc_24ghz}"
WIFI_24GHZ_PHY="${iface_phy[$alloc_24ghz]:-}"
WIFI_24GHZ_MAC="${iface_mac[$alloc_24ghz]:-}"

WIFI_5GHZ_IFACE="${alloc_5ghz}"
WIFI_5GHZ_PHY="${iface_phy[$alloc_5ghz]:-}"
WIFI_5GHZ_MAC="${iface_mac[$alloc_5ghz]:-}"

# Is same radio used for both bands?
WIFI_SINGLE_RADIO=$([ "$alloc_24ghz" = "$alloc_5ghz" ] && echo "true" || echo "false")

# All detected interfaces
WIFI_ALL_INTERFACES="$interfaces"
EOF

    chmod 644 "$ALLOCATION_FILE"

    log_success "Band allocation saved to $ALLOCATION_FILE"

    # Export for use by other scripts
    export WIFI_24GHZ_IFACE="$alloc_24ghz"
    export WIFI_5GHZ_IFACE="$alloc_5ghz"

    return 0
}

# ============================================================
# HOSTAPD CONFIG UPDATE
# ============================================================

update_hostapd_configs() {
    # Update hostapd config files with allocated interfaces

    if [ ! -f "$ALLOCATION_FILE" ]; then
        log_error "No allocation file found. Run 'allocate' first."
        return 1
    fi

    source "$ALLOCATION_FILE"

    log_info "Updating hostapd configurations..."

    # Update 2.4GHz config
    if [ -n "$WIFI_24GHZ_IFACE" ] && [ -f "$HOSTAPD_24GHZ_CONF" ]; then
        local current_iface
        current_iface=$(grep "^interface=" "$HOSTAPD_24GHZ_CONF" | cut -d= -f2)

        if [ "$current_iface" != "$WIFI_24GHZ_IFACE" ]; then
            log_info "Updating 2.4GHz config: $current_iface -> $WIFI_24GHZ_IFACE"
            sed -i "s/^interface=.*/interface=${WIFI_24GHZ_IFACE}/" "$HOSTAPD_24GHZ_CONF"
        else
            log_info "2.4GHz config already correct: $WIFI_24GHZ_IFACE"
        fi
    elif [ -z "$WIFI_24GHZ_IFACE" ]; then
        log_warn "No interface allocated for 2.4GHz"
    fi

    # Update 5GHz config
    if [ -n "$WIFI_5GHZ_IFACE" ] && [ -f "$HOSTAPD_5GHZ_CONF" ]; then
        local current_iface
        current_iface=$(grep "^interface=" "$HOSTAPD_5GHZ_CONF" | cut -d= -f2)

        if [ "$current_iface" != "$WIFI_5GHZ_IFACE" ]; then
            log_info "Updating 5GHz config: $current_iface -> $WIFI_5GHZ_IFACE"
            sed -i "s/^interface=.*/interface=${WIFI_5GHZ_IFACE}/" "$HOSTAPD_5GHZ_CONF"
        else
            log_info "5GHz config already correct: $WIFI_5GHZ_IFACE"
        fi
    elif [ -z "$WIFI_5GHZ_IFACE" ]; then
        log_warn "No interface allocated for 5GHz"
    fi

    # Update systemd service dependencies if interfaces changed
    update_systemd_dependencies

    log_success "Hostapd configurations updated"
}

update_systemd_dependencies() {
    # Update systemd service files with correct interface device dependencies

    if [ ! -f "$ALLOCATION_FILE" ]; then
        return 0
    fi

    source "$ALLOCATION_FILE"

    local need_reload=false

    # Update 2.4GHz service
    local service_24ghz="/etc/systemd/system/fortress-hostapd-24ghz.service"
    if [ -f "$service_24ghz" ] && [ -n "$WIFI_24GHZ_IFACE" ]; then
        local dev_unit="sys-subsystem-net-devices-${WIFI_24GHZ_IFACE}.device"

        if ! grep -q "$dev_unit" "$service_24ghz" 2>/dev/null; then
            log_info "Updating 2.4GHz service dependencies"
            sed -i "s/sys-subsystem-net-devices-[^.]*\.device/$dev_unit/g" "$service_24ghz"
            # Also update ExecStartPre interface references
            sed -i "s|ip link set [^ ]* |ip link set ${WIFI_24GHZ_IFACE} |g" "$service_24ghz"
            need_reload=true
        fi
    fi

    # Update 5GHz service
    local service_5ghz="/etc/systemd/system/fortress-hostapd-5ghz.service"
    if [ -f "$service_5ghz" ] && [ -n "$WIFI_5GHZ_IFACE" ]; then
        local dev_unit="sys-subsystem-net-devices-${WIFI_5GHZ_IFACE}.device"

        if ! grep -q "$dev_unit" "$service_5ghz" 2>/dev/null; then
            log_info "Updating 5GHz service dependencies"
            sed -i "s/sys-subsystem-net-devices-[^.]*\.device/$dev_unit/g" "$service_5ghz"
            sed -i "s|ip link set [^ ]* |ip link set ${WIFI_5GHZ_IFACE} |g" "$service_5ghz"
            need_reload=true
        fi
    fi

    if [ "$need_reload" = true ]; then
        systemctl daemon-reload 2>/dev/null || true
        log_info "Systemd daemon reloaded"
    fi
}

# ============================================================
# STATUS DISPLAY
# ============================================================

show_status() {
    echo ""
    echo "WiFi Band Allocation Status"
    echo "============================"

    if [ -f "$ALLOCATION_FILE" ]; then
        source "$ALLOCATION_FILE"

        echo ""
        echo "2.4GHz Band:"
        if [ -n "$WIFI_24GHZ_IFACE" ]; then
            echo "  Interface: $WIFI_24GHZ_IFACE"
            echo "  PHY:       ${WIFI_24GHZ_PHY:-unknown}"
            echo "  MAC:       ${WIFI_24GHZ_MAC:-unknown}"
        else
            echo "  Not allocated"
        fi

        echo ""
        echo "5GHz Band:"
        if [ -n "$WIFI_5GHZ_IFACE" ]; then
            echo "  Interface: $WIFI_5GHZ_IFACE"
            echo "  PHY:       ${WIFI_5GHZ_PHY:-unknown}"
            echo "  MAC:       ${WIFI_5GHZ_MAC:-unknown}"
        else
            echo "  Not allocated"
        fi

        echo ""
        if [ "$WIFI_SINGLE_RADIO" = "true" ]; then
            echo "Note: Single dual-band radio - only one band active at a time"
        fi

        echo ""
        echo "All interfaces: $WIFI_ALL_INTERFACES"
    else
        echo ""
        echo "No allocation file found."
        echo "Run: $0 allocate"
    fi

    echo ""
    echo "Hostapd Configs:"
    if [ -f "$HOSTAPD_24GHZ_CONF" ]; then
        local iface=$(grep "^interface=" "$HOSTAPD_24GHZ_CONF" | cut -d= -f2)
        echo "  2.4GHz: $HOSTAPD_24GHZ_CONF (interface=$iface)"
    else
        echo "  2.4GHz: not configured"
    fi

    if [ -f "$HOSTAPD_5GHZ_CONF" ]; then
        local iface=$(grep "^interface=" "$HOSTAPD_5GHZ_CONF" | cut -d= -f2)
        echo "  5GHz:   $HOSTAPD_5GHZ_CONF (interface=$iface)"
    else
        echo "  5GHz:   not configured"
    fi
    echo ""
}

# ============================================================
# MAIN
# ============================================================

main() {
    case "${1:-}" in
        allocate)
            allocate_interfaces_to_bands
            update_hostapd_configs
            ;;
        update)
            update_hostapd_configs
            ;;
        wait)
            wait_for_wifi_interfaces
            allocate_interfaces_to_bands
            update_hostapd_configs
            ;;
        status)
            show_status
            ;;
        -h|--help|help)
            echo "Usage: $0 <command>"
            echo ""
            echo "Commands:"
            echo "  allocate  - Detect bands and allocate interfaces"
            echo "  update    - Update hostapd configs from existing allocation"
            echo "  wait      - Wait for interfaces, then allocate"
            echo "  status    - Show current allocation status"
            echo ""
            echo "Run 'wait' at boot to ensure interfaces are ready before allocation."
            ;;
        *)
            echo "Usage: $0 {allocate|update|wait|status|help}"
            exit 1
            ;;
    esac
}

main "$@"
