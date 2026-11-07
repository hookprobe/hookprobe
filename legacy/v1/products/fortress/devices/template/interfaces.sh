#!/bin/bash
# ============================================================
# Interface Detection Template for HookProbe Fortress
# ============================================================
#
# INSTRUCTIONS:
# 1. Copy this file to your device folder
# 2. Implement the detection functions for your hardware
# 3. Test with: ./interfaces.sh
# 4. Generate config: ./interfaces.sh --generate
#
# Key functions to implement:
#   - detect_<device>_interfaces(): Main detection logic
#   - generate_netplan_config(): Network configuration
#   - configure_xdp_mode(): XDP mode per interface
#
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source profile configuration
# shellcheck source=profile.conf
source "${SCRIPT_DIR}/profile.conf"

# ============================================================
# Interface Detection Functions
# ============================================================

# Detect onboard Ethernet interfaces
# Returns: interface names, one per line
detect_onboard_nics() {
    local nics=()

    # TODO: Implement detection for your device
    #
    # Common methods:
    #
    # 1. By driver name:
    #    for iface in /sys/class/net/*; do
    #        driver=$(readlink -f "$iface/device/driver" | xargs basename)
    #        if [ "$driver" = "your_driver" ]; then
    #            nics+=("$(basename "$iface")")
    #        fi
    #    done
    #
    # 2. By PCI vendor/device ID:
    #    for iface in /sys/class/net/*; do
    #        vendor=$(cat "$iface/device/vendor" 2>/dev/null)
    #        device=$(cat "$iface/device/device" 2>/dev/null)
    #        if [ "$vendor" = "0x8086" ]; then  # Intel
    #            nics+=("$(basename "$iface")")
    #        fi
    #    done
    #
    # 3. By device tree (ARM):
    #    if [ -d "/sys/class/net/eth0" ]; then
    #        nics+=("eth0")
    #    fi

    printf '%s\n' "${nics[@]}"
}

# Detect PCIe NICs (expansion cards, M.2, etc.)
detect_pcie_nics() {
    local pcie_nics=()

    for iface in /sys/class/net/*; do
        [ -d "$iface" ] || continue
        local name
        name=$(basename "$iface")
        [ "$name" = "lo" ] && continue

        local device_path
        device_path=$(readlink -f "$iface/device" 2>/dev/null || true)

        if [[ "$device_path" == *"/pci"* ]]; then
            local pci_addr
            pci_addr=$(basename "$device_path")
            pcie_nics+=("$pci_addr:$name")
        fi
    done

    # Sort by PCI address for consistent ordering
    printf '%s\n' "${pcie_nics[@]}" | sort
}

# Detect USB NICs
detect_usb_nics() {
    local usb_nics=()

    for iface in /sys/class/net/*; do
        [ -d "$iface" ] || continue
        local name
        name=$(basename "$iface")
        [ "$name" = "lo" ] && continue

        local device_path
        device_path=$(readlink -f "$iface/device" 2>/dev/null || true)

        if [[ "$device_path" == *"/usb"* ]]; then
            usb_nics+=("$name")
        fi
    done

    printf '%s\n' "${usb_nics[@]}"
}

# ============================================================
# Main Interface Detection
# ============================================================

detect_device_interfaces() {
    local wan_iface=""
    local lan_ifaces=""
    local all_ifaces=()

    echo "Detecting network interfaces for ${DEVICE_ID}..."

    # Collect all interfaces
    while IFS= read -r iface; do
        [ -n "$iface" ] && all_ifaces+=("$iface")
    done < <(detect_onboard_nics)

    while IFS=: read -r _ iface; do
        [ -n "$iface" ] && all_ifaces+=("$iface")
    done < <(detect_pcie_nics)

    while IFS= read -r iface; do
        [ -n "$iface" ] && all_ifaces+=("$iface")
    done < <(detect_usb_nics)

    # Display detected interfaces
    for iface in "${all_ifaces[@]}"; do
        local driver speed
        driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "unknown")
        speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "?")
        echo "  Found: $iface (driver: $driver, speed: ${speed}Mbps)"
    done

    export FORTRESS_TOTAL_NICS="${#all_ifaces[@]}"
    echo "  Total NICs: ${FORTRESS_TOTAL_NICS}"

    # TODO: Implement your WAN/LAN assignment logic
    #
    # Common strategies:
    #
    # 1. First interface = WAN, rest = LAN
    #    wan_iface="${all_ifaces[0]:-}"
    #    lan_ifaces="${all_ifaces[*]:1}"
    #
    # 2. Fastest interface = WAN
    #    (sort by speed and pick fastest for WAN)
    #
    # 3. By port label (if known)
    #    (some devices have WAN/LAN labels on ports)
    #
    # 4. By MAC address prefix
    #    (manufacturer-specific assignment)

    # Default: first interface = WAN, rest = LAN
    if [ ${#all_ifaces[@]} -gt 0 ]; then
        wan_iface="${all_ifaces[0]}"
        if [ ${#all_ifaces[@]} -gt 1 ]; then
            lan_ifaces="${all_ifaces[*]:1}"
        fi
    fi

    export FORTRESS_WAN_IFACE="$wan_iface"
    export FORTRESS_LAN_IFACES="$lan_ifaces"

    echo ""
    echo "Interface assignment:"
    echo "  WAN: ${wan_iface:-none}"
    echo "  LAN: ${lan_ifaces:-none}"
}

# ============================================================
# Network Configuration Generation
# ============================================================

generate_netplan_config() {
    local wan_iface="${FORTRESS_WAN_IFACE:-eth0}"
    local lan_ifaces="${FORTRESS_LAN_IFACES:-eth1}"
    local output_file="${1:-/etc/netplan/60-fortress.yaml}"

    cat > "$output_file" << EOF
# Fortress Network Configuration for ${DEVICE_ID}
# Generated: $(date -Iseconds)
#
# WAN: $wan_iface
# LAN: $lan_ifaces
#
network:
  version: 2
  renderer: networkd

  ethernets:
    # WAN Interface - DHCP from upstream
    $wan_iface:
      dhcp4: true
      dhcp6: false
      optional: true
EOF

    # Add LAN interfaces
    for iface in $lan_ifaces; do
        cat >> "$output_file" << EOF

    # LAN Interface
    $iface:
      dhcp4: false
      dhcp6: false
      optional: true
EOF
    done

    # Add bridge configuration if we have LAN interfaces
    if [ -n "$lan_ifaces" ]; then
        cat >> "$output_file" << EOF

  bridges:
    fortress:
      interfaces:
EOF
        for iface in $lan_ifaces; do
            echo "        - $iface" >> "$output_file"
        done

        cat >> "$output_file" << EOF
      addresses:
        - 10.250.0.1/24
      dhcp4: false
      parameters:
        stp: false
        forward-delay: 0
EOF
    fi

    echo "Generated netplan config: $output_file"
}

# ============================================================
# XDP Mode Configuration
# ============================================================

configure_xdp_mode() {
    local iface="$1"

    if [ -z "$iface" ]; then
        echo "ERROR: No interface specified for XDP configuration"
        return 1
    fi

    local driver
    driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

    # TODO: Add your driver-specific XDP mode detection
    #
    # Drivers with XDP native support:
    #   - Intel: i40e, ixgbe, igc, ice
    #   - Mellanox: mlx5_core, mlx4_en
    #   - Broadcom: bnxt_en
    #   - Amazon: ena
    #   - Realtek: r8125 (partial)
    #
    # Most other drivers: generic mode

    local xdp_mode="generic"

    case "$driver" in
        "i40e"|"ixgbe"|"igc"|"ice")
            xdp_mode="native"
            ;;
        "mlx5_core"|"mlx4_en")
            xdp_mode="native"
            ;;
        "bnxt_en")
            xdp_mode="native"
            ;;
        "ena")
            xdp_mode="native"
            ;;
        *)
            xdp_mode="generic"
            ;;
    esac

    export "FORTRESS_XDP_MODE_${iface//-/_}=$xdp_mode"
    echo "XDP mode for $iface ($driver): $xdp_mode"
}

# ============================================================
# WiFi Detection (if applicable)
# ============================================================

detect_wifi_interfaces() {
    local wifi_ifaces=""

    for iface in /sys/class/net/wlan*; do
        [ -d "$iface" ] || continue
        local name
        name=$(basename "$iface")

        local driver
        driver=$(readlink -f "$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

        echo "  WiFi: $name (driver: $driver)"
        wifi_ifaces="${wifi_ifaces:+$wifi_ifaces }$name"
    done

    export FORTRESS_WIFI_IFACES="$wifi_ifaces"
}

# ============================================================
# Main Entry Point
# ============================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "====================================="
    echo "${DEVICE_ID} Interface Detection"
    echo "====================================="

    detect_device_interfaces
    detect_wifi_interfaces

    # Configure XDP for each interface
    [ -n "$FORTRESS_WAN_IFACE" ] && configure_xdp_mode "$FORTRESS_WAN_IFACE"
    for iface in $FORTRESS_LAN_IFACES; do
        configure_xdp_mode "$iface"
    done

    echo ""
    echo "====================================="
    echo "Summary"
    echo "====================================="
    echo "Device: ${DEVICE_ID}"
    echo "Family: ${DEVICE_FAMILY}"
    echo "Architecture: ${ARCHITECTURE}"
    echo "Total NICs: ${FORTRESS_TOTAL_NICS:-0}"
    echo "WAN Interface: ${FORTRESS_WAN_IFACE:-not detected}"
    echo "LAN Interfaces: ${FORTRESS_LAN_IFACES:-not detected}"
    echo "WiFi Interfaces: ${FORTRESS_WIFI_IFACES:-none}"

    # Generate config if requested
    if [ "${1:-}" = "--generate" ]; then
        echo ""
        echo "Generating netplan configuration..."
        generate_netplan_config "${2:-/tmp/fortress-${DEVICE_ID}.yaml}"
    fi
fi
