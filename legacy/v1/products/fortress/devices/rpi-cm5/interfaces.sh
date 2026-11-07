#!/bin/bash
# ============================================================
# Raspberry Pi Compute Module 5 Interface Detection
# ============================================================
#
# Detects and configures network interfaces on CM5 and
# compatible carrier boards.
#
# Interface Naming on CM5:
#   - Default: eth0, eth1 (device tree naming)
#   - With predictable naming: end0, enx<MAC>
#   - PCIe NIC: enp1s0, enp1s0np0
#   - USB NIC: enx<MAC>
#
# Carrier Board Variations:
#   - Official IO Board: 1x GbE (eth0), USB for additional
#   - Waveshare CM5 IO: 1-2x GbE
#   - Custom carriers: Up to 4x GbE via PCIe switch
#
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source profile configuration
# shellcheck source=profile.conf
source "${SCRIPT_DIR}/profile.conf"

# ============================================================
# CM5 Interface Detection Functions
# ============================================================

# Get the onboard NIC (BCM54213PE on IO board)
get_onboard_nic() {
    local iface

    # Check for eth0 (device tree naming)
    if [ -d "/sys/class/net/eth0" ]; then
        # Verify it's not a USB NIC
        local path
        path=$(readlink -f /sys/class/net/eth0/device 2>/dev/null || true)
        if [[ "$path" != *"/usb"* ]]; then
            echo "eth0"
            return 0
        fi
    fi

    # Check for end0 (predictable naming)
    if [ -d "/sys/class/net/end0" ]; then
        echo "end0"
        return 0
    fi

    # Check for platform device (BCM GENET)
    for iface in /sys/class/net/*; do
        iface=$(basename "$iface")
        [ "$iface" = "lo" ] && continue

        local driver
        driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)
        if [ "$driver" = "bcmgenet" ]; then
            echo "$iface"
            return 0
        fi
    done

    return 1
}

# Detect PCIe NICs (common on multi-port carrier boards)
detect_pcie_nics() {
    local pcie_nics=()
    local iface

    for iface in /sys/class/net/*; do
        iface=$(basename "$iface")
        [ "$iface" = "lo" ] && continue

        # Check if device is on PCIe bus
        local device_path
        device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null || true)

        if [[ "$device_path" == *"/pci"* ]]; then
            # Get PCI address for sorting
            local pci_addr
            pci_addr=$(basename "$device_path" 2>/dev/null || echo "")

            # Get driver info
            local driver
            driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

            # Get link speed capability
            local speed="1000"
            if [ -f "/sys/class/net/$iface/speed" ]; then
                speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "1000")
            fi

            pcie_nics+=("${pci_addr}:${iface}:${driver}:${speed}")
        fi
    done

    # Sort by PCI address
    printf '%s\n' "${pcie_nics[@]}" | sort
}

# Detect USB NICs (common for adding extra ports)
detect_usb_nics() {
    local usb_nics=()
    local iface

    for iface in /sys/class/net/*; do
        iface=$(basename "$iface")
        [ "$iface" = "lo" ] && continue

        local device_path
        device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null || true)

        if [[ "$device_path" == *"/usb"* ]]; then
            # Get USB bus and device numbers for consistent ordering
            local usb_path
            usb_path=$(echo "$device_path" | grep -oP 'usb\d+/\d+-[\d.]+' | head -1 || echo "")

            # Get MAC address for enx* naming verification
            local mac
            mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "")

            usb_nics+=("${usb_path}:${iface}:${mac}")
        fi
    done

    # Sort by USB path for consistent ordering
    printf '%s\n' "${usb_nics[@]}" | sort
}

# Get carrier board type from device tree
get_carrier_board() {
    local carrier="unknown"

    # Check for carrier board compatible string
    if [ -f "/proc/device-tree/compatible" ]; then
        local compat
        compat=$(tr '\0' '\n' < /proc/device-tree/compatible | head -5)

        if echo "$compat" | grep -qi "waveshare"; then
            carrier="waveshare"
        elif echo "$compat" | grep -qi "compute-module"; then
            carrier="official-io"
        elif echo "$compat" | grep -qi "turingpi"; then
            carrier="turingpi"
        fi
    fi

    # Check for known GPIO expanders or I2C devices
    if [ -d "/sys/bus/i2c/devices" ]; then
        # Waveshare boards often have specific I2C devices
        if ls /sys/bus/i2c/devices/ | grep -q "1-0020"; then
            carrier="waveshare"
        fi
    fi

    echo "$carrier"
}

# ============================================================
# Main Interface Detection
# ============================================================

detect_cm5_interfaces() {
    local onboard_nic=""
    local pcie_nics=()
    local usb_nics=()
    local wan_iface=""
    local lan_ifaces=""

    echo "Detecting CM5 network interfaces..."

    # Get carrier board type
    local carrier
    carrier=$(get_carrier_board)
    export FORTRESS_CARRIER_BOARD="$carrier"
    echo "  Carrier board: $carrier"

    # Detect onboard NIC
    onboard_nic=$(get_onboard_nic) || true
    if [ -n "$onboard_nic" ]; then
        echo "  Onboard NIC: $onboard_nic"
    fi

    # Detect PCIe NICs
    while IFS=: read -r pci_addr iface driver speed; do
        [ -z "$iface" ] && continue
        pcie_nics+=("$iface")
        echo "  PCIe NIC: $iface (driver: $driver, speed: ${speed}Mbps)"
    done < <(detect_pcie_nics)

    # Detect USB NICs
    while IFS=: read -r usb_path iface mac; do
        [ -z "$iface" ] && continue
        usb_nics+=("$iface")
        echo "  USB NIC: $iface (MAC: $mac)"
    done < <(detect_usb_nics)

    # Build interface list
    local all_ifaces=()
    [ -n "$onboard_nic" ] && all_ifaces+=("$onboard_nic")
    all_ifaces+=("${pcie_nics[@]}")
    all_ifaces+=("${usb_nics[@]}")

    local total=${#all_ifaces[@]}
    export FORTRESS_TOTAL_NICS="$total"
    echo "  Total NICs: $total"

    # Assign WAN and LAN interfaces
    # Strategy: First interface is WAN, rest are LAN
    # PCIe NICs take priority for WAN (better performance)

    if [ ${#pcie_nics[@]} -gt 0 ]; then
        # If we have PCIe NICs, use first one as WAN
        wan_iface="${pcie_nics[0]}"

        # Rest of PCIe + onboard + USB = LAN
        local lan_list=()
        for ((i=1; i<${#pcie_nics[@]}; i++)); do
            lan_list+=("${pcie_nics[$i]}")
        done
        [ -n "$onboard_nic" ] && lan_list+=("$onboard_nic")
        lan_list+=("${usb_nics[@]}")
        lan_ifaces=$(IFS=' '; echo "${lan_list[*]}")
    elif [ -n "$onboard_nic" ]; then
        # No PCIe, use onboard as WAN
        wan_iface="$onboard_nic"

        # USB NICs become LAN
        if [ ${#usb_nics[@]} -gt 0 ]; then
            lan_ifaces=$(IFS=' '; echo "${usb_nics[*]}")
        fi
    elif [ ${#usb_nics[@]} -gt 0 ]; then
        # Only USB NICs - first is WAN, rest are LAN
        wan_iface="${usb_nics[0]}"
        if [ ${#usb_nics[@]} -gt 1 ]; then
            local lan_list=()
            for ((i=1; i<${#usb_nics[@]}; i++)); do
                lan_list+=("${usb_nics[$i]}")
            done
            lan_ifaces=$(IFS=' '; echo "${lan_list[*]}")
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
# Fortress Network Configuration for Raspberry Pi CM5
# Generated: $(date -Iseconds)
# Carrier: ${FORTRESS_CARRIER_BOARD:-unknown}
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
# XDP Mode Configuration (CM5 specific)
# ============================================================

configure_xdp_mode() {
    local iface="$1"

    if [ -z "$iface" ]; then
        echo "ERROR: No interface specified for XDP configuration"
        return 1
    fi

    # CM5's BCM54213PE (via bcmgenet) doesn't support XDP native
    # PCIe NICs might support it depending on the chip

    local driver
    driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

    local xdp_mode="generic"

    case "$driver" in
        "bcmgenet")
            # Broadcom GENET - no XDP native support
            xdp_mode="generic"
            ;;
        "r8169"|"r8168"|"r8125")
            # Realtek - check for XDP support
            if ethtool -i "$iface" 2>/dev/null | grep -q "supports-xdp"; then
                xdp_mode="native"
            else
                xdp_mode="generic"
            fi
            ;;
        "igc"|"igb")
            # Intel - good XDP support
            xdp_mode="native"
            ;;
        "ixgbe"|"i40e")
            # Intel 10GbE/40GbE - excellent XDP support
            xdp_mode="native"
            ;;
        "mlx5_core")
            # Mellanox - excellent XDP support
            xdp_mode="native"
            ;;
        *)
            # Unknown - use generic
            xdp_mode="generic"
            ;;
    esac

    export "FORTRESS_XDP_MODE_${iface//-/_}=$xdp_mode"
    echo "XDP mode for $iface ($driver): $xdp_mode"
}

# ============================================================
# WiFi Interface Detection (CM5 has optional WiFi)
# ============================================================

detect_cm5_wifi() {
    local wifi_iface=""

    # Check for wlan0 (Broadcom WiFi on some CM5 variants)
    if [ -d "/sys/class/net/wlan0" ]; then
        local driver
        driver=$(readlink -f "/sys/class/net/wlan0/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

        if [ "$driver" = "brcmfmac" ]; then
            wifi_iface="wlan0"
            echo "  WiFi: wlan0 (Broadcom onboard)"
        fi
    fi

    # Check for USB WiFi adapters
    for iface in /sys/class/net/wlan*; do
        [ -d "$iface" ] || continue
        iface=$(basename "$iface")
        [ "$iface" = "wlan0" ] && continue  # Already handled

        local device_path
        device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null || true)

        if [[ "$device_path" == *"/usb"* ]]; then
            echo "  WiFi: $iface (USB adapter)"
            wifi_iface="${wifi_iface:+$wifi_iface }$iface"
        fi
    done

    export FORTRESS_WIFI_IFACES="$wifi_iface"
}

# ============================================================
# Main Entry Point
# ============================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "====================================="
    echo "CM5 Interface Detection"
    echo "====================================="

    detect_cm5_interfaces
    detect_cm5_wifi

    # Configure XDP for each interface
    [ -n "$FORTRESS_WAN_IFACE" ] && configure_xdp_mode "$FORTRESS_WAN_IFACE"
    for iface in $FORTRESS_LAN_IFACES; do
        configure_xdp_mode "$iface"
    done

    echo ""
    echo "====================================="
    echo "Summary"
    echo "====================================="
    echo "Device: Raspberry Pi CM5"
    echo "Carrier: ${FORTRESS_CARRIER_BOARD:-unknown}"
    echo "Total NICs: ${FORTRESS_TOTAL_NICS:-0}"
    echo "WAN Interface: ${FORTRESS_WAN_IFACE:-not detected}"
    echo "LAN Interfaces: ${FORTRESS_LAN_IFACES:-not detected}"
    echo "WiFi Interfaces: ${FORTRESS_WIFI_IFACES:-none}"

    # Generate config if requested
    if [ "${1:-}" = "--generate" ]; then
        echo ""
        echo "Generating netplan configuration..."
        generate_netplan_config "${2:-/tmp/fortress-cm5.yaml}"
    fi
fi
