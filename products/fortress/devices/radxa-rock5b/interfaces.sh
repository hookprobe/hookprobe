#!/bin/bash
# ============================================================
# Radxa Rock 5B Interface Detection
# ============================================================
#
# Detects and configures network interfaces on Rock 5B.
#
# Interface Layout:
#   - eth0: Native 1GbE (gmac1, Rockchip GMAC)
#   - enp4s0: RTL8125B 2.5GbE (PCIe)
#
# The Rock 5B is unique in having BOTH interfaces built-in,
# making it an excellent dual-WAN or WAN+LAN router.
#
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source profile configuration
# shellcheck source=profile.conf
source "${SCRIPT_DIR}/profile.conf"

# ============================================================
# Rock 5B Interface Detection Functions
# ============================================================

# Detect the native 1GbE interface (gmac1)
detect_native_gbe() {
    local iface=""

    # Check for eth0 with Rockchip GMAC driver
    if [ -d "/sys/class/net/eth0" ]; then
        local driver
        driver=$(readlink -f "/sys/class/net/eth0/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

        if [ "$driver" = "rk_gmac-dwmac" ] || [ "$driver" = "dwmac-rk" ]; then
            iface="eth0"
        fi
    fi

    # Also check end0 (predictable naming)
    if [ -z "$iface" ] && [ -d "/sys/class/net/end0" ]; then
        local driver
        driver=$(readlink -f "/sys/class/net/end0/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

        if [ "$driver" = "rk_gmac-dwmac" ] || [ "$driver" = "dwmac-rk" ]; then
            iface="end0"
        fi
    fi

    echo "$iface"
}

# Detect the RTL8125B 2.5GbE interface (PCIe)
detect_rtl8125() {
    local iface=""

    # RTL8125B is typically on PCIe bus, named enp4s0 on Rock 5B
    for netif in /sys/class/net/enp*; do
        [ -d "$netif" ] || continue
        local name
        name=$(basename "$netif")

        local driver
        driver=$(readlink -f "$netif/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

        if [ "$driver" = "r8125" ] || [ "$driver" = "r8169" ]; then
            # Verify it's 2.5GbE capable
            local speed
            speed=$(ethtool "$name" 2>/dev/null | grep "Supported link modes" -A 5 | grep -c "2500" || echo "0")

            if [ "$speed" -gt 0 ]; then
                iface="$name"
                break
            fi
        fi
    done

    # Fallback: check for any RTL8125 by vendor ID
    if [ -z "$iface" ]; then
        for netif in /sys/class/net/*; do
            [ -d "$netif" ] || continue
            local name
            name=$(basename "$netif")
            [ "$name" = "lo" ] && continue

            local vendor
            vendor=$(cat "$netif/device/vendor" 2>/dev/null || echo "")

            # Realtek vendor ID: 0x10ec
            if [ "$vendor" = "0x10ec" ]; then
                local device
                device=$(cat "$netif/device/device" 2>/dev/null || echo "")

                # RTL8125B device ID: 0x8125
                if [ "$device" = "0x8125" ]; then
                    iface="$name"
                    break
                fi
            fi
        done
    fi

    echo "$iface"
}

# Get interface speed capability
get_interface_speed() {
    local iface="$1"

    if [ -z "$iface" ]; then
        echo "0"
        return
    fi

    # Try to get supported link modes
    local speed
    speed=$(ethtool "$iface" 2>/dev/null | grep "Speed:" | awk '{print $2}' | tr -d 'Mb/s' || echo "")

    if [ -z "$speed" ] || [ "$speed" = "Unknown!" ]; then
        # Fallback: check driver
        local driver
        driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

        case "$driver" in
            "r8125") speed="2500" ;;
            "rk_gmac-dwmac"|"dwmac-rk") speed="1000" ;;
            *) speed="1000" ;;
        esac
    fi

    echo "$speed"
}

# ============================================================
# Main Interface Detection
# ============================================================

detect_rock5b_interfaces() {
    local native_gbe=""
    local rtl8125=""
    local wan_iface=""
    local lan_ifaces=""

    echo "Detecting Rock 5B network interfaces..."

    # Detect native 1GbE
    native_gbe=$(detect_native_gbe)
    if [ -n "$native_gbe" ]; then
        local speed
        speed=$(get_interface_speed "$native_gbe")
        echo "  Native GbE: $native_gbe (${speed}Mbps)"
    fi

    # Detect RTL8125B 2.5GbE
    rtl8125=$(detect_rtl8125)
    if [ -n "$rtl8125" ]; then
        local speed
        speed=$(get_interface_speed "$rtl8125")
        echo "  RTL8125B 2.5GbE: $rtl8125 (${speed}Mbps)"
    fi

    # Detect any USB NICs
    local usb_nics=()
    for iface in /sys/class/net/*; do
        iface=$(basename "$iface")
        [ "$iface" = "lo" ] && continue
        [ "$iface" = "$native_gbe" ] && continue
        [ "$iface" = "$rtl8125" ] && continue

        local device_path
        device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null || true)

        if [[ "$device_path" == *"/usb"* ]]; then
            usb_nics+=("$iface")
            echo "  USB NIC: $iface"
        fi
    done

    # Determine total NIC count
    local total=0
    [ -n "$native_gbe" ] && ((total++))
    [ -n "$rtl8125" ] && ((total++))
    total=$((total + ${#usb_nics[@]}))

    export FORTRESS_TOTAL_NICS="$total"
    echo "  Total NICs: $total"

    # Interface assignment strategy:
    # - 2.5GbE (RTL8125) = WAN (higher bandwidth for upstream)
    # - 1GbE (native) = LAN (sufficient for local devices)
    # This is opposite to some configurations but makes sense for
    # maximizing WAN throughput

    if [ -n "$rtl8125" ]; then
        wan_iface="$rtl8125"
        if [ -n "$native_gbe" ]; then
            lan_ifaces="$native_gbe"
        fi
    elif [ -n "$native_gbe" ]; then
        wan_iface="$native_gbe"
    fi

    # Add USB NICs to LAN
    if [ ${#usb_nics[@]} -gt 0 ]; then
        if [ -n "$lan_ifaces" ]; then
            lan_ifaces="$lan_ifaces ${usb_nics[*]}"
        else
            lan_ifaces="${usb_nics[*]}"
        fi
    fi

    export FORTRESS_WAN_IFACE="$wan_iface"
    export FORTRESS_LAN_IFACES="$lan_ifaces"
    export FORTRESS_NATIVE_GBE="$native_gbe"
    export FORTRESS_RTL8125="$rtl8125"

    echo ""
    echo "Interface assignment:"
    echo "  WAN: ${wan_iface:-none} (2.5GbE preferred)"
    echo "  LAN: ${lan_ifaces:-none}"
}

# ============================================================
# Network Configuration Generation
# ============================================================

generate_netplan_config() {
    local wan_iface="${FORTRESS_WAN_IFACE:-enp4s0}"
    local lan_ifaces="${FORTRESS_LAN_IFACES:-eth0}"
    local output_file="${1:-/etc/netplan/60-fortress.yaml}"

    cat > "$output_file" << EOF
# Fortress Network Configuration for Radxa Rock 5B
# Generated: $(date -Iseconds)
#
# WAN: $wan_iface (2.5GbE RTL8125B)
# LAN: $lan_ifaces (1GbE native)
#
network:
  version: 2
  renderer: networkd

  ethernets:
    # WAN Interface - 2.5GbE for maximum upstream bandwidth
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

    # Add bridge configuration
    if [ -n "$lan_ifaces" ]; then
        cat >> "$output_file" << EOF

  bridges:
    br-lan:
      interfaces:
EOF
        for iface in $lan_ifaces; do
            echo "        - $iface" >> "$output_file"
        done

        cat >> "$output_file" << EOF
      addresses:
        - 10.200.0.1/24
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

    local xdp_mode="generic"

    case "$driver" in
        "r8125")
            # RTL8125 has XDP native support (partial)
            xdp_mode="native"
            ;;
        "r8169")
            # Older Realtek driver - generic only
            xdp_mode="generic"
            ;;
        "rk_gmac-dwmac"|"dwmac-rk")
            # Rockchip GMAC - limited XDP support
            xdp_mode="generic"
            ;;
        *)
            xdp_mode="generic"
            ;;
    esac

    export "FORTRESS_XDP_MODE_${iface//-/_}=$xdp_mode"
    echo "XDP mode for $iface ($driver): $xdp_mode"
}

# ============================================================
# RTL8125 Optimization
# ============================================================

optimize_rtl8125() {
    local iface="${FORTRESS_RTL8125:-enp4s0}"

    if [ ! -d "/sys/class/net/$iface" ]; then
        echo "RTL8125 interface $iface not found, skipping optimization"
        return 0
    fi

    echo "Optimizing RTL8125 ($iface)..."

    # Enable hardware offloads
    ethtool -K "$iface" tx-checksum-ip-generic on 2>/dev/null || true
    ethtool -K "$iface" rx-checksum on 2>/dev/null || true
    ethtool -K "$iface" tso on 2>/dev/null || true
    ethtool -K "$iface" gso on 2>/dev/null || true
    ethtool -K "$iface" gro on 2>/dev/null || true

    # Set ring buffer size (if supported)
    ethtool -G "$iface" rx 4096 tx 4096 2>/dev/null || true

    # Enable flow control
    ethtool -A "$iface" rx on tx on 2>/dev/null || true

    echo "  Hardware offloads enabled"
    echo "  Ring buffers configured"
}

# ============================================================
# WiFi/LTE Detection (M.2 E-key)
# ============================================================

detect_m2_devices() {
    echo "Checking M.2 E-key slot..."

    # WiFi detection
    for iface in /sys/class/net/wlan*; do
        [ -d "$iface" ] || continue
        local name
        name=$(basename "$iface")

        local driver
        driver=$(readlink -f "$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)

        echo "  WiFi: $name (driver: $driver)"
        export FORTRESS_WIFI_IFACES="${FORTRESS_WIFI_IFACES:+$FORTRESS_WIFI_IFACES }$name"
    done

    # LTE detection (via ModemManager or direct)
    if command -v mmcli &>/dev/null; then
        local modems
        modems=$(mmcli -L 2>/dev/null | grep -c "/Modem/" || echo "0")

        if [ "$modems" -gt 0 ]; then
            echo "  LTE modems detected: $modems"
            export FORTRESS_LTE_AVAILABLE="true"
        fi
    fi

    # Check for wwan interfaces
    for iface in /sys/class/net/wwan*; do
        [ -d "$iface" ] || continue
        local name
        name=$(basename "$iface")
        echo "  WWAN: $name"
        export FORTRESS_WWAN_IFACES="${FORTRESS_WWAN_IFACES:+$FORTRESS_WWAN_IFACES }$name"
    done
}

# ============================================================
# Main Entry Point
# ============================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "====================================="
    echo "Rock 5B Interface Detection"
    echo "====================================="

    detect_rock5b_interfaces
    detect_m2_devices

    # Configure XDP for each interface
    [ -n "$FORTRESS_WAN_IFACE" ] && configure_xdp_mode "$FORTRESS_WAN_IFACE"
    for iface in $FORTRESS_LAN_IFACES; do
        configure_xdp_mode "$iface"
    done

    echo ""
    echo "====================================="
    echo "Summary"
    echo "====================================="
    echo "Device: Radxa Rock 5B"
    echo "Total NICs: ${FORTRESS_TOTAL_NICS:-0}"
    echo "Native GbE: ${FORTRESS_NATIVE_GBE:-not detected}"
    echo "RTL8125 2.5GbE: ${FORTRESS_RTL8125:-not detected}"
    echo "WAN Interface: ${FORTRESS_WAN_IFACE:-not detected}"
    echo "LAN Interfaces: ${FORTRESS_LAN_IFACES:-not detected}"
    echo "WiFi Interfaces: ${FORTRESS_WIFI_IFACES:-none}"
    echo "LTE Available: ${FORTRESS_LTE_AVAILABLE:-false}"

    # Optimize RTL8125 if present
    if [ -n "$FORTRESS_RTL8125" ]; then
        echo ""
        optimize_rtl8125
    fi

    # Generate config if requested
    if [ "${1:-}" = "--generate" ]; then
        echo ""
        echo "Generating netplan configuration..."
        generate_netplan_config "${2:-/tmp/fortress-rock5b.yaml}"
    fi
fi
