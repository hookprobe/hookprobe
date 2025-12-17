#!/bin/bash
# ============================================================
# HookProbe Fortress WiFi DFS Capability Detection
# ============================================================
#
# Detects WiFi hardware capabilities for DFS (Dynamic Frequency Selection)
# and radar detection. Provides fallback recommendations for hardware
# that doesn't support advanced DFS features.
#
# Supported Chipset Families:
#   - Intel (iwlwifi): AX200/AX210/BE200 - Full DFS support
#   - Mediatek (mt76): MT7921/MT7922/MT7996 - Full DFS support
#   - Qualcomm/Atheros (ath10k/ath11k): QCA6174/QCA9984 - Full DFS
#   - Realtek (rtw88/rtw89): RTL8852/RTL8922 - Partial DFS
#   - Broadcom (brcmfmac): BCM4366/BCM4377 - Partial DFS
#
# Version: 1.0.0
# License: AGPL-3.0
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[DFS-CAP]${NC} $*"; }
log_success() { echo -e "${GREEN}[DFS-CAP]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[DFS-CAP]${NC} $*"; }
log_error() { echo -e "${RED}[DFS-CAP]${NC} $*"; }

# ============================================================
# VENDOR/CHIPSET DATABASE
# ============================================================
#
# DFS Capability Levels:
#   full:     Hardware radar detection, CSA, fast channel switch
#   partial:  Software radar detection, CSA support, slower switch
#   basic:    No radar detection, manual channel management
#   none:     No DFS support (2.4GHz only or restricted)

# Vendor PCI IDs (format: vendor:device)
declare -A WIFI_VENDOR_NAMES=(
    ["8086"]="Intel"
    ["14c3"]="MediaTek"
    ["168c"]="Qualcomm/Atheros"
    ["10ec"]="Realtek"
    ["14e4"]="Broadcom"
    ["1ae9"]="Wilocity"
    ["02d0"]="Broadcom (SDIO)"
)

# Intel Chipsets (iwlwifi)
declare -A INTEL_DFS_CAPS=(
    # WiFi 7 (BE)
    ["7e40"]="full:BE200:wifi7"
    ["7e80"]="full:BE202:wifi7"
    # WiFi 6E (AX)
    ["2725"]="full:AX210:wifi6e"
    ["2726"]="full:AX211:wifi6e"
    ["51f0"]="full:AX411:wifi6e"
    ["51f1"]="full:AX211:wifi6e"
    ["54f0"]="full:AX211:wifi6e"
    # WiFi 6 (AX)
    ["2723"]="full:AX200:wifi6"
    ["2720"]="full:AX201:wifi6"
    ["43f0"]="full:AX201:wifi6"
    ["a0f0"]="full:AX201:wifi6"
    # WiFi 5 (AC)
    ["24fb"]="partial:AC9260:wifi5"
    ["24fd"]="partial:AC8265:wifi5"
    ["24f3"]="partial:AC8260:wifi5"
    ["095a"]="partial:AC7265:wifi5"
    ["095b"]="partial:AC7265:wifi5"
    # Older (N)
    ["08b1"]="basic:N7260:wifi4"
    ["08b2"]="basic:N7260:wifi4"
)

# MediaTek Chipsets (mt76)
declare -A MEDIATEK_DFS_CAPS=(
    # WiFi 7
    ["7990"]="full:MT7996:wifi7"
    ["7992"]="full:MT7992:wifi7"
    # WiFi 6E
    ["7961"]="full:MT7921:wifi6e"
    ["7922"]="full:MT7922:wifi6e"
    ["0608"]="full:MT7921K:wifi6e"
    ["0616"]="full:MT7922:wifi6e"
    # WiFi 6
    ["7915"]="full:MT7915:wifi6"
    ["7916"]="full:MT7916:wifi6"
    # WiFi 5
    ["7612"]="partial:MT7612:wifi5"
    ["7662"]="partial:MT7662:wifi5"
)

# Qualcomm/Atheros Chipsets (ath10k/ath11k/ath12k)
declare -A QUALCOMM_DFS_CAPS=(
    # WiFi 7 (ath12k)
    ["1107"]="full:WCN7850:wifi7"
    # WiFi 6E (ath11k)
    ["1103"]="full:QCA6390:wifi6e"
    ["1101"]="full:QCN9074:wifi6e"
    # WiFi 6 (ath11k)
    ["1104"]="full:QCA6490:wifi6"
    # WiFi 5 (ath10k)
    ["003e"]="full:QCA6174:wifi5"
    ["0046"]="full:QCA9984:wifi5"
    ["0042"]="full:QCA9377:wifi5"
    ["003c"]="partial:QCA9880:wifi5"
    # WiFi 4 (ath9k)
    ["002a"]="basic:AR9280:wifi4"
    ["002b"]="basic:AR9285:wifi4"
    ["0030"]="basic:AR9300:wifi4"
)

# Realtek Chipsets (rtw88/rtw89)
declare -A REALTEK_DFS_CAPS=(
    # WiFi 7 (rtw89)
    ["8922"]="partial:RTL8922AE:wifi7"
    # WiFi 6E (rtw89)
    ["8852"]="partial:RTL8852CE:wifi6e"
    ["a85b"]="partial:RTL8852BE:wifi6e"
    ["b852"]="partial:RTL8852BE:wifi6e"
    # WiFi 6 (rtw89)
    ["8852"]="partial:RTL8852AE:wifi6"
    # WiFi 5 (rtw88)
    ["c822"]="basic:RTL8822CE:wifi5"
    ["c821"]="basic:RTL8821CE:wifi5"
    ["b822"]="basic:RTL8822BE:wifi5"
    # WiFi 4
    ["8179"]="none:RTL8188EUS:wifi4"
    ["0bda"]="none:RTL8188:wifi4"
)

# Broadcom Chipsets (brcmfmac)
declare -A BROADCOM_DFS_CAPS=(
    # WiFi 6E
    ["4387"]="partial:BCM4387:wifi6e"
    ["4388"]="partial:BCM4388:wifi6e"
    # WiFi 6
    ["4377"]="partial:BCM4377:wifi6"
    ["4378"]="partial:BCM4378:wifi6"
    # WiFi 5
    ["4366"]="partial:BCM4366:wifi5"
    ["4365"]="partial:BCM4365:wifi5"
    ["43a3"]="basic:BCM4350:wifi5"
    ["43b1"]="basic:BCM4352:wifi5"
    # WiFi 4
    ["4331"]="none:BCM4331:wifi4"
    ["4360"]="basic:BCM4360:wifi5"
)

# USB WiFi Adapters (by USB ID)
declare -A USB_WIFI_DFS_CAPS=(
    # MediaTek USB
    ["0e8d:7961"]="full:MT7921AU:wifi6e"
    ["0e8d:7922"]="full:MT7922AU:wifi6e"
    ["0e8d:7612"]="partial:MT7612U:wifi5"
    # Realtek USB
    ["0bda:8812"]="basic:RTL8812AU:wifi5"
    ["0bda:8814"]="basic:RTL8814AU:wifi5"
    ["0bda:b812"]="basic:RTL8812BU:wifi5"
    ["0bda:c811"]="basic:RTL8811CU:wifi5"
    ["0bda:1a2b"]="none:RTL8188:wifi4"
    # Atheros USB
    ["0cf3:9271"]="basic:AR9271:wifi4"
    ["0cf3:7015"]="none:AR9287:wifi4"
    # Ralink USB (now MediaTek)
    ["148f:5370"]="none:RT5370:wifi4"
    ["148f:7601"]="none:MT7601U:wifi4"
)

# Driver to DFS capability mapping (fallback)
declare -A DRIVER_DFS_CAPS=(
    ["iwlwifi"]="full"
    ["mt76"]="full"
    ["mt7921e"]="full"
    ["mt7922e"]="full"
    ["ath10k_pci"]="full"
    ["ath11k_pci"]="full"
    ["ath12k"]="full"
    ["ath9k"]="basic"
    ["rtw89_pci"]="partial"
    ["rtw88_pci"]="basic"
    ["brcmfmac"]="partial"
    ["brcmsmac"]="basic"
    ["rtl8xxxu"]="none"
    ["rtl8192cu"]="none"
    ["rt2800usb"]="none"
    ["rt2x00"]="none"
)

# ============================================================
# CAPABILITY DETECTION FUNCTIONS
# ============================================================

get_interface_driver() {
    # Get the kernel driver for a network interface
    local iface="$1"

    if [ -L "/sys/class/net/$iface/device/driver" ]; then
        basename "$(readlink -f /sys/class/net/$iface/device/driver)"
    elif [ -f "/sys/class/net/$iface/device/uevent" ]; then
        grep "^DRIVER=" "/sys/class/net/$iface/device/uevent" | cut -d= -f2
    fi
}

get_pci_ids() {
    # Get PCI vendor and device IDs for an interface
    local iface="$1"
    local vendor="" device=""

    if [ -f "/sys/class/net/$iface/device/vendor" ]; then
        vendor=$(cat "/sys/class/net/$iface/device/vendor" | sed 's/0x//')
    fi
    if [ -f "/sys/class/net/$iface/device/device" ]; then
        device=$(cat "/sys/class/net/$iface/device/device" | sed 's/0x//')
    fi

    echo "${vendor}:${device}"
}

get_usb_ids() {
    # Get USB vendor and product IDs for an interface
    local iface="$1"
    local usb_path

    # Find the USB device path
    usb_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)

    # Walk up to find idVendor/idProduct
    while [ -n "$usb_path" ] && [ "$usb_path" != "/" ]; do
        if [ -f "$usb_path/idVendor" ] && [ -f "$usb_path/idProduct" ]; then
            local vendor product
            vendor=$(cat "$usb_path/idVendor")
            product=$(cat "$usb_path/idProduct")
            echo "${vendor}:${product}"
            return 0
        fi
        usb_path=$(dirname "$usb_path")
    done

    return 1
}

is_usb_interface() {
    # Check if interface is USB-based
    local iface="$1"
    local device_path

    device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)
    [[ "$device_path" == */usb*/* ]]
}

get_chipset_dfs_capability() {
    # Get DFS capability for a specific chipset
    #
    # Args:
    #   $1 - Interface name
    #
    # Output: capability:chipset:wifi_gen (e.g., "full:AX210:wifi6e")

    local iface="$1"
    local driver pci_ids usb_ids vendor device

    driver=$(get_interface_driver "$iface")

    # Check if USB interface
    if is_usb_interface "$iface"; then
        usb_ids=$(get_usb_ids "$iface")
        if [ -n "$usb_ids" ] && [ -n "${USB_WIFI_DFS_CAPS[$usb_ids]}" ]; then
            echo "${USB_WIFI_DFS_CAPS[$usb_ids]}"
            return 0
        fi
    fi

    # Get PCI IDs
    pci_ids=$(get_pci_ids "$iface")
    vendor="${pci_ids%%:*}"
    device="${pci_ids##*:}"

    # Lookup by vendor
    case "$vendor" in
        8086)  # Intel
            if [ -n "${INTEL_DFS_CAPS[$device]}" ]; then
                echo "${INTEL_DFS_CAPS[$device]}"
                return 0
            fi
            ;;
        14c3)  # MediaTek
            if [ -n "${MEDIATEK_DFS_CAPS[$device]}" ]; then
                echo "${MEDIATEK_DFS_CAPS[$device]}"
                return 0
            fi
            ;;
        168c)  # Qualcomm/Atheros
            if [ -n "${QUALCOMM_DFS_CAPS[$device]}" ]; then
                echo "${QUALCOMM_DFS_CAPS[$device]}"
                return 0
            fi
            ;;
        10ec)  # Realtek
            if [ -n "${REALTEK_DFS_CAPS[$device]}" ]; then
                echo "${REALTEK_DFS_CAPS[$device]}"
                return 0
            fi
            ;;
        14e4)  # Broadcom
            if [ -n "${BROADCOM_DFS_CAPS[$device]}" ]; then
                echo "${BROADCOM_DFS_CAPS[$device]}"
                return 0
            fi
            ;;
    esac

    # Fallback to driver-based detection
    if [ -n "$driver" ] && [ -n "${DRIVER_DFS_CAPS[$driver]}" ]; then
        local cap="${DRIVER_DFS_CAPS[$driver]}"
        echo "${cap}:unknown:unknown"
        return 0
    fi

    # Unknown - assume basic
    echo "basic:unknown:unknown"
}

probe_dfs_features() {
    # Probe actual DFS feature support from the driver/firmware
    #
    # Args:
    #   $1 - Interface name
    #
    # Output: JSON object with feature flags

    local iface="$1"
    local phy radar_detect cac_support csa_support background_cac

    # Get phy name
    phy=$(basename "$(readlink -f /sys/class/net/$iface/phy80211 2>/dev/null)" 2>/dev/null)

    # Check radar detection support
    radar_detect="false"
    if iw phy "$phy" info 2>/dev/null | grep -q "DFS"; then
        radar_detect="true"
    fi

    # Check CAC support
    cac_support="false"
    if iw phy "$phy" info 2>/dev/null | grep -q "radar detection"; then
        cac_support="true"
    fi

    # Check CSA support
    csa_support="false"
    if command -v hostapd_cli &>/dev/null; then
        # hostapd with chan_switch command implies CSA support
        csa_support="true"
    fi

    # Check background CAC support (newer feature)
    background_cac="false"
    if iw phy "$phy" info 2>/dev/null | grep -qi "background.*cac\|zero.*wait"; then
        background_cac="true"
    fi

    # Check DFS channels availability
    local dfs_channels=""
    dfs_channels=$(iw phy "$phy" channels 2>/dev/null | grep -c "radar detection" || echo "0")

    cat << EOF
{
    "interface": "$iface",
    "phy": "$phy",
    "features": {
        "radar_detection": $radar_detect,
        "cac_support": $cac_support,
        "csa_support": $csa_support,
        "background_cac": $background_cac
    },
    "dfs_channels_available": $dfs_channels
}
EOF
}

get_dfs_recommendation() {
    # Get recommended DFS operation mode based on hardware capability
    #
    # Args:
    #   $1 - Interface name
    #
    # Output: Recommendation JSON

    local iface="$1"
    local cap_info chipset_cap chipset wifi_gen

    cap_info=$(get_chipset_dfs_capability "$iface")
    chipset_cap="${cap_info%%:*}"
    chipset="${cap_info#*:}"
    chipset="${chipset%%:*}"
    wifi_gen="${cap_info##*:}"

    local driver vendor_name pci_ids vendor
    driver=$(get_interface_driver "$iface")
    pci_ids=$(get_pci_ids "$iface")
    vendor="${pci_ids%%:*}"
    vendor_name="${WIFI_VENDOR_NAMES[$vendor]:-Unknown}"

    local use_ml use_radar use_csa use_nop recommended_mode

    case "$chipset_cap" in
        full)
            use_ml="true"
            use_radar="true"
            use_csa="true"
            use_nop="true"
            recommended_mode="advanced"
            ;;
        partial)
            use_ml="true"
            use_radar="true"
            use_csa="true"
            use_nop="true"
            recommended_mode="standard"
            ;;
        basic)
            use_ml="true"
            use_radar="false"
            use_csa="false"
            use_nop="true"
            recommended_mode="basic"
            ;;
        none|*)
            use_ml="false"
            use_radar="false"
            use_csa="false"
            use_nop="false"
            recommended_mode="disabled"
            ;;
    esac

    cat << EOF
{
    "interface": "$iface",
    "driver": "$driver",
    "vendor": "$vendor_name",
    "chipset": "$chipset",
    "wifi_generation": "$wifi_gen",
    "capability_level": "$chipset_cap",
    "recommended_mode": "$recommended_mode",
    "features": {
        "use_ml_prediction": $use_ml,
        "use_radar_detection": $use_radar,
        "use_csa_switching": $use_csa,
        "use_nop_tracking": $use_nop
    },
    "notes": "$(get_capability_notes "$chipset_cap" "$driver")"
}
EOF
}

get_capability_notes() {
    # Get human-readable notes for capability level
    local cap="$1"
    local driver="$2"

    case "$cap" in
        full)
            echo "Full DFS support: Hardware radar detection, fast CSA, background CAC. Recommended for DFS channels."
            ;;
        partial)
            echo "Partial DFS support: Software radar detection, CSA available. Channel switch may take 1-2s longer."
            ;;
        basic)
            echo "Basic DFS support: No hardware radar detection. Manual channel management recommended. Avoid UNII-2C."
            ;;
        none)
            echo "No DFS support: 2.4GHz only or restricted. Do not use DFS channels."
            ;;
    esac
}

# ============================================================
# SUMMARY AND REPORTING
# ============================================================

detect_all_wifi_interfaces() {
    # Detect all WiFi interfaces and their DFS capabilities

    local ifaces=""

    # Find wireless interfaces
    for dir in /sys/class/net/*/wireless; do
        [ -d "$dir" ] || continue
        local iface
        iface=$(basename "$(dirname "$dir")")
        ifaces="$ifaces $iface"
    done

    echo "$ifaces" | xargs
}

show_dfs_capabilities_report() {
    # Show comprehensive DFS capabilities report

    log_info "=========================================="
    log_info "WiFi DFS CAPABILITIES REPORT"
    log_info "=========================================="

    local interfaces
    interfaces=$(detect_all_wifi_interfaces)

    if [ -z "$interfaces" ]; then
        log_warn "No wireless interfaces detected"
        return 1
    fi

    for iface in $interfaces; do
        log_info ""
        log_info "Interface: $iface"
        log_info "------------------------------------------"

        local cap_info recommendation
        cap_info=$(get_chipset_dfs_capability "$iface")
        recommendation=$(get_dfs_recommendation "$iface")

        local chipset_cap chipset wifi_gen driver vendor_name
        chipset_cap="${cap_info%%:*}"
        chipset="${cap_info#*:}"
        chipset="${chipset%%:*}"
        wifi_gen="${cap_info##*:}"
        driver=$(get_interface_driver "$iface")

        local pci_ids vendor
        pci_ids=$(get_pci_ids "$iface")
        vendor="${pci_ids%%:*}"
        vendor_name="${WIFI_VENDOR_NAMES[$vendor]:-Unknown}"

        echo "  Vendor:     $vendor_name"
        echo "  Chipset:    $chipset"
        echo "  Driver:     $driver"
        echo "  WiFi Gen:   $wifi_gen"
        echo "  DFS Level:  $chipset_cap"

        case "$chipset_cap" in
            full)
                log_success "  Status:     Full DFS support - All features available"
                ;;
            partial)
                log_warn "  Status:     Partial DFS - Some features limited"
                ;;
            basic)
                log_warn "  Status:     Basic - Avoid DFS channels"
                ;;
            none)
                log_error "  Status:     No DFS support"
                ;;
        esac

        # Probe actual features
        log_info ""
        log_info "  Probed Features:"
        local features
        features=$(probe_dfs_features "$iface")
        echo "$features" | grep -E "radar|cac|csa|dfs_channels" | sed 's/^/    /'
    done

    log_info ""
    log_info "=========================================="
}

# ============================================================
# MAIN / CLI
# ============================================================

show_help() {
    cat << EOF
WiFi DFS Capability Detection

Usage: $(basename "$0") <command> [options]

Commands:
  detect <iface>      Detect DFS capability for interface
  probe <iface>       Probe actual DFS features from driver
  recommend <iface>   Get recommended DFS mode for interface
  report              Show full capabilities report for all interfaces
  json <iface>        Output recommendation as JSON

Capability Levels:
  full:     Hardware radar, fast CSA, background CAC
  partial:  Software radar, CSA available, slower switch
  basic:    No radar detection, manual channel management
  none:     No DFS support (2.4GHz only)

Supported Vendors:
  - Intel (iwlwifi): AX200/AX210/BE200
  - MediaTek (mt76): MT7921/MT7922/MT7996
  - Qualcomm (ath10k/ath11k): QCA6174/QCA9984
  - Realtek (rtw88/rtw89): RTL8852/RTL8922
  - Broadcom (brcmfmac): BCM4366/BCM4377

Examples:
  $(basename "$0") detect wlan0
  $(basename "$0") recommend wlan0
  $(basename "$0") report

EOF
}

main() {
    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        detect|cap|capability)
            local iface="${1:?Interface required}"
            get_chipset_dfs_capability "$iface"
            ;;
        probe|features)
            local iface="${1:?Interface required}"
            probe_dfs_features "$iface"
            ;;
        recommend|rec)
            local iface="${1:?Interface required}"
            get_dfs_recommendation "$iface"
            ;;
        report|all)
            show_dfs_capabilities_report
            ;;
        json)
            local iface="${1:?Interface required}"
            get_dfs_recommendation "$iface"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
