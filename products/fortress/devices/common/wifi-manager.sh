#!/bin/bash
# ============================================================
# HookProbe Fortress WiFi Manager
# ============================================================
#
# Detects and manages WiFi interfaces for Fortress deployments.
# Inspired by Guardian's guardian-wlan-setup.sh approach.
#
# Supported Interface Naming:
#   - wlan*      Traditional naming (wlan0, wlan1)
#   - wlp*       PCI-based naming (wlp2s0, wlp0s20f3)
#   - wlx*       MAC-based naming (wlxaabbccddeeff)
#
# Common Chipsets:
#   - Intel AX200/210/211 (iwlwifi) - wlp*
#   - Qualcomm QCN62xx/92xx (ath11k/ath12k) - wlan* or wlp*
#   - MediaTek MT7612U/MT7921 (mt76) - wlan* or wlx*
#   - Realtek RTL8812AU (rtw88) - wlan* or wlx*
#   - Atheros AR9271 (ath9k_htc) - wlan*
#
# Version: 5.0.0
# License: AGPL-3.0
#
# ============================================================

set -e

LOG_TAG="fortress-wifi"

log_info() {
    logger -t "$LOG_TAG" -p user.info "$1" 2>/dev/null || true
    echo "[INFO] $1"
}

log_warn() {
    logger -t "$LOG_TAG" -p user.warning "$1" 2>/dev/null || true
    echo "[WARN] $1"
}

log_error() {
    logger -t "$LOG_TAG" -p user.err "$1" 2>/dev/null || true
    echo "[ERROR] $1"
}

# ============================================================
# Interface Helper Functions
# ============================================================

get_mac_address() {
    local iface="$1"
    if [ -f "/sys/class/net/$iface/address" ]; then
        cat "/sys/class/net/$iface/address" 2>/dev/null | tr '[:lower:]' '[:upper:]'
    fi
}

get_interface_driver() {
    local iface="$1"
    if [ -L "/sys/class/net/$iface/device/driver" ]; then
        basename "$(readlink -f /sys/class/net/$iface/device/driver)" 2>/dev/null
    fi
}

get_interface_vendor() {
    local iface="$1"
    local driver
    driver=$(get_interface_driver "$iface")

    case "$driver" in
        iwlwifi) echo "Intel" ;;
        ath11k|ath12k|ath10k|ath9k|ath9k_htc) echo "Qualcomm/Atheros" ;;
        mt76|mt7921e|mt7921u) echo "MediaTek" ;;
        rtw88|rtw89|rtl8xxxu) echo "Realtek" ;;
        brcmfmac|brcmsmac) echo "Broadcom" ;;
        *) echo "Unknown" ;;
    esac
}

# ============================================================
# WiFi Interface Detection
# ============================================================

# Get all WiFi interfaces (wlan*, wlp*, wlx*)
detect_wifi_interfaces() {
    local wifi_list=()

    # Check /sys/class/net for wireless interfaces
    for iface in /sys/class/net/*; do
        [ -d "$iface" ] || continue
        local name
        name=$(basename "$iface")

        # Skip non-wireless interfaces
        case "$name" in
            wlan*|wlp*|wlx*)
                # Verify it's actually a wireless interface
                if [ -d "$iface/wireless" ] || [ -L "$iface/phy80211" ]; then
                    wifi_list+=("$name")
                fi
                ;;
        esac
    done

    printf '%s\n' "${wifi_list[@]}" | sort
}

# Get WiFi bands for an interface
get_wifi_bands() {
    local iface="$1"

    if ! command -v iw &>/dev/null; then
        echo "unknown"
        return
    fi

    local phy=""
    if [ -L "/sys/class/net/$iface/phy80211" ]; then
        phy=$(basename "$(readlink -f /sys/class/net/$iface/phy80211)")
    else
        echo "unknown"
        return
    fi

    local bands=()
    local phy_info
    phy_info=$(iw phy "$phy" info 2>/dev/null || true)

    # Check for 2.4GHz (Band 1)
    if echo "$phy_info" | grep -q "Band 1:"; then
        bands+=("2.4GHz")
    fi

    # Check for 5GHz (Band 2)
    if echo "$phy_info" | grep -q "Band 2:"; then
        bands+=("5GHz")
    fi

    # Check for 6GHz (Band 4) - WiFi 6E
    if echo "$phy_info" | grep -q "Band 4:"; then
        bands+=("6GHz")
    fi

    echo "${bands[*]}"
}

# Check if interface supports AP mode
check_ap_support() {
    local iface="$1"

    if ! command -v iw &>/dev/null; then
        return 1
    fi

    if iw list 2>/dev/null | grep -A 15 "Supported interface modes" | grep -q "\* AP"; then
        return 0
    fi

    return 1
}

# Check if interface supports AP/VLAN (VAP) for VLAN segregation
check_vap_support() {
    local iface="$1"

    if ! command -v iw &>/dev/null; then
        return 1
    fi

    if iw list 2>/dev/null | grep -A 20 "Supported interface modes" | grep -q "AP/VLAN"; then
        return 0
    fi

    return 1
}

# ============================================================
# Main Detection Function
# ============================================================

detect_fortress_wifi() {
    log_info "Detecting WiFi interfaces..."

    local wifi_count=0
    local ap_capable=()
    local vap_capable=()

    # Arrays to store results
    declare -a DETECTED_WIFI=()

    while IFS= read -r iface; do
        [ -z "$iface" ] && continue

        local mac driver vendor bands

        mac=$(get_mac_address "$iface")
        driver=$(get_interface_driver "$iface")
        vendor=$(get_interface_vendor "$iface")
        bands=$(get_wifi_bands "$iface")

        DETECTED_WIFI+=("$iface")

        log_info "  $iface:"
        log_info "    MAC: $mac"
        log_info "    Driver: $driver"
        log_info "    Vendor: $vendor"
        log_info "    Bands: $bands"

        # Check capabilities
        if check_ap_support "$iface"; then
            ap_capable+=("$iface")
            log_info "    AP Mode: supported"
        else
            log_info "    AP Mode: not supported"
        fi

        if check_vap_support "$iface"; then
            vap_capable+=("$iface")
            log_info "    VAP/VLAN: supported"
        fi

        ((wifi_count++))
    done < <(detect_wifi_interfaces)

    # Export results
    export FORTRESS_WIFI_COUNT="$wifi_count"
    export FORTRESS_WIFI_IFACES="${DETECTED_WIFI[*]}"
    export FORTRESS_WIFI_AP_CAPABLE="${ap_capable[*]}"
    export FORTRESS_WIFI_VAP_CAPABLE="${vap_capable[*]}"

    log_info ""
    log_info "WiFi Summary:"
    log_info "  Total adapters: $wifi_count"
    log_info "  AP capable: ${#ap_capable[@]}"
    log_info "  VAP capable: ${#vap_capable[@]}"

    return 0
}

# ============================================================
# NetworkManager Integration
# ============================================================

# Set interface as unmanaged by NetworkManager
set_nm_unmanaged() {
    local iface="$1"

    if ! command -v nmcli &>/dev/null; then
        return 0
    fi

    nmcli device set "$iface" managed no 2>/dev/null || true
    log_info "Set $iface as unmanaged by NetworkManager"
}

# Set interface as managed by NetworkManager
set_nm_managed() {
    local iface="$1"

    if ! command -v nmcli &>/dev/null; then
        return 0
    fi

    nmcli device set "$iface" managed yes 2>/dev/null || true
    log_info "Set $iface as managed by NetworkManager"
}

# Generate NetworkManager config to unmanage AP interfaces
generate_nm_config() {
    local ap_ifaces="$1"  # Space-separated list of AP interfaces
    local output_file="${2:-/etc/NetworkManager/conf.d/fortress-unmanaged.conf}"

    mkdir -p "$(dirname "$output_file")"

    cat > "$output_file" << 'NMHEADER'
# HookProbe Fortress - NetworkManager Configuration
# Generated by fortress wifi-manager.sh
#
# Interfaces managed by Fortress (hostapd/bridge):
NMHEADER

    # Build unmanaged list
    local unmanaged_list="interface-name:br*;interface-name:ovs-*;interface-name:vlan*;interface-name:fortress"

    for iface in $ap_ifaces; do
        local mac
        mac=$(get_mac_address "$iface")
        unmanaged_list="${unmanaged_list};interface-name:${iface}"
        [ -n "$mac" ] && unmanaged_list="${unmanaged_list};mac:${mac}"
        echo "# $iface: $mac" >> "$output_file"
    done

    cat >> "$output_file" << NMEOF

[keyfile]
unmanaged-devices=$unmanaged_list

[device]
wifi.scan-rand-mac-address=no
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve

[connection]
wifi.cloned-mac-address=preserve
ethernet.cloned-mac-address=preserve

[main]
dns=none
NMEOF

    chmod 644 "$output_file"
    log_info "Generated NetworkManager config: $output_file"

    # Reload NetworkManager if running
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        nmcli general reload 2>/dev/null || true
    fi
}

# ============================================================
# Interface Preparation for AP Mode
# ============================================================

prepare_ap_interface() {
    local iface="$1"

    log_info "Preparing $iface for AP mode..."

    # Unblock rfkill if needed
    rfkill unblock wifi 2>/dev/null || true

    # Kill any wpa_supplicant on this interface
    pkill -f "wpa_supplicant.*$iface" 2>/dev/null || true

    # Set as unmanaged by NetworkManager
    set_nm_unmanaged "$iface"

    # Remove from any existing bridge
    for br in $(ls /sys/class/net/*/brif 2>/dev/null | xargs -I{} dirname {} | xargs -I{} basename {} 2>/dev/null); do
        ip link set "$iface" nomaster 2>/dev/null || true
    done

    # Bring interface down for hostapd
    ip link set "$iface" down 2>/dev/null || true
    sleep 1

    log_info "$iface prepared for AP mode"
}

# ============================================================
# Bridge Integration
# ============================================================

add_wifi_to_bridge() {
    local iface="$1"
    local bridge="${2:-FTS}"

    # Ensure bridge exists
    if [ ! -d "/sys/class/net/$bridge" ]; then
        log_warn "Bridge $bridge does not exist"
        return 1
    fi

    # Add interface to bridge
    ip link set "$iface" master "$bridge" 2>/dev/null || {
        log_warn "Failed to add $iface to $bridge"
        return 1
    }

    log_info "Added $iface to bridge $bridge"
}

# ============================================================
# Main Entry Point
# ============================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "====================================="
    echo "Fortress WiFi Manager"
    echo "====================================="
    echo ""

    detect_fortress_wifi

    echo ""
    echo "====================================="
    echo "Export Variables"
    echo "====================================="
    echo "FORTRESS_WIFI_COUNT=$FORTRESS_WIFI_COUNT"
    echo "FORTRESS_WIFI_IFACES=$FORTRESS_WIFI_IFACES"
    echo "FORTRESS_WIFI_AP_CAPABLE=$FORTRESS_WIFI_AP_CAPABLE"
    echo "FORTRESS_WIFI_VAP_CAPABLE=$FORTRESS_WIFI_VAP_CAPABLE"
fi
