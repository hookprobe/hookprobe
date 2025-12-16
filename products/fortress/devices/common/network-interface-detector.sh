#!/bin/bash
#
# network-interface-detector.sh - Unified Network Interface Detection for Fortress
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Provides comprehensive detection of:
#   - Ethernet interfaces (eth*, enp*, eno*, ens*) with WAN/LAN auto-classification
#   - WiFi interfaces (wlan*, wlp*, wlx*) with multi-radio and band detection
#   - WWAN/modem interfaces (wwan*, wwp*) with nmcli integration
#
# Interface Naming Conventions:
#   Ethernet:  eth0, enp1s0, eno1, ens192 (predictable naming)
#   WiFi:      wlan0, wlp2s0, wlx00112233aabb (predictable naming)
#   WWAN:      wwan0, wwp0s20f0u4 (double 'w' prefix)
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================
# CONFIGURATION
# ============================================================

STATE_DIR="/var/lib/fortress"
INTERFACE_STATE_FILE="$STATE_DIR/network-interfaces.conf"
WIFI_STATE_FILE="$STATE_DIR/wifi-radios.conf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() { echo -e "${CYAN}[NET]${NC} $*"; }
log_success() { echo -e "${GREEN}[NET]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[NET]${NC} $*"; }
log_error() { echo -e "${RED}[NET]${NC} $*"; }
log_section() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

# ============================================================
# HELPER FUNCTIONS
# ============================================================

get_interface_driver() {
    local iface="$1"
    local driver_path="/sys/class/net/$iface/device/driver"
    if [ -L "$driver_path" ]; then
        basename "$(readlink -f "$driver_path")" 2>/dev/null
    fi
}

get_interface_mac() {
    local iface="$1"
    if [ -f "/sys/class/net/$iface/address" ]; then
        cat "/sys/class/net/$iface/address" 2>/dev/null | tr '[:lower:]' '[:upper:]'
    fi
}

get_pci_info() {
    local iface="$1"
    if [ -d "/sys/class/net/$iface/device" ]; then
        local vendor=$(cat "/sys/class/net/$iface/device/vendor" 2>/dev/null | sed 's/0x//')
        local device=$(cat "/sys/class/net/$iface/device/device" 2>/dev/null | sed 's/0x//')
        echo "${vendor}:${device}"
    fi
}

get_pci_slot() {
    local iface="$1"
    if [ -L "/sys/class/net/$iface/device" ]; then
        local pci_path
        pci_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)
        basename "$pci_path" 2>/dev/null
    fi
}

get_interface_speed() {
    local iface="$1"
    local speed=""

    # Try ethtool
    if command -v ethtool &>/dev/null; then
        speed=$(ethtool "$iface" 2>/dev/null | grep -E "Speed:|Supported link modes:" | head -1)
        if echo "$speed" | grep -q "2500"; then
            echo "2.5GbE"
            return
        elif echo "$speed" | grep -q "10000\|10Gb"; then
            echo "10GbE"
            return
        elif echo "$speed" | grep -q "1000"; then
            echo "1GbE"
            return
        elif echo "$speed" | grep -q "100"; then
            echo "100Mb"
            return
        fi
    fi

    # Fallback to sysfs
    if [ -f "/sys/class/net/$iface/speed" ]; then
        local spd
        spd=$(cat "/sys/class/net/$iface/speed" 2>/dev/null)
        case "$spd" in
            10000) echo "10GbE" ;;
            2500)  echo "2.5GbE" ;;
            1000)  echo "1GbE" ;;
            100)   echo "100Mb" ;;
            *)     echo "${spd}Mb" ;;
        esac
        return
    fi

    echo "Unknown"
}

is_interface_up() {
    local iface="$1"
    ip link show "$iface" 2>/dev/null | grep -q "state UP"
}

has_ip_address() {
    local iface="$1"
    ip addr show "$iface" 2>/dev/null | grep -q "inet "
}

has_carrier() {
    local iface="$1"
    [ "$(cat /sys/class/net/$iface/carrier 2>/dev/null)" = "1" ]
}

# ============================================================
# ETHERNET INTERFACE DETECTION
# ============================================================

# Interface patterns for classification
VIRTUAL_IFACE_PATTERNS="lo|br.*|veth.*|vlan.*|docker.*|podman.*|ovs-.*|vxlan.*|tap.*|tun.*|virbr.*"
WWAN_IFACE_PATTERNS="wwan.*|wwp.*|ww.*"
WIFI_IFACE_PATTERNS="wlan.*|wlp.*|wlx.*"

detect_ethernet_interfaces() {
    # Detect all physical Ethernet interfaces
    #
    # Returns sorted list by PCI bus order (consistent physical port ordering)

    log_section "Ethernet Interface Detection"

    local -a eth_interfaces=()
    declare -A iface_pci_order

    for iface_path in /sys/class/net/*; do
        [ -d "$iface_path" ] || continue
        local iface
        iface=$(basename "$iface_path")

        # Skip virtual interfaces
        if [[ "$iface" =~ ^($VIRTUAL_IFACE_PATTERNS)$ ]]; then
            continue
        fi

        # Skip WWAN interfaces (double 'w' prefix)
        if [[ "$iface" =~ ^($WWAN_IFACE_PATTERNS)$ ]]; then
            continue
        fi

        # Skip WiFi interfaces
        if [[ "$iface" =~ ^($WIFI_IFACE_PATTERNS)$ ]] || \
           [ -d "$iface_path/wireless" ] || \
           [ -L "$iface_path/phy80211" ]; then
            continue
        fi

        # Check if physical device
        if [ ! -d "$iface_path/device" ]; then
            continue
        fi

        # Verify it's Ethernet (ARPHRD_ETHER = 1)
        local devtype
        devtype=$(cat "$iface_path/type" 2>/dev/null)
        if [ "$devtype" != "1" ]; then
            continue
        fi

        # Get PCI slot for ordering
        local pci_slot
        pci_slot=$(get_pci_slot "$iface")

        eth_interfaces+=("$iface")
        iface_pci_order["$iface"]="$pci_slot"

        local driver speed mac
        driver=$(get_interface_driver "$iface")
        speed=$(get_interface_speed "$iface")
        mac=$(get_interface_mac "$iface")

        log_info "Found: $iface"
        log_info "  PCI: $pci_slot"
        log_info "  Driver: $driver"
        log_info "  Speed: $speed"
        log_info "  MAC: $mac"
    done

    # Sort interfaces by PCI slot order
    local sorted_ifaces=""
    for iface in $(for k in "${!iface_pci_order[@]}"; do
        echo "${iface_pci_order[$k]}:$k"
    done | sort | cut -d: -f2-); do
        sorted_ifaces="$sorted_ifaces $iface"
    done

    export NET_ETH_INTERFACES=$(echo "$sorted_ifaces" | xargs)
    export NET_ETH_COUNT=${#eth_interfaces[@]}

    log_success "Found $NET_ETH_COUNT Ethernet interface(s): $NET_ETH_INTERFACES"
}

classify_wan_lan_interfaces() {
    # Classify interfaces into WAN (first) and LAN (remaining)
    #
    # Strategy:
    #   1. First Ethernet interface (by PCI order) = WAN
    #   2. All other Ethernet interfaces = LAN (bridged together)
    #
    # This follows the standard router convention:
    #   - Port 1 (eth0/enp1s0): WAN uplink
    #   - Ports 2-N (eth1+/enp2s0+): LAN ports

    log_section "WAN/LAN Classification"

    local first=true
    local wan_iface=""
    local lan_ifaces=""

    for iface in $NET_ETH_INTERFACES; do
        if $first; then
            wan_iface="$iface"
            first=false
            log_info "WAN: $iface (first physical port)"
        else
            lan_ifaces="$lan_ifaces $iface"
            log_info "LAN: $iface (bridge member)"
        fi
    done

    export NET_WAN_IFACE="$wan_iface"
    export NET_LAN_IFACES=$(echo "$lan_ifaces" | xargs)

    log_success "WAN Interface: ${NET_WAN_IFACE:-none}"
    log_success "LAN Interfaces: ${NET_LAN_IFACES:-none}"
}

# ============================================================
# WIFI INTERFACE DETECTION WITH MULTI-RADIO SUPPORT
# ============================================================

detect_wifi_interfaces() {
    # Detect WiFi interfaces with band and radio information
    #
    # Some devices have multiple radios:
    #   - Single radio, dual-band (2.4GHz + 5GHz, one at a time)
    #   - Dual radio (2.4GHz + 5GHz simultaneously)
    #   - Tri-band (2.4GHz + 5GHz-1 + 5GHz-2 or 6GHz)

    log_section "WiFi Interface Detection"

    local -a wifi_interfaces=()
    declare -A wifi_radios

    for iface_path in /sys/class/net/*; do
        [ -d "$iface_path" ] || continue
        local iface
        iface=$(basename "$iface_path")

        # Check if wireless interface
        if [[ "$iface" =~ ^($WIFI_IFACE_PATTERNS)$ ]] || \
           [ -d "$iface_path/wireless" ] || \
           [ -L "$iface_path/phy80211" ]; then

            wifi_interfaces+=("$iface")

            local driver mac phy
            driver=$(get_interface_driver "$iface")
            mac=$(get_interface_mac "$iface")

            # Get PHY name - try multiple methods
            if [ -L "$iface_path/phy80211" ]; then
                phy=$(basename "$(readlink -f "$iface_path/phy80211")")
            fi

            # Fallback: use iw dev to find PHY
            if [ -z "$phy" ] && command -v iw &>/dev/null; then
                phy=$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/ {print "phy"$2}')
            fi

            # Another fallback: look in /sys/class/ieee80211
            if [ -z "$phy" ]; then
                for p in /sys/class/ieee80211/phy*; do
                    if [ -d "$p" ] && ls "$p/device/net/" 2>/dev/null | grep -q "^${iface}$"; then
                        phy=$(basename "$p")
                        break
                    fi
                done
            fi

            log_info "Found WiFi: $iface"
            log_info "  Driver: $driver"
            log_info "  MAC: $mac"
            log_info "  PHY: ${phy:-unknown}"

            # Detect bands and capabilities
            if [ -n "$phy" ]; then
                detect_wifi_radio_capabilities "$iface" "$phy"
            else
                log_warn "  Cannot detect PHY for $iface - trying direct frequency scan"
                detect_wifi_bands_direct "$iface"
            fi
        fi
    done

    export NET_WIFI_INTERFACES="${wifi_interfaces[*]}"
    export NET_WIFI_COUNT=${#wifi_interfaces[@]}

    log_success "Found $NET_WIFI_COUNT WiFi interface(s): $NET_WIFI_INTERFACES"
}

detect_wifi_bands_direct() {
    # Fallback band detection when PHY cannot be determined
    # Uses iwlist or iw dev to scan for available frequencies
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"
    local supports_24ghz=false
    local supports_5ghz=false
    local supports_6ghz=false
    local freq_info=""

    log_info "  Attempting direct frequency detection for $iface..."

    # Method 1: Use iwlist frequency
    if command -v iwlist &>/dev/null; then
        freq_info=$(iwlist "$iface" frequency 2>/dev/null)
        if [ -n "$freq_info" ]; then
            # Check for 2.4GHz channels (2.4xx GHz)
            if echo "$freq_info" | grep -qE "2\.[0-9]+ GHz|24[0-9][0-9]"; then
                supports_24ghz=true
            fi
            # Check for 5GHz channels (5.xxx GHz)
            if echo "$freq_info" | grep -qE "5\.[0-9]+ GHz|5[0-9][0-9][0-9]"; then
                supports_5ghz=true
            fi
        fi
    fi

    # Method 2: Try iw list and find our interface's phy info
    if ! $supports_24ghz && ! $supports_5ghz && command -v iw &>/dev/null; then
        freq_info=$(iw list 2>/dev/null)
        if [ -n "$freq_info" ]; then
            # Look for frequency entries
            if echo "$freq_info" | grep -qE "24[0-9][0-9] MHz"; then
                supports_24ghz=true
            fi
            if echo "$freq_info" | grep -qE "5[0-9][0-9][0-9] MHz"; then
                supports_5ghz=true
            fi
            if echo "$freq_info" | grep -qE "(59[2-9][0-9]|6[0-9][0-9][0-9]|7[0-1][0-9][0-9]) MHz"; then
                supports_6ghz=true
            fi
        fi
    fi

    # Method 3: Check sysfs for supported bands
    if ! $supports_24ghz && ! $supports_5ghz; then
        # Look for any phy directory and check its bands
        for phy_dir in /sys/class/ieee80211/phy*; do
            if [ -d "$phy_dir" ]; then
                local phy_name
                phy_name=$(basename "$phy_dir")
                # Use iw phy (without 'info') or iw list
                freq_info=$(iw phy "$phy_name" 2>/dev/null)
                if [ -z "$freq_info" ]; then
                    freq_info=$(iw list 2>/dev/null)
                fi
                if [ -n "$freq_info" ]; then
                    if echo "$freq_info" | grep -qE "24[0-9][0-9] MHz"; then
                        supports_24ghz=true
                    fi
                    if echo "$freq_info" | grep -qE "5[0-9][0-9][0-9] MHz"; then
                        supports_5ghz=true
                    fi
                    # Found info, assign to this interface
                    break
                fi
            fi
        done
    fi

    # Method 4: Driver-based fallback for known WiFi chipsets
    if ! $supports_24ghz && ! $supports_5ghz; then
        local driver
        driver=$(get_interface_driver "$iface")
        log_info "  Frequency detection failed, using driver fallback: $driver"
        case "$driver" in
            ath12k*|ath12k_pci)
                # WiFi 7 - tri-band
                supports_24ghz=true
                supports_5ghz=true
                supports_6ghz=true
                ;;
            ath11k*|ath11k_pci|mt76*|mt7921*|mt7922*)
                # WiFi 6/6E - tri-band
                supports_24ghz=true
                supports_5ghz=true
                supports_6ghz=true
                ;;
            iwlwifi|ath10k*|ath10k_pci|ath9k*|rtw88*|rtw89*|rtl8*|brcmfmac*|brcmsmac*)
                # Dual-band adapters
                supports_24ghz=true
                supports_5ghz=true
                ;;
            *)
                # Unknown - assume 2.4GHz only
                supports_24ghz=true
                ;;
        esac
    fi

    # Export capabilities
    local iface_upper="${iface^^}"
    eval "export NET_WIFI_${iface_upper}_24GHZ=\"$supports_24ghz\""
    eval "export NET_WIFI_${iface_upper}_5GHZ=\"$supports_5ghz\""
    eval "export NET_WIFI_${iface_upper}_6GHZ=\"$supports_6ghz\""
    eval "export NET_WIFI_${iface_upper}_AP=\"true\""  # Assume AP mode supported
    eval "export NET_WIFI_${iface_upper}_TYPE=\"unknown\""

    if $supports_24ghz || $supports_5ghz; then
        log_info "  Bands detected: ${supports_24ghz:+2.4GHz }${supports_5ghz:+5GHz }${supports_6ghz:+6GHz}"
    else
        log_warn "  Could not detect supported bands for $iface"
    fi
}

detect_wifi_radio_capabilities() {
    # Detect radio capabilities including bands, modes, and features
    #
    # Args:
    #   $1 - Interface name
    #   $2 - PHY name

    local iface="$1"
    local phy="$2"

    if ! command -v iw &>/dev/null; then
        log_warn "iw not installed - cannot detect radio capabilities"
        return 1
    fi

    [ -z "$phy" ] && return 1

    local phy_info
    # Try multiple methods to get PHY info
    # Method 1: iw phy <name> (without 'info' subcommand)
    phy_info=$(iw phy "$phy" 2>/dev/null)

    # Method 2: Extract from iw list output for specific phy
    if [ -z "$phy_info" ] || ! echo "$phy_info" | grep -qE "[0-9]+ MHz"; then
        log_info "  Trying iw list for $phy..."
        phy_info=$(iw list 2>/dev/null | sed -n "/^Wiphy $phy$/,/^Wiphy /p" | head -n -1)
    fi

    # Method 3: Use full iw list if single phy
    if [ -z "$phy_info" ] || ! echo "$phy_info" | grep -qE "[0-9]+ MHz"; then
        log_info "  Using full iw list output..."
        phy_info=$(iw list 2>/dev/null)
    fi

    # Method 4: For ath12k/newer drivers, try iw dev directly
    if [ -z "$phy_info" ] || ! echo "$phy_info" | grep -qE "[0-9]+ MHz"; then
        log_info "  Trying iw dev $iface scan frequencies..."
        # Get available frequencies from channel list
        phy_info=$(iw phy "$phy" channels 2>/dev/null)
    fi

    # Check if we got any frequency data
    if [ -z "$phy_info" ] || ! echo "$phy_info" | grep -qE "[0-9]+ MHz"; then
        log_warn "  No frequency data found via iw - checking sysfs"
        # Last resort: check if phy directories exist for bands
        if [ -d "/sys/class/ieee80211/$phy" ]; then
            # Just use iw list and assume it works
            phy_info=$(iw list 2>/dev/null)
        fi
    fi

    # Debug: Show if we found frequencies
    local freq_count
    freq_count=$(echo "$phy_info" | grep -cE "[0-9]+ MHz" 2>/dev/null || echo "0")
    log_info "  Frequencies found: $freq_count"

    # Detect supported bands
    local supports_24ghz=false
    local supports_5ghz=false
    local supports_6ghz=false
    local supports_80211n=false
    local supports_80211ac=false
    local supports_80211ax=false
    local supports_80211be=false  # WiFi 7
    local supports_ap=false
    local supports_vap=false

    # Get driver name for fallback logic
    local driver
    driver=$(get_interface_driver "$iface")

    # Band detection using frequency ranges (more reliable than "Band N:" which varies by driver)
    # 2.4GHz: 2412-2484 MHz (channels 1-14)
    # 5GHz:   5180-5825 MHz (channels 36-165)
    # 6GHz:   5925-7125 MHz (WiFi 6E/7)
    #
    # Note: Match frequency numbers only - output format varies by driver/kernel
    if echo "$phy_info" | grep -qE "24[0-9][0-9] MHz"; then
        supports_24ghz=true
    fi
    if echo "$phy_info" | grep -qE "5[0-9][0-9][0-9] MHz"; then
        supports_5ghz=true
    fi
    if echo "$phy_info" | grep -qE "(59[2-9][0-9]|6[0-9][0-9][0-9]|7[0-1][0-9][0-9]) MHz"; then
        supports_6ghz=true
    fi

    # Driver-based fallback for known modern WiFi chipsets
    # When iw commands don't return parseable frequency data, use driver knowledge
    if ! $supports_24ghz && ! $supports_5ghz; then
        log_info "  Frequency detection failed, checking driver: $driver"
        case "$driver" in
            ath12k*|ath12k_pci)
                # Qualcomm WiFi 7 (802.11be) - supports 2.4/5/6GHz
                log_info "  Driver $driver is WiFi 7 - assuming tri-band support"
                supports_24ghz=true
                supports_5ghz=true
                supports_6ghz=true
                supports_80211n=true
                supports_80211ac=true
                supports_80211ax=true
                supports_80211be=true
                supports_ap=true
                ;;
            ath11k*|ath11k_pci)
                # Qualcomm WiFi 6/6E - supports 2.4/5/6GHz
                log_info "  Driver $driver is WiFi 6E - assuming tri-band support"
                supports_24ghz=true
                supports_5ghz=true
                supports_6ghz=true
                supports_80211n=true
                supports_80211ac=true
                supports_80211ax=true
                supports_ap=true
                ;;
            mt76*|mt7921*|mt7922*)
                # MediaTek WiFi 6/6E - dual/tri-band
                log_info "  Driver $driver is WiFi 6/6E - assuming dual-band support"
                supports_24ghz=true
                supports_5ghz=true
                supports_80211n=true
                supports_80211ac=true
                supports_80211ax=true
                supports_ap=true
                ;;
            iwlwifi)
                # Intel WiFi - check for AX/BE in module info or assume dual-band
                log_info "  Driver $driver - assuming dual-band WiFi 6 support"
                supports_24ghz=true
                supports_5ghz=true
                supports_80211n=true
                supports_80211ac=true
                supports_80211ax=true
                supports_ap=true
                ;;
            ath10k*|ath10k_pci)
                # Qualcomm WiFi 5 - dual-band
                log_info "  Driver $driver is WiFi 5 - assuming dual-band support"
                supports_24ghz=true
                supports_5ghz=true
                supports_80211n=true
                supports_80211ac=true
                supports_ap=true
                ;;
            ath9k*)
                # Atheros WiFi 4 - typically dual-band
                log_info "  Driver $driver is WiFi 4 - assuming dual-band support"
                supports_24ghz=true
                supports_5ghz=true
                supports_80211n=true
                supports_ap=true
                ;;
            rtw88*|rtw89*|rtl8*|r8188*|r8192*)
                # Realtek WiFi adapters - typically dual-band for modern ones
                log_info "  Driver $driver - assuming dual-band support"
                supports_24ghz=true
                supports_5ghz=true
                supports_80211n=true
                supports_80211ac=true
                supports_ap=true
                ;;
            brcmfmac*|brcmsmac*)
                # Broadcom WiFi - typically dual-band
                log_info "  Driver $driver - assuming dual-band support"
                supports_24ghz=true
                supports_5ghz=true
                supports_80211n=true
                supports_80211ac=true
                supports_ap=true
                ;;
            *)
                # Unknown driver - assume at least 2.4GHz
                log_warn "  Unknown driver $driver - assuming 2.4GHz only"
                supports_24ghz=true
                supports_80211n=true
                supports_ap=true
                ;;
        esac
    fi

    # Check 802.11 capabilities
    if echo "$phy_info" | grep -qE "HT[24]0|HT Capabilities"; then
        supports_80211n=true
    fi
    if echo "$phy_info" | grep -qE "VHT|vht_capab"; then
        supports_80211ac=true
    fi
    if echo "$phy_info" | grep -qE "HE Capabilities|HE PHY"; then
        supports_80211ax=true
    fi
    # WiFi 7 (802.11be) uses EHT (Extremely High Throughput)
    if echo "$phy_info" | grep -qE "EHT Capabilities|EHT PHY|EHT MAC"; then
        supports_80211be=true
    fi

    # Check interface modes
    if echo "$phy_info" | grep -A 20 "Supported interface modes" | grep -q "\* AP"; then
        supports_ap=true
    fi
    if echo "$phy_info" | grep -A 20 "Supported interface modes" | grep -q "AP/VLAN"; then
        supports_vap=true
    fi

    # Get max TX power and antennas
    local max_tx_power
    max_tx_power=$(echo "$phy_info" | grep -m1 "max TX power" | awk '{print $NF}')

    local antennas_tx antennas_rx
    antennas_tx=$(echo "$phy_info" | grep "Available Antennas:" | awk '{print $NF}' | cut -d'x' -f1)
    antennas_rx=$(echo "$phy_info" | grep "Available Antennas:" | awk '{print $NF}' | cut -d'x' -f2)

    # Classify radio type
    local radio_type="single-band"
    if $supports_24ghz && $supports_5ghz; then
        radio_type="dual-band"
    fi
    if $supports_6ghz; then
        radio_type="tri-band"
    fi

    # WiFi generation
    local wifi_gen="WiFi 4 (802.11n)"
    if $supports_80211be; then
        wifi_gen="WiFi 7 (802.11be)"
    elif $supports_80211ax; then
        if $supports_6ghz; then
            wifi_gen="WiFi 6E (802.11ax)"
        else
            wifi_gen="WiFi 6 (802.11ax)"
        fi
    elif $supports_80211ac; then
        wifi_gen="WiFi 5 (802.11ac)"
    fi

    log_info "  Bands: $(echo "${supports_24ghz:+2.4GHz }${supports_5ghz:+5GHz }${supports_6ghz:+6GHz}" | xargs)"
    log_info "  Generation: $wifi_gen"
    log_info "  Radio Type: $radio_type"
    log_info "  AP Mode: $($supports_ap && echo "supported" || echo "not supported")"
    log_info "  VAP/VLAN: $($supports_vap && echo "supported" || echo "not supported")"
    [ -n "$max_tx_power" ] && log_info "  Max TX Power: $max_tx_power"

    # Export capabilities for this interface
    eval "export NET_WIFI_${iface^^}_PHY=\"$phy\""
    eval "export NET_WIFI_${iface^^}_24GHZ=\"$supports_24ghz\""
    eval "export NET_WIFI_${iface^^}_5GHZ=\"$supports_5ghz\""
    eval "export NET_WIFI_${iface^^}_6GHZ=\"$supports_6ghz\""
    eval "export NET_WIFI_${iface^^}_80211N=\"$supports_80211n\""
    eval "export NET_WIFI_${iface^^}_80211AC=\"$supports_80211ac\""
    eval "export NET_WIFI_${iface^^}_80211AX=\"$supports_80211ax\""
    eval "export NET_WIFI_${iface^^}_80211BE=\"$supports_80211be\""
    eval "export NET_WIFI_${iface^^}_AP=\"$supports_ap\""
    eval "export NET_WIFI_${iface^^}_VAP=\"$supports_vap\""
    eval "export NET_WIFI_${iface^^}_TYPE=\"$radio_type\""
    eval "export NET_WIFI_${iface^^}_GEN=\"$wifi_gen\""
}

classify_wifi_for_dual_band() {
    # Determine WiFi configuration strategy for dual-band operation
    #
    # Strategies:
    #   1. Single dual-band radio: Create one hostapd, let clients choose band
    #   2. Two single-band radios: Create two hostapds (2.4GHz + 5GHz)
    #   3. Multiple dual-band radios: Use first for 2.4GHz, second for 5GHz

    log_section "Dual-Band WiFi Configuration Strategy"

    local wifi_24ghz=""
    local wifi_5ghz=""
    local wifi_6ghz=""
    local dual_band_iface=""

    for iface in $NET_WIFI_INTERFACES; do
        local iface_upper="${iface^^}"
        local has_24 has_5 has_6
        eval "has_24=\$NET_WIFI_${iface_upper}_24GHZ"
        eval "has_5=\$NET_WIFI_${iface_upper}_5GHZ"
        eval "has_6=\$NET_WIFI_${iface_upper}_6GHZ"

        if [ "$has_24" = "true" ] && [ "$has_5" = "true" ]; then
            # Dual-band radio
            if [ -z "$dual_band_iface" ]; then
                dual_band_iface="$iface"
                # Use first dual-band for both (hostapd can handle band steering)
                wifi_24ghz="$iface"
                wifi_5ghz="$iface"
                log_info "Dual-band radio: $iface (will serve 2.4GHz + 5GHz)"
            else
                # Second dual-band radio - dedicate to 5GHz
                wifi_5ghz="$iface"
                log_info "Second dual-band radio: $iface (dedicated to 5GHz)"
            fi
        elif [ "$has_24" = "true" ]; then
            # 2.4GHz only
            wifi_24ghz="$iface"
            log_info "2.4GHz only radio: $iface"
        elif [ "$has_5" = "true" ]; then
            # 5GHz only
            wifi_5ghz="$iface"
            log_info "5GHz only radio: $iface"
        fi

        if [ "$has_6" = "true" ]; then
            wifi_6ghz="$iface"
            log_info "6GHz support: $iface"
        fi
    done

    # Determine configuration mode
    local wifi_config_mode="none"

    if [ -n "$wifi_24ghz" ] && [ -n "$wifi_5ghz" ]; then
        if [ "$wifi_24ghz" = "$wifi_5ghz" ]; then
            wifi_config_mode="single-dual-band"
            log_success "Config Mode: Single dual-band radio (2.4GHz + 5GHz same interface)"
        else
            wifi_config_mode="separate-radios"
            log_success "Config Mode: Separate radios (2.4GHz: $wifi_24ghz, 5GHz: $wifi_5ghz)"
        fi
    elif [ -n "$wifi_24ghz" ]; then
        wifi_config_mode="24ghz-only"
        log_success "Config Mode: 2.4GHz only"
    elif [ -n "$wifi_5ghz" ]; then
        wifi_config_mode="5ghz-only"
        log_success "Config Mode: 5GHz only"
    fi

    export NET_WIFI_24GHZ_IFACE="$wifi_24ghz"
    export NET_WIFI_5GHZ_IFACE="$wifi_5ghz"
    export NET_WIFI_6GHZ_IFACE="$wifi_6ghz"
    export NET_WIFI_CONFIG_MODE="$wifi_config_mode"
}

# ============================================================
# WWAN/MODEM INTERFACE DETECTION
# ============================================================

detect_wwan_interfaces() {
    # Detect WWAN/LTE modem interfaces
    #
    # WWAN interfaces use double 'w' prefix (wwan*, wwp*)
    # to distinguish from WiFi (wlan*, wlp*)

    log_section "WWAN/Modem Interface Detection"

    local -a wwan_interfaces=()
    local control_device=""

    # Find WWAN network interfaces
    for iface_path in /sys/class/net/*; do
        [ -d "$iface_path" ] || continue
        local iface
        iface=$(basename "$iface_path")

        # Match WWAN patterns (double 'w')
        if [[ "$iface" =~ ^($WWAN_IFACE_PATTERNS)$ ]]; then
            wwan_interfaces+=("$iface")

            local driver mac
            driver=$(get_interface_driver "$iface")
            mac=$(get_interface_mac "$iface")

            log_info "Found WWAN: $iface"
            log_info "  Driver: ${driver:-unknown}"
            log_info "  MAC: ${mac:-none}"
        fi
    done

    # Find modem control devices
    local control_devices=()

    # QMI/MBIM devices (preferred)
    for dev in /dev/cdc-wdm*; do
        if [ -c "$dev" ]; then
            control_devices+=("$dev")
            log_info "Found control device: $dev (QMI/MBIM)"
        fi
    done 2>/dev/null

    # AT command devices (fallback)
    for dev in /dev/ttyUSB*; do
        if [ -c "$dev" ]; then
            # ttyUSB2 is typically the AT command port
            if [ "$(basename "$dev")" = "ttyUSB2" ]; then
                control_devices+=("$dev")
                log_info "Found control device: $dev (AT command)"
            fi
        fi
    done 2>/dev/null

    # Check ModemManager
    if command -v mmcli &>/dev/null && systemctl is-active --quiet ModemManager 2>/dev/null; then
        local modem_list
        modem_list=$(mmcli -L 2>/dev/null | grep -oP '/org/freedesktop/ModemManager1/Modem/\d+' | head -1)

        if [ -n "$modem_list" ]; then
            local modem_idx
            modem_idx=$(basename "$modem_list")

            local mm_info
            mm_info=$(mmcli -m "$modem_idx" 2>/dev/null)

            local mm_model mm_state
            mm_model=$(echo "$mm_info" | grep -E "model:" | head -1 | awk -F: '{print $2}' | xargs)
            mm_state=$(echo "$mm_info" | grep -E "state:" | head -1 | awk -F: '{print $2}' | xargs)

            log_info "ModemManager: modem $modem_idx"
            [ -n "$mm_model" ] && log_info "  Model: $mm_model"
            [ -n "$mm_state" ] && log_info "  State: $mm_state"
        fi
    fi

    # Check for USB modems via lsusb
    if command -v lsusb &>/dev/null; then
        # Known LTE modem vendors
        local known_modems=$(lsusb 2>/dev/null | grep -iE "2c7c|1199|12d1|19d2|2cb7|1bc7|quectel|sierra|huawei|fibocom" | head -3)
        if [ -n "$known_modems" ]; then
            log_info "USB Modems detected:"
            echo "$known_modems" | while read -r line; do
                log_info "  $line"
            done
        fi
    fi

    # Set primary WWAN interface
    local primary_wwan=""
    if [ ${#wwan_interfaces[@]} -gt 0 ]; then
        primary_wwan="${wwan_interfaces[0]}"
    fi

    # Set primary control device
    local primary_control=""
    if [ ${#control_devices[@]} -gt 0 ]; then
        primary_control="${control_devices[0]}"
    fi

    export NET_WWAN_INTERFACES="${wwan_interfaces[*]}"
    export NET_WWAN_COUNT=${#wwan_interfaces[@]}
    export NET_WWAN_IFACE="$primary_wwan"
    export NET_WWAN_CONTROL="$primary_control"

    if [ "$NET_WWAN_COUNT" -gt 0 ]; then
        log_success "Found $NET_WWAN_COUNT WWAN interface(s): $NET_WWAN_INTERFACES"
        log_success "Primary WWAN: ${NET_WWAN_IFACE:-none}"
        log_success "Control Device: ${NET_WWAN_CONTROL:-none}"
    else
        log_info "No WWAN interfaces detected"
    fi
}

configure_wwan_nmcli() {
    # Configure WWAN modem using NetworkManager (nmcli)
    #
    # Args:
    #   $1 - APN name
    #   $2 - Auth type (none, pap, chap, mschapv2)
    #   $3 - Username (optional)
    #   $4 - Password (optional)

    local apn="${1:-internet}"
    local auth_type="${2:-none}"
    local username="$3"
    local password="$4"

    if ! command -v nmcli &>/dev/null; then
        log_error "NetworkManager not installed"
        return 1
    fi

    # Find modem device for nmcli
    local modem_device=""

    # Prefer CDC-WDM device
    for dev in /dev/cdc-wdm*; do
        if [ -c "$dev" ]; then
            modem_device=$(basename "$dev")
            break
        fi
    done 2>/dev/null

    if [ -z "$modem_device" ]; then
        log_error "No modem control device found"
        return 1
    fi

    local con_name="fortress-lte"

    log_info "Configuring WWAN via nmcli"
    log_info "  Device: $modem_device"
    log_info "  APN: $apn"
    log_info "  Auth: $auth_type"

    # Delete existing connection
    nmcli con delete "$con_name" 2>/dev/null || true

    # Build connection command
    local nmcli_cmd="nmcli con add type gsm ifname \"$modem_device\" con-name \"$con_name\" apn \"$apn\" ipv4.method auto"

    if [ "$auth_type" != "none" ] && [ -n "$username" ]; then
        nmcli_cmd="$nmcli_cmd gsm.username \"$username\""
        [ -n "$password" ] && nmcli_cmd="$nmcli_cmd gsm.password \"$password\" gsm.password-flags 0"
    fi

    if eval "$nmcli_cmd"; then
        log_success "WWAN connection '$con_name' created"
        export NET_WWAN_CONNECTION="$con_name"
        return 0
    else
        log_error "Failed to create WWAN connection"
        return 1
    fi
}

# ============================================================
# SCAN WIFI CHANNELS
# ============================================================

scan_wifi_channels_24ghz() {
    # Scan 2.4GHz channels and find best one (least congested)
    # Channels: 1, 6, 11 (non-overlapping)

    local iface="$1"

    if ! command -v iw &>/dev/null; then
        echo "6"  # Default to channel 6
        return
    fi

    log_info "Scanning 2.4GHz channels on $iface..."

    # Bring interface up temporarily
    ip link set "$iface" up 2>/dev/null || true
    sleep 1

    # Trigger scan
    iw dev "$iface" scan 2>/dev/null || true
    sleep 2

    # Count networks per channel
    local ch1_count=0 ch6_count=0 ch11_count=0

    while read -r line; do
        case "$line" in
            1) ch1_count=$((ch1_count + 1)) ;;
            6) ch6_count=$((ch6_count + 1)) ;;
            11) ch11_count=$((ch11_count + 1)) ;;
            2|3|4|5) ch1_count=$((ch1_count + 1)); ch6_count=$((ch6_count + 1)) ;;
            7|8|9|10) ch6_count=$((ch6_count + 1)); ch11_count=$((ch11_count + 1)) ;;
        esac
    done < <(iw dev "$iface" scan 2>/dev/null | grep "DS Parameter set: channel" | awk '{print $NF}')

    # Find least congested
    local best_channel=6
    local min_count=$ch6_count

    if [ "$ch1_count" -lt "$min_count" ]; then
        best_channel=1
        min_count=$ch1_count
    fi

    if [ "$ch11_count" -lt "$min_count" ]; then
        best_channel=11
        min_count=$ch11_count
    fi

    log_info "  Channel 1: $ch1_count networks"
    log_info "  Channel 6: $ch6_count networks"
    log_info "  Channel 11: $ch11_count networks"
    log_success "Best 2.4GHz channel: $best_channel ($min_count networks)"

    echo "$best_channel"
}

scan_wifi_channels_5ghz() {
    # Scan 5GHz channels and find best one
    # UNII-1: 36, 40, 44, 48 (lower power, indoor)
    # UNII-3: 149, 153, 157, 161, 165 (higher power)

    local iface="$1"

    if ! command -v iw &>/dev/null; then
        echo "36"  # Default to channel 36
        return
    fi

    log_info "Scanning 5GHz channels on $iface..."

    # Bring interface up temporarily
    ip link set "$iface" up 2>/dev/null || true
    sleep 1

    # Count networks per channel band
    local unii1_count=0 unii3_count=0

    while read -r freq; do
        if [[ "$freq" -ge 5170 && "$freq" -le 5250 ]]; then
            unii1_count=$((unii1_count + 1))
        elif [[ "$freq" -ge 5735 && "$freq" -le 5835 ]]; then
            unii3_count=$((unii3_count + 1))
        fi
    done < <(iw dev "$iface" scan 2>/dev/null | grep "freq:" | awk '{print $2}')

    # Prefer UNII-3 (higher power, better range) if less congested
    local best_channel
    if [ "$unii3_count" -le "$unii1_count" ]; then
        best_channel=149
        log_info "  UNII-1 (36-48): $unii1_count networks"
        log_info "  UNII-3 (149-165): $unii3_count networks"
        log_success "Best 5GHz channel: 149 (UNII-3, less congested)"
    else
        best_channel=36
        log_info "  UNII-1 (36-48): $unii1_count networks"
        log_info "  UNII-3 (149-165): $unii3_count networks"
        log_success "Best 5GHz channel: 36 (UNII-1, less congested)"
    fi

    echo "$best_channel"
}

# ============================================================
# STATE PERSISTENCE
# ============================================================

save_network_state() {
    # Save detected network configuration to state file

    mkdir -p "$STATE_DIR"

    cat > "$INTERFACE_STATE_FILE" << EOF
# Fortress Network Interface Configuration
# Generated: $(date -Iseconds)
# Do not edit manually

# Ethernet Interfaces
NET_ETH_INTERFACES="$NET_ETH_INTERFACES"
NET_ETH_COUNT="$NET_ETH_COUNT"
NET_WAN_IFACE="$NET_WAN_IFACE"
NET_LAN_IFACES="$NET_LAN_IFACES"

# WiFi Interfaces
NET_WIFI_INTERFACES="$NET_WIFI_INTERFACES"
NET_WIFI_COUNT="$NET_WIFI_COUNT"
NET_WIFI_24GHZ_IFACE="$NET_WIFI_24GHZ_IFACE"
NET_WIFI_5GHZ_IFACE="$NET_WIFI_5GHZ_IFACE"
NET_WIFI_6GHZ_IFACE="$NET_WIFI_6GHZ_IFACE"
NET_WIFI_CONFIG_MODE="$NET_WIFI_CONFIG_MODE"

# WWAN Interfaces
NET_WWAN_INTERFACES="$NET_WWAN_INTERFACES"
NET_WWAN_COUNT="$NET_WWAN_COUNT"
NET_WWAN_IFACE="$NET_WWAN_IFACE"
NET_WWAN_CONTROL="$NET_WWAN_CONTROL"
EOF

    # Save per-interface WiFi capabilities
    for iface in $NET_WIFI_INTERFACES; do
        local iface_upper="${iface^^}"
        cat >> "$INTERFACE_STATE_FILE" << EOF

# WiFi Interface: $iface
NET_WIFI_${iface_upper}_PHY="$(eval echo \$NET_WIFI_${iface_upper}_PHY)"
NET_WIFI_${iface_upper}_24GHZ="$(eval echo \$NET_WIFI_${iface_upper}_24GHZ)"
NET_WIFI_${iface_upper}_5GHZ="$(eval echo \$NET_WIFI_${iface_upper}_5GHZ)"
NET_WIFI_${iface_upper}_6GHZ="$(eval echo \$NET_WIFI_${iface_upper}_6GHZ)"
NET_WIFI_${iface_upper}_80211N="$(eval echo \$NET_WIFI_${iface_upper}_80211N)"
NET_WIFI_${iface_upper}_80211AC="$(eval echo \$NET_WIFI_${iface_upper}_80211AC)"
NET_WIFI_${iface_upper}_80211AX="$(eval echo \$NET_WIFI_${iface_upper}_80211AX)"
NET_WIFI_${iface_upper}_AP="$(eval echo \$NET_WIFI_${iface_upper}_AP)"
NET_WIFI_${iface_upper}_VAP="$(eval echo \$NET_WIFI_${iface_upper}_VAP)"
NET_WIFI_${iface_upper}_TYPE="$(eval echo \$NET_WIFI_${iface_upper}_TYPE)"
NET_WIFI_${iface_upper}_GEN="$(eval echo \$NET_WIFI_${iface_upper}_GEN)"
EOF
    done

    chmod 644 "$INTERFACE_STATE_FILE"
    log_success "Network state saved to $INTERFACE_STATE_FILE"
}

load_network_state() {
    # Load previously detected network configuration

    if [ -f "$INTERFACE_STATE_FILE" ]; then
        source "$INTERFACE_STATE_FILE"
        return 0
    fi
    return 1
}

# ============================================================
# SUMMARY
# ============================================================

print_network_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Fortress - Network Interface Summary${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Ethernet:${NC}"
    echo -e "    WAN:          ${NET_WAN_IFACE:-none}"
    echo -e "    LAN:          ${NET_LAN_IFACES:-none}"
    echo -e "    Total:        $NET_ETH_COUNT interface(s)"
    echo ""
    echo -e "  ${GREEN}WiFi:${NC}"
    echo -e "    2.4GHz:       ${NET_WIFI_24GHZ_IFACE:-none}"
    echo -e "    5GHz:         ${NET_WIFI_5GHZ_IFACE:-none}"
    echo -e "    6GHz:         ${NET_WIFI_6GHZ_IFACE:-none}"
    echo -e "    Config Mode:  ${NET_WIFI_CONFIG_MODE:-none}"
    echo -e "    Total:        $NET_WIFI_COUNT interface(s)"
    echo ""
    echo -e "  ${GREEN}WWAN/LTE:${NC}"
    echo -e "    Interface:    ${NET_WWAN_IFACE:-none}"
    echo -e "    Control:      ${NET_WWAN_CONTROL:-none}"
    echo -e "    Total:        $NET_WWAN_COUNT interface(s)"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

detect_all_interfaces() {
    # Main detection function - detects all network interfaces

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  HookProbe Fortress - Network Interface Detection${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"

    # Detect each type
    detect_ethernet_interfaces
    classify_wan_lan_interfaces
    detect_wifi_interfaces
    classify_wifi_for_dual_band
    detect_wwan_interfaces

    # Save state
    save_network_state

    # Print summary
    print_network_summary
}

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  detect           - Detect all network interfaces"
    echo "  ethernet         - Detect Ethernet interfaces only"
    echo "  wifi             - Detect WiFi interfaces only"
    echo "  wwan             - Detect WWAN/LTE interfaces only"
    echo "  scan-24ghz       - Scan 2.4GHz WiFi channels"
    echo "  scan-5ghz        - Scan 5GHz WiFi channels"
    echo "  summary          - Print current interface summary"
    echo "  load             - Load saved interface configuration"
    echo "  configure-wwan <apn> [auth] [user] [pass]"
    echo "                   - Configure WWAN with nmcli"
    echo ""
    echo "Examples:"
    echo "  $0 detect"
    echo "  $0 configure-wwan internet.vodafone.ro"
    echo "  $0 configure-wwan private.apn chap myuser mypass"
    echo ""
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-detect}" in
        detect|all)
            detect_all_interfaces
            ;;
        ethernet|eth)
            detect_ethernet_interfaces
            classify_wan_lan_interfaces
            ;;
        wifi|wlan)
            detect_wifi_interfaces
            classify_wifi_for_dual_band
            ;;
        wwan|lte)
            detect_wwan_interfaces
            ;;
        scan-24ghz|scan24)
            iface="${2:-$NET_WIFI_24GHZ_IFACE}"
            [ -z "$iface" ] && load_network_state && iface="$NET_WIFI_24GHZ_IFACE"
            [ -z "$iface" ] && { echo "No 2.4GHz interface specified"; exit 1; }
            scan_wifi_channels_24ghz "$iface"
            ;;
        scan-5ghz|scan5)
            iface="${2:-$NET_WIFI_5GHZ_IFACE}"
            [ -z "$iface" ] && load_network_state && iface="$NET_WIFI_5GHZ_IFACE"
            [ -z "$iface" ] && { echo "No 5GHz interface specified"; exit 1; }
            scan_wifi_channels_5ghz "$iface"
            ;;
        summary)
            load_network_state || detect_all_interfaces
            print_network_summary
            ;;
        load)
            if load_network_state; then
                print_network_summary
            else
                echo "No saved state found, run 'detect' first"
                exit 1
            fi
            ;;
        configure-wwan)
            configure_wwan_nmcli "$2" "${3:-none}" "$4" "$5"
            ;;
        *)
            usage
            ;;
    esac
fi
