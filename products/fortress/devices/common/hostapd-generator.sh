#!/bin/bash
#
# hostapd-generator.sh - Dual-Band WiFi hostapd Configuration Generator
# Part of HookProbe Fortress - Small Business Security Gateway
#
# Generates hostapd configuration for dual-band WiFi with:
#   - 2.4GHz: WPA2 for legacy/IoT device compatibility
#   - 5GHz: WPA3/WPA2 mixed mode for modern devices
#
# Supports:
#   - Single dual-band radio (one hostapd, band steering)
#   - Separate radios (two hostapds, dedicated bands)
#   - WiFi 7 (802.11be), WiFi 6 (802.11ax) and WiFi 5 (802.11ac) features
#   - VLAN segregation via AP/VLAN mode
#   - Hardware band verification (detects 5GHz-only or 2.4GHz-only adapters)
#   - hostapd version detection (WiFi 6 requires 2.9+, WiFi 7 requires 2.11+)
#
# Version: 1.1.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source DFS/Regulatory management script if available
DFS_SCRIPT="$SCRIPT_DIR/wifi-regulatory-dfs.sh"
if [ -f "$DFS_SCRIPT" ]; then
    # shellcheck source=wifi-regulatory-dfs.sh
    source "$DFS_SCRIPT"
    DFS_AVAILABLE=true
else
    DFS_AVAILABLE=false
fi

# Configuration paths
HOSTAPD_DIR="/etc/hostapd"
HOSTAPD_24GHZ_CONF="$HOSTAPD_DIR/hostapd-24ghz.conf"
HOSTAPD_5GHZ_CONF="$HOSTAPD_DIR/hostapd-5ghz.conf"
HOSTAPD_DUAL_CONF="$HOSTAPD_DIR/hostapd.conf"
HOSTAPD_VLAN_FILE="$HOSTAPD_DIR/hostapd.vlan"

# State file from network-interface-detector.sh
INTERFACE_STATE_FILE="/var/lib/fortress/network-interfaces.conf"

# OVS Bridge Configuration
# Fortress uses OVS for SDN-based network segmentation
# WiFi interfaces are added to OVS bridge with VLAN tagging
DEFAULT_BRIDGE="${FORTRESS_BRIDGE:-43ess}"
SUBNET_PREFIX="${FORTRESS_SUBNET:-10.250}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Log to stderr so command substitution only captures return values
log_info() { echo -e "${CYAN}[WIFI]${NC} $*" >&2; }
log_success() { echo -e "${GREEN}[WIFI]${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}[WIFI]${NC} $*" >&2; }
log_error() { echo -e "${RED}[WIFI]${NC} $*" >&2; }

# ============================================================
# REGULATORY DOMAIN AUTO-DETECTION
# ============================================================

detect_regulatory_domain() {
    # Auto-detect regulatory domain for WiFi configuration
    #
    # Detection priority:
    #   1. Environment variable (WIFI_COUNTRY_CODE)
    #   2. Saved configuration (/etc/hookprobe/wifi.conf)
    #   3. Timezone-based detection (most reliable)
    #   4. Locale-based detection
    #   5. GeoIP lookup (if available)
    #   6. Default to US
    #
    # Returns: Two-letter ISO 3166-1 country code (e.g., US, GB, DE)

    # Check environment variable first
    if [ -n "$WIFI_COUNTRY_CODE" ]; then
        echo "${WIFI_COUNTRY_CODE^^}"
        return
    fi

    # Check saved configuration
    if [ -f /etc/hookprobe/wifi.conf ]; then
        local saved_country
        saved_country=$(grep "^WIFI_COUNTRY=" /etc/hookprobe/wifi.conf 2>/dev/null | cut -d= -f2 | tr -d '"')
        if [ -n "$saved_country" ]; then
            echo "${saved_country^^}"
            return
        fi
    fi

    # Timezone-based detection (most reliable offline method)
    local tz_country
    tz_country=$(detect_country_from_timezone)
    if [ -n "$tz_country" ]; then
        echo "$tz_country"
        return
    fi

    # Locale-based detection
    local locale_country
    locale_country=$(detect_country_from_locale)
    if [ -n "$locale_country" ]; then
        echo "$locale_country"
        return
    fi

    # GeoIP lookup (optional, requires internet)
    local geoip_country
    geoip_country=$(detect_country_from_geoip)
    if [ -n "$geoip_country" ]; then
        echo "$geoip_country"
        return
    fi

    # Default to US
    echo "US"
}

detect_country_from_timezone() {
    # Map timezone to country code
    # Uses timedatectl or /etc/timezone

    local timezone=""

    # Try timedatectl first
    if command -v timedatectl &>/dev/null; then
        timezone=$(timedatectl show -p Timezone --value 2>/dev/null)
    fi

    # Fallback to /etc/timezone
    if [ -z "$timezone" ] && [ -f /etc/timezone ]; then
        timezone=$(cat /etc/timezone 2>/dev/null)
    fi

    # Fallback to readlink /etc/localtime
    if [ -z "$timezone" ] && [ -L /etc/localtime ]; then
        timezone=$(readlink -f /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')
    fi

    [ -z "$timezone" ] && return 1

    # Map timezones to country codes
    # Common timezone → country mappings
    case "$timezone" in
        # Europe
        Europe/London|Europe/Belfast)                    echo "GB" ;;
        Europe/Dublin)                                   echo "IE" ;;
        Europe/Paris)                                    echo "FR" ;;
        Europe/Berlin|Europe/Munich)                     echo "DE" ;;
        Europe/Rome)                                     echo "IT" ;;
        Europe/Madrid|Europe/Barcelona)                  echo "ES" ;;
        Europe/Amsterdam)                                echo "NL" ;;
        Europe/Brussels)                                 echo "BE" ;;
        Europe/Vienna)                                   echo "AT" ;;
        Europe/Zurich)                                   echo "CH" ;;
        Europe/Stockholm)                                echo "SE" ;;
        Europe/Oslo)                                     echo "NO" ;;
        Europe/Copenhagen)                               echo "DK" ;;
        Europe/Helsinki)                                 echo "FI" ;;
        Europe/Warsaw)                                   echo "PL" ;;
        Europe/Prague)                                   echo "CZ" ;;
        Europe/Budapest)                                 echo "HU" ;;
        Europe/Bucharest)                                echo "RO" ;;
        Europe/Sofia)                                    echo "BG" ;;
        Europe/Athens)                                   echo "GR" ;;
        Europe/Istanbul)                                 echo "TR" ;;
        Europe/Moscow|Europe/St_Petersburg)              echo "RU" ;;
        Europe/Kiev|Europe/Kyiv)                         echo "UA" ;;
        Europe/Lisbon)                                   echo "PT" ;;

        # Americas
        America/New_York|America/Chicago|America/Denver|America/Los_Angeles)
                                                         echo "US" ;;
        America/Phoenix|America/Detroit|America/Indiana/*)
                                                         echo "US" ;;
        America/Anchorage|America/Juneau|US/*)           echo "US" ;;
        America/Toronto|America/Vancouver|America/Montreal|Canada/*)
                                                         echo "CA" ;;
        America/Mexico_City|America/Tijuana|America/Cancun)
                                                         echo "MX" ;;
        America/Sao_Paulo|America/Rio_Branco|Brazil/*)   echo "BR" ;;
        America/Argentina/*)                             echo "AR" ;;
        America/Santiago)                                echo "CL" ;;
        America/Lima)                                    echo "PE" ;;
        America/Bogota)                                  echo "CO" ;;

        # Asia Pacific
        Asia/Tokyo)                                      echo "JP" ;;
        Asia/Seoul)                                      echo "KR" ;;
        Asia/Shanghai|Asia/Hong_Kong|Asia/Chongqing)     echo "CN" ;;
        Asia/Taipei)                                     echo "TW" ;;
        Asia/Singapore)                                  echo "SG" ;;
        Asia/Bangkok)                                    echo "TH" ;;
        Asia/Jakarta)                                    echo "ID" ;;
        Asia/Kuala_Lumpur)                               echo "MY" ;;
        Asia/Manila)                                     echo "PH" ;;
        Asia/Ho_Chi_Minh|Asia/Hanoi)                     echo "VN" ;;
        Asia/Kolkata|Asia/Mumbai|Asia/Calcutta)          echo "IN" ;;
        Asia/Dubai)                                      echo "AE" ;;
        Asia/Riyadh)                                     echo "SA" ;;
        Asia/Jerusalem|Asia/Tel_Aviv)                    echo "IL" ;;

        # Oceania
        Australia/Sydney|Australia/Melbourne|Australia/Brisbane)
                                                         echo "AU" ;;
        Australia/Perth|Australia/Adelaide|Australia/*) echo "AU" ;;
        Pacific/Auckland|Pacific/Wellington|NZ)         echo "NZ" ;;

        # Africa
        Africa/Cairo)                                    echo "EG" ;;
        Africa/Johannesburg)                             echo "ZA" ;;
        Africa/Lagos)                                    echo "NG" ;;
        Africa/Nairobi)                                  echo "KE" ;;

        # Generic patterns
        US/*|America/US/*)                               echo "US" ;;
        *)
            # Try to extract country from timezone path (e.g., Europe/London → GB)
            # This is a fallback for less common timezones
            return 1
            ;;
    esac
}

detect_country_from_locale() {
    # Extract country from system locale (e.g., en_US.UTF-8 → US)

    local locale=""

    # Try LANG environment variable
    locale="${LANG:-}"

    # Fallback to localectl
    if [ -z "$locale" ] && command -v localectl &>/dev/null; then
        locale=$(localectl status 2>/dev/null | grep "System Locale" | sed 's/.*LANG=//' | cut -d' ' -f1)
    fi

    # Fallback to /etc/default/locale
    if [ -z "$locale" ] && [ -f /etc/default/locale ]; then
        locale=$(grep "^LANG=" /etc/default/locale 2>/dev/null | cut -d= -f2 | tr -d '"')
    fi

    [ -z "$locale" ] && return 1

    # Extract country code (e.g., en_US.UTF-8 → US, de_DE → DE)
    local country
    country=$(echo "$locale" | sed -n 's/.*_\([A-Z][A-Z]\).*/\1/p')

    if [ -n "$country" ] && [ ${#country} -eq 2 ]; then
        echo "$country"
        return 0
    fi

    return 1
}

detect_country_from_geoip() {
    # Use GeoIP lookup to detect country
    # Only used as last resort (requires internet)

    # Check if we have internet connectivity (quick check)
    if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null && ! ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        return 1
    fi

    local country=""

    # Try multiple GeoIP services (all return plain text country code)
    for service in \
        "http://ip-api.com/line/?fields=countryCode" \
        "https://ipapi.co/country/" \
        "https://ifconfig.co/country-iso"; do

        country=$(curl -sf --max-time 3 "$service" 2>/dev/null | head -1 | tr -d '\r\n')

        if [ -n "$country" ] && [ ${#country} -eq 2 ]; then
            echo "${country^^}"
            return 0
        fi
    done

    return 1
}

save_regulatory_domain() {
    # Save detected regulatory domain to config
    local country="$1"

    mkdir -p /etc/hookprobe

    if [ -f /etc/hookprobe/wifi.conf ]; then
        # Update existing config
        if grep -q "^WIFI_COUNTRY=" /etc/hookprobe/wifi.conf; then
            sed -i "s/^WIFI_COUNTRY=.*/WIFI_COUNTRY=\"$country\"/" /etc/hookprobe/wifi.conf
        else
            echo "WIFI_COUNTRY=\"$country\"" >> /etc/hookprobe/wifi.conf
        fi
    else
        # Create new config
        echo "WIFI_COUNTRY=\"$country\"" > /etc/hookprobe/wifi.conf
    fi

    log_info "Regulatory domain saved: $country"
}

# ============================================================
# HOSTAPD VERSION DETECTION
# ============================================================

get_hostapd_version() {
    # Get hostapd version as a comparable number
    # Returns: Version string (e.g., "2.10", "2.11") or empty if not found

    local version=""

    if command -v hostapd &>/dev/null; then
        # hostapd -v outputs version to stderr
        version=$(hostapd -v 2>&1 | head -1 | grep -oE 'v[0-9]+\.[0-9]+' | sed 's/v//')

        # Alternative parsing if first method fails
        if [ -z "$version" ]; then
            version=$(hostapd -v 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        fi
    fi

    echo "$version"
}

check_hostapd_supports_wifi7() {
    # Check if hostapd supports WiFi 7 (802.11be/EHT)
    # WiFi 7 support requires hostapd 2.11 or later
    #
    # Returns: 0 (true) if supported, 1 (false) if not

    local version
    version=$(get_hostapd_version)

    if [ -z "$version" ]; then
        log_warn "hostapd not found, cannot determine WiFi 7 support"
        return 1
    fi

    # Parse major.minor version
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    # WiFi 7 (EHT) requires hostapd 2.11+
    if [ "${major:-0}" -gt 2 ]; then
        return 0
    elif [ "${major:-0}" -eq 2 ] && [ "${minor:-0}" -ge 11 ]; then
        return 0
    fi

    log_warn "hostapd $version does not support WiFi 7 (requires 2.11+)"
    return 1
}

check_hostapd_supports_wifi6() {
    # Check if hostapd supports WiFi 6 (802.11ax/HE)
    # WiFi 6 support requires hostapd 2.9 or later
    #
    # Returns: 0 (true) if supported, 1 (false) if not

    local version
    version=$(get_hostapd_version)

    if [ -z "$version" ]; then
        log_warn "hostapd not found, cannot determine WiFi 6 support"
        return 1
    fi

    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    # WiFi 6 (HE) requires hostapd 2.9+
    if [ "${major:-0}" -gt 2 ]; then
        return 0
    elif [ "${major:-0}" -eq 2 ] && [ "${minor:-0}" -ge 9 ]; then
        return 0
    fi

    log_warn "hostapd $version does not support WiFi 6 (requires 2.9+)"
    return 1
}

# ============================================================
# CAPABILITY DETECTION HELPERS
# ============================================================

get_phy_for_iface() {
    local iface="$1"
    if [ -L "/sys/class/net/$iface/phy80211" ]; then
        basename "$(readlink -f /sys/class/net/$iface/phy80211)"
    fi
}

get_phy_info() {
    # Get iw phy info for a specific phy
    # This handles multi-phy systems correctly by extracting only the relevant phy's section
    #
    # Args:
    #   $1 - phy name (e.g., "phy0", "phy1")
    #
    # Returns: The iw phy output for just this phy
    #
    # Note: "iw phy <name> info" doesn't work on some drivers like ath12k,
    #       so we parse "iw phy" output and extract the relevant section.

    local phy="$1"
    local phy_info=""

    # Method 1: Use awk to extract this specific phy's section
    # More reliable than sed for handling the last phy in the list
    phy_info=$(iw phy 2>/dev/null | awk -v phy="$phy" '
        /^Wiphy / { if (found) exit; if ($2 == phy) found=1 }
        found { print }
    ') || true

    # Method 2: Fallback to whole iw phy output if extraction failed
    if [ -z "$phy_info" ] || ! echo "$phy_info" | grep -qE "[0-9]+ MHz"; then
        phy_info=$(iw phy 2>/dev/null) || true
    fi

    # Method 3: Try iw list as last resort
    if [ -z "$phy_info" ] || ! echo "$phy_info" | grep -qE "[0-9]+ MHz"; then
        phy_info=$(iw list 2>/dev/null) || true
    fi

    echo "$phy_info"
}

get_wifi_driver() {
    # Get the WiFi driver name for an interface
    #
    # Args:
    #   $1 - Interface name
    #
    # Returns: Driver name (e.g., "ath12k_pci", "iwlwifi", "mt76x2u")

    local iface="$1"
    local driver=""

    # Method 1: Check /sys/class/net/*/device/driver
    if [ -L "/sys/class/net/$iface/device/driver" ]; then
        driver=$(basename "$(readlink -f /sys/class/net/$iface/device/driver)")
    fi

    # Method 2: Try phy80211 driver
    if [ -z "$driver" ] && [ -L "/sys/class/net/$iface/phy80211" ]; then
        local phy
        phy=$(basename "$(readlink -f /sys/class/net/$iface/phy80211)")
        if [ -L "/sys/class/ieee80211/$phy/device/driver" ]; then
            driver=$(basename "$(readlink -f /sys/class/ieee80211/$phy/device/driver)")
        fi
    fi

    # Method 3: ethtool -i
    if [ -z "$driver" ] && command -v ethtool &>/dev/null; then
        driver=$(ethtool -i "$iface" 2>/dev/null | grep "^driver:" | awk '{print $2}')
    fi

    echo "$driver"
}

is_ath12k_driver() {
    # Check if interface uses ath12k driver (WiFi 7 / QCN9274)
    # ath12k has known limitations:
    #   - fragm_threshold not supported (-95 Operation not supported)
    #   - "iw phy <name> info" doesn't work, must use "iw phy | sed"
    #
    # Args:
    #   $1 - Interface name
    #
    # Returns: 0 if ath12k, 1 otherwise

    local iface="$1"
    local driver
    driver=$(get_wifi_driver "$iface")

    case "$driver" in
        ath12k*|ath11k*)
            return 0
            ;;
    esac

    return 1
}

prepare_interface_for_hostapd() {
    # Prepare interface for hostapd by releasing it from other services
    #
    # This ensures NetworkManager and wpa_supplicant don't hold the interface
    # which would cause "Device or resource busy" errors
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"

    log_info "Preparing interface $iface for hostapd..."

    # Stop wpa_supplicant if running on this interface
    if pgrep -f "wpa_supplicant.*$iface" &>/dev/null; then
        log_info "  Stopping wpa_supplicant on $iface"
        pkill -f "wpa_supplicant.*-i$iface" 2>/dev/null || true
        pkill -f "wpa_supplicant.*$iface" 2>/dev/null || true
        sleep 1
    fi

    # Tell NetworkManager to unmanage this interface
    if command -v nmcli &>/dev/null; then
        # Check if NM is managing this interface
        if nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -q "^$iface:"; then
            log_info "  Setting $iface as unmanaged by NetworkManager"
            nmcli device set "$iface" managed no 2>/dev/null || true
        fi
    fi

    # Release any IP address
    ip addr flush dev "$iface" 2>/dev/null || true

    # Ensure interface is up but not connected
    ip link set "$iface" up 2>/dev/null || true

    # Set interface to monitor mode and back to managed to reset state
    # This clears any stale connection attempts
    iw dev "$iface" set type managed 2>/dev/null || true

    log_success "  Interface $iface prepared for hostapd"
}

is_ovs_bridge() {
    # Check if a bridge is an OVS bridge
    # Returns 0 (true) if OVS bridge, 1 (false) otherwise
    local bridge="$1"

    if command -v ovs-vsctl &>/dev/null; then
        ovs-vsctl br-exists "$bridge" 2>/dev/null && return 0
    fi
    return 1
}

ensure_bridge_exists() {
    # Ensure the bridge exists for hostapd
    #
    # Fortress prefers OVS bridges for SDN capabilities.
    # Falls back to Linux bridge if OVS is not available.
    #
    # Args:
    #   $1 - Bridge name (default: fortress OVS bridge)
    #   $2 - Gateway IP (default: 10.250.0.1)
    #   $3 - Netmask (default: 16)
    #
    # If bridge doesn't exist, create it

    local bridge="${1:-$DEFAULT_BRIDGE}"
    local gateway="${2:-${SUBNET_PREFIX}.0.1}"
    local netmask="${3:-16}"

    # Check if bridge already exists
    if ip link show "$bridge" &>/dev/null; then
        return 0
    fi

    log_info "Creating bridge $bridge..."

    # Prefer OVS bridge for SDN capabilities
    if command -v ovs-vsctl &>/dev/null; then
        log_info "  Using OVS bridge (SDN enabled)"

        # Create OVS bridge
        if ! ovs-vsctl br-exists "$bridge" 2>/dev/null; then
            ovs-vsctl add-br "$bridge" 2>/dev/null || {
                log_warn "Could not create OVS bridge $bridge"
                # Fall through to Linux bridge
            }
        fi

        # If OVS bridge was created successfully
        if ovs-vsctl br-exists "$bridge" 2>/dev/null; then
            ip link set "$bridge" up 2>/dev/null || true

            # Add IP if not already present
            if ! ip addr show "$bridge" 2>/dev/null | grep -q "$gateway"; then
                ip addr add "${gateway}/${netmask}" dev "$bridge" 2>/dev/null || true
            fi

            log_success "OVS bridge $bridge created with gateway $gateway/$netmask"
            return 0
        fi
    fi

    # Fallback: Try network-cleanup.sh if available
    if [ -x "$SCRIPT_DIR/network-cleanup.sh" ]; then
        "$SCRIPT_DIR/network-cleanup.sh" cleanup 2>/dev/null && return 0
    fi

    # Fallback: Linux bridge
    log_info "  Falling back to Linux bridge"
    if ! ip link add name "$bridge" type bridge 2>/dev/null; then
        log_warn "Could not create bridge $bridge (may need root)"
        return 1
    fi

    # Configure bridge
    ip link set "$bridge" up 2>/dev/null || true

    # Add IP if not already present
    if ! ip addr show "$bridge" 2>/dev/null | grep -q "$gateway"; then
        ip addr add "${gateway}/${netmask}" dev "$bridge" 2>/dev/null || true
    fi

    # Enable STP
    echo 1 > /sys/class/net/"$bridge"/bridge/stp_state 2>/dev/null || true

    log_success "Linux bridge $bridge created with gateway $gateway/$netmask"
    return 0
}

create_networkmanager_unmanaged_rule() {
    # Create udev/NetworkManager rule to mark WiFi AP interfaces as unmanaged
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"
    local nm_conf="/etc/NetworkManager/conf.d/10-fortress-unmanaged.conf"

    # Only if NetworkManager is installed
    if ! command -v nmcli &>/dev/null; then
        return 0
    fi

    mkdir -p /etc/NetworkManager/conf.d

    # Check if rule already exists
    if [ -f "$nm_conf" ] && grep -q "$iface" "$nm_conf"; then
        return 0
    fi

    log_info "Creating NetworkManager unmanaged rule for $iface"

    # Append to existing file or create new
    if [ -f "$nm_conf" ]; then
        # Add interface to keyfile unmanaged list if not in [keyfile] section
        if ! grep -q "\[keyfile\]" "$nm_conf"; then
            echo "" >> "$nm_conf"
            echo "[keyfile]" >> "$nm_conf"
            echo "unmanaged-devices=interface-name:$iface" >> "$nm_conf"
        else
            # Append to existing unmanaged-devices line
            sed -i "/^unmanaged-devices=/ s/$/;interface-name:$iface/" "$nm_conf"
        fi
    else
        cat > "$nm_conf" << EOF
# Fortress WiFi AP interfaces - do not manage with NetworkManager
[keyfile]
unmanaged-devices=interface-name:$iface
EOF
    fi

    # Reload NetworkManager if running
    if systemctl is-active --quiet NetworkManager; then
        nmcli general reload conf 2>/dev/null || true
    fi
}

verify_band_support() {
    # Verify that hardware actually supports a specific band
    # This checks the phy capabilities directly, not just the state file
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Band: "24ghz" or "5ghz"
    #
    # Returns: 0 (true) if supported, 1 (false) if not

    local iface="$1"
    local band="$2"
    local phy

    phy=$(get_phy_for_iface "$iface")
    [ -z "$phy" ] && return 1

    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    # First try frequency-based detection
    if [ -n "$phy_info" ]; then
        case "$band" in
            24ghz|2.4ghz)
                # 2.4GHz band frequencies: 2412-2484 MHz (channels 1-14)
                if echo "$phy_info" | grep -qE "24[0-9][0-9] MHz"; then
                    return 0
                fi
                ;;
            5ghz)
                # 5GHz band frequencies: 5180-5825 MHz (channels 36-165)
                if echo "$phy_info" | grep -qE "5[0-9][0-9][0-9] MHz"; then
                    return 0
                fi
                ;;
            6ghz)
                # 6GHz band frequencies: 5925-7125 MHz (WiFi 6E/7)
                if echo "$phy_info" | grep -qE "(59[2-9][0-9]|6[0-9][0-9][0-9]|7[0-1][0-9][0-9]) MHz"; then
                    return 0
                fi
                ;;
        esac
    fi

    # Driver-based fallback for known WiFi chipsets
    # When iw commands don't return parseable frequency data, use driver knowledge
    local driver
    driver=$(cat "/sys/class/net/$iface/device/driver/module/drivers/"*/uevent 2>/dev/null | grep "DRIVER=" | cut -d= -f2 | head -1)
    if [ -z "$driver" ]; then
        # Fallback to readlink method
        local driver_path="/sys/class/net/$iface/device/driver"
        if [ -L "$driver_path" ]; then
            driver=$(basename "$(readlink -f "$driver_path")" 2>/dev/null)
        fi
    fi

    log_info "  Band verification fallback: driver=$driver, band=$band"

    case "$driver" in
        ath12k*|ath12k_pci)
            # Qualcomm WiFi 7 - supports 2.4/5/6GHz
            case "$band" in
                24ghz|2.4ghz|5ghz|6ghz) return 0 ;;
            esac
            ;;
        ath11k*|ath11k_pci)
            # Qualcomm WiFi 6E - supports 2.4/5/6GHz
            case "$band" in
                24ghz|2.4ghz|5ghz|6ghz) return 0 ;;
            esac
            ;;
        mt76*|mt7921*|mt7922*)
            # MediaTek WiFi 6/6E - dual/tri-band
            case "$band" in
                24ghz|2.4ghz|5ghz|6ghz) return 0 ;;
            esac
            ;;
        iwlwifi|ath10k*|ath10k_pci|ath9k*)
            # Intel/Qualcomm dual-band adapters
            case "$band" in
                24ghz|2.4ghz|5ghz) return 0 ;;
            esac
            ;;
        rtw88*|rtw89*|rtl8*|r8188*|r8192*|brcmfmac*|brcmsmac*)
            # Realtek/Broadcom typically dual-band
            case "$band" in
                24ghz|2.4ghz|5ghz) return 0 ;;
            esac
            ;;
        *)
            # Unknown driver - assume at least 2.4GHz
            if [ "$band" = "24ghz" ] || [ "$band" = "2.4ghz" ]; then
                return 0
            fi
            ;;
    esac

    return 1
}

get_supported_channels_24ghz() {
    # Get list of available 2.4GHz channels for interface
    #
    # Args:
    #   $1 - Interface name
    #
    # Returns: Space-separated list of channels (e.g., "1 6 11")

    local iface="$1"
    local phy

    phy=$(get_phy_for_iface "$iface")
    [ -z "$phy" ] && { echo "6"; return; }

    # Parse iw phy for 2.4GHz frequencies and convert to channels
    local channels=""
    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    # Look for 2.4GHz frequencies (2412-2484 MHz)
    while read -r line; do
        if echo "$line" | grep -qE "^\s*\* 24[0-9][0-9] MHz \[([0-9]+)\]"; then
            local ch
            ch=$(echo "$line" | grep -oE '\[[0-9]+\]' | tr -d '[]')
            # Check if channel is disabled
            if ! echo "$line" | grep -qE "disabled|no IR|radar"; then
                channels="$channels $ch"
            fi
        fi
    done <<< "$phy_info"

    # Return available channels or default to 6
    if [ -n "$channels" ]; then
        echo "$channels" | xargs
    else
        echo "6"
    fi
}

get_supported_channels_5ghz() {
    # Get list of available 5GHz channels for interface
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Country code (optional, for regulatory domain setup)
    #
    # Returns: Space-separated list of channels (e.g., "36 40 44 48 149 153")
    #
    # Note: We include "no IR" channels because they ARE valid for AP mode.
    #       hostapd handles DFS/CAC for these channels. We only exclude
    #       truly "disabled" or "radar detected" channels.

    local iface="$1"
    local country="${2:-}"
    local phy

    phy=$(get_phy_for_iface "$iface")
    [ -z "$phy" ] && { echo "36 40 44 48"; return; }

    # Ensure regulatory domain is set before querying
    if [ -n "$country" ]; then
        iw reg set "$country" 2>/dev/null || true
        # Wait for regulatory domain to apply
        sleep 1
    fi

    # Parse iw phy for 5GHz frequencies and convert to channels
    local channels=""
    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    # Look for 5GHz frequencies (5170-5895 MHz)
    # Format: "* 5180 MHz [36] (20.0 dBm)" or "* 5180 MHz [36] (disabled)"
    while read -r line; do
        # Match 5GHz frequencies (5xxx MHz)
        if echo "$line" | grep -qE "^\s*\* 5[0-9]{3} MHz \[([0-9]+)\]"; then
            local ch
            ch=$(echo "$line" | grep -oE '\[[0-9]+\]' | tr -d '[]')

            # ONLY skip if truly disabled or radar currently detected
            # DO NOT skip "no IR" - those are valid for AP mode with DFS
            if echo "$line" | grep -qiE "disabled|radar.detected"; then
                continue
            fi
            channels="$channels $ch"
        fi
    done <<< "$phy_info"

    # Return available channels or default to UNII-1 (always safe)
    if [ -n "$channels" ]; then
        echo "$channels" | xargs
    else
        # Fallback: UNII-1 channels are always available
        echo "36 40 44 48"
    fi
}

is_channel_supported() {
    # Check if a specific channel is supported by the hardware
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Channel number
    #
    # Returns: 0 if supported, 1 if not

    local iface="$1"
    local channel="$2"
    local supported_channels

    # Get supported channels based on band
    if [ "$channel" -le 14 ]; then
        supported_channels=$(get_supported_channels_24ghz "$iface")
    else
        supported_channels=$(get_supported_channels_5ghz "$iface")
    fi

    # Check if channel is in the list
    echo " $supported_channels " | grep -q " $channel "
}

check_wifi_capability() {
    local iface="$1"
    local capability="$2"  # 80211n, 80211ac, 80211ax, 80211be, WPA3

    local iface_upper="${iface^^}"

    # First check state file variables
    case "$capability" in
        80211n)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211N\" = 'true' ]" && return 0
            ;;
        80211ac)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211AC\" = 'true' ]" && return 0
            ;;
        80211ax)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211AX\" = 'true' ]" && return 0
            ;;
        80211be)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211BE\" = 'true' ]" && return 0
            ;;
        5ghz)
            eval "[ \"\$NET_WIFI_${iface_upper}_5GHZ\" = 'true' ]" && return 0
            ;;
        6ghz)
            eval "[ \"\$NET_WIFI_${iface_upper}_6GHZ\" = 'true' ]" && return 0
            ;;
        24ghz)
            eval "[ \"\$NET_WIFI_${iface_upper}_24GHZ\" = 'true' ]" && return 0
            ;;
        ap)
            eval "[ \"\$NET_WIFI_${iface_upper}_AP\" = 'true' ]" && return 0
            ;;
        vap)
            eval "[ \"\$NET_WIFI_${iface_upper}_VAP\" = 'true' ]" && return 0
            ;;
    esac

    # Fallback: directly check iw phy output for capabilities
    local phy
    phy=$(get_phy_for_iface "$iface")
    [ -z "$phy" ] && return 1

    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    case "$capability" in
        80211n)
            echo "$phy_info" | grep -qE "HT20|HT40|Capabilities.*0x" && return 0
            ;;
        80211ac)
            echo "$phy_info" | grep -qE "VHT Capabilities" && return 0
            ;;
        80211ax)
            echo "$phy_info" | grep -qE "HE Capabilities|HE PHY|HE MAC" && return 0
            ;;
        80211be)
            echo "$phy_info" | grep -qE "EHT Capabilities|EHT PHY|EHT MAC" && return 0
            ;;
        5ghz)
            echo "$phy_info" | grep -qE "5[0-9]{3} MHz" && return 0
            ;;
        6ghz)
            echo "$phy_info" | grep -qE "(59[2-9][0-9]|6[0-9]{3}|7[01][0-9]{2}) MHz" && return 0
            ;;
        24ghz)
            echo "$phy_info" | grep -qE "24[0-9]{2} MHz" && return 0
            ;;
        ap)
            echo "$phy_info" | grep -qE "AP$|AP\s" && return 0
            ;;
    esac

    return 1
}

detect_ht_capabilities() {
    # Detect 802.11n HT capabilities for 2.4GHz
    # Args:
    #   $1 - Interface name
    #   $2 - Channel (optional, for HT40+/- selection)
    local iface="$1"
    local channel="${2:-6}"
    local phy
    phy=$(get_phy_for_iface "$iface")

    [ -z "$phy" ] && { echo "[SHORT-GI-20]"; return; }

    local caps=""
    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    # HT40 channel selection based on 2.4GHz channel rules:
    # - Channels 1-7: Can use HT40+ (secondary channel above)
    # - Channels 5-9: Can use HT40- (secondary channel below)
    # - Channels 10-13: Can only use HT40-
    # - Channel 14: No HT40 (Japan only)
    # Best practice: Use channel 1 or 6 with HT40+ for maximum compatibility
    if echo "$phy_info" | grep -q "HT40"; then
        if [ "$channel" -le 7 ] 2>/dev/null; then
            caps="[HT40+]"
        elif [ "$channel" -ge 5 ] && [ "$channel" -le 13 ] 2>/dev/null; then
            caps="[HT40-]"
        fi
    fi

    if echo "$phy_info" | grep -q "SHORT-GI-20"; then
        caps="${caps}[SHORT-GI-20]"
    fi

    if echo "$phy_info" | grep -q "SHORT-GI-40"; then
        caps="${caps}[SHORT-GI-40]"
    fi

    if echo "$phy_info" | grep -q "DSSS_CCK-40"; then
        caps="${caps}[DSSS_CCK-40]"
    fi

    # Default to safe capabilities if detection failed
    echo "${caps:-[SHORT-GI-20]}"
}

detect_vht_capabilities() {
    # Detect 802.11ac VHT capabilities for 5GHz
    local iface="$1"
    local phy
    phy=$(get_phy_for_iface "$iface")

    [ -z "$phy" ] && { echo "[MAX-MPDU-11454][SHORT-GI-80]"; return; }

    local caps=""
    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    if echo "$phy_info" | grep -q "MAX-MPDU-11454"; then
        caps="[MAX-MPDU-11454]"
    fi

    if echo "$phy_info" | grep -q "SHORT-GI-80"; then
        caps="${caps}[SHORT-GI-80]"
    fi

    if echo "$phy_info" | grep -q "SU-BEAMFORMER"; then
        caps="${caps}[SU-BEAMFORMER]"
    fi

    if echo "$phy_info" | grep -q "SU-BEAMFORMEE"; then
        caps="${caps}[SU-BEAMFORMEE]"
    fi

    echo "${caps:-[MAX-MPDU-11454][SHORT-GI-80]}"
}

detect_he_capabilities() {
    # Detect 802.11ax HE capabilities for WiFi 6
    local iface="$1"
    local phy
    phy=$(get_phy_for_iface "$iface")

    [ -z "$phy" ] && return 1

    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    # Check if HE is supported
    if ! echo "$phy_info" | grep -qE "HE Capabilities|HE PHY"; then
        return 1
    fi

    echo "true"
}

detect_eht_capabilities() {
    # Detect 802.11be EHT capabilities for WiFi 7
    local iface="$1"
    local phy
    phy=$(get_phy_for_iface "$iface")

    [ -z "$phy" ] && return 1

    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    # Check if EHT (802.11be/WiFi 7) is supported
    if ! echo "$phy_info" | grep -qE "EHT Capabilities|EHT PHY|EHT MAC"; then
        return 1
    fi

    echo "true"
}

detect_eht_channel_width() {
    # Detect maximum EHT channel width supported (WiFi 7)
    # Returns: 20, 40, 80, 160, or 320
    local iface="$1"
    local phy
    phy=$(get_phy_for_iface "$iface")

    [ -z "$phy" ] && { echo "80"; return; }

    local phy_info=""
    phy_info=$(get_phy_info "$phy")

    # WiFi 7 can support up to 320 MHz channels
    if echo "$phy_info" | grep -qE "320 MHz|EHT.*320"; then
        echo "320"
    elif echo "$phy_info" | grep -qE "160 MHz"; then
        echo "160"
    elif echo "$phy_info" | grep -qE "80.*80|80\+80"; then
        echo "160"
    else
        echo "80"
    fi
}

calculate_safe_eht_width() {
    # Calculate safe EHT channel width considering DFS constraints
    # Prioritizes high throughput but falls back if 160/320MHz would span DFS channels
    #
    # Args:
    #   $1 - channel number
    #   $2 - hardware max width (from detect_eht_channel_width)
    #
    # Returns: safe width (80, 160, or 320)

    local channel="$1"
    local hw_max_width="${2:-80}"

    # UNII-1 channels (36-48): Non-DFS, but 160MHz spans into UNII-2A (DFS)
    # UNII-2A channels (52-64): DFS, 160MHz spans UNII-1 + UNII-2A (mixed)
    # UNII-2C channels (100-144): DFS, complex 160MHz requirements
    # UNII-3 channels (149-165): Non-DFS in most countries

    case "$channel" in
        # UNII-1 (36-48): 80MHz safe, 160MHz spans into DFS (52-64)
        36|40|44|48)
            # 160MHz on ch36 would use center 50 (5250MHz) = channels 36-64
            # This spans DFS channels 52-64, causing CAC/radar issues
            # Limit to 80MHz for reliability
            if [ "$hw_max_width" -ge 80 ]; then
                echo "80"
            else
                echo "$hw_max_width"
            fi
            ;;

        # UNII-2A (52-64): DFS channels, 160MHz spans non-DFS + DFS (problematic)
        52|56|60|64)
            # Same issue - 160MHz spans 36-64 mixing DFS and non-DFS
            # Limit to 80MHz
            if [ "$hw_max_width" -ge 80 ]; then
                echo "80"
            else
                echo "$hw_max_width"
            fi
            ;;

        # UNII-2C (100-144): All DFS, 160MHz possible within band
        # 160MHz: 100-128 (center 114) or 116-144 (center 130) - both fully DFS
        100|104|108|112|116|120|124|128)
            # 160MHz is safe here (all channels are DFS anyway)
            # But requires 10-minute CAC for weather radar band
            if [ "$hw_max_width" -ge 160 ]; then
                echo "160"
            elif [ "$hw_max_width" -ge 80 ]; then
                echo "80"
            else
                echo "$hw_max_width"
            fi
            ;;

        132|136|140|144)
            # Upper UNII-2C - 160MHz possible but edge of band
            if [ "$hw_max_width" -ge 80 ]; then
                echo "80"
            else
                echo "$hw_max_width"
            fi
            ;;

        # UNII-3 (149-165): Non-DFS, 160MHz possible if hw supports
        149|153|157|161|165)
            # 160MHz on UNII-3 is possible in some regulatory domains
            # but channel availability varies by country
            if [ "$hw_max_width" -ge 160 ]; then
                echo "160"
            elif [ "$hw_max_width" -ge 80 ]; then
                echo "80"
            else
                echo "$hw_max_width"
            fi
            ;;

        # 6GHz channels (WiFi 6E/7) - 320MHz possible, no DFS
        # Channels start at 1, 5, 9... up to 233
        1|5|9|13|17|21|25|29|33|37|41|45|49|53|57|61|65|69|73|77|81|85|89|93)
            # 6GHz band - full width supported, no DFS
            echo "$hw_max_width"
            ;;

        *)
            # Unknown channel - default to safe 80MHz
            echo "80"
            ;;
    esac
}

calculate_eht_center_freq() {
    # Calculate EHT center frequency segment 0 index
    # Must match the VHT center freq for 80MHz, or be recalculated for wider
    #
    # Args:
    #   $1 - channel number
    #   $2 - bandwidth (80, 160, 320)
    #
    # Returns: center frequency index

    local channel="$1"
    local bandwidth="${2:-80}"

    case "$bandwidth" in
        80)
            # Same as VHT 80MHz center frequencies
            case "$channel" in
                36|40|44|48)     echo "42" ;;
                52|56|60|64)     echo "58" ;;
                100|104|108|112) echo "106" ;;
                116|120|124|128) echo "122" ;;
                132|136|140|144) echo "138" ;;
                149|153|157|161) echo "155" ;;
                165)             echo "155" ;;  # Edge case
                *)               echo "42" ;;   # Default
            esac
            ;;
        160)
            # 160MHz center frequencies (spanning two 80MHz blocks)
            case "$channel" in
                36|40|44|48|52|56|60|64)     echo "50" ;;   # 5250 MHz
                100|104|108|112|116|120|124|128) echo "114" ;; # 5570 MHz
                149|153|157|161|165)         echo "155" ;;  # Limited
                *)                           echo "50" ;;
            esac
            ;;
        320)
            # 320MHz - primarily for 6GHz band
            # Center frequencies for 6GHz 320MHz channels
            case "$channel" in
                1|5|9|13|17|21|25|29|33|37|41|45) echo "31" ;;
                49|53|57|61|65|69|73|77|81|85|89|93) echo "63" ;;
                *)  echo "31" ;;
            esac
            ;;
        *)
            # Fallback to 80MHz calculation
            calculate_eht_center_freq "$channel" 80
            ;;
    esac
}

# ============================================================
# INTELLIGENT CHANNEL SELECTION WITH VALIDATION
# ============================================================

# Channel+bandwidth combinations prioritized by throughput
# Format: "channel:bandwidth:band"
build_5ghz_priority_list() {
    # Build priority list of channel+bandwidth combinations
    # Sorted by throughput: 160MHz > 80MHz > 40MHz
    # IMPORTANT: Only includes channels that hardware actually supports
    #
    # Args:
    #   $1 - Interface name (for capability detection)
    #   $2 - Country code
    #   $3 - Hardware max width
    #
    # Output: List of "channel:bandwidth:band" entries (filtered by hardware)

    local iface="$1"
    local country="${2:-US}"
    local hw_max_width="${3:-80}"
    local raw_list=""
    local priority_list=""

    # Set regulatory domain and get hardware-supported channels
    # Pass country code to ensure channels are queried after regdomain is set
    local supported_channels
    supported_channels=$(get_supported_channels_5ghz "$iface" "$country")
    log_info "    Hardware-supported 5GHz channels: $supported_channels"

    # If only a few channels, something may be wrong - log warning
    local channel_count
    channel_count=$(echo "$supported_channels" | wc -w)
    if [ "$channel_count" -lt 4 ]; then
        log_warn "    Only $channel_count channels detected - regulatory domain may be restrictive"
        log_warn "    Country: $country, consider checking 'iw reg get' output"
    fi

    # Build raw priority list (before hardware filtering)
    # Tier 1: 160MHz on UNII-3 (non-DFS, highest throughput)
    if [ "$hw_max_width" -ge 160 ]; then
        raw_list="149:160:UNII-3 153:160:UNII-3 157:160:UNII-3 161:160:UNII-3"
    fi

    # Tier 2: 160MHz on UNII-2C (DFS but 160MHz possible)
    if [ "$hw_max_width" -ge 160 ]; then
        raw_list="$raw_list 100:160:UNII-2C 108:160:UNII-2C 116:160:UNII-2C 124:160:UNII-2C"
    fi

    # Tier 3: 80MHz on UNII-3 (non-DFS)
    raw_list="$raw_list 149:80:UNII-3 153:80:UNII-3 157:80:UNII-3 161:80:UNII-3"

    # Tier 4: 80MHz on UNII-1 (non-DFS, most compatible)
    raw_list="$raw_list 36:80:UNII-1 40:80:UNII-1 44:80:UNII-1 48:80:UNII-1"

    # Tier 5: 80MHz on UNII-2A (DFS, 60s CAC)
    raw_list="$raw_list 52:80:UNII-2A 56:80:UNII-2A 60:80:UNII-2A 64:80:UNII-2A"

    # Tier 6: 80MHz on UNII-2C (DFS, 600s CAC - weather radar)
    raw_list="$raw_list 100:80:UNII-2C 104:80:UNII-2C 108:80:UNII-2C 112:80:UNII-2C"

    # Tier 7: 40MHz fallback (if 80MHz doesn't work)
    raw_list="$raw_list 36:40:UNII-1 44:40:UNII-1 149:40:UNII-3 157:40:UNII-3"

    # Filter by hardware-supported channels
    for entry in $raw_list; do
        local ch
        ch=$(echo "$entry" | cut -d: -f1)
        # Check if this channel is in the supported list
        if echo " $supported_channels " | grep -q " $ch "; then
            priority_list="$priority_list $entry"
        fi
    done

    # If no channels match, fall back to whatever hardware supports
    if [ -z "$priority_list" ]; then
        log_warn "    No priority channels supported, using first available"
        local first_ch
        first_ch=$(echo "$supported_channels" | awk '{print $1}')
        if [ -n "$first_ch" ]; then
            priority_list="$first_ch:80:FALLBACK $first_ch:40:FALLBACK"
        else
            priority_list="36:80:UNII-1"  # Last resort
        fi
    fi

    echo "$priority_list" | xargs
}

validate_hostapd_connection() {
    # Validate that hostapd started successfully and interface is in AP mode
    #
    # Args:
    #   $1 - Interface name
    #   $2 - PID file path
    #   $3 - Timeout in seconds (default 10)
    #   $4 - Expected bandwidth in MHz (optional, for bandwidth verification)
    #
    # Returns: 0 if valid, 1 if failed
    # Exports: ACTUAL_BANDWIDTH (the bandwidth hostapd actually achieved)

    local iface="$1"
    local pidfile="${2:-/run/hostapd-test.pid}"
    local timeout="${3:-10}"
    local expected_bw="${4:-0}"
    local elapsed=0

    # Wait for hostapd to start
    while [ $elapsed -lt $timeout ]; do
        if [ -f "$pidfile" ]; then
            local pid
            pid=$(cat "$pidfile" 2>/dev/null)
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                # Check if interface is in AP mode
                local iw_info
                iw_info=$(iw dev "$iface" info 2>/dev/null) || true
                local mode
                mode=$(echo "$iw_info" | grep -oP 'type \K\w+')
                if [ "$mode" = "AP" ]; then
                    # Extract actual bandwidth from iw output
                    local actual_bw
                    actual_bw=$(echo "$iw_info" | grep -oP 'width: \K[0-9]+')
                    export ACTUAL_BANDWIDTH="${actual_bw:-20}"

                    # If expected bandwidth specified, verify it matches
                    if [ "$expected_bw" -gt 0 ] 2>/dev/null; then
                        if [ "${actual_bw:-20}" -ge "$expected_bw" ]; then
                            return 0
                        else
                            # Bandwidth mismatch - hostapd fell back to lower bandwidth
                            log_warn "      Bandwidth mismatch: requested ${expected_bw}MHz, got ${actual_bw:-20}MHz"
                            return 1
                        fi
                    fi
                    return 0
                fi
            fi
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    return 1
}

try_channel_bandwidth_combination() {
    # Try a specific channel+bandwidth combination
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Channel
    #   $3 - Bandwidth (40, 80, 160)
    #   $4 - Country code
    #
    # Returns: 0 if success, 1 if failed
    # Exports: WORKING_CHANNEL, WORKING_BANDWIDTH if successful

    local iface="$1"
    local channel="$2"
    local bandwidth="$3"
    local country="${4:-US}"
    local test_conf="/tmp/hostapd-test-$$.conf"
    local test_pid="/run/hostapd-test-$$.pid"

    log_info "    Trying channel $channel @ ${bandwidth}MHz..."

    # Safety check: Verify hardware supports this channel
    if ! is_channel_supported "$iface" "$channel"; then
        log_warn "    Channel $channel not supported by hardware - skipping"
        return 1
    fi

    # IMPORTANT: 160MHz on UNII-1 (36-48) requires channels 36-64, but 52-64 are DFS.
    # This causes "DFS chan_idx seems wrong" errors. Cap UNII-1 to 80MHz.
    case "$channel" in
        36|40|44|48)
            if [ "$bandwidth" -eq 160 ]; then
                log_warn "    160MHz not supported on UNII-1 (requires DFS channels 52-64), using 80MHz"
                bandwidth=80
            fi
            ;;
    esac

    # Calculate center frequency based on bandwidth
    # EHT uses SAME encoding as VHT: 0=20/40, 1=80, 2=160
    local vht_width vht_center eht_width eht_center
    case "$bandwidth" in
        160)
            vht_width=2
            eht_width=2
            ;;
        80)
            vht_width=1
            eht_width=1
            ;;
        40)
            vht_width=0
            eht_width=0
            ;;
        *)
            vht_width=1
            eht_width=1
            bandwidth=80
            ;;
    esac

    # Calculate center frequency for VHT
    case "$channel" in
        36|40|44|48)
            # UNII-1: Only 80MHz max (160MHz capped above)
            vht_center=42
            eht_center=42
            ;;
        52|56|60|64)
            vht_center=58
            eht_center=58
            ;;
        100|104|108|112)
            if [ "$bandwidth" -eq 160 ]; then
                vht_center=114
                eht_center=114
            else
                vht_center=106
                eht_center=106
            fi
            ;;
        116|120|124|128)
            if [ "$bandwidth" -eq 160 ]; then
                vht_center=130
                eht_center=130
            else
                vht_center=122
                eht_center=122
            fi
            ;;
        149|153|157|161)
            if [ "$bandwidth" -eq 160 ]; then
                vht_center=163
                eht_center=163
            else
                vht_center=155
                eht_center=155
            fi
            ;;
        *)
            vht_center=42
            eht_center=42
            ;;
    esac

    # Stop any existing test hostapd
    pkill -f "hostapd.*hostapd-test" 2>/dev/null || true
    sleep 1

    # Create minimal test config
    cat > "$test_conf" << EOF
interface=$iface
driver=nl80211
ctrl_interface=/var/run/hostapd-test
ssid=test-channel-validation
hw_mode=a
channel=$channel
country_code=$country
ieee80211d=1
# 802.11h: DFS + TPC - required for EU bandwidth
ieee80211h=1
spectrum_mgmt_required=1
local_pwr_constraint=3
ieee80211n=1
ieee80211ac=1
vht_oper_chwidth=$vht_width
vht_oper_centr_freq_seg0_idx=$vht_center
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=test12345678
EOF

    # Add WiFi 7 if available (requires WiFi 6)
    if check_hostapd_supports_wifi7 2>/dev/null; then
        cat >> "$test_conf" << EOF
ieee80211ax=1
ieee80211be=1
eht_oper_chwidth=$eht_width
eht_oper_centr_freq_seg0_idx=$eht_center
EOF
    elif check_hostapd_supports_wifi6 2>/dev/null; then
        # WiFi 6 only
        cat >> "$test_conf" << EOF
ieee80211ax=1
EOF
    fi

    # Try to start hostapd (capture any error output)
    local hostapd_error=""
    if hostapd -B -P "$test_pid" "$test_conf" 2>&1 | head -5 > /tmp/hostapd-5ghz-error-$$.log; then
        # Wait and validate with bandwidth check
        if validate_hostapd_connection "$iface" "$test_pid" 8 "$bandwidth"; then
            log_info "    ✓ Channel $channel @ ${bandwidth}MHz works!"

            # Stop test hostapd
            if [ -f "$test_pid" ]; then
                kill $(cat "$test_pid") 2>/dev/null || true
            fi
            rm -f "$test_conf" "$test_pid" /tmp/hostapd-5ghz-error-$$.log

            # Export working combination
            export WORKING_CHANNEL="$channel"
            export WORKING_BANDWIDTH="$bandwidth"
            export WORKING_VHT_WIDTH="$vht_width"
            export WORKING_VHT_CENTER="$vht_center"
            export WORKING_EHT_WIDTH="$eht_width"
            export WORKING_EHT_CENTER="$eht_center"

            return 0
        else
            # Validation failed - check if it's a bandwidth issue
            if [ -n "$ACTUAL_BANDWIDTH" ] && [ "$ACTUAL_BANDWIDTH" -lt "$bandwidth" ] 2>/dev/null; then
                log_warn "    ✗ Channel $channel: hostapd achieved only ${ACTUAL_BANDWIDTH}MHz (DFS/regulatory?)"
            fi
        fi
    else
        # hostapd failed to start - capture error
        hostapd_error=$(cat /tmp/hostapd-5ghz-error-$$.log 2>/dev/null | head -2 | tr '\n' ' ')
        if [ -n "$hostapd_error" ]; then
            log_warn "    ✗ hostapd error: $hostapd_error"
        fi
    fi

    # Cleanup on failure
    pkill -f "hostapd.*hostapd-test" 2>/dev/null || true
    rm -f "$test_conf" "$test_pid" /tmp/hostapd-5ghz-error-$$.log

    log_warn "    ✗ Channel $channel @ ${bandwidth}MHz failed"
    return 1
}

find_best_working_channel() {
    # Find the best working channel+bandwidth combination
    #
    # This function:
    #   1. Builds priority list (highest throughput first)
    #   2. Scans for congestion
    #   3. Tries each combination with validation
    #   4. Returns first working combination
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Country code
    #   $3 - Hardware max width (optional)
    #
    # Exports: WORKING_CHANNEL, WORKING_BANDWIDTH, etc.

    local iface="$1"
    local country="${2:-US}"
    local hw_max_width="${3:-80}"

    log_info "  Finding best working channel+bandwidth combination..."

    # Get hardware capabilities
    local supports_be=false
    if check_wifi_capability "$iface" "80211be" && check_hostapd_supports_wifi7 2>/dev/null; then
        supports_be=true
        hw_max_width=$(detect_eht_channel_width "$iface" 2>/dev/null) || hw_max_width=80
        log_info "    Hardware: WiFi 7, max ${hw_max_width}MHz"
    else
        log_info "    Hardware: WiFi 5/6, max ${hw_max_width}MHz"
    fi

    # Build priority list
    local priority_list
    priority_list=$(build_5ghz_priority_list "$iface" "$country" "$hw_max_width")

    # Scan for congestion (optional, improves selection)
    local scan_results=""
    if ip link set "$iface" up 2>/dev/null; then
        sleep 1
        scan_results=$(iw dev "$iface" scan 2>/dev/null) || true
    fi

    # Sort by congestion within same bandwidth tier
    local sorted_list=""
    for entry in $priority_list; do
        local ch bw band
        ch=$(echo "$entry" | cut -d: -f1)
        bw=$(echo "$entry" | cut -d: -f2)
        band=$(echo "$entry" | cut -d: -f3)

        # Count APs on this channel
        local freq ap_count
        freq=$((5000 + ch * 5))
        ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null) || ap_count=0

        sorted_list="$sorted_list $ap_count:$ch:$bw:$band"
    done

    # Sort by AP count (least congested first within same bandwidth)
    sorted_list=$(echo "$sorted_list" | tr ' ' '\n' | sort -t: -k1 -n | tr '\n' ' ')

    log_info "    Testing channel+bandwidth combinations (ordered by throughput)..."

    # Try each combination
    for entry in $sorted_list; do
        [ -z "$entry" ] && continue
        local ap_count ch bw band
        ap_count=$(echo "$entry" | cut -d: -f1)
        ch=$(echo "$entry" | cut -d: -f2)
        bw=$(echo "$entry" | cut -d: -f3)
        band=$(echo "$entry" | cut -d: -f4)

        [ -z "$ch" ] || [ -z "$bw" ] && continue

        if try_channel_bandwidth_combination "$iface" "$ch" "$bw" "$country"; then
            log_info "  Selected: Channel $ch @ ${bw}MHz ($band)"
            return 0
        fi
    done

    # Fallback: Try first hardware-supported channel
    log_warn "  All combinations failed, trying hardware-supported fallback..."
    local fallback_channels
    fallback_channels=$(get_supported_channels_5ghz "$iface" "$country")
    log_info "    Hardware-supported channels: $fallback_channels"

    for fb_ch in $fallback_channels; do
        # Try 80MHz first, then 40MHz
        if try_channel_bandwidth_combination "$iface" "$fb_ch" "80" "$country"; then
            log_info "  Fallback success: Channel $fb_ch @ 80MHz"
            return 0
        fi
        if try_channel_bandwidth_combination "$iface" "$fb_ch" "40" "$country"; then
            log_info "  Fallback success: Channel $fb_ch @ 40MHz"
            return 0
        fi
    done

    log_error "  No working channel+bandwidth combination found!"
    log_error "  Hardware-supported channels: $fallback_channels"
    return 1
}

# ============================================================
# 2.4GHz INTELLIGENT CHANNEL SELECTION
# ============================================================

build_24ghz_priority_list() {
    # Build priority list of 2.4GHz channel+bandwidth combinations
    # Only 3 non-overlapping channels: 1, 6, 11
    # Sorted by throughput: 40MHz > 20MHz
    #
    # Args:
    #   $1 - Country code
    #
    # Output: List of "channel:bandwidth:ht_mode" entries
    #
    # 2.4GHz HT40 channel rules:
    # - Channel 1 with HT40+ → secondary channel 5 (uses 1-5)
    # - Channel 6 with HT40+ → secondary channel 10 (uses 6-10)
    # - Channel 6 with HT40- → secondary channel 2 (uses 2-6)
    # - Channel 11 with HT40- → secondary channel 7 (uses 7-11)
    #
    # We try both HT40+ and HT40- for channel 6 since congestion varies

    local country="${1:-US}"
    local priority_list=""

    # Tier 1: 40MHz on non-overlapping channels
    # Try channel 1 first (usually least congested)
    # Then channel 6 with both HT40 modes (try both directions)
    # Then channel 11
    priority_list="1:40:HT40+ 6:40:HT40+ 6:40:HT40- 11:40:HT40-"

    # Tier 2: 20MHz fallback (always works if band is supported)
    priority_list="$priority_list 1:20:HT20 6:20:HT20 11:20:HT20"

    echo "$priority_list"
}

try_24ghz_channel_combination() {
    # Try a specific 2.4GHz channel+bandwidth combination
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Channel (1, 6, 11)
    #   $3 - Bandwidth (20, 40)
    #   $4 - HT mode (HT20, HT40+, HT40-)
    #   $5 - Country code
    #
    # Returns: 0 if success, 1 if failed

    local iface="$1"
    local channel="$2"
    local bandwidth="$3"
    local ht_mode="$4"
    local country="${5:-US}"
    local test_conf="/tmp/hostapd-24ghz-test-$$.conf"
    local test_pid="/run/hostapd-24ghz-test-$$.pid"

    log_info "    Trying channel $channel @ ${bandwidth}MHz ($ht_mode)..."

    # Build HT capabilities
    local ht_capab=""
    case "$ht_mode" in
        HT40+) ht_capab="[HT40+][SHORT-GI-20][SHORT-GI-40]" ;;
        HT40-) ht_capab="[HT40-][SHORT-GI-20][SHORT-GI-40]" ;;
        HT20)  ht_capab="[SHORT-GI-20]" ;;
        *)     ht_capab="[SHORT-GI-20]" ;;
    esac

    # Stop any existing test hostapd
    pkill -f "hostapd.*hostapd-24ghz-test" 2>/dev/null || true
    sleep 1

    # Create minimal test config
    cat > "$test_conf" << EOF
interface=$iface
driver=nl80211
ctrl_interface=/var/run/hostapd-24ghz-test
ssid=test-24ghz-validation
hw_mode=g
channel=$channel
country_code=$country
ieee80211d=1
ieee80211n=1
ht_capab=$ht_capab
obss_interval=0
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=test12345678
EOF

    # Add WiFi 6 on 2.4GHz if available
    if check_hostapd_supports_wifi6 2>/dev/null; then
        cat >> "$test_conf" << EOF
ieee80211ax=1
EOF
    fi

    # Try to start hostapd (capture any error output)
    local hostapd_error=""
    if hostapd -B -P "$test_pid" "$test_conf" 2>&1 | head -5 > /tmp/hostapd-24ghz-error-$$.log; then
        # Wait and validate with bandwidth check
        if validate_hostapd_connection "$iface" "$test_pid" 8 "$bandwidth"; then
            log_info "    ✓ Channel $channel @ ${bandwidth}MHz ($ht_mode) works!"

            # Stop test hostapd
            if [ -f "$test_pid" ]; then
                kill $(cat "$test_pid") 2>/dev/null || true
            fi
            rm -f "$test_conf" "$test_pid" /tmp/hostapd-24ghz-error-$$.log

            # Export working combination
            export WORKING_24GHZ_CHANNEL="$channel"
            export WORKING_24GHZ_BANDWIDTH="$bandwidth"
            export WORKING_24GHZ_HT_MODE="$ht_mode"
            export WORKING_24GHZ_HT_CAPAB="$ht_capab"

            return 0
        else
            # Validation failed - check if it's a bandwidth issue
            if [ -n "$ACTUAL_BANDWIDTH" ] && [ "$ACTUAL_BANDWIDTH" -lt "$bandwidth" ] 2>/dev/null; then
                log_warn "    ✗ Channel $channel: hostapd started but achieved only ${ACTUAL_BANDWIDTH}MHz (overlapping BSSs?)"
            fi
        fi
    else
        # hostapd failed to start - capture error
        hostapd_error=$(cat /tmp/hostapd-24ghz-error-$$.log 2>/dev/null | head -2 | tr '\n' ' ')
        if [ -n "$hostapd_error" ]; then
            log_warn "    ✗ hostapd error: $hostapd_error"
        fi
    fi

    # Cleanup on failure
    pkill -f "hostapd.*hostapd-24ghz-test" 2>/dev/null || true
    rm -f "$test_conf" "$test_pid" /tmp/hostapd-24ghz-error-$$.log

    log_warn "    ✗ Channel $channel @ ${bandwidth}MHz ($ht_mode) failed"
    return 1
}

find_best_working_24ghz_channel() {
    # Find the best working 2.4GHz channel+bandwidth combination
    #
    # This function:
    #   1. Builds priority list (40MHz > 20MHz)
    #   2. Scans for congestion on channels 1, 6, 11
    #   3. Tries each combination with validation
    #   4. Returns first working combination
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Country code
    #
    # Exports: WORKING_24GHZ_CHANNEL, WORKING_24GHZ_BANDWIDTH, etc.

    local iface="$1"
    local country="${2:-US}"

    log_info "  Finding best working 2.4GHz channel+bandwidth combination..."

    # Build priority list
    local priority_list
    priority_list=$(build_24ghz_priority_list "$country")

    # Scan for congestion
    local scan_results=""
    if ip link set "$iface" up 2>/dev/null; then
        sleep 1
        scan_results=$(iw dev "$iface" scan 2>/dev/null) || true
    fi

    # Sort by congestion within same bandwidth tier
    local sorted_list=""
    for entry in $priority_list; do
        local ch bw ht_mode
        ch=$(echo "$entry" | cut -d: -f1)
        bw=$(echo "$entry" | cut -d: -f2)
        ht_mode=$(echo "$entry" | cut -d: -f3)

        # Count APs on this channel (2.4GHz freq = 2407 + ch*5)
        local freq ap_count
        freq=$((2407 + ch * 5))
        ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null) || ap_count=0

        sorted_list="$sorted_list $bw:$ap_count:$ch:$ht_mode"
    done

    # Sort by bandwidth (desc) then AP count (asc)
    sorted_list=$(echo "$sorted_list" | tr ' ' '\n' | sort -t: -k1 -rn -k2 -n | tr '\n' ' ')

    log_info "    Testing channel+bandwidth combinations..."

    # Try each combination
    for entry in $sorted_list; do
        [ -z "$entry" ] && continue
        local bw ap_count ch ht_mode
        bw=$(echo "$entry" | cut -d: -f1)
        ap_count=$(echo "$entry" | cut -d: -f2)
        ch=$(echo "$entry" | cut -d: -f3)
        ht_mode=$(echo "$entry" | cut -d: -f4)

        [ -z "$ch" ] || [ -z "$bw" ] && continue

        if try_24ghz_channel_combination "$iface" "$ch" "$bw" "$ht_mode" "$country"; then
            log_info "  Selected: Channel $ch @ ${bw}MHz ($ht_mode)"
            return 0
        fi
    done

    # Fallback: Try channel 6 @ 20MHz (most compatible)
    log_warn "  All combinations failed, trying safe fallback..."
    if try_24ghz_channel_combination "$iface" "6" "20" "HT20" "$country"; then
        return 0
    fi

    # Last resort: Channel 1 @ 20MHz
    if try_24ghz_channel_combination "$iface" "1" "20" "HT20" "$country"; then
        return 0
    fi

    log_error "  No working 2.4GHz channel+bandwidth combination found!"
    return 1
}

# ============================================================
# HOSTAPD CONFIGURATION GENERATORS
# ============================================================

generate_hostapd_24ghz() {
    # Generate hostapd config for 2.4GHz band
    #
    # Args:
    #   $1 - Interface name
    #   $2 - SSID
    #   $3 - Password
    #   $4 - Channel (auto or 1, 6, 11)
    #   $5 - Bridge name (optional)

    local iface="$1"
    local ssid="${2:-HookProbe-Fortress}"
    local password="$3"
    local channel="${4:-auto}"
    local bridge="${5:-$DEFAULT_BRIDGE}"

    [ -z "$iface" ] && { log_error "Interface required"; return 1; }
    [ -z "$password" ] && { log_error "Password required"; return 1; }
    [ ${#password} -lt 8 ] && { log_error "Password must be at least 8 characters"; return 1; }

    # Verify hardware actually supports 2.4GHz band
    if ! verify_band_support "$iface" "24ghz"; then
        log_error "Interface $iface does not support 2.4GHz band"
        log_error "  This adapter appears to be 5GHz-only"
        log_error "  Skipping 2.4GHz configuration"
        return 1
    fi

    # Auto-detect regulatory domain
    local country_code
    country_code=$(detect_regulatory_domain)

    # ═══════════════════════════════════════════════════════════════════════════
    # SELF-MANAGED REGULATORY DOMAIN CHECK
    # Some WiFi adapters (e.g., ath12k) have "self-managed" regulatory domains
    # that ignore the system's iw reg set command. We must use the adapter's
    # firmware country code, not the system's, or hostapd will fail with
    # "Could not determine operating frequency"
    # ═══════════════════════════════════════════════════════════════════════════
    local effective_country="$country_code"

    if is_self_managed_regdomain "$iface" 2>/dev/null; then
        local phy_reg
        phy_reg=$(get_phy_regdomain "$iface" 2>/dev/null)
        effective_country="${phy_reg%%:*}"  # Strip :self-managed suffix

        log_warn "  ⚠️  Adapter has SELF-MANAGED regulatory domain: $effective_country"
        log_warn "     System country ($country_code) will be IGNORED by firmware"

        if [ "$effective_country" != "$country_code" ]; then
            log_warn "  ⚠️  REGULATORY MISMATCH: System=$country_code, Firmware=$effective_country"
            log_warn "     Using firmware country code ($effective_country) in hostapd config"
        fi
    fi

    log_info "Generating 2.4GHz hostapd configuration"
    log_info "  Interface: $iface"
    log_info "  SSID: $ssid"
    log_info "  Channel: $channel"
    log_info "  Bridge: $bridge"
    log_info "  Country: $effective_country (effective)"

    # HT capabilities - will be set by validation or detection
    local ht_capab=""
    local used_validated_settings=false

    # Check if this is ath12k - skip validation (known to be problematic with test hostapd)
    local skip_validation=false
    if is_ath12k_driver "$iface"; then
        skip_validation=true
    fi

    # Auto channel selection
    if [ "$channel" = "auto" ]; then
        if [ "$skip_validation" = true ]; then
            # KISS: Skip validation for ath12k, use known-good defaults directly
            # The ath12k driver has issues with rapid hostapd start/stop during testing
            # Fallback chain: 6 (center of band) -> 1 (low) -> 11 (high)
            local supported_channels
            supported_channels=$(get_supported_channels "$iface" 2>/dev/null || echo "1 6 11")

            local ath12k_24ghz_channels="6:HT40+ 1:HT40+ 11:HT40-"
            local selected_channel=""
            local selected_ht_mode=""

            for entry in $ath12k_24ghz_channels; do
                local try_ch="${entry%%:*}"
                local try_ht="${entry##*:}"
                if echo " $supported_channels " | grep -q " $try_ch "; then
                    selected_channel="$try_ch"
                    selected_ht_mode="$try_ht"
                    break
                fi
            done

            if [ -n "$selected_channel" ]; then
                channel="$selected_channel"
                ht_capab="[${selected_ht_mode}][SHORT-GI-20][SHORT-GI-40]"
                used_validated_settings=true
                log_info "  ath12k: Using direct config - Channel $channel @ 40MHz ($selected_ht_mode)"
            else
                # Ultimate fallback
                channel=6
                ht_capab="[HT40+][SHORT-GI-20][SHORT-GI-40]"
                used_validated_settings=true
                log_warn "  ath12k: No channels from fallback list, using Channel 6 @ 40MHz (HT40+)"
            fi
        else
            log_info "  Using intelligent 2.4GHz channel selection with validation..."

            if find_best_working_24ghz_channel "$iface" "$effective_country"; then
                channel="$WORKING_24GHZ_CHANNEL"
                ht_capab="$WORKING_24GHZ_HT_CAPAB"
                used_validated_settings=true
                log_info "  ✓ Validated: Channel $channel @ ${WORKING_24GHZ_BANDWIDTH}MHz ($WORKING_24GHZ_HT_MODE)"
            else
                log_warn "  Intelligent selection failed, using safe defaults"
                channel=6
                ht_capab="[HT40+][SHORT-GI-20][SHORT-GI-40]"
                used_validated_settings=true
                log_info "  Fallback: Channel 6 @ 40MHz (HT40+)"
            fi
        fi
    fi

    # Detect capabilities if not already validated (pass channel for HT40+/- selection)
    if [ "$used_validated_settings" = false ]; then
        ht_capab=$(detect_ht_capabilities "$iface" "$channel")
    fi

    # Detect driver for capability restrictions
    local wifi_driver
    wifi_driver=$(get_wifi_driver "$iface")
    local skip_fragm=false
    if is_ath12k_driver "$iface"; then
        log_info "  Driver: $wifi_driver (ath12k - fragm_threshold disabled)"
        skip_fragm=true
    else
        log_info "  Driver: ${wifi_driver:-unknown}"
    fi

    # Prepare interface (stop wpa_supplicant, unmanage from NetworkManager)
    prepare_interface_for_hostapd "$iface"
    create_networkmanager_unmanaged_rule "$iface"

    # Ensure bridge exists for VLAN tagging
    ensure_bridge_exists "$bridge"

    local supports_ax=false
    # Check hardware capability for WiFi 6
    local hw_supports_ax=false
    if check_wifi_capability "$iface" "80211ax"; then
        hw_supports_ax=true
    fi

    # Only enable WiFi 6 if BOTH hardware AND hostapd support it
    if $hw_supports_ax && check_hostapd_supports_wifi6; then
        supports_ax=true
        log_info "  WiFi 6 (802.11ax) on 2.4GHz: enabled"
    elif $hw_supports_ax; then
        log_warn "  WiFi 6 (802.11ax) on 2.4GHz: hardware supported but hostapd too old"
    fi

    mkdir -p "$HOSTAPD_DIR"

    # Check if bridge is OVS - don't use nl80211 bridge mode for OVS
    # OVS doesn't support nl80211 bridge integration - we'll add interface to OVS post-start
    local use_bridge=""
    if ! is_ovs_bridge "$bridge"; then
        use_bridge="bridge=$bridge"
        log_info "  Using Linux bridge mode"
    else
        log_info "  OVS bridge detected - will add WiFi to OVS after hostapd starts"
    fi

    cat > "$HOSTAPD_24GHZ_CONF" << EOF
# HookProbe Fortress - 2.4GHz WiFi Configuration
# Generated: $(date -Iseconds)
#
# Purpose: Legacy/IoT device compatibility with WPA2
# Band: 2.4GHz (802.11n/b/g)
#

interface=$iface
driver=nl80211
${use_bridge}

# Control interface for hostapd_cli
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0

# Network Settings
ssid=$ssid
utf8_ssid=1
country_code=$effective_country
ieee80211d=1

# Band: 2.4GHz (802.11g mode)
hw_mode=g
channel=$channel

# 802.11n (WiFi 4)
ieee80211n=1
require_ht=0
ht_capab=$ht_capab

# Force HT40 bandwidth - disable 20/40 MHz coexistence
# ht_coex=0 disables the 20/40 MHz BSS coexistence scan
# obss_interval=0 disables the Overlapping BSS scan timer
# Both are needed to prevent ath12k and similar drivers from falling back to 20MHz
ht_coex=0
obss_interval=0

# WMM (QoS) - Required for 802.11n
wmm_enabled=1
uapsd_advertisement_enabled=1

EOF

    # Add WiFi 6 (802.11ax) if supported
    if $supports_ax; then
        cat >> "$HOSTAPD_24GHZ_CONF" << EOF
# WiFi 6 (802.11ax) - 2.4GHz HE mode
ieee80211ax=1
he_su_beamformer=0
he_su_beamformee=1
he_mu_beamformer=0

EOF
    fi

    # WPA2 configuration (for IoT compatibility)
    cat >> "$HOSTAPD_24GHZ_CONF" << EOF
# Security: WPA2-PSK (for legacy/IoT devices)
# Note: Many IoT devices do not support WPA3
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=$password

# Access Control
macaddr_acl=0
ap_isolate=0
max_num_sta=64

# Dynamic VLAN Assignment (disabled by default - requires VLAN infrastructure)
# To enable: set dynamic_vlan=1, create /etc/hostapd/hostapd.vlan,
# and ensure VLAN bridges (br-mgmt, br-pos, br-staff, br-guest, br-iot) exist
# VLANs: 10=Management, 20=POS, 30=Staff, 40=Guest, 99=IoT
dynamic_vlan=0
#vlan_file=$HOSTAPD_VLAN_FILE
#vlan_tagged_interface=$bridge
#vlan_naming=1

# Performance Tuning
beacon_int=100
dtim_period=2
rts_threshold=2347
EOF

    # Add fragm_threshold only if driver supports it (ath12k does not)
    if ! $skip_fragm; then
        echo "fragm_threshold=2346" >> "$HOSTAPD_24GHZ_CONF"
    else
        echo "# fragm_threshold disabled - not supported by $wifi_driver driver" >> "$HOSTAPD_24GHZ_CONF"
    fi

    cat >> "$HOSTAPD_24GHZ_CONF" << EOF

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

EOF

    chmod 640 "$HOSTAPD_24GHZ_CONF"
    log_success "2.4GHz configuration saved: $HOSTAPD_24GHZ_CONF"
    log_success "  Security: WPA2-PSK (IoT compatible)"
    log_success "  Channel: $channel"

    echo "$HOSTAPD_24GHZ_CONF"
}

# EU/ETSI countries - UNII-3 (149-165) typically not allowed without special license
EU_COUNTRIES="AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE"
# Also include EEA and other ETSI countries
ETSI_COUNTRIES="$EU_COUNTRIES GB CH NO IS LI"

is_eu_country() {
    # Check if country code is in EU/ETSI region
    local country="$1"
    echo "$ETSI_COUNTRIES" | grep -qw "$country"
}

get_safe_5ghz_channel() {
    # Get a safe 5GHz channel based on regulatory domain
    #
    # IMPORTANT: Always default to UNII-1 (36-48) which is universally allowed
    # UNII-3 (149-165) requires DFS radar detection in many regions and may fail
    #
    # Args:
    #   $1 - Country code
    #   $2 - Interface (for scanning)
    #
    # Note: log_info redirected to stderr to avoid polluting channel output

    local country="$1"
    local iface="$2"

    # Always use UNII-1 band (channels 36-48) by default
    # These channels are allowed worldwide without DFS radar detection
    # UNII-3 (149-165) often fails due to regulatory restrictions
    log_info "  Using UNII-1 band (channel 36) - universally allowed without DFS" >&2
    echo "36"
}

generate_hostapd_5ghz() {
    # Generate hostapd config for 5GHz band with WPA3
    #
    # Args:
    #   $1 - Interface name
    #   $2 - SSID
    #   $3 - Password
    #   $4 - Channel (auto or 36-48, 149-165)
    #   $5 - Bridge name (optional)

    local iface="$1"
    local ssid="${2:-HookProbe-Fortress}"
    local password="$3"
    local channel="${4:-auto}"
    local bridge="${5:-$DEFAULT_BRIDGE}"

    [ -z "$iface" ] && { log_error "Interface required"; return 1; }
    [ -z "$password" ] && { log_error "Password required"; return 1; }
    [ ${#password} -lt 8 ] && { log_error "Password must be at least 8 characters"; return 1; }

    # Verify hardware actually supports 5GHz band
    if ! verify_band_support "$iface" "5ghz"; then
        log_error "Interface $iface does not support 5GHz band"
        log_error "  This adapter appears to be 2.4GHz-only"
        log_error "  Skipping 5GHz configuration"
        return 1
    fi

    # Auto-detect regulatory domain
    local country_code
    country_code=$(detect_regulatory_domain)

    # Set regulatory domain BEFORE any configuration
    # This is critical for EU/ETSI compliance and DFS
    if [ "$DFS_AVAILABLE" = "true" ]; then
        log_info "Setting regulatory domain before configuration..."
        if ! set_regulatory_domain "$country_code" "$iface"; then
            log_warn "Could not set regulatory domain - continuing anyway"
        fi
    else
        # Fallback: use iw directly
        iw reg set "$country_code" 2>/dev/null || true
    fi
    sleep 1  # Allow regulatory database to update

    log_info "Generating 5GHz hostapd configuration"
    log_info "  Interface: $iface"
    log_info "  SSID: $ssid"
    log_info "  Channel: $channel"
    log_info "  Bridge: $bridge"
    log_info "  Country: $country_code (auto-detected)"

    # ═══════════════════════════════════════════════════════════════════════════
    # REGULATORY DOMAIN CHECK
    # Some WiFi adapters have "self-managed" regulatory domains that ignore
    # the system's iw reg set command. We must detect this and use safe channels.
    # ═══════════════════════════════════════════════════════════════════════════
    local self_managed_regdomain=false
    local effective_country="$country_code"

    if [ "$DFS_AVAILABLE" = "true" ]; then
        # Log regulatory status
        log_regulatory_status "$iface" 2>/dev/null || true

        # Check if adapter has self-managed regulatory domain
        if is_self_managed_regdomain "$iface" 2>/dev/null; then
            self_managed_regdomain=true
            local phy_reg
            phy_reg=$(get_phy_regdomain "$iface" 2>/dev/null)
            effective_country="${phy_reg%%:*}"  # Strip :self-managed suffix

            log_warn "  ⚠️  Adapter has SELF-MANAGED regulatory domain: $effective_country"
            log_warn "     System country ($country_code) will be IGNORED by firmware"

            if [ "$effective_country" != "$country_code" ]; then
                log_warn "  ⚠️  REGULATORY MISMATCH: System=$country_code, Firmware=$effective_country"
                log_warn "     Using conservative channel selection (UNII-1: 36-48 only)"
            fi
        fi
    fi

    # Check if this is ath12k - skip validation (known to be problematic with test hostapd)
    local skip_validation=false
    if is_ath12k_driver "$iface"; then
        skip_validation=true
    fi

    # Auto channel selection
    if [ "$channel" = "auto" ]; then
        if [ "$skip_validation" = true ]; then
            # KISS: Skip validation for ath12k, use known-good defaults directly
            # The ath12k driver has issues with rapid hostapd start/stop during testing
            #
            # Fallback priority for EU/ETSI (RO):
            #   1. Channel 36 @ 80MHz (UNII-1, non-DFS, indoor)
            #   2. Channel 44 @ 80MHz (UNII-1, non-DFS, different primary)
            #   3. Channel 52 @ 80MHz (UNII-2A, DFS, 60s CAC)
            #   4. Channel 100 @ 80MHz (UNII-2C, DFS, 600s CAC)
            #
            # Channel -> Center frequency mapping for 80MHz:
            #   36-48  -> center=42
            #   52-64  -> center=58
            #   100-112 -> center=106
            #   116-128 -> center=122
            #   149-161 -> center=155

            local ath12k_channel_list="36:42 44:42 52:58 100:106"
            local selected_channel=""
            local selected_center=""

            log_info "  ath12k: Trying channel fallback chain..."
            for entry in $ath12k_channel_list; do
                local try_ch="${entry%%:*}"
                local try_center="${entry##*:}"

                # Check if channel is in supported list
                local supported_channels
                supported_channels=$(get_supported_channels_5ghz "$iface" "$effective_country" 2>/dev/null)

                if echo " $supported_channels " | grep -q " $try_ch "; then
                    selected_channel="$try_ch"
                    selected_center="$try_center"

                    # Check if this is a DFS channel
                    if [ "$try_ch" -ge 52 ]; then
                        log_info "  ath12k: Selected DFS channel $try_ch @ 80MHz (center=$try_center)"
                        log_warn "    Note: DFS channel requires CAC (Channel Availability Check)"
                        if [ "$try_ch" -ge 100 ]; then
                            log_warn "    CAC time: 600 seconds (weather radar band)"
                        else
                            log_warn "    CAC time: 60 seconds"
                        fi
                    else
                        log_info "  ath12k: Selected channel $try_ch @ 80MHz (center=$try_center)"
                    fi
                    break
                else
                    log_info "    Channel $try_ch not available, trying next..."
                fi
            done

            # Use selected channel or fallback to 36
            if [ -n "$selected_channel" ]; then
                channel="$selected_channel"
                VALIDATED_VHT_CENTER="$selected_center"
                VALIDATED_EHT_CENTER="$selected_center"
            else
                log_warn "  ath12k: No channels available from fallback list, using channel 36"
                channel=36
                VALIDATED_VHT_CENTER=42
                VALIDATED_EHT_CENTER=42
            fi

            VALIDATED_VHT_WIDTH=1
            VALIDATED_EHT_WIDTH=1  # EHT uses same encoding as VHT: 1=80MHz
            VALIDATED_BANDWIDTH=80
        else
            log_info "  Using intelligent channel+bandwidth selection..."

            # Use intelligent channel selection with validation
            if find_best_working_channel "$iface" "$effective_country"; then
                channel="$WORKING_CHANNEL"
                log_info "  Validated working combination: channel $channel @ ${WORKING_BANDWIDTH}MHz"

                # Store validated settings for use in config generation
                VALIDATED_VHT_WIDTH="$WORKING_VHT_WIDTH"
                VALIDATED_VHT_CENTER="$WORKING_VHT_CENTER"
                VALIDATED_EHT_WIDTH="$WORKING_EHT_WIDTH"
                VALIDATED_EHT_CENTER="$WORKING_EHT_CENTER"
                VALIDATED_BANDWIDTH="$WORKING_BANDWIDTH"
            else
                # Fallback to safe channel if validation fails
                log_warn "  Intelligent selection failed, using safe fallback..."
                channel=36
                VALIDATED_VHT_WIDTH=1
                VALIDATED_VHT_CENTER=42
                VALIDATED_EHT_WIDTH=1  # EHT uses same encoding as VHT: 1=80MHz
                VALIDATED_EHT_CENTER=42
                VALIDATED_BANDWIDTH=80
                log_info "  Fallback: Channel 36 @ 80MHz (center=42)"
            fi
        fi
    else
        # Manual channel specified - validate for regulatory domain
        if $self_managed_regdomain && [ "$effective_country" != "$country_code" ]; then
            # With domain mismatch, warn if not in UNII-1
            if [ "$channel" -lt 36 ] || [ "$channel" -gt 48 ] 2>/dev/null; then
                log_warn "  ⚠️  Channel $channel may fail with domain mismatch (System=$country_code, Firmware=$effective_country)"
                log_warn "     Consider using channels 36-48 (UNII-1) for guaranteed compatibility"
            fi
        elif is_eu_country "$effective_country"; then
            if [ "$channel" -ge 149 ] && [ "$channel" -le 177 ] 2>/dev/null; then
                log_warn "  Channel $channel (UNII-3) may not be allowed in EU country $effective_country"
                log_warn "  Consider using channels 36-48 (UNII-1) instead"
            fi
        fi
    fi

    # Test channel before configuration if DFS script available
    # Skip for ath12k - the test hostapd causes issues with this driver
    if [ "$DFS_AVAILABLE" = "true" ] && [ "$skip_validation" != true ]; then
        log_info "  Testing channel $channel..."
        if ! test_channel "$iface" "$channel" 3 2>/dev/null; then
            log_warn "  Channel $channel test failed, falling back to channel 36"
            channel=36
        fi

        # Check if DFS channel requires CAC wait
        if is_dfs_channel "$channel" 2>/dev/null; then
            local cac_time
            cac_time=$(get_cac_time "$channel")
            log_warn "  Channel $channel is DFS, requires ${cac_time}s CAC"
            log_info "  hostapd will handle radar detection automatically"
        fi
    fi

    # Validate and detect maximum bandwidth
    local max_bandwidth=80
    if [ "$DFS_AVAILABLE" = "true" ]; then
        max_bandwidth=$(detect_max_bandwidth "$iface" "5ghz" 2>/dev/null) || max_bandwidth=80
        log_info "  Maximum bandwidth: ${max_bandwidth}MHz"

        # Validate bandwidth for selected channel
        if ! validate_bandwidth "$iface" "$max_bandwidth" "$channel" 2>/dev/null; then
            log_warn "  Reducing bandwidth to 80MHz for channel $channel"
            max_bandwidth=80
        fi
    fi

    # Detect capabilities
    local vht_capab
    vht_capab=$(detect_vht_capabilities "$iface")

    # Detect driver for capability restrictions
    local wifi_driver
    wifi_driver=$(get_wifi_driver "$iface")
    local skip_fragm=false
    if is_ath12k_driver "$iface"; then
        log_info "  Driver: $wifi_driver (ath12k - fragm_threshold disabled)"
        skip_fragm=true
    else
        log_info "  Driver: ${wifi_driver:-unknown}"
    fi

    # Prepare interface (stop wpa_supplicant, unmanage from NetworkManager)
    prepare_interface_for_hostapd "$iface"
    create_networkmanager_unmanaged_rule "$iface"

    # Ensure bridge exists for VLAN tagging
    ensure_bridge_exists "$bridge"

    local supports_ac=false
    local supports_ax=false
    local supports_be=false  # WiFi 7

    # Check hardware capabilities
    local hw_supports_ac=false
    local hw_supports_ax=false
    local hw_supports_be=false

    if check_wifi_capability "$iface" "80211ac"; then
        hw_supports_ac=true
    fi
    if check_wifi_capability "$iface" "80211ax"; then
        hw_supports_ax=true
    fi
    if check_wifi_capability "$iface" "80211be"; then
        hw_supports_be=true
    fi

    # Check hostapd version support
    # Only enable features if BOTH hardware AND hostapd support them
    if $hw_supports_ac; then
        supports_ac=true  # WiFi 5 (802.11ac) supported in all hostapd versions
    fi
    if $hw_supports_ax && check_hostapd_supports_wifi6; then
        supports_ax=true
        log_info "  WiFi 6 (802.11ax): hardware + hostapd supported"
    elif $hw_supports_ax; then
        log_warn "  WiFi 6 (802.11ax): hardware supported but hostapd too old"
    fi
    if $hw_supports_be && check_hostapd_supports_wifi7; then
        supports_be=true
        log_info "  WiFi 7 (802.11be): hardware + hostapd supported"
    elif $hw_supports_be; then
        log_warn "  WiFi 7 (802.11be): hardware supported but hostapd too old (needs 2.11+)"
    fi

    # Calculate VHT center frequency (use validated settings if available)
    local vht_oper_centr_freq_seg0_idx vht_oper_chwidth_val
    if [ -n "$VALIDATED_VHT_CENTER" ]; then
        # Use validated settings from intelligent channel selection
        vht_oper_centr_freq_seg0_idx="$VALIDATED_VHT_CENTER"
        vht_oper_chwidth_val="${VALIDATED_VHT_WIDTH:-1}"

        # Safety check: UNII-1 (36-48) cannot use 160MHz (requires DFS channels 52-64)
        case "$channel" in
            36|40|44|48)
                if [ "$vht_oper_chwidth_val" -ge 2 ]; then
                    log_warn "  Capping UNII-1 to 80MHz (160MHz requires DFS channels)"
                    vht_oper_chwidth_val=1
                    vht_oper_centr_freq_seg0_idx=42
                fi
                ;;
        esac
        log_info "  Using validated VHT: width=$vht_oper_chwidth_val, center=$vht_oper_centr_freq_seg0_idx"
    else
        # Manual channel - calculate center frequency
        vht_oper_chwidth_val=1  # Default 80MHz
        case "$channel" in
            36|40|44|48)   vht_oper_centr_freq_seg0_idx=42 ;;
            52|56|60|64)   vht_oper_centr_freq_seg0_idx=58 ;;
            100|104|108|112) vht_oper_centr_freq_seg0_idx=106 ;;
            116|120|124|128) vht_oper_centr_freq_seg0_idx=122 ;;
            132|136|140|144) vht_oper_centr_freq_seg0_idx=138 ;;
            149|153|157|161) vht_oper_centr_freq_seg0_idx=155 ;;
            *)              vht_oper_centr_freq_seg0_idx=42 ;;
        esac
    fi

    mkdir -p "$HOSTAPD_DIR"

    # Check if bridge is OVS - don't use nl80211 bridge mode for OVS
    # OVS doesn't support nl80211 bridge integration - we'll add interface to OVS post-start
    local use_bridge=""
    if ! is_ovs_bridge "$bridge"; then
        use_bridge="bridge=$bridge"
        log_info "  Using Linux bridge mode"
    else
        log_info "  OVS bridge detected - will add WiFi to OVS after hostapd starts"
    fi

    cat > "$HOSTAPD_5GHZ_CONF" << EOF
# HookProbe Fortress - 5GHz WiFi Configuration
# Generated: $(date -Iseconds)
#
# Purpose: High-throughput access with WPA3 security
# Band: 5GHz (802.11ac/ax/be)
#

interface=$iface
driver=nl80211
${use_bridge}

# Control interface for hostapd_cli
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0

# Network Settings
ssid=$ssid
utf8_ssid=1
# Use effective country code (from adapter firmware if self-managed)
country_code=$effective_country
ieee80211d=1
# 802.11h: DFS (radar detection) + TPC (transmit power control)
# MANDATORY for EU/ETSI countries to unlock >20MHz bandwidth
ieee80211h=1
# Spectrum management required for DFS/TPC compliance
spectrum_mgmt_required=1
local_pwr_constraint=3

# DFS Radar Detection (ETSI EN 301 893 compliance)
# Enabled automatically when using DFS channels (52-64, 100-144)
# CAC (Channel Availability Check) times:
#   - UNII-2A (52-64): 60 seconds
#   - UNII-2C (100-144): 600 seconds (weather radar)

# Band: 5GHz (802.11a mode)
hw_mode=a
channel=$channel

# 802.11n (WiFi 4 base)
ieee80211n=1
require_ht=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][MAX-AMSDU-7935]

# WMM (QoS) - Required
wmm_enabled=1
uapsd_advertisement_enabled=1

EOF

    # Add 802.11ac (WiFi 5) if supported
    if $supports_ac; then
        cat >> "$HOSTAPD_5GHZ_CONF" << EOF
# 802.11ac (WiFi 5)
ieee80211ac=1
require_vht=1
# VHT channel width: 0=40MHz, 1=80MHz, 2=160MHz, 3=80+80MHz
vht_oper_chwidth=$vht_oper_chwidth_val
vht_oper_centr_freq_seg0_idx=$vht_oper_centr_freq_seg0_idx
vht_capab=$vht_capab

EOF
    fi

    # Add 802.11ax (WiFi 6) if supported
    if $supports_ax; then
        cat >> "$HOSTAPD_5GHZ_CONF" << EOF
# 802.11ax (WiFi 6)
ieee80211ax=1
he_su_beamformer=1
he_su_beamformee=1
he_mu_beamformer=1
he_bss_color=1
he_default_pe_duration=4
he_rts_threshold=1023
he_mu_edca_qos_info_param_count=0
he_mu_edca_qos_info_q_ack=0
he_mu_edca_qos_info_queue_request=0
he_mu_edca_qos_info_txop_request=0

EOF
    fi

    # Add 802.11be (WiFi 7) if supported
    # Note: WiFi 7 requires hostapd 2.11+ with EHT support
    if $supports_be; then
        local hw_eht_width safe_eht_width eht_center_freq eht_oper_chwidth_val_be

        # Use validated settings if available (from intelligent channel selection)
        if [ -n "$VALIDATED_EHT_WIDTH" ]; then
            eht_oper_chwidth_val_be="$VALIDATED_EHT_WIDTH"
            eht_center_freq="$VALIDATED_EHT_CENTER"

            # Safety check: UNII-1 (36-48) cannot use 160MHz+ (requires DFS channels 52-64)
            # EHT uses same encoding as VHT: 0=20/40, 1=80, 2=160
            case "$channel" in
                36|40|44|48)
                    if [ "$eht_oper_chwidth_val_be" -ge 2 ]; then
                        log_warn "  Capping EHT on UNII-1 to 80MHz (160MHz+ requires DFS channels)"
                        eht_oper_chwidth_val_be=1  # 80MHz
                        eht_center_freq=42
                    fi
                    ;;
            esac

            # Convert width value back to MHz for logging
            # EHT: 0=20/40, 1=80, 2=160 (same as VHT)
            case "$eht_oper_chwidth_val_be" in
                2) safe_eht_width=160 ;;
                1) safe_eht_width=80 ;;
                *) safe_eht_width=40 ;;
            esac
            hw_eht_width=$(detect_eht_channel_width "$iface" 2>/dev/null) || hw_eht_width="$safe_eht_width"
            log_info "  Using validated EHT: width=$eht_oper_chwidth_val_be (${safe_eht_width}MHz), center=$eht_center_freq"
        else
            # Manual channel - calculate safe width
            hw_eht_width=$(detect_eht_channel_width "$iface")
            safe_eht_width=$(calculate_safe_eht_width "$channel" "$hw_eht_width")
            eht_center_freq=$(calculate_eht_center_freq "$channel" "$safe_eht_width")

            # Convert MHz to hostapd eht_oper_chwidth value
            # EHT uses SAME encoding as VHT: 0=20/40, 1=80, 2=160, 3=80+80
            case "$safe_eht_width" in
                320) eht_oper_chwidth_val_be=2 ;;  # 320MHz uses chwidth=2 with extended center freq
                160) eht_oper_chwidth_val_be=2 ;;
                80)  eht_oper_chwidth_val_be=1 ;;
                40|20|*)  eht_oper_chwidth_val_be=0 ;;  # 20/40 uses HT capability
            esac
        fi

        cat >> "$HOSTAPD_5GHZ_CONF" << EOF
# 802.11be (WiFi 7) - EHT (Extremely High Throughput)
# Requires hostapd 2.11+ and compatible driver
ieee80211be=1
eht_su_beamformer=1
eht_su_beamformee=1
eht_mu_beamformer=1

# WiFi 7 channel width
# eht_oper_chwidth uses SAME encoding as VHT: 0=20/40MHz, 1=80MHz, 2=160MHz
# Note: 320MHz uses chwidth=2 with extended center frequency
# Configuration validated during channel selection
eht_oper_chwidth=$eht_oper_chwidth_val_be
eht_oper_centr_freq_seg0_idx=$eht_center_freq

# Multi-Link Operation (MLO) - disabled by default
# Enable for dual-band simultaneous operation (requires compatible clients)
# mlo_enabled=0

EOF
        if [ "$safe_eht_width" != "$hw_eht_width" ]; then
            log_info "  WiFi 7 (802.11be): enabled (${safe_eht_width}MHz - reduced from ${hw_eht_width}MHz for channel $channel)"
        else
            log_info "  WiFi 7 (802.11be): enabled (${safe_eht_width}MHz)"
        fi
    fi

    # WPA3/WPA2 Transition Mode (SAE + PSK)
    cat >> "$HOSTAPD_5GHZ_CONF" << EOF
# Security: WPA3/WPA2 Transition Mode
# - WPA3-SAE for modern devices
# - WPA2-PSK fallback for compatibility
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE
wpa_pairwise=CCMP
rsn_pairwise=CCMP CCMP-256

# WPA3-SAE Configuration
sae_password=$password
sae_require_mfp=1
sae_pwe=2

# Protected Management Frames (Required for WPA3)
ieee80211w=1

# WPA2 Fallback Password
wpa_passphrase=$password

# Access Control
macaddr_acl=0
ap_isolate=0
max_num_sta=128

# Dynamic VLAN Assignment (disabled by default - requires VLAN infrastructure)
# To enable: set dynamic_vlan=1, create /etc/hostapd/hostapd.vlan,
# and ensure VLAN bridges (br-mgmt, br-pos, br-staff, br-guest, br-iot) exist
# VLANs: 10=Management, 20=POS, 30=Staff, 40=Guest, 99=IoT
dynamic_vlan=0
#vlan_file=$HOSTAPD_VLAN_FILE
#vlan_tagged_interface=$bridge
#vlan_naming=1

# Performance Tuning (High Throughput)
beacon_int=100
dtim_period=2
rts_threshold=2347
EOF

    # Add fragm_threshold only if driver supports it (ath12k does not)
    if ! $skip_fragm; then
        echo "fragm_threshold=2346" >> "$HOSTAPD_5GHZ_CONF"
    else
        echo "# fragm_threshold disabled - not supported by $wifi_driver driver" >> "$HOSTAPD_5GHZ_CONF"
    fi

    cat >> "$HOSTAPD_5GHZ_CONF" << EOF

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

EOF

    chmod 640 "$HOSTAPD_5GHZ_CONF"
    log_success "5GHz configuration saved: $HOSTAPD_5GHZ_CONF"
    log_success "  Security: WPA3-SAE + WPA2-PSK (Transition Mode)"
    log_success "  Channel: $channel"
    $supports_ac && log_success "  WiFi 5 (802.11ac): enabled"
    $supports_ax && log_success "  WiFi 6 (802.11ax): enabled"
    $supports_be && log_success "  WiFi 7 (802.11be): enabled"

    echo "$HOSTAPD_5GHZ_CONF"
}

generate_vlan_file() {
    # Generate VLAN configuration file for hostapd
    #
    # Default VLANs for Fortress:
    #   10 - Management
    #   20 - POS (Point of Sale)
    #   30 - Staff
    #   40 - Guest
    #   99 - IoT

    log_info "Generating VLAN configuration"

    mkdir -p "$HOSTAPD_DIR"

    cat > "$HOSTAPD_VLAN_FILE" << EOF
# HookProbe Fortress - VLAN Configuration
# Generated: $(date -Iseconds)
#
# Format: vlan_id interface_name
# The interface will be created as: wlan0.vlan_id
#

# Management VLAN (admin devices)
10 br-mgmt

# POS VLAN (payment terminals)
20 br-pos

# Staff VLAN (employee devices)
30 br-staff

# Guest VLAN (customer WiFi)
40 br-guest

# IoT VLAN (cameras, sensors)
99 br-iot

EOF

    chmod 644 "$HOSTAPD_VLAN_FILE"
    log_success "VLAN file saved: $HOSTAPD_VLAN_FILE"
}

generate_radius_config() {
    # Generate RADIUS server configuration for hostapd
    # This enables WPA-Enterprise with FreeRADIUS for dynamic VLAN assignment
    #
    # Args:
    #   $1 - config file path (hostapd-24ghz.conf or hostapd-5ghz.conf)
    #   $2 - RADIUS secret (optional, defaults to hookprobe_fortress)

    local config_file="$1"
    local radius_secret="${2:-hookprobe_fortress}"

    if [ ! -f "$config_file" ]; then
        log_warn "Config file not found: $config_file"
        return 1
    fi

    log_info "Adding WPA-Enterprise RADIUS configuration to $config_file"

    # Append RADIUS configuration
    cat >> "$config_file" << EOF

# ============================================================
# WPA-Enterprise (RADIUS) Configuration
# ============================================================
# For dynamic VLAN assignment based on MAC/vendor
# Requires FreeRADIUS running locally

# RADIUS Authentication Server
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=$radius_secret

# RADIUS Accounting Server (optional but recommended)
acct_server_addr=127.0.0.1
acct_server_port=1813
acct_server_shared_secret=$radius_secret

# EAP Configuration
eap_server=0
ieee8021x=1
eapol_version=2

# MAC Authentication (MAC-based RADIUS auth for non-802.1X clients)
# This allows PSK clients to still get VLAN assignment via RADIUS
macaddr_acl=2
EOF

    log_success "RADIUS configuration added to $config_file"
}

enable_enterprise_mode() {
    # Convert a hostapd config from PSK to WPA-Enterprise mode
    # This enables full RADIUS-based authentication and dynamic VLAN
    #
    # Args:
    #   $1 - config file path
    #   $2 - RADIUS secret (optional)

    local config_file="$1"
    local radius_secret="${2:-hookprobe_fortress}"

    if [ ! -f "$config_file" ]; then
        log_error "Config file not found: $config_file"
        return 1
    fi

    log_info "Converting to WPA-Enterprise mode: $config_file"

    # Change WPA key management from PSK to EAP
    sed -i 's/wpa_key_mgmt=WPA-PSK.*/wpa_key_mgmt=WPA-EAP/' "$config_file"

    # Comment out PSK passphrase (no longer needed for Enterprise)
    sed -i 's/^wpa_passphrase=/#wpa_passphrase=/' "$config_file"
    sed -i 's/^sae_password=/#sae_password=/' "$config_file"

    # Set macaddr_acl to 2 for RADIUS-based MAC authentication
    sed -i 's/macaddr_acl=0/macaddr_acl=2/' "$config_file"

    # Set dynamic_vlan to 2 (required for WPA-Enterprise)
    sed -i 's/dynamic_vlan=1/dynamic_vlan=2/' "$config_file"

    # Add RADIUS configuration
    generate_radius_config "$config_file" "$radius_secret"

    log_success "WPA-Enterprise mode enabled"
    log_info "  Authentication: FreeRADIUS (127.0.0.1:1812)"
    log_info "  VLAN Assignment: Dynamic (based on MAC/vendor OUI)"
}

generate_dual_band_single_radio() {
    # Generate single hostapd config for dual-band radio
    # Uses band steering to direct clients to optimal band
    #
    # Args:
    #   $1 - Interface name
    #   $2 - SSID
    #   $3 - Password
    #   $4 - Primary band (5ghz or 24ghz)

    local iface="$1"
    local ssid="${2:-HookProbe-Fortress}"
    local password="$3"
    local primary_band="${4:-5ghz}"

    log_info "Generating dual-band single-radio configuration"
    log_info "  Primary band: $primary_band"

    # For single dual-band radio, generate config for primary band
    # Clients will connect and the radio handles both bands
    if [ "$primary_band" = "5ghz" ]; then
        generate_hostapd_5ghz "$iface" "$ssid" "$password" "auto"
    else
        generate_hostapd_24ghz "$iface" "$ssid" "$password" "auto"
    fi
}

# ============================================================
# SYSTEMD SERVICE GENERATION
# ============================================================

generate_wifi_bridge_helper() {
    # Generate helper script to add WiFi interface to OVS bridge after hostapd starts
    #
    # OVS bridges don't support nl80211 bridge mode, so we need to add the
    # WiFi interface to OVS manually after hostapd creates it.
    #
    # Note: This works fine with hostapd 2.10/2.11 on most drivers (ath12k, mt76, etc.)
    # The "Interface X is in master ovs-system" log message is informational, not an error.

    local helper_script="/usr/local/bin/fortress-wifi-bridge-helper.sh"

    log_info "Generating WiFi bridge helper script"

    cat > "$helper_script" << 'HELPER_EOF'
#!/bin/bash
# Fortress WiFi Bridge Helper
# Adds WiFi interface to OVS bridge after hostapd starts

IFACE="$1"
BRIDGE="${2:-43ess}"
ACTION="${3:-add}"

[ -z "$IFACE" ] && exit 1

# Wait for interface to be ready
for i in {1..10}; do
    if ip link show "$IFACE" &>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! ip link show "$IFACE" &>/dev/null; then
    echo "Interface $IFACE not found after waiting"
    exit 1
fi

# Check if OVS is available and bridge exists
if ! command -v ovs-vsctl &>/dev/null; then
    echo "OVS not available, skipping bridge configuration"
    exit 0
fi

if ! ovs-vsctl br-exists "$BRIDGE" 2>/dev/null; then
    echo "OVS bridge $BRIDGE does not exist, skipping"
    exit 0
fi

if [ "$ACTION" = "add" ]; then
    # Add interface to OVS bridge
    if ! ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "^${IFACE}$"; then
        echo "Adding $IFACE to OVS bridge $BRIDGE"
        ovs-vsctl --may-exist add-port "$BRIDGE" "$IFACE" 2>/dev/null || {
            echo "Failed to add $IFACE to $BRIDGE"
            exit 1
        }
    fi
    ip link set "$IFACE" up 2>/dev/null || true
    echo "WiFi interface $IFACE added to OVS bridge $BRIDGE"
elif [ "$ACTION" = "remove" ]; then
    # Remove interface from OVS bridge
    if ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "^${IFACE}$"; then
        echo "Removing $IFACE from OVS bridge $BRIDGE"
        ovs-vsctl del-port "$BRIDGE" "$IFACE" 2>/dev/null || true
    fi
fi

exit 0
HELPER_EOF

    chmod +x "$helper_script"
    log_success "Created: $helper_script"
}

generate_systemd_services() {
    # Generate systemd service files for hostapd
    #
    # Args:
    #   $1 - has_24ghz (true/false)
    #   $2 - has_5ghz (true/false)
    #   $3 - 24ghz interface name (optional)
    #   $4 - 5ghz interface name (optional)
    #   $5 - bridge name (optional, default: fortress)

    local has_24ghz="$1"
    local has_5ghz="$2"
    local iface_24ghz="${3:-}"
    local iface_5ghz="${4:-}"
    local bridge="${5:-$DEFAULT_BRIDGE}"

    log_info "Generating systemd service files"

    # Find hostapd binary - check common locations
    local hostapd_bin=""
    for path in /usr/local/bin/hostapd /usr/sbin/hostapd /usr/bin/hostapd; do
        if [ -x "$path" ]; then
            hostapd_bin="$path"
            break
        fi
    done
    if [ -z "$hostapd_bin" ]; then
        hostapd_bin=$(which hostapd 2>/dev/null || echo "/usr/sbin/hostapd")
    fi
    log_info "  Using hostapd: $hostapd_bin"

    # Generate helper script for OVS bridge integration
    generate_wifi_bridge_helper

    if [ "$has_24ghz" = "true" ]; then
        # Extract interface from config if not provided
        if [ -z "$iface_24ghz" ] && [ -f "$HOSTAPD_24GHZ_CONF" ]; then
            iface_24ghz=$(grep "^interface=" "$HOSTAPD_24GHZ_CONF" | cut -d= -f2)
        fi

        # Systemd device unit for the WiFi interface (waits for interface to exist)
        local dev_unit_24ghz="sys-subsystem-net-devices-${iface_24ghz}.device"

        cat > /etc/systemd/system/fortress-hostapd-24ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 2.4GHz WiFi Access Point
After=network.target openvswitch-switch.service ${dev_unit_24ghz}
Wants=network.target openvswitch-switch.service ${dev_unit_24ghz}
# Rate limit restarts
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
PIDFile=/run/hostapd-24ghz.pid
# Wait for interface to be ready (handles udev rename timing)
ExecStartPre=/bin/bash -c 'for i in {1..30}; do [ -e /sys/class/net/${iface_24ghz} ] && break; sleep 0.5; done; [ -e /sys/class/net/${iface_24ghz} ] || exit 1'
# Clean up interface state before starting (fixes "Match already configured" error)
ExecStartPre=-/bin/bash -c 'pkill -f "hostapd.*${iface_24ghz}" 2>/dev/null; rm -f /run/hostapd-24ghz.pid'
ExecStartPre=-/sbin/ip link set ${iface_24ghz} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${iface_24ghz} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-24ghz.pid $HOSTAPD_24GHZ_CONF
ExecStartPost=/usr/local/bin/fortress-wifi-bridge-helper.sh ${iface_24ghz} ${bridge} add
ExecStop=-/bin/kill -TERM \$MAINPID
ExecStopPost=-/sbin/ip link set ${iface_24ghz} down
ExecStopPost=-/usr/local/bin/fortress-wifi-bridge-helper.sh ${iface_24ghz} ${bridge} remove
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        log_success "Created: fortress-hostapd-24ghz.service (waits for ${iface_24ghz})"
    fi

    if [ "$has_5ghz" = "true" ]; then
        # Extract interface from config if not provided
        if [ -z "$iface_5ghz" ] && [ -f "$HOSTAPD_5GHZ_CONF" ]; then
            iface_5ghz=$(grep "^interface=" "$HOSTAPD_5GHZ_CONF" | cut -d= -f2)
        fi

        # Systemd device unit for the WiFi interface (waits for interface to exist)
        local dev_unit_5ghz="sys-subsystem-net-devices-${iface_5ghz}.device"

        cat > /etc/systemd/system/fortress-hostapd-5ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 5GHz WiFi Access Point
After=network.target openvswitch-switch.service ${dev_unit_5ghz}
Wants=network.target openvswitch-switch.service ${dev_unit_5ghz}
# Rate limit restarts
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
PIDFile=/run/hostapd-5ghz.pid
# Wait for interface to be ready (handles udev rename timing)
ExecStartPre=/bin/bash -c 'for i in {1..30}; do [ -e /sys/class/net/${iface_5ghz} ] && break; sleep 0.5; done; [ -e /sys/class/net/${iface_5ghz} ] || exit 1'
# Clean up interface state before starting (fixes "Match already configured" error)
ExecStartPre=-/bin/bash -c 'pkill -f "hostapd.*${iface_5ghz}" 2>/dev/null; rm -f /run/hostapd-5ghz.pid'
ExecStartPre=-/sbin/ip link set ${iface_5ghz} down
ExecStartPre=/bin/sleep 0.5
ExecStartPre=/sbin/ip link set ${iface_5ghz} up
ExecStart=${hostapd_bin} -B -P /run/hostapd-5ghz.pid $HOSTAPD_5GHZ_CONF
ExecStartPost=/usr/local/bin/fortress-wifi-bridge-helper.sh ${iface_5ghz} ${bridge} add
ExecStop=-/bin/kill -TERM \$MAINPID
ExecStopPost=-/sbin/ip link set ${iface_5ghz} down
ExecStopPost=-/usr/local/bin/fortress-wifi-bridge-helper.sh ${iface_5ghz} ${bridge} remove
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        log_success "Created: fortress-hostapd-5ghz.service (waits for ${iface_5ghz})"
    fi

    systemctl daemon-reload
}

# ============================================================
# VLAN SETUP HELPER
# ============================================================

setup_vlan_infrastructure() {
    # Set up VLAN infrastructure for hostapd dynamic VLANs
    #
    # This creates:
    #   1. VLAN bridges (br-mgmt, br-pos, br-staff, br-guest, br-iot)
    #   2. hostapd.vlan mapping file
    #   3. Enables dynamic_vlan in hostapd configs
    #
    # Run this AFTER generating hostapd configs if you want VLAN segregation

    log_info "Setting up VLAN infrastructure for hostapd..."

    # Create VLAN bridges
    local vlan_bridges="br-mgmt br-pos br-staff br-guest br-iot"
    for bridge in $vlan_bridges; do
        if ! ip link show "$bridge" &>/dev/null; then
            log_info "  Creating bridge $bridge"
            ip link add name "$bridge" type bridge 2>/dev/null || true
            ip link set "$bridge" up 2>/dev/null || true
        else
            log_info "  Bridge $bridge already exists"
        fi
    done

    # Create hostapd.vlan mapping file
    log_info "  Creating $HOSTAPD_VLAN_FILE"
    cat > "$HOSTAPD_VLAN_FILE" << 'EOF'
# hostapd VLAN mapping file
# Format: vlan_id bridge_name
# VLANs: 10=Management, 20=POS, 30=Staff, 40=Guest, 99=IoT
10 br-mgmt
20 br-pos
30 br-staff
40 br-guest
99 br-iot
EOF
    chmod 644 "$HOSTAPD_VLAN_FILE"

    # Enable dynamic VLANs in existing configs
    for conf in "$HOSTAPD_24GHZ_CONF" "$HOSTAPD_5GHZ_CONF"; do
        if [ -f "$conf" ]; then
            log_info "  Enabling dynamic VLANs in $conf"
            sed -i 's/^dynamic_vlan=0/dynamic_vlan=1/' "$conf"
            sed -i 's/^#vlan_file=/vlan_file=/' "$conf"
            sed -i 's/^#vlan_tagged_interface=/vlan_tagged_interface=/' "$conf"
            sed -i 's/^#vlan_naming=/vlan_naming=/' "$conf"
        fi
    done

    log_success "VLAN infrastructure ready"
    log_info "  Restart hostapd services to apply: systemctl restart fortress-hostapd-*"
}

disable_vlan_infrastructure() {
    # Disable dynamic VLANs in hostapd configs
    #
    # Use this if you want to run without VLAN segregation

    log_info "Disabling VLAN infrastructure..."

    for conf in "$HOSTAPD_24GHZ_CONF" "$HOSTAPD_5GHZ_CONF"; do
        if [ -f "$conf" ]; then
            log_info "  Disabling dynamic VLANs in $conf"
            sed -i 's/^dynamic_vlan=1/dynamic_vlan=0/' "$conf"
            sed -i 's/^dynamic_vlan=2/dynamic_vlan=0/' "$conf"
            sed -i 's/^vlan_file=/#vlan_file=/' "$conf"
            sed -i 's/^vlan_tagged_interface=/#vlan_tagged_interface=/' "$conf"
            sed -i 's/^vlan_naming=/#vlan_naming=/' "$conf"
        fi
    done

    log_success "Dynamic VLANs disabled"
    log_info "  Restart hostapd services to apply: systemctl restart fortress-hostapd-*"
}

# ============================================================
# MAIN CONFIGURATION WORKFLOW
# ============================================================

configure_dual_band_wifi() {
    # Main function to configure dual-band WiFi
    #
    # Args:
    #   $1 - SSID
    #   $2 - Password
    #   $3 - Bridge name (optional, defaults to OVS fortress bridge)

    local ssid="${1:-HookProbe-Fortress}"
    local password="$2"
    local bridge="${3:-$DEFAULT_BRIDGE}"

    [ -z "$password" ] && { log_error "Password required"; return 1; }
    [ ${#password} -lt 8 ] && { log_error "Password must be at least 8 characters"; return 1; }

    # Load network state - prefer environment variables if already set
    # This allows install-container.sh to override with stable interface names
    if [ -n "$NET_WIFI_24GHZ_IFACE" ] || [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
        log_info "Using pre-configured interface names from environment"
        # Don't source state file - environment variables take precedence
    elif [ -f "$INTERFACE_STATE_FILE" ]; then
        source "$INTERFACE_STATE_FILE"
    else
        log_warn "No network state found, detecting interfaces..."
        if [ -x "$SCRIPT_DIR/network-interface-detector.sh" ]; then
            source <("$SCRIPT_DIR/network-interface-detector.sh" detect 2>/dev/null | grep "^export")
        else
            log_error "Cannot detect interfaces"
            return 1
        fi
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Dual-Band WiFi Configuration${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    log_info "SSID: $ssid"
    log_info "Bridge: $bridge"
    log_info "Config Mode: ${NET_WIFI_CONFIG_MODE:-unknown}"
    log_info "2.4GHz Interface: ${NET_WIFI_24GHZ_IFACE:-none}"
    log_info "5GHz Interface: ${NET_WIFI_5GHZ_IFACE:-none}"

    local has_24ghz=false
    local has_5ghz=false

    case "${NET_WIFI_CONFIG_MODE:-none}" in
        separate-radios)
            # Two separate radios - create two hostapd configs
            if [ -n "$NET_WIFI_24GHZ_IFACE" ]; then
                if generate_hostapd_24ghz "$NET_WIFI_24GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"; then
                    has_24ghz=true
                else
                    log_warn "2.4GHz configuration skipped (hardware may not support this band)"
                fi
            fi
            if [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
                if generate_hostapd_5ghz "$NET_WIFI_5GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"; then
                    has_5ghz=true
                else
                    log_warn "5GHz configuration skipped (hardware may not support this band)"
                fi
            fi
            ;;

        single-dual-band)
            # Single dual-band radio - create both configs for same interface
            # User can choose to run one or both (if radio supports it)
            if [ -n "$NET_WIFI_24GHZ_IFACE" ]; then
                if generate_hostapd_24ghz "$NET_WIFI_24GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"; then
                    has_24ghz=true
                else
                    log_warn "2.4GHz configuration skipped (hardware may not support this band)"
                fi
            fi

            if [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
                # Only add 5GHz if it's a different physical operation mode
                # Some radios can do both simultaneously, others cannot
                if generate_hostapd_5ghz "$NET_WIFI_5GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"; then
                    has_5ghz=true
                else
                    log_warn "5GHz configuration skipped (hardware may not support this band)"
                fi
            fi

            if $has_24ghz && $has_5ghz; then
                log_warn "Single dual-band radio detected"
                log_warn "  You may need to choose one band or use VAP if supported"
            fi
            ;;

        24ghz-only)
            if [ -n "$NET_WIFI_24GHZ_IFACE" ]; then
                if generate_hostapd_24ghz "$NET_WIFI_24GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"; then
                    has_24ghz=true
                else
                    log_error "2.4GHz configuration failed"
                fi
            fi
            ;;

        5ghz-only)
            if [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
                if generate_hostapd_5ghz "$NET_WIFI_5GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"; then
                    has_5ghz=true
                else
                    log_error "5GHz configuration failed"
                fi
            fi
            ;;

        none|*)
            log_error "No WiFi configuration mode detected"
            return 1
            ;;
    esac

    # Check if at least one band was configured
    if ! $has_24ghz && ! $has_5ghz; then
        log_error "No WiFi bands could be configured!"
        log_error "  Please check your WiFi hardware and hostapd installation"
        return 1
    fi

    # Generate VLAN file
    generate_vlan_file

    # Generate systemd services only for configured bands
    # Pass interface names for OVS bridge integration
    generate_systemd_services "$has_24ghz" "$has_5ghz" \
        "${NET_WIFI_24GHZ_IFACE:-}" "${NET_WIFI_5GHZ_IFACE:-}" "$bridge"

    echo ""
    if $has_24ghz && $has_5ghz; then
        log_success "Dual-band WiFi configuration complete!"
    elif $has_5ghz; then
        log_success "5GHz WiFi configuration complete!"
        log_warn "  2.4GHz not available (hardware may not support it)"
    else
        log_success "2.4GHz WiFi configuration complete!"
        log_warn "  5GHz not available (hardware may not support it)"
    fi
    echo ""
    echo "Generated files:"
    [ "$has_24ghz" = "true" ] && echo "  2.4GHz: $HOSTAPD_24GHZ_CONF"
    [ "$has_5ghz" = "true" ] && echo "  5GHz:   $HOSTAPD_5GHZ_CONF"
    echo "  VLANs:  $HOSTAPD_VLAN_FILE"
    echo ""
    echo "To start WiFi:"
    [ "$has_24ghz" = "true" ] && echo "  systemctl start fortress-hostapd-24ghz"
    [ "$has_5ghz" = "true" ] && echo "  systemctl start fortress-hostapd-5ghz"
    echo ""

    return 0
}

# ============================================================
# USAGE
# ============================================================

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  configure <ssid> <password> [bridge]"
    echo "                    - Configure dual-band WiFi"
    echo "  24ghz <iface> <ssid> <password> [channel] [bridge]"
    echo "                    - Generate 2.4GHz config only"
    echo "  5ghz <iface> <ssid> <password> [channel] [bridge]"
    echo "                    - Generate 5GHz config only"
    echo "  vlan              - Generate VLAN file only"
    echo "  systemd           - Generate systemd services"
    echo "  setup-vlan        - Set up VLAN infrastructure (bridges + enable in configs)"
    echo "  disable-vlan      - Disable VLAN infrastructure in configs"
    echo ""
    echo "DFS/Regulatory Commands (EU 5GHz compliance):"
    echo "  preflight <iface> [country]  - Pre-flight validation before WiFi config"
    echo "  set-regdomain <country>      - Set regulatory domain (GB, DE, FR, etc.)"
    echo "  get-channels <iface>         - List available 5GHz channels"
    echo "  calibrate <iface>            - Find optimal channel (least congested)"
    echo "  install-timer [iface]        - Install 4AM daily calibration timer"
    echo ""
    echo "Examples:"
    echo "  $0 configure MyNetwork 'MySecurePassword123'"
    echo "  $0 24ghz wlan0 MyNetwork 'MyPassword' 6 fortress"
    echo "  $0 5ghz wlan1 MyNetwork 'MyPassword' 36 fortress"
    echo "  $0 setup-vlan                # Enable VLAN segregation"
    echo "  $0 preflight wlan0 GB        # Validate before EU deployment"
    echo "  $0 set-regdomain DE          # Set German regulatory domain"
    echo "  $0 calibrate wlan0           # Find best 5GHz channel"
    echo "  $0 install-timer wlan0       # Install 4AM optimization"
    echo ""
    echo "Security:"
    echo "  - 2.4GHz uses WPA2-PSK for IoT device compatibility"
    echo "  - 5GHz uses WPA3-SAE with WPA2-PSK fallback"
    echo "  - Passwords must be at least 8 characters"
    echo "  - Dynamic VLANs disabled by default (use 'setup-vlan' to enable)"
    echo ""
    echo "EU/ETSI 5GHz Channels:"
    echo "  UNII-1 (36-48):   No DFS, safe for all EU countries"
    echo "  UNII-2A (52-64):  DFS required, 1-min CAC, indoor only"
    echo "  UNII-2C (100-144): DFS required, 10-min CAC (weather radar)"
    echo "  UNII-3 (149-165): NOT allowed in DE, FR, IT, ES, NL, etc."
    echo ""
}

# ============================================================
# MAIN
# ============================================================

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        configure)
            configure_dual_band_wifi "$2" "$3" "${4:-43ess}"
            ;;
        24ghz)
            generate_hostapd_24ghz "$2" "$3" "$4" "${5:-auto}" "${6:-43ess}"
            ;;
        5ghz)
            generate_hostapd_5ghz "$2" "$3" "$4" "${5:-auto}" "${6:-43ess}"
            ;;
        vlan)
            generate_vlan_file
            ;;
        systemd)
            generate_systemd_services "true" "true"
            ;;
        setup-vlan)
            setup_vlan_infrastructure
            ;;
        disable-vlan)
            disable_vlan_infrastructure
            ;;
        # DFS/Regulatory commands (delegate to wifi-regulatory-dfs.sh)
        preflight)
            if [ "$DFS_AVAILABLE" = "true" ]; then
                preflight_check "$2" "${3:-}"
            else
                log_error "DFS script not available. Install wifi-regulatory-dfs.sh"
                exit 1
            fi
            ;;
        set-regdomain|set-reg)
            if [ "$DFS_AVAILABLE" = "true" ]; then
                set_regulatory_domain "$2"
            else
                iw reg set "${2:-US}" 2>/dev/null || log_error "Failed to set regdomain"
            fi
            ;;
        get-channels|channels)
            if [ "$DFS_AVAILABLE" = "true" ]; then
                echo "Non-DFS channels: $(get_non_dfs_channels "$2")"
                echo "DFS channels: $(get_dfs_channels "$2")"
            else
                log_error "DFS script not available"
                exit 1
            fi
            ;;
        calibrate)
            if [ "$DFS_AVAILABLE" = "true" ]; then
                calibrate_channel "$2" "${3:-/etc/hostapd/hostapd-5ghz.conf}"
            else
                log_error "DFS script not available"
                exit 1
            fi
            ;;
        install-timer|timer)
            if [ "$DFS_AVAILABLE" = "true" ]; then
                install_calibration_timer "$2"
            else
                log_error "DFS script not available"
                exit 1
            fi
            ;;
        *)
            usage
            ;;
    esac
fi
