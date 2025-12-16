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
#
# Version: 1.0.0
# License: AGPL-3.0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration paths
HOSTAPD_DIR="/etc/hostapd"
HOSTAPD_24GHZ_CONF="$HOSTAPD_DIR/hostapd-24ghz.conf"
HOSTAPD_5GHZ_CONF="$HOSTAPD_DIR/hostapd-5ghz.conf"
HOSTAPD_DUAL_CONF="$HOSTAPD_DIR/hostapd.conf"
HOSTAPD_VLAN_FILE="$HOSTAPD_DIR/hostapd.vlan"

# State file from network-interface-detector.sh
INTERFACE_STATE_FILE="/var/lib/fortress/network-interfaces.conf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[WIFI]${NC} $*"; }
log_success() { echo -e "${GREEN}[WIFI]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WIFI]${NC} $*"; }
log_error() { echo -e "${RED}[WIFI]${NC} $*"; }

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
# CAPABILITY DETECTION HELPERS
# ============================================================

get_phy_for_iface() {
    local iface="$1"
    if [ -L "/sys/class/net/$iface/phy80211" ]; then
        basename "$(readlink -f /sys/class/net/$iface/phy80211)"
    fi
}

check_wifi_capability() {
    local iface="$1"
    local capability="$2"  # 80211n, 80211ac, 80211ax, 80211be, WPA3

    local iface_upper="${iface^^}"

    case "$capability" in
        80211n)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211N\" = 'true' ]"
            ;;
        80211ac)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211AC\" = 'true' ]"
            ;;
        80211ax)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211AX\" = 'true' ]"
            ;;
        80211be)
            eval "[ \"\$NET_WIFI_${iface_upper}_80211BE\" = 'true' ]"
            ;;
        5ghz)
            eval "[ \"\$NET_WIFI_${iface_upper}_5GHZ\" = 'true' ]"
            ;;
        6ghz)
            eval "[ \"\$NET_WIFI_${iface_upper}_6GHZ\" = 'true' ]"
            ;;
        24ghz)
            eval "[ \"\$NET_WIFI_${iface_upper}_24GHZ\" = 'true' ]"
            ;;
        ap)
            eval "[ \"\$NET_WIFI_${iface_upper}_AP\" = 'true' ]"
            ;;
        vap)
            eval "[ \"\$NET_WIFI_${iface_upper}_VAP\" = 'true' ]"
            ;;
    esac
}

detect_ht_capabilities() {
    # Detect 802.11n HT capabilities for 2.4GHz
    local iface="$1"
    local phy
    phy=$(get_phy_for_iface "$iface")

    [ -z "$phy" ] && { echo "[HT40+][SHORT-GI-20]"; return; }

    local caps=""

    if iw phy "$phy" info 2>/dev/null | grep -q "HT40"; then
        caps="[HT40+]"
    fi

    if iw phy "$phy" info 2>/dev/null | grep -q "SHORT-GI-20"; then
        caps="${caps}[SHORT-GI-20]"
    fi

    if iw phy "$phy" info 2>/dev/null | grep -q "SHORT-GI-40"; then
        caps="${caps}[SHORT-GI-40]"
    fi

    if iw phy "$phy" info 2>/dev/null | grep -q "DSSS_CCK-40"; then
        caps="${caps}[DSSS_CCK-40]"
    fi

    echo "${caps:-[HT40+][SHORT-GI-20]}"
}

detect_vht_capabilities() {
    # Detect 802.11ac VHT capabilities for 5GHz
    local iface="$1"
    local phy
    phy=$(get_phy_for_iface "$iface")

    [ -z "$phy" ] && { echo "[MAX-MPDU-11454][SHORT-GI-80]"; return; }

    local caps=""

    if iw phy "$phy" info 2>/dev/null | grep -q "MAX-MPDU-11454"; then
        caps="[MAX-MPDU-11454]"
    fi

    if iw phy "$phy" info 2>/dev/null | grep -q "SHORT-GI-80"; then
        caps="${caps}[SHORT-GI-80]"
    fi

    if iw phy "$phy" info 2>/dev/null | grep -q "SU-BEAMFORMER"; then
        caps="${caps}[SU-BEAMFORMER]"
    fi

    if iw phy "$phy" info 2>/dev/null | grep -q "SU-BEAMFORMEE"; then
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

    # Check if HE is supported
    if ! iw phy "$phy" info 2>/dev/null | grep -qE "HE Capabilities|HE PHY"; then
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

    # Check if EHT (802.11be/WiFi 7) is supported
    if ! iw phy "$phy" info 2>/dev/null | grep -qE "EHT Capabilities|EHT PHY|EHT MAC"; then
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

    local phy_info
    phy_info=$(iw phy "$phy" info 2>/dev/null)

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
    local bridge="${5:-br-lan}"

    [ -z "$iface" ] && { log_error "Interface required"; return 1; }
    [ -z "$password" ] && { log_error "Password required"; return 1; }
    [ ${#password} -lt 8 ] && { log_error "Password must be at least 8 characters"; return 1; }

    # Auto-detect regulatory domain
    local country_code
    country_code=$(detect_regulatory_domain)

    log_info "Generating 2.4GHz hostapd configuration"
    log_info "  Interface: $iface"
    log_info "  SSID: $ssid"
    log_info "  Channel: $channel"
    log_info "  Bridge: $bridge"
    log_info "  Country: $country_code (auto-detected)"

    # Auto channel selection
    if [ "$channel" = "auto" ]; then
        channel=6  # Default if scan not available
        if [ -x "$SCRIPT_DIR/network-interface-detector.sh" ]; then
            channel=$("$SCRIPT_DIR/network-interface-detector.sh" scan-24ghz "$iface" 2>/dev/null | tail -1) || channel=6
        fi
    fi

    # Detect capabilities
    local ht_capab
    ht_capab=$(detect_ht_capabilities "$iface")

    local supports_ax=false
    if check_wifi_capability "$iface" "80211ax"; then
        supports_ax=true
    fi

    mkdir -p "$HOSTAPD_DIR"

    cat > "$HOSTAPD_24GHZ_CONF" << EOF
# HookProbe Fortress - 2.4GHz WiFi Configuration
# Generated: $(date -Iseconds)
#
# Purpose: Legacy/IoT device compatibility with WPA2
# Band: 2.4GHz (802.11n/b/g)
#

interface=$iface
driver=nl80211
bridge=$bridge

# Network Settings
ssid=$ssid
utf8_ssid=1
country_code=$country_code
ieee80211d=1
ieee80211h=1

# Band: 2.4GHz (802.11g mode)
hw_mode=g
channel=$channel

# 802.11n (WiFi 4)
ieee80211n=1
require_ht=0
ht_capab=$ht_capab

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

# Performance Tuning
beacon_int=100
dtim_period=2
rts_threshold=2347
fragm_threshold=2346

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
    local bridge="${5:-br-lan}"

    [ -z "$iface" ] && { log_error "Interface required"; return 1; }
    [ -z "$password" ] && { log_error "Password required"; return 1; }
    [ ${#password} -lt 8 ] && { log_error "Password must be at least 8 characters"; return 1; }

    # Auto-detect regulatory domain
    local country_code
    country_code=$(detect_regulatory_domain)

    log_info "Generating 5GHz hostapd configuration"
    log_info "  Interface: $iface"
    log_info "  SSID: $ssid"
    log_info "  Channel: $channel"
    log_info "  Bridge: $bridge"
    log_info "  Country: $country_code (auto-detected)"

    # Auto channel selection
    if [ "$channel" = "auto" ]; then
        channel=36  # Default if scan not available
        if [ -x "$SCRIPT_DIR/network-interface-detector.sh" ]; then
            channel=$("$SCRIPT_DIR/network-interface-detector.sh" scan-5ghz "$iface" 2>/dev/null | tail -1) || channel=36
        fi
    fi

    # Detect capabilities
    local vht_capab
    vht_capab=$(detect_vht_capabilities "$iface")

    local supports_ac=false
    local supports_ax=false
    local supports_be=false  # WiFi 7

    if check_wifi_capability "$iface" "80211ac"; then
        supports_ac=true
    fi
    if check_wifi_capability "$iface" "80211ax"; then
        supports_ax=true
    fi
    if check_wifi_capability "$iface" "80211be"; then
        supports_be=true
    fi

    # Calculate VHT center frequency
    local vht_oper_centr_freq_seg0_idx
    case "$channel" in
        36|40|44|48)   vht_oper_centr_freq_seg0_idx=42 ;;
        52|56|60|64)   vht_oper_centr_freq_seg0_idx=58 ;;
        100|104|108|112) vht_oper_centr_freq_seg0_idx=106 ;;
        116|120|124|128) vht_oper_centr_freq_seg0_idx=122 ;;
        132|136|140|144) vht_oper_centr_freq_seg0_idx=138 ;;
        149|153|157|161) vht_oper_centr_freq_seg0_idx=155 ;;
        *)              vht_oper_centr_freq_seg0_idx=42 ;;
    esac

    mkdir -p "$HOSTAPD_DIR"

    cat > "$HOSTAPD_5GHZ_CONF" << EOF
# HookProbe Fortress - 5GHz WiFi Configuration
# Generated: $(date -Iseconds)
#
# Purpose: High-throughput access with WPA3 security
# Band: 5GHz (802.11ac/ax/be)
#

interface=$iface
driver=nl80211
bridge=$bridge

# Network Settings
ssid=$ssid
utf8_ssid=1
country_code=$country_code
ieee80211d=1
ieee80211h=1

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
vht_oper_chwidth=1
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
        local eht_channel_width
        eht_channel_width=$(detect_eht_channel_width "$iface")

        cat >> "$HOSTAPD_5GHZ_CONF" << EOF
# 802.11be (WiFi 7) - EHT (Extremely High Throughput)
# Requires hostapd 2.11+ and compatible driver
ieee80211be=1
eht_su_beamformer=1
eht_su_beamformee=1
eht_mu_beamformer=1

# WiFi 7 channel width (up to 320 MHz supported)
# eht_oper_chwidth: 0=20MHz, 1=40MHz, 2=80MHz, 3=160MHz, 4=320MHz
EOF
        case "$eht_channel_width" in
            320) echo "eht_oper_chwidth=4" >> "$HOSTAPD_5GHZ_CONF" ;;
            160) echo "eht_oper_chwidth=3" >> "$HOSTAPD_5GHZ_CONF" ;;
            80)  echo "eht_oper_chwidth=2" >> "$HOSTAPD_5GHZ_CONF" ;;
            *)   echo "eht_oper_chwidth=2" >> "$HOSTAPD_5GHZ_CONF" ;;
        esac

        cat >> "$HOSTAPD_5GHZ_CONF" << EOF

# Multi-Link Operation (MLO) - disabled by default
# Enable for dual-band simultaneous operation (requires compatible clients)
# mlo_enabled=0

EOF
        log_info "  WiFi 7 (802.11be): enabled (${eht_channel_width}MHz max width)"
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

# Performance Tuning (High Throughput)
beacon_int=100
dtim_period=2
rts_threshold=2347
fragm_threshold=2346

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

generate_systemd_services() {
    # Generate systemd service files for hostapd

    local has_24ghz="$1"
    local has_5ghz="$2"

    log_info "Generating systemd service files"

    if [ "$has_24ghz" = "true" ]; then
        cat > /etc/systemd/system/fortress-hostapd-24ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 2.4GHz WiFi Access Point
After=network.target
Wants=network.target

[Service]
Type=forking
PIDFile=/run/hostapd-24ghz.pid
ExecStartPre=/bin/sleep 2
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd-24ghz.pid $HOSTAPD_24GHZ_CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        log_success "Created: fortress-hostapd-24ghz.service"
    fi

    if [ "$has_5ghz" = "true" ]; then
        cat > /etc/systemd/system/fortress-hostapd-5ghz.service << EOF
[Unit]
Description=HookProbe Fortress - 5GHz WiFi Access Point
After=network.target
Wants=network.target

[Service]
Type=forking
PIDFile=/run/hostapd-5ghz.pid
ExecStartPre=/bin/sleep 2
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd-5ghz.pid $HOSTAPD_5GHZ_CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        log_success "Created: fortress-hostapd-5ghz.service"
    fi

    systemctl daemon-reload
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
    #   $3 - Bridge name (optional)

    local ssid="${1:-HookProbe-Fortress}"
    local password="$2"
    local bridge="${3:-br-lan}"

    [ -z "$password" ] && { log_error "Password required"; return 1; }
    [ ${#password} -lt 8 ] && { log_error "Password must be at least 8 characters"; return 1; }

    # Load network state
    if [ -f "$INTERFACE_STATE_FILE" ]; then
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
                generate_hostapd_24ghz "$NET_WIFI_24GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"
                has_24ghz=true
            fi
            if [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
                generate_hostapd_5ghz "$NET_WIFI_5GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"
                has_5ghz=true
            fi
            ;;

        single-dual-band)
            # Single dual-band radio - create both configs for same interface
            # User can choose to run one or both (if radio supports it)
            if [ -n "$NET_WIFI_24GHZ_IFACE" ]; then
                generate_hostapd_24ghz "$NET_WIFI_24GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"
                has_24ghz=true

                # Only add 5GHz if it's a different physical operation mode
                # Some radios can do both simultaneously, others cannot
                generate_hostapd_5ghz "$NET_WIFI_5GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"
                has_5ghz=true

                log_warn "Single dual-band radio detected"
                log_warn "  You may need to choose one band or use VAP if supported"
            fi
            ;;

        24ghz-only)
            if [ -n "$NET_WIFI_24GHZ_IFACE" ]; then
                generate_hostapd_24ghz "$NET_WIFI_24GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"
                has_24ghz=true
            fi
            ;;

        5ghz-only)
            if [ -n "$NET_WIFI_5GHZ_IFACE" ]; then
                generate_hostapd_5ghz "$NET_WIFI_5GHZ_IFACE" "$ssid" "$password" "auto" "$bridge"
                has_5ghz=true
            fi
            ;;

        none|*)
            log_error "No WiFi configuration mode detected"
            return 1
            ;;
    esac

    # Generate VLAN file
    generate_vlan_file

    # Generate systemd services
    generate_systemd_services "$has_24ghz" "$has_5ghz"

    echo ""
    log_success "Dual-band WiFi configuration complete!"
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
    echo "  vlan              - Generate VLAN configuration"
    echo "  systemd           - Generate systemd services"
    echo ""
    echo "Examples:"
    echo "  $0 configure MyNetwork 'MySecurePassword123'"
    echo "  $0 24ghz wlan0 MyNetwork 'MyPassword' 6 br-lan"
    echo "  $0 5ghz wlan1 MyNetwork 'MyPassword' 36 br-lan"
    echo ""
    echo "Security:"
    echo "  - 2.4GHz uses WPA2-PSK for IoT device compatibility"
    echo "  - 5GHz uses WPA3-SAE with WPA2-PSK fallback"
    echo "  - Passwords must be at least 8 characters"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        configure)
            configure_dual_band_wifi "$2" "$3" "${4:-br-lan}"
            ;;
        24ghz)
            generate_hostapd_24ghz "$2" "$3" "$4" "${5:-auto}" "${6:-br-lan}"
            ;;
        5ghz)
            generate_hostapd_5ghz "$2" "$3" "$4" "${5:-auto}" "${6:-br-lan}"
            ;;
        vlan)
            generate_vlan_file
            ;;
        systemd)
            generate_systemd_services "true" "true"
            ;;
        *)
            usage
            ;;
    esac
fi
