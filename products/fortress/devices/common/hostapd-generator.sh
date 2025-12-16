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
#   - WiFi 6 (802.11ax) and WiFi 5 (802.11ac) features
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
    local capability="$2"  # 80211n, 80211ac, 80211ax, WPA3

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
        5ghz)
            eval "[ \"\$NET_WIFI_${iface_upper}_5GHZ\" = 'true' ]"
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

    log_info "Generating 2.4GHz hostapd configuration"
    log_info "  Interface: $iface"
    log_info "  SSID: $ssid"
    log_info "  Channel: $channel"
    log_info "  Bridge: $bridge"

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
country_code=US
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

    log_info "Generating 5GHz hostapd configuration"
    log_info "  Interface: $iface"
    log_info "  SSID: $ssid"
    log_info "  Channel: $channel"
    log_info "  Bridge: $bridge"

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

    if check_wifi_capability "$iface" "80211ac"; then
        supports_ac=true
    fi
    if check_wifi_capability "$iface" "80211ax"; then
        supports_ax=true
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
# Band: 5GHz (802.11ac/ax)
#

interface=$iface
driver=nl80211
bridge=$bridge

# Network Settings
ssid=$ssid
utf8_ssid=1
country_code=US
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
