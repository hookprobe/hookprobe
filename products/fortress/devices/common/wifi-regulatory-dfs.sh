#!/bin/bash
# ============================================================
# HookProbe Fortress WiFi Regulatory & DFS Manager
# ============================================================
#
# Comprehensive regulatory domain and DFS (Dynamic Frequency Selection)
# management for European and worldwide 5GHz WiFi deployments.
#
# Features:
#   - Sets regulatory domain BEFORE any WiFi configuration
#   - EU/ETSI DFS channel handling with CAC (Channel Availability Check)
#   - Pre-flight channel validation and testing
#   - Bandwidth capability detection (20/40/80/160/320 MHz)
#   - 4AM channel calibration for optimal performance
#   - DFS radar detection wait times
#
# European 5GHz Channel Bands (ETSI):
#   UNII-1 (36-48):  No DFS required, indoor/outdoor
#   UNII-2A (52-64): DFS required, 1-minute CAC, indoor only
#   UNII-2C (100-140): DFS required, 10-minute CAC, weather radar
#   UNII-3 (149-177): Varies by country, some allow outdoor
#
# Version: 1.0.0
# License: AGPL-3.0
#
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# State files
REGULATORY_STATE="/var/lib/fortress/regulatory-state.json"
CHANNEL_CACHE="/var/lib/fortress/channel-cache.json"
DFS_STATE="/var/lib/fortress/dfs-state.json"

log_info() { echo -e "${CYAN}[REG]${NC} $*"; }
log_success() { echo -e "${GREEN}[REG]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[REG]${NC} $*"; }
log_error() { echo -e "${RED}[REG]${NC} $*"; }
log_debug() { [ "${DEBUG:-0}" = "1" ] && echo -e "${BLUE}[DBG]${NC} $*" || true; }

# ============================================================
# EUROPEAN 5GHz CHANNEL DEFINITIONS
# ============================================================

# ETSI (European) 5GHz Channel Map
# Format: channel:frequency:dfs_required:cac_time_sec:max_power_dbm:indoor_only
declare -A EU_5GHZ_CHANNELS=(
    # UNII-1 Band (5150-5250 MHz) - No DFS, Indoor/Outdoor
    [36]="5180:no:0:23:no"
    [40]="5200:no:0:23:no"
    [44]="5220:no:0:23:no"
    [48]="5240:no:0:23:no"

    # UNII-2A Band (5250-5350 MHz) - DFS Required, Indoor Only
    [52]="5260:yes:60:23:yes"
    [56]="5280:yes:60:23:yes"
    [60]="5300:yes:60:23:yes"
    [64]="5320:yes:60:23:yes"

    # UNII-2C Band (5470-5725 MHz) - DFS Required, Weather Radar
    # 10-minute CAC for weather radar channels
    [100]="5500:yes:600:30:no"
    [104]="5520:yes:600:30:no"
    [108]="5540:yes:600:30:no"
    [112]="5560:yes:600:30:no"
    [116]="5580:yes:600:30:no"
    [120]="5600:yes:600:30:no"
    [124]="5620:yes:600:30:no"
    [128]="5640:yes:600:30:no"
    [132]="5660:yes:600:30:no"
    [136]="5680:yes:600:30:no"
    [140]="5700:yes:600:30:no"
    [144]="5720:yes:600:30:no"

    # UNII-3 Band (5725-5875 MHz) - Varies by country
    # Not allowed in many EU countries, or limited power
    [149]="5745:no:0:14:no"
    [153]="5765:no:0:14:no"
    [157]="5785:no:0:14:no"
    [161]="5805:no:0:14:no"
    [165]="5825:no:0:14:no"
)

# EU countries list (ETSI regulatory domain)
EU_ETSI_COUNTRIES="AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE GB UK CH NO IS LI"

# Countries where UNII-3 (149-165) is NOT allowed
EU_NO_UNII3="DE FR IT ES PL NL BE AT CZ HU RO BG SK SI HR EE LV LT"

# ============================================================
# REGULATORY DOMAIN MANAGEMENT
# ============================================================

get_phy_for_interface() {
    local iface="$1"
    if [ -L "/sys/class/net/$iface/phy80211" ]; then
        basename "$(readlink -f /sys/class/net/$iface/phy80211)"
    fi
}

get_current_regdomain() {
    # Get currently active regulatory domain
    if command -v iw &>/dev/null; then
        iw reg get 2>/dev/null | grep -oP "country \K[A-Z]{2}" | head -1
    fi
}

set_regulatory_domain() {
    # Set regulatory domain for WiFi operation
    # MUST be called BEFORE any hostapd configuration
    #
    # Args:
    #   $1 - Country code (e.g., GB, DE, FR)
    #   $2 - Interface (optional, for phy-specific setting)

    local country="${1:-}"
    local iface="${2:-}"

    if [ -z "$country" ]; then
        log_error "Country code required"
        return 1
    fi

    country="${country^^}"  # Uppercase

    log_info "Setting regulatory domain: $country"

    # Method 1: iw reg set (preferred)
    if command -v iw &>/dev/null; then
        log_debug "Using iw reg set $country"
        if ! iw reg set "$country" 2>/dev/null; then
            log_warn "iw reg set failed, trying alternative methods"
        fi
    fi

    # Method 2: wpa_cli (if wpa_supplicant running)
    if command -v wpa_cli &>/dev/null; then
        wpa_cli -g /var/run/wpa_supplicant/ctrl set country "$country" 2>/dev/null || true
    fi

    # Method 3: Kernel module parameter
    if [ -f /sys/module/cfg80211/parameters/ieee80211_regdom ]; then
        echo "$country" > /sys/module/cfg80211/parameters/ieee80211_regdom 2>/dev/null || true
    fi

    # Wait for regulatory database to update
    sleep 1

    # Verify
    local current
    current=$(get_current_regdomain)
    if [ "$current" = "$country" ]; then
        log_success "Regulatory domain set to $country"

        # Save state
        mkdir -p "$(dirname "$REGULATORY_STATE")"
        cat > "$REGULATORY_STATE" << EOF
{
    "country": "$country",
    "set_at": "$(date -Iseconds)",
    "method": "iw",
    "verified": true
}
EOF
        return 0
    else
        log_warn "Regulatory domain may not be fully applied (current: ${current:-unknown})"
        return 1
    fi
}

detect_country_from_system() {
    # Auto-detect country from system settings
    # Priority: env > saved config > timezone > locale > geoip

    # 1. Environment variable
    [ -n "${WIFI_COUNTRY_CODE:-}" ] && echo "${WIFI_COUNTRY_CODE^^}" && return

    # 2. Saved configuration
    if [ -f /etc/hookprobe/wifi.conf ]; then
        local saved
        saved=$(grep "^WIFI_COUNTRY=" /etc/hookprobe/wifi.conf 2>/dev/null | cut -d= -f2 | tr -d '"')
        [ -n "$saved" ] && echo "${saved^^}" && return
    fi

    # 3. Timezone-based detection
    local timezone=""
    if command -v timedatectl &>/dev/null; then
        timezone=$(timedatectl show -p Timezone --value 2>/dev/null)
    elif [ -f /etc/timezone ]; then
        timezone=$(cat /etc/timezone 2>/dev/null)
    fi

    if [ -n "$timezone" ]; then
        case "$timezone" in
            Europe/London|Europe/Belfast)     echo "GB"; return ;;
            Europe/Dublin)                    echo "IE"; return ;;
            Europe/Paris)                     echo "FR"; return ;;
            Europe/Berlin|Europe/Munich)      echo "DE"; return ;;
            Europe/Rome)                      echo "IT"; return ;;
            Europe/Madrid|Europe/Barcelona)   echo "ES"; return ;;
            Europe/Amsterdam)                 echo "NL"; return ;;
            Europe/Brussels)                  echo "BE"; return ;;
            Europe/Vienna)                    echo "AT"; return ;;
            Europe/Zurich)                    echo "CH"; return ;;
            Europe/Stockholm)                 echo "SE"; return ;;
            Europe/Oslo)                      echo "NO"; return ;;
            Europe/Copenhagen)                echo "DK"; return ;;
            Europe/Helsinki)                  echo "FI"; return ;;
            Europe/Warsaw)                    echo "PL"; return ;;
            Europe/Prague)                    echo "CZ"; return ;;
            Europe/Budapest)                  echo "HU"; return ;;
            Europe/Bucharest)                 echo "RO"; return ;;
            Europe/Athens)                    echo "GR"; return ;;
            Europe/Lisbon)                    echo "PT"; return ;;
            America/New_York|America/Chicago|America/Los_Angeles|America/Denver)
                                              echo "US"; return ;;
            America/Toronto|America/Vancouver) echo "CA"; return ;;
            Asia/Tokyo)                       echo "JP"; return ;;
            Asia/Seoul)                       echo "KR"; return ;;
            Australia/Sydney|Australia/Melbourne) echo "AU"; return ;;
        esac
    fi

    # 4. Locale-based
    local locale="${LANG:-}"
    if [ -n "$locale" ]; then
        local lc_country
        lc_country=$(echo "$locale" | sed -n 's/.*_\([A-Z][A-Z]\).*/\1/p')
        [ -n "$lc_country" ] && [ ${#lc_country} -eq 2 ] && echo "$lc_country" && return
    fi

    # 5. Default
    echo "US"
}

is_eu_country() {
    local country="${1:-}"
    echo "$EU_ETSI_COUNTRIES" | grep -qw "$country"
}

is_unii3_allowed() {
    local country="${1:-}"
    ! echo "$EU_NO_UNII3" | grep -qw "$country"
}

# ============================================================
# CHANNEL AVAILABILITY & DFS
# ============================================================

get_available_channels_5ghz() {
    # Get list of available 5GHz channels for an interface
    # Respects regulatory domain and DFS status
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Include DFS channels (true/false, default: false)
    #
    # Output: Space-separated channel list

    local iface="$1"
    local include_dfs="${2:-false}"

    local phy
    phy=$(get_phy_for_interface "$iface")
    [ -z "$phy" ] && return 1

    local channels=""
    local phy_info

    # Get phy info (handle ath12k which needs different parsing)
    phy_info=$(iw phy "$phy" info 2>/dev/null) || phy_info=$(iw phy 2>/dev/null | sed -n "/Wiphy $phy/,/^Wiphy /p")

    # Parse 5GHz frequencies (5150-5925 MHz)
    while read -r line; do
        if echo "$line" | grep -qE "^\s*\* 5[0-9]{3} MHz \[([0-9]+)\]"; then
            local freq ch disabled no_ir radar

            freq=$(echo "$line" | grep -oE "5[0-9]{3}" | head -1)
            ch=$(echo "$line" | grep -oE '\[[0-9]+\]' | tr -d '[]')

            # Check for restrictions
            disabled=$(echo "$line" | grep -q "disabled" && echo "yes" || echo "no")
            no_ir=$(echo "$line" | grep -q "no IR" && echo "yes" || echo "no")
            radar=$(echo "$line" | grep -q "radar" && echo "yes" || echo "no")

            log_debug "Channel $ch ($freq MHz): disabled=$disabled, no_ir=$no_ir, radar=$radar"

            # Skip disabled channels
            [ "$disabled" = "yes" ] && continue

            # Handle DFS channels
            if [ "$radar" = "yes" ] || [ "$no_ir" = "yes" ]; then
                if [ "$include_dfs" = "true" ]; then
                    channels="$channels $ch"
                fi
            else
                channels="$channels $ch"
            fi
        fi
    done <<< "$phy_info"

    echo "$channels" | xargs
}

get_non_dfs_channels() {
    # Get only non-DFS 5GHz channels (UNII-1 band)
    # Safe channels that don't require radar detection
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Country code

    local iface="$1"
    local country="${2:-$(get_current_regdomain)}"

    local all_channels
    all_channels=$(get_available_channels_5ghz "$iface" false)

    local safe_channels=""
    for ch in $all_channels; do
        # UNII-1 channels (36-48) are non-DFS worldwide
        if [ "$ch" -ge 36 ] && [ "$ch" -le 48 ] 2>/dev/null; then
            safe_channels="$safe_channels $ch"
        fi
        # UNII-3 channels if allowed in country
        if [ "$ch" -ge 149 ] && [ "$ch" -le 165 ] 2>/dev/null; then
            if is_unii3_allowed "$country"; then
                safe_channels="$safe_channels $ch"
            fi
        fi
    done

    echo "$safe_channels" | xargs
}

get_dfs_channels() {
    # Get DFS channels (UNII-2A and UNII-2C bands)
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"

    local all_channels
    all_channels=$(get_available_channels_5ghz "$iface" true)

    local dfs_channels=""
    for ch in $all_channels; do
        # UNII-2A (52-64) and UNII-2C (100-144)
        if [ "$ch" -ge 52 ] && [ "$ch" -le 64 ] 2>/dev/null; then
            dfs_channels="$dfs_channels $ch"
        elif [ "$ch" -ge 100 ] && [ "$ch" -le 144 ] 2>/dev/null; then
            dfs_channels="$dfs_channels $ch"
        fi
    done

    echo "$dfs_channels" | xargs
}

get_cac_time() {
    # Get CAC (Channel Availability Check) time for a channel
    # ETSI requires 60s for UNII-2A, 600s for UNII-2C (weather radar)
    #
    # Args:
    #   $1 - Channel number
    #
    # Output: CAC time in seconds

    local channel="$1"

    # UNII-2A (52-64): 60 second CAC
    if [ "$channel" -ge 52 ] && [ "$channel" -le 64 ] 2>/dev/null; then
        echo "60"
        return
    fi

    # UNII-2C (100-144): 600 second CAC (10 minutes) for weather radar
    if [ "$channel" -ge 100 ] && [ "$channel" -le 144 ] 2>/dev/null; then
        echo "600"
        return
    fi

    # Non-DFS: no CAC required
    echo "0"
}

is_dfs_channel() {
    # Check if a channel is a DFS channel
    #
    # Args:
    #   $1 - Channel number
    #
    # Returns: 0 if DFS, 1 if not

    local channel="$1"

    # UNII-2A (52-64) or UNII-2C (100-144)
    if [ "$channel" -ge 52 ] && [ "$channel" -le 64 ] 2>/dev/null; then
        return 0
    fi
    if [ "$channel" -ge 100 ] && [ "$channel" -le 144 ] 2>/dev/null; then
        return 0
    fi

    return 1
}

wait_for_dfs() {
    # Wait for DFS CAC to complete
    # Shows progress bar and allows cancellation
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Channel number
    #   $3 - Skip wait if CAC already done (true/false)

    local iface="$1"
    local channel="$2"
    local skip_if_done="${3:-false}"

    if ! is_dfs_channel "$channel"; then
        log_info "Channel $channel is non-DFS, no CAC wait required"
        return 0
    fi

    local cac_time
    cac_time=$(get_cac_time "$channel")

    if [ "$cac_time" -eq 0 ]; then
        return 0
    fi

    log_info "DFS Channel $channel requires ${cac_time}s CAC (Channel Availability Check)"

    # Check if CAC already completed (from previous hostapd run)
    if [ "$skip_if_done" = "true" ] && [ -f "$DFS_STATE" ]; then
        local cached_time
        cached_time=$(jq -r ".channels[\"$channel\"].cac_completed // empty" "$DFS_STATE" 2>/dev/null)
        if [ -n "$cached_time" ]; then
            local now cached_epoch
            now=$(date +%s)
            cached_epoch=$(date -d "$cached_time" +%s 2>/dev/null || echo 0)
            # CAC valid for 30 minutes after completion
            if [ $((now - cached_epoch)) -lt 1800 ]; then
                log_info "CAC previously completed for channel $channel, skipping wait"
                return 0
            fi
        fi
    fi

    log_warn "Waiting ${cac_time}s for DFS radar detection..."

    local start_time elapsed remaining pct
    start_time=$(date +%s)

    while true; do
        elapsed=$(($(date +%s) - start_time))
        remaining=$((cac_time - elapsed))

        if [ "$remaining" -le 0 ]; then
            break
        fi

        pct=$((elapsed * 100 / cac_time))
        printf "\r  [%-50s] %3d%% (%ds remaining)  " \
            "$(printf '#%.0s' $(seq 1 $((pct / 2))))" \
            "$pct" "$remaining"

        sleep 1
    done

    printf "\n"
    log_success "CAC complete for channel $channel"

    # Save CAC completion
    mkdir -p "$(dirname "$DFS_STATE")"
    if [ -f "$DFS_STATE" ]; then
        local tmp
        tmp=$(mktemp)
        jq --arg ch "$channel" --arg time "$(date -Iseconds)" \
            '.channels[$ch].cac_completed = $time' "$DFS_STATE" > "$tmp" && mv "$tmp" "$DFS_STATE"
    else
        cat > "$DFS_STATE" << EOF
{
    "channels": {
        "$channel": {
            "cac_completed": "$(date -Iseconds)"
        }
    }
}
EOF
    fi

    return 0
}

# ============================================================
# BANDWIDTH CAPABILITY DETECTION
# ============================================================

detect_max_bandwidth() {
    # Detect maximum supported channel bandwidth
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Band (5ghz or 6ghz)
    #
    # Output: Maximum bandwidth in MHz (20, 40, 80, 160, 320)

    local iface="$1"
    local band="${2:-5ghz}"

    local phy
    phy=$(get_phy_for_interface "$iface")
    [ -z "$phy" ] && { echo "20"; return; }

    local phy_info
    phy_info=$(iw phy "$phy" info 2>/dev/null) || phy_info=$(iw phy 2>/dev/null)

    local max_bw=20

    # Check for 320 MHz (WiFi 7 EHT)
    if echo "$phy_info" | grep -qiE "320 MHz|EHT.*320|eht_oper_chwidth.*4"; then
        max_bw=320
    # Check for 160 MHz
    elif echo "$phy_info" | grep -qiE "VHT160|160 MHz|vht_capab.*\[VHT160\]|vht.*160"; then
        max_bw=160
    # Check for 80+80 MHz (treated as 160)
    elif echo "$phy_info" | grep -qiE "80\+80|VHT80\+80"; then
        max_bw=160
    # Check for 80 MHz
    elif echo "$phy_info" | grep -qiE "VHT80|80 MHz|vht_capab|ieee80211ac"; then
        max_bw=80
    # Check for 40 MHz
    elif echo "$phy_info" | grep -qiE "HT40|40 MHz|ht_capab"; then
        max_bw=40
    fi

    echo "$max_bw"
}

validate_bandwidth() {
    # Validate that a bandwidth configuration is supported
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Requested bandwidth (20, 40, 80, 160, 320)
    #   $3 - Channel number
    #
    # Returns: 0 if valid, 1 if not

    local iface="$1"
    local requested_bw="$2"
    local channel="$3"

    local max_bw
    max_bw=$(detect_max_bandwidth "$iface")

    log_debug "Validating bandwidth: requested=$requested_bw, max_supported=$max_bw, channel=$channel"

    # Check if hardware supports this bandwidth
    if [ "$requested_bw" -gt "$max_bw" ] 2>/dev/null; then
        log_error "Hardware supports max ${max_bw}MHz, requested ${requested_bw}MHz"
        return 1
    fi

    # Check channel compatibility with bandwidth
    case "$requested_bw" in
        320)
            # 320 MHz requires specific channels (WiFi 7)
            case "$channel" in
                36|40|44|48|52|56|60|64) ;; # Primary 320 MHz
                *) log_warn "Channel $channel may not support 320MHz width"; return 1 ;;
            esac
            ;;
        160)
            # 160 MHz valid channel groups
            case "$channel" in
                36|40|44|48|52|56|60|64) ;;   # 5180-5320 MHz
                100|104|108|112|116|120|124|128) ;; # 5500-5640 MHz
                *) log_warn "Channel $channel does not support 160MHz width"; return 1 ;;
            esac
            ;;
        80)
            # 80 MHz valid channel groups
            case "$channel" in
                36|40|44|48) ;;     # Center: 42
                52|56|60|64) ;;     # Center: 58
                100|104|108|112) ;; # Center: 106
                116|120|124|128) ;; # Center: 122
                132|136|140|144) ;; # Center: 138
                149|153|157|161) ;; # Center: 155
                *) log_warn "Channel $channel does not support 80MHz width"; return 1 ;;
            esac
            ;;
        40)
            # HT40 requires proper +/- configuration
            # Even channels: HT40+, Odd channels at boundaries: HT40-
            ;;
    esac

    log_success "Bandwidth ${requested_bw}MHz validated for channel $channel"
    return 0
}

get_vht_center_freq() {
    # Get VHT center frequency segment 0 index for a channel
    #
    # Args:
    #   $1 - Channel number
    #   $2 - Bandwidth (80 or 160)
    #
    # Output: Center frequency index

    local channel="$1"
    local bandwidth="${2:-80}"

    case "$bandwidth" in
        160)
            case "$channel" in
                36|40|44|48|52|56|60|64) echo "50" ;;
                100|104|108|112|116|120|124|128) echo "114" ;;
                *) echo "50" ;;
            esac
            ;;
        80)
            case "$channel" in
                36|40|44|48) echo "42" ;;
                52|56|60|64) echo "58" ;;
                100|104|108|112) echo "106" ;;
                116|120|124|128) echo "122" ;;
                132|136|140|144) echo "138" ;;
                149|153|157|161) echo "155" ;;
                *) echo "42" ;;
            esac
            ;;
        *)
            echo "0"
            ;;
    esac
}

# ============================================================
# CHANNEL TESTING & VALIDATION
# ============================================================

test_channel() {
    # Test if a channel can be used before configuration
    # Performs actual frequency switch to verify
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Channel number
    #   $3 - Timeout in seconds (default: 5)
    #
    # Returns: 0 if channel works, 1 if not

    local iface="$1"
    local channel="$2"
    local timeout="${3:-5}"

    log_info "Testing channel $channel on $iface..."

    # Ensure interface is up but not in use
    ip link set "$iface" down 2>/dev/null || true
    sleep 0.5
    ip link set "$iface" up 2>/dev/null || true

    # Set interface to managed mode
    iw dev "$iface" set type managed 2>/dev/null || true

    # Convert channel to frequency
    local freq
    freq=$(channel_to_freq "$channel")
    [ -z "$freq" ] && { log_error "Invalid channel $channel"; return 1; }

    # Try to set frequency
    if timeout "$timeout" iw dev "$iface" set freq "$freq" 2>/dev/null; then
        log_success "Channel $channel ($freq MHz) - OK"
        return 0
    else
        log_warn "Channel $channel ($freq MHz) - FAILED"
        return 1
    fi
}

channel_to_freq() {
    # Convert WiFi channel number to frequency in MHz
    #
    # Args:
    #   $1 - Channel number
    #
    # Output: Frequency in MHz

    local ch="$1"

    # 2.4 GHz (channels 1-14)
    if [ "$ch" -ge 1 ] && [ "$ch" -le 14 ] 2>/dev/null; then
        if [ "$ch" -eq 14 ]; then
            echo "2484"
        else
            echo $((2407 + ch * 5))
        fi
        return
    fi

    # 5 GHz (channels 36-177)
    if [ "$ch" -ge 36 ] && [ "$ch" -le 177 ] 2>/dev/null; then
        echo $((5000 + ch * 5))
        return
    fi

    # 6 GHz (channels 1-233)
    if [ "$ch" -ge 1 ] && [ "$ch" -le 233 ] 2>/dev/null; then
        echo $((5950 + ch * 5))
        return
    fi
}

scan_for_best_channel() {
    # Scan for least congested channel in 5GHz band
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Include DFS channels (true/false, default: false)
    #   $3 - Country code
    #   $4 - Prefer UNII-2A DFS (52-64) over UNII-1 (true/false, default: false)
    #
    # Output: Best channel number

    local iface="$1"
    local include_dfs="${2:-false}"
    local country="${3:-$(get_current_regdomain)}"
    local prefer_unii2a="${4:-false}"

    log_info "Scanning for best 5GHz channel..."
    log_info "  Include DFS: $include_dfs"
    log_info "  Country: $country"

    # Build channel list based on mode
    local channels=""

    if [ "$include_dfs" = "true" ]; then
        # Include DFS channels - prioritize UNII-2A (52-64) as they're often clearer
        if [ "$prefer_unii2a" = "true" ]; then
            # UNII-2A first (52-64), then UNII-1 (36-48)
            channels="52 56 60 64 36 40 44 48"
            log_info "  Priority: UNII-2A (52-64) > UNII-1 (36-48)"
        else
            # All available DFS + non-DFS
            channels=$(get_available_channels_5ghz "$iface" true)
        fi
    else
        # Non-DFS only
        channels=$(get_non_dfs_channels "$iface" "$country")
    fi

    [ -z "$channels" ] && { echo "36"; return; }

    # Bring interface up for scanning
    ip link set "$iface" up 2>/dev/null || true
    sleep 1

    # Scan for APs
    local scan_results
    scan_results=$(iw dev "$iface" scan 2>/dev/null) || true

    # Count APs per channel
    local best_channel=36
    local min_aps=999
    local channel_scores=""

    for ch in $channels; do
        local freq
        freq=$(channel_to_freq "$ch")

        local ap_count
        ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null || echo "0")

        # Add DFS penalty score (prefer non-DFS if equal AP count)
        local score="$ap_count"
        if is_dfs_channel "$ch" 2>/dev/null && [ "$prefer_unii2a" != "true" ]; then
            # Add small penalty to DFS channels unless explicitly preferred
            score=$((ap_count + 1))
        fi

        log_debug "Channel $ch ($freq MHz): $ap_count APs (score: $score)"
        channel_scores="${channel_scores}$ch:$score "

        if [ "$score" -lt "$min_aps" ]; then
            min_aps="$score"
            best_channel="$ch"
        fi
    done

    # If DFS preferred and UNII-2A is clear, prefer it over UNII-1
    if [ "$prefer_unii2a" = "true" ]; then
        for ch in 52 56 60 64; do
            local freq
            freq=$(channel_to_freq "$ch")
            local ap_count
            ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null || echo "0")

            # If UNII-2A channel is clear (0 APs), prefer it
            if [ "$ap_count" -eq 0 ]; then
                best_channel="$ch"
                log_info "  Found clear UNII-2A channel: $ch"
                break
            fi
        done
    fi

    local dfs_marker=""
    if is_dfs_channel "$best_channel" 2>/dev/null; then
        dfs_marker=" (DFS)"
    fi

    log_success "Best channel: $best_channel$dfs_marker ($min_aps nearby APs)"
    echo "$best_channel"
}

# ============================================================
# CHANNEL CALIBRATION (4AM OPTIMIZATION)
# ============================================================

calibrate_channel() {
    # Perform full channel calibration
    # At 4AM: Includes DFS channels (52-64) with CAC wait
    # Quick mode: Non-DFS only for fast startup
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Config file to update
    #   $3 - Mode: "full" (4AM, includes DFS) or "quick" (non-DFS only)
    #   $4 - Dry run (true/false, default: false)

    local iface="$1"
    local config_file="${2:-/etc/hostapd/hostapd-5ghz.conf}"
    local mode="${3:-full}"
    local dry_run="${4:-false}"

    log_info "=========================================="
    log_info "WiFi Channel Calibration"
    log_info "Time: $(date -Iseconds)"
    log_info "Interface: $iface"
    log_info "Mode: $mode"
    log_info "=========================================="

    # Get current country
    local country
    country=$(get_current_regdomain)
    log_info "Regulatory domain: $country"

    # Ensure regulatory domain is set before any operations
    set_regulatory_domain "$country" "$iface" 2>/dev/null || true

    # Get current channel from config
    local current_channel
    if [ -f "$config_file" ]; then
        current_channel=$(grep "^channel=" "$config_file" | cut -d= -f2)
    fi
    log_info "Current channel: ${current_channel:-unknown}"

    # Scan for best channel based on mode
    local best_channel
    local include_dfs=false
    local prefer_unii2a=false

    if [ "$mode" = "full" ]; then
        # Full mode (4AM): Include DFS, prefer UNII-2A (52-64) which are often clearer
        include_dfs=true
        prefer_unii2a=true
        log_info "Full calibration: Including DFS channels (52-64), will wait for CAC"
    else
        # Quick mode: Non-DFS only for fast startup
        include_dfs=false
        log_info "Quick calibration: Non-DFS only (36-48) for fast startup"
    fi

    best_channel=$(scan_for_best_channel "$iface" "$include_dfs" "$country" "$prefer_unii2a")
    log_info "Recommended channel: $best_channel"

    # Check if selected channel is DFS
    local is_dfs=false
    local cac_time=0
    if is_dfs_channel "$best_channel" 2>/dev/null; then
        is_dfs=true
        cac_time=$(get_cac_time "$best_channel")
        log_warn "Selected channel $best_channel is DFS (UNII-2A)"
        log_warn "CAC (radar detection) required: ${cac_time}s"
    fi

    # Compare with current
    if [ "$best_channel" = "$current_channel" ]; then
        log_success "Already on optimal channel $best_channel"
        return 0
    fi

    # Validate new channel
    if ! test_channel "$iface" "$best_channel" 5; then
        log_warn "Channel $best_channel test failed"

        # If DFS failed, try falling back to UNII-1
        if [ "$is_dfs" = "true" ]; then
            log_info "Falling back to non-DFS channel scan..."
            best_channel=$(scan_for_best_channel "$iface" false "$country" false)
            log_info "Fallback channel: $best_channel"
            is_dfs=false
            cac_time=0
        else
            log_error "Channel validation failed, keeping current"
            return 1
        fi
    fi

    if [ "$dry_run" = "true" ]; then
        log_info "DRY RUN: Would switch from channel $current_channel to $best_channel"
        [ "$is_dfs" = "true" ] && log_info "DRY RUN: Would wait ${cac_time}s for DFS CAC"
        return 0
    fi

    # For DFS channels, we need to wait for CAC before hostapd can use it
    # hostapd handles this automatically, but we should inform the user
    if [ "$is_dfs" = "true" ] && [ "$cac_time" -gt 0 ]; then
        log_warn "=========================================="
        log_warn "DFS Channel Selected: $best_channel"
        log_warn "=========================================="
        log_warn "hostapd will perform ${cac_time}s CAC (radar detection)"
        log_warn "AP will not be available during this time"
        log_warn "This is normal for UNII-2A channels in EU/ETSI regions"
        log_warn "=========================================="
    fi

    # Update configuration
    if [ -f "$config_file" ]; then
        log_info "Updating $config_file: channel=$best_channel"
        sed -i "s/^channel=.*/channel=$best_channel/" "$config_file"

        # Update VHT center frequency if needed
        local center_freq
        center_freq=$(get_vht_center_freq "$best_channel" 80)
        if grep -q "vht_oper_centr_freq_seg0_idx" "$config_file"; then
            sed -i "s/^vht_oper_centr_freq_seg0_idx=.*/vht_oper_centr_freq_seg0_idx=$center_freq/" "$config_file"
        fi

        # Restart hostapd
        if systemctl is-active --quiet hostapd-5ghz 2>/dev/null; then
            log_info "Restarting hostapd-5ghz..."
            systemctl restart hostapd-5ghz
        elif systemctl is-active --quiet hostapd 2>/dev/null; then
            log_info "Restarting hostapd..."
            systemctl restart hostapd
        fi

        log_success "Channel calibration complete: $current_channel → $best_channel"
    else
        log_warn "Config file $config_file not found"
        return 1
    fi

    # Save calibration result
    mkdir -p "$(dirname "$CHANNEL_CACHE")"
    cat > "$CHANNEL_CACHE" << EOF
{
    "interface": "$iface",
    "previous_channel": ${current_channel:-null},
    "new_channel": $best_channel,
    "is_dfs": $is_dfs,
    "cac_time_sec": $cac_time,
    "mode": "$mode",
    "calibrated_at": "$(date -Iseconds)",
    "country": "$country"
}
EOF

    return 0
}

quick_start_channel() {
    # Quick channel selection for boot/restart scenarios
    # Uses ONLY non-DFS channels for immediate availability
    # No CAC wait - AP starts immediately
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Config file to update (optional)
    #
    # Returns: Selected channel number

    local iface="$1"
    local config_file="${2:-}"

    log_info "=========================================="
    log_info "Quick Start Channel Selection"
    log_info "=========================================="
    log_info "Mode: Non-DFS only (immediate startup)"

    local country
    country=$(get_current_regdomain)

    # Set regulatory domain
    set_regulatory_domain "$country" "$iface" 2>/dev/null || true

    # Scan only non-DFS channels (36-48, and 149-165 where allowed)
    local best_channel
    best_channel=$(scan_for_best_channel "$iface" false "$country" false)

    log_success "Quick start channel: $best_channel (non-DFS)"

    # Update config if specified
    if [ -n "$config_file" ] && [ -f "$config_file" ]; then
        log_info "Updating $config_file: channel=$best_channel"
        sed -i "s/^channel=.*/channel=$best_channel/" "$config_file"

        local center_freq
        center_freq=$(get_vht_center_freq "$best_channel" 80)
        if grep -q "vht_oper_centr_freq_seg0_idx" "$config_file"; then
            sed -i "s/^vht_oper_centr_freq_seg0_idx=.*/vht_oper_centr_freq_seg0_idx=$center_freq/" "$config_file"
        fi
    fi

    echo "$best_channel"
}

install_calibration_timer() {
    # Install systemd timer for 4AM daily channel calibration
    #
    # Args:
    #   $1 - Interface name (default: auto-detect)

    local iface="${1:-}"

    log_info "Installing channel calibration timer..."

    # Auto-detect interface if not specified
    if [ -z "$iface" ]; then
        iface=$(ls /sys/class/net | grep -E "^wl" | head -1)
        [ -z "$iface" ] && { log_error "No WiFi interface found"; return 1; }
    fi

    # Create calibration service - uses FULL mode at 4AM to include DFS channels
    cat > /etc/systemd/system/fortress-channel-calibrate.service << EOF
[Unit]
Description=HookProbe Fortress WiFi Channel Calibration (4AM Full Mode with DFS)
After=network.target hostapd.service

[Service]
Type=oneshot
# Full mode: Scans DFS channels (52-64), waits for CAC if needed
# This is safe at 4AM when we have time for the 60s radar detection
ExecStart=/opt/hookprobe/fortress/devices/common/wifi-regulatory-dfs.sh calibrate-full $iface
StandardOutput=journal
StandardError=journal
# Allow up to 10 minutes for DFS CAC
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
EOF

    # Create timer for 4AM daily
    cat > /etc/systemd/system/fortress-channel-calibrate.timer << EOF
[Unit]
Description=Daily WiFi Channel Calibration at 4AM (includes DFS channels)

[Timer]
# Run at 4AM - low traffic time, safe to wait for DFS CAC
OnCalendar=*-*-* 04:00:00
# Add randomization to avoid all devices calibrating at once
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Create quick-start service for boot/reboot (non-DFS only)
    cat > /etc/systemd/system/fortress-channel-quickstart.service << EOF
[Unit]
Description=HookProbe Fortress WiFi Quick Start (Non-DFS only)
After=network.target
Before=hostapd.service hostapd-5ghz.service

[Service]
Type=oneshot
# Quick mode: Only non-DFS channels (36-48) for immediate AP availability
ExecStart=/opt/hookprobe/fortress/devices/common/wifi-regulatory-dfs.sh quick-start $iface /etc/hostapd/hostapd-5ghz.conf
StandardOutput=journal
StandardError=journal
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Enable timer
    systemctl daemon-reload
    systemctl enable fortress-channel-calibrate.timer
    systemctl start fortress-channel-calibrate.timer

    log_success "Channel calibration timer installed (runs daily at 4AM)"
    log_info "  4AM Service: fortress-channel-calibrate.service (full mode with DFS)"
    log_info "  Timer: fortress-channel-calibrate.timer"
    log_info "  Quick Start: fortress-channel-quickstart.service (non-DFS for boot)"
    log_info ""
    log_info "Modes:"
    log_info "  4AM (full): Scans DFS channels (52-64), may wait 60s for CAC"
    log_info "  Boot (quick): Non-DFS only (36-48), immediate startup"
    log_info ""
    log_info "To enable quick-start on boot:"
    log_info "  systemctl enable fortress-channel-quickstart.service"
}

# ============================================================
# PRE-FLIGHT VALIDATION
# ============================================================

preflight_check() {
    # Comprehensive pre-flight check before WiFi configuration
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Country code (optional, auto-detected)
    #
    # Validates:
    #   - Regulatory domain is set
    #   - Available channels
    #   - Bandwidth capabilities
    #   - DFS requirements

    local iface="$1"
    local country="${2:-}"

    log_info "=========================================="
    log_info "WiFi Pre-Flight Check"
    log_info "=========================================="

    local errors=0

    # Check interface exists
    if [ ! -d "/sys/class/net/$iface" ]; then
        log_error "Interface $iface not found"
        return 1
    fi
    log_success "Interface $iface exists"

    # Get/set regulatory domain
    if [ -z "$country" ]; then
        country=$(detect_country_from_system)
    fi

    local current_reg
    current_reg=$(get_current_regdomain)

    if [ "$current_reg" != "$country" ]; then
        log_warn "Regulatory domain mismatch: current=$current_reg, expected=$country"
        log_info "Setting regulatory domain to $country..."
        if ! set_regulatory_domain "$country"; then
            log_error "Failed to set regulatory domain"
            ((errors++))
        fi
    else
        log_success "Regulatory domain: $country"
    fi

    # Check if EU country
    if is_eu_country "$country"; then
        log_info "EU/ETSI regulatory region detected"
        if ! is_unii3_allowed "$country"; then
            log_warn "UNII-3 (149-165) channels NOT allowed in $country"
        fi
    fi

    # Get available channels
    log_info "Checking available channels..."

    local non_dfs_channels dfs_channels
    non_dfs_channels=$(get_non_dfs_channels "$iface" "$country")
    dfs_channels=$(get_dfs_channels "$iface")

    log_info "Non-DFS channels: ${non_dfs_channels:-none}"
    log_info "DFS channels: ${dfs_channels:-none}"

    if [ -z "$non_dfs_channels" ]; then
        log_error "No non-DFS channels available!"
        ((errors++))
    fi

    # Check bandwidth capabilities
    local max_bw
    max_bw=$(detect_max_bandwidth "$iface" "5ghz")
    log_success "Maximum bandwidth: ${max_bw}MHz"

    case "$max_bw" in
        320) log_info "  WiFi 7 (802.11be) capable" ;;
        160) log_info "  WiFi 6/5 (802.11ax/ac) capable" ;;
        80)  log_info "  WiFi 5 (802.11ac) capable" ;;
        40)  log_info "  WiFi 4 (802.11n) capable" ;;
        20)  log_warn "  Limited to 20MHz channels" ;;
    esac

    # Test a channel
    local test_ch="${non_dfs_channels%% *}"  # First non-DFS channel
    if [ -n "$test_ch" ]; then
        if test_channel "$iface" "$test_ch" 3; then
            log_success "Channel test passed ($test_ch)"
        else
            log_warn "Channel test failed ($test_ch)"
            ((errors++))
        fi
    fi

    # Summary
    log_info "=========================================="
    if [ "$errors" -eq 0 ]; then
        log_success "Pre-flight check PASSED"
        log_info "Recommended configuration:"
        log_info "  Country: $country"
        log_info "  Channel: ${test_ch:-36}"
        log_info "  Bandwidth: ${max_bw}MHz"
        return 0
    else
        log_error "Pre-flight check FAILED ($errors errors)"
        return 1
    fi
}

# ============================================================
# HOSTAPD CONFIGURATION HELPERS
# ============================================================

generate_dfs_hostapd_config() {
    # Generate DFS-aware hostapd configuration snippet
    #
    # Args:
    #   $1 - Channel number
    #   $2 - Country code
    #
    # Output: Hostapd config lines for DFS

    local channel="$1"
    local country="${2:-$(get_current_regdomain)}"

    cat << EOF
# Regulatory & DFS Configuration
country_code=$country
ieee80211d=1
EOF

    if is_dfs_channel "$channel"; then
        local cac_time
        cac_time=$(get_cac_time "$channel")

        cat << EOF
# DFS (Dynamic Frequency Selection) - Required for channel $channel
ieee80211h=1
# CAC time: ${cac_time}s
# hostapd will perform radar detection automatically
EOF
    else
        cat << EOF
# Non-DFS channel - No radar detection required
ieee80211h=0
EOF
    fi
}

# ============================================================
# MAIN ENTRY POINT
# ============================================================

show_help() {
    cat << EOF
HookProbe Fortress WiFi Regulatory & DFS Manager

Usage: $(basename "$0") <command> [options]

Commands:
  preflight <iface> [country]    Pre-flight validation before WiFi config
  set-regdomain <country>        Set regulatory domain (MUST be done first!)
  get-channels <iface>           List available 5GHz channels
  get-dfs <iface>                List DFS channels requiring CAC
  get-bandwidth <iface>          Detect maximum bandwidth capability
  test-channel <iface> <ch>      Test if a channel works
  wait-dfs <iface> <ch>          Wait for DFS CAC on a channel
  scan <iface> [include-dfs]     Scan for best channel (default: non-DFS only)
  scan-dfs <iface>               Scan including DFS channels (52-64)

Calibration Commands:
  quick-start <iface> [config]   Fast channel selection (non-DFS only, for boot)
  calibrate <iface> [config]     Quick calibration (non-DFS only)
  calibrate-full <iface> [conf]  Full calibration with DFS (52-64), for 4AM
  install-timer [iface]          Install 4AM timer + boot quick-start service

EU/ETSI 5GHz Channel Bands:
  UNII-1 (36-48):    No DFS - Always safe, immediate startup
  UNII-2A (52-64):   DFS, 60s CAC - Often clearer, use at 4AM
  UNII-2C (100-144): DFS, 600s CAC - Weather radar, long wait
  UNII-3 (149-165):  NOT allowed in DE, FR, IT, ES, NL, BE, etc.

Examples:
  # Set regulatory domain FIRST (before any config)
  $(basename "$0") set-regdomain GB

  # Pre-flight check for EU deployment
  $(basename "$0") preflight wlan0 DE

  # Quick start on boot (non-DFS, immediate)
  $(basename "$0") quick-start wlan0 /etc/hostapd/hostapd-5ghz.conf

  # Full calibration at 4AM (includes DFS 52-64, may wait 60s)
  $(basename "$0") calibrate-full wlan0 /etc/hostapd/hostapd-5ghz.conf

  # Install both 4AM timer and boot quick-start
  $(basename "$0") install-timer wlan0

Environment Variables:
  WIFI_COUNTRY_CODE    Override country code
  DEBUG=1              Enable debug output

EOF
}

main() {
    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        preflight)
            preflight_check "$@"
            ;;
        set-regdomain|set-reg)
            set_regulatory_domain "$@"
            ;;
        get-channels|channels)
            local iface="$1"
            echo "Non-DFS channels: $(get_non_dfs_channels "$iface")"
            echo "DFS channels: $(get_dfs_channels "$iface")"
            ;;
        get-dfs|dfs)
            get_dfs_channels "$@"
            ;;
        get-bandwidth|bandwidth|bw)
            detect_max_bandwidth "$@"
            ;;
        test-channel|test)
            test_channel "$@"
            ;;
        wait-dfs|wait)
            wait_for_dfs "$@"
            ;;
        scan)
            # Default scan: non-DFS only
            local iface="$1"
            local include_dfs="${2:-false}"
            scan_for_best_channel "$iface" "$include_dfs"
            ;;
        scan-dfs)
            # Scan including DFS channels (52-64), prefer UNII-2A
            local iface="$1"
            scan_for_best_channel "$iface" true "" true
            ;;
        quick-start|quickstart)
            # Quick start: non-DFS only, for boot/restart
            quick_start_channel "$@"
            ;;
        calibrate)
            # Quick calibration: non-DFS only
            local iface="$1"
            local config="${2:-/etc/hostapd/hostapd-5ghz.conf}"
            calibrate_channel "$iface" "$config" "quick"
            ;;
        calibrate-full|calibrate-dfs)
            # Full calibration: includes DFS (52-64), for 4AM
            local iface="$1"
            local config="${2:-/etc/hostapd/hostapd-5ghz.conf}"
            calibrate_channel "$iface" "$config" "full"
            ;;
        install-timer|timer)
            install_calibration_timer "$@"
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
