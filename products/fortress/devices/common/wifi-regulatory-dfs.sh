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

# Log to stderr so command substitution only captures return values
log_info() { echo -e "${CYAN}[WIFI]${NC} $*" >&2; }
log_success() { echo -e "${GREEN}[WIFI]${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}[WIFI]${NC} $*" >&2; }
log_error() { echo -e "${RED}[WIFI]${NC} $*" >&2; }
log_debug() { [ "${DEBUG:-0}" = "1" ] && echo -e "${BLUE}[DBG]${NC} $*" >&2 || true; }

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

# Channel band definitions for easy iteration
UNII1_CHANNELS="36 40 44 48"        # No DFS, always safe
UNII2A_CHANNELS="52 56 60 64"       # DFS, 60s CAC
UNII2C_CHANNELS="100 104 108 112 116 120 124 128 132 136 140 144"  # DFS, 600s CAC
UNII3_CHANNELS="149 153 157 161 165" # Non-DFS, but country-restricted

# CAC timeouts by band
UNII2A_CAC_TIME=60    # 1 minute
UNII2C_CAC_TIME=600   # 10 minutes (weather radar)

# ============================================================
# DFS COMPLIANCE & RADAR DETECTION (ETSI EN 301 893)
# ============================================================
#
# ETSI DFS Requirements:
#   - CAC (Channel Availability Check): 60s UNII-2A, 600s UNII-2C
#   - NOP (Non-Occupancy Period): 30 minutes after radar detection
#   - Channel Move Time: Must vacate within 10 seconds of radar
#   - CSA (Channel Switch Announcement): Announce switch in beacons
#   - In-Service Monitoring: Continuous radar detection while operating
#
# State Machine:
#   AVAILABLE → CAC_IN_PROGRESS → OPERATIONAL → NOP_ACTIVE → AVAILABLE
#                    ↓                 ↓
#              (timeout/fail)    (radar detected)
#                    ↓                 ↓
#               UNAVAILABLE      NOP_ACTIVE (30 min)
#

# DFS State Files
DFS_RADAR_HISTORY="/var/lib/fortress/dfs-radar-history.json"
DFS_NOP_STATE="/var/lib/fortress/dfs-nop-state.json"
DFS_CHANNEL_STATE="/var/lib/fortress/dfs-channel-state.json"
DFS_EVENT_LOG="/var/log/fortress/dfs-events.log"
DFS_FALLBACK_CHANNELS="/var/lib/fortress/dfs-fallback-channels.json"

# ETSI Timing Constants (seconds)
NOP_DURATION=1800           # 30 minutes Non-Occupancy Period
CHANNEL_MOVE_TIME=10        # Must vacate within 10 seconds
CSA_BEACON_COUNT=5          # Number of CSA beacons before switch
CAC_TIMEOUT_BUFFER=5        # Extra buffer for CAC completion
RADAR_HISTORY_RETENTION=604800  # 7 days of radar history

# DFS Channel States
DFS_STATE_AVAILABLE="available"
DFS_STATE_CAC="cac_in_progress"
DFS_STATE_OPERATIONAL="operational"
DFS_STATE_NOP="nop_active"
DFS_STATE_UNAVAILABLE="unavailable"

# ============================================================
# DFS STATE MANAGEMENT
# ============================================================

init_dfs_state() {
    # Initialize DFS state tracking files
    #
    # Creates necessary directories and initializes state files
    # with empty/default values if they don't exist

    log_info "Initializing DFS state management..."

    # Create directories
    mkdir -p /var/lib/fortress
    mkdir -p /var/log/fortress

    # Initialize radar history if not exists
    if [ ! -f "$DFS_RADAR_HISTORY" ]; then
        cat > "$DFS_RADAR_HISTORY" << 'EOF'
{
    "version": "1.0",
    "created": "",
    "radar_events": [],
    "channel_stats": {}
}
EOF
        # Set creation time
        local now
        now=$(date -Iseconds)
        sed -i "s/\"created\": \"\"/\"created\": \"$now\"/" "$DFS_RADAR_HISTORY"
    fi

    # Initialize NOP state if not exists
    if [ ! -f "$DFS_NOP_STATE" ]; then
        cat > "$DFS_NOP_STATE" << 'EOF'
{
    "nop_channels": {},
    "last_updated": ""
}
EOF
    fi

    # Initialize channel state if not exists
    if [ ! -f "$DFS_CHANNEL_STATE" ]; then
        cat > "$DFS_CHANNEL_STATE" << 'EOF'
{
    "channels": {},
    "current_channel": null,
    "fallback_channel": null,
    "last_cac": null
}
EOF
    fi

    # Initialize fallback channels
    if [ ! -f "$DFS_FALLBACK_CHANNELS" ]; then
        cat > "$DFS_FALLBACK_CHANNELS" << 'EOF'
{
    "primary_fallback": 36,
    "secondary_fallback": 44,
    "precomputed": false,
    "last_computed": null
}
EOF
    fi

    log_success "DFS state initialized"
}

get_channel_dfs_state() {
    # Get the current DFS state of a channel
    #
    # Args:
    #   $1 - Channel number
    #
    # Output: State string (available, cac_in_progress, operational, nop_active, unavailable)

    local channel="$1"

    # Check if channel is in NOP
    if is_channel_in_nop "$channel"; then
        echo "$DFS_STATE_NOP"
        return
    fi

    # Check channel state file
    if [ -f "$DFS_CHANNEL_STATE" ]; then
        local state
        state=$(jq -r ".channels[\"$channel\"].state // \"$DFS_STATE_AVAILABLE\"" "$DFS_CHANNEL_STATE" 2>/dev/null)
        echo "$state"
    else
        # Non-DFS channels are always available
        if ! is_dfs_channel "$channel"; then
            echo "$DFS_STATE_AVAILABLE"
        else
            echo "$DFS_STATE_AVAILABLE"
        fi
    fi
}

set_channel_dfs_state() {
    # Set the DFS state of a channel
    #
    # Args:
    #   $1 - Channel number
    #   $2 - State
    #   $3 - Additional info (optional)

    local channel="$1"
    local state="$2"
    local info="${3:-}"
    local now
    now=$(date -Iseconds)

    [ ! -f "$DFS_CHANNEL_STATE" ] && init_dfs_state

    # Update state
    local tmp
    tmp=$(mktemp)
    jq --arg ch "$channel" \
       --arg state "$state" \
       --arg time "$now" \
       --arg info "$info" \
       '.channels[$ch] = {
           "state": $state,
           "updated_at": $time,
           "info": $info
       }' "$DFS_CHANNEL_STATE" > "$tmp" && mv "$tmp" "$DFS_CHANNEL_STATE"

    log_debug "Channel $channel state: $state"
}

# ============================================================
# NON-OCCUPANCY PERIOD (NOP) TRACKING
# ============================================================

is_channel_in_nop() {
    # Check if a channel is currently in Non-Occupancy Period
    #
    # Args:
    #   $1 - Channel number
    #
    # Returns: 0 if in NOP, 1 if available

    local channel="$1"

    [ ! -f "$DFS_NOP_STATE" ] && return 1

    local nop_end
    nop_end=$(jq -r ".nop_channels[\"$channel\"].nop_ends // empty" "$DFS_NOP_STATE" 2>/dev/null)

    [ -z "$nop_end" ] && return 1

    # Check if NOP has expired
    local now nop_epoch now_epoch
    now=$(date +%s)
    nop_epoch=$(date -d "$nop_end" +%s 2>/dev/null || echo 0)

    if [ "$now" -lt "$nop_epoch" ]; then
        return 0  # Still in NOP
    else
        # NOP expired, clean up
        remove_channel_from_nop "$channel"
        return 1
    fi
}

add_channel_to_nop() {
    # Add a channel to Non-Occupancy Period after radar detection
    #
    # Args:
    #   $1 - Channel number
    #   $2 - Radar type (optional)

    local channel="$1"
    local radar_type="${2:-unknown}"
    local now nop_ends
    now=$(date -Iseconds)
    nop_ends=$(date -d "+$NOP_DURATION seconds" -Iseconds)

    [ ! -f "$DFS_NOP_STATE" ] && init_dfs_state

    log_warn "Adding channel $channel to NOP (30 minutes)"
    log_warn "  Radar type: $radar_type"
    log_warn "  NOP ends: $nop_ends"

    local tmp
    tmp=$(mktemp)
    jq --arg ch "$channel" \
       --arg start "$now" \
       --arg ends "$nop_ends" \
       --arg radar "$radar_type" \
       '.nop_channels[$ch] = {
           "nop_started": $start,
           "nop_ends": $ends,
           "radar_type": $radar,
           "duration_sec": '"$NOP_DURATION"'
       } | .last_updated = $start' "$DFS_NOP_STATE" > "$tmp" && mv "$tmp" "$DFS_NOP_STATE"

    # Log the event
    log_dfs_event "NOP_START" "$channel" "Radar: $radar_type, NOP ends: $nop_ends"

    # Update channel state
    set_channel_dfs_state "$channel" "$DFS_STATE_NOP" "radar_detected"
}

remove_channel_from_nop() {
    # Remove a channel from NOP (after 30 min expiry)
    #
    # Args:
    #   $1 - Channel number

    local channel="$1"

    [ ! -f "$DFS_NOP_STATE" ] && return

    local tmp
    tmp=$(mktemp)
    jq --arg ch "$channel" 'del(.nop_channels[$ch])' "$DFS_NOP_STATE" > "$tmp" && mv "$tmp" "$DFS_NOP_STATE"

    log_info "Channel $channel NOP expired, now available"
    log_dfs_event "NOP_END" "$channel" "Channel available after 30-min NOP"

    # Update channel state
    set_channel_dfs_state "$channel" "$DFS_STATE_AVAILABLE" "nop_expired"
}

get_nop_channels() {
    # Get list of all channels currently in NOP
    #
    # Output: Space-separated list of channels

    [ ! -f "$DFS_NOP_STATE" ] && return

    local channels=""
    local now
    now=$(date +%s)

    # Get all NOP channels and check if still valid
    while read -r ch nop_end; do
        [ -z "$ch" ] && continue
        local nop_epoch
        nop_epoch=$(date -d "$nop_end" +%s 2>/dev/null || echo 0)

        if [ "$now" -lt "$nop_epoch" ]; then
            channels="$channels $ch"
        fi
    done < <(jq -r '.nop_channels | to_entries[] | "\(.key) \(.value.nop_ends)"' "$DFS_NOP_STATE" 2>/dev/null)

    echo "$channels" | xargs
}

get_nop_remaining() {
    # Get remaining NOP time for a channel
    #
    # Args:
    #   $1 - Channel number
    #
    # Output: Remaining seconds, or 0 if not in NOP

    local channel="$1"

    [ ! -f "$DFS_NOP_STATE" ] && { echo "0"; return; }

    local nop_end
    nop_end=$(jq -r ".nop_channels[\"$channel\"].nop_ends // empty" "$DFS_NOP_STATE" 2>/dev/null)

    [ -z "$nop_end" ] && { echo "0"; return; }

    local now nop_epoch remaining
    now=$(date +%s)
    nop_epoch=$(date -d "$nop_end" +%s 2>/dev/null || echo 0)
    remaining=$((nop_epoch - now))

    [ "$remaining" -lt 0 ] && remaining=0
    echo "$remaining"
}

# ============================================================
# RADAR HISTORY & LEARNING ALGORITHM
# ============================================================

log_dfs_event() {
    # Log a DFS event to the event log
    #
    # Args:
    #   $1 - Event type
    #   $2 - Channel
    #   $3 - Details

    local event_type="$1"
    local channel="$2"
    local details="${3:-}"
    local timestamp
    timestamp=$(date -Iseconds)

    mkdir -p "$(dirname "$DFS_EVENT_LOG")"

    echo "[$timestamp] $event_type channel=$channel $details" >> "$DFS_EVENT_LOG"
}

record_radar_event() {
    # Record a radar detection event to history
    # This data is used by the learning algorithm
    #
    # Args:
    #   $1 - Channel number
    #   $2 - Radar type
    #   $3 - Signal strength (optional, dBm)

    local channel="$1"
    local radar_type="${2:-unknown}"
    local signal="${3:-0}"
    local now
    now=$(date -Iseconds)
    local hour
    hour=$(date +%H)
    local day_of_week
    day_of_week=$(date +%u)

    [ ! -f "$DFS_RADAR_HISTORY" ] && init_dfs_state

    log_info "Recording radar event: channel=$channel, type=$radar_type"

    # Add event to history
    local tmp
    tmp=$(mktemp)
    jq --arg ch "$channel" \
       --arg type "$radar_type" \
       --arg time "$now" \
       --arg hour "$hour" \
       --arg dow "$day_of_week" \
       --argjson sig "$signal" \
       '.radar_events += [{
           "channel": ($ch | tonumber),
           "radar_type": $type,
           "timestamp": $time,
           "hour": ($hour | tonumber),
           "day_of_week": ($dow | tonumber),
           "signal_dbm": $sig
       }]' "$DFS_RADAR_HISTORY" > "$tmp" && mv "$tmp" "$DFS_RADAR_HISTORY"

    # Update channel statistics
    update_channel_radar_stats "$channel"

    # Clean old events (keep last 7 days)
    cleanup_radar_history
}

update_channel_radar_stats() {
    # Update radar statistics for a channel
    #
    # Args:
    #   $1 - Channel number

    local channel="$1"

    [ ! -f "$DFS_RADAR_HISTORY" ] && return

    # Count total radar events for this channel
    local count
    count=$(jq --arg ch "$channel" '[.radar_events[] | select(.channel == ($ch | tonumber))] | length' "$DFS_RADAR_HISTORY" 2>/dev/null || echo 0)

    # Get last event time
    local last_event
    last_event=$(jq -r --arg ch "$channel" '[.radar_events[] | select(.channel == ($ch | tonumber))] | last | .timestamp // empty' "$DFS_RADAR_HISTORY" 2>/dev/null)

    # Calculate radar frequency (events per day)
    local first_event days_active freq
    first_event=$(jq -r '.radar_events[0].timestamp // empty' "$DFS_RADAR_HISTORY" 2>/dev/null)

    if [ -n "$first_event" ] && [ -n "$last_event" ]; then
        local first_epoch last_epoch
        first_epoch=$(date -d "$first_event" +%s 2>/dev/null || echo 0)
        last_epoch=$(date -d "$last_event" +%s 2>/dev/null || date +%s)
        days_active=$(( (last_epoch - first_epoch) / 86400 + 1 ))
        [ "$days_active" -lt 1 ] && days_active=1
        freq=$(echo "scale=2; $count / $days_active" | bc 2>/dev/null || echo "0")
    else
        freq="0"
    fi

    # Update stats
    local tmp
    tmp=$(mktemp)
    jq --arg ch "$channel" \
       --argjson count "$count" \
       --arg last "$last_event" \
       --arg freq "$freq" \
       '.channel_stats[$ch] = {
           "total_events": $count,
           "last_event": $last,
           "events_per_day": ($freq | tonumber),
           "risk_score": (if $count > 10 then "high" elif $count > 3 then "medium" else "low" end)
       }' "$DFS_RADAR_HISTORY" > "$tmp" && mv "$tmp" "$DFS_RADAR_HISTORY"
}

cleanup_radar_history() {
    # Remove radar events older than retention period
    #
    # Keeps the last 7 days of history

    [ ! -f "$DFS_RADAR_HISTORY" ] && return

    local cutoff
    cutoff=$(date -d "-$RADAR_HISTORY_RETENTION seconds" -Iseconds 2>/dev/null)

    [ -z "$cutoff" ] && return

    local tmp
    tmp=$(mktemp)
    jq --arg cutoff "$cutoff" \
       '.radar_events = [.radar_events[] | select(.timestamp >= $cutoff)]' \
       "$DFS_RADAR_HISTORY" > "$tmp" && mv "$tmp" "$DFS_RADAR_HISTORY"
}

get_channel_radar_risk() {
    # Get the radar risk score for a channel
    #
    # Args:
    #   $1 - Channel number
    #
    # Output: Risk score (low, medium, high) or "unknown"

    local channel="$1"

    # Non-DFS channels have no radar risk
    if ! is_dfs_channel "$channel"; then
        echo "none"
        return
    fi

    [ ! -f "$DFS_RADAR_HISTORY" ] && { echo "unknown"; return; }

    local risk
    risk=$(jq -r --arg ch "$channel" '.channel_stats[$ch].risk_score // "unknown"' "$DFS_RADAR_HISTORY" 2>/dev/null)
    echo "$risk"
}

get_safest_dfs_channels() {
    # Get DFS channels sorted by radar risk (safest first)
    #
    # Args:
    #   $1 - Include UNII-2C (true/false)
    #
    # Output: Space-separated channel list

    local include_unii2c="${1:-false}"

    local channels=""

    # Start with UNII-2A
    channels="$UNII2A_CHANNELS"

    # Add UNII-2C if requested
    if [ "$include_unii2c" = "true" ]; then
        channels="$channels $UNII2C_CHANNELS"
    fi

    # If no history, return as-is
    [ ! -f "$DFS_RADAR_HISTORY" ] && { echo "$channels"; return; }

    # Sort by risk (low first, then unknown, then medium, then high)
    local sorted=""
    for risk_level in "low" "unknown" "medium" "high"; do
        for ch in $channels; do
            local ch_risk
            ch_risk=$(get_channel_radar_risk "$ch")
            if [ "$ch_risk" = "$risk_level" ]; then
                # Skip if in NOP
                is_channel_in_nop "$ch" && continue
                sorted="$sorted $ch"
            fi
        done
    done

    echo "$sorted" | xargs
}

# ============================================================
# CSA (CHANNEL SWITCH ANNOUNCEMENT) HANDLING
# ============================================================

generate_csa_hostapd_config() {
    # Generate hostapd configuration for CSA and DFS
    #
    # Args:
    #   $1 - Channel number
    #   $2 - Country code
    #
    # Output: Hostapd config snippet for DFS/CSA

    local channel="$1"
    local country="${2:-$(get_current_regdomain)}"

    cat << EOF
# ============================================================
# DFS & CSA Configuration (ETSI EN 301 893 Compliant)
# ============================================================

# Regulatory settings
country_code=$country
ieee80211d=1
EOF

    if is_dfs_channel "$channel"; then
        local cac_time
        cac_time=$(get_cac_time "$channel")

        cat << EOF

# DFS (Dynamic Frequency Selection) - Required for channel $channel
ieee80211h=1

# Channel Switch Announcement (CSA)
# Announce channel switch in beacons before switching
# This ensures clients can follow to the new channel
spectrum_mgmt_required=1

# Number of beacons to send with CSA before switching
# ETSI requires advance notice (typically 3-5 beacons)
# With 100ms beacon interval, 5 beacons = 500ms warning
# hostapd default is usually 3

# CAC time for this channel: ${cac_time}s
# Channel band: $(get_band_for_channel "$channel")
EOF

    else
        cat << EOF

# Non-DFS channel - No radar detection required
ieee80211h=0
EOF
    fi
}

prepare_fallback_channel() {
    # Pre-compute and cache a fallback channel for quick switching
    # This channel should be non-DFS for immediate availability
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Current channel

    local iface="$1"
    local current_channel="${2:-}"
    local country
    country=$(get_current_regdomain)

    log_info "Preparing fallback channel for fast CSA..."

    # Get best non-DFS channel (excluding current)
    local fallback
    fallback=$(scan_for_best_channel "$iface" "quick" "$country" 2>/dev/null | tail -1)

    # If current is non-DFS, pick a different non-DFS
    if [ "$fallback" = "$current_channel" ]; then
        # Pick next best
        for ch in $UNII1_CHANNELS; do
            if [ "$ch" != "$current_channel" ]; then
                fallback="$ch"
                break
            fi
        done
    fi

    # Secondary fallback (different from primary)
    local secondary=36
    for ch in $UNII1_CHANNELS; do
        if [ "$ch" != "$fallback" ]; then
            secondary="$ch"
            break
        fi
    done

    log_info "  Primary fallback: $fallback ($(get_band_for_channel "$fallback"))"
    log_info "  Secondary fallback: $secondary"

    # Save fallback channels
    cat > "$DFS_FALLBACK_CHANNELS" << EOF
{
    "primary_fallback": $fallback,
    "secondary_fallback": $secondary,
    "current_channel": ${current_channel:-null},
    "precomputed": true,
    "last_computed": "$(date -Iseconds)",
    "country": "$country"
}
EOF

    echo "$fallback"
}

get_fallback_channel() {
    # Get the pre-computed fallback channel
    #
    # Output: Fallback channel number

    if [ -f "$DFS_FALLBACK_CHANNELS" ]; then
        jq -r '.primary_fallback // 36' "$DFS_FALLBACK_CHANNELS" 2>/dev/null
    else
        echo "36"
    fi
}

execute_fast_channel_switch() {
    # Execute a fast channel switch using CSA
    # This is called when radar is detected
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Target channel (optional, uses fallback if not specified)
    #   $3 - CSA beacon count (optional, default: 5)

    local iface="$1"
    local target_channel="${2:-}"
    local csa_count="${3:-$CSA_BEACON_COUNT}"

    log_warn "=========================================="
    log_warn "FAST CHANNEL SWITCH INITIATED"
    log_warn "=========================================="

    # Get current channel
    local current_channel
    current_channel=$(iw dev "$iface" info 2>/dev/null | grep -oP "channel \K[0-9]+" | head -1)
    log_info "Current channel: $current_channel"

    # Get target channel
    if [ -z "$target_channel" ]; then
        target_channel=$(get_fallback_channel)
    fi
    log_info "Target channel: $target_channel"

    # Verify target is not in NOP
    if is_channel_in_nop "$target_channel"; then
        log_warn "Target channel $target_channel is in NOP, using secondary fallback"
        target_channel=$(jq -r '.secondary_fallback // 36' "$DFS_FALLBACK_CHANNELS" 2>/dev/null)
    fi

    local target_freq
    target_freq=$(channel_to_freq "$target_channel")

    # Method 1: hostapd_cli (preferred - uses CSA)
    if command -v hostapd_cli &>/dev/null; then
        log_info "Executing CSA via hostapd_cli..."

        # Find hostapd control socket
        local ctrl_sock=""
        for sock in /var/run/hostapd/"$iface" /var/run/hostapd-"$iface" /run/hostapd/"$iface"; do
            [ -S "$sock" ] && { ctrl_sock="$sock"; break; }
        done

        if [ -n "$ctrl_sock" ]; then
            # Execute channel switch with CSA
            # Format: chan_switch <cs_count> <freq> [sec_channel_offset=] [center_freq1=] [center_freq2=] [bandwidth=] [blocktx] [ht|vht]
            local result
            result=$(hostapd_cli -p "$(dirname "$ctrl_sock")" chan_switch "$csa_count" "$target_freq" 2>&1)

            if echo "$result" | grep -qi "ok"; then
                log_success "CSA initiated: $current_channel → $target_channel"
                log_info "  CSA beacons: $csa_count"
                log_info "  Target frequency: $target_freq MHz"

                # Log the event
                log_dfs_event "CSA_SWITCH" "$target_channel" "from=$current_channel csa_count=$csa_count"

                # Update state
                set_channel_dfs_state "$target_channel" "$DFS_STATE_OPERATIONAL" "csa_switch"

                return 0
            else
                log_warn "hostapd_cli chan_switch failed: $result"
            fi
        else
            log_warn "hostapd control socket not found"
        fi
    fi

    # Method 2: Direct iw command (fallback - no CSA)
    log_warn "Falling back to direct channel switch (no CSA)"

    if iw dev "$iface" set freq "$target_freq" 2>/dev/null; then
        log_success "Channel switched: $current_channel → $target_channel"
        log_dfs_event "DIRECT_SWITCH" "$target_channel" "from=$current_channel"
        return 0
    else
        log_error "Channel switch failed!"
        return 1
    fi
}

# ============================================================
# RADAR EVENT MONITORING
# ============================================================

start_radar_monitor() {
    # Start monitoring for radar events
    # Monitors kernel messages and hostapd for DFS events
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Run in foreground (true/false)

    local iface="$1"
    local foreground="${2:-false}"

    log_info "Starting DFS radar monitor for $iface..."

    # Initialize state
    init_dfs_state

    # Prepare fallback channel
    prepare_fallback_channel "$iface"

    if [ "$foreground" = "true" ]; then
        _radar_monitor_loop "$iface"
    else
        # Run in background
        _radar_monitor_loop "$iface" &
        local pid=$!
        echo "$pid" > /var/run/fortress-radar-monitor.pid
        log_success "Radar monitor started (PID: $pid)"
    fi
}

_radar_monitor_loop() {
    # Internal radar monitoring loop
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"

    log_info "Radar monitor active, watching for DFS events..."

    # Monitor kernel messages for radar detection
    # dmesg format varies by driver, common patterns:
    #   ath10k: "radar detected"
    #   ath11k: "Radar detected"
    #   ath12k: "DFS radar detected"
    #   iwlwifi: "radar detected on frequency"
    #   mt76: "radar detected"

    # Use journalctl for real-time monitoring
    journalctl -k -f --no-pager 2>/dev/null | while read -r line; do
        # Check for radar detection
        if echo "$line" | grep -qiE "radar.*(detect|found)|dfs.*(radar|event)"; then
            log_warn "RADAR DETECTED!"
            log_warn "  Event: $line"

            # Extract channel if possible
            local channel freq
            freq=$(echo "$line" | grep -oE "[0-9]{4}\s*MHz" | grep -oE "[0-9]{4}" | head -1)
            if [ -n "$freq" ]; then
                channel=$(freq_to_channel "$freq")
            else
                # Try to get current channel
                channel=$(iw dev "$iface" info 2>/dev/null | grep -oP "channel \K[0-9]+" | head -1)
            fi

            if [ -n "$channel" ]; then
                # Handle radar event
                handle_radar_event "$iface" "$channel" "kernel_event"
            fi
        fi

        # Check for CAC completion
        if echo "$line" | grep -qiE "cac.*(complet|finish|done)|dfs.*available"; then
            log_success "CAC completed"
            log_dfs_event "CAC_COMPLETE" "" "$line"
        fi

        # Check for NOP expiry
        if echo "$line" | grep -qiE "nop.*(expir|end|finish)|channel.*available"; then
            log_info "NOP expired notification"
        fi
    done
}

handle_radar_event() {
    # Handle a radar detection event
    # This triggers the fast channel switch procedure
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Channel where radar was detected
    #   $3 - Radar type

    local iface="$1"
    local channel="$2"
    local radar_type="${3:-unknown}"

    log_error "=========================================="
    log_error "RADAR DETECTED ON CHANNEL $channel"
    log_error "=========================================="
    log_error "Time: $(date -Iseconds)"
    log_error "Radar type: $radar_type"
    log_error "Action: Initiating fast channel switch"

    # Record the event
    record_radar_event "$channel" "$radar_type"

    # Add channel to NOP
    add_channel_to_nop "$channel" "$radar_type"

    # Execute fast channel switch
    execute_fast_channel_switch "$iface"

    # Update fallback channel for next event
    prepare_fallback_channel "$iface"

    log_warn "=========================================="
    log_warn "Radar event handled"
    log_warn "Channel $channel in NOP for 30 minutes"
    log_warn "=========================================="
}

freq_to_channel() {
    # Convert frequency in MHz to channel number
    #
    # Args:
    #   $1 - Frequency in MHz
    #
    # Output: Channel number

    local freq="$1"

    # 5 GHz band
    if [ "$freq" -ge 5180 ] && [ "$freq" -le 5825 ]; then
        echo $(( (freq - 5000) / 5 ))
        return
    fi

    # 2.4 GHz band
    if [ "$freq" -ge 2412 ] && [ "$freq" -le 2484 ]; then
        if [ "$freq" -eq 2484 ]; then
            echo "14"
        else
            echo $(( (freq - 2407) / 5 ))
        fi
        return
    fi

    echo "0"
}

stop_radar_monitor() {
    # Stop the radar monitor daemon
    #

    if [ -f /var/run/fortress-radar-monitor.pid ]; then
        local pid
        pid=$(cat /var/run/fortress-radar-monitor.pid)
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log_info "Radar monitor stopped (PID: $pid)"
        fi
        rm -f /var/run/fortress-radar-monitor.pid
    fi
}

# ============================================================
# SMART CHANNEL SELECTION WITH HISTORY
# ============================================================

select_optimal_dfs_channel() {
    # Select the optimal DFS channel considering:
    # - Current congestion (AP scan)
    # - Radar history (avoid high-risk channels)
    # - NOP status (avoid channels in NOP)
    # - Band preference (UNII-2A preferred over UNII-2C)
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Include UNII-2C (true/false)
    #   $3 - Country code
    #
    # Output: Best channel number

    local iface="$1"
    local include_unii2c="${2:-false}"
    local country="${3:-$(get_current_regdomain)}"

    log_info "Selecting optimal DFS channel..."
    log_info "  Include UNII-2C: $include_unii2c"
    log_info "  Country: $country"

    # Get channels sorted by radar risk
    local candidates
    candidates=$(get_safest_dfs_channels "$include_unii2c")

    log_info "  Candidates (by radar risk): $candidates"

    # Filter out NOP channels
    local available_candidates=""
    local nop_channels
    nop_channels=$(get_nop_channels)

    for ch in $candidates; do
        if ! echo " $nop_channels " | grep -q " $ch "; then
            available_candidates="$available_candidates $ch"
        else
            local remaining
            remaining=$(get_nop_remaining "$ch")
            log_debug "  Channel $ch in NOP ($remaining seconds remaining)"
        fi
    done

    available_candidates=$(echo "$available_candidates" | xargs)
    log_info "  After NOP filter: $available_candidates"

    [ -z "$available_candidates" ] && {
        log_warn "No DFS channels available, falling back to UNII-1"
        echo "36"
        return
    }

    # Scan for congestion among available candidates
    ip link set "$iface" up 2>/dev/null || true
    sleep 1
    local scan_results
    scan_results=$(iw dev "$iface" scan 2>/dev/null) || true

    local best_channel=""
    local best_score=9999

    for ch in $available_candidates; do
        local freq ap_count risk_penalty score
        freq=$(channel_to_freq "$ch")
        ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null) || true
        ap_count=${ap_count:-0}

        # Get risk penalty from history
        local risk
        risk=$(get_channel_radar_risk "$ch")
        case "$risk" in
            high)   risk_penalty=10 ;;
            medium) risk_penalty=3 ;;
            low)    risk_penalty=0 ;;
            *)      risk_penalty=1 ;;
        esac

        # UNII-2C penalty (prefer UNII-2A due to shorter CAC)
        local band_penalty=0
        if [ "$ch" -ge 100 ] && [ "$ch" -le 144 ]; then
            band_penalty=2
        fi

        score=$((ap_count + risk_penalty + band_penalty))

        log_debug "  Channel $ch: APs=$ap_count, risk=$risk (+$risk_penalty), band_penalty=$band_penalty, score=$score"

        if [ "$score" -lt "$best_score" ]; then
            best_score="$score"
            best_channel="$ch"
        fi

        # If we find a perfect channel (0 APs, low risk), use it
        if [ "$score" -eq 0 ]; then
            break
        fi
    done

    log_success "Selected channel: $best_channel ($(get_band_for_channel "$best_channel"), score=$best_score)"
    echo "$best_channel"
}

show_dfs_status() {
    # Display comprehensive DFS status
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"

    log_info "=========================================="
    log_info "DFS STATUS REPORT"
    log_info "=========================================="

    # Current channel
    local current_ch
    current_ch=$(iw dev "$iface" info 2>/dev/null | grep -oP "channel \K[0-9]+" | head -1)
    if [ -n "$current_ch" ]; then
        local band dfs_state
        band=$(get_band_for_channel "$current_ch")
        dfs_state=$(get_channel_dfs_state "$current_ch")
        log_info "Current: Channel $current_ch [$band] - State: $dfs_state"
    fi

    # Fallback channels
    if [ -f "$DFS_FALLBACK_CHANNELS" ]; then
        local primary secondary
        primary=$(jq -r '.primary_fallback' "$DFS_FALLBACK_CHANNELS" 2>/dev/null)
        secondary=$(jq -r '.secondary_fallback' "$DFS_FALLBACK_CHANNELS" 2>/dev/null)
        log_info "Fallback: Primary=$primary, Secondary=$secondary"
    fi

    # NOP channels
    log_info ""
    log_info "Channels in NOP (Non-Occupancy Period):"
    local nop_list
    nop_list=$(get_nop_channels)
    if [ -n "$nop_list" ]; then
        for ch in $nop_list; do
            local remaining
            remaining=$(get_nop_remaining "$ch")
            local mins=$((remaining / 60))
            local secs=$((remaining % 60))
            log_warn "  Channel $ch: ${mins}m ${secs}s remaining"
        done
    else
        log_success "  None (all DFS channels available)"
    fi

    # Radar history summary
    log_info ""
    log_info "Radar History Summary:"
    if [ -f "$DFS_RADAR_HISTORY" ]; then
        local total_events
        total_events=$(jq '.radar_events | length' "$DFS_RADAR_HISTORY" 2>/dev/null || echo 0)
        log_info "  Total radar events (last 7 days): $total_events"

        # Show high-risk channels
        log_info "  Channel risk levels:"
        for ch in $UNII2A_CHANNELS $UNII2C_CHANNELS; do
            local risk count
            risk=$(get_channel_radar_risk "$ch")
            count=$(jq -r --arg ch "$ch" '.channel_stats[$ch].total_events // 0' "$DFS_RADAR_HISTORY" 2>/dev/null)
            if [ "$count" -gt 0 ]; then
                log_info "    Channel $ch: $risk ($count events)"
            fi
        done
    else
        log_info "  No radar history recorded"
    fi

    log_info "=========================================="
}

# ============================================================
# ML-ENHANCED CHANNEL SELECTION (Python Integration)
# ============================================================
#
# Integration with shared/wireless/dfs_intelligence.py
# Provides ML-powered channel scoring when Python module is available.
# Supports both native Python and containerized API modes.
# Falls back to bash-based scoring if unavailable.
#
# Modes:
#   container: Use DFS Intelligence container API (preferred)
#   native:    Use local Python module directly
#   fallback:  Use bash-based scoring (no ML)

# Shared module paths (canonical location)
DFS_INTELLIGENCE_PY="${DFS_INTELLIGENCE_PY:-/opt/hookprobe/shared/wireless/dfs_intelligence.py}"
DFS_INTELLIGENCE_DEV="${SCRIPT_DIR}/../../../../shared/wireless/dfs_intelligence.py"
DFS_CAPABILITIES_SCRIPT="${DFS_CAPABILITIES_SCRIPT:-/opt/hookprobe/shared/wireless/dfs_capabilities.sh}"
DFS_CAPABILITIES_DEV="${SCRIPT_DIR}/../../../../shared/wireless/dfs_capabilities.sh"
DFS_CONTAINER_CTL="${DFS_CONTAINER_CTL:-/opt/hookprobe/shared/wireless/containers/dfs-intelligence/dfs-container-ctl.sh}"
DFS_API_PORT="${DFS_API_PORT:-8767}"
DFS_API_URL="http://127.0.0.1:${DFS_API_PORT}"

# DFS operation mode (set by detect_dfs_mode)
DFS_MODE="${DFS_MODE:-auto}"
DFS_CAPABILITY_LEVEL=""

# ============================================================
# VENDOR/CAPABILITY DETECTION
# ============================================================

source_capabilities_script() {
    # Source the capabilities detection script if available
    # Priority: DFS_CAPABILITIES_SCRIPT -> shared location -> dev location -> local
    if [ -f "$DFS_CAPABILITIES_SCRIPT" ]; then
        # shellcheck source=/dev/null
        source "$DFS_CAPABILITIES_SCRIPT"
        return 0
    elif [ -f "$DFS_CAPABILITIES_DEV" ]; then
        # shellcheck source=/dev/null
        source "$DFS_CAPABILITIES_DEV"
        return 0
    elif [ -f "${SCRIPT_DIR}/wifi-dfs-capabilities.sh" ]; then
        # Fallback to local (deprecated)
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/wifi-dfs-capabilities.sh"
        return 0
    fi
    return 1
}

detect_vendor_dfs_capability() {
    # Detect vendor-specific DFS capability for an interface
    #
    # Args:
    #   $1 - Interface name
    #
    # Output: Capability level (full/partial/basic/none)
    # Sets: DFS_CAPABILITY_LEVEL global variable

    local iface="$1"

    # Try to source and use the capabilities script
    if source_capabilities_script 2>/dev/null; then
        if command -v get_chipset_dfs_capability &>/dev/null; then
            local cap_info
            cap_info=$(get_chipset_dfs_capability "$iface" 2>/dev/null)
            DFS_CAPABILITY_LEVEL="${cap_info%%:*}"
            echo "$DFS_CAPABILITY_LEVEL"
            return 0
        fi
    fi

    # Fallback: probe driver capabilities directly
    local driver phy
    driver=$(basename "$(readlink -f /sys/class/net/$iface/device/driver 2>/dev/null)" 2>/dev/null)
    phy=$(basename "$(readlink -f /sys/class/net/$iface/phy80211 2>/dev/null)" 2>/dev/null)

    # Check for DFS support via iw
    if iw phy "$phy" info 2>/dev/null | grep -q "DFS"; then
        # Has some DFS support, determine level by driver
        case "$driver" in
            iwlwifi|mt76*|mt792*|ath10k*|ath11k*|ath12k*)
                DFS_CAPABILITY_LEVEL="full"
                ;;
            rtw89*|brcmfmac*)
                DFS_CAPABILITY_LEVEL="partial"
                ;;
            rtw88*|ath9k*|brcmsmac*)
                DFS_CAPABILITY_LEVEL="basic"
                ;;
            *)
                DFS_CAPABILITY_LEVEL="partial"
                ;;
        esac
    else
        DFS_CAPABILITY_LEVEL="none"
    fi

    echo "$DFS_CAPABILITY_LEVEL"
}

get_dfs_recommendation() {
    # Get DFS mode recommendation based on hardware capability
    #
    # Args:
    #   $1 - Interface name
    #
    # Output: JSON recommendation (if jq available) or text

    local iface="$1"

    if source_capabilities_script 2>/dev/null; then
        if command -v get_dfs_recommendation &>/dev/null; then
            get_dfs_recommendation "$iface"
            return 0
        fi
    fi

    # Fallback: basic recommendation
    local cap
    cap=$(detect_vendor_dfs_capability "$iface")

    cat << EOF
{
    "interface": "$iface",
    "capability_level": "$cap",
    "recommended_mode": "$(case "$cap" in full) echo "advanced";; partial) echo "standard";; basic) echo "basic";; *) echo "disabled";; esac)",
    "features": {
        "use_ml_prediction": $([ "$cap" = "full" ] || [ "$cap" = "partial" ] && echo "true" || echo "false"),
        "use_radar_detection": $([ "$cap" = "full" ] || [ "$cap" = "partial" ] && echo "true" || echo "false"),
        "use_csa_switching": $([ "$cap" = "full" ] || [ "$cap" = "partial" ] && echo "true" || echo "false"),
        "use_nop_tracking": $([ "$cap" != "none" ] && echo "true" || echo "false")
    }
}
EOF
}

# ============================================================
# MODE DETECTION (Container vs Native vs Fallback)
# ============================================================

dfs_container_available() {
    # Check if DFS Intelligence container API is available
    curl -sf "${DFS_API_URL}/health" &>/dev/null
}

dfs_native_available() {
    # Check if native Python module is available

    # Check Python3 is available
    if ! command -v python3 &>/dev/null; then
        return 1
    fi

    # Check if DFS intelligence module exists
    local py_script=""
    if [ -f "$DFS_INTELLIGENCE_PY" ]; then
        py_script="$DFS_INTELLIGENCE_PY"
    elif [ -f "$DFS_INTELLIGENCE_DEV" ]; then
        py_script="$DFS_INTELLIGENCE_DEV"
    else
        return 1
    fi

    # Verify Python script is loadable
    python3 -c "import sys; sys.path.insert(0, '$(dirname "$py_script")'); import dfs_intelligence" 2>/dev/null
}

dfs_ml_available() {
    # Check if ML-enhanced DFS intelligence is available (any mode)
    #
    # Returns 0 if container OR native is available

    # Prefer container mode
    if dfs_container_available; then
        DFS_MODE="container"
        return 0
    fi

    # Fall back to native
    if dfs_native_available; then
        DFS_MODE="native"
        return 0
    fi

    DFS_MODE="fallback"
    return 1
}

detect_dfs_mode() {
    # Detect and set the DFS operation mode
    #
    # Sets: DFS_MODE global variable
    # Returns: mode string

    if [ "$DFS_MODE" != "auto" ]; then
        echo "$DFS_MODE"
        return 0
    fi

    if dfs_container_available; then
        DFS_MODE="container"
    elif dfs_native_available; then
        DFS_MODE="native"
    else
        DFS_MODE="fallback"
    fi

    log_debug "DFS mode detected: $DFS_MODE"
    echo "$DFS_MODE"
}

_get_dfs_py_script() {
    # Get path to DFS intelligence Python script
    if [ -f "$DFS_INTELLIGENCE_PY" ]; then
        echo "$DFS_INTELLIGENCE_PY"
    elif [ -f "$DFS_INTELLIGENCE_DEV" ]; then
        echo "$DFS_INTELLIGENCE_DEV"
    fi
}

# ============================================================
# ML FUNCTIONS (Container + Native modes)
# ============================================================

ml_score_channel() {
    # Get ML-enhanced score for a channel
    #
    # Args:
    #   $1 - Channel number
    #   $2 - Hour of day (optional)
    #
    # Output: Score and recommendation

    local channel="$1"
    local hour="${2:-$(date +%H)}"

    detect_dfs_mode >/dev/null

    case "$DFS_MODE" in
        container)
            curl -sf -X POST "${DFS_API_URL}/score" \
                -H "Content-Type: application/json" \
                -d "{\"channel\": $channel, \"hour\": $hour}" 2>/dev/null
            ;;
        native)
            local py_script
            py_script=$(_get_dfs_py_script)
            [ -z "$py_script" ] && return 1
            python3 "$py_script" score --channel "$channel" --hour "$hour" 2>/dev/null
            ;;
        *)
            log_error "ML scoring not available (mode: $DFS_MODE)"
            return 1
            ;;
    esac
}

ml_best_channel() {
    # Get ML-recommended best channel
    #
    # Args:
    #   $1 - Prefer DFS (true/false)
    #   $2 - Minimum bandwidth (MHz)
    #   $3 - Exclude channels (space-separated)
    #
    # Output: Best channel number

    local prefer_dfs="${1:-false}"
    local min_bw="${2:-20}"
    local exclude="${3:-}"

    detect_dfs_mode >/dev/null

    case "$DFS_MODE" in
        container)
            local exclude_json="[]"
            if [ -n "$exclude" ]; then
                exclude_json="[$(echo "$exclude" | tr ' ' ',')]"
            fi
            curl -sf -X POST "${DFS_API_URL}/best" \
                -H "Content-Type: application/json" \
                -d "{\"prefer_dfs\": $prefer_dfs, \"min_bandwidth\": $min_bw, \"exclude\": $exclude_json}" 2>/dev/null | \
                jq -r '.channel' 2>/dev/null || \
                curl -sf -X POST "${DFS_API_URL}/best" \
                    -H "Content-Type: application/json" \
                    -d "{\"prefer_dfs\": $prefer_dfs, \"min_bandwidth\": $min_bw}" 2>/dev/null | \
                    grep -oP '"channel":\s*\K[0-9]+'
            ;;
        native)
            local py_script
            py_script=$(_get_dfs_py_script)
            [ -z "$py_script" ] && return 1

            local args=("--min-bandwidth" "$min_bw")
            [ "$prefer_dfs" = "true" ] && args+=("--prefer-dfs")
            [ -n "$exclude" ] && args+=("--exclude" $exclude)

            python3 "$py_script" best "${args[@]}" 2>/dev/null | grep -oP "Best Channel: \K[0-9]+"
            ;;
        *)
            return 1
            ;;
    esac
}

ml_rank_channels() {
    # Get ML-based channel rankings
    #
    # Args:
    #   $1 - Include DFS (true/false)
    #   $2 - Output format (text/json)
    #
    # Output: Ranked channel list

    local include_dfs="${1:-true}"
    local format="${2:-text}"

    detect_dfs_mode >/dev/null

    case "$DFS_MODE" in
        container)
            curl -sf "${DFS_API_URL}/rank?include_dfs=$include_dfs" 2>/dev/null
            ;;
        native)
            local py_script
            py_script=$(_get_dfs_py_script)
            [ -z "$py_script" ] && return 1

            local args=()
            [ "$include_dfs" = "true" ] && args+=("--include-dfs")
            [ "$format" = "json" ] && args+=("--json")

            python3 "$py_script" rank "${args[@]}" 2>/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

ml_log_radar() {
    # Log radar event to ML database
    #
    # Args:
    #   $1 - Channel number
    #   $2 - Frequency (optional)

    local channel="$1"
    local frequency="${2:-}"

    detect_dfs_mode >/dev/null

    case "$DFS_MODE" in
        container)
            local data="{\"channel\": $channel"
            [ -n "$frequency" ] && data="$data, \"frequency\": $frequency"
            data="$data}"
            curl -sf -X POST "${DFS_API_URL}/radar" \
                -H "Content-Type: application/json" \
                -d "$data" 2>/dev/null
            ;;
        native)
            local py_script
            py_script=$(_get_dfs_py_script)
            [ -z "$py_script" ] && return 1

            local args=("--channel" "$channel")
            [ -n "$frequency" ] && args+=("--frequency" "$frequency")

            python3 "$py_script" log-radar "${args[@]}" 2>/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

ml_train_model() {
    # Train the ML model on historical data
    #
    # Args:
    #   $1 - Minimum samples required

    local min_samples="${1:-50}"

    detect_dfs_mode >/dev/null

    case "$DFS_MODE" in
        container)
            curl -sf -X POST "${DFS_API_URL}/train" \
                -H "Content-Type: application/json" \
                -d "{\"min_samples\": $min_samples}" 2>/dev/null
            ;;
        native)
            local py_script
            py_script=$(_get_dfs_py_script)
            [ -z "$py_script" ] && return 1

            python3 "$py_script" train --min-samples "$min_samples" 2>/dev/null
            ;;
        *)
            log_error "ML training not available (mode: $DFS_MODE)"
            return 1
            ;;
    esac
}

ml_start_monitor() {
    # Start ML-based radar monitoring
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"

    detect_dfs_mode >/dev/null

    case "$DFS_MODE" in
        container)
            log_info "Container mode: radar monitoring handled by container"
            log_info "Container already monitors via hostapd socket mount"
            ;;
        native)
            local py_script
            py_script=$(_get_dfs_py_script)
            [ -z "$py_script" ] && return 1

            mkdir -p /var/run/fortress
            log_info "Starting ML-enhanced radar monitor on $iface..."
            python3 "$py_script" monitor --interface "$iface" &
            local pid=$!
            echo "$pid" > /var/run/fortress/dfs-ml-monitor.pid
            log_success "ML radar monitor started (PID: $pid)"
            ;;
        *)
            log_warn "ML not available, falling back to basic monitor"
            start_radar_monitor "$iface"
            ;;
    esac
}

ml_stop_monitor() {
    # Stop ML-based radar monitoring

    local pidfile="/var/run/fortress/dfs-ml-monitor.pid"
    if [ -f "$pidfile" ]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log_info "ML radar monitor stopped (PID: $pid)"
        fi
        rm -f "$pidfile"
    fi
}

select_optimal_channel_ml() {
    # Select optimal channel using ML when available, fallback to bash
    # Also considers hardware capability level
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Include DFS (true/false)
    #   $3 - Minimum bandwidth (MHz)
    #
    # Output: Best channel number

    local iface="$1"
    local include_dfs="${2:-true}"
    local min_bw="${3:-20}"

    # Check hardware capability first
    local cap_level
    cap_level=$(detect_vendor_dfs_capability "$iface" 2>/dev/null || echo "unknown")

    case "$cap_level" in
        none)
            log_warn "Hardware does not support DFS, using UNII-1 only"
            include_dfs="false"
            ;;
        basic)
            log_warn "Basic DFS support, avoiding UNII-2C channels"
            ;;
    esac

    # Try ML-based selection first
    if dfs_ml_available; then
        log_info "Using ML-enhanced channel selection (mode: $DFS_MODE)..."
        local best_channel
        best_channel=$(ml_best_channel "$include_dfs" "$min_bw")

        if [ -n "$best_channel" ] && [ "$best_channel" -gt 0 ] 2>/dev/null; then
            log_success "ML recommendation: Channel $best_channel"
            echo "$best_channel"
            return 0
        fi
        log_warn "ML selection failed, falling back to bash scoring"
    fi

    # Fallback to bash-based selection
    if [ "$include_dfs" = "true" ]; then
        select_optimal_dfs_channel "$iface" "false"
    else
        # Non-DFS only: use UNII-1
        local nop_channels best_ch=""
        nop_channels=$(get_nop_channels)

        for ch in $UNII1_CHANNELS; do
            if ! echo " $nop_channels " | grep -q " $ch "; then
                best_ch="$ch"
                break
            fi
        done

        echo "${best_ch:-36}"
    fi
}

show_ml_status() {
    # Show ML subsystem status with container/native mode detection

    log_info "=========================================="
    log_info "DFS INTELLIGENCE STATUS"
    log_info "=========================================="

    # Detect mode
    local mode
    mode=$(detect_dfs_mode)
    echo ""
    case "$mode" in
        container)
            log_success "Mode: Container API"
            echo "  API URL: ${DFS_API_URL}"

            # Get container status
            if curl -sf "${DFS_API_URL}/status" &>/dev/null; then
                local status
                status=$(curl -sf "${DFS_API_URL}/status")
                log_success "  Container: Running"
                echo "$status" | jq -r '
                    "  sklearn: \(if .sklearn_installed then "Installed" else "Not installed" end)",
                    "  numpy: \(if .numpy_installed then "Installed" else "Not installed" end)",
                    "  Model trained: \(if .model_trained then "Yes" else "No" end)"
                ' 2>/dev/null || true
            else
                log_error "  Container: Not responding"
            fi
            ;;
        native)
            log_success "Mode: Native Python"

            # Check Python availability
            if command -v python3 &>/dev/null; then
                local py_version
                py_version=$(python3 --version 2>&1)
                log_success "  Python: $py_version"
            fi

            # Check ML module
            local py_script
            py_script=$(_get_dfs_py_script)
            if [ -n "$py_script" ]; then
                log_success "  ML Module: $py_script"
            fi

            # Check for sklearn/numpy
            if python3 -c "import sklearn" 2>/dev/null; then
                log_success "  sklearn: Installed"
            else
                log_warn "  sklearn: Not installed (basic scoring only)"
            fi

            if python3 -c "import numpy" 2>/dev/null; then
                log_success "  numpy: Installed"
            else
                log_warn "  numpy: Not installed"
            fi

            # Check model status
            if [ -f "/var/lib/fortress/dfs_model.json" ]; then
                local trained_at
                trained_at=$(jq -r '.trained_at // "unknown"' /var/lib/fortress/dfs_model.json 2>/dev/null)
                log_success "  ML Model: Trained at $trained_at"
            else
                log_info "  ML Model: Not trained (run 'ml-train' to train)"
            fi

            # Check monitor status
            local pidfile="/var/run/fortress/dfs-ml-monitor.pid"
            if [ -f "$pidfile" ]; then
                local pid
                pid=$(cat "$pidfile")
                if kill -0 "$pid" 2>/dev/null; then
                    log_success "  Radar Monitor: Running (PID: $pid)"
                else
                    log_warn "  Radar Monitor: Stale PID file"
                fi
            else
                log_info "  Radar Monitor: Not running"
            fi
            ;;
        fallback|*)
            log_warn "Mode: Fallback (bash-based scoring)"
            log_info "  Container API not available"
            log_info "  Native Python not available"
            log_info "  Using basic bash scoring algorithm"
            ;;
    esac

    log_info "=========================================="
}

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

get_phy_regdomain() {
    # Get regulatory domain for a specific phy/interface
    # Some WiFi adapters have "self-managed" regulatory domains that ignore
    # the global setting from 'iw reg set'. This function detects that.
    #
    # Args:
    #   $1 - Interface name (e.g., wlan0) or phy name (e.g., phy0)
    #
    # Returns:
    #   Country code for the phy (may differ from global)
    #   "self-managed" flag if applicable

    local iface="$1"
    local phy=""

    # Get phy name from interface
    if [[ "$iface" == phy* ]]; then
        phy="$iface"
    else
        phy=$(get_phy_name "$iface" 2>/dev/null)
    fi

    if [ -z "$phy" ] || ! command -v iw &>/dev/null; then
        # Fall back to global
        get_current_regdomain
        return
    fi

    # Parse iw reg get output for this specific phy
    # Format: "phy#N (self-managed)" followed by "country XX: DFS-XXX"
    local reg_output
    reg_output=$(iw reg get 2>/dev/null)

    # Check if this phy is self-managed
    local phy_section=""
    local in_phy=false
    local phy_num="${phy#phy}"

    while IFS= read -r line; do
        if [[ "$line" == "phy#$phy_num"* ]]; then
            in_phy=true
            phy_section="$line"
        elif [[ "$line" == "phy#"* ]] || [[ "$line" == "global" ]]; then
            in_phy=false
        elif $in_phy && [[ "$line" == *"country"* ]]; then
            # Extract country from "country XX: DFS-XXX"
            local country
            country=$(echo "$line" | grep -oP "country \K[A-Z]{2}")
            if [ -n "$country" ]; then
                # Check if self-managed
                if [[ "$phy_section" == *"self-managed"* ]]; then
                    echo "$country:self-managed"
                else
                    echo "$country"
                fi
                return
            fi
        fi
    done <<< "$reg_output"

    # Fall back to global
    get_current_regdomain
}

is_self_managed_regdomain() {
    # Check if a phy has a self-managed regulatory domain
    # Self-managed domains are firmware-controlled and ignore iw reg set
    #
    # Args:
    #   $1 - Interface or phy name
    #
    # Returns:
    #   0 (true) if self-managed
    #   1 (false) if not

    local result
    result=$(get_phy_regdomain "$1")
    [[ "$result" == *":self-managed"* ]]
}

get_effective_regdomain() {
    # Get the EFFECTIVE regulatory domain for channel selection
    # When a phy has self-managed domain, we must use the most restrictive
    # constraints from BOTH the global and self-managed domains.
    #
    # Args:
    #   $1 - Interface name
    #
    # Returns:
    #   JSON object with regulatory info:
    #   {
    #     "global": "RO",
    #     "phy": "US",
    #     "self_managed": true,
    #     "effective": "US",  # Use more restrictive for channels
    #     "dfs_type": "FCC"   # DFS-FCC, DFS-ETSI, etc.
    #   }

    local iface="$1"

    local global_domain
    global_domain=$(get_current_regdomain)

    local phy_result
    phy_result=$(get_phy_regdomain "$iface")

    local phy_domain="${phy_result%%:*}"
    local self_managed=false
    [[ "$phy_result" == *":self-managed"* ]] && self_managed=true

    # Determine DFS type
    local dfs_type="ETSI"
    if [[ "$phy_domain" == "US" ]] || [[ "$phy_domain" == "CA" ]] || [[ "$phy_domain" == "TW" ]]; then
        dfs_type="FCC"
    elif [[ "$phy_domain" == "JP" ]]; then
        dfs_type="JP"
    fi

    # For self-managed domains, we use the PHY's domain as effective
    # because that's what the firmware will enforce
    local effective="$phy_domain"
    if ! $self_managed; then
        effective="$global_domain"
    fi

    cat << EOF
{
  "global": "$global_domain",
  "phy": "$phy_domain",
  "self_managed": $self_managed,
  "effective": "$effective",
  "dfs_type": "$dfs_type"
}
EOF
}

get_safe_channels_for_regdomain() {
    # Get channels that are SAFE given potential regulatory domain mismatches
    # When self-managed domain differs from global, return only universally safe channels
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Mode: "quick" (non-DFS only), "standard", "full"
    #
    # Returns:
    #   Space-separated list of safe channel numbers

    local iface="$1"
    local mode="${2:-quick}"

    local global_domain phy_domain self_managed
    global_domain=$(get_current_regdomain)

    local phy_result
    phy_result=$(get_phy_regdomain "$iface")
    phy_domain="${phy_result%%:*}"
    [[ "$phy_result" == *":self-managed"* ]] && self_managed=true || self_managed=false

    # If domains match or not self-managed, use normal channel selection
    if ! $self_managed || [ "$global_domain" = "$phy_domain" ]; then
        build_calibration_channel_list "$iface" "$mode" "$global_domain"
        return
    fi

    # DOMAINS MISMATCH AND SELF-MANAGED
    # Use most conservative approach - only universally safe channels
    log_warn "Regulatory domain mismatch detected!"
    log_warn "  Global: $global_domain, PHY: $phy_domain (self-managed)"
    log_warn "  Using conservative channel selection"

    local safe_channels=""

    # UNII-1 (36-48): Safe in ALL regulatory domains
    # These channels never require DFS and are always allowed
    safe_channels="36 40 44 48"

    case "$mode" in
        quick)
            # Quick mode: ONLY use UNII-1 for guaranteed safety
            # UNII-3 varies too much between regions to be safe
            echo "$safe_channels"
            ;;
        standard|full|extended)
            # Standard/Full mode: Add UNII-3 only if allowed in BOTH domains
            local global_unii3=false
            local phy_unii3=false

            is_unii3_allowed "$global_domain" && global_unii3=true
            is_unii3_allowed "$phy_domain" && phy_unii3=true

            if $global_unii3 && $phy_unii3; then
                # US allows UNII-3 (149-165), check if global domain also allows
                safe_channels="$safe_channels 149 153 157 161 165"
            else
                log_info "  UNII-3 (149-165) not safe - disabled"
            fi

            # DFS channels are risky with domain mismatch
            # Different domains have different CAC times and channel restrictions
            if [ "$mode" = "full" ] || [ "$mode" = "extended" ]; then
                log_warn "  DFS channels disabled due to regulatory mismatch"
                log_warn "  To use DFS, ensure adapter firmware matches your country"
            fi

            echo "$safe_channels"
            ;;
        *)
            echo "$safe_channels"
            ;;
    esac
}

log_regulatory_status() {
    # Log detailed regulatory status for debugging
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"

    log_info "=========================================="
    log_info "REGULATORY DOMAIN STATUS"
    log_info "=========================================="

    local global_domain
    global_domain=$(get_current_regdomain)
    log_info "Global domain: ${global_domain:-UNKNOWN}"

    local phy_result
    phy_result=$(get_phy_regdomain "$iface")
    local phy_domain="${phy_result%%:*}"
    local self_managed=""
    [[ "$phy_result" == *":self-managed"* ]] && self_managed=" (SELF-MANAGED)"

    log_info "PHY domain for $iface: ${phy_domain:-UNKNOWN}$self_managed"

    if [ -n "$self_managed" ]; then
        log_warn "⚠️  This adapter has SELF-MANAGED regulatory domain"
        log_warn "   The firmware ignores 'iw reg set' commands"
        log_warn "   Channel availability is controlled by adapter firmware"

        if [ "$global_domain" != "$phy_domain" ]; then
            log_warn "⚠️  DOMAIN MISMATCH: Global=$global_domain, PHY=$phy_domain"
            log_warn "   Using conservative channel selection (UNII-1 only)"
            log_warn "   For full channel access, check adapter firmware country setting"
        fi
    fi

    log_info "=========================================="
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

    # Method 3: Kernel module parameter (requires root and write access)
    if [ -f /sys/module/cfg80211/parameters/ieee80211_regdom ] && [ -w /sys/module/cfg80211/parameters/ieee80211_regdom ]; then
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

get_band_for_channel() {
    # Get the UNII band name for a channel
    #
    # Args:
    #   $1 - Channel number
    #
    # Output: Band name (UNII-1, UNII-2A, UNII-2C, UNII-3)

    local ch="$1"

    if [ "$ch" -ge 36 ] && [ "$ch" -le 48 ] 2>/dev/null; then
        echo "UNII-1"
    elif [ "$ch" -ge 52 ] && [ "$ch" -le 64 ] 2>/dev/null; then
        echo "UNII-2A"
    elif [ "$ch" -ge 100 ] && [ "$ch" -le 144 ] 2>/dev/null; then
        echo "UNII-2C"
    elif [ "$ch" -ge 149 ] && [ "$ch" -le 165 ] 2>/dev/null; then
        echo "UNII-3"
    else
        echo "unknown"
    fi
}

get_channels_by_band() {
    # Get available channels for specific bands with country validation
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Bands to include (comma-separated: "UNII-1,UNII-2A,UNII-2C,UNII-3")
    #   $3 - Country code (for UNII-3 validation)
    #
    # Output: Space-separated channel list

    local iface="$1"
    local bands="${2:-UNII-1}"
    local country="${3:-$(get_current_regdomain)}"

    local channels=""

    # UNII-1 (36-48) - Always available
    if echo "$bands" | grep -q "UNII-1"; then
        channels="$channels $UNII1_CHANNELS"
    fi

    # UNII-2A (52-64) - DFS, 60s CAC
    if echo "$bands" | grep -q "UNII-2A"; then
        channels="$channels $UNII2A_CHANNELS"
    fi

    # UNII-2C (100-144) - DFS, 600s CAC (weather radar)
    if echo "$bands" | grep -q "UNII-2C"; then
        channels="$channels $UNII2C_CHANNELS"
    fi

    # UNII-3 (149-165) - Country restricted
    if echo "$bands" | grep -q "UNII-3"; then
        if is_unii3_allowed "$country"; then
            channels="$channels $UNII3_CHANNELS"
        else
            log_debug "UNII-3 not allowed in $country, skipping 149-165"
        fi
    fi

    echo "$channels" | xargs
}

build_calibration_channel_list() {
    # Build prioritized channel list based on calibration mode
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Mode: "quick", "standard", "full", "extended"
    #   $3 - Country code
    #
    # Modes:
    #   quick:    UNII-1 only (36-48) - No DFS, immediate startup
    #   standard: UNII-1 + UNII-2A (36-64) - Include 60s DFS
    #   full:     UNII-2A > UNII-1 (prioritize 52-64) - For 4AM
    #   extended: All bands (52-64 > 100-144 > 36-48 > 149-165)
    #
    # Output: Space-separated channel list in priority order

    local iface="$1"
    local mode="${2:-quick}"
    local country="${3:-$(get_current_regdomain)}"

    local channels=""

    case "$mode" in
        quick)
            # Non-DFS only, fastest startup
            channels="$UNII1_CHANNELS"
            if is_unii3_allowed "$country"; then
                channels="$channels $UNII3_CHANNELS"
            fi
            ;;
        standard)
            # Include UNII-2A (60s CAC acceptable)
            # Priority: UNII-1 first (no wait), then UNII-2A
            channels="$UNII1_CHANNELS $UNII2A_CHANNELS"
            if is_unii3_allowed "$country"; then
                channels="$channels $UNII3_CHANNELS"
            fi
            ;;
        full)
            # 4AM mode: Prefer UNII-2A (often clearer), then UNII-1
            # 60s CAC is acceptable at 4AM
            channels="$UNII2A_CHANNELS $UNII1_CHANNELS"
            if is_unii3_allowed "$country"; then
                channels="$channels $UNII3_CHANNELS"
            fi
            ;;
        extended)
            # Include ALL bands, including UNII-2C (10 min CAC)
            # Priority: UNII-2A (60s) > UNII-2C (600s) > UNII-1 > UNII-3
            # UNII-2C often has least congestion due to long CAC deterring others
            channels="$UNII2A_CHANNELS $UNII2C_CHANNELS $UNII1_CHANNELS"
            if is_unii3_allowed "$country"; then
                channels="$channels $UNII3_CHANNELS"
            fi
            ;;
        *)
            log_warn "Unknown mode: $mode, defaulting to quick"
            channels="$UNII1_CHANNELS"
            ;;
    esac

    echo "$channels" | xargs
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
    #   $2 - Mode: "quick", "standard", "full", "extended" OR legacy true/false
    #   $3 - Country code
    #   $4 - Prefer DFS (true/false, default based on mode)
    #
    # Modes:
    #   quick:    UNII-1 only (36-48) - No DFS
    #   standard: UNII-1 + UNII-2A (36-64) - With 60s DFS
    #   full:     UNII-2A > UNII-1 (prioritize 52-64)
    #   extended: All bands including UNII-2C (100-144)
    #
    # Output: Best channel number

    local iface="$1"
    local mode="${2:-quick}"
    local country="${3:-$(get_current_regdomain)}"
    local prefer_dfs="${4:-}"

    # Legacy compatibility: convert true/false to mode
    if [ "$mode" = "true" ]; then
        mode="full"
    elif [ "$mode" = "false" ]; then
        mode="quick"
    fi

    log_info "Scanning for best 5GHz channel..."
    log_info "  Mode: $mode"
    log_info "  Country: $country"

    # Build channel list based on mode
    local channels
    channels=$(build_calibration_channel_list "$iface" "$mode" "$country")

    # Log bands being scanned
    case "$mode" in
        quick)
            log_info "  Bands: UNII-1 (36-48)"
            [ -n "$(echo "$channels" | grep -E '149|153|157|161|165')" ] && log_info "       + UNII-3 (149-165)"
            ;;
        standard)
            log_info "  Bands: UNII-1 (36-48) + UNII-2A (52-64)"
            ;;
        full)
            log_info "  Bands: UNII-2A (52-64) > UNII-1 (36-48)"
            log_info "  Priority: DFS channels first (often clearer)"
            ;;
        extended)
            log_info "  Bands: UNII-2A (52-64) > UNII-2C (100-144) > UNII-1 (36-48)"
            log_info "  Warning: UNII-2C requires 10-minute CAC (weather radar)"
            ;;
    esac

    [ -z "$channels" ] && { echo "36"; return; }

    # Bring interface up for scanning
    ip link set "$iface" up 2>/dev/null || true
    sleep 1

    # Scan for APs
    local scan_results
    scan_results=$(iw dev "$iface" scan 2>/dev/null) || true

    # Count APs per channel with band-aware scoring
    local best_channel=36
    local min_score=9999
    local channel_results=""

    for ch in $channels; do
        local freq band ap_count score cac_time
        freq=$(channel_to_freq "$ch")
        band=$(get_band_for_channel "$ch")
        ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null) || true
        ap_count=${ap_count:-0}
        cac_time=$(get_cac_time "$ch")

        # Calculate score: AP count + CAC penalty (unless in DFS-preferred mode)
        score="$ap_count"

        # In quick/standard mode, add CAC time penalty to discourage DFS
        if [ "$mode" = "quick" ] || [ "$mode" = "standard" ]; then
            if [ "$cac_time" -gt 0 ]; then
                # Small penalty for 60s CAC, larger for 600s
                score=$((ap_count + cac_time / 30))
            fi
        fi

        # In extended mode, add smaller penalty to UNII-2C (encourage UNII-2A first)
        if [ "$mode" = "extended" ] && [ "$cac_time" -eq 600 ]; then
            # Only add penalty if UNII-2A has similar congestion
            score=$((ap_count + 2))
        fi

        log_debug "Channel $ch ($band, $freq MHz): $ap_count APs, CAC=${cac_time}s, score=$score"
        channel_results="${channel_results}$ch:$ap_count:$band:$score "

        if [ "$score" -lt "$min_score" ]; then
            min_score="$score"
            best_channel="$ch"
        fi
    done

    # In full/extended mode, prefer clear DFS channels
    if [ "$mode" = "full" ] || [ "$mode" = "extended" ]; then
        # Check UNII-2A first (52-64)
        for ch in $UNII2A_CHANNELS; do
            local freq ap_count
            freq=$(channel_to_freq "$ch")
            ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null) || true
            ap_count=${ap_count:-0}

            if [ "$ap_count" -eq 0 ]; then
                best_channel="$ch"
                log_info "  Found clear UNII-2A channel: $ch (60s CAC)"
                break
            fi
        done

        # In extended mode, also check UNII-2C if UNII-2A is congested
        if [ "$mode" = "extended" ] && is_dfs_channel "$best_channel" && [ "$(get_cac_time "$best_channel")" -ne 600 ]; then
            # Check if UNII-2C has clearer channels
            for ch in $UNII2C_CHANNELS; do
                local freq ap_count
                freq=$(channel_to_freq "$ch")
                ap_count=$(echo "$scan_results" | grep -c "freq: $freq" 2>/dev/null) || true
                ap_count=${ap_count:-0}

                # Only use UNII-2C if it's significantly clearer (0 APs)
                if [ "$ap_count" -eq 0 ]; then
                    local current_best_aps
                    current_best_aps=$(echo "$scan_results" | grep -c "freq: $(channel_to_freq "$best_channel")" 2>/dev/null) || true
                    current_best_aps=${current_best_aps:-0}

                    if [ "$current_best_aps" -gt 2 ]; then
                        best_channel="$ch"
                        log_info "  Found clear UNII-2C channel: $ch (600s CAC)"
                        log_warn "  Note: 10-minute CAC required for weather radar"
                        break
                    fi
                fi
            done
        fi
    fi

    # Get final channel info
    local best_band best_cac dfs_marker=""
    best_band=$(get_band_for_channel "$best_channel")
    best_cac=$(get_cac_time "$best_channel")

    if [ "$best_cac" -gt 0 ]; then
        dfs_marker=" (DFS, ${best_cac}s CAC)"
    fi

    log_success "Best channel: $best_channel [$best_band]$dfs_marker"

    # Log scan summary
    log_info "Scan results summary:"
    for result in $channel_results; do
        local ch aps band score
        ch=$(echo "$result" | cut -d: -f1)
        aps=$(echo "$result" | cut -d: -f2)
        band=$(echo "$result" | cut -d: -f3)
        score=$(echo "$result" | cut -d: -f4)
        [ "$ch" = "$best_channel" ] && log_info "  → $ch ($band): $aps APs [SELECTED]" || log_debug "    $ch ($band): $aps APs"
    done

    echo "$best_channel"
}

# ============================================================
# CHANNEL CALIBRATION (4AM OPTIMIZATION)
# ============================================================

calibrate_channel() {
    # Perform channel calibration with multiple modes
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Config file to update
    #   $3 - Mode: "quick", "standard", "full", "extended"
    #   $4 - Dry run (true/false, default: false)
    #
    # Modes:
    #   quick:    UNII-1 only (36-48) - No DFS, immediate startup
    #   standard: UNII-1 + UNII-2A - Include 60s DFS if beneficial
    #   full:     UNII-2A > UNII-1 - Prefer 52-64, wait for CAC (4AM default)
    #   extended: All bands including UNII-2C (100-144) - Full 10min CAC

    local iface="$1"
    local config_file="${2:-/etc/hostapd/hostapd-5ghz.conf}"
    local mode="${3:-full}"
    local dry_run="${4:-false}"

    log_info "=========================================="
    log_info "WiFi Channel Calibration"
    log_info "=========================================="
    log_info "Time: $(date -Iseconds)"
    log_info "Interface: $iface"
    log_info "Mode: $mode"

    # Get current country
    local country
    country=$(get_current_regdomain)
    log_info "Regulatory domain: $country"

    # Ensure regulatory domain is set before any operations
    set_regulatory_domain "$country" "$iface" 2>/dev/null || true

    # Get current channel from config
    local current_channel current_band
    if [ -f "$config_file" ]; then
        current_channel=$(grep "^channel=" "$config_file" | cut -d= -f2)
        current_band=$(get_band_for_channel "$current_channel")
    fi
    log_info "Current channel: ${current_channel:-unknown} [${current_band:-unknown}]"

    # Mode descriptions
    case "$mode" in
        quick)
            log_info "=========================================="
            log_info "Quick Mode: Non-DFS only (immediate startup)"
            log_info "  Bands: UNII-1 (36-48)"
            is_unii3_allowed "$country" && log_info "       + UNII-3 (149-165)"
            log_info "  CAC: None required"
            log_info "=========================================="
            ;;
        standard)
            log_info "=========================================="
            log_info "Standard Mode: Include UNII-2A for validation"
            log_info "  Bands: UNII-1 (36-48) + UNII-2A (52-64)"
            log_info "  CAC: Up to 60s if DFS channel selected"
            log_info "=========================================="
            ;;
        full)
            log_info "=========================================="
            log_info "Full Mode: Prioritize DFS (4AM calibration)"
            log_info "  Bands: UNII-2A (52-64) > UNII-1 (36-48)"
            log_info "  CAC: 60s expected (UNII-2A channels)"
            log_info "  Note: DFS channels often clearer due to CAC deterrent"
            log_info "=========================================="
            ;;
        extended)
            log_info "=========================================="
            log_info "Extended Mode: All bands including UNII-2C"
            log_info "  Bands: UNII-2A (52-64) > UNII-2C (100-144) > UNII-1 (36-48)"
            log_info "  CAC: Up to 600s (10 min) for UNII-2C weather radar"
            log_warn "  Warning: UNII-2C may cause long AP unavailability"
            log_info "=========================================="
            ;;
    esac

    # Scan for best channel using the mode
    local best_channel
    best_channel=$(scan_for_best_channel "$iface" "$mode" "$country")
    log_info "Recommended channel: $best_channel"

    # Get channel details
    local best_band is_dfs cac_time
    best_band=$(get_band_for_channel "$best_channel")
    cac_time=$(get_cac_time "$best_channel")
    is_dfs=false
    [ "$cac_time" -gt 0 ] && is_dfs=true

    if [ "$is_dfs" = "true" ]; then
        log_warn "Selected channel $best_channel [$best_band] is DFS"
        log_warn "CAC (radar detection) required: ${cac_time}s"
    fi

    # Compare with current
    if [ "$best_channel" = "$current_channel" ]; then
        log_success "Already on optimal channel $best_channel [$best_band]"
        return 0
    fi

    # Validate new channel
    if ! test_channel "$iface" "$best_channel" 5; then
        log_warn "Channel $best_channel test failed"

        # Fallback logic based on mode
        if [ "$is_dfs" = "true" ]; then
            log_info "Falling back to non-DFS channel scan..."
            best_channel=$(scan_for_best_channel "$iface" "quick" "$country")
            best_band=$(get_band_for_channel "$best_channel")
            cac_time=$(get_cac_time "$best_channel")
            is_dfs=false
            log_info "Fallback channel: $best_channel [$best_band]"
        else
            log_error "Channel validation failed, keeping current"
            return 1
        fi
    fi

    if [ "$dry_run" = "true" ]; then
        log_info "=========================================="
        log_info "DRY RUN: Would switch from channel $current_channel to $best_channel"
        [ "$is_dfs" = "true" ] && log_info "DRY RUN: Would wait ${cac_time}s for DFS CAC"
        log_info "=========================================="
        return 0
    fi

    # For DFS channels, inform about CAC wait
    if [ "$is_dfs" = "true" ] && [ "$cac_time" -gt 0 ]; then
        log_warn "=========================================="
        log_warn "DFS Channel Selected: $best_channel [$best_band]"
        log_warn "=========================================="
        log_warn "hostapd will perform ${cac_time}s CAC (radar detection)"
        log_warn "AP will not be available during this time"

        if [ "$cac_time" -ge 600 ]; then
            log_warn "This is a UNII-2C (weather radar) channel"
            log_warn "10-minute CAC is ETSI requirement"
        else
            log_warn "This is a UNII-2A channel (1-minute CAC)"
        fi
        log_warn "=========================================="
    fi

    # Update configuration
    if [ -f "$config_file" ]; then
        log_info "Updating $config_file: channel=$best_channel"
        sed -i "s/^channel=.*/channel=$best_channel/" "$config_file"

        # Update VHT center frequency based on bandwidth and channel
        local bandwidth center_freq
        bandwidth=$(grep "vht_oper_chwidth" "$config_file" 2>/dev/null | cut -d= -f2)
        case "$bandwidth" in
            2) center_freq=$(get_vht_center_freq "$best_channel" 160) ;;
            1) center_freq=$(get_vht_center_freq "$best_channel" 80) ;;
            *) center_freq=$(get_vht_center_freq "$best_channel" 80) ;;
        esac

        if grep -q "vht_oper_centr_freq_seg0_idx" "$config_file"; then
            sed -i "s/^vht_oper_centr_freq_seg0_idx=.*/vht_oper_centr_freq_seg0_idx=$center_freq/" "$config_file"
        fi

        # Enable DFS if needed
        if [ "$is_dfs" = "true" ]; then
            if grep -q "^ieee80211h=" "$config_file"; then
                sed -i "s/^ieee80211h=.*/ieee80211h=1/" "$config_file"
            fi
        fi

        # Restart hostapd
        if systemctl is-active --quiet hostapd-5ghz 2>/dev/null; then
            log_info "Restarting hostapd-5ghz..."
            systemctl restart hostapd-5ghz
        elif systemctl is-active --quiet hostapd 2>/dev/null; then
            log_info "Restarting hostapd..."
            systemctl restart hostapd
        fi

        log_success "Channel calibration complete: $current_channel → $best_channel [$best_band]"
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
    "previous_band": "${current_band:-unknown}",
    "new_channel": $best_channel,
    "new_band": "$best_band",
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
    # Uses non-DFS channels for immediate availability by default
    # Can optionally include UNII-2A (60s CAC) in "standard" mode
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Config file to update (optional)
    #   $3 - Mode: "quick" (default, no DFS) or "standard" (includes UNII-2A)
    #
    # Returns: Selected channel number

    local iface="$1"
    local config_file="${2:-}"
    local mode="${3:-quick}"

    log_info "=========================================="
    log_info "Quick Start Channel Selection"
    log_info "=========================================="

    local country
    country=$(get_current_regdomain)

    # Set regulatory domain first
    set_regulatory_domain "$country" "$iface" 2>/dev/null || true

    case "$mode" in
        standard)
            log_info "Mode: Standard (UNII-1 + UNII-2A with 60s CAC)"
            log_info "  Includes DFS validation for channels 52-64"
            ;;
        *)
            log_info "Mode: Quick (non-DFS only, immediate startup)"
            mode="quick"
            ;;
    esac

    # Scan based on mode
    local best_channel best_band cac_time
    best_channel=$(scan_for_best_channel "$iface" "$mode" "$country")
    best_band=$(get_band_for_channel "$best_channel")
    cac_time=$(get_cac_time "$best_channel")

    if [ "$cac_time" -gt 0 ]; then
        log_success "Quick start channel: $best_channel [$best_band] (DFS, ${cac_time}s CAC)"
    else
        log_success "Quick start channel: $best_channel [$best_band] (non-DFS)"
    fi

    # Update config if specified
    if [ -n "$config_file" ] && [ -f "$config_file" ]; then
        log_info "Updating $config_file: channel=$best_channel"
        sed -i "s/^channel=.*/channel=$best_channel/" "$config_file"

        local center_freq
        center_freq=$(get_vht_center_freq "$best_channel" 80)
        if grep -q "vht_oper_centr_freq_seg0_idx" "$config_file"; then
            sed -i "s/^vht_oper_centr_freq_seg0_idx=.*/vht_oper_centr_freq_seg0_idx=$center_freq/" "$config_file"
        fi

        # Enable DFS if needed
        if [ "$cac_time" -gt 0 ] && grep -q "^ieee80211h=" "$config_file"; then
            sed -i "s/^ieee80211h=.*/ieee80211h=1/" "$config_file"
        fi
    fi

    echo "$best_channel"
}

install_calibration_timer() {
    # Install systemd timer for 4AM daily channel calibration
    #
    # Args:
    #   $1 - Interface name (default: auto-detect)
    #   $2 - 4AM mode: "full" or "extended" (default: full)

    local iface="${1:-}"
    local calibrate_mode="${2:-full}"

    log_info "Installing channel calibration timer..."

    # Auto-detect interface if not specified
    if [ -z "$iface" ]; then
        iface=$(ls /sys/class/net | grep -E "^wl" | head -1)
        [ -z "$iface" ] && { log_error "No WiFi interface found"; return 1; }
    fi

    # Set timeout based on mode (extended needs longer for UNII-2C)
    local timeout=600
    [ "$calibrate_mode" = "extended" ] && timeout=900

    # Create calibration service - uses FULL or EXTENDED mode at 4AM
    cat > /etc/systemd/system/fortress-channel-calibrate.service << EOF
[Unit]
Description=HookProbe Fortress WiFi Channel Calibration (4AM $calibrate_mode mode)
After=network.target hostapd.service

[Service]
Type=oneshot
# Mode: $calibrate_mode
# full: UNII-2A (52-64) + UNII-1 (36-48), 60s CAC
# extended: + UNII-2C (100-144), up to 600s CAC for weather radar
ExecStart=/opt/hookprobe/fortress/devices/common/wifi-regulatory-dfs.sh calibrate-$calibrate_mode $iface
StandardOutput=journal
StandardError=journal
# Timeout: ${timeout}s (allows for DFS CAC)
TimeoutStartSec=$timeout

[Install]
WantedBy=multi-user.target
EOF

    # Create timer for 4AM daily
    cat > /etc/systemd/system/fortress-channel-calibrate.timer << EOF
[Unit]
Description=Daily WiFi Channel Calibration at 4AM ($calibrate_mode mode with DFS)

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
ExecStart=/opt/hookprobe/fortress/devices/common/wifi-regulatory-dfs.sh quick-start $iface /etc/hostapd/hostapd-5ghz.conf quick
StandardOutput=journal
StandardError=journal
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Create standard-start service for boot with UNII-2A validation
    cat > /etc/systemd/system/fortress-channel-standard.service << EOF
[Unit]
Description=HookProbe Fortress WiFi Standard Start (with UNII-2A validation)
After=network.target
Before=hostapd.service hostapd-5ghz.service

[Service]
Type=oneshot
# Standard mode: UNII-1 (36-48) + UNII-2A (52-64) with 60s CAC
# Validates DFS channels but prefers non-DFS for faster startup
ExecStart=/opt/hookprobe/fortress/devices/common/wifi-regulatory-dfs.sh quick-start $iface /etc/hostapd/hostapd-5ghz.conf standard
StandardOutput=journal
StandardError=journal
# Allow up to 90s (60s CAC + 30s for scanning)
TimeoutStartSec=90

[Install]
WantedBy=multi-user.target
EOF

    # Enable timer
    systemctl daemon-reload
    systemctl enable fortress-channel-calibrate.timer
    systemctl start fortress-channel-calibrate.timer

    log_success "Channel calibration services installed"
    log_info ""
    log_info "Services installed:"
    log_info "  fortress-channel-calibrate.service - 4AM $calibrate_mode mode"
    log_info "  fortress-channel-calibrate.timer   - Daily 4AM trigger"
    log_info "  fortress-channel-quickstart.service - Boot (non-DFS only)"
    log_info "  fortress-channel-standard.service  - Boot with UNII-2A validation"
    log_info ""
    log_info "Calibration Modes:"
    log_info "  quick:    UNII-1 only (36-48) - No CAC"
    log_info "  standard: UNII-1 + UNII-2A (36-64) - Up to 60s CAC"
    log_info "  full:     UNII-2A > UNII-1 (52-64 preferred) - 60s CAC"
    log_info "  extended: + UNII-2C (100-144) - Up to 600s CAC"
    log_info ""
    log_info "To enable on boot (choose one):"
    log_info "  systemctl enable fortress-channel-quickstart.service  # Fastest"
    log_info "  systemctl enable fortress-channel-standard.service    # With DFS validation"
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
# BACKTESTING & VALIDATION
# ============================================================

run_backtest() {
    # Comprehensive backtest of all calibration modes and scenarios
    # Validates channel selection logic without making changes
    #
    # Args:
    #   $1 - Interface name
    #   $2 - Country code to test (default: current)
    #
    # Tests all modes and validates:
    #   - Channel availability per band
    #   - DFS/non-DFS selection logic
    #   - Country-specific restrictions (UNII-3)
    #   - CAC time calculations
    #   - Fallback behavior

    local iface="$1"
    local country="${2:-$(get_current_regdomain)}"

    log_info "=========================================="
    log_info "COMPREHENSIVE CHANNEL CALIBRATION BACKTEST"
    log_info "=========================================="
    log_info "Interface: $iface"
    log_info "Country: $country"
    log_info "Time: $(date -Iseconds)"
    log_info "=========================================="

    local errors=0
    local warnings=0
    local test_results=""

    # Test 1: Verify regulatory domain
    log_info ""
    log_info "[TEST 1] Regulatory Domain Validation"
    log_info "----------------------------------------"

    local current_reg
    current_reg=$(get_current_regdomain)
    if [ "$current_reg" = "$country" ]; then
        log_success "  ✓ Regulatory domain matches: $country"
    else
        log_warn "  ! Regulatory domain mismatch: current=$current_reg, expected=$country"
        ((warnings++))
    fi

    # Test 2: Verify channel availability by band
    log_info ""
    log_info "[TEST 2] Channel Availability by Band"
    log_info "----------------------------------------"

    log_info "  UNII-1 (36-48): No DFS"
    for ch in $UNII1_CHANNELS; do
        local cac=$(get_cac_time "$ch")
        local band=$(get_band_for_channel "$ch")
        if [ "$cac" -eq 0 ] && [ "$band" = "UNII-1" ]; then
            log_debug "    ✓ Channel $ch: CAC=${cac}s, Band=$band"
        else
            log_error "    ✗ Channel $ch: Unexpected CAC=$cac or Band=$band"
            ((errors++))
        fi
    done
    log_success "  ✓ UNII-1 channels validated"

    log_info "  UNII-2A (52-64): DFS, 60s CAC"
    for ch in $UNII2A_CHANNELS; do
        local cac=$(get_cac_time "$ch")
        local band=$(get_band_for_channel "$ch")
        if [ "$cac" -eq 60 ] && [ "$band" = "UNII-2A" ]; then
            log_debug "    ✓ Channel $ch: CAC=${cac}s, Band=$band"
        else
            log_error "    ✗ Channel $ch: Unexpected CAC=$cac (expected 60) or Band=$band"
            ((errors++))
        fi
    done
    log_success "  ✓ UNII-2A channels validated"

    log_info "  UNII-2C (100-144): DFS, 600s CAC"
    for ch in $UNII2C_CHANNELS; do
        local cac=$(get_cac_time "$ch")
        local band=$(get_band_for_channel "$ch")
        if [ "$cac" -eq 600 ] && [ "$band" = "UNII-2C" ]; then
            log_debug "    ✓ Channel $ch: CAC=${cac}s, Band=$band"
        else
            log_error "    ✗ Channel $ch: Unexpected CAC=$cac (expected 600) or Band=$band"
            ((errors++))
        fi
    done
    log_success "  ✓ UNII-2C channels validated"

    log_info "  UNII-3 (149-165): Country-restricted"
    local unii3_allowed="NO"
    is_unii3_allowed "$country" && unii3_allowed="YES"
    log_info "    UNII-3 allowed in $country: $unii3_allowed"

    for ch in $UNII3_CHANNELS; do
        local cac=$(get_cac_time "$ch")
        local band=$(get_band_for_channel "$ch")
        if [ "$cac" -eq 0 ] && [ "$band" = "UNII-3" ]; then
            log_debug "    ✓ Channel $ch: CAC=${cac}s, Band=$band"
        else
            log_error "    ✗ Channel $ch: Unexpected CAC=$cac or Band=$band"
            ((errors++))
        fi
    done
    log_success "  ✓ UNII-3 channels validated"

    # Test 3: Channel list building for each mode
    log_info ""
    log_info "[TEST 3] Channel List Building by Mode"
    log_info "----------------------------------------"

    local modes="quick standard full extended"
    for mode in $modes; do
        local channels
        channels=$(build_calibration_channel_list "$iface" "$mode" "$country")
        local ch_count
        ch_count=$(echo "$channels" | wc -w)

        log_info "  Mode: $mode"
        log_info "    Channels ($ch_count): $channels"

        # Validate channel count expectations
        case "$mode" in
            quick)
                # Should have UNII-1 (4) + possibly UNII-3 (5 if allowed)
                if [ "$unii3_allowed" = "YES" ]; then
                    [ "$ch_count" -ge 4 ] || { log_error "    ✗ Expected >=4 channels"; ((errors++)); }
                else
                    [ "$ch_count" -eq 4 ] || { log_error "    ✗ Expected 4 channels"; ((errors++)); }
                fi
                ;;
            standard)
                # Should have UNII-1 (4) + UNII-2A (4) = 8 minimum
                [ "$ch_count" -ge 8 ] || { log_error "    ✗ Expected >=8 channels"; ((errors++)); }
                ;;
            full)
                # Should have UNII-2A (4) + UNII-1 (4) = 8 minimum
                [ "$ch_count" -ge 8 ] || { log_error "    ✗ Expected >=8 channels"; ((errors++)); }
                # Verify UNII-2A comes first
                local first_ch
                first_ch=$(echo "$channels" | awk '{print $1}')
                if [ "$first_ch" -ge 52 ] && [ "$first_ch" -le 64 ]; then
                    log_debug "    ✓ UNII-2A prioritized (first channel: $first_ch)"
                else
                    log_warn "    ! First channel $first_ch not in UNII-2A range"
                    ((warnings++))
                fi
                ;;
            extended)
                # Should have all bands: UNII-2A (4) + UNII-2C (12) + UNII-1 (4) = 20 minimum
                [ "$ch_count" -ge 20 ] || { log_error "    ✗ Expected >=20 channels"; ((errors++)); }
                ;;
        esac
        log_success "    ✓ Mode $mode validated"
    done

    # Test 4: Dry-run calibration for each mode
    log_info ""
    log_info "[TEST 4] Dry-Run Calibration Tests"
    log_info "----------------------------------------"

    for mode in $modes; do
        log_info "  Testing calibrate mode: $mode"

        # Run scan (no config update)
        local result
        result=$(scan_for_best_channel "$iface" "$mode" "$country" 2>&1)
        local selected_ch
        selected_ch=$(echo "$result" | tail -1)

        if [ -n "$selected_ch" ] && [ "$selected_ch" -ge 36 ]; then
            local sel_band sel_cac
            sel_band=$(get_band_for_channel "$selected_ch")
            sel_cac=$(get_cac_time "$selected_ch")
            log_success "    ✓ Selected channel $selected_ch [$sel_band] (CAC: ${sel_cac}s)"
            test_results="${test_results}$mode:$selected_ch:$sel_band:$sel_cac "
        else
            log_error "    ✗ Failed to select valid channel"
            ((errors++))
        fi
    done

    # Test 5: Country-specific validation
    log_info ""
    log_info "[TEST 5] Country-Specific Validation ($country)"
    log_info "----------------------------------------"

    if is_eu_country "$country"; then
        log_info "  Country is in EU/ETSI region"

        if ! is_unii3_allowed "$country"; then
            log_info "  UNII-3 (149-165) NOT allowed in $country"

            # Verify no calibration mode selects UNII-3
            for mode in $modes; do
                local channels
                channels=$(build_calibration_channel_list "$iface" "$mode" "$country")
                if echo "$channels" | grep -qE "149|153|157|161|165"; then
                    log_error "    ✗ Mode $mode includes UNII-3 channels in restricted country"
                    ((errors++))
                else
                    log_success "    ✓ Mode $mode correctly excludes UNII-3"
                fi
            done
        else
            log_info "  UNII-3 (149-165) IS allowed in $country"
        fi
    else
        log_info "  Country is NOT in EU/ETSI region"
    fi

    # Test 6: VHT center frequency validation
    log_info ""
    log_info "[TEST 6] VHT Center Frequency Validation"
    log_info "----------------------------------------"

    local test_channels="36 52 100 149"
    for ch in $test_channels; do
        local center_80 center_160
        center_80=$(get_vht_center_freq "$ch" 80)
        center_160=$(get_vht_center_freq "$ch" 160)

        log_info "  Channel $ch: center_80=$center_80, center_160=$center_160"

        if [ -n "$center_80" ] && [ "$center_80" -gt 0 ]; then
            log_success "    ✓ 80MHz center frequency valid"
        else
            log_error "    ✗ Invalid 80MHz center frequency"
            ((errors++))
        fi
    done

    # Test Summary
    log_info ""
    log_info "=========================================="
    log_info "BACKTEST SUMMARY"
    log_info "=========================================="
    log_info "Test Results:"
    for result in $test_results; do
        local mode ch band cac
        mode=$(echo "$result" | cut -d: -f1)
        ch=$(echo "$result" | cut -d: -f2)
        band=$(echo "$result" | cut -d: -f3)
        cac=$(echo "$result" | cut -d: -f4)
        log_info "  $mode → Channel $ch [$band] (${cac}s CAC)"
    done
    log_info ""

    if [ "$errors" -eq 0 ] && [ "$warnings" -eq 0 ]; then
        log_success "All tests PASSED"
        return 0
    elif [ "$errors" -eq 0 ]; then
        log_warn "Tests passed with $warnings warnings"
        return 0
    else
        log_error "Tests FAILED: $errors errors, $warnings warnings"
        return 1
    fi
}

validate_all_countries() {
    # Validate channel selection for multiple EU countries
    #
    # Args:
    #   $1 - Interface name

    local iface="$1"

    log_info "=========================================="
    log_info "MULTI-COUNTRY VALIDATION"
    log_info "=========================================="

    local test_countries="GB DE FR IT ES NL BE AT CH SE NO DK FI PL CZ"
    local passed=0
    local failed=0

    for country in $test_countries; do
        log_info ""
        log_info "Testing country: $country"
        log_info "  UNII-3 allowed: $(is_unii3_allowed "$country" && echo "YES" || echo "NO")"

        # Build channel lists for all modes
        local quick_ch standard_ch full_ch extended_ch
        quick_ch=$(build_calibration_channel_list "$iface" "quick" "$country")
        standard_ch=$(build_calibration_channel_list "$iface" "standard" "$country")
        full_ch=$(build_calibration_channel_list "$iface" "full" "$country")
        extended_ch=$(build_calibration_channel_list "$iface" "extended" "$country")

        # Verify UNII-3 restriction
        if ! is_unii3_allowed "$country"; then
            local has_unii3=false
            echo "$quick_ch $standard_ch $full_ch $extended_ch" | grep -qE "149|153|157|161|165" && has_unii3=true

            if [ "$has_unii3" = "true" ]; then
                log_error "  ✗ UNII-3 channels incorrectly included"
                ((failed++))
            else
                log_success "  ✓ UNII-3 correctly excluded"
                ((passed++))
            fi
        else
            log_success "  ✓ UNII-3 allowed (no restriction check needed)"
            ((passed++))
        fi
    done

    log_info ""
    log_info "=========================================="
    log_info "MULTI-COUNTRY SUMMARY"
    log_info "=========================================="
    log_info "Passed: $passed"
    log_info "Failed: $failed"

    [ "$failed" -eq 0 ] && return 0 || return 1
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

Scan Commands:
  scan <iface> [mode]            Scan for best channel
                                 Modes: quick, standard, full, extended
  scan-dfs <iface>               Scan including DFS channels (52-64)
  scan-extended <iface>          Scan all bands including UNII-2C (100-144)

Calibration Commands:
  quick-start <iface> [config] [mode]
                                 Fast startup (mode: quick or standard)
  calibrate <iface> [config]     Quick calibration (non-DFS only)
  calibrate-standard <iface>     Standard mode (UNII-1 + UNII-2A)
  calibrate-full <iface> [conf]  Full calibration with DFS (52-64), for 4AM
  calibrate-extended <iface>     Extended mode (all bands including 100-144)
  install-timer [iface] [mode]   Install 4AM timer (mode: full or extended)

DFS Compliance Commands (ETSI EN 301 893):
  dfs-init                       Initialize DFS state management
  dfs-status <iface>             Show comprehensive DFS status & radar history
  radar-monitor-start <iface>    Start background radar detection monitor
  radar-monitor-stop             Stop radar detection monitor
  nop-status                     Show channels in Non-Occupancy Period
  radar-history [channel]        Show radar event history
  select-dfs-channel <iface>     Select optimal DFS channel using history
  csa-switch <iface> <channel>   Execute fast channel switch with CSA frames
  prepare-fallback <iface>       Pre-compute fallback channel for fast switch

ML-Enhanced Channel Selection:
  ml-status                      Show ML intelligence subsystem status
  ml-score <channel>             Get ML-based score for a channel
  ml-best [--prefer-dfs] [--min-bandwidth N]
                                 Get ML-recommended best channel
  ml-rank [--include-dfs] [--json]
                                 Rank all channels using ML scoring
  ml-train [min_samples]         Train ML model on historical data
  ml-monitor-start <iface>       Start ML-enhanced radar monitoring
  ml-monitor-stop                Stop ML radar monitoring
  ml-select <iface>              Select channel using ML (with fallback)

Testing & Validation:
  backtest <iface> [country]     Run comprehensive backtest of all modes
  validate-countries <iface>     Validate channel selection for EU countries

EU/ETSI 5GHz Channel Bands:
  UNII-1 (36-48):    No DFS - Always safe, immediate startup
  UNII-2A (52-64):   DFS, 60s CAC - Often clearer, use at 4AM
  UNII-2C (100-144): DFS, 600s CAC - Weather radar, long wait (10 min)
  UNII-3 (149-165):  NOT allowed in DE, FR, IT, ES, NL, BE, AT, etc.

DFS Compliance (ETSI EN 301 893):
  - CAC: Channel Availability Check (60s UNII-2A, 600s UNII-2C)
  - NOP: Non-Occupancy Period (30 minutes after radar detection)
  - CSA: Channel Switch Announcement (beacon frames before switch)
  - Channel Move Time: Must vacate within 10 seconds of radar

Calibration Modes:
  quick:    UNII-1 only (36-48) - No CAC, immediate
  standard: UNII-1 + UNII-2A (36-64) - Up to 60s CAC
  full:     UNII-2A > UNII-1 (52-64 first) - 60s CAC, 4AM default
  extended: All bands (52-64 > 100-144 > 36-48) - Up to 600s CAC

Examples:
  # Set regulatory domain FIRST (before any config)
  $(basename "$0") set-regdomain GB

  # Pre-flight check for EU deployment
  $(basename "$0") preflight wlan0 DE

  # Quick start on boot (non-DFS, immediate)
  $(basename "$0") quick-start wlan0 /etc/hostapd/hostapd-5ghz.conf

  # Standard start with UNII-2A validation
  $(basename "$0") quick-start wlan0 /etc/hostapd/hostapd-5ghz.conf standard

  # Full calibration at 4AM (includes DFS 52-64, may wait 60s)
  $(basename "$0") calibrate-full wlan0 /etc/hostapd/hostapd-5ghz.conf

  # Extended calibration (includes UNII-2C, may wait 10 min)
  $(basename "$0") calibrate-extended wlan0 /etc/hostapd/hostapd-5ghz.conf

  # Install 4AM timer with extended mode
  $(basename "$0") install-timer wlan0 extended

  # DFS compliance: Start radar monitoring
  $(basename "$0") dfs-init
  $(basename "$0") radar-monitor-start wlan0

  # Check DFS status and radar history
  $(basename "$0") dfs-status wlan0
  $(basename "$0") radar-history

  # Select safest DFS channel based on history
  $(basename "$0") select-dfs-channel wlan0

  # Fast channel switch after radar detection
  $(basename "$0") csa-switch wlan0 36

  # Run comprehensive backtest
  $(basename "$0") backtest wlan0 DE

  # Validate all EU countries
  $(basename "$0") validate-countries wlan0

  # ML-enhanced channel selection
  $(basename "$0") ml-status
  $(basename "$0") ml-best --prefer-dfs --min-bandwidth 80
  $(basename "$0") ml-rank --include-dfs --json
  $(basename "$0") ml-train 50
  $(basename "$0") ml-monitor-start wlan0

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
            echo ""
            echo "By band:"
            echo "  UNII-1 (36-48):    $UNII1_CHANNELS"
            echo "  UNII-2A (52-64):   $UNII2A_CHANNELS"
            echo "  UNII-2C (100-144): $UNII2C_CHANNELS"
            echo "  UNII-3 (149-165):  $UNII3_CHANNELS"
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
            # Scan with mode: quick, standard, full, extended
            local iface="$1"
            local mode="${2:-quick}"
            scan_for_best_channel "$iface" "$mode"
            ;;
        scan-dfs)
            # Scan including DFS channels (52-64), prefer UNII-2A
            local iface="$1"
            scan_for_best_channel "$iface" "full"
            ;;
        scan-extended)
            # Scan all bands including UNII-2C (100-144)
            local iface="$1"
            scan_for_best_channel "$iface" "extended"
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
        calibrate-standard)
            # Standard calibration: UNII-1 + UNII-2A
            local iface="$1"
            local config="${2:-/etc/hostapd/hostapd-5ghz.conf}"
            calibrate_channel "$iface" "$config" "standard"
            ;;
        calibrate-full|calibrate-dfs)
            # Full calibration: includes DFS (52-64), for 4AM
            local iface="$1"
            local config="${2:-/etc/hostapd/hostapd-5ghz.conf}"
            calibrate_channel "$iface" "$config" "full"
            ;;
        calibrate-extended|calibrate-all)
            # Extended calibration: all bands including UNII-2C (100-144)
            local iface="$1"
            local config="${2:-/etc/hostapd/hostapd-5ghz.conf}"
            calibrate_channel "$iface" "$config" "extended"
            ;;
        install-timer|timer)
            install_calibration_timer "$@"
            ;;
        # DFS Compliance Commands
        dfs-init|init-dfs)
            # Initialize DFS state management
            init_dfs_state
            log_success "DFS state management initialized"
            ;;
        dfs-status|status)
            # Show comprehensive DFS status
            show_dfs_status "$@"
            ;;
        radar-monitor-start|monitor-start)
            # Start radar detection monitor
            local iface="${1:?Interface required}"
            start_radar_monitor "$iface"
            ;;
        radar-monitor-stop|monitor-stop)
            # Stop radar detection monitor
            stop_radar_monitor
            ;;
        nop-status|nop)
            # Show channels in NOP
            local nop_channels
            nop_channels=$(get_nop_channels)
            if [ -z "$nop_channels" ]; then
                log_info "No channels currently in Non-Occupancy Period"
            else
                echo "Channels in NOP (30-minute exclusion after radar):"
                for ch in $nop_channels; do
                    local remaining
                    remaining=$(get_nop_remaining "$ch")
                    echo "  Channel $ch: ${remaining}s remaining"
                done
            fi
            ;;
        radar-history|history)
            # Show radar event history
            local channel="${1:-}"
            if [ -n "$channel" ]; then
                log_info "Radar history for channel $channel:"
                local risk
                risk=$(get_channel_radar_risk "$channel")
                echo "  Risk level: $risk"
                if [ -f "$DFS_RADAR_HISTORY" ]; then
                    jq -r ".channel_stats.\"$channel\" // \"No data\"" "$DFS_RADAR_HISTORY"
                fi
            else
                log_info "Radar event history:"
                if [ -f "$DFS_RADAR_HISTORY" ]; then
                    echo "Recent events:"
                    jq -r '.radar_events[-10:] | .[] | "  \(.timestamp): Ch \(.channel) - \(.event_type)"' "$DFS_RADAR_HISTORY" 2>/dev/null || echo "  No events recorded"
                    echo ""
                    echo "Channel statistics:"
                    jq -r '.channel_stats | to_entries[] | "  Ch \(.key): \(.value.radar_count // 0) events, risk: \(.value.risk_score // "unknown")"' "$DFS_RADAR_HISTORY" 2>/dev/null || echo "  No statistics"
                else
                    echo "No radar history file found. Run 'dfs-init' first."
                fi
            fi
            ;;
        select-dfs-channel|select-dfs)
            # Select optimal DFS channel using radar history
            local iface="${1:?Interface required}"
            local safest
            safest=$(get_safest_dfs_channels "$iface" | head -1)
            if [ -n "$safest" ]; then
                log_success "Optimal DFS channel: $safest"
                echo "$safest"
            else
                log_warn "No safe DFS channels available, using UNII-1"
                echo "36"
            fi
            ;;
        csa-switch|fast-switch)
            # Execute fast channel switch with CSA
            local iface="${1:?Interface required}"
            local target_ch="${2:?Target channel required}"
            execute_fast_channel_switch "$iface" "$target_ch"
            ;;
        prepare-fallback|fallback)
            # Pre-compute fallback channel for fast switch
            local iface="${1:?Interface required}"
            prepare_fallback_channel "$iface"
            ;;
        # ML-Enhanced Commands
        ml-status)
            # Show ML intelligence status
            show_ml_status
            ;;
        ml-score)
            # Get ML score for a channel
            local channel="${1:?Channel required}"
            local hour="${2:-}"
            if dfs_ml_available; then
                ml_score_channel "$channel" "$hour"
            else
                log_error "ML intelligence not available"
                exit 1
            fi
            ;;
        ml-best)
            # Get ML-recommended best channel
            local prefer_dfs="false"
            local min_bw="20"
            local exclude=""
            while [ $# -gt 0 ]; do
                case "$1" in
                    --prefer-dfs) prefer_dfs="true"; shift ;;
                    --min-bandwidth) min_bw="$2"; shift 2 ;;
                    --exclude) exclude="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            if dfs_ml_available; then
                ml_best_channel "$prefer_dfs" "$min_bw" "$exclude"
            else
                log_error "ML intelligence not available"
                exit 1
            fi
            ;;
        ml-rank)
            # Rank all channels using ML
            local include_dfs="false"
            local format="text"
            while [ $# -gt 0 ]; do
                case "$1" in
                    --include-dfs) include_dfs="true"; shift ;;
                    --json) format="json"; shift ;;
                    *) shift ;;
                esac
            done
            if dfs_ml_available; then
                ml_rank_channels "$include_dfs" "$format"
            else
                log_error "ML intelligence not available"
                exit 1
            fi
            ;;
        ml-train)
            # Train ML model
            local min_samples="${1:-50}"
            if dfs_ml_available; then
                ml_train_model "$min_samples"
            else
                log_error "ML intelligence not available (check Python installation)"
                exit 1
            fi
            ;;
        ml-monitor-start)
            # Start ML-enhanced radar monitoring
            local iface="${1:?Interface required}"
            if dfs_ml_available; then
                ml_start_monitor "$iface"
            else
                log_warn "ML not available, falling back to basic monitor"
                start_radar_monitor "$iface"
            fi
            ;;
        ml-monitor-stop)
            # Stop ML radar monitoring
            ml_stop_monitor
            ;;
        ml-select)
            # Select channel using ML with fallback
            local iface="${1:?Interface required}"
            local include_dfs="${2:-true}"
            local min_bw="${3:-20}"
            select_optimal_channel_ml "$iface" "$include_dfs" "$min_bw"
            ;;
        backtest|test-all)
            # Comprehensive backtest of all modes
            run_backtest "$@"
            ;;
        validate-countries|test-countries)
            # Multi-country validation
            validate_all_countries "$@"
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
