#!/bin/bash
# =============================================================================
# WiFi Signal Collector - Premium SDN Feature
# =============================================================================
# Collects RSSI/signal quality for all connected WiFi clients
# Runs on HOST (not container) - requires access to wireless interfaces
#
# Output: /opt/hookprobe/fortress/data/wifi_signals.json
# Schedule: Run via systemd timer every 30 seconds
# =============================================================================

set -euo pipefail

# Configuration
DATA_DIR="/opt/hookprobe/fortress/data"
OUTPUT_FILE="${DATA_DIR}/wifi_signals.json"
TEMP_FILE="${OUTPUT_FILE}.tmp"
LOG_FILE="/var/log/hookprobe/wifi-signal-collector.log"

# WiFi interface names (set during Fortress install)
WIFI_CONFIG="/etc/hookprobe/wifi-interfaces.conf"

# Proximity thresholds (dBm)
THRESHOLD_IMMEDIATE=-45   # Very close to router
THRESHOLD_NEAR=-65        # Same room
THRESHOLD_FAR=-75         # Adjacent room
# Below -75 = "Distant" (potential security concern for full_access devices)

# Ensure directories exist with proper permissions (container runs as UID 1000)
mkdir -p "$DATA_DIR" "$(dirname "$LOG_FILE")"
chmod 777 "$DATA_DIR" 2>/dev/null || true
chown 1000:1000 "$DATA_DIR" 2>/dev/null || true

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# Get proximity label from RSSI
get_proximity() {
    local rssi=$1
    if [ "$rssi" -gt "$THRESHOLD_IMMEDIATE" ]; then
        echo "immediate"
    elif [ "$rssi" -gt "$THRESHOLD_NEAR" ]; then
        echo "near"
    elif [ "$rssi" -gt "$THRESHOLD_FAR" ]; then
        echo "far"
    else
        echo "distant"
    fi
}

# Calculate signal quality percentage (0-100)
# Formula: quality = 2 * (rssi + 100), clamped to 0-100
get_quality() {
    local rssi=$1
    local quality=$((2 * (rssi + 100)))
    if [ "$quality" -gt 100 ]; then
        quality=100
    elif [ "$quality" -lt 0 ]; then
        quality=0
    fi
    echo "$quality"
}

# Get WiFi interface names
get_interfaces() {
    local interfaces=()

    # Try config file first
    if [ -f "$WIFI_CONFIG" ]; then
        while IFS='=' read -r key value; do
            case "$key" in
                WIFI_24GHZ|WIFI_5GHZ)
                    [ -n "$value" ] && interfaces+=("$value")
                    ;;
            esac
        done < "$WIFI_CONFIG"
    fi

    # Fallback: detect wireless interfaces
    if [ ${#interfaces[@]} -eq 0 ]; then
        for iface in /sys/class/net/*/wireless; do
            if [ -d "$iface" ]; then
                interfaces+=("$(basename "$(dirname "$iface")")")
            fi
        done
    fi

    # Last resort: common names
    if [ ${#interfaces[@]} -eq 0 ]; then
        for iface in wlan0 wlan1 wlan_24ghz wlan_5ghz; do
            if [ -d "/sys/class/net/$iface" ]; then
                interfaces+=("$iface")
            fi
        done
    fi

    echo "${interfaces[@]}"
}

# Tickle device with ARP ping to refresh RSSI
tickle_device() {
    local ip=$1
    # Send single ARP ping (non-blocking, ignore errors)
    arping -c 1 -w 1 "$ip" &>/dev/null || true
}

# Collect signals from one interface
collect_interface_signals() {
    local iface=$1
    local band=$2

    # Check interface exists and is up
    if ! ip link show "$iface" &>/dev/null; then
        return
    fi

    # Get station dump
    local dump
    dump=$(iw dev "$iface" station dump 2>/dev/null) || return

    # Parse station data
    local current_mac=""
    local current_rssi=""
    local current_rx_bytes=""
    local current_tx_bytes=""
    local current_connected_time=""
    local current_inactive_time=""

    while IFS= read -r line; do
        # New station entry
        if [[ "$line" =~ ^Station[[:space:]]([0-9a-fA-F:]+) ]]; then
            # Output previous station if we have data
            if [ -n "$current_mac" ] && [ -n "$current_rssi" ]; then
                local quality=$(get_quality "$current_rssi")
                local proximity=$(get_proximity "$current_rssi")
                echo "{\"mac\":\"${current_mac^^}\",\"rssi\":$current_rssi,\"quality\":$quality,\"proximity\":\"$proximity\",\"band\":\"$band\",\"interface\":\"$iface\",\"rx_bytes\":${current_rx_bytes:-0},\"tx_bytes\":${current_tx_bytes:-0},\"connected_time\":${current_connected_time:-0},\"inactive_ms\":${current_inactive_time:-0}}"
            fi
            current_mac="${BASH_REMATCH[1]}"
            current_rssi=""
            current_rx_bytes=""
            current_tx_bytes=""
            current_connected_time=""
            current_inactive_time=""
        fi

        # Parse signal strength
        if [[ "$line" =~ signal:[[:space:]]*(-?[0-9]+)[[:space:]]*dBm ]]; then
            current_rssi="${BASH_REMATCH[1]}"
        fi

        # Parse traffic counters
        if [[ "$line" =~ rx\ bytes:[[:space:]]*([0-9]+) ]]; then
            current_rx_bytes="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ tx\ bytes:[[:space:]]*([0-9]+) ]]; then
            current_tx_bytes="${BASH_REMATCH[1]}"
        fi

        # Parse connection time
        if [[ "$line" =~ connected\ time:[[:space:]]*([0-9]+) ]]; then
            current_connected_time="${BASH_REMATCH[1]}"
        fi

        # Parse inactive time (ms since last packet)
        if [[ "$line" =~ inactive\ time:[[:space:]]*([0-9]+) ]]; then
            current_inactive_time="${BASH_REMATCH[1]}"
        fi

    done <<< "$dump"

    # Output last station
    if [ -n "$current_mac" ] && [ -n "$current_rssi" ]; then
        local quality=$(get_quality "$current_rssi")
        local proximity=$(get_proximity "$current_rssi")
        echo "{\"mac\":\"${current_mac^^}\",\"rssi\":$current_rssi,\"quality\":$quality,\"proximity\":\"$proximity\",\"band\":\"$band\",\"interface\":\"$iface\",\"rx_bytes\":${current_rx_bytes:-0},\"tx_bytes\":${current_tx_bytes:-0},\"connected_time\":${current_connected_time:-0},\"inactive_ms\":${current_inactive_time:-0}}"
    fi
}

# Main collection
main() {
    local interfaces
    read -ra interfaces <<< "$(get_interfaces)"

    if [ ${#interfaces[@]} -eq 0 ]; then
        log "No wireless interfaces found"
        # Write empty result
        echo '{"timestamp":"'"$(date -Iseconds)"'","stations":[],"interfaces":[]}' > "$TEMP_FILE"
        mv "$TEMP_FILE" "$OUTPUT_FILE"
        return
    fi

    log "Collecting WiFi signals from: ${interfaces[*]}"

    # Collect from all interfaces
    local stations=()
    local iface_list=()

    for iface in "${interfaces[@]}"; do
        # Determine band from interface name or channel
        local band="unknown"
        local channel
        channel=$(iw dev "$iface" info 2>/dev/null | grep -oP 'channel \K\d+' || echo "0")

        if [ "$channel" -le 14 ] && [ "$channel" -gt 0 ]; then
            band="2.4GHz"
        elif [ "$channel" -gt 14 ]; then
            band="5GHz"
        fi

        # Also check interface name hints
        if [[ "$iface" =~ 24 ]] || [[ "$iface" =~ 2g ]]; then
            band="2.4GHz"
        elif [[ "$iface" =~ 5g ]] || [[ "$iface" =~ 5ghz ]]; then
            band="5GHz"
        fi

        iface_list+=("\"$iface\"")

        # Collect stations
        while IFS= read -r station_json; do
            [ -n "$station_json" ] && stations+=("$station_json")
        done < <(collect_interface_signals "$iface" "$band")
    done

    # Build JSON output
    {
        echo '{'
        echo '  "timestamp": "'"$(date -Iseconds)"'",'
        echo '  "interfaces": ['"$(IFS=,; echo "${iface_list[*]}")"'],'
        echo '  "station_count": '"${#stations[@]}"','
        echo '  "thresholds": {'
        echo '    "immediate": '"$THRESHOLD_IMMEDIATE"','
        echo '    "near": '"$THRESHOLD_NEAR"','
        echo '    "far": '"$THRESHOLD_FAR"
        echo '  },'
        echo '  "stations": ['

        local first=true
        for station in "${stations[@]}"; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ','
            fi
            echo -n "    $station"
        done

        echo ''
        echo '  ]'
        echo '}'
    } > "$TEMP_FILE"

    mv "$TEMP_FILE" "$OUTPUT_FILE"
    log "Collected ${#stations[@]} WiFi stations"
}

main "$@"
