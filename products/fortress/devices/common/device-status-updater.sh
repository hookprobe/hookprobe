#!/bin/bash
# Device Status Updater - Premium SDN Status Tracking
#
# Runs on HOST (not in container) to update device online/idle/offline status
# using OpenFlow counters and kernel neighbor state.
#
# Output: /opt/hookprobe/fortress/data/device_status.json
#
# Schedule via systemd timer or cron every 30 seconds
# Version: 1.0

set -e

OUTPUT_FILE="/opt/hookprobe/fortress/data/device_status.json"
AUTOPILOT_DB="/var/lib/hookprobe/autopilot.db"
OVS_BRIDGE="FTS"
DATA_DIR="$(dirname "$OUTPUT_FILE")"

# Ensure data directory has proper permissions (container runs as UID 1000)
mkdir -p "$DATA_DIR"
chmod 777 "$DATA_DIR" 2>/dev/null || true
chown 1000:1000 "$DATA_DIR" 2>/dev/null || true

# Thresholds (seconds)
ONLINE_THRESHOLD=60
IDLE_THRESHOLD=300
OFFLINE_THRESHOLD=600

log() {
    logger -t "device-status" "$1"
}

# Get kernel neighbor states
get_neighbor_states() {
    ip neigh show 2>/dev/null | while read line; do
        ip=$(echo "$line" | awk '{print $1}')
        mac=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1 | tr 'a-f' 'A-F')
        state="UNKNOWN"

        for s in REACHABLE STALE DELAY PROBE FAILED INCOMPLETE PERMANENT; do
            if echo "$line" | grep -qw "$s"; then
                state="$s"
                break
            fi
        done

        if [ -n "$mac" ]; then
            echo "${mac}|${state}|${ip}"
        fi
    done
}

# Get OpenFlow packet counters
get_flow_counters() {
    ovs-ofctl dump-flows "$OVS_BRIDGE" -O OpenFlow13 2>/dev/null | \
    grep -oE 'dl_src=[0-9a-fA-F:]+.*n_packets=[0-9]+' | \
    sed -E 's/.*dl_src=([0-9a-fA-F:]+).*n_packets=([0-9]+).*/\1|\2/' | \
    tr 'a-f' 'A-F' | \
    awk -F'|' '{sum[$1]+=$2} END {for (mac in sum) print mac"|"sum[mac]}'
}

# Main status update
update_status() {
    local now=$(date +%s)
    local timestamp=$(date -Iseconds)

    # Build lookup tables
    declare -A neighbor_state
    declare -A neighbor_ip
    declare -A flow_packets
    declare -A prev_packets
    declare -A last_seen

    # Read neighbor states
    while IFS='|' read -r mac state ip; do
        [ -n "$mac" ] && neighbor_state["$mac"]="$state"
        [ -n "$ip" ] && neighbor_ip["$mac"]="$ip"
    done < <(get_neighbor_states)

    # Read flow counters
    while IFS='|' read -r mac packets; do
        [ -n "$mac" ] && flow_packets["$mac"]="$packets"
    done < <(get_flow_counters)

    # Read previous state from JSON if exists
    if [ -f "$OUTPUT_FILE" ]; then
        while IFS='|' read -r mac pkts seen; do
            [ -n "$mac" ] && prev_packets["$mac"]="$pkts"
            [ -n "$seen" ] && last_seen["$mac"]="$seen"
        done < <(jq -r '.devices[] | "\(.mac)|\(.last_packet_count)|\(.last_seen_epoch)"' "$OUTPUT_FILE" 2>/dev/null)
    fi

    # Get devices from autopilot.db
    if [ ! -f "$AUTOPILOT_DB" ]; then
        log "autopilot.db not found at $AUTOPILOT_DB"
        echo '{"timestamp":"'"$timestamp"'","devices":[],"stats":{"online":0,"idle":0,"offline":0}}'
        return
    fi

    local online=0 idle=0 offline=0
    local devices_json="["
    local first=true

    while IFS='|' read -r mac ip hostname policy; do
        [ -z "$mac" ] && continue
        mac=$(echo "$mac" | tr 'a-f' 'A-F')

        # Get current state
        local state="${neighbor_state[$mac]:-UNKNOWN}"
        local curr_pkts="${flow_packets[$mac]:-0}"
        local prev_pkts="${prev_packets[$mac]:-0}"
        local prev_seen="${last_seen[$mac]:-$now}"

        # Check for new traffic
        local has_new_traffic=false
        [ "$curr_pkts" -gt "$prev_pkts" ] 2>/dev/null && has_new_traffic=true

        # Calculate elapsed time
        local elapsed=$((now - prev_seen))
        [ "$has_new_traffic" = true ] && elapsed=0

        # Determine status
        local status="offline"

        if [ "$has_new_traffic" = true ]; then
            status="online"
        elif [ "$state" = "REACHABLE" ]; then
            status="online"
        elif [ "$state" = "STALE" ] || [ "$state" = "DELAY" ] || [ "$state" = "PROBE" ]; then
            if [ "$elapsed" -lt "$IDLE_THRESHOLD" ]; then
                status="idle"
            fi
        elif [ "$elapsed" -lt "$ONLINE_THRESHOLD" ]; then
            status="online"
        elif [ "$elapsed" -lt "$IDLE_THRESHOLD" ]; then
            status="idle"
        fi

        # Update counters (use : || true to prevent set -e exit on 0++ returning 0)
        case "$status" in
            online) ((++online)) || true ;;
            idle) ((++idle)) || true ;;
            offline) ((++offline)) || true ;;
        esac

        # Update last_seen if new traffic
        local seen_epoch="$prev_seen"
        [ "$has_new_traffic" = true ] && seen_epoch="$now"

        # Build JSON entry
        [ "$first" = false ] && devices_json+=","
        first=false
        devices_json+=$(cat <<ENTRY
{
  "mac": "$mac",
  "ip": "$ip",
  "hostname": "$hostname",
  "policy": "$policy",
  "status": "$status",
  "neighbor_state": "$state",
  "last_packet_count": $curr_pkts,
  "last_seen_epoch": $seen_epoch
}
ENTRY
)
    done < <(sqlite3 "$AUTOPILOT_DB" "SELECT mac, ip, COALESCE(friendly_name, hostname, ''), policy FROM device_identity" 2>/dev/null)

    # Also add ARP-discovered devices not yet in autopilot.db
    # This ensures new devices show online status before they're classified
    declare -A processed_macs
    for mac in "${!neighbor_state[@]}"; do
        processed_macs["$mac"]=1
    done

    # Check which ARP devices are not in DB and add them
    while IFS='|' read -r mac state ip; do
        [ -z "$mac" ] && continue

        # Skip if already processed from autopilot.db
        if sqlite3 "$AUTOPILOT_DB" "SELECT 1 FROM device_identity WHERE mac = '$mac'" 2>/dev/null | grep -q 1; then
            continue
        fi

        # New device from ARP - add to output
        local status="offline"
        if [ "$state" = "REACHABLE" ]; then
            status="online"
            ((++online)) || true
        elif [ "$state" = "STALE" ] || [ "$state" = "DELAY" ] || [ "$state" = "PROBE" ]; then
            status="idle"
            ((++idle)) || true
        else
            ((++offline)) || true
        fi

        [ "$first" = false ] && devices_json+=","
        first=false
        devices_json+=$(cat <<ENTRY
{
  "mac": "$mac",
  "ip": "$ip",
  "hostname": "",
  "policy": "quarantine",
  "status": "$status",
  "neighbor_state": "$state",
  "last_packet_count": 0,
  "last_seen_epoch": $now,
  "discovered_via": "arp"
}
ENTRY
)
    done < <(get_neighbor_states)

    devices_json+="]"

    # Write output
    cat > "$OUTPUT_FILE" <<EOF
{
  "timestamp": "$timestamp",
  "updated_epoch": $now,
  "stats": {
    "online": $online,
    "idle": $idle,
    "offline": $offline,
    "total": $((online + idle + offline))
  },
  "devices": $devices_json
}
EOF

    log "Status update: $online online, $idle idle, $offline offline"
}

# Ensure output directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Run update
update_status
