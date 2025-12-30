#!/bin/bash
# ==============================================================================
# LTE Traffic Collector - Host-side script for wwan0 traffic monitoring
# ==============================================================================
# Runs on host (not in container) to collect interface statistics from sysfs.
# Updates: /opt/hookprobe/fortress/data/lte_usage.json
#
# Install: Copy to /opt/hookprobe/fortress/devices/common/
# Run: Via systemd timer or cron every 30 seconds
# ==============================================================================

set -e

# Configuration
DATA_DIR="/opt/hookprobe/fortress/data"
OUTPUT_FILE="$DATA_DIR/lte_usage.json"
TEMP_FILE="$DATA_DIR/.lte_usage.tmp"

# Find LTE interface
find_lte_interface() {
    # Check common LTE interface names
    for iface in wwan0 usb0 enp0s20u1 wwp0s20u1 wwx* enx*; do
        if [ -d "/sys/class/net/$iface" ]; then
            # Verify it's up or has been up
            if [ -f "/sys/class/net/$iface/statistics/rx_bytes" ]; then
                echo "$iface"
                return 0
            fi
        fi
    done
    return 1
}

# Read interface stats from sysfs
get_interface_stats() {
    local iface="$1"
    local rx_bytes=0
    local tx_bytes=0

    if [ -f "/sys/class/net/$iface/statistics/rx_bytes" ]; then
        rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo 0)
    fi
    if [ -f "/sys/class/net/$iface/statistics/tx_bytes" ]; then
        tx_bytes=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo 0)
    fi

    echo "$rx_bytes $tx_bytes"
}

# Format bytes to human readable (always GB for LTE - more consistent)
format_bytes() {
    local bytes=$1
    # Always show GB for values over 100MB (more consistent for LTE metering)
    if [ "$bytes" -ge 104857600 ]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1073741824}") GB"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1048576}") MB"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1024}") KB"
    else
        echo "$bytes B"
    fi
}

# Format bytes always as GB (for consistency in dashboard)
format_bytes_gb() {
    local bytes=$1
    echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1073741824}") GB"
}

# Main collection logic
main() {
    mkdir -p "$DATA_DIR"

    # Find LTE interface
    local iface
    iface=$(find_lte_interface) || {
        # No LTE interface - write empty state
        cat > "$TEMP_FILE" << EOF
{
  "interface": null,
  "error": "No LTE interface found",
  "last_update": "$(date -Iseconds)"
}
EOF
        mv "$TEMP_FILE" "$OUTPUT_FILE"
        exit 0
    }

    # Get current stats
    read -r current_rx current_tx <<< "$(get_interface_stats "$iface")"

    # Load previous data
    local prev_rx=0
    local prev_tx=0
    local monthly_bytes=0
    local daily_bytes=0
    local stored_month=""
    local stored_day=""

    if [ -f "$OUTPUT_FILE" ]; then
        prev_rx=$(jq -r '.last_rx_bytes // 0' "$OUTPUT_FILE" 2>/dev/null || echo 0)
        prev_tx=$(jq -r '.last_tx_bytes // 0' "$OUTPUT_FILE" 2>/dev/null || echo 0)
        monthly_bytes=$(jq -r '.monthly_bytes // 0' "$OUTPUT_FILE" 2>/dev/null || echo 0)
        daily_bytes=$(jq -r '.daily_bytes // 0' "$OUTPUT_FILE" 2>/dev/null || echo 0)
        stored_month=$(jq -r '.month // ""' "$OUTPUT_FILE" 2>/dev/null || echo "")
        stored_day=$(jq -r '.day // ""' "$OUTPUT_FILE" 2>/dev/null || echo "")
    fi

    # Current date
    local current_month=$(date +%Y-%m)
    local current_day=$(date +%Y-%m-%d)

    # Check for month rollover
    if [ "$stored_month" != "$current_month" ]; then
        monthly_bytes=0
    fi

    # Check for day rollover
    if [ "$stored_day" != "$current_day" ]; then
        daily_bytes=0
    fi

    # Calculate delta (handle counter reset on reboot)
    local delta_rx=0
    local delta_tx=0

    if [ "$current_rx" -ge "$prev_rx" ] && [ "$current_tx" -ge "$prev_tx" ]; then
        delta_rx=$((current_rx - prev_rx))
        delta_tx=$((current_tx - prev_tx))
    else
        # Counter reset detected (reboot) - use current values as delta
        # This means we lose data from before reboot, but that's acceptable
        delta_rx=$current_rx
        delta_tx=$current_tx
    fi

    # Update totals
    monthly_bytes=$((monthly_bytes + delta_rx + delta_tx))
    daily_bytes=$((daily_bytes + delta_rx + delta_tx))

    # Calculate rates (if we have previous data)
    local rx_mbps=0
    local tx_mbps=0

    # Write output - always use GB for daily/monthly (consistent LTE metering)
    cat > "$TEMP_FILE" << EOF
{
  "interface": "$iface",
  "month": "$current_month",
  "day": "$current_day",
  "monthly_bytes": $monthly_bytes,
  "daily_bytes": $daily_bytes,
  "monthly_formatted": "$(format_bytes_gb $monthly_bytes)",
  "daily_formatted": "$(format_bytes_gb $daily_bytes)",
  "monthly_gb": $(awk "BEGIN {printf \"%.2f\", $monthly_bytes/1073741824}"),
  "daily_gb": $(awk "BEGIN {printf \"%.2f\", $daily_bytes/1073741824}"),
  "last_rx_bytes": $current_rx,
  "last_tx_bytes": $current_tx,
  "current_rx_formatted": "$(format_bytes $current_rx)",
  "current_tx_formatted": "$(format_bytes $current_tx)",
  "delta_rx": $delta_rx,
  "delta_tx": $delta_tx,
  "last_update": "$(date -Iseconds)",
  "reset_history": []
}
EOF

    mv "$TEMP_FILE" "$OUTPUT_FILE"
    chmod 644 "$OUTPUT_FILE"
}

main "$@"
