#!/bin/bash
# ==============================================================================
# LTE Usage Tracker - Watermark-based metered data tracking
# ==============================================================================
# Uses SQLite database to track usage with proper baseline/watermark resets.
# The kernel counters are READ-ONLY - we store snapshots and calculate deltas.
#
# Database: /var/lib/hookprobe/lte_usage.db
# Output:   /opt/hookprobe/fortress/data/lte_usage.json
#
# Tables:
#   - baselines: Monthly reset watermarks (baseline snapshots)
#   - readings:  Historical readings for trend analysis
#   - resets:    Reset history log
# ==============================================================================

set -e

# Configuration
DATA_DIR="/opt/hookprobe/fortress/data"
DB_FILE="/var/lib/hookprobe/lte_usage.db"
OUTPUT_FILE="$DATA_DIR/lte_usage.json"
TEMP_FILE="$DATA_DIR/.lte_usage.tmp"
RESET_REQUEST_FILE="$DATA_DIR/.lte_reset_request"

# Ensure directories exist
mkdir -p "$DATA_DIR"
mkdir -p "$(dirname "$DB_FILE")"

# Check for pending reset requests (from container via trigger file)
check_reset_requests() {
    if [ -f "$RESET_REQUEST_FILE" ]; then
        local reset_type
        reset_type=$(cat "$RESET_REQUEST_FILE" 2>/dev/null | grep -o '"type"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')

        if [ -n "$reset_type" ]; then
            echo "Processing reset request: $reset_type"
            do_reset "$reset_type"
        fi

        # Remove the request file
        rm -f "$RESET_REQUEST_FILE"
    fi
}

# Initialize SQLite database
init_database() {
    sqlite3 "$DB_FILE" << 'EOF'
CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL,
    period_type TEXT NOT NULL,  -- 'monthly' or 'daily'
    period_key TEXT NOT NULL,   -- '2025-12' or '2025-12-30'
    rx_baseline INTEGER NOT NULL DEFAULT 0,
    tx_baseline INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(interface, period_type, period_key)
);

CREATE TABLE IF NOT EXISTS readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL,
    reset_type TEXT NOT NULL,  -- 'monthly', 'daily', 'manual'
    period_key TEXT NOT NULL,
    rx_at_reset INTEGER NOT NULL,
    tx_at_reset INTEGER NOT NULL,
    reset_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason TEXT
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_baselines_lookup
    ON baselines(interface, period_type, period_key);
CREATE INDEX IF NOT EXISTS idx_readings_time
    ON readings(interface, timestamp);
EOF
}

# Find LTE interface
find_lte_interface() {
    for iface in wwan0 usb0 enp0s20u1 wwp0s20u1 wwx* enx*; do
        if [ -d "/sys/class/net/$iface" ]; then
            if [ -f "/sys/class/net/$iface/statistics/rx_bytes" ]; then
                echo "$iface"
                return 0
            fi
        fi
    done
    return 1
}

# Read current hardware counters
get_hw_counters() {
    local iface="$1"
    local rx=0 tx=0

    if [ -f "/sys/class/net/$iface/statistics/rx_bytes" ]; then
        rx=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo 0)
    fi
    if [ -f "/sys/class/net/$iface/statistics/tx_bytes" ]; then
        tx=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo 0)
    fi

    echo "$rx $tx"
}

# Get or create baseline for a period
get_baseline() {
    local iface="$1"
    local period_type="$2"
    local period_key="$3"
    local current_rx="$4"
    local current_tx="$5"

    # Try to get existing baseline
    local result
    result=$(sqlite3 "$DB_FILE" "SELECT rx_baseline, tx_baseline FROM baselines
        WHERE interface='$iface' AND period_type='$period_type' AND period_key='$period_key' LIMIT 1;")

    if [ -n "$result" ]; then
        echo "$result" | tr '|' ' '
    else
        # No baseline exists - create one with current values
        # This means usage starts from 0 for this new period
        sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO baselines
            (interface, period_type, period_key, rx_baseline, tx_baseline)
            VALUES ('$iface', '$period_type', '$period_key', $current_rx, $current_tx);"
        echo "$current_rx $current_tx"
    fi
}

# Record a manual reset (creates new baseline)
record_reset() {
    local iface="$1"
    local reset_type="$2"
    local period_key="$3"
    local current_rx="$4"
    local current_tx="$5"
    local reason="${6:-manual}"

    # Log the reset
    sqlite3 "$DB_FILE" "INSERT INTO resets
        (interface, reset_type, period_key, rx_at_reset, tx_at_reset, reason)
        VALUES ('$iface', '$reset_type', '$period_key', $current_rx, $current_tx, '$reason');"

    # Update baseline to current values (usage becomes 0)
    sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO baselines
        (interface, period_type, period_key, rx_baseline, tx_baseline)
        VALUES ('$iface', '$reset_type', '$period_key', $current_rx, $current_tx);"
}

# Store reading for history
store_reading() {
    local iface="$1"
    local rx="$2"
    local tx="$3"

    sqlite3 "$DB_FILE" "INSERT INTO readings (interface, rx_bytes, tx_bytes)
        VALUES ('$iface', $rx, $tx);"

    # Cleanup old readings (keep last 7 days)
    sqlite3 "$DB_FILE" "DELETE FROM readings
        WHERE timestamp < datetime('now', '-7 days');"
}

# Format bytes to GB
format_gb() {
    local bytes=$1
    awk "BEGIN {printf \"%.2f\", $bytes/1073741824}"
}

# Main collection logic
main() {
    # Initialize database if needed
    init_database

    # Check for pending reset requests from container
    check_reset_requests

    # Find LTE interface
    local iface
    iface=$(find_lte_interface) || {
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

    # Get current hardware counters
    read -r hw_rx hw_tx <<< "$(get_hw_counters "$iface")"

    # Current periods
    local current_month=$(date +%Y-%m)
    local current_day=$(date +%Y-%m-%d)

    # Get or create baselines
    read -r monthly_rx_base monthly_tx_base <<< "$(get_baseline "$iface" "monthly" "$current_month" "$hw_rx" "$hw_tx")"
    read -r daily_rx_base daily_tx_base <<< "$(get_baseline "$iface" "daily" "$current_day" "$hw_rx" "$hw_tx")"

    # Calculate usage (current - baseline)
    # Handle counter overflow/reset (if hw < baseline, counter was reset)
    local monthly_usage=0
    local daily_usage=0

    if [ "$hw_rx" -ge "$monthly_rx_base" ] && [ "$hw_tx" -ge "$monthly_tx_base" ]; then
        monthly_usage=$(( (hw_rx - monthly_rx_base) + (hw_tx - monthly_tx_base) ))
    else
        # Hardware counter was reset (reboot) - update baseline
        record_reset "$iface" "monthly" "$current_month" "$hw_rx" "$hw_tx" "hw_counter_reset"
        monthly_usage=0
    fi

    if [ "$hw_rx" -ge "$daily_rx_base" ] && [ "$hw_tx" -ge "$daily_tx_base" ]; then
        daily_usage=$(( (hw_rx - daily_rx_base) + (hw_tx - daily_tx_base) ))
    else
        # Hardware counter was reset - update baseline
        record_reset "$iface" "daily" "$current_day" "$hw_rx" "$hw_tx" "hw_counter_reset"
        daily_usage=0
    fi

    # Store reading for trend analysis
    store_reading "$iface" "$hw_rx" "$hw_tx"

    # Get last reset info
    local last_reset
    last_reset=$(sqlite3 "$DB_FILE" "SELECT reset_at FROM resets
        WHERE interface='$iface' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")

    # Write output JSON
    cat > "$TEMP_FILE" << EOF
{
  "interface": "$iface",
  "month": "$current_month",
  "day": "$current_day",
  "monthly_bytes": $monthly_usage,
  "daily_bytes": $daily_usage,
  "monthly_formatted": "$(format_gb $monthly_usage) GB",
  "daily_formatted": "$(format_gb $daily_usage) GB",
  "monthly_gb": $(format_gb $monthly_usage),
  "daily_gb": $(format_gb $daily_usage),
  "hw_rx_bytes": $hw_rx,
  "hw_tx_bytes": $hw_tx,
  "monthly_baseline": {
    "rx": $monthly_rx_base,
    "tx": $monthly_tx_base
  },
  "daily_baseline": {
    "rx": $daily_rx_base,
    "tx": $daily_tx_base
  },
  "last_reset": ${last_reset:+\"$last_reset\"}${last_reset:-null},
  "last_update": "$(date -Iseconds)",
  "tracking_method": "watermark"
}
EOF

    mv "$TEMP_FILE" "$OUTPUT_FILE"
    chmod 644 "$OUTPUT_FILE"
}

# Reset command (called by API)
do_reset() {
    local reset_type="${1:-monthly}"
    local iface
    iface=$(find_lte_interface) || exit 1

    read -r hw_rx hw_tx <<< "$(get_hw_counters "$iface")"

    case "$reset_type" in
        monthly)
            local period_key=$(date +%Y-%m)
            record_reset "$iface" "monthly" "$period_key" "$hw_rx" "$hw_tx" "user_reset"
            echo "Monthly usage reset to 0 (baseline updated)"
            ;;
        daily)
            local period_key=$(date +%Y-%m-%d)
            record_reset "$iface" "daily" "$period_key" "$hw_rx" "$hw_tx" "user_reset"
            echo "Daily usage reset to 0 (baseline updated)"
            ;;
        all)
            local month=$(date +%Y-%m)
            local day=$(date +%Y-%m-%d)
            record_reset "$iface" "monthly" "$month" "$hw_rx" "$hw_tx" "user_reset"
            record_reset "$iface" "daily" "$day" "$hw_rx" "$hw_tx" "user_reset"
            echo "All usage counters reset to 0"
            ;;
        *)
            echo "Unknown reset type: $reset_type"
            exit 1
            ;;
    esac
}

# Command handling
case "${1:-collect}" in
    collect)
        main
        ;;
    reset)
        do_reset "${2:-monthly}"
        ;;
    init)
        init_database
        echo "Database initialized: $DB_FILE"
        ;;
    *)
        echo "Usage: $0 [collect|reset <type>|init]"
        exit 1
        ;;
esac
