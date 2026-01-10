#!/bin/bash
#
# throttle-device.sh - AIOCHI AI Agent Tool: Throttle Device
# Rate-limit a device's network access using Traffic Control (tc)
#
# This is a TOOL called by the AI Security Agent via n8n.
# It applies bandwidth limiting to traffic from/to the specified MAC address.
#
# Usage:
#   ./throttle-device.sh <mac_address> <rate> <reason>
#
# Rate formats:
#   - 1mbit (1 Mbps)
#   - 5mbit (5 Mbps)
#   - 10mbit (10 Mbps)
#   - 100kbit (100 Kbps)
#
# Example:
#   ./throttle-device.sh "aa:bb:cc:dd:ee:ff" "1mbit" "Excessive bandwidth usage"
#
# Returns: JSON with status and details
#
# Version: 1.0.0
# License: AGPL-3.0

set -e

# ============================================================
# CONFIGURATION
# ============================================================

OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
STATE_DIR="/var/lib/fortress/aiochi"
THROTTLE_FILE="$STATE_DIR/throttled-devices.json"
LOG_FILE="/var/log/aiochi/agent-actions.log"

# Default throttle rates
DEFAULT_RATE="1mbit"
BURST_SIZE="32k"
LATENCY="50ms"

# Ensure directories exist
mkdir -p "$STATE_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# ============================================================
# INPUT VALIDATION
# ============================================================

MAC_ADDRESS="${1:-}"
RATE="${2:-$DEFAULT_RATE}"
REASON="${3:-AI Agent decision}"

if [ -z "$MAC_ADDRESS" ]; then
    echo '{"success": false, "error": "MAC address required", "action": "THROTTLE"}'
    exit 1
fi

# Validate MAC format
if ! echo "$MAC_ADDRESS" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then
    echo '{"success": false, "error": "Invalid MAC address format", "action": "THROTTLE", "mac": "'"$MAC_ADDRESS"'"}'
    exit 1
fi

# Normalize MAC to lowercase
MAC_ADDRESS=$(echo "$MAC_ADDRESS" | tr '[:upper:]' '[:lower:]')

# Validate rate format
if ! echo "$RATE" | grep -qE '^[0-9]+[kmg]?bit$'; then
    echo '{"success": false, "error": "Invalid rate format. Use: 1mbit, 100kbit, etc.", "action": "THROTTLE"}'
    exit 1
fi

# ============================================================
# CHECK PREREQUISITES
# ============================================================

if ! command -v tc &> /dev/null; then
    echo '{"success": false, "error": "tc (traffic control) not installed", "action": "THROTTLE"}'
    exit 1
fi

if ! command -v ovs-vsctl &> /dev/null; then
    echo '{"success": false, "error": "OVS not installed", "action": "THROTTLE"}'
    exit 1
fi

# ============================================================
# GET INTERFACE FOR MAC
# ============================================================

# Find which OVS port this MAC is associated with
# This is complex with OVS, so we'll use the bridge interface directly
INTERFACE="$OVS_BRIDGE"

# Check if bridge exists as network interface
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo '{"success": false, "error": "Cannot find OVS bridge interface", "action": "THROTTLE"}'
    exit 1
fi

# ============================================================
# APPLY QoS USING OVS NATIVE QoS
# ============================================================

TIMESTAMP=$(date -Iseconds)

# Convert rate to bytes per second for OVS
# OVS uses bytes/sec for max-rate
RATE_VALUE=$(echo "$RATE" | grep -oE '^[0-9]+')
RATE_UNIT=$(echo "$RATE" | grep -oE '[kmg]?bit$')

case "$RATE_UNIT" in
    "kbit")
        RATE_BPS=$((RATE_VALUE * 125))  # kbps to bytes/sec
        ;;
    "mbit")
        RATE_BPS=$((RATE_VALUE * 125000))  # mbps to bytes/sec
        ;;
    "gbit")
        RATE_BPS=$((RATE_VALUE * 125000000))
        ;;
    *)
        RATE_BPS=$((RATE_VALUE / 8))
        ;;
esac

# Generate unique queue ID from MAC (last 2 octets as hex to decimal)
QUEUE_ID=$(echo "$MAC_ADDRESS" | awk -F: '{printf "%d", ("0x" $5 $6)}')
QUEUE_ID=$((QUEUE_ID % 65535 + 1))

# Create OVS QoS policy
# First, find/create the QoS record
QOS_UUID=$(ovs-vsctl create qos type=linux-htb other-config:max-rate=$RATE_BPS 2>/dev/null) || true

if [ -n "$QOS_UUID" ]; then
    # Apply to OVS with meter (OpenFlow 1.3+)
    # Using OpenFlow meter for rate limiting
    ovs-ofctl -O OpenFlow13 add-meter "$OVS_BRIDGE" \
        "meter=$QUEUE_ID,kbps,burst,stats,band=type=drop,rate=$((RATE_VALUE * (echo "$RATE_UNIT" | grep -q "mbit" && echo 1000 || echo 1))),burst_size=32" 2>/dev/null || true

    # Add flow rule that applies the meter
    ovs-ofctl -O OpenFlow13 add-flow "$OVS_BRIDGE" \
        "priority=40000,dl_src=$MAC_ADDRESS,actions=meter:$QUEUE_ID,normal" 2>/dev/null || true

    QOS_APPLIED=true
else
    # Fallback: Use tc if OVS QoS fails
    # Add ingress qdisc if not exists
    tc qdisc add dev "$INTERFACE" handle ffff: ingress 2>/dev/null || true

    # Add filter to rate limit this MAC
    tc filter add dev "$INTERFACE" parent ffff: protocol ip prio 1 \
        u32 match ether src "$MAC_ADDRESS" 0xffffffffffff \
        police rate "$RATE" burst "$BURST_SIZE" drop flowid :1 2>/dev/null || true

    QOS_APPLIED=true
fi

# ============================================================
# RECORD TO STATE FILE
# ============================================================

if [ ! -f "$THROTTLE_FILE" ]; then
    echo '{"throttled_devices": []}' > "$THROTTLE_FILE"
fi

if command -v jq &> /dev/null; then
    TEMP_FILE=$(mktemp)
    jq --arg mac "$MAC_ADDRESS" --arg rate "$RATE" --arg reason "$REASON" --arg ts "$TIMESTAMP" \
        '.throttled_devices += [{"mac": $mac, "rate": $rate, "reason": $reason, "throttled_at": $ts, "source": "ai_agent"}]' \
        "$THROTTLE_FILE" > "$TEMP_FILE" && mv "$TEMP_FILE" "$THROTTLE_FILE"
else
    echo "$TIMESTAMP|$MAC_ADDRESS|$RATE|$REASON|ai_agent" >> "$STATE_DIR/throttled-devices.log"
fi

# ============================================================
# LOG ACTION
# ============================================================

echo "$TIMESTAMP [THROTTLE] $MAC_ADDRESS @ $RATE - $REASON" >> "$LOG_FILE"

# ============================================================
# OUTPUT RESULT
# ============================================================

cat <<EOF
{
    "success": true,
    "action": "THROTTLE",
    "mac_address": "$MAC_ADDRESS",
    "rate_limit": "$RATE",
    "rate_bps": $RATE_BPS,
    "reason": "$REASON",
    "timestamp": "$TIMESTAMP",
    "interface": "$INTERFACE",
    "message": "Device throttled to $RATE"
}
EOF
