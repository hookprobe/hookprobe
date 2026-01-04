#!/bin/bash
#
# unblock-device.sh - AIOCHI AI Agent Tool: Unblock Device
# Remove block rules for a previously blocked device
#
# This is a TOOL called when a user provides feedback to undo a BLOCK action.
#
# Usage:
#   ./unblock-device.sh <mac_address> <reason>
#
# Example:
#   ./unblock-device.sh "aa:bb:cc:dd:ee:ff" "User approved device"
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
BLOCKED_FILE="$STATE_DIR/blocked-devices.json"
LOG_FILE="/var/log/aiochi/agent-actions.log"

# Ensure directories exist
mkdir -p "$STATE_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# ============================================================
# INPUT VALIDATION
# ============================================================

MAC_ADDRESS="${1:-}"
REASON="${2:-User feedback: approved}"

if [ -z "$MAC_ADDRESS" ]; then
    echo '{"success": false, "error": "MAC address required", "action": "UNBLOCK"}'
    exit 1
fi

# Validate MAC format
if ! echo "$MAC_ADDRESS" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then
    echo '{"success": false, "error": "Invalid MAC address format", "action": "UNBLOCK", "mac": "'"$MAC_ADDRESS"'"}'
    exit 1
fi

# Normalize MAC to lowercase
MAC_ADDRESS=$(echo "$MAC_ADDRESS" | tr '[:upper:]' '[:lower:]')

# ============================================================
# REMOVE DROP RULES
# ============================================================

TIMESTAMP=$(date -Iseconds)

if command -v ovs-ofctl &> /dev/null && ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
    # Remove DROP rules (both directions)
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=65535" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$MAC_ADDRESS,priority=65535" 2>/dev/null || true
fi

# ============================================================
# UPDATE STATE FILE
# ============================================================

if [ -f "$BLOCKED_FILE" ] && command -v jq &> /dev/null; then
    TEMP_FILE=$(mktemp)
    jq --arg mac "$MAC_ADDRESS" \
        '.blocked_devices = [.blocked_devices[] | select(.mac != $mac)]' \
        "$BLOCKED_FILE" > "$TEMP_FILE" && mv "$TEMP_FILE" "$BLOCKED_FILE"
fi

# ============================================================
# LOG ACTION
# ============================================================

echo "$TIMESTAMP [UNBLOCK] $MAC_ADDRESS - $REASON" >> "$LOG_FILE"

# ============================================================
# OUTPUT RESULT
# ============================================================

cat <<EOF
{
    "success": true,
    "action": "UNBLOCK",
    "mac_address": "$MAC_ADDRESS",
    "reason": "$REASON",
    "timestamp": "$TIMESTAMP",
    "message": "Device unblocked and restored to network"
}
EOF
