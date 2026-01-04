#!/bin/bash
#
# block-device.sh - AIOCHI AI Agent Tool: Block Device
# Immediately block a device from the network using OVS flow rules
#
# This is a TOOL called by the AI Security Agent via n8n.
# It adds a high-priority DROP rule to OVS for the specified MAC address.
#
# Usage:
#   ./block-device.sh <mac_address> <reason>
#
# Example:
#   ./block-device.sh "aa:bb:cc:dd:ee:ff" "Detected malware C2 communication"
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
REASON="${2:-AI Agent decision}"

if [ -z "$MAC_ADDRESS" ]; then
    echo '{"success": false, "error": "MAC address required", "action": "BLOCK"}'
    exit 1
fi

# Validate MAC format (xx:xx:xx:xx:xx:xx)
if ! echo "$MAC_ADDRESS" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then
    echo '{"success": false, "error": "Invalid MAC address format", "action": "BLOCK", "mac": "'"$MAC_ADDRESS"'"}'
    exit 1
fi

# Normalize MAC to lowercase
MAC_ADDRESS=$(echo "$MAC_ADDRESS" | tr '[:upper:]' '[:lower:]')

# ============================================================
# CHECK OVS BRIDGE
# ============================================================

if ! command -v ovs-vsctl &> /dev/null; then
    echo '{"success": false, "error": "OVS not installed", "action": "BLOCK"}'
    exit 1
fi

if ! ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
    echo '{"success": false, "error": "OVS bridge not found: '"$OVS_BRIDGE"'", "action": "BLOCK"}'
    exit 1
fi

# ============================================================
# ADD DROP RULE
# ============================================================

TIMESTAMP=$(date -Iseconds)

# Add high-priority DROP rule for this MAC (both directions)
# Priority 65535 = highest priority in OpenFlow
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=65535,dl_src=$MAC_ADDRESS,actions=drop" 2>/dev/null || true
ovs-ofctl add-flow "$OVS_BRIDGE" "priority=65535,dl_dst=$MAC_ADDRESS,actions=drop" 2>/dev/null || true

# ============================================================
# RECORD TO STATE FILE
# ============================================================

# Ensure JSON file exists
if [ ! -f "$BLOCKED_FILE" ]; then
    echo '{"blocked_devices": []}' > "$BLOCKED_FILE"
fi

# Add entry using jq if available, otherwise simple append
if command -v jq &> /dev/null; then
    TEMP_FILE=$(mktemp)
    jq --arg mac "$MAC_ADDRESS" --arg reason "$REASON" --arg ts "$TIMESTAMP" \
        '.blocked_devices += [{"mac": $mac, "reason": $reason, "blocked_at": $ts, "source": "ai_agent"}]' \
        "$BLOCKED_FILE" > "$TEMP_FILE" && mv "$TEMP_FILE" "$BLOCKED_FILE"
else
    # Fallback: log to separate line-delimited file
    echo "$TIMESTAMP|$MAC_ADDRESS|$REASON|ai_agent" >> "$STATE_DIR/blocked-devices.log"
fi

# ============================================================
# LOG ACTION
# ============================================================

echo "$TIMESTAMP [BLOCK] $MAC_ADDRESS - $REASON" >> "$LOG_FILE"

# ============================================================
# OUTPUT RESULT
# ============================================================

cat <<EOF
{
    "success": true,
    "action": "BLOCK",
    "mac_address": "$MAC_ADDRESS",
    "reason": "$REASON",
    "timestamp": "$TIMESTAMP",
    "bridge": "$OVS_BRIDGE",
    "rule_priority": 65535,
    "message": "Device blocked from network"
}
EOF
