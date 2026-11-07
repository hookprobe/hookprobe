#!/bin/bash
#
# trust-device.sh - AIOCHI AI Agent Tool: Trust Device
# Mark a device as trusted and add to ecosystem bubble
#
# This is a TOOL called by the AI Security Agent via n8n.
# It removes any blocking/throttling rules and marks the device as trusted.
#
# Usage:
#   ./trust-device.sh <mac_address> <ecosystem> <reason>
#
# Ecosystem options:
#   - apple (Apple devices)
#   - google (Android/Google devices)
#   - amazon (Echo, Fire, etc.)
#   - microsoft (Windows, Xbox)
#   - iot (Generic IoT)
#   - family (User-identified family device)
#
# Example:
#   ./trust-device.sh "aa:bb:cc:dd:ee:ff" "apple" "Identified as Dad's iPhone"
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
TRUSTED_FILE="$STATE_DIR/trusted-devices.json"
BLOCKED_FILE="$STATE_DIR/blocked-devices.json"
LOG_FILE="/var/log/aiochi/agent-actions.log"

# Ensure directories exist
mkdir -p "$STATE_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# ============================================================
# INPUT VALIDATION
# ============================================================

MAC_ADDRESS="${1:-}"
ECOSYSTEM="${2:-unknown}"
REASON="${3:-AI Agent decision}"

if [ -z "$MAC_ADDRESS" ]; then
    echo '{"success": false, "error": "MAC address required", "action": "TRUST"}'
    exit 1
fi

# Validate MAC format
if ! echo "$MAC_ADDRESS" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then
    echo '{"success": false, "error": "Invalid MAC address format", "action": "TRUST", "mac": "'"$MAC_ADDRESS"'"}'
    exit 1
fi

# Normalize MAC to lowercase
MAC_ADDRESS=$(echo "$MAC_ADDRESS" | tr '[:upper:]' '[:lower:]')
ECOSYSTEM=$(echo "$ECOSYSTEM" | tr '[:upper:]' '[:lower:]')

# ============================================================
# REMOVE ANY BLOCKING RULES
# ============================================================

TIMESTAMP=$(date -Iseconds)

if command -v ovs-ofctl &> /dev/null && ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
    # Remove DROP rules for this MAC
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=65535" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$MAC_ADDRESS,priority=65535" 2>/dev/null || true

    # Remove VLAN migration rules (let device use normal VLAN)
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=50000" 2>/dev/null || true

    # Remove throttling rules
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=40000" 2>/dev/null || true
fi

# Remove from blocked list if using jq
if [ -f "$BLOCKED_FILE" ] && command -v jq &> /dev/null; then
    TEMP_FILE=$(mktemp)
    jq --arg mac "$MAC_ADDRESS" \
        '.blocked_devices = [.blocked_devices[] | select(.mac != $mac)]' \
        "$BLOCKED_FILE" > "$TEMP_FILE" && mv "$TEMP_FILE" "$BLOCKED_FILE"
fi

# ============================================================
# ADD TO TRUSTED LIST
# ============================================================

if [ ! -f "$TRUSTED_FILE" ]; then
    echo '{"trusted_devices": []}' > "$TRUSTED_FILE"
fi

if command -v jq &> /dev/null; then
    TEMP_FILE=$(mktemp)
    # Remove any existing entry for this MAC first, then add new
    jq --arg mac "$MAC_ADDRESS" --arg eco "$ECOSYSTEM" --arg reason "$REASON" --arg ts "$TIMESTAMP" \
        '.trusted_devices = [.trusted_devices[] | select(.mac != $mac)] + [{"mac": $mac, "ecosystem": $eco, "reason": $reason, "trusted_at": $ts, "trust_score": 90, "source": "ai_agent"}]' \
        "$TRUSTED_FILE" > "$TEMP_FILE" && mv "$TEMP_FILE" "$TRUSTED_FILE"
else
    echo "$TIMESTAMP|$MAC_ADDRESS|$ECOSYSTEM|$REASON|90|ai_agent" >> "$STATE_DIR/trusted-devices.log"
fi

# ============================================================
# LOG ACTION
# ============================================================

echo "$TIMESTAMP [TRUST] $MAC_ADDRESS -> $ECOSYSTEM - $REASON" >> "$LOG_FILE"

# ============================================================
# OUTPUT RESULT
# ============================================================

cat <<EOF
{
    "success": true,
    "action": "TRUST",
    "mac_address": "$MAC_ADDRESS",
    "ecosystem": "$ECOSYSTEM",
    "trust_score": 90,
    "reason": "$REASON",
    "timestamp": "$TIMESTAMP",
    "message": "Device marked as trusted in $ECOSYSTEM ecosystem"
}
EOF
