#!/bin/bash
#
# migrate-device.sh - AIOCHI AI Agent Tool: Apply Network Policy
# Apply an OpenFlow policy to a device (quarantine, internet_only, etc.)
#
# This is a TOOL called by the AI Security Agent via n8n.
# It modifies device network access by applying OpenFlow/nftables policies.
#
# Usage:
#   ./migrate-device.sh <mac_address> <policy> <reason>
#
# OpenFlow Policies:
#   - quarantine: Isolated, no network access (DROP all traffic)
#   - internet_only: Internet only, no LAN access (guests, voice assistants)
#   - lan_only: LAN only, no internet (IoT, cameras, sensors)
#   - smart_home: Local network + mDNS/Bonjour (HomeKit, AirPlay, normal IoT)
#   - full_access: Full internet + LAN access (trusted devices)
#
# Example:
#   ./migrate-device.sh "aa:bb:cc:dd:ee:ff" "quarantine" "Unknown device detected"
#
# Returns: JSON with status and details
#
# Version: 1.1.0
# License: AGPL-3.0

set -e

# ============================================================
# CONFIGURATION
# ============================================================

OVS_BRIDGE="${OVS_BRIDGE:-FTS}"
STATE_DIR="/var/lib/fortress/aiochi"
MIGRATE_FILE="$STATE_DIR/policy-assignments.json"
LOG_FILE="/var/log/aiochi/agent-actions.log"
NFT_MANAGER="/opt/hookprobe/products/fortress/devices/common/network-filter-manager.sh"

# OpenFlow policy priorities (higher = processed first)
# Agent actions use priority 55000-60000 range
declare -A POLICY_PRIORITY
POLICY_PRIORITY["quarantine"]=60000    # Highest - complete isolation
POLICY_PRIORITY["internet_only"]=57000
POLICY_PRIORITY["lan_only"]=55000
POLICY_PRIORITY["smart_home"]=55000
POLICY_PRIORITY["full_access"]=0       # Remove restrictions (use NORMAL)

# Ensure directories exist
mkdir -p "$STATE_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# ============================================================
# INPUT VALIDATION
# ============================================================

MAC_ADDRESS="${1:-}"
POLICY="${2:-quarantine}"
REASON="${3:-AI Agent decision}"

if [ -z "$MAC_ADDRESS" ]; then
    echo '{"success": false, "error": "MAC address required", "action": "MIGRATE"}'
    exit 1
fi

# Validate MAC format
if ! echo "$MAC_ADDRESS" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then
    echo '{"success": false, "error": "Invalid MAC address format", "action": "MIGRATE", "mac": "'"$MAC_ADDRESS"'"}'
    exit 1
fi

# Normalize MAC to lowercase
MAC_ADDRESS=$(echo "$MAC_ADDRESS" | tr '[:upper:]' '[:lower:]')

# Normalize policy name
POLICY=$(echo "$POLICY" | tr '[:upper:]' '[:lower:]' | tr '-' '_')

# Map aliases to canonical policy names
case "$POLICY" in
    "isolated") POLICY="quarantine" ;;
    "default"|"iot") POLICY="lan_only" ;;
    "guest") POLICY="internet_only" ;;
    "trusted") POLICY="full_access" ;;
esac

# Validate policy
VALID_POLICIES=("quarantine" "internet_only" "lan_only" "smart_home" "full_access")
POLICY_VALID=false
for p in "${VALID_POLICIES[@]}"; do
    if [ "$POLICY" = "$p" ]; then
        POLICY_VALID=true
        break
    fi
done

if [ "$POLICY_VALID" = false ]; then
    echo '{"success": false, "error": "Unknown policy: '"$POLICY"'. Valid: quarantine, internet_only, lan_only, smart_home, full_access", "action": "MIGRATE"}'
    exit 1
fi

# ============================================================
# CHECK OVS BRIDGE
# ============================================================

USE_OVS=false
if command -v ovs-vsctl &> /dev/null && ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
    USE_OVS=true
fi

USE_NFT=false
if command -v nft &> /dev/null; then
    USE_NFT=true
fi

if [ "$USE_OVS" = false ] && [ "$USE_NFT" = false ]; then
    echo '{"success": false, "error": "Neither OVS nor nftables available", "action": "MIGRATE"}'
    exit 1
fi

# ============================================================
# REMOVE EXISTING RULES FOR THIS MAC
# ============================================================

TIMESTAMP=$(date -Iseconds)

if [ "$USE_OVS" = true ]; then
    # Delete any existing OpenFlow rules for this MAC (priorities 55000-60000)
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=60000" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$MAC_ADDRESS,priority=60000" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=57000" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$MAC_ADDRESS,priority=57000" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=57001" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=55000" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_dst=$MAC_ADDRESS,priority=55000" 2>/dev/null || true
    ovs-ofctl del-flows "$OVS_BRIDGE" "dl_src=$MAC_ADDRESS,priority=55001" 2>/dev/null || true
fi

# ============================================================
# APPLY NEW POLICY VIA OPENFLOW
# ============================================================

PRIORITY="${POLICY_PRIORITY[$POLICY]:-55000}"

case "$POLICY" in
    "quarantine")
        # Complete isolation - DROP all traffic from/to this MAC
        if [ "$USE_OVS" = true ]; then
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$PRIORITY,dl_src=$MAC_ADDRESS,actions=drop"
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$PRIORITY,dl_dst=$MAC_ADDRESS,actions=drop"
        fi
        if [ "$USE_NFT" = true ] && [ -x "$NFT_MANAGER" ]; then
            "$NFT_MANAGER" block "$MAC_ADDRESS" 2>/dev/null || true
        fi
        ;;

    "internet_only")
        # Allow internet, block LAN access
        # Block traffic to/from LAN subnet but allow to gateway (for internet)
        if [ "$USE_OVS" = true ]; then
            # Block LAN traffic (10.200.0.0/16 is LAN range)
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$PRIORITY,ip,dl_src=$MAC_ADDRESS,nw_dst=10.200.0.0/16,actions=drop"
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$PRIORITY,ip,dl_dst=$MAC_ADDRESS,nw_src=10.200.0.0/16,actions=drop"
            # But allow DHCP, DNS (for internet to work)
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$((PRIORITY + 1)),udp,dl_src=$MAC_ADDRESS,tp_dst=67,actions=normal"
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$((PRIORITY + 1)),udp,dl_src=$MAC_ADDRESS,tp_dst=53,actions=normal"
        fi
        if [ "$USE_NFT" = true ] && [ -x "$NFT_MANAGER" ]; then
            "$NFT_MANAGER" set-policy "$MAC_ADDRESS" "internet_only" 2>/dev/null || true
        fi
        ;;

    "lan_only")
        # Allow LAN, block internet (via nftables - OVS just allows normal flow)
        if [ "$USE_OVS" = true ]; then
            # Allow normal LAN switching, nftables handles internet blocking
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$PRIORITY,ip,dl_src=$MAC_ADDRESS,actions=normal"
        fi
        if [ "$USE_NFT" = true ] && [ -x "$NFT_MANAGER" ]; then
            "$NFT_MANAGER" set-policy "$MAC_ADDRESS" "lan_only" 2>/dev/null || true
        fi
        ;;

    "smart_home")
        # LAN + mDNS/Bonjour (for HomeKit, AirPlay, Chromecast)
        if [ "$USE_OVS" = true ]; then
            # Allow mDNS multicast (essential for discovery)
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$((PRIORITY + 1)),udp,dl_src=$MAC_ADDRESS,tp_dst=5353,actions=normal"
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$((PRIORITY + 1)),udp,dl_dst=$MAC_ADDRESS,tp_src=5353,actions=normal"
            # Allow IPv6 multicast (HomeKit uses this heavily)
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$((PRIORITY + 1)),ipv6,dl_src=$MAC_ADDRESS,actions=normal"
            # Allow LAN traffic
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$PRIORITY,ip,dl_src=$MAC_ADDRESS,nw_dst=10.200.0.0/16,actions=normal"
            ovs-ofctl add-flow "$OVS_BRIDGE" "priority=$PRIORITY,ip,dl_dst=$MAC_ADDRESS,nw_src=10.200.0.0/16,actions=normal"
        fi
        if [ "$USE_NFT" = true ] && [ -x "$NFT_MANAGER" ]; then
            "$NFT_MANAGER" set-policy "$MAC_ADDRESS" "lan_only" 2>/dev/null || true
        fi
        ;;

    "full_access")
        # Remove all restrictions - use normal switching
        # We already removed the rules above, nothing more to add
        if [ "$USE_NFT" = true ] && [ -x "$NFT_MANAGER" ]; then
            "$NFT_MANAGER" set-policy "$MAC_ADDRESS" "full_access" 2>/dev/null || true
        fi
        ;;
esac

# ============================================================
# RECORD TO STATE FILE
# ============================================================

if [ ! -f "$MIGRATE_FILE" ]; then
    echo '{"policy_assignments": []}' > "$MIGRATE_FILE"
fi

if command -v jq &> /dev/null; then
    TEMP_FILE=$(mktemp)
    # Remove any existing entry for this MAC, then add new
    jq --arg mac "$MAC_ADDRESS" --arg policy "$POLICY" \
       --arg reason "$REASON" --arg ts "$TIMESTAMP" --argjson prio "$PRIORITY" \
        '.policy_assignments = [.policy_assignments[] | select(.mac != $mac)] + [{"mac": $mac, "policy": $policy, "priority": $prio, "reason": $reason, "assigned_at": $ts, "source": "ai_agent"}]' \
        "$MIGRATE_FILE" > "$TEMP_FILE" && mv "$TEMP_FILE" "$MIGRATE_FILE"
else
    echo "$TIMESTAMP|$MAC_ADDRESS|$POLICY|$PRIORITY|$REASON|ai_agent" >> "$STATE_DIR/policy-assignments.log"
fi

# ============================================================
# LOG ACTION
# ============================================================

echo "$TIMESTAMP [POLICY] $MAC_ADDRESS -> $POLICY (priority $PRIORITY) - $REASON" >> "$LOG_FILE"

# ============================================================
# OUTPUT RESULT
# ============================================================

cat <<EOF
{
    "success": true,
    "action": "MIGRATE",
    "mac_address": "$MAC_ADDRESS",
    "policy": "$POLICY",
    "priority": $PRIORITY,
    "reason": "$REASON",
    "timestamp": "$TIMESTAMP",
    "method": "$([ "$USE_OVS" = true ] && echo 'openflow' || echo 'nftables')",
    "message": "Device policy set to $POLICY"
}
EOF
