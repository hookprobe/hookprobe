#!/bin/bash
# DHCP Hook Script for dnsmasq
#
# This script is called by dnsmasq on DHCP lease events.
# It triggers the AI Autopilot DHCP Sentinel for new device detection.
#
# Usage in /etc/dnsmasq.d/fts-dhcp.conf:
#   dhcp-script=/opt/hookprobe/fortress/scripts/dhcp-hook.sh
#
# dnsmasq calls: script <action> <mac> <ip> [hostname]
# Environment variables:
#   DNSMASQ_VENDOR_CLASS    - DHCP option 60 (vendor class)
#   DNSMASQ_REQUESTED_OPTIONS - DHCP option 55 (fingerprint)
#   DNSMASQ_CLIENT_ID       - DHCP option 61 (client ID)
#   DNSMASQ_INTERFACE       - Interface name
#   DNSMASQ_LEASE_LENGTH    - Lease duration
#
# Copyright (c) 2024-2026 HookProbe Security

set -euo pipefail

# Configuration
LOG_FILE="/var/log/fortress/dhcp-hook.log"
PYTHON_MODULE="autopilot.dhcp_sentinel"
FORTRESS_LIB="/opt/hookprobe/fortress/lib"
WEBHOOK_URL="${N8N_DHCP_WEBHOOK:-http://localhost:5678/webhook/dhcp-event}"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_FILE"
}

# Parse arguments
ACTION="${1:-}"
MAC="${2:-}"
IP="${3:-}"
HOSTNAME="${4:-}"

if [[ -z "$ACTION" || -z "$MAC" || -z "$IP" ]]; then
    log "ERROR: Missing required arguments: action=$ACTION mac=$MAC ip=$IP"
    exit 1
fi

# Normalize MAC to uppercase
MAC=$(echo "$MAC" | tr '[:lower:]' '[:upper:]')

log "Event: action=$ACTION mac=$MAC ip=$IP hostname=${HOSTNAME:-none}"

# Only process 'add' events for new device detection
if [[ "$ACTION" != "add" ]]; then
    log "Skipping non-add event: $ACTION"
    exit 0
fi

# Method 1: Try Python module (full features)
if command -v python3 &>/dev/null; then
    export PYTHONPATH="${FORTRESS_LIB}:${PYTHONPATH:-}"

    if python3 -c "import $PYTHON_MODULE" 2>/dev/null; then
        log "Using Python DHCP Sentinel"

        # Build arguments
        ARGS=("$ACTION" "$MAC" "$IP")
        [[ -n "$HOSTNAME" ]] && ARGS+=("$HOSTNAME")

        # Run sentinel (async, don't block dnsmasq)
        python3 -m "$PYTHON_MODULE" "${ARGS[@]}" &

        exit 0
    fi
fi

# Method 2: Fallback to curl webhook
log "Using webhook fallback"

# Build JSON payload
JSON_PAYLOAD=$(cat <<EOF
{
    "event": "new_device",
    "source": "dhcp_hook",
    "data": {
        "action": "$ACTION",
        "mac": "$MAC",
        "ip": "$IP",
        "hostname": "${HOSTNAME:-null}",
        "vendor_class": "${DNSMASQ_VENDOR_CLASS:-null}",
        "option55": "${DNSMASQ_REQUESTED_OPTIONS:-null}",
        "client_id": "${DNSMASQ_CLIENT_ID:-null}",
        "interface": "${DNSMASQ_INTERFACE:-vlan100}",
        "lease_length": "${DNSMASQ_LEASE_LENGTH:-3600}",
        "timestamp": "$(date -Iseconds)"
    },
    "trigger_probe": true
}
EOF
)

# Send webhook (async, don't block)
if command -v curl &>/dev/null; then
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$JSON_PAYLOAD" \
        --connect-timeout 5 \
        "$WEBHOOK_URL" &>/dev/null &

    log "Webhook sent for $MAC"
else
    log "WARNING: curl not available, cannot send webhook"
fi

exit 0
