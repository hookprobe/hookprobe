#!/bin/bash
# DHCP Hook Script for dnsmasq
#
# This script is called by dnsmasq on DHCP lease events.
# It registers devices with the Device Lifecycle Manager for identity tracking.
#
# G.N.C. Phase 2: Enhanced device tracking with MAC randomization support
#
# Usage in /etc/dnsmasq.d/fts-dhcp.conf:
#   dhcp-script=/opt/hookprobe/fortress/scripts/dhcp-hook.sh
#
# dnsmasq calls: script <action> <mac> <ip> [hostname]
# Actions: add, del, old (renewal)
#
# Environment variables (set by dnsmasq):
#   DNSMASQ_VENDOR_CLASS    - DHCP option 60 (vendor class identifier)
#   DNSMASQ_REQUESTED_OPTIONS - DHCP option 55 (parameter request list / fingerprint)
#   DNSMASQ_CLIENT_ID       - DHCP option 61 (client identifier - CRITICAL for MAC randomization)
#   DNSMASQ_INTERFACE       - Interface name
#   DNSMASQ_LEASE_LENGTH    - Lease duration in seconds
#   DNSMASQ_SUPPLIED_HOSTNAME - Hostname from Option 12
#   DNSMASQ_DOMAIN          - Domain name
#   DNSMASQ_OLD_HOSTNAME    - Previous hostname (for renewals)
#
# Copyright (c) 2024-2026 HookProbe Security

set -euo pipefail

# Configuration
LOG_FILE="/var/log/fortress/dhcp-hook.log"
FORTRESS_LIB="/opt/hookprobe/fortress/lib"
WEBHOOK_URL="${N8N_DHCP_WEBHOOK:-http://localhost:5678/webhook/dhcp-event}"

# Database configuration (for direct registration)
DATABASE_HOST="${DATABASE_HOST:-172.20.200.10}"
DATABASE_PORT="${DATABASE_PORT:-5432}"
DATABASE_NAME="${DATABASE_NAME:-fortress}"
DATABASE_USER="${DATABASE_USER:-fortress}"
if [[ -z "${DATABASE_PASSWORD:-}" ]]; then
    log "ERROR: DATABASE_PASSWORD not set, cannot register device"
    exit 1
fi

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
HOSTNAME="${4:-${DNSMASQ_SUPPLIED_HOSTNAME:-}}"

if [[ -z "$ACTION" || -z "$MAC" ]]; then
    log "ERROR: Missing required arguments: action=$ACTION mac=$MAC"
    exit 1
fi

# Capture all DHCP options
OPTION55="${DNSMASQ_REQUESTED_OPTIONS:-}"
OPTION61="${DNSMASQ_CLIENT_ID:-}"
VENDOR_CLASS="${DNSMASQ_VENDOR_CLASS:-}"
LEASE_LENGTH="${DNSMASQ_LEASE_LENGTH:-3600}"
INTERFACE="${DNSMASQ_INTERFACE:-FTS}"

log "Event: action=$ACTION mac=$MAC ip=${IP:-none} hostname=${HOSTNAME:-none} opt55=${OPTION55:-none} opt61=${OPTION61:-none}"

# Function to sanitize MAC address (only allow valid MAC characters)
sanitize_mac() {
    local mac="$1"
    # Only allow hex characters and colons, uppercase
    echo "$mac" | tr '[:lower:]' '[:upper:]' | sed 's/[^0-9A-F:]//g'
}

# Sanitize inputs early
MAC=$(sanitize_mac "$MAC")

# Validate MAC format
if [[ ! "$MAC" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ ]]; then
    log "ERROR: Invalid MAC format after sanitization: $MAC"
    exit 1
fi

# Handle different actions
case "$ACTION" in
    del)
        # Device released lease - mark as OFFLINE
        log "Device released: $MAC"

        # Update database directly via psql (fast, no Python overhead)
        # MAC is sanitized and validated above - safe for direct use
        if command -v psql &>/dev/null; then
            PGPASSWORD="$DATABASE_PASSWORD" psql -h "$DATABASE_HOST" -p "$DATABASE_PORT" \
                -U "$DATABASE_USER" -d "$DATABASE_NAME" -c "
                UPDATE devices
                SET status = 'OFFLINE', offline_at = NOW(), ip_address = NULL
                WHERE mac_address = '$MAC'
            " &>/dev/null &
        fi
        exit 0
        ;;
    old)
        # Lease renewal - update last_seen but don't create new device
        log "Lease renewal: $MAC"

        # LEASE_LENGTH is validated as integer
        if [[ ! "$LEASE_LENGTH" =~ ^[0-9]+$ ]]; then
            LEASE_LENGTH=3600
        fi

        if command -v psql &>/dev/null; then
            PGPASSWORD="$DATABASE_PASSWORD" psql -h "$DATABASE_HOST" -p "$DATABASE_PORT" \
                -U "$DATABASE_USER" -d "$DATABASE_NAME" -c "
                UPDATE devices
                SET status = 'ONLINE',
                    last_seen = NOW(),
                    dhcp_lease_expiry = NOW() + INTERVAL '$LEASE_LENGTH seconds',
                    stale_at = NULL,
                    offline_at = NULL
                WHERE mac_address = '$MAC'
            " &>/dev/null &
        fi
        exit 0
        ;;
    add)
        # New lease - full device registration
        log "New device: $MAC"
        ;;
    *)
        log "Unknown action: $ACTION"
        exit 0
        ;;
esac

# ========================================
# DEVICE REGISTRATION
# ========================================

# Function to escape strings for PostgreSQL (prevent SQL injection)
pg_escape() {
    local val="$1"
    if [[ -z "$val" ]]; then
        echo "NULL"
    else
        # Escape single quotes by doubling them
        val="${val//\'/\'\'}"
        # Remove any control characters and null bytes
        val=$(echo -n "$val" | tr -d '\0-\037')
        echo "'${val}'"
    fi
}

# Method 1: Direct PostgreSQL registration (fastest, recommended)
# Uses the register_device() stored function for identity correlation
if command -v psql &>/dev/null && [[ -n "$IP" ]]; then
    log "Registering device via PostgreSQL: $MAC -> $IP"

    # Get manufacturer from OUI prefix
    OUI_PREFIX="${MAC:0:8}"
    MANUFACTURER=""

    # Simple OUI lookup (extend as needed)
    case "$OUI_PREFIX" in
        "DC:A6:32"|"B8:27:EB"|"D8:3A:DD"|"E4:5F:01") MANUFACTURER="Raspberry Pi" ;;
        "00:1C:B3"|"00:03:93"|"A4:5E:60"|"F4:5C:89"|"3C:06:30") MANUFACTURER="Apple" ;;
        "80:8A:BD"|"00:09:18"|"34:23:BA"|"78:BD:BC") MANUFACTURER="Samsung" ;;
        "3C:5A:B4"|"94:EB:2C"|"F4:F5:D8") MANUFACTURER="Google" ;;
        "00:E0:4C"|"52:54:00") MANUFACTURER="Realtek" ;;
        "00:24:E4") MANUFACTURER="Withings" ;;
        *) MANUFACTURER="" ;;
    esac

    # Check for randomized MAC (locally administered bit set)
    if [[ "${MAC:1:1}" =~ [26AaEe] ]]; then
        log "Detected randomized MAC: $MAC"
        [[ -z "$MANUFACTURER" ]] && MANUFACTURER="Randomized MAC"
    fi

    # Build safe SQL with escaped values
    ESCAPED_MAC=$(pg_escape "$MAC")
    ESCAPED_HOSTNAME=$(pg_escape "$HOSTNAME")
    ESCAPED_OPTION55=$(pg_escape "$OPTION55")
    ESCAPED_OPTION61=$(pg_escape "$OPTION61")
    ESCAPED_VENDOR=$(pg_escape "$VENDOR_CLASS")
    ESCAPED_MANUFACTURER=$(pg_escape "$MANUFACTURER")

    # Register device using stored function (handles identity correlation)
    PGPASSWORD="$DATABASE_PASSWORD" psql -h "$DATABASE_HOST" -p "$DATABASE_PORT" \
        -U "$DATABASE_USER" -d "$DATABASE_NAME" -t -A -c "
        SELECT * FROM register_device(
            ${ESCAPED_MAC},
            '${IP}'::inet,
            ${ESCAPED_HOSTNAME},
            ${ESCAPED_OPTION55},
            ${ESCAPED_OPTION61},
            ${ESCAPED_VENDOR},
            NULL,
            ${LEASE_LENGTH},
            ${ESCAPED_MANUFACTURER}
        );
    " 2>/dev/null && log "Device registered successfully" || log "Database registration failed, trying fallback"
fi

# Method 2: Python device_lifecycle module (full features with callbacks)
# SECURITY: Pass values via environment variables, NOT inline string interpolation
# (CWE-78 fix: attacker-controlled DHCP options like hostname/vendor_class could
#  inject arbitrary Python code if interpolated into python3 -c strings)
if command -v python3 &>/dev/null; then
    export PYTHONPATH="${FORTRESS_LIB}:${PYTHONPATH:-}"
    export DATABASE_HOST DATABASE_PORT DATABASE_NAME DATABASE_USER DATABASE_PASSWORD
    export DHCP_MAC="$MAC" DHCP_IP="$IP" DHCP_HOSTNAME="$HOSTNAME"
    export DHCP_OPTION55="$OPTION55" DHCP_OPTION61="$OPTION61"
    export DHCP_VENDOR_CLASS="$VENDOR_CLASS" DHCP_LEASE_LENGTH="$LEASE_LENGTH"

    if python3 -c "import device_lifecycle" 2>/dev/null; then
        log "Using Python Device Lifecycle Manager"

        python3 -c "
import os
from device_lifecycle import get_lifecycle_manager

manager = get_lifecycle_manager()
result = manager.register_device(
    mac=os.environ['DHCP_MAC'],
    ip=os.environ['DHCP_IP'],
    hostname=os.environ.get('DHCP_HOSTNAME') or None,
    dhcp_option55=os.environ.get('DHCP_OPTION55') or None,
    dhcp_option61=os.environ.get('DHCP_OPTION61') or None,
    dhcp_vendor_class=os.environ.get('DHCP_VENDOR_CLASS') or None,
    lease_duration=int(os.environ.get('DHCP_LEASE_LENGTH', '3600')),
)
print(f'Registered: {result.canonical_name} (new={result.is_new})')
" 2>/dev/null &

        exit 0
    fi
fi

# Method 3: Fallback to curl webhook (n8n workflows)
log "Using webhook fallback"

# Build JSON safely using jq to prevent injection from DHCP fields
if command -v jq &>/dev/null && command -v curl &>/dev/null; then
    JSON_PAYLOAD=$(jq -n \
        --arg action "$ACTION" \
        --arg mac "$MAC" \
        --arg ip "$IP" \
        --arg hostname "${HOSTNAME:-}" \
        --arg vendor_class "${VENDOR_CLASS:-}" \
        --arg option55 "${OPTION55:-}" \
        --arg option61 "${OPTION61:-}" \
        --arg interface "${INTERFACE}" \
        --argjson lease_length "${LEASE_LENGTH}" \
        --arg timestamp "$(date -Iseconds)" \
        '{
            event: "new_device",
            source: "dhcp_hook",
            data: {
                action: $action,
                mac: $mac,
                ip: $ip,
                hostname: (if $hostname == "" then null else $hostname end),
                vendor_class: (if $vendor_class == "" then null else $vendor_class end),
                option55: (if $option55 == "" then null else $option55 end),
                option61: (if $option61 == "" then null else $option61 end),
                interface: $interface,
                lease_length: $lease_length,
                timestamp: $timestamp
            },
            trigger_probe: true
        }')

    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$JSON_PAYLOAD" \
        --connect-timeout 5 \
        "$WEBHOOK_URL" &>/dev/null &

    log "Webhook sent for $MAC"
elif command -v curl &>/dev/null; then
    log "WARNING: jq not available, skipping webhook (unsafe to build JSON without it)"
else
    log "WARNING: curl not available, cannot send webhook"
fi

exit 0
