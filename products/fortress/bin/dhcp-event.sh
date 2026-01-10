#!/bin/bash
#
# dhcp-event.sh - DHCP lease event handler for Fortress
# Called by dnsmasq on DHCP events: add, old, del
#
# Usage: dhcp-event.sh <action> <mac> <ip> [hostname]
#
# Environment variables from dnsmasq:
#   DNSMASQ_REQUESTED_OPTIONS - DHCP Option 55 fingerprint (device DNA)
#   DNSMASQ_VENDOR_CLASS - Vendor class identifier
#   DNSMASQ_CLIENT_ID - Client identifier (CRITICAL for MAC randomization)
#   DNSMASQ_INTERFACE - Network interface
#   DNSMASQ_LEASE_LENGTH - Lease duration in seconds
#
# G.N.C. Phase 2: Enhanced device tracking with MAC randomization support
#
# This script integrates with:
# - PostgreSQL device_lifecycle (primary - real-time status tracking)
# - SDN Auto Pilot for device classification
# - OpenFlow micro-segmentation policy enforcement

set -e

ACTION="${1:-}"
MAC="${2:-}"
IP="${3:-}"
HOSTNAME="${4:-${DNSMASQ_SUPPLIED_HOSTNAME:-}}"
# CRITICAL: DHCP Option 55 fingerprint - the device "DNA"
DHCP_FINGERPRINT="${DNSMASQ_REQUESTED_OPTIONS:-}"
DHCP_OPTION61="${DNSMASQ_CLIENT_ID:-}"  # Client identifier - stable across MAC randomization
VENDOR_CLASS="${DNSMASQ_VENDOR_CLASS:-}"
INTERFACE="${DNSMASQ_INTERFACE:-FTS}"
LEASE_LENGTH="${DNSMASQ_LEASE_LENGTH:-3600}"

# Database configuration (for PostgreSQL device lifecycle)
DATABASE_HOST="${DATABASE_HOST:-172.20.200.10}"
DATABASE_PORT="${DATABASE_PORT:-5432}"
DATABASE_NAME="${DATABASE_NAME:-fortress}"
DATABASE_USER="${DATABASE_USER:-fortress}"
DATABASE_PASSWORD="${DATABASE_PASSWORD:-fortress_db_secret}"

# Paths
DATA_DIR="/opt/hookprobe/fortress/data"
LEASE_LOG="$DATA_DIR/dhcp_events.log"
DEVICE_FILE="$DATA_DIR/devices.json"
STATS_FILE="$DATA_DIR/dhcp_stats.json"

# Ensure data directory exists
mkdir -p "$DATA_DIR"

# Timestamp
NOW=$(date '+%Y-%m-%d %H:%M:%S')

# ============================================================
# INPUT VALIDATION & SANITIZATION (Security)
# ============================================================

# Function to sanitize MAC address (only allow valid MAC characters)
sanitize_mac() {
    local mac="$1"
    # Only allow hex characters and colons, uppercase
    echo "$mac" | tr '[:lower:]' '[:upper:]' | sed 's/[^0-9A-F:]//g'
}

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

# Sanitize MAC address
MAC=$(sanitize_mac "$MAC")

# Validate MAC format
if [[ ! "$MAC" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ ]]; then
    echo "$NOW ERROR: Invalid MAC format: $MAC" >> "$LEASE_LOG"
    exit 1
fi

# Validate LEASE_LENGTH is numeric
if [[ ! "$LEASE_LENGTH" =~ ^[0-9]+$ ]]; then
    LEASE_LENGTH=3600
fi

# ============================================================
# POSTGRESQL DEVICE LIFECYCLE (G.N.C. Phase 2 - Primary)
# ============================================================
# Direct PostgreSQL registration for real-time device status tracking
# This is FASTER than Python and provides immediate database updates

register_device_postgres() {
    # Skip if psql not available
    command -v psql &>/dev/null || return 1

    # Get manufacturer from OUI prefix
    local OUI_PREFIX="${MAC:0:8}"
    local MANUFACTURER=""

    case "$OUI_PREFIX" in
        "DC:A6:32"|"B8:27:EB"|"D8:3A:DD"|"E4:5F:01") MANUFACTURER="Raspberry Pi" ;;
        "00:1C:B3"|"00:03:93"|"A4:5E:60"|"F4:5C:89"|"3C:06:30") MANUFACTURER="Apple" ;;
        "80:8A:BD"|"00:09:18"|"34:23:BA"|"78:BD:BC") MANUFACTURER="Samsung" ;;
        "3C:5A:B4"|"94:EB:2C"|"F4:F5:D8") MANUFACTURER="Google" ;;
        "00:E0:4C"|"52:54:00") MANUFACTURER="Realtek" ;;
        "00:24:E4") MANUFACTURER="Withings" ;;
    esac

    # Check for randomized MAC (locally administered bit set)
    if [[ "${MAC:1:1}" =~ [26AaEe] ]]; then
        [[ -z "$MANUFACTURER" ]] && MANUFACTURER="Randomized MAC"
    fi

    # Build escaped values
    local ESC_MAC=$(pg_escape "$MAC")
    local ESC_HOSTNAME=$(pg_escape "$HOSTNAME")
    local ESC_OPT55=$(pg_escape "$DHCP_FINGERPRINT")
    local ESC_OPT61=$(pg_escape "$DHCP_OPTION61")
    local ESC_VENDOR=$(pg_escape "$VENDOR_CLASS")
    local ESC_MANUFACTURER=$(pg_escape "$MANUFACTURER")

    # Call register_device stored function
    PGPASSWORD="$DATABASE_PASSWORD" psql -h "$DATABASE_HOST" -p "$DATABASE_PORT" \
        -U "$DATABASE_USER" -d "$DATABASE_NAME" -t -A -q -c "
        SELECT * FROM register_device(
            ${ESC_MAC},
            '${IP}'::inet,
            ${ESC_HOSTNAME},
            ${ESC_OPT55},
            ${ESC_OPT61},
            ${ESC_VENDOR},
            NULL,
            ${LEASE_LENGTH},
            ${ESC_MANUFACTURER}
        );
    " 2>/dev/null
}

release_device_postgres() {
    command -v psql &>/dev/null || return 1

    PGPASSWORD="$DATABASE_PASSWORD" psql -h "$DATABASE_HOST" -p "$DATABASE_PORT" \
        -U "$DATABASE_USER" -d "$DATABASE_NAME" -q -c "
        UPDATE devices
        SET status = 'OFFLINE', offline_at = NOW(), ip_address = NULL
        WHERE mac_address = '$MAC'
    " 2>/dev/null
}

renew_device_postgres() {
    command -v psql &>/dev/null || return 1

    PGPASSWORD="$DATABASE_PASSWORD" psql -h "$DATABASE_HOST" -p "$DATABASE_PORT" \
        -U "$DATABASE_USER" -d "$DATABASE_NAME" -q -c "
        UPDATE devices
        SET status = 'ONLINE',
            last_seen = NOW(),
            dhcp_lease_expiry = NOW() + INTERVAL '$LEASE_LENGTH seconds',
            stale_at = NULL,
            offline_at = NULL
        WHERE mac_address = '$MAC'
    " 2>/dev/null
}

# Log event (fast, non-blocking)
log_event() {
    echo "$NOW $ACTION $MAC $IP $HOSTNAME fp=$DHCP_FINGERPRINT vc=$VENDOR_CLASS if=$INTERFACE" >> "$LEASE_LOG" 2>/dev/null &
}

# Process device through SDN Auto Pilot (async to prevent DHCP slowdown)
process_device() {
    # Run in background to not block DHCP response
    (
        # Python script for SDN Auto Pilot classification and OpenFlow rules
        # NOTE: Using '-' tells python to read script from stdin, args come after
        # Args: MAC IP HOSTNAME FINGERPRINT ACTION VENDOR_CLASS
        python3 - "$MAC" "$IP" "$HOSTNAME" "$DHCP_FINGERPRINT" "$ACTION" "$VENDOR_CLASS" <<'PYTHON_SCRIPT'
import sys
import os
import json
import logging
from datetime import datetime
from pathlib import Path

# Ensure data directory exists and is writable
data_dir = Path('/opt/hookprobe/fortress/data')
data_dir.mkdir(parents=True, exist_ok=True)

# Setup logging - with fallback to stderr if file not writable
log_file = data_dir / 'autopilot.log'
try:
    logging.basicConfig(
        filename=str(log_file),
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
except Exception:
    # Fallback to stderr (captured in debug log)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
logger = logging.getLogger('dhcp-event')

# Parse arguments
mac = sys.argv[1].upper() if len(sys.argv) > 1 else ""
ip = sys.argv[2] if len(sys.argv) > 2 else ""
hostname = sys.argv[3] if len(sys.argv) > 3 else ""
dhcp_fingerprint = sys.argv[4] if len(sys.argv) > 4 else ""
action = sys.argv[5] if len(sys.argv) > 5 else "add"
vendor_class = sys.argv[6] if len(sys.argv) > 6 else ""  # DHCP Option 60

if not mac:
    sys.exit(0)

# =========================================================================
# DEVICE IDENTITY LAYER - MAC Randomization Tracking
# =========================================================================
# This links MAC addresses to persistent device identities using DHCP Option 55
# fingerprint (device DNA) and mDNS names. Prevents "iPhone 3, 4, 5..." syndrome.
try:
    sys.path.insert(0, '/opt/hookprobe/fortress/lib')
    from device_identity import DeviceIdentityTracker

    tracker = DeviceIdentityTracker()
    identity = tracker.find_or_create_identity(
        mac=mac,
        dhcp_option55=dhcp_fingerprint or None,
        hostname=hostname or None,
        dhcp_vendor_class=vendor_class or None,
    )
    if identity:
        logger.info(f"Device identity: {identity.identity_id} -> {identity.display_name}")
except ImportError:
    logger.debug("Device Identity Layer not available")
except Exception as e:
    logger.debug(f"Device identity error: {e}")

# =========================================================================
# SDN AUTO PILOT INTEGRATION
# =========================================================================
try:
    from sdn_autopilot import SDNAutoPilot

    # Use HOST database path (not container path /app/db/autopilot.db)
    HOST_DB_PATH = '/var/lib/hookprobe/autopilot.db'
    autopilot = SDNAutoPilot(HOST_DB_PATH)

    if action in ['add', 'old']:
        # Full device classification + OpenFlow rule application
        result = autopilot.sync_device(
            mac=mac,
            ip=ip,
            hostname=hostname or None,
            dhcp_fingerprint=dhcp_fingerprint or None,
            vendor_class=vendor_class or None,  # Pass DHCP Option 60
            apply_rules=True  # Auto-apply OpenFlow rules
        )
        # Log with vendor_class for debugging
        vc_info = f", vc={vendor_class}" if vendor_class else ""
        logger.info(f"DHCP {action}: {mac} -> {result.policy} "
                   f"(confidence={result.confidence:.2f}, fp={dhcp_fingerprint}{vc_info})")

    elif action == 'del':
        # Mark device inactive but keep policy (will reapply on reconnect)
        logger.info(f"DHCP del: {mac} lease released")

except Exception as e:
    logger.error(f"SDN Auto Pilot error: {e}")

# =========================================================================
# UPDATE LOCAL JSON FILE (for fast dashboard access)
# =========================================================================
devices_file = Path('/opt/hookprobe/fortress/data/devices.json')
try:
    devices = {}
    if devices_file.exists():
        with open(devices_file, 'r') as f:
            devices = json.load(f)

    now = datetime.now().isoformat()

    if action in ['add', 'old']:
        if mac not in devices:
            devices[mac] = {'first_seen': now}
        devices[mac].update({
            'mac_address': mac,
            'ip_address': ip,
            'hostname': hostname,
            'dhcp_fingerprint': dhcp_fingerprint,
            'last_seen': now,
            'is_active': True
        })
    elif action == 'del':
        if mac in devices:
            devices[mac]['is_active'] = False
            devices[mac]['last_seen'] = now

    with open(devices_file, 'w') as f:
        json.dump(devices, f, indent=2)
except Exception as e:
    logger.debug(f"JSON update error: {e}")

# =========================================================================
# UPDATE STATS
# =========================================================================
stats_file = Path('/opt/hookprobe/fortress/data/dhcp_stats.json')
try:
    stats = {'total_leases': 0, 'add_events': 0, 'del_events': 0, 'old_events': 0}
    if stats_file.exists():
        with open(stats_file, 'r') as f:
            stats = json.load(f)

    if action == 'add':
        stats['add_events'] = stats.get('add_events', 0) + 1
        stats['total_leases'] = stats.get('total_leases', 0) + 1
    elif action == 'old':
        stats['old_events'] = stats.get('old_events', 0) + 1
    elif action == 'del':
        stats['del_events'] = stats.get('del_events', 0) + 1
        stats['total_leases'] = max(0, stats.get('total_leases', 1) - 1)

    stats['last_event'] = now
    stats['last_mac'] = mac

    with open(stats_file, 'w') as f:
        json.dump(stats, f)
except Exception:
    pass
PYTHON_SCRIPT
    ) >> /opt/hookprobe/fortress/data/autopilot_debug.log 2>&1 &
}

# Notify web UI of new device (optional websocket)
notify_ui() {
    if [ "$ACTION" = "add" ]; then
        # Send notification to any listening UI
        curl -s -X POST "http://localhost:5000/api/devices/notify" \
            -H "Content-Type: application/json" \
            -d "{\"mac\": \"$MAC\", \"ip\": \"$IP\", \"hostname\": \"$HOSTNAME\"}" \
            >/dev/null 2>&1 &
    fi
}

# Main execution
case "$ACTION" in
    add)
        # New lease - full classification pipeline + PostgreSQL registration
        log_event
        # PostgreSQL device lifecycle (primary - real-time status)
        register_device_postgres &
        # Python SDN Auto Pilot (secondary - classification)
        process_device
        notify_ui
        ;;
    old)
        # Renewed lease - update status + refresh classification
        log_event
        # PostgreSQL device lifecycle (primary - renew status)
        renew_device_postgres &
        # Python SDN Auto Pilot (secondary - refresh)
        process_device
        ;;
    del)
        # Lease released - mark offline
        log_event
        # PostgreSQL device lifecycle (primary - mark offline)
        release_device_postgres &
        # Python fallback
        process_device
        ;;
    init)
        # dnsmasq startup - initialize
        echo "DHCP event handler initialized at $NOW (G.N.C. Phase 2 + SDN Auto Pilot)" >> "$LEASE_LOG"
        ;;
    tftp)
        # TFTP event - ignore
        ;;
    *)
        # Unknown action
        echo "Unknown DHCP action: $ACTION" >> "$LEASE_LOG"
        ;;
esac

# Exit immediately - don't block dnsmasq
exit 0
