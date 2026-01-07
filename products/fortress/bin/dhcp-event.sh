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
#   DNSMASQ_CLIENT_ID - Client identifier
#   DNSMASQ_INTERFACE - Network interface
#
# This script integrates with SDN Auto Pilot for device classification
# and OpenFlow micro-segmentation policy enforcement.

set -e

ACTION="${1:-}"
MAC="${2:-}"
IP="${3:-}"
HOSTNAME="${4:-}"
# CRITICAL: DHCP Option 55 fingerprint - the device "DNA"
DHCP_FINGERPRINT="${DNSMASQ_REQUESTED_OPTIONS:-}"
VENDOR_CLASS="${DNSMASQ_VENDOR_CLASS:-}"
INTERFACE="${DNSMASQ_INTERFACE:-}"

# Paths
DATA_DIR="/opt/hookprobe/fortress/data"
LEASE_LOG="$DATA_DIR/dhcp_events.log"
DEVICE_FILE="$DATA_DIR/devices.json"
STATS_FILE="$DATA_DIR/dhcp_stats.json"

# Ensure data directory exists
mkdir -p "$DATA_DIR"

# Timestamp
NOW=$(date '+%Y-%m-%d %H:%M:%S')

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
    add|old)
        # New or renewed lease - full classification pipeline
        log_event
        process_device
        notify_ui
        ;;
    del)
        # Lease released - log only
        log_event
        process_device
        ;;
    init)
        # dnsmasq startup - initialize
        echo "DHCP event handler initialized at $NOW (SDN Auto Pilot enabled)" >> "$LEASE_LOG"
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
