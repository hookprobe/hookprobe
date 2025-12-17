#!/bin/bash
#
# dhcp-event.sh - DHCP lease event handler for Fortress
# Called by dnsmasq on DHCP events: add, old, del
#
# Usage: dhcp-event.sh <action> <mac> <ip> [hostname] [vendor-class]
#
# This script integrates with the device manager to track devices
# and apply automatic VLAN/policy assignments based on OUI.

set -e

ACTION="${1:-}"
MAC="${2:-}"
IP="${3:-}"
HOSTNAME="${4:-}"
VENDOR_CLASS="${DNSMASQ_VENDOR_CLASS:-}"

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
    echo "$NOW $ACTION $MAC $IP $HOSTNAME $VENDOR_CLASS" >> "$LEASE_LOG" 2>/dev/null &
}

# Update device database (async to prevent DHCP slowdown)
update_device_db() {
    # Run in background to not block DHCP response
    (
        # Python script for database update
        python3 << 'PYTHON_SCRIPT' "$MAC" "$IP" "$HOSTNAME" "$VENDOR_CLASS" "$ACTION" 2>/dev/null
import sys
import json
import os
from datetime import datetime
from pathlib import Path

mac = sys.argv[1] if len(sys.argv) > 1 else ""
ip = sys.argv[2] if len(sys.argv) > 2 else ""
hostname = sys.argv[3] if len(sys.argv) > 3 else ""
vendor = sys.argv[4] if len(sys.argv) > 4 else ""
action = sys.argv[5] if len(sys.argv) > 5 else "add"

if not mac:
    sys.exit(0)

# Try to use device_manager
try:
    sys.path.insert(0, '/opt/hookprobe/fortress/lib')
    from device_manager import get_device_manager
    dm = get_device_manager()
    if action in ['add', 'old']:
        dm.db.upsert_device(
            mac_address=mac.upper(),
            ip_address=ip,
            hostname=hostname or None
        )
    elif action == 'del':
        pass  # Don't delete, just mark inactive
except Exception:
    pass

# Also update local JSON file for fast dashboard access
devices_file = Path('/opt/hookprobe/fortress/data/devices.json')
try:
    devices = {}
    if devices_file.exists():
        with open(devices_file, 'r') as f:
            devices = json.load(f)

    if action in ['add', 'old']:
        if mac.upper() not in devices:
            devices[mac.upper()] = {}
        devices[mac.upper()].update({
            'mac_address': mac.upper(),
            'ip_address': ip,
            'hostname': hostname,
            'vendor_class': vendor,
            'last_seen': datetime.now().isoformat(),
            'is_active': True
        })
        if action == 'add':
            devices[mac.upper()]['first_seen'] = datetime.now().isoformat()
    elif action == 'del':
        if mac.upper() in devices:
            devices[mac.upper()]['is_active'] = False
            devices[mac.upper()]['last_seen'] = datetime.now().isoformat()

    with open(devices_file, 'w') as f:
        json.dump(devices, f)
except Exception:
    pass

# Update stats
stats_file = Path('/opt/hookprobe/fortress/data/dhcp_stats.json')
try:
    stats = {'total_leases': 0, 'add_events': 0, 'del_events': 0}
    if stats_file.exists():
        with open(stats_file, 'r') as f:
            stats = json.load(f)

    if action == 'add':
        stats['add_events'] = stats.get('add_events', 0) + 1
        stats['total_leases'] = stats.get('total_leases', 0) + 1
    elif action == 'del':
        stats['del_events'] = stats.get('del_events', 0) + 1
        stats['total_leases'] = max(0, stats.get('total_leases', 1) - 1)

    stats['last_event'] = datetime.now().isoformat()

    with open(stats_file, 'w') as f:
        json.dump(stats, f)
except Exception:
    pass
PYTHON_SCRIPT
    ) &
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
    add|old|del)
        log_event
        update_device_db
        notify_ui
        ;;
    init)
        # dnsmasq startup - clear stale data
        echo "DHCP event handler initialized at $NOW" >> "$LEASE_LOG"
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
