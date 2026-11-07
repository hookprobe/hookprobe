#!/bin/bash
# Comprehensive SDN Auto Pilot Diagnostic & Fix Script
# Run with: sudo bash diagnose-and-fix.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=============================================="
echo "SDN Auto Pilot - Comprehensive Diagnostic"
echo "=============================================="
echo ""

# 1. Check file versions
echo -e "${BLUE}1. Checking file versions...${NC}"
echo "-------------------------------------------"

PROD_DIR="/opt/hookprobe/fortress/lib"
# Dynamically detect git repo root from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
GIT_DIR="${GIT_ROOT}/products/fortress/lib"

for file in fingerbank.py sdn_autopilot.py mdns_resolver.py; do
    if [[ -f "$PROD_DIR/$file" ]] && [[ -f "$GIT_DIR/$file" ]]; then
        prod_hash=$(md5sum "$PROD_DIR/$file" 2>/dev/null | awk '{print $1}')
        git_hash=$(md5sum "$GIT_DIR/$file" 2>/dev/null | awk '{print $1}')
        if [[ "$prod_hash" == "$git_hash" ]]; then
            echo -e "  ${GREEN}✓${NC} $file: SYNCED"
        else
            echo -e "  ${RED}✗${NC} $file: OUT OF SYNC"
            echo "    Fixing: cp $GIT_DIR/$file $PROD_DIR/$file"
            cp "$GIT_DIR/$file" "$PROD_DIR/$file"
        fi
    else
        echo -e "  ${YELLOW}?${NC} $file: Missing in prod or git"
        if [[ -f "$GIT_DIR/$file" ]]; then
            cp "$GIT_DIR/$file" "$PROD_DIR/$file"
            echo "    Copied from git"
        fi
    fi
done

echo ""

# 2. Check database schema
echo -e "${BLUE}2. Checking database schema...${NC}"
echo "-------------------------------------------"

DB_PATH="/var/lib/hookprobe/autopilot.db"
if [[ -f "$DB_PATH" ]]; then
    echo "  Database: $DB_PATH"

    # Check for device_type column
    if sqlite3 "$DB_PATH" ".schema device_identity" | grep -q "device_type"; then
        echo -e "  ${GREEN}✓${NC} device_type column exists"
    else
        echo -e "  ${RED}✗${NC} device_type column MISSING - adding..."
        sqlite3 "$DB_PATH" "ALTER TABLE device_identity ADD COLUMN device_type TEXT;"
        echo -e "  ${GREEN}✓${NC} device_type column added"
    fi

    # Show current schema
    echo "  Current columns:"
    sqlite3 "$DB_PATH" "PRAGMA table_info(device_identity);" | while read line; do
        col=$(echo "$line" | cut -d'|' -f2)
        echo "    - $col"
    done
else
    echo -e "  ${RED}✗${NC} Database not found at $DB_PATH"
fi

echo ""

# 3. Check mDNS/Avahi
echo -e "${BLUE}3. Checking mDNS/Avahi...${NC}"
echo "-------------------------------------------"

if systemctl is-active --quiet avahi-daemon; then
    echo -e "  ${GREEN}✓${NC} avahi-daemon is running"
else
    echo -e "  ${RED}✗${NC} avahi-daemon not running"
    echo "    Starting avahi-daemon..."
    systemctl start avahi-daemon
fi

# Test mDNS resolution for known IPs
echo "  Testing mDNS resolution..."
for ip in 10.200.0.4 10.200.0.7 10.200.0.9 10.200.0.10 10.200.0.13; do
    result=$(timeout 2 avahi-resolve -a "$ip" 2>/dev/null || echo "")
    if [[ -n "$result" ]]; then
        echo -e "    ${GREEN}✓${NC} $ip -> $(echo $result | awk '{print $2}')"
    else
        echo -e "    ${YELLOW}?${NC} $ip -> no mDNS response"
    fi
done

echo ""

# 4. Check OUI lookups
echo -e "${BLUE}4. Testing OUI lookups...${NC}"
echo "-------------------------------------------"

python3 << 'PYEOF'
import sys
sys.path.insert(0, '/opt/hookprobe/fortress/lib')

test_macs = [
    ("9C:B1:50:E2:0B:49", "Dell (not Microsoft!)"),
    ("80:8A:BD:43:E2:BA", "Samsung"),
    ("40:ED:CF:82:62:6B", "Apple HomePod"),
    ("DC:A6:32:A4:B6:88", "Raspberry Pi"),
    ("00:24:E4:FE:5A:0A", "Withings"),
    ("66:E1:5E:04:CE:05", "Apple (randomized)"),
]

try:
    from fingerbank import Fingerbank, OUI_DATABASE, SPECIFIC_OUI_DEVICES
    fb = Fingerbank()

    for mac, expected in test_macs:
        oui = mac[:8].upper()
        vendor = OUI_DATABASE.get(oui, "NOT IN DATABASE")
        specific = SPECIFIC_OUI_DEVICES.get(oui, {})

        status = "✓" if expected.split()[0] in vendor or expected.split()[0] in str(specific) else "✗"
        print(f"  {status} {oui} -> vendor: {vendor}, specific: {specific.get('name', 'N/A')}")

        if vendor == "NOT IN DATABASE":
            print(f"    MISSING: Need to add {oui} for {expected}")

except Exception as e:
    print(f"  ERROR: {e}")
    import traceback
    traceback.print_exc()
PYEOF

echo ""

# 5. Test full identification pipeline
echo -e "${BLUE}5. Testing full identification pipeline...${NC}"
echo "-------------------------------------------"

python3 << 'PYEOF'
import sys
sys.path.insert(0, '/opt/hookprobe/fortress/lib')

test_devices = [
    # (mac, hostname, dhcp_fingerprint, expected_name)
    ("9C:B1:50:E2:0B:49", "E1633173", None, "Dell"),
    ("80:8A:BD:43:E2:BA", "Samsung", None, "Samsung TV"),
    ("40:ED:CF:82:62:6B", "hookprobe", None, "HomePod"),
    ("DC:A6:32:A4:B6:88", "hookprobe", None, "Raspberry Pi"),
    ("00:24:E4:FE:5A:0A", None, None, "Withings"),
    ("66:E1:5E:04:CE:05", "MacBookPro", "1,121,3,6,15,119,252,95,44,46", "MacBook"),
    ("46:32:0C:94:20:BB", None, "1,3,6,15,119,252,78,79", "Apple Watch"),
    ("C2:01:B1:72:4D:DC", "iPhone", "1,121,3,6,15,119,252", "iPhone"),
]

try:
    from fingerbank import Fingerbank
    fb = Fingerbank()

    print("  MAC              | Hostname      | Name               | Vendor      | Conf | Policy")
    print("  " + "-" * 85)

    for mac, hostname, fp, expected in test_devices:
        result = fb.identify(mac, fp, hostname)
        match = "✓" if expected.lower() in result.name.lower() else "✗"
        print(f"  {match} {mac} | {(hostname or 'N/A'):12} | {result.name:18} | {result.vendor:11} | {result.confidence:.2f} | {result.policy}")

except Exception as e:
    print(f"  ERROR: {e}")
    import traceback
    traceback.print_exc()
PYEOF

echo ""

# 6. Check what's stored in database vs what fingerbank returns
echo -e "${BLUE}6. Checking database vs fingerbank results...${NC}"
echo "-------------------------------------------"

python3 << 'PYEOF'
import sys
import sqlite3
sys.path.insert(0, '/opt/hookprobe/fortress/lib')

try:
    from fingerbank import Fingerbank
    fb = Fingerbank()

    conn = sqlite3.connect('/var/lib/hookprobe/autopilot.db')
    conn.row_factory = sqlite3.Row

    devices = conn.execute('''
        SELECT mac, ip, hostname, vendor, device_type, confidence, dhcp_fingerprint
        FROM device_identity ORDER BY last_seen DESC LIMIT 20
    ''').fetchall()

    print(f"  Found {len(devices)} devices in database")
    print("")
    print("  MAC              | DB Vendor   | DB device_type      | FB Name            | Match?")
    print("  " + "-" * 90)

    for d in devices:
        mac = d['mac']
        hostname = d['hostname'] if d['hostname'] and d['hostname'] != '(none)' else None
        fp = d['dhcp_fingerprint']

        fb_result = fb.identify(mac, fp, hostname)

        db_type = d['device_type'] or "NULL"
        match = "✓" if fb_result.name in db_type or db_type in fb_result.name else "✗"

        print(f"  {match} {mac} | {d['vendor']:11} | {db_type:19} | {fb_result.name:18} | {match}")

    conn.close()

except Exception as e:
    print(f"  ERROR: {e}")
    import traceback
    traceback.print_exc()
PYEOF

echo ""
echo -e "${BLUE}7. Recommendations${NC}"
echo "-------------------------------------------"
echo "  Based on the diagnostics above:"
echo ""
echo "  1. If OUI lookups are wrong, we need to fix the OUI database"
echo "  2. If device_type is NULL, devices need to be re-identified"
echo "  3. If mDNS isn't resolving, check firewall for UDP 5353"
echo ""
echo "  To force re-identification of all devices:"
echo "    sudo systemctl restart fortress"
echo "    sudo systemctl restart dnsmasq"
echo ""
echo "=============================================="
echo "Diagnostic complete"
echo "=============================================="
