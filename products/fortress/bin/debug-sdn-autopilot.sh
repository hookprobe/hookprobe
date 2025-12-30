#!/bin/bash
#
# Debug script for SDN Auto Pilot
# Checks the entire flow and identifies gaps
#

echo "========================================"
echo "SDN Auto Pilot Debug Report"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}✓ PASS${NC}: $1"; }
fail() { echo -e "${RED}✗ FAIL${NC}: $1"; }
warn() { echo -e "${YELLOW}⚠ WARN${NC}: $1"; }

echo "1. Checking file locations..."
echo "-------------------------------------------"

# Check if /opt/hookprobe exists
if [ -d "/opt/hookprobe/fortress/lib" ]; then
    pass "/opt/hookprobe/fortress/lib exists"
else
    fail "/opt/hookprobe/fortress/lib missing"
fi

# Check fingerbank.py
if [ -f "/opt/hookprobe/fortress/lib/fingerbank.py" ]; then
    pass "fingerbank.py exists"

    # Check for SPECIFIC_OUI_DEVICES (new feature)
    if grep -q "SPECIFIC_OUI_DEVICES" /opt/hookprobe/fortress/lib/fingerbank.py; then
        pass "fingerbank.py has SPECIFIC_OUI_DEVICES"
    else
        fail "fingerbank.py MISSING SPECIFIC_OUI_DEVICES - outdated!"
    fi

    # Check for _match_vendor_signature (new feature)
    if grep -q "_match_vendor_signature" /opt/hookprobe/fortress/lib/fingerbank.py; then
        pass "fingerbank.py has _match_vendor_signature"
    else
        fail "fingerbank.py MISSING _match_vendor_signature - outdated!"
    fi

    # Check for Dell 9C:B1:50
    if grep -q "9C:B1:50" /opt/hookprobe/fortress/lib/fingerbank.py; then
        pass "fingerbank.py has Dell OUI 9C:B1:50"
    else
        fail "fingerbank.py MISSING Dell OUI 9C:B1:50"
    fi
else
    fail "fingerbank.py NOT FOUND"
fi

# Check sdn_autopilot.py
if [ -f "/opt/hookprobe/fortress/lib/sdn_autopilot.py" ]; then
    pass "sdn_autopilot.py exists"

    # Check for mDNS import
    if grep -q "HAS_MDNS" /opt/hookprobe/fortress/lib/sdn_autopilot.py; then
        pass "sdn_autopilot.py has mDNS support"
    else
        warn "sdn_autopilot.py missing mDNS support (optional)"
    fi
else
    fail "sdn_autopilot.py NOT FOUND"
fi

# Check mdns_resolver.py
if [ -f "/opt/hookprobe/fortress/lib/mdns_resolver.py" ]; then
    pass "mdns_resolver.py exists"
else
    warn "mdns_resolver.py NOT FOUND (optional for mDNS)"
fi

echo ""
echo "2. Testing Python imports..."
echo "-------------------------------------------"

python3 << 'EOF'
import sys
sys.path.insert(0, '/opt/hookprobe/fortress/lib')

# Test fingerbank import
try:
    from fingerbank import Fingerbank, SPECIFIC_OUI_DEVICES, CATEGORY_POLICIES
    print(f"✓ PASS: Fingerbank imported successfully")
    print(f"  - SPECIFIC_OUI_DEVICES entries: {len(SPECIFIC_OUI_DEVICES)}")
    print(f"  - CATEGORY_POLICIES entries: {len(CATEGORY_POLICIES)}")

    # Check for Dell
    if "9C:B1:50" in SPECIFIC_OUI_DEVICES:
        print(f"✓ PASS: Dell 9C:B1:50 in SPECIFIC_OUI_DEVICES")
    else:
        print(f"✗ FAIL: Dell 9C:B1:50 NOT in SPECIFIC_OUI_DEVICES")

    # Check for Raspberry Pi
    if "DC:A6:32" in SPECIFIC_OUI_DEVICES:
        print(f"✓ PASS: Raspberry Pi DC:A6:32 in SPECIFIC_OUI_DEVICES")
    else:
        print(f"✗ FAIL: Raspberry Pi DC:A6:32 NOT in SPECIFIC_OUI_DEVICES")

except Exception as e:
    print(f"✗ FAIL: Fingerbank import failed: {e}")

# Test sdn_autopilot import
try:
    from sdn_autopilot import SDNAutoPilot, get_autopilot
    print(f"✓ PASS: SDNAutoPilot imported successfully")
except Exception as e:
    print(f"✗ FAIL: SDNAutoPilot import failed: {e}")
EOF

echo ""
echo "3. Testing device identification..."
echo "-------------------------------------------"

python3 << 'EOF'
import sys
sys.path.insert(0, '/opt/hookprobe/fortress/lib')

try:
    from fingerbank import Fingerbank
    fb = Fingerbank()

    test_devices = [
        ("9C:B1:50:E2:0B:49", "E1633173", None, "Dell laptop"),
        ("DC:A6:32:A4:B6:88", "hookprobe", None, "Raspberry Pi"),
        ("40:ED:CF:82:62:6B", "hookprobe", None, "HomePod"),
        ("00:24:E4:FE:5A:0A", None, None, "Withings"),
        ("46:32:0C:94:20:BB", None, "1,3,6,15,119,252,78,79", "Apple Watch"),
        ("66:E1:5E:04:CE:05", "MacBookPro", "1,121,3,6,15,119,252,95,44,46", "MacBook"),
    ]

    for mac, hostname, fingerprint, expected in test_devices:
        result = fb.identify(mac, fingerprint, hostname)
        status = "✓" if result.confidence >= 0.85 else "✗"
        print(f"{status} {expected}: {result.name} ({result.vendor}) | {result.confidence:.2f} | {result.policy}")

except Exception as e:
    print(f"✗ FAIL: Test failed: {e}")
    import traceback
    traceback.print_exc()
EOF

echo ""
echo "4. Comparing git repo vs production..."
echo "-------------------------------------------"

GIT_FB="/home/user/hookprobe/products/fortress/lib/fingerbank.py"
PROD_FB="/opt/hookprobe/fortress/lib/fingerbank.py"

if [ -f "$GIT_FB" ] && [ -f "$PROD_FB" ]; then
    GIT_LINES=$(wc -l < "$GIT_FB")
    PROD_LINES=$(wc -l < "$PROD_FB")

    if [ "$GIT_LINES" -eq "$PROD_LINES" ]; then
        pass "fingerbank.py line count matches ($GIT_LINES lines)"
    else
        fail "fingerbank.py MISMATCH: git=$GIT_LINES lines, prod=$PROD_LINES lines"
        echo "  → Run: sudo cp $GIT_FB $PROD_FB"
    fi

    # Check MD5
    GIT_MD5=$(md5sum "$GIT_FB" | awk '{print $1}')
    PROD_MD5=$(md5sum "$PROD_FB" | awk '{print $1}')

    if [ "$GIT_MD5" = "$PROD_MD5" ]; then
        pass "fingerbank.py content matches (md5: $GIT_MD5)"
    else
        fail "fingerbank.py CONTENT MISMATCH"
        echo "  → Git:  $GIT_MD5"
        echo "  → Prod: $PROD_MD5"
        echo "  → Run: sudo cp $GIT_FB $PROD_FB"
    fi
else
    warn "Cannot compare - one or both files missing"
fi

echo ""
echo "5. Fix Commands (if needed)..."
echo "-------------------------------------------"
echo "# Sync all lib files from git to production:"
echo "sudo cp /home/user/hookprobe/products/fortress/lib/*.py /opt/hookprobe/fortress/lib/"
echo ""
echo "# Then restart dnsmasq to trigger new DHCP events:"
echo "sudo systemctl restart dnsmasq"
echo ""
echo "# Or force a device to renew DHCP to test"
