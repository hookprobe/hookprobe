#!/bin/bash
# fix-web-ovs.sh - Patch the installed fts-ovs-connect.sh to NOT attach fts-web to OVS
# This fixes the Web UI not being accessible due to OVS intercepting podman's port forwarding
#
# Run as root: sudo ./fix-web-ovs.sh

set -e

SCRIPT_PATH="/opt/hookprobe/fortress/bin/fts-ovs-connect.sh"

if [ ! -f "$SCRIPT_PATH" ]; then
    echo "[INFO] fts-ovs-connect.sh not found at $SCRIPT_PATH"
    echo "[INFO] This is OK - it may not be installed yet"
    exit 0
fi

echo "[INFO] Checking $SCRIPT_PATH for fts-web attachment..."

# Check if already fixed
if grep -q "# attach_if_ready fts-web" "$SCRIPT_PATH" 2>/dev/null; then
    echo "[OK] fts-web attachment is already disabled"
    exit 0
fi

# Check if needs fixing
if grep -q "attach_if_ready fts-web" "$SCRIPT_PATH" 2>/dev/null; then
    echo "[FIX] Commenting out fts-web OVS attachment..."

    # Create backup
    cp "$SCRIPT_PATH" "${SCRIPT_PATH}.bak.$(date +%Y%m%d%H%M%S)"

    # Comment out the line
    sed -i 's/^attach_if_ready fts-web/# attach_if_ready fts-web  # DISABLED - breaks port 8443 forwarding/' "$SCRIPT_PATH"

    echo "[OK] Patched successfully. Backup created."
    echo "[INFO] Restart fortress service: sudo systemctl restart fortress"
else
    echo "[OK] No fts-web attachment found (already clean)"
fi
