#!/bin/bash
#
# Update Cortex modules without full reinstall
# Copies shared/cortex/ frontend JS + backend Python to /opt/hookprobe/shared/cortex/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDIAN_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[Cortex]${NC} Updating shared Cortex visualization modules..."

# Find Cortex source - check multiple locations
SHARED_CORTEX=""
POSSIBLE_PATHS=(
    # Development/repo structure (products/guardian/scripts -> ../../shared/cortex)
    "$GUARDIAN_ROOT/../../shared/cortex"
    # Installed structure at /opt/hookprobe
    "/opt/hookprobe/shared/cortex"
    # If running from repo root
    "./shared/cortex"
    # Alternative: look for hookprobe repo
    "$HOME/hookprobe/shared/cortex"
)

for path in "${POSSIBLE_PATHS[@]}"; do
    if [ -d "$path/frontend/js" ] || [ -d "$path/backend" ]; then
        SHARED_CORTEX="$path"
        echo -e "${GREEN}[Cortex]${NC} Found source at: $SHARED_CORTEX"
        break
    fi
done

if [ -z "$SHARED_CORTEX" ] || [ ! -d "$SHARED_CORTEX" ]; then
    echo -e "${RED}[Error]${NC} Cortex source not found in any of:"
    for path in "${POSSIBLE_PATHS[@]}"; do
        echo "  - $path"
    done
    echo ""
    echo "Please run this script from the hookprobe repository directory,"
    echo "or ensure /opt/hookprobe/shared/cortex exists."
    exit 1
fi

# ========================================
# Frontend JS Modules (Globe visualization)
# ========================================
if [ -d "$SHARED_CORTEX/frontend/js" ]; then
    mkdir -p /opt/hookprobe/shared/cortex/frontend/js
    cp "$SHARED_CORTEX/frontend/js/"*.js /opt/hookprobe/shared/cortex/frontend/js/ 2>/dev/null || {
        echo -e "${RED}[Error]${NC} Failed to copy frontend modules"
        exit 1
    }
    echo -e "${GREEN}[Cortex]${NC} Frontend JS modules updated:"
    ls -1 /opt/hookprobe/shared/cortex/frontend/js/*.js 2>/dev/null | wc -l | xargs -I {} echo "  {} files copied"
else
    echo -e "${YELLOW}[WARN]${NC} Frontend JS not found at $SHARED_CORTEX/frontend/js"
fi

# ========================================
# Backend Python Modules (Demo data with 75+ nodes)
# ========================================
if [ -d "$SHARED_CORTEX/backend" ]; then
    mkdir -p /opt/hookprobe/shared/cortex/backend
    cp "$SHARED_CORTEX/backend/"*.py /opt/hookprobe/shared/cortex/backend/ 2>/dev/null || true
    # Create __init__.py files for Python imports
    touch /opt/hookprobe/shared/cortex/__init__.py
    touch /opt/hookprobe/shared/cortex/backend/__init__.py
    echo -e "${GREEN}[Cortex]${NC} Backend Python modules updated:"
    ls -1 /opt/hookprobe/shared/cortex/backend/*.py 2>/dev/null | wc -l | xargs -I {} echo "  {} files copied"
else
    echo -e "${YELLOW}[WARN]${NC} Backend Python not found at $SHARED_CORTEX/backend"
fi

# Verify key files
echo -e "\n${GREEN}[Cortex]${NC} Verification:"
for file in cluster-manager.js zoom-controller.js basemap-config.js deck-renderer.js; do
    if [ -f "/opt/hookprobe/shared/cortex/frontend/js/$file" ]; then
        echo -e "  ${GREEN}[OK]${NC} frontend/js/$file"
    else
        echo -e "  ${YELLOW}[WARN]${NC} Missing: frontend/js/$file"
    fi
done

for file in demo_data.py server.py node_registry.py; do
    if [ -f "/opt/hookprobe/shared/cortex/backend/$file" ]; then
        echo -e "  ${GREEN}[OK]${NC} backend/$file"
    else
        echo -e "  ${YELLOW}[WARN]${NC} Missing: backend/$file"
    fi
done

echo -e "\n${GREEN}[Cortex]${NC} Update complete!"
echo -e "Restart Guardian web UI to apply changes:"
echo -e "  ${YELLOW}systemctl restart guardian-webui${NC}"
