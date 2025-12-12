#!/bin/bash
#
# Update Cortex modules without full reinstall
# Copies shared/cortex/ JS modules to /opt/hookprobe/shared/cortex/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDIAN_ROOT="$(dirname "$SCRIPT_DIR")"
SHARED_CORTEX="$GUARDIAN_ROOT/../../shared/cortex"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[Cortex]${NC} Updating shared Cortex visualization modules..."

# Check source exists
if [ ! -d "$SHARED_CORTEX/frontend/js" ]; then
    echo -e "${RED}[Error]${NC} Cortex source not found at $SHARED_CORTEX"
    exit 1
fi

# Create destination if needed
mkdir -p /opt/hookprobe/shared/cortex/frontend/js

# Copy all JS modules
cp "$SHARED_CORTEX/frontend/js/"*.js /opt/hookprobe/shared/cortex/frontend/js/ 2>/dev/null || {
    echo -e "${RED}[Error]${NC} Failed to copy modules"
    exit 1
}

# List copied files
echo -e "${GREEN}[Cortex]${NC} Modules updated:"
ls -la /opt/hookprobe/shared/cortex/frontend/js/*.js | awk '{print "  - " $NF}'

# Verify key files
for file in cluster-manager.js zoom-controller.js basemap-config.js deck-renderer.js; do
    if [ -f "/opt/hookprobe/shared/cortex/frontend/js/$file" ]; then
        echo -e "${GREEN}[OK]${NC} $file"
    else
        echo -e "${YELLOW}[WARN]${NC} Missing: $file"
    fi
done

echo -e "\n${GREEN}[Cortex]${NC} Update complete!"
echo -e "Restart Guardian web UI to apply changes:"
echo -e "  ${YELLOW}systemctl restart guardian-webui${NC}"
echo -e "  or"
echo -e "  ${YELLOW}systemctl restart guardian-web${NC}"
