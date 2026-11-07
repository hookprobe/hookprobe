#!/bin/bash
#
# install-sentinel-lite.sh - HookProbe Sentinel Lite Installer
#
# This script installs the ultra-lightweight validator for constrained devices.
# It can be run locally from the repository or downloaded directly:
#
#   # Option 1: Direct download (recommended for constrained devices)
#   curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/products/sentinel/bootstrap.sh | sudo bash
#
#   # Option 2: From cloned repository
#   sudo ./install-sentinel-lite.sh
#
# Target platforms:
#   - Raspberry Pi 3/Zero/Pico-class
#   - Low-power ARM/IoT gateways
#   - LTE/mobile network validators
#   - Any Linux with 256MB+ RAM
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if we're in the repository with the product files
if [ -f "$SCRIPT_DIR/products/sentinel/bootstrap.sh" ]; then
    # Run the bootstrap script from the repository
    exec bash "$SCRIPT_DIR/products/sentinel/bootstrap.sh" "$@"
else
    # Fallback: download bootstrap from GitHub then execute
    echo "Downloading Sentinel Lite bootstrap..."
    tmpscript=$(mktemp /tmp/hookprobe-sentinel-XXXXXX.sh)
    curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/products/sentinel/bootstrap.sh -o "$tmpscript"
    bash "$tmpscript" "$@"
    rm -f "$tmpscript"
fi
