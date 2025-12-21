#!/bin/bash
# dnsXai Container Entrypoint
# Copies default whitelist to data volume if not present

set -e

DATA_DIR="${DNSXAI_DATA_DIR:-/opt/hookprobe/shared/dnsXai/data}"
DEFAULTS_DIR="/opt/hookprobe/shared/dnsXai/defaults"

# Ensure data directory exists
mkdir -p "$DATA_DIR"

# Copy default whitelist if not present in data volume
if [ ! -f "$DATA_DIR/whitelist.txt" ] && [ -f "$DEFAULTS_DIR/whitelist.txt" ]; then
    echo "[dnsXai] Copying default whitelist to data directory..."
    cp "$DEFAULTS_DIR/whitelist.txt" "$DATA_DIR/whitelist.txt"
    echo "[dnsXai] Default whitelist installed ($(wc -l < "$DATA_DIR/whitelist.txt") entries)"
fi

# Start the DNS engine
exec python engine.py "$@"
