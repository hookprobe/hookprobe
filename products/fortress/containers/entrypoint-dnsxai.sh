#!/bin/bash
# dnsXai Container Entrypoint
# Runs both DNS server (5353/udp) and HTTP API server (8080/tcp)

set -e

DATA_DIR="${DNSXAI_DATA_DIR:-/opt/hookprobe/shared/dnsXai/data}"
USERDATA_DIR="${DNSXAI_USERDATA_DIR:-/opt/hookprobe/shared/dnsXai/userdata}"
DEFAULTS_DIR="/opt/hookprobe/shared/dnsXai/defaults"
LOG_DIR="${LOG_DIR:-/var/log/hookprobe}"

# Ensure directories exist
mkdir -p "$DATA_DIR" "$USERDATA_DIR" "$LOG_DIR"

# ============================================================
# USER DATA PERSISTENCE
# ============================================================
# User whitelist and config are stored in USERDATA_DIR which is
# bind-mounted from the host (/var/lib/hookprobe/userdata/dnsxai).
# This data survives container rebuilds and reinstallation.
#
# Priority order for whitelist:
# 1. USERDATA_DIR/whitelist.txt (user's persistent whitelist)
# 2. DATA_DIR/whitelist.txt (container volume, regenerated on reinstall)
# 3. DEFAULTS_DIR/whitelist.txt (bundled defaults)
# ============================================================

# Symlink whitelist from userdata to data directory if user whitelist exists
# This allows the engine to always read from DATA_DIR while persisting in USERDATA_DIR
if [ -f "$USERDATA_DIR/whitelist.txt" ]; then
    echo "[dnsXai] Using persistent user whitelist from $USERDATA_DIR"
    # Copy to data dir (engine reads from there)
    cp "$USERDATA_DIR/whitelist.txt" "$DATA_DIR/whitelist.txt"
    echo "[dnsXai] User whitelist: $(wc -l < "$USERDATA_DIR/whitelist.txt") entries"
elif [ ! -f "$DATA_DIR/whitelist.txt" ] && [ -f "$DEFAULTS_DIR/whitelist.txt" ]; then
    # No user whitelist and no data whitelist - copy defaults to both locations
    echo "[dnsXai] Initializing whitelist from defaults..."
    cp "$DEFAULTS_DIR/whitelist.txt" "$DATA_DIR/whitelist.txt"
    cp "$DEFAULTS_DIR/whitelist.txt" "$USERDATA_DIR/whitelist.txt"
    echo "[dnsXai] Default whitelist installed ($(wc -l < "$DATA_DIR/whitelist.txt") entries)"
fi

# Create initial config if not exists (check userdata first)
if [ -f "$USERDATA_DIR/config.json" ]; then
    echo "[dnsXai] Using persistent config from $USERDATA_DIR"
    cp "$USERDATA_DIR/config.json" "$DATA_DIR/config.json"
elif [ ! -f "$DATA_DIR/config.json" ]; then
    echo "[dnsXai] Creating default configuration..."
    cat > "$DATA_DIR/config.json" << EOF
{
    "protection_level": ${DNSXAI_PROTECTION_LEVEL:-3},
    "upstream_dns": "${DNSXAI_UPSTREAM:-1.1.1.1}",
    "enable_ml": true,
    "enable_cname_uncloaking": true,
    "cache_ttl": 300,
    "created_at": "$(date -Iseconds)"
}
EOF
    # Also save to userdata for persistence
    cp "$DATA_DIR/config.json" "$USERDATA_DIR/config.json"
fi

# Export userdata dir for API server to use when saving whitelist changes
export DNSXAI_USERDATA_DIR="$USERDATA_DIR"

# ============================================================
# BLOCKLIST INITIALIZATION
# ============================================================
# Download blocklists on first run if they don't exist
BLOCKLIST_FILE="$DATA_DIR/blocklist.txt"
if [ ! -f "$BLOCKLIST_FILE" ] || [ ! -s "$BLOCKLIST_FILE" ]; then
    echo "[dnsXai] Blocklist not found, downloading on first run..."
    # Run engine with --update-blocklist flag to download blocklists
    timeout 120 python engine.py --update-blocklist --data-dir "$DATA_DIR" 2>&1 || {
        echo "[dnsXai] Warning: Blocklist download timed out or failed, will retry on next startup"
    }
    if [ -s "$BLOCKLIST_FILE" ]; then
        echo "[dnsXai] Blocklist downloaded: $(wc -l < "$BLOCKLIST_FILE") domains"
    fi
fi

echo "[dnsXai] Starting services..."
echo "[dnsXai] - DNS server on port 5353/udp"
echo "[dnsXai] - HTTP API on port 8080/tcp"

# Start HTTP API server in background
python api_server.py --host 0.0.0.0 --port 8080 &
API_PID=$!
echo "[dnsXai] HTTP API server started (PID: $API_PID)"

# Give API server time to start
sleep 1

# Trap to cleanup on exit
cleanup() {
    echo "[dnsXai] Shutting down..."
    kill $API_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Start DNS engine in foreground
exec python engine.py "$@"
