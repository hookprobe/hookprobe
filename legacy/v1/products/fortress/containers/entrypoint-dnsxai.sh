#!/bin/bash
# dnsXai Container Entrypoint
# DNS server: container:5353/udp → host:127.0.0.1:53 (dnsmasq forwards here)
# HTTP API: container:8080/tcp → host:127.0.0.1:8053
# Port 5353 on host is FREE for mDNS (Avahi, bubble manager ecosystem detection)

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

# ============================================================
# WHITELIST SYNCHRONIZATION
# ============================================================
# Ensure whitelist is synced between DATA_DIR (fast volume) and
# USERDATA_DIR (persistent bind mount that survives reinstalls).
#
# Priority order:
# 1. USERDATA_DIR/whitelist.txt (user's persistent whitelist)
# 2. DATA_DIR/whitelist.txt (container volume, may have old data)
# 3. DEFAULTS_DIR/whitelist.txt (bundled defaults)
# ============================================================

# Handle dangling symlinks in userdata (can happen if target doesn't exist)
if [ -L "$USERDATA_DIR/whitelist.txt" ] && [ ! -e "$USERDATA_DIR/whitelist.txt" ]; then
    echo "[dnsXai] Removing dangling symlink for whitelist"
    rm -f "$USERDATA_DIR/whitelist.txt"
fi

if [ -f "$USERDATA_DIR/whitelist.txt" ]; then
    # User has a persistent whitelist - use it
    echo "[dnsXai] Using persistent user whitelist from $USERDATA_DIR"
    cp "$USERDATA_DIR/whitelist.txt" "$DATA_DIR/whitelist.txt"
    echo "[dnsXai] User whitelist: $(wc -l < "$USERDATA_DIR/whitelist.txt") entries"
elif [ -f "$DATA_DIR/whitelist.txt" ]; then
    # No userdata whitelist, but data volume has one - sync to userdata for persistence
    # This handles the case where user ran --purge but --keep-data preserved volumes
    echo "[dnsXai] Syncing whitelist from data volume to persistent storage..."
    cp "$DATA_DIR/whitelist.txt" "$USERDATA_DIR/whitelist.txt"
    echo "[dnsXai] Whitelist synced: $(wc -l < "$DATA_DIR/whitelist.txt") entries"
elif [ -f "$DEFAULTS_DIR/whitelist.txt" ]; then
    # No whitelist anywhere - install defaults to both locations
    echo "[dnsXai] Initializing whitelist from defaults..."
    cp "$DEFAULTS_DIR/whitelist.txt" "$DATA_DIR/whitelist.txt"
    cp "$DEFAULTS_DIR/whitelist.txt" "$USERDATA_DIR/whitelist.txt"
    echo "[dnsXai] Default whitelist installed ($(wc -l < "$DATA_DIR/whitelist.txt") entries)"
else
    # No whitelist anywhere - create empty file
    echo "[dnsXai] WARNING: No whitelist found, creating empty whitelist"
    touch "$DATA_DIR/whitelist.txt"
    touch "$USERDATA_DIR/whitelist.txt"
fi

# ============================================================
# CONFIG SYNCHRONIZATION
# ============================================================
if [ -f "$USERDATA_DIR/config.json" ]; then
    # User has persistent config - use it
    echo "[dnsXai] Using persistent config from $USERDATA_DIR"
    cp "$USERDATA_DIR/config.json" "$DATA_DIR/config.json"
elif [ -f "$DATA_DIR/config.json" ]; then
    # No userdata config, but data volume has one - sync to userdata
    echo "[dnsXai] Syncing config from data volume to persistent storage..."
    cp "$DATA_DIR/config.json" "$USERDATA_DIR/config.json"
else
    # No config anywhere - create default
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

# ============================================================
# STATS SYNCHRONIZATION (Protection Level & Query Stats)
# ============================================================
# stats.json contains protection_level, query counts, and other runtime stats
# This must be synced to preserve user's protection level preference
if [ -f "$USERDATA_DIR/stats.json" ]; then
    # User has persistent stats - use them (protection level preserved)
    echo "[dnsXai] Using persistent stats from $USERDATA_DIR"
    cp "$USERDATA_DIR/stats.json" "$DATA_DIR/stats.json"
    # Extract protection level for logging
    SAVED_LEVEL=$(python3 -c "import json; print(json.load(open('$USERDATA_DIR/stats.json')).get('protection_level', 3))" 2>/dev/null || echo "3")
    echo "[dnsXai] Restored protection level: $SAVED_LEVEL"
elif [ -f "$DATA_DIR/stats.json" ]; then
    # No userdata stats, but data volume has them - sync to userdata
    echo "[dnsXai] Syncing stats from data volume to persistent storage..."
    cp "$DATA_DIR/stats.json" "$USERDATA_DIR/stats.json"
fi
# If no stats exist, API server will create defaults on startup

# Export userdata dir for API server to use when saving whitelist changes
export DNSXAI_USERDATA_DIR="$USERDATA_DIR"

# ============================================================
# BLOCKLIST INITIALIZATION
# ============================================================
# Download blocklists on first run if they don't exist
BLOCKLIST_FILE="$DATA_DIR/blocklist.txt"
if [ ! -f "$BLOCKLIST_FILE" ] || [ ! -s "$BLOCKLIST_FILE" ]; then
    echo "[dnsXai] Blocklist not found, downloading on first run..."
    # Run engine with --update flag to download blocklists
    cd /opt/hookprobe/shared/dnsXai
    timeout 120 python engine.py --update 2>&1 || {
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

    # Sync stats to persistent storage before exit
    if [ -f "$DATA_DIR/stats.json" ]; then
        echo "[dnsXai] Syncing stats to persistent storage..."
        cp "$DATA_DIR/stats.json" "$USERDATA_DIR/stats.json" 2>/dev/null || true
    fi

    # Sync whitelist changes to persistent storage
    if [ -f "$DATA_DIR/whitelist.txt" ]; then
        cp "$DATA_DIR/whitelist.txt" "$USERDATA_DIR/whitelist.txt" 2>/dev/null || true
    fi

    kill $API_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Start DNS engine in foreground with server mode
# --serve: Start the DNS resolver service
# --address: Listen on all interfaces (required for container networking)
# --port: Explicit port (matches container port mapping)
# --dot: Enable DNS over TLS for Windows/modern clients that require encrypted DNS
# --dot-port: DoT listens on standard port 853
exec python engine.py --serve --address 0.0.0.0 --port 5353 \
    --dot --dot-port 853 \
    --dot-cert /etc/hookprobe/certs/dnsxai.crt \
    --dot-key /etc/hookprobe/certs/dnsxai.key \
    "$@"
