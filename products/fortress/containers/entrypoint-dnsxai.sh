#!/bin/bash
# dnsXai Container Entrypoint
# Runs both DNS server (5353/udp) and HTTP API server (8080/tcp)

set -e

DATA_DIR="${DNSXAI_DATA_DIR:-/opt/hookprobe/shared/dnsXai/data}"
DEFAULTS_DIR="/opt/hookprobe/shared/dnsXai/defaults"
LOG_DIR="${LOG_DIR:-/var/log/hookprobe}"

# Ensure directories exist
mkdir -p "$DATA_DIR" "$LOG_DIR"

# Copy default whitelist if not present in data volume
if [ ! -f "$DATA_DIR/whitelist.txt" ] && [ -f "$DEFAULTS_DIR/whitelist.txt" ]; then
    echo "[dnsXai] Copying default whitelist to data directory..."
    cp "$DEFAULTS_DIR/whitelist.txt" "$DATA_DIR/whitelist.txt"
    echo "[dnsXai] Default whitelist installed ($(wc -l < "$DATA_DIR/whitelist.txt") entries)"
fi

# Create initial config if not exists
if [ ! -f "$DATA_DIR/config.json" ]; then
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
