#!/bin/bash
# ============================================================
# HookProbe DFS Intelligence Container Entrypoint
# ============================================================

set -e

# Colors for logging
log_info() { echo "[INFO] $*"; }
log_error() { echo "[ERROR] $*" >&2; }

# Ensure directories exist
mkdir -p /var/lib/hookprobe /var/log/hookprobe /var/run/hookprobe

# Initialize database if needed
log_info "Initializing DFS database..."
python3 -c "from dfs_intelligence import DFSDatabase; DFSDatabase()" 2>/dev/null || true

case "${1:-server}" in
    server)
        log_info "Starting DFS Intelligence API server..."
        exec gunicorn \
            --bind "${DFS_API_HOST:-0.0.0.0}:${DFS_API_PORT:-8767}" \
            --workers 2 \
            --threads 2 \
            --timeout 30 \
            --access-logfile - \
            --error-logfile - \
            --capture-output \
            "dfs_api_server:app"
        ;;

    cli)
        shift
        log_info "Running DFS Intelligence CLI..."
        exec python3 /app/dfs_intelligence.py "$@"
        ;;

    train)
        log_info "Training ML model..."
        exec python3 /app/dfs_intelligence.py train "${2:-50}"
        ;;

    monitor)
        # Note: This requires hostapd socket access from host
        log_info "Starting radar monitor..."
        exec python3 /app/dfs_intelligence.py monitor --interface "${2:-wlan0}"
        ;;

    shell)
        log_info "Starting shell..."
        exec /bin/bash
        ;;

    *)
        log_error "Unknown command: $1"
        echo "Usage: entrypoint.sh {server|cli|train|monitor|shell}"
        exit 1
        ;;
esac
