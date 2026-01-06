#!/bin/bash
set -e

echo "=== AIOCHI Identity Engine ==="
echo "Starting identity engine on port 8060..."

# Start Flask API server
# NOTE: create_app() is in identity_engine_app.py (copied during container build)
exec gunicorn \
    --bind 0.0.0.0:8060 \
    --workers 2 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    "backend.identity_engine_app:create_app()"
