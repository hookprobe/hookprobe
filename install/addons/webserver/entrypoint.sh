#!/bin/bash
set -e

# Configuration
DB_WAIT_TIMEOUT=${DB_WAIT_TIMEOUT:-60}
REDIS_WAIT_TIMEOUT=${REDIS_WAIT_TIMEOUT:-30}
STANDALONE_MODE=${STANDALONE_MODE:-false}

wait_for_service() {
    local host=$1
    local port=$2
    local service=$3
    local timeout=$4
    local count=0

    echo "Waiting for $service at $host:$port (timeout: ${timeout}s)..."

    while ! nc -z "$host" "$port" 2>/dev/null; do
        count=$((count + 1))
        if [ $count -ge $timeout ]; then
            echo "WARNING: $service not available after ${timeout}s"
            return 1
        fi
        sleep 1
    done
    echo "$service is ready"
    return 0
}

# Check if we should wait for services
if [ "$STANDALONE_MODE" = "true" ]; then
    echo "Running in standalone mode - using SQLite"
    export DATABASE_URL="sqlite:///db.sqlite3"
else
    # Wait for PostgreSQL with timeout
    if [ -n "$POSTGRES_HOST" ] && [ -n "$POSTGRES_PORT" ]; then
        if ! wait_for_service "$POSTGRES_HOST" "$POSTGRES_PORT" "PostgreSQL" "$DB_WAIT_TIMEOUT"; then
            echo "ERROR: PostgreSQL unavailable. Set STANDALONE_MODE=true to use SQLite."
            echo "Continuing anyway - Django will fail if DB is required..."
        fi
    fi

    # Wait for Redis with timeout (optional)
    if [ -n "$REDIS_HOST" ] && [ -n "$REDIS_PORT" ]; then
        if ! wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis" "$REDIS_WAIT_TIMEOUT"; then
            echo "WARNING: Redis unavailable. Caching will be disabled."
        fi
    fi
fi

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --noinput 2>&1 || {
    echo "WARNING: Migrations failed. This may be expected if database is unavailable."
}

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput 2>&1 || true

# Start Gunicorn
echo "Starting Gunicorn on port 8000..."
exec gunicorn hookprobe.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers ${GUNICORN_WORKERS:-2} \
    --timeout ${GUNICORN_TIMEOUT:-120} \
    --access-logfile - \
    --error-logfile - \
    --log-level info
