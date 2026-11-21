#!/bin/bash
set -e

echo "=== AIOCHI Supplementary Log Shipper ==="
echo "ClickHouse: ${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
echo "NAPSE handles primary IDS event shipping via clickhouse_shipper.py"

exec python /app/log_shipper.py
