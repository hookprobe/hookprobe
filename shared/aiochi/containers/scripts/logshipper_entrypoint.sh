#!/bin/bash
set -e

echo "=== AIOCHI Log Shipper ==="
echo "Shipping logs to ClickHouse at ${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
echo "Suricata log: ${SURICATA_LOG_PATH}"
echo "Zeek logs: ${ZEEK_LOG_PATH}"

exec python /app/log_shipper.py
