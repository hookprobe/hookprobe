#!/bin/bash
# Export ARP table to JSON for container access
# This script runs on the host and writes ARP data to a shared location
# that the fts-web container can read.

set -e

OUTPUT_DIR="/var/lib/hookprobe"
OUTPUT_FILE="${OUTPUT_DIR}/arp-status.json"
TEMP_FILE="${OUTPUT_FILE}.tmp"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Get ARP table for FTS bridge and convert to JSON using Python for proper formatting
python3 << 'PYTHON'
import subprocess
import json
import sys

result = subprocess.run(['ip', 'neigh', 'show', 'dev', 'FTS'],
                        capture_output=True, text=True, timeout=5)

arp_data = {}
for line in result.stdout.strip().split('\n'):
    if not line:
        continue
    parts = line.split()
    if len(parts) < 4:
        continue

    ip = parts[0]
    # Skip IPv6
    if ':' in ip and not ip.startswith('10.') and not ip.startswith('192.'):
        continue

    mac = None
    state = 'UNKNOWN'

    for i, part in enumerate(parts):
        if part == 'lladdr' and i + 1 < len(parts):
            mac = parts[i + 1].upper()
        if part in ('REACHABLE', 'STALE', 'DELAY', 'PROBE', 'FAILED', 'INCOMPLETE', 'PERMANENT'):
            state = part

    if mac:
        is_online = state in ('REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT')
        arp_data[mac] = {
            'online': is_online,
            'state': state,
            'ip': ip
        }

# Write to temp file
with open('/var/lib/hookprobe/arp-status.json.tmp', 'w') as f:
    json.dump(arp_data, f, indent=2)

print(f"Exported {len(arp_data)} ARP entries")
PYTHON

# Atomically replace the output file
mv "$TEMP_FILE" "$OUTPUT_FILE"
chmod 644 "$OUTPUT_FILE"
