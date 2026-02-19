#!/usr/bin/env bash
# HookProbe HYDRA nftables Sync
# ===============================
# Reads confirmed threat IPs from ClickHouse NAPSE intents and adds
# to nftables blocklist set with auto-expiry timeout.
#
# Runs as systemd timer every 5 minutes.
#
# Usage:
#   sudo ./hydra-nftables-sync.sh
#
# Requirements:
#   - nftables (nft command)
#   - ClickHouse accessible on localhost:8123
#   - CLICKHOUSE_PASSWORD environment variable

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment
if [[ -f "${SCRIPT_DIR}/../.env" ]]; then
    set -a
    source "${SCRIPT_DIR}/../.env"
    set +a
fi

# ClickHouse config
CH_HOST="${CLICKHOUSE_HOST:-127.0.0.1}"
CH_PORT="${CLICKHOUSE_PORT:-8123}"
CH_DB="${CLICKHOUSE_DB:-hookprobe_ids}"
CH_USER="${CLICKHOUSE_USER:-ids}"
CH_PASSWORD="${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD required}"

# Block duration in seconds (default: 1 hour)
BLOCK_DURATION="${HYDRA_BLOCK_DURATION:-3600}"

# Minimum events from an IP before blocking
MIN_EVENTS=3

# Minimum unique destination ports (to avoid blocking single-port scanners trivially)
MIN_DST_PORTS=2

# Maximum severity for blocking (1=critical, 2=high)
MAX_SEVERITY=2

# NFT table/set names
NFT_TABLE="hydra"
NFT_FAMILY="inet"
NFT_SET="blocklist"

# Trusted IPs that must NEVER be blocked
TRUSTED_IPS=(
    "160.79.104.0/23"    # Anthropic
    "213.233.111.0/24"   # Vodafone Romania
    "46.97.153.0/24"     # Vodafone Romania
    "209.249.57.0/24"    # Mitel Networks
    "127.0.0.0/8"        # Loopback
    "10.0.0.0/8"         # RFC1918
    "172.16.0.0/12"      # RFC1918
    "192.168.0.0/16"     # RFC1918
    "169.254.0.0/16"     # Link-local
)

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [HYDRA-NFT] $*"; }
err() { echo "$(date '+%Y-%m-%d %H:%M:%S') [HYDRA-NFT] ERROR: $*" >&2; }

ch_query() {
    local query="$1"
    curl -sf "http://${CH_HOST}:${CH_PORT}/" \
        --user "${CH_USER}:${CH_PASSWORD}" \
        --data-binary "$query" 2>/dev/null
}

# Ensure nftables table and set exist
setup_nftables() {
    # Create table if not exists
    nft list table "${NFT_FAMILY}" "${NFT_TABLE}" &>/dev/null || {
        log "Creating nftables table ${NFT_FAMILY} ${NFT_TABLE}..."
        nft add table "${NFT_FAMILY}" "${NFT_TABLE}"
    }

    # Create set if not exists (IPv4 set with timeout support)
    nft list set "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_SET}" &>/dev/null || {
        log "Creating nftables set ${NFT_SET} with timeout support..."
        nft add set "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_SET}" \
            "{ type ipv4_addr; flags timeout; }"
    }

    # Create chain and rule if not exists
    nft list chain "${NFT_FAMILY}" "${NFT_TABLE}" input &>/dev/null || {
        log "Creating input chain with drop rule..."
        nft add chain "${NFT_FAMILY}" "${NFT_TABLE}" input \
            "{ type filter hook input priority -10; policy accept; }"
        nft add rule "${NFT_FAMILY}" "${NFT_TABLE}" input \
            ip saddr @"${NFT_SET}" counter drop
    }
}

# Check if an IP is in the trusted list
is_trusted() {
    local ip="$1"
    for trusted in "${TRUSTED_IPS[@]}"; do
        # Simple prefix check (not full CIDR math, but covers our use case)
        local prefix="${trusted%%/*}"
        local prefix_parts="${prefix%.*}"
        if [[ "$ip" == ${prefix_parts}.* ]]; then
            return 0
        fi
    done
    return 1
}

# Query ClickHouse for threat IPs and block them
sync_blocks() {
    log "Querying ClickHouse for threat IPs..."

    # Find IPs with severity 1-2 intents in the last hour,
    # with >= MIN_EVENTS events and >= MIN_DST_PORTS unique dest ports
    local query="
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS event_count,
            uniq(dst_port) AS unique_ports,
            min(severity) AS min_severity
        FROM ${CH_DB}.napse_intents
        WHERE timestamp >= now() - INTERVAL 1 HOUR
          AND severity <= ${MAX_SEVERITY}
          AND intent_class NOT IN ('benign', 'dns_anomaly')
        GROUP BY src_ip
        HAVING event_count >= ${MIN_EVENTS}
           AND unique_ports >= ${MIN_DST_PORTS}
        ORDER BY event_count DESC
        LIMIT 100
        FORMAT TabSeparated
    "

    local result
    result=$(ch_query "$query") || {
        err "ClickHouse query failed"
        return 1
    }

    if [[ -z "$result" ]]; then
        log "No threat IPs found in last hour"
        return 0
    fi

    local blocked=0
    local skipped=0

    while IFS=$'\t' read -r ip count ports severity; do
        # Skip empty lines
        [[ -z "$ip" ]] && continue

        # Skip trusted IPs
        if is_trusted "$ip"; then
            log "SKIP trusted: ${ip} (${count} events)"
            skipped=$((skipped + 1))
            continue
        fi

        # Check if already in the set
        if nft list set "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_SET}" 2>/dev/null | grep -q "$ip"; then
            continue
        fi

        # Add to blocklist with timeout
        if nft add element "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_SET}" \
            "{ ${ip} timeout ${BLOCK_DURATION}s }" 2>/dev/null; then
            log "BLOCKED: ${ip} (${count} events, ${ports} ports, sev=${severity}, timeout=${BLOCK_DURATION}s)"
            blocked=$((blocked + 1))

            # Log to ClickHouse
            local now
            now=$(date -u '+%Y-%m-%d %H:%M:%S.000')
            ch_query "INSERT INTO ${CH_DB}.hydra_blocks
                (timestamp, src_ip, duration_seconds, reason, source, event_count)
                VALUES ('${now}', IPv4StringToNum('${ip}'), ${BLOCK_DURATION},
                        'brute_force', 'nftables', ${count})" || true
        else
            err "Failed to block ${ip}"
        fi

    done <<< "$result"

    log "Sync complete: ${blocked} blocked, ${skipped} skipped (trusted)"
}

# Main
log "HYDRA nftables sync starting..."
setup_nftables
sync_blocks
log "Done"
