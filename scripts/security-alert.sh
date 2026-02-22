#!/bin/bash
# ==========================================================
# HookProbe Security Alert Monitor
# ==========================================================
# Monitors ClickHouse for critical security events and sends
# Discord alerts when thresholds are exceeded.
#
# Run via systemd timer every 5 minutes or via cron.
# ==========================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load environment
if [[ -f "$PROJECT_DIR/.env" ]]; then
    source "$PROJECT_DIR/.env"
fi

# Configuration
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
DISCORD_WEBHOOK_NAME="${DISCORD_WEBHOOK_NAME:-HookProbe Security}"
# Always use localhost for ClickHouse (script runs on host, not in container)
CLICKHOUSE_HOST="127.0.0.1"
CLICKHOUSE_PORT="8123"
CLICKHOUSE_USER="ids"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-hookprobe_ids_secure}"
CLICKHOUSE_DB="hookprobe_ids"

# Alert thresholds (tuned to avoid false positives)
DDOS_THRESHOLD=500           # DDoS events in 5min (raised from 100)
DDOS_MIN_SOURCES=10          # Minimum unique sources to count as real DDoS
BRUTEFORCE_THRESHOLD=100     # Brute force events in 5min (raised from 50)
BRUTEFORCE_MIN_SOURCES=5     # Minimum unique sources for brute force alert
SCAN_THRESHOLD=200           # Scan events in 5min
CRITICAL_INCIDENTS=1         # New critical incidents in 5min
QSECBIT_DROP_THRESHOLD=20   # QSecBit score drop in 5min

# State file to avoid duplicate alerts
STATE_FILE="/tmp/hookprobe-security-alert-state"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Execute ClickHouse query
ch_query() {
    local query="$1"
    curl -s "http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}/?user=${CLICKHOUSE_USER}&password=${CLICKHOUSE_PASSWORD}&database=${CLICKHOUSE_DB}" \
        --data-binary "$query" 2>/dev/null
}

# Send Discord alert
send_discord_alert() {
    local title="$1"
    local description="$2"
    local color="$3"  # decimal color: red=16711680, amber=16753920, green=65280

    if [[ -z "$DISCORD_WEBHOOK_URL" ]]; then
        log "WARNING: DISCORD_WEBHOOK_URL not set, skipping alert"
        return 0
    fi

    local payload
    payload=$(jq -n \
        --arg username "$DISCORD_WEBHOOK_NAME" \
        --arg title "$title" \
        --arg desc "$description" \
        --argjson color "$color" \
        '{
            username: $username,
            embeds: [{
                title: $title,
                description: $desc,
                color: $color,
                timestamp: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
                footer: { text: "HookProbe xSOC" }
            }]
        }')

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)

    if [[ "$http_code" == "204" || "$http_code" == "200" ]]; then
        log "Discord alert sent: $title"
    else
        log "WARNING: Discord alert failed (HTTP $http_code)"
    fi
}

# Get last alert time for deduplication
get_last_alert() {
    local key="$1"
    if [[ -f "$STATE_FILE" ]]; then
        grep "^${key}=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "0"
    else
        echo "0"
    fi
}

# Set last alert time
set_last_alert() {
    local key="$1"
    local value
    value=$(date +%s)
    if [[ -f "$STATE_FILE" ]]; then
        # Remove old entry and add new one
        grep -v "^${key}=" "$STATE_FILE" > "${STATE_FILE}.tmp" 2>/dev/null || true
        echo "${key}=${value}" >> "${STATE_FILE}.tmp"
        mv "${STATE_FILE}.tmp" "$STATE_FILE"
    else
        echo "${key}=${value}" > "$STATE_FILE"
    fi
}

# Check if enough time has passed since last alert (cooldown: 15 minutes)
should_alert() {
    local key="$1"
    local cooldown="${2:-900}"  # 15 min default
    local last
    last=$(get_last_alert "$key")
    local now
    now=$(date +%s)
    local diff=$((now - last))
    [[ $diff -ge $cooldown ]]
}

# ==========================================
# CHECKS
# ==========================================

log "Starting security check..."

alerts_sent=0

# Check 1: DDoS events in last 5 minutes
# IMPORTANT: DDoS = DISTRIBUTED denial of service. Require multiple unique sources.
ddos_count=$(ch_query "SELECT count() FROM napse_intents WHERE timestamp > now() - INTERVAL 5 MINUTE AND intent_class = 'ddos'" | tr -d '[:space:]')
ddos_count=${ddos_count:-0}
ddos_sources_result=$(ch_query "SELECT uniq(src_ip) FROM napse_intents WHERE timestamp > now() - INTERVAL 5 MINUTE AND intent_class = 'ddos'" 2>/dev/null | tr -d '[:space:]')
if [[ "$ddos_sources_result" =~ ^[0-9]+$ ]]; then ddos_sources="$ddos_sources_result"; else ddos_sources=0; fi

if [[ "$ddos_count" -ge "$DDOS_THRESHOLD" && "$ddos_sources" -ge "$DDOS_MIN_SOURCES" ]] && should_alert "ddos" 900; then
    top_sources=$(ch_query "SELECT IPv4NumToString(src_ip) as ip, count() as cnt FROM napse_intents WHERE timestamp > now() - INTERVAL 5 MINUTE AND intent_class = 'ddos' GROUP BY src_ip ORDER BY cnt DESC LIMIT 5 FORMAT TabSeparated" | while read -r ip cnt; do echo "  - $ip ($cnt events)"; done)

    send_discord_alert \
        "DDoS Attack Detected" \
        "**${ddos_count} DDoS events** from **${ddos_sources} unique sources** in 5 minutes.\n\n**Top Sources:**\n${top_sources}\n\n**Action:** Review in xSOC dashboard." \
        16711680  # Red

    set_last_alert "ddos"
    ((alerts_sent++)) || true
fi

# Check 2: Brute force events in last 5 minutes
# Require multiple unique sources to reduce false positives from established sessions
bf_count=$(ch_query "SELECT count() FROM napse_intents WHERE timestamp > now() - INTERVAL 5 MINUTE AND intent_class = 'bruteforce'" | tr -d '[:space:]')
bf_count=${bf_count:-0}
bf_src_result=$(ch_query "SELECT uniq(src_ip) FROM napse_intents WHERE timestamp > now() - INTERVAL 5 MINUTE AND intent_class = 'bruteforce'" 2>/dev/null | tr -d '[:space:]')
if [[ "$bf_src_result" =~ ^[0-9]+$ ]]; then bf_src_count="$bf_src_result"; else bf_src_count=0; fi

if [[ "$bf_count" -ge "$BRUTEFORCE_THRESHOLD" && "$bf_src_count" -ge "$BRUTEFORCE_MIN_SOURCES" ]] && should_alert "bruteforce" 900; then
    top_bf=$(ch_query "SELECT IPv4NumToString(src_ip) as ip, count() as cnt FROM napse_intents WHERE timestamp > now() - INTERVAL 5 MINUTE AND intent_class = 'bruteforce' GROUP BY src_ip ORDER BY cnt DESC LIMIT 5 FORMAT TabSeparated" | while read -r ip cnt; do echo "  - $ip ($cnt attempts)"; done)

    send_discord_alert \
        "Brute Force Attack Detected" \
        "**${bf_count} brute force events** from **${bf_src_count} sources** in 5 minutes.\n\n**Top Attackers:**\n${top_bf}\n\n**Targets:** SSH (port 22), database ports.\n**Action:** Consider blocking these IPs." \
        16753920  # Amber

    set_last_alert "bruteforce"
    ((alerts_sent++)) || true
fi

# Check 3: New critical incidents in last 5 minutes
crit_result=$(ch_query "SELECT count() FROM incidents WHERE timestamp > now() - INTERVAL 5 MINUTE AND severity = 'critical'" 2>/dev/null || echo "0")
# Guard against ClickHouse error messages
if [[ "$crit_result" =~ ^[0-9]+$ ]]; then
    crit_count="$crit_result"
else
    crit_count=0
fi

if [[ "$crit_count" -ge "$CRITICAL_INCIDENTS" ]] && should_alert "critical_incident" 900; then
    incident_details=$(ch_query "SELECT title, arrayStringConcat(src_ips, ', ') as sources FROM incidents WHERE timestamp > now() - INTERVAL 5 MINUTE AND severity = 'critical' LIMIT 5 FORMAT TabSeparated" 2>/dev/null | while read -r title sources; do echo "  - **$title** from $sources"; done)

    send_discord_alert \
        "Critical Security Incident" \
        "**${crit_count} critical incident(s)** created in the last 5 minutes.\n\n${incident_details}\n\n**Action:** Immediate investigation required." \
        16711680  # Red

    set_last_alert "critical_incident"
    ((alerts_sent++)) || true
fi

# Check 4: QSecBit score drop
latest_result=$(ch_query "SELECT score FROM qsecbit_scores ORDER BY timestamp DESC LIMIT 1" 2>/dev/null | tr -d '[:space:]')
previous_result=$(ch_query "SELECT score FROM qsecbit_scores WHERE timestamp < now() - INTERVAL 5 MINUTE ORDER BY timestamp DESC LIMIT 1" 2>/dev/null | tr -d '[:space:]')
# Guard against ClickHouse error messages
if [[ "$latest_result" =~ ^[0-9]+$ ]]; then latest_score="$latest_result"; else latest_score=0; fi
if [[ "$previous_result" =~ ^[0-9]+$ ]]; then previous_score="$previous_result"; else previous_score=0; fi

if [[ -n "$latest_score" && -n "$previous_score" && "$previous_score" -gt 0 ]]; then
    score_drop=$((previous_score - latest_score))
    if [[ "$score_drop" -ge "$QSECBIT_DROP_THRESHOLD" ]] && should_alert "qsecbit_drop" 1800; then
        status="unknown"
        if [[ "$latest_score" -lt 30 ]]; then
            status="CRITICAL"
        elif [[ "$latest_score" -lt 55 ]]; then
            status="WARNING"
        else
            status="PROTECTED"
        fi

        send_discord_alert \
            "QSecBit Score Drop" \
            "Security score dropped **${score_drop} points** (${previous_score} → ${latest_score}).\n\nCurrent status: **${status}**\n\n**Action:** Check xSOC dashboard for threat details." \
            16753920  # Amber

        set_last_alert "qsecbit_drop"
        ((alerts_sent++)) || true
    fi
fi

# Check 5: High volume of unique brute force sources (distributed attack)
bf_sources_result=$(ch_query "SELECT uniq(src_ip) FROM napse_intents WHERE timestamp > now() - INTERVAL 15 MINUTE AND intent_class = 'bruteforce'" 2>/dev/null | tr -d '[:space:]')
if [[ "$bf_sources_result" =~ ^[0-9]+$ ]]; then bf_sources="$bf_sources_result"; else bf_sources=0; fi

if [[ "$bf_sources" -ge 10 ]] && should_alert "distributed_bf" 1800; then
    send_discord_alert \
        "Distributed Brute Force Detected" \
        "**${bf_sources} unique source IPs** performing brute force in the last 15 minutes.\n\nThis indicates a **coordinated botnet attack**.\n\n**Action:** Consider enabling automated IP blocking." \
        16711680  # Red

    set_last_alert "distributed_bf"
    ((alerts_sent++)) || true
fi

# ==========================================
# SENTINEL CHECKS (HYDRA ML Pipeline)
# ==========================================

# Check 6: SENTINEL malicious IP surge (10+ malicious verdicts in 15 minutes)
sentinel_malicious_result=$(ch_query "SELECT count() FROM hydra_verdicts WHERE timestamp > now() - INTERVAL 15 MINUTE AND verdict = 'malicious'" 2>/dev/null | tr -d '[:space:]')
if [[ "$sentinel_malicious_result" =~ ^[0-9]+$ ]]; then sentinel_malicious="$sentinel_malicious_result"; else sentinel_malicious=0; fi

if [[ "$sentinel_malicious" -ge 10 ]] && should_alert "sentinel_malicious_surge" 900; then
    top_malicious=$(ch_query "SELECT src_ip, max(score) as max_score FROM hydra_verdicts WHERE timestamp > now() - INTERVAL 15 MINUTE AND verdict = 'malicious' GROUP BY src_ip ORDER BY max_score DESC LIMIT 5 FORMAT TabSeparated" 2>/dev/null | while read -r ip score; do echo "  - $ip (score: $score)"; done)

    send_discord_alert \
        "SENTINEL: Malicious IP Surge" \
        "**${sentinel_malicious} malicious IPs** detected by HYDRA SENTINEL in 15 minutes.\n\n**Top Threats:**\n${top_malicious}\n\n**Action:** IPs auto-blocked by AEGIS GUARDIAN. Review verdicts." \
        16711680  # Red

    set_last_alert "sentinel_malicious_surge"
    ((alerts_sent++)) || true
fi

# Check 7: SENTINEL campaign detected (coordinated attack)
sentinel_campaigns_result=$(ch_query "SELECT count(DISTINCT campaign_id) FROM sentinel_campaigns WHERE first_seen > now() - INTERVAL 30 MINUTE" 2>/dev/null | tr -d '[:space:]')
if [[ "$sentinel_campaigns_result" =~ ^[0-9]+$ ]]; then sentinel_campaigns="$sentinel_campaigns_result"; else sentinel_campaigns=0; fi

if [[ "$sentinel_campaigns" -ge 1 ]] && should_alert "sentinel_campaign" 1800; then
    campaign_details=$(ch_query "SELECT campaign_id, member_count, max_reputation FROM sentinel_campaigns WHERE first_seen > now() - INTERVAL 30 MINUTE ORDER BY max_reputation DESC LIMIT 3 FORMAT TabSeparated" 2>/dev/null | while read -r cid members rep; do echo "  - Campaign $cid ($members IPs, reputation: $rep)"; done)

    send_discord_alert \
        "SENTINEL: Coordinated Campaign Detected" \
        "**${sentinel_campaigns} new campaign(s)** identified via IP co-occurrence analysis.\n\n**Campaigns:**\n${campaign_details}\n\n**Action:** MEDIC forensic capture activated. Review campaign graph." \
        16711680  # Red

    set_last_alert "sentinel_campaign"
    ((alerts_sent++)) || true
fi

# Check 8: SENTINEL model drift (Page-Hinkley triggered)
sentinel_drift_result=$(ch_query "SELECT max(drift_detected) FROM sentinel_lifecycle_metrics WHERE timestamp > now() - INTERVAL 10 MINUTE" 2>/dev/null | tr -d '[:space:]')
if [[ "$sentinel_drift_result" =~ ^[01]$ ]]; then sentinel_drift="$sentinel_drift_result"; else sentinel_drift=0; fi

if [[ "$sentinel_drift" -eq 1 ]] && should_alert "sentinel_drift" 3600; then
    send_discord_alert \
        "SENTINEL: Model Drift Detected" \
        "Page-Hinkley drift detector triggered — SENTINEL scoring distribution has shifted.\n\n**Action:** Automatic retrain cycle initiated. Monitor precision/recall convergence." \
        16753920  # Amber

    set_last_alert "sentinel_drift"
    ((alerts_sent++)) || true
fi

# Check 9: SENTINEL F1 score degradation (below 0.60)
sentinel_f1_result=$(ch_query "SELECT min(f1_score) FROM sentinel_lifecycle_metrics WHERE timestamp > now() - INTERVAL 1 HOUR AND f1_score > 0" 2>/dev/null | tr -d '[:space:]')
if [[ "$sentinel_f1_result" =~ ^[0-9.]+$ ]]; then
    # Compare float: multiply by 100 for integer comparison
    sentinel_f1_int=$(echo "$sentinel_f1_result" | awk '{printf "%d", $1 * 100}')
    if [[ "$sentinel_f1_int" -lt 60 ]] && should_alert "sentinel_f1_low" 3600; then
        send_discord_alert \
            "SENTINEL: F1 Score Degradation" \
            "SENTINEL F1 score dropped to **${sentinel_f1_result}** (threshold: 0.60).\n\nLow F1 indicates poor classification quality.\n\n**Action:** Check operator feedback queue. Consider manual model retrain." \
            16753920  # Amber

        set_last_alert "sentinel_f1_low"
        ((alerts_sent++)) || true
    fi
fi

# Check 10: SENTINEL pipeline stalled (no verdicts in 30 minutes)
sentinel_verdict_result=$(ch_query "SELECT count() FROM hydra_verdicts WHERE timestamp > now() - INTERVAL 30 MINUTE" 2>/dev/null | tr -d '[:space:]')
if [[ "$sentinel_verdict_result" =~ ^[0-9]+$ ]]; then sentinel_verdicts="$sentinel_verdict_result"; else sentinel_verdicts=0; fi

# Only alert if we expect verdicts (check if table has any data at all)
sentinel_total_result=$(ch_query "SELECT count() FROM hydra_verdicts" 2>/dev/null | tr -d '[:space:]')
if [[ "$sentinel_total_result" =~ ^[0-9]+$ ]]; then sentinel_total="$sentinel_total_result"; else sentinel_total=0; fi

if [[ "$sentinel_total" -gt 0 && "$sentinel_verdicts" -eq 0 ]] && should_alert "sentinel_stalled" 1800; then
    send_discord_alert \
        "SENTINEL: Pipeline Stalled" \
        "SENTINEL produced **0 verdicts** in the last 30 minutes.\n\nThe scoring pipeline may be down.\n\n**Action:** Check hydra-sentinel, hydra-profiler, hydra-temporal containers." \
        16753920  # Amber

    set_last_alert "sentinel_stalled"
    ((alerts_sent++)) || true
fi

# Summary
total_events=$(ch_query "SELECT count() FROM napse_intents WHERE timestamp > now() - INTERVAL 5 MINUTE AND intent_class != 'benign'" | tr -d '[:space:]')
total_events=${total_events:-0}

log "Check complete: DDoS=${ddos_count}(${ddos_sources}src) BF=${bf_count}(${bf_src_count}src) CritIncidents=${crit_count} Score=${latest_score} DistBF=${bf_sources} SENTINEL(mal=${sentinel_malicious},camp=${sentinel_campaigns},drift=${sentinel_drift},verdicts=${sentinel_verdicts}) Total5m=${total_events} AlertsSent=${alerts_sent}"
