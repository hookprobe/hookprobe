#!/bin/bash
#
# attack-mitigation-orchestrator.sh
# HookProbe Attack Detection & Mitigation Orchestrator
#
# Integrates: Qsecbit, VictoriaMetrics, ClickHouse, NAPSE, ModSecurity
# Actions: Honeypot redirection, SNAT rules, Email alerts
#
# Author: HookProbe Team
# License: AGPL-3.0 - see LICENSE file
#

set -euo pipefail

# ============================================================
# CONFIGURATION
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/mitigation-config.conf"

# Load configuration
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "ERROR: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# ============================================================
# GLOBAL VARIABLES
# ============================================================
LOG_FILE="${LOG_DIR}/attack-mitigation.log"
ATTACK_DB="${STATE_DIR}/detected_attacks.db"
HONEYPOT_IPS_FILE="${STATE_DIR}/honeypot_redirects.txt"
BLOCKED_IPS_FILE="${STATE_DIR}/blocked_ips.txt"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Ensure directories exist
mkdir -p "$LOG_DIR" "$STATE_DIR" "$REPORT_DIR"

# ============================================================
# LOGGING FUNCTIONS
# ============================================================
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

log_warning() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $*" | tee -a "$LOG_FILE"
}

# ============================================================
# QSECBIT INTEGRATION
# ============================================================
get_qsecbit_status() {
    local qsecbit_data
    qsecbit_data=$(curl -s "${QSECBIT_API}/api/qsecbit/latest" || echo "{}")
    
    if [ -z "$qsecbit_data" ] || [ "$qsecbit_data" = "{}" ]; then
        log_error "Failed to fetch Qsecbit data"
        echo "UNKNOWN"
        return 1
    fi
    
    local rag_status=$(echo "$qsecbit_data" | jq -r '.rag_status // "UNKNOWN"')
    local score=$(echo "$qsecbit_data" | jq -r '.score // 0')
    
    log "Qsecbit Status: $rag_status (Score: $score)"
    echo "$rag_status"
}

should_activate_mitigation() {
    local rag_status="$1"
    
    if [ "$rag_status" = "RED" ] || [ "$rag_status" = "AMBER" ]; then
        return 0  # Activate
    else
        return 1  # Do not activate
    fi
}

# ============================================================
# LOG AGGREGATION FROM MULTIPLE SOURCES
# ============================================================
query_clickhouse() {
    local query="$1"

    # Execute ClickHouse query and return JSON results
    curl -s "${CLICKHOUSE_URL}/?query=$(echo "$query" | jq -sRr @uri)&default_format=JSONEachRow" || echo ""
}

query_victoriametrics() {
    local query="$1"
    
    curl -s "${VICTORIAMETRICS_URL}/api/v1/query" \
        -d "query=$query" | jq -r '.data.result[]' || echo ""
}

get_modsecurity_alerts() {
    # Parse ModSecurity audit logs
    local modsec_query='_exists_:modsecurity AND (severity:CRITICAL OR severity:ERROR)'
    query_victorialogs "$modsec_query" "5m"
}

# ============================================================
# ATTACK DETECTION & ANALYSIS
# ============================================================
detect_attacks() {
    log "Starting attack detection from all sources..."
    
    local attacks_detected=0
    local attack_report="${REPORT_DIR}/attack_report_${TIMESTAMP}.json"
    
    echo "{" > "$attack_report"
    echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$attack_report"
    echo "  \"qsecbit_status\": \"$(get_qsecbit_status)\"," >> "$attack_report"
    echo "  \"attacks\": [" >> "$attack_report"
    
    # 1. NAPSE handles network-based attack detection via its own event bus
    # Alerts are consumed through ClickHouse (see check #3 below)

    # 2. Check ModSecurity for web attacks
    log "Checking ModSecurity alerts..."
    local modsec_alerts=$(get_modsecurity_alerts)
    if [ -n "$modsec_alerts" ]; then
        while IFS= read -r alert; do
            local src_ip=$(echo "$alert" | jq -r '.client_ip // .remote_addr // empty')
            if [ -n "$src_ip" ]; then
                echo "    {\"source\": \"modsecurity\", \"ip\": \"$src_ip\", \"alert\": $alert}," >> "$attack_report"
                log "ModSecurity alert from IP: $src_ip"
                attacks_detected=$((attacks_detected + 1))
                echo "$src_ip" >> "${STATE_DIR}/temp_ips.txt"
            fi
        done <<< "$modsec_alerts"
    fi
    
    # 4. Check ClickHouse for application-level attacks
    log "Checking ClickHouse for attack patterns..."
    local ch_query="SELECT src_ip, attack_type, severity FROM security.security_events WHERE timestamp >= now() - INTERVAL 5 MINUTE AND (attack_type IN ('xss', 'sqli', 'cmd_injection', 'path_traversal') OR severity IN ('high', 'critical'))"
    local ch_results=$(query_clickhouse "$ch_query")
    if [ -n "$ch_results" ]; then
        while IFS= read -r result; do
            local src_ip=$(echo "$result" | jq -r '.src_ip // empty')
            if [ -n "$src_ip" ]; then
                echo "    {\"source\": \"clickhouse\", \"ip\": \"$src_ip\", \"event\": $result}," >> "$attack_report"
                log "ClickHouse attack pattern from IP: $src_ip"
                attacks_detected=$((attacks_detected + 1))
                echo "$src_ip" >> "${STATE_DIR}/temp_ips.txt"
            fi
        done <<< "$ch_results"
    fi
    
    echo "    {}" >> "$attack_report"
    echo "  ]," >> "$attack_report"
    echo "  \"total_attacks\": $attacks_detected" >> "$attack_report"
    echo "}" >> "$attack_report"
    
    log "Attack detection complete. Total attacks: $attacks_detected"
    
    # Deduplicate IPs
    if [ -f "${STATE_DIR}/temp_ips.txt" ]; then
        sort -u "${STATE_DIR}/temp_ips.txt" > "${STATE_DIR}/malicious_ips.txt"
        rm -f "${STATE_DIR}/temp_ips.txt"
    fi
    
    echo "$attack_report"
}

# ============================================================
# HONEYPOT MANAGEMENT
# ============================================================
create_honeypot_container() {
    log "Creating honeypot container..."
    
    # Check if honeypot already exists
    if podman ps -a --format "{{.Names}}" | grep -q "^hookprobe-honeypot$"; then
        log "Honeypot container already exists"
        
        # Ensure it's running
        if ! podman ps --format "{{.Names}}" | grep -q "^hookprobe-honeypot$"; then
            podman start hookprobe-honeypot
            log "Started existing honeypot container"
        fi
        return 0
    fi
    
    # Create honeypot container with cowrie (SSH/Telnet honeypot)
    podman run -d --restart always \
        --name hookprobe-honeypot \
        --network pod \
        -p ${HONEYPOT_SSH_PORT}:2222 \
        -p ${HONEYPOT_TELNET_PORT}:2223 \
        -p ${HONEYPOT_HTTP_PORT}:8080 \
        -v hookprobe-honeypot-logs:/cowrie/var/log/cowrie \
        cowrie/cowrie:latest || {
            log_error "Failed to create honeypot container"
            return 1
        }
    
    log "Honeypot container created successfully"
    return 0
}

redirect_ip_to_honeypot() {
    local malicious_ip="$1"
    
    # Validate IP
    if ! [[ "$malicious_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address: $malicious_ip"
        return 1
    fi
    
    # Check if already redirected
    if grep -q "^$malicious_ip$" "$HONEYPOT_IPS_FILE" 2>/dev/null; then
        log "IP $malicious_ip already redirected to honeypot"
        return 0
    fi
    
    # Create SNAT rule to redirect to honeypot
    log "Creating SNAT rule for IP: $malicious_ip -> Honeypot"
    
    # Redirect SSH traffic
    iptables -t nat -A PREROUTING -s "$malicious_ip" -p tcp --dport 22 \
        -j DNAT --to-destination "${HONEYPOT_IP}:${HONEYPOT_SSH_PORT}" || {
        log_error "Failed to create SSH SNAT rule for $malicious_ip"
        return 1
    }
    
    # Redirect HTTP traffic
    iptables -t nat -A PREROUTING -s "$malicious_ip" -p tcp --dport 80 \
        -j DNAT --to-destination "${HONEYPOT_IP}:${HONEYPOT_HTTP_PORT}" || {
        log_error "Failed to create HTTP SNAT rule for $malicious_ip"
        return 1
    }
    
    # Redirect HTTPS traffic
    iptables -t nat -A PREROUTING -s "$malicious_ip" -p tcp --dport 443 \
        -j DNAT --to-destination "${HONEYPOT_IP}:${HONEYPOT_HTTP_PORT}" || {
        log_error "Failed to create HTTPS SNAT rule for $malicious_ip"
        return 1
    }
    
    # Log the redirection
    echo "$malicious_ip" >> "$HONEYPOT_IPS_FILE"
    
    log "Successfully redirected $malicious_ip to honeypot"
    return 0
}

# ============================================================
# IP BLOCKING
# ============================================================
block_ip() {
    local malicious_ip="$1"
    
    # Validate IP
    if ! [[ "$malicious_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address: $malicious_ip"
        return 1
    fi
    
    # Check if already blocked
    if grep -q "^$malicious_ip$" "$BLOCKED_IPS_FILE" 2>/dev/null; then
        log "IP $malicious_ip already blocked"
        return 0
    fi
    
    # Block the IP
    log "Blocking IP: $malicious_ip"
    
    iptables -I INPUT -s "$malicious_ip" -j DROP || {
        log_error "Failed to block IP: $malicious_ip"
        return 1
    }
    
    # Log the block
    echo "$malicious_ip" >> "$BLOCKED_IPS_FILE"
    
    log "Successfully blocked IP: $malicious_ip"
    return 0
}

# ============================================================
# MITIGATION DECISION ENGINE
# ============================================================
execute_mitigation() {
    local malicious_ip="$1"
    local attack_severity="$2"  # LOW, MEDIUM, HIGH, CRITICAL
    
    log "Executing mitigation for IP: $malicious_ip (Severity: $attack_severity)"
    
    case "$attack_severity" in
        CRITICAL|HIGH)
            # Severe attacks: Block immediately
            block_ip "$malicious_ip"
            ;;
        MEDIUM)
            # Medium severity: Redirect to honeypot
            if [ "$ENABLE_HONEYPOT" = "true" ]; then
                redirect_ip_to_honeypot "$malicious_ip"
            else
                block_ip "$malicious_ip"
            fi
            ;;
        LOW)
            # Low severity: Redirect to honeypot for analysis
            if [ "$ENABLE_HONEYPOT" = "true" ]; then
                redirect_ip_to_honeypot "$malicious_ip"
            else
                log "Low severity attack from $malicious_ip - monitoring only"
            fi
            ;;
        *)
            log_warning "Unknown severity level: $attack_severity for IP: $malicious_ip"
            ;;
    esac
}

classify_attack_severity() {
    local attack_count="$1"
    
    if [ "$attack_count" -ge 10 ]; then
        echo "CRITICAL"
    elif [ "$attack_count" -ge 5 ]; then
        echo "HIGH"
    elif [ "$attack_count" -ge 2 ]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# ============================================================
# EMAIL NOTIFICATION
# ============================================================
send_email_notification() {
    local subject="$1"
    local body="$2"
    local attachment="$3"
    
    log "Sending email notification to: $NOTIFICATION_EMAIL"
    
    if [ -z "$attachment" ]; then
        echo "$body" | mail -s "$subject" "$NOTIFICATION_EMAIL" || {
            log_error "Failed to send email notification"
            return 1
        }
    else
        echo "$body" | mail -s "$subject" -A "$attachment" "$NOTIFICATION_EMAIL" || {
            log_error "Failed to send email notification with attachment"
            return 1
        }
    fi
    
    log "Email notification sent successfully"
    return 0
}

create_incident_email() {
    local attack_report="$1"
    local rag_status="$2"
    
    local total_attacks=$(jq -r '.total_attacks' "$attack_report")
    local timestamp=$(jq -r '.timestamp' "$attack_report")
    
    cat << EOF
HookProbe Security Alert - Attack Detected
=============================================

Timestamp: $timestamp
Qsecbit Status: $rag_status
Total Attacks Detected: $total_attacks

INCIDENT SUMMARY:
-----------------
Multiple attack patterns have been detected by HookProbe's security systems.
The Qsecbit AI analysis engine has classified the current threat level as: $rag_status

ACTIONS TAKEN:
--------------
- Malicious IPs identified and catalogued
- Automatic mitigation initiated
- Honeypot redirection activated (if enabled)
- IP blocking applied for critical threats
- Detailed attack report attached

NEXT STEPS:
-----------
1. Review the attached attack report
2. Analyze honeypot logs for attacker behavior
3. Update WAF rules based on attack patterns
4. Review and adjust Qsecbit thresholds if needed

ATTACK REPORT:
--------------
$(cat "$attack_report")

=============================================
This is an automated message from HookProbe Security System.
For questions, contact: qsecbit@hookprobe.com
EOF
}

# ============================================================
# MAIN ORCHESTRATION LOOP
# ============================================================
main() {
    log "=========================================="
    log "HookProbe Attack Mitigation Orchestrator"
    log "=========================================="
    
    # 1. Check Qsecbit status
    local rag_status=$(get_qsecbit_status)
    
    if ! should_activate_mitigation "$rag_status"; then
        log "Qsecbit status is GREEN - no mitigation needed"
        exit 0
    fi
    
    log "⚠️  Qsecbit status is $rag_status - activating mitigation protocols"
    
    # 2. Create/ensure honeypot is running
    if [ "$ENABLE_HONEYPOT" = "true" ]; then
        create_honeypot_container
    fi
    
    # 3. Detect attacks from all sources
    local attack_report=$(detect_attacks)
    
    if [ ! -f "$attack_report" ]; then
        log_error "Attack report not generated"
        exit 1
    fi
    
    local total_attacks=$(jq -r '.total_attacks' "$attack_report")
    
    if [ "$total_attacks" -eq 0 ]; then
        log "No attacks detected in current scan"
        exit 0
    fi
    
    log "🚨 Total attacks detected: $total_attacks"
    
    # 4. Process each malicious IP
    if [ -f "${STATE_DIR}/malicious_ips.txt" ]; then
        while IFS= read -r malicious_ip; do
            # Count attacks from this IP
            local ip_attack_count=$(grep -c "$malicious_ip" "$attack_report" || echo "1")
            
            # Classify severity
            local severity=$(classify_attack_severity "$ip_attack_count")
            
            # Execute mitigation
            execute_mitigation "$malicious_ip" "$severity"
        done < "${STATE_DIR}/malicious_ips.txt"
    fi
    
    # 5. Send email notification
    local email_body=$(create_incident_email "$attack_report" "$rag_status")
    send_email_notification \
        "🚨 HookProbe Security Alert - $rag_status Status - $total_attacks Attacks Detected" \
        "$email_body" \
        "$attack_report"
    
    # 6. Update Qsecbit with mitigation status
    curl -s -X POST "${QSECBIT_API}/api/mitigation/complete" \
        -H "Content-Type: application/json" \
        -d "{
            \"timestamp\": \"$(date -Iseconds)\",
            \"total_attacks\": $total_attacks,
            \"rag_status\": \"$rag_status\",
            \"report_path\": \"$attack_report\"
        }" || log_warning "Failed to update Qsecbit with mitigation status"
    
    log "=========================================="
    log "Attack mitigation cycle complete"
    log "=========================================="
}

# Run main function
main "$@"
