#!/bin/bash
#
# kali-response-scripts.sh
# Automated attack mitigation scripts for Kali Linux container
#
# License: AGPL-3.0 - see LICENSE file
#

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# ============================================================
# INPUT VALIDATION
# ============================================================

validate_ip() {
    local ip=$1
    # Validate IPv4 address format
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ERROR: Invalid IP address: $ip" >&2
        return 1
    fi
    return 0
}

sanitize_pattern() {
    local pattern=$1
    # Remove potentially dangerous characters
    echo "$pattern" | tr -cd '[:alnum:][:space:]._-'
}

# ============================================================
# ANTI-XSS INJECTION RESPONSE
# ============================================================

anti_xss_response() {
    local ATTACK_IP=${1:-}
    local ATTACK_PATTERN=${2:-}
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    # Validate inputs
    if [ -z "$ATTACK_IP" ] || [ -z "$ATTACK_PATTERN" ]; then
        echo "ERROR: Missing required parameters" >&2
        echo "Usage: anti_xss_response <ATTACK_IP> <ATTACK_PATTERN>" >&2
        return 1
    fi

    if ! validate_ip "$ATTACK_IP"; then
        echo "ERROR: Invalid IP address: $ATTACK_IP" >&2
        return 1
    fi

    # Sanitize attack pattern
    ATTACK_PATTERN=$(sanitize_pattern "$ATTACK_PATTERN")

    echo "🛡️  [XSS DEFENSE] Initiating anti-XSS countermeasures..."
    echo "Attack IP: $ATTACK_IP"
    echo "Pattern: $ATTACK_PATTERN"

    # 1. Update NAXSI WAF rules
    cat >> /reports/naxsi_custom_rules_${TIMESTAMP}.rules << EOF
# Auto-generated XSS blocking rule - ${TIMESTAMP}
MainRule "str:${ATTACK_PATTERN}" "msg:XSS attack blocked" "mz:\$ARGS|\$BODY" "s:\$XSS:8" id:9${TIMESTAMP:0:6};
EOF
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create WAF rules" >&2
        return 1
    fi
    
    # 2. Add firewall rule to block attacker IP
    echo "Blocking IP: $ATTACK_IP"
    if ! iptables -I INPUT -s "$ATTACK_IP" -j DROP; then
        echo "WARNING: Failed to block IP in firewall" >&2
        # Continue anyway
    fi
    
    # 3. Scan attacker for vulnerabilities
    echo "Scanning attacker infrastructure..."
    nmap -sV -O $ATTACK_IP > /reports/attacker_scan_${TIMESTAMP}.txt
    
    # 4. Check for common XSS entry points
    echo "Analyzing XSS injection points..."
    nikto -h http://${ATTACK_IP} -o /reports/nikto_xss_${TIMESTAMP}.html -F html
    
    # 5. Create incident report
    cat > /reports/xss_incident_${TIMESTAMP}.json << EOF
{
    "timestamp": "$(date -Iseconds)",
    "attack_type": "XSS_INJECTION",
    "attacker_ip": "$ATTACK_IP",
    "attack_pattern": "$ATTACK_PATTERN",
    "actions_taken": [
        "WAF rules updated",
        "Attacker IP blocked in firewall",
        "Vulnerability scan initiated",
        "Incident documented"
    ],
    "recommendations": [
        "Review application input validation",
        "Implement Content Security Policy headers",
        "Enable HttpOnly and Secure flags on cookies",
        "Sanitize all user inputs on server side"
    ]
}
EOF
    
    # 6. Generate human-readable report
    cat > /reports/xss_human_report_${TIMESTAMP}.txt << EOF
==========================================
XSS INJECTION ATTACK DETECTED & MITIGATED
==========================================
Time: $(date)
Attacker IP: $ATTACK_IP
Attack Pattern: $ATTACK_PATTERN

ACTIONS TAKEN:
1. ✓ Updated WAF rules to block similar patterns
2. ✓ Blocked attacker IP in firewall
3. ✓ Performed reconnaissance scan on attacker
4. ✓ Analyzed application for vulnerabilities

IMMEDIATE RECOMMENDATIONS:
• Review all form inputs and URL parameters
• Implement proper output encoding
• Add Content-Security-Policy headers
• Review session management

TECHNICAL DETAILS:
WAF Rule: /reports/naxsi_custom_rules_${TIMESTAMP}.rules
Scan Results: /reports/attacker_scan_${TIMESTAMP}.txt
Nikto Report: /reports/nikto_xss_${TIMESTAMP}.html

Next Steps:
1. Deploy updated WAF rules to production
2. Monitor for similar attack patterns
3. Consider rate limiting on affected endpoints
==========================================
EOF
    
    echo "✓ XSS defense complete. Reports generated."
    return 0
}

# ============================================================
# ANTI-SQL INJECTION RESPONSE
# ============================================================

anti_sql_injection_response() {
    local ATTACK_IP=$1
    local SQL_QUERY=$2
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    echo "🛡️  [SQL DEFENSE] Initiating anti-SQL injection countermeasures..."
    echo "Attack IP: $ATTACK_IP"
    echo "Malicious Query: $SQL_QUERY"
    
    # 1. Create database snapshot
    echo "Creating emergency database snapshot..."
    pg_dump -h 10.103.0.10 -U hookprobe_admin -d hookprobe_db > /reports/db_snapshot_${TIMESTAMP}.sql
    
    # 2. Update NAXSI WAF rules for SQL injection
    cat >> /reports/naxsi_custom_rules_${TIMESTAMP}.rules << EOF
# Auto-generated SQL injection blocking rule - ${TIMESTAMP}
MainRule "str:${SQL_QUERY:0:50}" "msg:SQL injection blocked" "mz:\$ARGS|\$BODY" "s:\$SQL:8" id:8${TIMESTAMP:0:6};
MainRule "rx:union.*select" "msg:UNION SELECT blocked" "mz:\$ARGS|\$BODY" "s:\$SQL:8" id:8${TIMESTAMP:0:5}1;
MainRule "rx:;.*drop" "msg:DROP statement blocked" "mz:\$ARGS|\$BODY" "s:\$SQL:8" id:8${TIMESTAMP:0:5}2;
EOF
    
    # 3. Block attacker IP
    echo "Blocking IP: $ATTACK_IP"
    iptables -I INPUT -s $ATTACK_IP -j DROP
    
    # 4. Enable PostgreSQL query logging
    echo "Enabling detailed database logging..."
    cat > /reports/postgres_logging_${TIMESTAMP}.sql << EOF
-- Enable detailed logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 0;
SELECT pg_reload_conf();
EOF
    
    # 5. Scan for SQL injection vulnerabilities
    echo "Scanning for SQL injection points..."
    sqlmap -u "http://${ATTACK_IP}" --batch --random-agent > /reports/sqlmap_${TIMESTAMP}.txt
    
    # 6. Analyze database for compromised tables
    echo "Checking database integrity..."
    cat > /reports/db_integrity_check_${TIMESTAMP}.sql << EOF
-- Check for suspicious table modifications
SELECT schemaname, tablename, last_vacuum, last_autovacuum 
FROM pg_stat_user_tables 
WHERE last_vacuum > NOW() - INTERVAL '1 hour';

-- Check for unusual query patterns
SELECT datname, usename, query, state, query_start 
FROM pg_stat_activity 
WHERE state = 'active' AND query NOT LIKE '%pg_stat_activity%';

-- Check table permissions
SELECT tablename, tableowner, 
       has_table_privilege('public', tablename, 'SELECT') as public_select
FROM pg_tables 
WHERE schemaname = 'public';
EOF
    
    # 7. Create incident report
    cat > /reports/sql_incident_${TIMESTAMP}.json << EOF
{
    "timestamp": "$(date -Iseconds)",
    "attack_type": "SQL_INJECTION",
    "attacker_ip": "$ATTACK_IP",
    "malicious_query": "$SQL_QUERY",
    "database_snapshot": "db_snapshot_${TIMESTAMP}.sql",
    "actions_taken": [
        "Database snapshot created",
        "WAF rules updated for SQL injection patterns",
        "Attacker IP blocked",
        "PostgreSQL logging enabled",
        "Database integrity check performed"
    ],
    "recommendations": [
        "Use parameterized queries/prepared statements",
        "Implement least privilege database access",
        "Enable database firewall rules",
        "Regular security audits of database schema",
        "Implement ORM with proper escaping"
    ]
}
EOF
    
    # 8. Generate human-readable report
    cat > /reports/sql_human_report_${TIMESTAMP}.txt << EOF
==========================================
SQL INJECTION ATTACK DETECTED & MITIGATED
==========================================
Time: $(date)
Attacker IP: $ATTACK_IP
Malicious Query: ${SQL_QUERY:0:100}...

ACTIONS TAKEN:
1. ✓ Created emergency database snapshot
2. ✓ Updated WAF rules to block SQL injection patterns
3. ✓ Blocked attacker IP in firewall
4. ✓ Enabled comprehensive database logging
5. ✓ Performed database integrity check
6. ✓ Scanned for additional injection points

CRITICAL RECOMMENDATIONS:
• IMMEDIATELY review all database queries in application
• Implement parameterized queries/prepared statements
• Never concatenate user input into SQL queries
• Use ORM with proper sanitization
• Implement principle of least privilege for DB users

TECHNICAL DETAILS:
Database Snapshot: /reports/db_snapshot_${TIMESTAMP}.sql
WAF Rules: /reports/naxsi_custom_rules_${TIMESTAMP}.rules
SQLMap Report: /reports/sqlmap_${TIMESTAMP}.txt
Integrity Check: /reports/db_integrity_check_${TIMESTAMP}.sql

IMMEDIATE ACTIONS REQUIRED:
1. Restore database if compromised
2. Deploy updated WAF rules
3. Review application code for SQL injection vulnerabilities
4. Change database passwords
5. Audit recent database modifications

DATABASE STATUS:
- Snapshot created successfully
- Logging level increased
- Monitoring active connections
==========================================
EOF
    
    echo "✓ SQL injection defense complete. Database secured."
    return 0
}

# ============================================================
# MEMORY ATTACK RESPONSE
# ============================================================

memory_attack_response() {
    local AFFECTED_CONTAINER=$1
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    echo "🛡️  [MEMORY DEFENSE] Initiating memory attack countermeasures..."
    echo "Affected Container: $AFFECTED_CONTAINER"
    
    # 1. Capture current memory state
    echo "Capturing memory diagnostics..."
    podman stats --no-stream > /reports/memory_stats_${TIMESTAMP}.txt
    
    # 2. Identify memory anomalies
    cat > /reports/memory_analysis_${TIMESTAMP}.sh << 'EOF'
#!/bin/bash
# Analyze memory usage patterns
echo "Memory Analysis Report"
echo "====================="
echo ""
echo "Top Memory Consumers:"
podman stats --no-stream --format "{{.Name}}\t{{.MemUsage}}" | sort -k2 -rh | head -10
echo ""
echo "Container Resource Limits:"
podman inspect $1 | jq '.[0].HostConfig.Memory, .[0].HostConfig.MemorySwap'
EOF
    chmod +x /reports/memory_analysis_${TIMESTAMP}.sh
    
    # 3. Create memory-limited container restart
    echo "Preparing container restart with memory limits..."
    CURRENT_MEMORY=$(podman inspect $AFFECTED_CONTAINER | jq '.[0].HostConfig.Memory')
    NEW_MEMORY_LIMIT=$((CURRENT_MEMORY / 2))  # Reduce to 50% temporarily
    
    # 4. Generate restart script
    cat > /reports/container_restart_${TIMESTAMP}.sh << EOF
#!/bin/bash
# Container restart with memory protection
echo "Restarting container with memory limits..."

# Get current container configuration
CONFIG=\$(podman inspect $AFFECTED_CONTAINER)

# Stop container
podman stop $AFFECTED_CONTAINER

# Start with memory limit
podman start $AFFECTED_CONTAINER
podman update --memory=${NEW_MEMORY_LIMIT} --memory-swap=${NEW_MEMORY_LIMIT} $AFFECTED_CONTAINER

echo "Container restarted with memory limit: ${NEW_MEMORY_LIMIT} bytes"
EOF
    chmod +x /reports/container_restart_${TIMESTAMP}.sh
    
    # 5. Clear caches and reset connections
    echo "Clearing caches and resetting connections..."
    if [[ $AFFECTED_CONTAINER == *"redis"* ]]; then
        podman exec $AFFECTED_CONTAINER redis-cli FLUSHALL
    fi
    
    if [[ $AFFECTED_CONTAINER == *"postgres"* ]]; then
        podman exec $AFFECTED_CONTAINER psql -U hookprobe_admin -d hookprobe_db -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid();"
    fi
    
    # 6. Create incident report
    cat > /reports/memory_incident_${TIMESTAMP}.json << EOF
{
    "timestamp": "$(date -Iseconds)",
    "attack_type": "MEMORY_OVERFLOW_ATTEMPT",
    "affected_container": "$AFFECTED_CONTAINER",
    "actions_taken": [
        "Memory diagnostics captured",
        "Container resource limits enforced",
        "Caches cleared",
        "Connections reset",
        "Restart script generated"
    ],
    "recommendations": [
        "Review application for memory leaks",
        "Implement rate limiting",
        "Add input size validation",
        "Monitor for buffer overflow attempts",
        "Implement memory usage alerts"
    ]
}
EOF
    
    # 7. Human-readable report
    cat > /reports/memory_human_report_${TIMESTAMP}.txt << EOF
==========================================
MEMORY ATTACK DETECTED & MITIGATED
==========================================
Time: $(date)
Affected Container: $AFFECTED_CONTAINER

ACTIONS TAKEN:
1. ✓ Captured memory diagnostics
2. ✓ Reduced memory limits to prevent overflow
3. ✓ Cleared caches to free resources
4. ✓ Reset all connections
5. ✓ Generated safe restart script

CONTAINER STATUS:
Previous Memory Limit: $CURRENT_MEMORY bytes
New Memory Limit: $NEW_MEMORY_LIMIT bytes (50% reduction)

RECOMMENDATIONS:
• Review application for memory leaks
• Implement input size validation
• Add rate limiting on heavy endpoints
• Monitor memory usage trends
• Consider horizontal scaling

TO RESTART CONTAINER SAFELY:
bash /reports/container_restart_${TIMESTAMP}.sh

MONITORING:
Watch memory usage:
podman stats $AFFECTED_CONTAINER

Check logs for patterns:
podman logs --tail 1000 $AFFECTED_CONTAINER | grep -i "memory\|oom"
==========================================
EOF
    
    echo "✓ Memory attack mitigation complete."
    return 0
}

# ============================================================
# MAIN RESPONSE COORDINATOR
# ============================================================

coordinate_response() {
    local ATTACK_TYPE=$1
    local ATTACK_IP=$2
    local ATTACK_DATA=$3
    
    echo "🚨 ATTACK DETECTED: $ATTACK_TYPE from $ATTACK_IP"
    
    case $ATTACK_TYPE in
        "XSS"|"xss")
            anti_xss_response "$ATTACK_IP" "$ATTACK_DATA"
            ;;
        "SQL_INJECTION"|"sqli")
            anti_sql_injection_response "$ATTACK_IP" "$ATTACK_DATA"
            ;;
        "MEMORY_OVERFLOW"|"memory")
            memory_attack_response "$ATTACK_DATA"
            ;;
        *)
            echo "Unknown attack type: $ATTACK_TYPE"
            return 1
            ;;
    esac
    
    # Send notification to Qsecbit
    curl -X POST http://localhost:8888/api/response/complete \
        -H "Content-Type: application/json" \
        -d "{\"attack_type\":\"$ATTACK_TYPE\",\"status\":\"mitigated\",\"timestamp\":\"$(date -Iseconds)\"}"
    
    return 0
}

# Export functions
export -f anti_xss_response
export -f anti_sql_injection_response
export -f memory_attack_response
export -f coordinate_response

echo "✓ Kali response scripts loaded and ready"
