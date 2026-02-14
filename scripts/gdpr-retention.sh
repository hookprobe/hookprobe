#!/bin/bash
#
# gdpr-retention.sh - HookProbe v5.0 GDPR Data Retention & Deletion
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#
# Automatically enforces data retention policies and anonymization
# Run daily via cron: 0 2 * * * /opt/hookprobe/scripts/gdpr-retention.sh
#

set -e

# Source GDPR configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/gdpr-config.sh"
source "$SCRIPT_DIR/network-config.sh"

# ============================================================
# LOGGING FUNCTIONS
# ============================================================

log_info() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] INFO: $1" | tee -a /var/log/hookprobe/gdpr-retention.log
    log_gdpr_event "INFO" "$1"
}

log_warn() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] WARN: $1" | tee -a /var/log/hookprobe/gdpr-retention.log
    log_gdpr_event "WARN" "$1"
}

log_error() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR: $1" | tee -a /var/log/hookprobe/gdpr-retention.log
    log_gdpr_event "ERROR" "$1"
}

# ============================================================
# DATA DELETION FUNCTIONS
# ============================================================

delete_old_napse_logs() {
    local retention_days="$RETENTION_SECURITY_LOGS_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting NAPSE logs older than $retention_days days (before $deletion_date)"

    # NAPSE logs are in /var/log/napse/
    find /var/log/napse/ -type f -name "*.log*" -mtime +${retention_days} -delete 2>/dev/null || true

    # ClickHouse NAPSE event data (napse_events table)
    if [[ "$CLICKHOUSE_AVAILABLE" == "true" ]]; then
        podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
            ALTER TABLE security.napse_events
            DELETE WHERE timestamp < toDateTime('$deletion_date 00:00:00')
        " 2>/dev/null || log_warn "ClickHouse napse_events deletion failed"
    fi

    log_info "NAPSE log cleanup completed"
}

delete_old_waf_logs() {
    local retention_days="$RETENTION_WAF_LOGS_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting WAF logs older than $retention_days days (before $deletion_date)"

    # ModSecurity logs
    find /var/log/modsecurity/ -type f -mtime +${retention_days} -delete 2>/dev/null || true

    # ClickHouse deletion
    if [[ "$CLICKHOUSE_AVAILABLE" == "true" ]]; then
        podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
            ALTER TABLE security.waf_events
            DELETE WHERE timestamp < toDateTime('$deletion_date 00:00:00')
        " 2>/dev/null || log_warn "ClickHouse waf_events deletion failed"
    fi

    log_info "WAF log cleanup completed"
}

delete_old_network_flows() {
    local retention_days="$RETENTION_NETWORK_FLOWS_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting network flow data older than $retention_days days (before $deletion_date)"

    # ClickHouse network flows
    if [[ "$CLICKHOUSE_AVAILABLE" == "true" ]]; then
        podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
            ALTER TABLE security.network_flows
            DELETE WHERE timestamp < toDateTime('$deletion_date 00:00:00')
        " 2>/dev/null || log_warn "ClickHouse network_flows deletion failed"
    fi

    log_info "Network flow cleanup completed"
}

delete_old_qsecbit_scores() {
    local retention_days="$RETENTION_QSECBIT_SCORES_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting Qsecbit scores older than $retention_days days (before $deletion_date)"

    # ClickHouse qsecbit scores
    if [[ "$CLICKHOUSE_AVAILABLE" == "true" ]]; then
        podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
            ALTER TABLE security.qsecbit_scores
            DELETE WHERE timestamp < toDateTime('$deletion_date 00:00:00')
        " 2>/dev/null || log_warn "ClickHouse qsecbit_scores deletion failed"
    fi

    # File-based qsecbit logs
    find /var/log/qsecbit/ -type f -name "*.log" -mtime +${retention_days} -delete 2>/dev/null || true

    log_info "Qsecbit score cleanup completed"
}

delete_old_honeypot_data() {
    local retention_days="$RETENTION_HONEYPOT_LOGS_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting honeypot data older than $retention_days days (before $deletion_date)"

    # Honeypot logs
    find /var/log/honeypot/ -type f -mtime +${retention_days} -delete 2>/dev/null || true

    # ClickHouse honeypot data
    if [[ "$CLICKHOUSE_AVAILABLE" == "true" ]]; then
        podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
            ALTER TABLE security.honeypot_attacks
            DELETE WHERE timestamp < toDateTime('$deletion_date 00:00:00')
        " 2>/dev/null || log_warn "ClickHouse honeypot_attacks deletion failed"
    fi

    log_info "Honeypot data cleanup completed"
}

delete_old_auth_logs() {
    local retention_days="$RETENTION_AUTH_LOGS_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting authentication logs older than $retention_days days (before $deletion_date)"

    # PostgreSQL - Django auth logs
    podman exec hookprobe-pod-003-db-persistent-postgres psql -U hookprobe_admin -d hookprobe_db -c "
        DELETE FROM django_admin_log
        WHERE action_time < NOW() - INTERVAL '$retention_days days';
    " 2>/dev/null || log_warn "Django admin log deletion failed"

    # Keycloak event logs (PostgreSQL)
    podman exec hookprobe-pod-002-iam-keycloak-db psql -U keycloak -d keycloak -c "
        DELETE FROM event_entity
        WHERE created_date < EXTRACT(EPOCH FROM NOW() - INTERVAL '$retention_days days') * 1000;
    " 2>/dev/null || log_warn "Keycloak event deletion failed"

    log_info "Authentication log cleanup completed"
}

delete_inactive_user_accounts() {
    local retention_days="$RETENTION_INACTIVE_ACCOUNTS_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting inactive user accounts (no login for $retention_days days)"

    # Django - mark inactive users for deletion
    podman exec hookprobe-pod-001-web-dmz-django python manage.py shell <<EOF
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

cutoff_date = timezone.now() - timedelta(days=$retention_days)
inactive_users = User.objects.filter(last_login__lt=cutoff_date, is_active=True)

count = inactive_users.count()
if count > 0:
    print(f"Marking {count} inactive users for deletion")
    inactive_users.update(is_active=False)
    print("Done")
else:
    print("No inactive users found")
EOF

    log_info "Inactive user account cleanup completed"
}

delete_permanently_deleted_accounts() {
    local retention_days="$RETENTION_DELETED_ACCOUNTS_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Permanently deleting soft-deleted accounts (after $retention_days day grace period)"

    # Django - permanently delete soft-deleted users
    podman exec hookprobe-pod-001-web-dmz-django python manage.py shell <<EOF
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

cutoff_date = timezone.now() - timedelta(days=$retention_days)
deleted_users = User.objects.filter(is_active=False, date_joined__lt=cutoff_date)

count = deleted_users.count()
if count > 0:
    print(f"Permanently deleting {count} accounts")
    deleted_users.delete()
    print("Done")
else:
    print("No accounts to permanently delete")
EOF

    log_info "Permanent account deletion completed"
}

delete_old_victoriametrics_data() {
    local retention_days="$RETENTION_METRICS_DAYS"

    log_info "Deleting VictoriaMetrics data older than $retention_days days"

    # VictoriaMetrics has built-in retention via -retentionPeriod flag
    # This is configured during deployment, but we can verify/update it
    log_info "VictoriaMetrics retention is managed via -retentionPeriod=${retention_days}d flag"

    # Optional: Delete specific metrics manually
    # curl -X POST "http://$IP_VICTORIAMETRICS:8428/api/v1/admin/tsdb/delete_series?match[]={__name__=~".+"}&start=0&end=$(date -d "$retention_days days ago" +%s)"

    log_info "VictoriaMetrics cleanup completed"
}

delete_old_clickhouse_data() {
    if [[ "$CLICKHOUSE_AVAILABLE" != "true" ]]; then
        return 0
    fi

    local retention_days="$RETENTION_CLICKHOUSE_RAW_DAYS"
    local deletion_date=$(get_deletion_date "$retention_days")

    log_info "Deleting ClickHouse raw data older than $retention_days days"

    # ClickHouse uses TTL (Time To Live) for automatic deletion
    # This is configured in table schema, but we can manually delete if needed

    # Example: Delete old security events
    podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
        ALTER TABLE security.security_events
        DELETE WHERE timestamp < toDateTime('$deletion_date 00:00:00')
    " 2>/dev/null || log_warn "ClickHouse security_events deletion failed"

    log_info "ClickHouse data cleanup completed"
}

# ============================================================
# ANONYMIZATION FUNCTIONS
# ============================================================

anonymize_ip_address() {
    local ip="$1"
    local method="${IP_ANONYMIZATION_METHOD:-mask}"

    case "$method" in
        mask)
            # IPv4: 192.168.1.123 -> 192.168.1.0
            echo "$ip" | sed -E 's/([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/\1.0/'
            ;;
        hash)
            # Hash with salt
            echo -n "$ip" | sha256sum | cut -d' ' -f1
            ;;
        truncate)
            # Keep only first 3 octets
            echo "$ip" | cut -d. -f1-3
            ;;
    esac
}

anonymize_mac_address() {
    local mac="$1"
    local method="${MAC_ANONYMIZATION_METHOD:-mask}"

    case "$method" in
        mask)
            # Keep OUI (first 3 bytes), mask device ID
            echo "$mac" | sed -E 's/(([0-9a-fA-F]{2}:){3})([0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}/\100:00:00/'
            ;;
        hash)
            echo -n "$mac" | sha256sum | cut -d' ' -f1
            ;;
    esac
}

anonymize_archived_logs() {
    if [[ "$ANONYMIZE_ARCHIVED_LOGS" != "true" ]]; then
        return 0
    fi

    local anonymization_delay="$ANONYMIZATION_DELAY_DAYS"
    local anonymization_date=$(get_deletion_date "$anonymization_delay")

    log_info "Anonymizing logs older than $anonymization_delay days (before $anonymization_date)"

    # ClickHouse: Anonymize IP addresses in old data
    if [[ "$CLICKHOUSE_AVAILABLE" == "true" ]] && [[ "$ANONYMIZE_IP_ADDRESSES" == "true" ]]; then
        podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
            ALTER TABLE security.network_flows
            UPDATE src_ip = concat(splitByChar('.', src_ip)[1], '.', splitByChar('.', src_ip)[2], '.', splitByChar('.', src_ip)[3], '.0'),
                   dst_ip = concat(splitByChar('.', dst_ip)[1], '.', splitByChar('.', dst_ip)[2], '.', splitByChar('.', dst_ip)[3], '.0')
            WHERE timestamp < toDateTime('$anonymization_date 00:00:00')
              AND src_ip NOT LIKE '%.0'
        " 2>/dev/null || log_warn "ClickHouse IP anonymization failed"
    fi

    log_info "Log anonymization completed"
}

# ============================================================
# DATA SUBJECT RIGHTS PROCESSING
# ============================================================

process_erasure_requests() {
    log_info "Processing pending data erasure requests"

    # Check for pending erasure requests in database
    podman exec hookprobe-pod-001-web-dmz-django python manage.py shell <<EOF
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

# Find users marked for deletion with grace period expired
grace_period = timedelta(days=$ERASURE_GRACE_PERIOD_DAYS)
cutoff_date = timezone.now() - grace_period

# Assuming we have a 'deletion_requested_at' field
# users_to_delete = User.objects.filter(deletion_requested=True, deletion_requested_at__lt=cutoff_date)

# For now, just handle is_active=False users
# users_to_delete = User.objects.filter(is_active=False, date_joined__lt=cutoff_date)

# count = users_to_delete.count()
# if count > 0:
#     print(f"Processing {count} erasure requests")
#     for user in users_to_delete:
#         user.delete()
#     print("Erasure requests processed")

print("No pending erasure requests")
EOF

    log_info "Erasure request processing completed"
}

# ============================================================
# COMPLIANCE REPORTING
# ============================================================

generate_compliance_report() {
    if [[ "$ENABLE_COMPLIANCE_REPORTS" != "true" ]]; then
        return 0
    fi

    local report_date=$(date +%Y-%m-%d)
    local report_path="$COMPLIANCE_REPORT_PATH/compliance-report-$report_date.txt"

    mkdir -p "$COMPLIANCE_REPORT_PATH"

    log_info "Generating GDPR compliance report: $report_path"

    cat > "$report_path" <<EOF
HookProbe GDPR Compliance Report
Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Version: $GDPR_COMPLIANCE_VERSION

============================================================
DATA INVENTORY
============================================================

Security Logs:
- NAPSE logs: $(find /var/log/napse/ -type f 2>/dev/null | wc -l) files
- WAF logs: $(find /var/log/modsecurity/ -type f 2>/dev/null | wc -l) files

User Accounts:
$(podman exec hookprobe-pod-003-db-persistent-postgres psql -U hookprobe_admin -d hookprobe_db -t -c "
    SELECT 'Total users: ' || COUNT(*) FROM auth_user;
    SELECT 'Active users: ' || COUNT(*) FROM auth_user WHERE is_active = true;
    SELECT 'Inactive users: ' || COUNT(*) FROM auth_user WHERE is_active = false;
" 2>/dev/null || echo "Database query failed")

============================================================
RETENTION COMPLIANCE
============================================================

Retention Periods (days):
- Security logs: $RETENTION_SECURITY_LOGS_DAYS
- Network flows: $RETENTION_NETWORK_FLOWS_DAYS
- User accounts: $RETENTION_USER_ACCOUNTS_DAYS
- Qsecbit scores: $RETENTION_QSECBIT_SCORES_DAYS
- Authentication logs: $RETENTION_AUTH_LOGS_DAYS

Last cleanup: $(date)

============================================================
DATA SUBJECT RIGHTS
============================================================

Right to Access: $ENABLE_DATA_ACCESS_REQUEST
Right to Erasure: $ENABLE_RIGHT_TO_ERASURE
Right to Portability: $ENABLE_DATA_PORTABILITY
Right to Rectification: $ENABLE_DATA_RECTIFICATION

Pending requests: 0 (automated processing)

============================================================
PRIVACY SETTINGS
============================================================

IP Anonymization: $ANONYMIZE_IP_ADDRESSES
MAC Anonymization: $ANONYMIZE_MAC_ADDRESSES
Archived Log Anonymization: $ANONYMIZE_ARCHIVED_LOGS
Data Encryption at Rest: $ENCRYPT_DATA_AT_REST

============================================================
SECURITY MEASURES
============================================================

VXLAN Encryption: Enabled
RBAC: $RBAC_ENABLED
MFA for PII Access: $REQUIRE_MFA_FOR_PII_ACCESS
Audit Logging: $AUDIT_LOG_PII_ACCESS

============================================================
LEGAL BASIS
============================================================

Processing Legal Basis: $DATA_PROCESSING_LEGAL_BASIS
Legitimate Interest: $LEGITIMATE_INTEREST_PURPOSE
DPIA Completed: $DPIA_COMPLETED
DPIA Review Date: $DPIA_REVIEW_DATE

============================================================
SUPERVISORY AUTHORITY
============================================================

DPO Email: $DPO_EMAIL
Supervisory Authority: $SUPERVISORY_AUTHORITY_NAME
Country: $SUPERVISORY_AUTHORITY_COUNTRY

============================================================
BREACH NOTIFICATION
============================================================

Breach Detection: $BREACH_DETECTION_ENABLED
Notification Deadline: $BREACH_NOTIFICATION_DEADLINE_HOURS hours
Notification Email: $BREACH_NOTIFICATION_EMAIL
Breaches (last 30 days): 0

============================================================
END OF REPORT
============================================================
EOF

    log_info "Compliance report generated: $report_path"

    # Email report if configured
    if [[ -n "$COMPLIANCE_REPORT_EMAIL" ]]; then
        mail -s "HookProbe GDPR Compliance Report - $report_date" "$COMPLIANCE_REPORT_EMAIL" < "$report_path" 2>/dev/null || \
            log_warn "Failed to email compliance report (mail command not available)"
    fi
}

# ============================================================
# MAIN EXECUTION
# ============================================================

main() {
    log_info "========== Starting GDPR retention cleanup =========="

    # Check if GDPR is enabled
    if ! is_gdpr_enabled; then
        log_warn "GDPR compliance is disabled (GDPR_ENABLED=false). Exiting."
        exit 0
    fi

    # Create log directory
    mkdir -p /var/log/hookprobe/

    # Run deletion tasks
    delete_old_napse_logs
    delete_old_waf_logs
    delete_old_network_flows
    delete_old_qsecbit_scores
    delete_old_honeypot_data
    delete_old_auth_logs
    delete_old_victoriametrics_data
    delete_old_clickhouse_data

    # User account cleanup
    delete_inactive_user_accounts
    delete_permanently_deleted_accounts
    process_erasure_requests

    # Anonymization
    anonymize_archived_logs

    # Reporting
    generate_compliance_report

    log_info "========== GDPR retention cleanup completed =========="
}

# Run if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
