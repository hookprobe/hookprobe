#!/bin/bash
#
# gdpr-config.sh - HookProbe v5.0 GDPR Compliance Configuration
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#
# This file contains all GDPR compliance settings for HookProbe
# Implements privacy-by-design and privacy-by-default principles
#

# ============================================================
# GDPR COMPLIANCE ENABLE/DISABLE
# ============================================================
GDPR_ENABLED=true                      # Master switch for GDPR features
GDPR_STRICT_MODE=false                 # Extra strict compliance (may reduce security visibility)

# ============================================================
# DATA PROCESSING LEGAL BASIS
# ============================================================
# Legal basis for processing under GDPR Article 6(1)
# Options: legitimate_interest, contract, legal_obligation, consent
DATA_PROCESSING_LEGAL_BASIS="legitimate_interest"

# Legitimate Interest Assessment (LIA)
# HookProbe processes personal data (IP, MAC, network metadata) for:
# - Network security and fraud prevention (legitimate interest)
# - Service delivery and infrastructure protection (contract)
# - Security incident response (legal obligation in some jurisdictions)
LEGITIMATE_INTEREST_PURPOSE="network_security_and_fraud_prevention"

# ============================================================
# DATA MINIMIZATION SETTINGS
# ============================================================
# Implement GDPR Article 5(1)(c) - Data Minimization Principle

# IP Address Anonymization
ANONYMIZE_IP_ADDRESSES=true            # Mask last octet of IPv4 (192.168.1.0/24)
ANONYMIZE_IPV6_ADDRESSES=true          # Mask last 80 bits of IPv6
IP_ANONYMIZATION_METHOD="mask"         # Options: mask, hash, truncate

# MAC Address Anonymization
ANONYMIZE_MAC_ADDRESSES=true           # Mask device identifier portion
MAC_ANONYMIZATION_METHOD="mask"        # Options: mask, hash, truncate

# User Account Data
COLLECT_USER_EMAIL=true                # Required for account management
COLLECT_USER_PHONE=false               # Disable if not needed
COLLECT_USER_REAL_NAME=false           # Use usernames only
COLLECT_USER_LOCATION=false            # Disable geolocation collection

# Network Traffic Metadata
COLLECT_FULL_PAYLOAD=false             # NEVER collect payload data (privacy violation)
COLLECT_PACKET_HEADERS=true            # Headers needed for security analysis
COLLECT_DNS_QUERIES=true               # DNS needed for threat detection
COLLECT_HTTP_URLS=true                 # URLs needed for WAF/IDS
ANONYMIZE_HTTP_QUERY_PARAMS=true       # Strip query parameters (may contain PII)

# ============================================================
# DATA RETENTION PERIODS (GDPR Article 5(1)(e))
# ============================================================
# Storage Limitation Principle - data must not be kept longer than necessary

# Security Logs
RETENTION_SECURITY_LOGS_DAYS=90        # Zeek, Snort, ModSecurity logs (3 months default)
RETENTION_WAF_LOGS_DAYS=90             # WAF block logs
RETENTION_IDS_ALERTS_DAYS=365          # Critical security alerts (1 year for forensics)

# Network Flow Data
RETENTION_NETWORK_FLOWS_DAYS=30        # Zeek connection logs (1 month)
RETENTION_DNS_LOGS_DAYS=30             # DNS query logs
RETENTION_HTTP_LOGS_DAYS=30            # HTTP metadata logs

# Honeypot Data
RETENTION_HONEYPOT_LOGS_DAYS=180       # Attacker IP data (6 months for threat intel)
RETENTION_ATTACKER_IPS_DAYS=365        # Blocked attacker IPs (1 year)

# User Account Data
RETENTION_USER_ACCOUNTS_DAYS=730       # Active user accounts (2 years)
RETENTION_INACTIVE_ACCOUNTS_DAYS=365   # Delete after 1 year of inactivity
RETENTION_DELETED_ACCOUNTS_DAYS=30     # Soft delete grace period

# Authentication Logs
RETENTION_AUTH_LOGS_DAYS=365           # Login attempts, MFA events
RETENTION_FAILED_AUTH_DAYS=90          # Failed login attempts

# Qsecbit Analysis Data
RETENTION_QSECBIT_SCORES_DAYS=365      # RAG scores and trends (1 year)
RETENTION_QSECBIT_ALERTS_DAYS=730      # Critical security alerts (2 years)

# Monitoring Metrics (VictoriaMetrics, Grafana)
RETENTION_METRICS_DAYS=90              # System/network metrics (3 months)
RETENTION_LOGS_DAYS=90                 # Application logs (VictoriaLogs)

# ClickHouse Data (if deployed)
RETENTION_CLICKHOUSE_RAW_DAYS=30       # Raw event data
RETENTION_CLICKHOUSE_AGGREGATED_DAYS=365  # Aggregated statistics

# ============================================================
# PSEUDONYMIZATION AND ANONYMIZATION
# ============================================================
# GDPR Article 32 - Security of Processing

# Pseudonymization (reversible with key)
PSEUDONYMIZE_USER_IDS=false            # Hash user IDs with secret key
PSEUDONYMIZATION_KEY=""                # Generate: openssl rand -base64 32
PSEUDONYMIZATION_ALGORITHM="sha256"    # Options: sha256, sha3-256, blake2b

# Full Anonymization (irreversible)
ANONYMIZE_ARCHIVED_LOGS=true           # Strip all identifiers from archived data
ANONYMIZATION_DELAY_DAYS=90            # Anonymize after 90 days

# ============================================================
# DATA SUBJECT RIGHTS (GDPR Chapter III)
# ============================================================

# Right of Access (Article 15)
ENABLE_DATA_ACCESS_REQUEST=true        # Allow users to request their data
DATA_ACCESS_RESPONSE_DAYS=30           # Respond within 30 days (GDPR requirement)

# Right to Erasure / Right to be Forgotten (Article 17)
ENABLE_RIGHT_TO_ERASURE=true           # Allow users to delete their data
ERASURE_VERIFICATION=true              # Require identity verification
ERASURE_GRACE_PERIOD_DAYS=7            # Grace period before permanent deletion

# Right to Rectification (Article 16)
ENABLE_DATA_RECTIFICATION=true         # Allow users to correct their data

# Right to Data Portability (Article 20)
ENABLE_DATA_PORTABILITY=true           # Export user data in machine-readable format
DATA_EXPORT_FORMAT="json"              # Options: json, csv, xml

# Right to Object (Article 21)
ENABLE_RIGHT_TO_OBJECT=true            # Allow objection to processing

# Right to Restriction (Article 18)
ENABLE_RESTRICTION_OF_PROCESSING=true  # Allow temporary processing restriction

# ============================================================
# AUTOMATED DECISION MAKING (Article 22)
# ============================================================
# Qsecbit performs automated threat analysis and blocking

AUTOMATED_BLOCKING_ENABLED=true        # Qsecbit can auto-block attackers
AUTOMATED_BLOCKING_REQUIRES_REVIEW=false  # Human review before blocking
AUTOMATED_BLOCKING_APPEAL_PROCESS=true # Allow appeals for false positives
AUTOMATED_DECISION_LOGGING=true        # Log all automated decisions

# ============================================================
# BREACH NOTIFICATION (Article 33/34)
# ============================================================
# Data breach detection and notification

BREACH_DETECTION_ENABLED=true          # Monitor for potential data breaches
BREACH_NOTIFICATION_EMAIL="qsecbit@hookprobe.com"  # Data Protection Officer contact
BREACH_NOTIFICATION_DEADLINE_HOURS=72  # Notify within 72 hours (GDPR requirement)
BREACH_LOG_RETENTION_DAYS=2190         # Keep breach records for 6 years

# Breach Severity Thresholds
BREACH_SEVERITY_HIGH_THRESHOLD=1000    # Records affected for HIGH severity
BREACH_SEVERITY_CRITICAL_THRESHOLD=10000  # Records affected for CRITICAL

# ============================================================
# THIRD-PARTY DATA PROCESSORS
# ============================================================
# GDPR Article 28 - Processor Requirements

# External Services (configure if used)
USES_CLOUDFLARE=false                  # Cloudflare Tunnel (US company - EU-US DPF)
USES_EXTERNAL_DNS=false                # External DNS resolver
USES_EXTERNAL_NTP=true                 # External time sync
USES_CLOUD_BACKUP=false                # Cloud backup services

# Data Processing Agreements (DPA)
DPA_CLOUDFLARE_SIGNED=false            # DPA with Cloudflare
DPA_BACKUP_PROVIDER_SIGNED=false       # DPA with backup provider

# ============================================================
# INTERNATIONAL DATA TRANSFERS (Chapter V)
# ============================================================
# Restrictions on data transfers outside EU/EEA

ALLOW_INTERNATIONAL_TRANSFERS=false    # Block data transfers outside EU/EEA
INTERNATIONAL_TRANSFER_MECHANISM=""    # Options: adequacy_decision, standard_contractual_clauses, bcr

# If transfers enabled, specify countries
ALLOWED_TRANSFER_COUNTRIES=""          # Comma-separated ISO codes (e.g., "US,CH,UK")

# ============================================================
# PRIVACY BY DESIGN / DEFAULT (Article 25)
# ============================================================

# Default Privacy Settings for New Users
DEFAULT_TELEMETRY_ENABLED=false        # Opt-in for telemetry
DEFAULT_ANALYTICS_ENABLED=false        # Opt-in for analytics
DEFAULT_EMAIL_NOTIFICATIONS=false      # Opt-in for marketing emails

# Encryption
ENCRYPT_DATA_AT_REST=true              # Encrypt stored data
ENCRYPT_DATA_IN_TRANSIT=true           # TLS/VXLAN encryption (already enabled)
ENCRYPTION_ALGORITHM="AES-256-GCM"     # For at-rest encryption

# Access Controls
RBAC_ENABLED=true                      # Role-based access control
REQUIRE_MFA_FOR_PII_ACCESS=true        # MFA for accessing personal data
AUDIT_LOG_PII_ACCESS=true              # Log all PII data access

# ============================================================
# DATA PROTECTION IMPACT ASSESSMENT (DPIA)
# ============================================================
# Article 35 - DPIA required for high-risk processing

DPIA_REQUIRED=true                     # HookProbe processes security data at scale
DPIA_COMPLETED=false                   # Set to true after completing DPIA
DPIA_REVIEW_DATE=""                    # Next DPIA review date (YYYY-MM-DD)
DPIA_DOCUMENT_PATH="/opt/hookprobe/compliance/DPIA.pdf"

# High-Risk Processing Activities
PROCESSES_LARGE_SCALE_DATA=true        # Network-wide monitoring
PROCESSES_SENSITIVE_DATA=false         # No special category data (Article 9)
USES_SYSTEMATIC_MONITORING=true        # Continuous network monitoring
USES_PROFILING=true                    # Behavioral analysis (Qsecbit)

# ============================================================
# CONSENT MANAGEMENT (if applicable)
# ============================================================
# Article 7 - Conditions for Consent

CONSENT_REQUIRED=false                 # Use consent as legal basis (not recommended for security)
CONSENT_GRANULAR=true                  # Separate consent for different purposes
CONSENT_WITHDRAWABLE=true              # Easy consent withdrawal
CONSENT_RECORD_RETENTION_DAYS=2190     # Keep consent records for 6 years

# ============================================================
# DATA PROTECTION OFFICER (DPO)
# ============================================================
# Article 37 - Designation of DPO

DPO_REQUIRED=false                     # Required for public authorities or large-scale monitoring
DPO_NAME=""                            # Data Protection Officer name
DPO_EMAIL="qsecbit@hookprobe.com"          # DPO contact email
DPO_PHONE=""                           # DPO phone number

# ============================================================
# LOGGING AND AUDITING (Article 30)
# ============================================================
# Records of Processing Activities

ENABLE_GDPR_AUDIT_LOG=true             # Log all GDPR-related activities
GDPR_AUDIT_LOG_PATH="/var/log/hookprobe/gdpr-audit.log"
GDPR_AUDIT_LOG_RETENTION_DAYS=2190     # 6 years retention for compliance

# Activities to Log
LOG_DATA_ACCESS=true                   # Log all personal data access
LOG_DATA_EXPORT=true                   # Log data portability requests
LOG_DATA_DELETION=true                 # Log erasure requests
LOG_DATA_MODIFICATION=true             # Log rectification requests
LOG_CONSENT_CHANGES=true               # Log consent grant/withdrawal

# ============================================================
# JURISDICTION AND SUPERVISORY AUTHORITY
# ============================================================

# Lead Supervisory Authority (for multi-EU deployment)
SUPERVISORY_AUTHORITY_COUNTRY=""       # ISO code of primary establishment (e.g., "DE", "FR", "NL")
SUPERVISORY_AUTHORITY_NAME=""          # e.g., "CNIL (France)", "BfDI (Germany)"
SUPERVISORY_AUTHORITY_CONTACT=""       # Contact information

# ============================================================
# AUTOMATED COMPLIANCE REPORTING
# ============================================================

ENABLE_COMPLIANCE_REPORTS=true         # Generate periodic compliance reports
COMPLIANCE_REPORT_FREQUENCY_DAYS=30    # Monthly reports
COMPLIANCE_REPORT_PATH="/var/log/hookprobe/compliance-reports/"
COMPLIANCE_REPORT_EMAIL="qsecbit@hookprobe.com"

# Report Contents
REPORT_DATA_INVENTORY=true             # What data is collected
REPORT_RETENTION_STATUS=true           # Data retention compliance
REPORT_DELETION_STATS=true             # Automated deletion statistics
REPORT_ACCESS_REQUESTS=true            # Data subject requests
REPORT_BREACH_STATUS=true              # Security incidents

# ============================================================
# GDPR IMPLEMENTATION STATUS
# ============================================================

GDPR_COMPLIANCE_VERSION="5.0"
GDPR_IMPLEMENTATION_DATE="2025-11-23"
GDPR_LAST_REVIEW_DATE="2025-11-23"
GDPR_NEXT_REVIEW_DATE="2026-11-23"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

# Check if GDPR is enabled
is_gdpr_enabled() {
    [[ "$GDPR_ENABLED" == "true" ]]
}

# Get retention period for specific data type
get_retention_days() {
    local data_type="$1"
    case "$data_type" in
        security_logs)
            echo "$RETENTION_SECURITY_LOGS_DAYS"
            ;;
        network_flows)
            echo "$RETENTION_NETWORK_FLOWS_DAYS"
            ;;
        user_accounts)
            echo "$RETENTION_USER_ACCOUNTS_DAYS"
            ;;
        qsecbit_scores)
            echo "$RETENTION_QSECBIT_SCORES_DAYS"
            ;;
        *)
            echo "90"  # Default 90 days
            ;;
    esac
}

# Calculate deletion date
get_deletion_date() {
    local retention_days="$1"
    date -d "$retention_days days ago" +%Y-%m-%d
}

# Log GDPR audit event
log_gdpr_event() {
    if [[ "$ENABLE_GDPR_AUDIT_LOG" == "true" ]]; then
        local event_type="$1"
        local event_details="$2"
        local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

        mkdir -p "$(dirname "$GDPR_AUDIT_LOG_PATH")"
        echo "$timestamp | $event_type | $event_details" >> "$GDPR_AUDIT_LOG_PATH"
    fi
}

# ============================================================
# END OF GDPR CONFIGURATION
# ============================================================
