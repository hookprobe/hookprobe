## GDPR Compliance Guide for HookProbe

**Version**: 5.0
**Last Updated**: 2025-11-23
**Status**: Production-Ready
**Regulation**: EU General Data Protection Regulation (GDPR) 2016/679

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [What Personal Data Does HookProbe Process?](#what-personal-data-does-hookprobe-process)
- [Legal Basis for Processing](#legal-basis-for-processing)
- [GDPR Compliance Features](#gdpr-compliance-features)
- [Privacy by Design and Default](#privacy-by-design-and-default)
- [Data Subject Rights](#data-subject-rights)
- [Configuration Guide](#configuration-guide)
- [Automated Data Retention](#automated-data-retention)
- [Privacy-Preserving Security Analysis](#privacy-preserving-security-analysis)
- [Data Processing Records](#data-processing-records)
- [Breach Notification](#breach-notification)
- [Compliance Checklist](#compliance-checklist)
- [FAQ](#faq)

---

## Executive Summary

**HookProbe v5.0 is GDPR-compliant by design and by default.**

As a network security platform, HookProbe processes personal data (IP addresses, MAC addresses, network metadata) for legitimate security purposes. We have implemented comprehensive technical and organizational measures to ensure GDPR compliance while maintaining effective threat detection capabilities.

### Key Compliance Features

✅ **Privacy by Design** - Anonymization and pseudonymization built-in
✅ **Privacy by Default** - Minimal data collection, strict retention limits
✅ **Data Minimization** - Only collect what's necessary for security
✅ **Automated Retention** - Automatic deletion after retention period
✅ **Data Subject Rights** - Access, erasure, portability, rectification
✅ **Security Measures** - Encryption, access controls, audit logging
✅ **Breach Detection** - Automated breach notification procedures
✅ **Transparency** - Clear documentation and privacy notices

---

## What Personal Data Does HookProbe Process?

Under GDPR Article 4(1), personal data is "any information relating to an identified or identifiable natural person." HookProbe processes the following categories:

### 1. Network Identifiers (GDPR considers these personal data)

| Data Type | Where Collected | Retention | Anonymization |
|-----------|----------------|-----------|---------------|
| **IP Addresses (IPv4/IPv6)** | Network flows, security logs, WAF | 30-90 days | ✅ Last octet masked |
| **MAC Addresses** | Network layer monitoring | 30 days | ✅ Device ID masked (OUI kept) |
| **Port Numbers** | Connection logs | 30 days | ❌ Not personal data |
| **DNS Queries** | DNS logs, threat detection | 30 days | ⚠️ Domain only, no query params |

### 2. User Account Data (if Django/Keycloak used)

| Data Type | Where Stored | Retention | Required |
|-----------|--------------|-----------|----------|
| **Username** | PostgreSQL (Django) | 2 years active | ✅ Required |
| **Email Address** | PostgreSQL (Django/Keycloak) | 2 years active | ✅ Required for auth |
| **Password Hash** | PostgreSQL (bcrypt/Argon2) | 2 years active | ✅ Required |
| **Phone Number** | PostgreSQL (optional) | 2 years active | ❌ Disabled by default |
| **Real Name** | PostgreSQL (optional) | 2 years active | ❌ Disabled by default |
| **Login History** | PostgreSQL, Keycloak | 365 days | ✅ Security requirement |

### 3. Security Event Data

| Data Type | Where Stored | Retention | Purpose |
|-----------|--------------|-----------|---------|
| **Attack Source IPs** | Zeek, Snort3, ModSecurity, ClickHouse | 90 days | Threat intelligence |
| **WAF Block Events** | ModSecurity, ClickHouse | 90 days | Security analysis |
| **IDS Alerts** | Snort3, Zeek, ClickHouse | 365 days | Incident response |
| **Honeypot Logs** | Custom honeypots | 180 days | Attacker profiling |
| **Qsecbit Scores** | ClickHouse, VictoriaMetrics | 365 days | Trend analysis |

### 4. Data NOT Collected (Privacy by Default)

❌ **Packet Payloads** - Never collected (COLLECT_FULL_PAYLOAD=false)
❌ **Browsing History** - Only threat-related URLs logged
❌ **Email Content** - Never collected
❌ **Geolocation** - Disabled by default (COLLECT_USER_LOCATION=false)
❌ **Biometric Data** - Not collected
❌ **Special Category Data (Article 9)** - Not processed

---

## Legal Basis for Processing

### Primary Legal Basis: Legitimate Interests (Article 6(1)(f))

HookProbe processes personal data based on **legitimate interests** in:

1. **Network Security** - Protecting systems from cyber attacks
2. **Fraud Prevention** - Detecting and blocking malicious activity
3. **Service Delivery** - Maintaining infrastructure availability
4. **Legal Compliance** - Meeting security obligations

**Legitimate Interest Assessment (LIA):**
- **Necessity**: IP/MAC data essential for threat detection
- **Balancing Test**: Security benefits outweigh minimal privacy impact
- **Safeguards**: Anonymization, retention limits, access controls
- **Data Subject Expectations**: Users expect security monitoring

### Alternative Legal Bases

| Legal Basis (Article 6) | Applicable When | Example Use Cases |
|------------------------|-----------------|-------------------|
| **Contract (b)** | Service delivery | User account management, SLA compliance |
| **Legal Obligation (c)** | Security laws | Incident reporting (NIS2, DORA) |
| **Consent (a)** | ❌ Not recommended | Marketing (not used in HookProbe) |

**Why Not Consent?** Security monitoring should not require consent - users cannot opt-out of essential security. Legitimate interest is the appropriate basis.

---

## GDPR Compliance Features

### Article 5: Principles of Data Processing

| Principle | Implementation |
|-----------|----------------|
| **Lawfulness, Fairness, Transparency (a)** | Clear privacy notice, legitimate interest basis |
| **Purpose Limitation (b)** | Data only used for security/fraud prevention |
| **Data Minimization (c)** | IP anonymization, no payload collection |
| **Accuracy (d)** | Data rectification available, automated validation |
| **Storage Limitation (e)** | Automated retention enforcement (30-365 days) |
| **Integrity and Confidentiality (f)** | VXLAN encryption, RBAC, audit logging |

### Article 25: Privacy by Design and Default

**Built-in Privacy Features:**

1. **IP Anonymization** - Last octet masked (192.168.1.0 instead of 192.168.1.123)
2. **MAC Anonymization** - Device ID masked (AA:BB:CC:00:00:00)
3. **Minimal Data Collection** - Headers only, no payloads
4. **Short Retention** - 30 days for network flows (vs. years)
5. **Encrypted Storage** - AES-256-GCM encryption at rest
6. **Encrypted Transit** - VXLAN PSK encryption, TLS for web
7. **Access Controls** - RBAC with MFA for PII access

**Default Privacy Settings:**
```bash
# From gdpr-config.sh
ANONYMIZE_IP_ADDRESSES=true          # Default: ON
ANONYMIZE_MAC_ADDRESSES=true         # Default: ON
COLLECT_FULL_PAYLOAD=false           # Default: OFF (privacy-first)
COLLECT_USER_LOCATION=false          # Default: OFF
RETENTION_NETWORK_FLOWS_DAYS=30      # Default: 30 days (minimal)
```

### Article 30: Records of Processing Activities

**Automated ROPA (Record of Processing Activities):**

```bash
# Generate compliance report
sudo /opt/hookprobe/scripts/gdpr-retention.sh

# Output: /var/log/hookprobe/compliance-reports/compliance-report-YYYY-MM-DD.txt
```

**Report Contents:**
- Data inventory (what data is collected)
- Legal basis for each data type
- Retention periods and compliance status
- Data subject rights implementation
- Security measures (encryption, access controls)
- Third-party processors (if any)
- Breach notification procedures

### Article 32: Security of Processing

**Technical Measures:**

| Measure | Implementation | Standard |
|---------|---------------|----------|
| **Encryption at Rest** | AES-256-GCM | NIST FIPS 140-2 |
| **Encryption in Transit** | VXLAN PSK + TLS 1.3 | RFC 7348, RFC 8446 |
| **Pseudonymization** | HMAC-SHA256 | NIST SP 800-107 |
| **Access Control** | RBAC + MFA | NIST SP 800-63B |
| **Audit Logging** | All PII access logged | ISO 27001 |
| **Integrity** | Checksums, signatures | SHA-256 |

**Organizational Measures:**
- Regular security audits
- Incident response procedures
- Staff training on data protection
- Data minimization reviews

### Article 33/34: Breach Notification

**Automated Breach Detection:**

```bash
BREACH_DETECTION_ENABLED=true
BREACH_NOTIFICATION_DEADLINE_HOURS=72  # GDPR requirement
BREACH_NOTIFICATION_EMAIL="qsecbit@hookprobe.com"
```

**Breach Severity Thresholds:**
- **LOW**: < 100 records affected
- **MEDIUM**: 100-1,000 records
- **HIGH**: 1,000-10,000 records
- **CRITICAL**: > 10,000 records (supervisory authority notification required)

**Notification Process:**
1. Automated detection triggers alert
2. DPO notified within 1 hour
3. Preliminary assessment within 24 hours
4. Supervisory authority notification within 72 hours (if required)
5. Data subject notification if high risk to rights and freedoms

---

## Privacy by Design and Default

### Anonymization Architecture

**Layer 1: Collection** - Minimal data collected
```
Network Packet → Headers Only (no payload) → Qsecbit Analysis
```

**Layer 2: Processing** - Anonymization at ingestion
```python
from qsecbit.gdpr_privacy import anonymize_ip, anonymize_mac

# Automatic anonymization
src_ip = anonymize_ip("192.168.1.123")  # → 192.168.1.0
src_mac = anonymize_mac("AA:BB:CC:11:22:33")  # → AA:BB:CC:00:00:00
```

**Layer 3: Storage** - Encrypted and retention-limited
```
Anonymized Data → AES-256-GCM Encryption → ClickHouse/PostgreSQL
→ Automatic Deletion after Retention Period
```

**Layer 4: Access** - RBAC + Audit Logging
```
User Request → MFA Authentication → RBAC Check → Access Logged → Data Returned
```

### Qsecbit Privacy Features

**Privacy-Preserving Threat Detection:**

```python
# Qsecbit analyzes anonymized data without compromising security effectiveness

from qsecbit import QsecbitAnalyzer
from qsecbit.gdpr_privacy import PrivacyPreserver

analyzer = QsecbitAnalyzer()
privacy = PrivacyPreserver()

# Network flow with anonymization
flow = {
    'src_ip': '192.168.1.123',
    'dst_ip': '8.8.8.8',
    'src_mac': 'AA:BB:CC:11:22:33'
}

# Anonymize before analysis
anonymized_flow = privacy.anonymize_network_flow(flow)
# Result: {'src_ip': '192.168.1.0', 'dst_ip': '8.8.8.0', 'src_mac': 'AA:BB:CC:00:00:00'}

# Qsecbit can still detect threats with anonymized data!
score = analyzer.analyze_flow(anonymized_flow)
```

**Why This Works:**

- **Network patterns** don't require exact IPs (e.g., scanning from .0 subnet is still detectable)
- **MAC OUI** (vendor) is preserved for device fingerprinting
- **Port/protocol/timing** data remains intact
- **Statistical anomalies** work with anonymized data

---

## Data Subject Rights

### Right of Access (Article 15)

**Implementation:**

Users can request all personal data HookProbe holds about them.

```bash
# Enable data access requests
ENABLE_DATA_ACCESS_REQUEST=true
DATA_ACCESS_RESPONSE_DAYS=30  # GDPR requirement: respond within 30 days
```

**What's Included in Data Export:**
- User account information (username, email, registration date)
- Login history (timestamps, IP addresses)
- Security events (if associated with user account)
- Qsecbit scores (if user-specific)

**Export Format:** JSON (machine-readable, GDPR Article 20 compliant)

**How to Request:**
1. User submits request via web interface or email
2. Identity verification (prevent unauthorized access)
3. Data export generated within 30 days
4. Delivered via secure download link

### Right to Erasure / Right to be Forgotten (Article 17)

**Implementation:**

```bash
ENABLE_RIGHT_TO_ERASURE=true
ERASURE_GRACE_PERIOD_DAYS=7  # Grace period before permanent deletion
```

**Erasure Process:**

1. **User Request** → Identity verification
2. **Soft Delete** → Account marked inactive, 7-day grace period
3. **Data Purge** → Permanent deletion after grace period
   - User account deleted from PostgreSQL
   - Associated security logs anonymized (IPs → 0.0.0.0)
   - Audit trail retained (regulatory requirement)

**Limitations (Article 17(3)):**

Erasure may be **denied** if data is needed for:
- **Legal obligation** (e.g., breach investigation)
- **Public interest** (e.g., critical security incident)
- **Legal claims** (e.g., ongoing lawsuit)

If denied, user is notified with justification.

### Right to Data Portability (Article 20)

**Implementation:**

```bash
ENABLE_DATA_PORTABILITY=true
DATA_EXPORT_FORMAT="json"  # Machine-readable format
```

**Export Includes:**
- User profile data
- Login history
- Preferences/settings
- Security events (user-specific)

**Format:** JSON (interoperable, standard)

### Right to Rectification (Article 16)

Users can correct inaccurate personal data:
- Email address
- Username
- Profile information

**Not Applicable To:**
- Security logs (historical records, must remain accurate)
- IP addresses (technical data, not user-provided)

### Right to Object (Article 21)

Users can object to processing based on legitimate interests.

**Implementation:**

```bash
ENABLE_RIGHT_TO_OBJECT=true
```

**What Happens:**
- User account can be deleted (equivalent to opt-out)
- Network security monitoring continues (essential for service)
- Marketing/analytics disabled (if any - not used in HookProbe)

**Note:** Users cannot opt-out of essential security monitoring (service requirement).

### Right to Restriction of Processing (Article 18)

Temporarily suspend processing while verifying accuracy or assessing objection.

```bash
ENABLE_RESTRICTION_OF_PROCESSING=true
```

---

## Configuration Guide

### Step 1: Enable GDPR Compliance

Edit `/opt/hookprobe/scripts/gdpr-config.sh`:

```bash
# Master switch
GDPR_ENABLED=true

# Strict mode (extra privacy, may reduce visibility)
GDPR_STRICT_MODE=false

# Legal basis
DATA_PROCESSING_LEGAL_BASIS="legitimate_interest"
LEGITIMATE_INTEREST_PURPOSE="network_security_and_fraud_prevention"
```

### Step 2: Configure Data Minimization

```bash
# IP/MAC Anonymization
ANONYMIZE_IP_ADDRESSES=true
ANONYMIZE_IPV6_ADDRESSES=true
ANONYMIZE_MAC_ADDRESSES=true
IP_ANONYMIZATION_METHOD="mask"  # Options: mask, hash, truncate

# Data Collection Limits
COLLECT_FULL_PAYLOAD=false      # NEVER enable (privacy violation)
COLLECT_PACKET_HEADERS=true     # Required for security
COLLECT_DNS_QUERIES=true        # Required for threat detection
COLLECT_HTTP_URLS=true          # Required for WAF
ANONYMIZE_HTTP_QUERY_PARAMS=true  # Strip ?param=value (may contain PII)
```

### Step 3: Set Retention Periods

**Recommended Retention Periods:**

```bash
# Security Logs (balance security vs. privacy)
RETENTION_SECURITY_LOGS_DAYS=90       # 3 months (default)
RETENTION_IDS_ALERTS_DAYS=365         # 1 year (critical incidents)

# Network Data (minimize retention)
RETENTION_NETWORK_FLOWS_DAYS=30       # 1 month (default)
RETENTION_DNS_LOGS_DAYS=30
RETENTION_HTTP_LOGS_DAYS=30

# User Accounts
RETENTION_USER_ACCOUNTS_DAYS=730      # 2 years (active accounts)
RETENTION_INACTIVE_ACCOUNTS_DAYS=365  # Delete after 1 year inactivity

# Qsecbit Analysis
RETENTION_QSECBIT_SCORES_DAYS=365     # 1 year (trend analysis)
```

**Adjust Based On:**
- **Industry requirements** (e.g., finance = longer retention)
- **Legal obligations** (e.g., NIS2 = 12 months minimum)
- **Threat intelligence needs** (longer = better trends, but less privacy)

### Step 4: Enable Data Subject Rights

```bash
# Right of Access
ENABLE_DATA_ACCESS_REQUEST=true
DATA_ACCESS_RESPONSE_DAYS=30

# Right to Erasure
ENABLE_RIGHT_TO_ERASURE=true
ERASURE_GRACE_PERIOD_DAYS=7

# Right to Portability
ENABLE_DATA_PORTABILITY=true
DATA_EXPORT_FORMAT="json"

# Right to Rectification
ENABLE_DATA_RECTIFICATION=true
```

### Step 5: Configure DPO (if required)

```bash
# Data Protection Officer (required for public authorities)
DPO_REQUIRED=false  # Set to true if required
DPO_NAME="Jane Doe"
DPO_EMAIL="qsecbit@hookprobe.com"
DPO_PHONE="+1-555-123-4567"
```

**When is DPO Required? (Article 37)**
- Public authority or body
- Large-scale systematic monitoring
- Large-scale processing of special category data

For most HookProbe deployments, DPO is **optional but recommended**.

### Step 6: Configure Breach Notification

```bash
BREACH_DETECTION_ENABLED=true
BREACH_NOTIFICATION_EMAIL="qsecbit@hookprobe.com"
BREACH_NOTIFICATION_DEADLINE_HOURS=72  # GDPR requirement
BREACH_SEVERITY_HIGH_THRESHOLD=1000
BREACH_SEVERITY_CRITICAL_THRESHOLD=10000
```

### Step 7: Set Supervisory Authority

```bash
# Lead Supervisory Authority (for EU deployments)
SUPERVISORY_AUTHORITY_COUNTRY="DE"  # Germany (example)
SUPERVISORY_AUTHORITY_NAME="BfDI (Germany)"
SUPERVISORY_AUTHORITY_CONTACT="poststelle@bfdi.bund.de"
```

**Choose Based On:**
- Primary EU establishment location
- Where main processing decisions are made

**Examples:**
- **Germany**: BfDI (Bundesbeauftragter für den Datenschutz und die Informationsfreiheit)
- **France**: CNIL (Commission Nationale de l'Informatique et des Libertés)
- **Ireland**: DPC (Data Protection Commission)
- **Netherlands**: AP (Autoriteit Persoonsgegevens)

---

## Automated Data Retention

### Setup Automated Cleanup

**Install cron job** to run daily data retention cleanup:

```bash
# Edit crontab
sudo crontab -e

# Add daily cleanup at 2 AM
0 2 * * * /opt/hookprobe/scripts/gdpr-retention.sh >> /var/log/hookprobe/gdpr-retention.log 2>&1
```

**What Gets Deleted:**

| Data Type | Retention Period | Deletion Method |
|-----------|------------------|-----------------|
| Zeek network flows | 30 days | File deletion + ClickHouse DELETE |
| Snort3 alerts | 90 days | File deletion + ClickHouse DELETE |
| ModSecurity WAF logs | 90 days | File deletion + ClickHouse DELETE |
| Honeypot logs | 180 days | File deletion + ClickHouse DELETE |
| Qsecbit scores | 365 days | ClickHouse DELETE |
| Inactive user accounts | 365 days | PostgreSQL soft delete |
| Authentication logs | 365 days | PostgreSQL DELETE |
| VictoriaMetrics data | 90 days | Built-in retention (-retentionPeriod flag) |

**Manual Execution:**

```bash
# Run retention cleanup manually
sudo /opt/hookprobe/scripts/gdpr-retention.sh

# Check logs
tail -f /var/log/hookprobe/gdpr-retention.log
```

**Verification:**

```bash
# Generate compliance report
sudo /opt/hookprobe/scripts/gdpr-retention.sh

# View report
cat /var/log/hookprobe/compliance-reports/compliance-report-$(date +%Y-%m-%d).txt
```

---

## Privacy-Preserving Security Analysis

### How Qsecbit Works with Anonymized Data

**Myth:** "Anonymization breaks security detection"
**Reality:** Qsecbit detects threats using **patterns, not identities**

**Example: DDoS Detection**

```python
# BEFORE anonymization
attack_ips = ['192.168.1.10', '192.168.1.11', '192.168.1.12', ...]
# 1000 IPs from 192.168.1.0/24 → DDoS from that subnet

# AFTER anonymization
anonymized_ips = ['192.168.1.0', '192.168.1.0', '192.168.1.0', ...]
# Still detectable! 1000 connections from 192.168.1.0/24 → DDoS
```

**Example: Port Scanning Detection**

```python
# Anonymized flow data
flows = [
    {'src_ip': '10.0.0.0', 'dst_port': 22, 'timestamp': t1},
    {'src_ip': '10.0.0.0', 'dst_port': 23, 'timestamp': t2},
    {'src_ip': '10.0.0.0', 'dst_port': 80, 'timestamp': t3},
    ...  # 100+ different ports from same /24 subnet
]

# Qsecbit detects: Port scan from 10.0.0.0/24 (no exact IP needed!)
```

**What Qsecbit Analyzes (Privacy-Preserving):**

✅ **Traffic volume patterns** - Works with anonymized IPs
✅ **Port/protocol distributions** - No PII involved
✅ **Connection timing** - Statistical patterns, not identities
✅ **Packet sizes** - No PII involved
✅ **Subnet-level behavior** - /24 aggregation (e.g., 192.168.1.0/24)
✅ **Device types** (via MAC OUI) - Vendor prefix preserved
✅ **Protocol anomalies** - No PII needed

❌ **Individual user tracking** - Disabled
❌ **Behavioral profiling of individuals** - Not performed
❌ **Geolocation tracking** - Disabled by default

### XDP/eBPF DDoS Mitigation with Privacy

**XDP blocking works with anonymized IPs:**

```bash
# Block entire /24 subnet (no need for exact IPs)
xdp_block_subnet "192.168.1.0/24"

# Rate limiting per subnet
xdp_ratelimit "10.0.0.0/24" --limit 1000pps
```

**Privacy benefit:** Blocking /24 subnets is **more private** than tracking individual IPs!

---

## Data Processing Records

### Automated ROPA Generation

**Generate Record of Processing Activities (ROPA):**

```bash
# Run compliance report
sudo /opt/hookprobe/scripts/gdpr-retention.sh

# Output location
cat /var/log/hookprobe/compliance-reports/compliance-report-$(date +%Y-%m-%d).txt
```

**Report Contents (Article 30 compliant):**

1. **Controller Information** - Organization details
2. **Data Inventory** - What personal data is processed
3. **Legal Basis** - Justification for each data type
4. **Retention Periods** - Storage limitation compliance
5. **Security Measures** - Technical and organizational safeguards
6. **Data Subject Rights** - Implementation status
7. **Third-Party Processors** - Subprocessor list (if any)
8. **International Transfers** - Cross-border data flows (if any)
9. **Breach History** - Security incidents (last 30 days)

### DPIA (Data Protection Impact Assessment)

**When is DPIA Required? (Article 35)**

✅ **Yes, for HookProbe** - Large-scale monitoring + profiling (Qsecbit)

**DPIA Template:**

```bash
# Location
/opt/hookprobe/compliance/DPIA.pdf

# Set completion status
DPIA_COMPLETED=true
DPIA_REVIEW_DATE="2026-11-23"  # Annual review
```

**DPIA Contents:**

1. **Description of Processing**
   - Network security monitoring
   - Threat detection via Qsecbit
   - Automated response (Kali Linux)

2. **Necessity and Proportionality**
   - Why processing is necessary (security)
   - Why chosen methods are proportionate

3. **Risks to Data Subjects**
   - Risk: Unauthorized access to network logs
   - Risk: Over-collection of personal data
   - Risk: Inadequate anonymization

4. **Mitigation Measures**
   - VXLAN encryption
   - IP/MAC anonymization
   - Short retention periods (30-90 days)
   - RBAC + MFA access controls

5. **Stakeholder Consultation**
   - DPO review
   - IT security team input
   - Legal counsel approval

6. **Approval**
   - DPO sign-off
   - Management approval

**Review Frequency:** Annually or when significant changes occur

---

## Breach Notification

### Automated Breach Detection

**What Triggers a Breach Alert:**

1. **Unauthorized Access to Database**
   - Failed authentication attempts > 100/hour
   - Successful login from unknown IP/country
   - PostgreSQL unauthorized access attempts

2. **Data Exfiltration**
   - Large data export (> 10,000 records)
   - Unusual database query patterns
   - Abnormal network egress traffic

3. **System Compromise**
   - Qsecbit RAG status: RED for > 1 hour
   - Honeypot container breached
   - Malware detected in containers

4. **Encryption Failure**
   - VXLAN encryption disabled
   - TLS certificate expired
   - Database encryption key compromised

### Breach Response Procedure

**Timeline (GDPR Article 33/34):**

```
T+0 hours    Breach detected (automated alert)
T+1 hour     DPO notified
T+24 hours   Preliminary assessment complete
T+72 hours   Supervisory authority notified (if required)
T+72 hours   Data subjects notified (if high risk)
```

**Step-by-Step Response:**

1. **Detection** (Automated)
   ```bash
   # Breach detected by Qsecbit
   LOG: "BREACH DETECTED - Severity: HIGH - Records affected: 5000"
   ```

2. **Notification** (Automated email to DPO)
   ```
   To: qsecbit@hookprobe.com
   Subject: URGENT - Data Breach Detected

   Severity: HIGH
   Records Affected: 5000
   Data Types: IP addresses, usernames
   Detection Time: 2025-11-23 14:32:00 UTC
   Root Cause: Database unauthorized access attempt
   ```

3. **Assessment** (Manual - within 24 hours)
   - Determine breach scope
   - Identify affected data subjects
   - Assess risk level (low/medium/high)
   - Determine if supervisory authority notification required

4. **Supervisory Authority Notification** (if required - within 72 hours)
   - **When Required:**
     - High risk to rights and freedoms
     - Special category data affected (Article 9)
     - Large number of data subjects (> 1000)

   - **Notification Contents (Article 33(3)):**
     - Nature of breach
     - Categories and number of data subjects
     - Categories and number of records
     - Contact details of DPO
     - Likely consequences
     - Measures taken to mitigate

5. **Data Subject Notification** (if high risk - within 72 hours)
   - **When Required (Article 34):**
     - High risk to rights and freedoms
     - Examples: SSN leak, financial data, health data

   - **Notification Contents:**
     - Plain language description of breach
     - Contact details of DPO
     - Likely consequences
     - Measures taken to mitigate
     - Recommended actions for data subjects

6. **Documentation** (Article 33(5))
   ```bash
   # Breach log (retain for 6 years)
   /var/log/hookprobe/gdpr-audit.log
   ```

**Breach Severity Matrix:**

| Severity | Records Affected | Data Types | Supervisory Authority | Data Subjects |
|----------|------------------|------------|----------------------|---------------|
| **LOW** | < 100 | IP addresses only | ❌ No | ❌ No |
| **MEDIUM** | 100-1,000 | IP + usernames | ⚠️ Maybe | ❌ No |
| **HIGH** | 1,000-10,000 | IP + emails | ✅ Yes | ⚠️ Maybe |
| **CRITICAL** | > 10,000 | Any PII | ✅ Yes | ✅ Yes |

---

## Compliance Checklist

### Pre-Deployment Checklist

Before deploying HookProbe in production:

- [ ] **GDPR configuration reviewed**
  ```bash
  nano /opt/hookprobe/scripts/gdpr-config.sh
  ```

- [ ] **Retention periods set appropriately**
  - Security logs: 90 days (default)
  - Network flows: 30 days (default)
  - User accounts: 365 days inactive deletion

- [ ] **IP/MAC anonymization enabled**
  ```bash
  ANONYMIZE_IP_ADDRESSES=true
  ANONYMIZE_MAC_ADDRESSES=true
  ```

- [ ] **Payload collection disabled** (privacy violation if enabled)
  ```bash
  COLLECT_FULL_PAYLOAD=false  # MUST be false!
  ```

- [ ] **Data subject rights implemented**
  ```bash
  ENABLE_DATA_ACCESS_REQUEST=true
  ENABLE_RIGHT_TO_ERASURE=true
  ```

- [ ] **Breach notification configured**
  ```bash
  BREACH_DETECTION_ENABLED=true
  BREACH_NOTIFICATION_EMAIL="dpo@example.com"  # Set real email!
  ```

- [ ] **Encryption enabled**
  - VXLAN PSK encryption: ✅ (enabled by default)
  - Database encryption: ✅ (PostgreSQL + pgcrypto)
  - TLS for web services: ✅ (Nginx/Django)

- [ ] **Automated retention cleanup scheduled**
  ```bash
  sudo crontab -e
  # Add: 0 2 * * * /opt/hookprobe/scripts/gdpr-retention.sh
  ```

- [ ] **Privacy notice prepared** (for users)
  - What data is collected
  - Why (legal basis)
  - How long (retention)
  - Data subject rights

- [ ] **DPIA completed** (if required)
  ```bash
  DPIA_COMPLETED=true
  DPIA_REVIEW_DATE="2026-11-23"
  ```

- [ ] **DPO designated** (if required)
  ```bash
  DPO_EMAIL="dpo@example.com"
  ```

- [ ] **Supervisory authority identified**
  ```bash
  SUPERVISORY_AUTHORITY_COUNTRY="DE"
  SUPERVISORY_AUTHORITY_NAME="BfDI (Germany)"
  ```

### Post-Deployment Checklist

After HookProbe is running:

- [ ] **Verify anonymization is working**
  ```bash
  # Check Zeek logs for anonymized IPs
  tail /opt/zeek/logs/conn.log | grep "\.0$"  # Should see .0 IPs
  ```

- [ ] **Test data retention cleanup**
  ```bash
  sudo /opt/hookprobe/scripts/gdpr-retention.sh
  tail /var/log/hookprobe/gdpr-retention.log
  ```

- [ ] **Generate compliance report**
  ```bash
  cat /var/log/hookprobe/compliance-reports/compliance-report-$(date +%Y-%m-%d).txt
  ```

- [ ] **Test data subject rights**
  - Submit data access request → verify export works
  - Submit erasure request → verify deletion works

- [ ] **Monitor GDPR audit log**
  ```bash
  tail -f /var/log/hookprobe/gdpr-audit.log
  ```

- [ ] **Verify breach detection**
  - Trigger test alert (if test mode available)
  - Verify DPO receives notification email

- [ ] **Review access controls**
  ```bash
  # Verify RBAC is enforced
  # Verify MFA is required for PII access
  ```

- [ ] **Schedule annual DPIA review**
  - Calendar reminder for DPIA_REVIEW_DATE

- [ ] **Publish privacy notice**
  - Add to website/user portal
  - Inform existing users (if applicable)

---

## FAQ

### General Questions

**Q: Is HookProbe GDPR-compliant out of the box?**
A: Yes, with default configuration. Anonymization, minimal retention, and encryption are enabled by default.

**Q: Do I need a DPO (Data Protection Officer)?**
A: Only if you are a public authority or process data at very large scale. For most deployments, DPO is optional but recommended.

**Q: Can I use HookProbe outside the EU?**
A: Yes, but GDPR applies if you process data of EU residents. Consider local laws (e.g., CCPA in California, LGPD in Brazil).

**Q: What's the legal basis for processing network data?**
A: **Legitimate interests** (Article 6(1)(f)) - network security and fraud prevention. This is the standard basis for security monitoring.

### Technical Questions

**Q: Does anonymization reduce security effectiveness?**
A: No. Qsecbit detects threats using **patterns**, not exact IPs. Subnet-level anonymization (192.168.1.0/24) preserves detection capability.

**Q: Can I disable anonymization for better forensics?**
A: Yes, but **not recommended**. Set `ANONYMIZE_IP_ADDRESSES=false` only if you have a strong legal justification (e.g., law enforcement cooperation).

**Q: How long should I retain security logs?**
A: **Balance:**
- **Privacy**: Shorter is better (30 days)
- **Security**: Longer enables trend analysis (90-365 days)
- **Compliance**: Some regulations require 12+ months (e.g., NIS2, PCI-DSS)

**Recommendation:** 90 days for general security, 365 days for critical alerts.

**Q: What if I need longer retention for compliance?**
A: Adjust retention periods in `gdpr-config.sh`. Document the legal basis (e.g., "NIS2 requires 12-month retention").

**Q: Can I store logs outside the EU?**
A: Only with appropriate safeguards:
- **Adequacy decision** (Article 45) - EU Commission approved country
- **Standard Contractual Clauses (SCCs)** (Article 46) - Legal contract with processor
- **Binding Corporate Rules (BCRs)** (Article 47) - Internal company policies

**Q: What about ClickHouse data?**
A: ClickHouse supports TTL (Time To Live) for automatic deletion. Set retention periods in `gdpr-config.sh`, and ClickHouse will auto-delete old data.

### Data Subject Rights Questions

**Q: How do users request their data?**
A: Via web interface (Django admin) or email to DPO. User must verify identity (prevent unauthorized access).

**Q: What format is data exported in?**
A: JSON (machine-readable, GDPR Article 20 compliant). Users can import into other systems.

**Q: Can users opt-out of security monitoring?**
A: **No**. Network security monitoring is essential for service delivery. Users can delete their account (full opt-out) but cannot use the service without security monitoring.

**Q: How long does erasure take?**
A: 7-day grace period (soft delete), then permanent deletion. This prevents accidental deletions while meeting GDPR timelines.

**Q: Are there exceptions to the right to erasure?**
A: Yes (Article 17(3)):
- Legal obligation (e.g., breach investigation ongoing)
- Public interest (e.g., critical security incident)
- Legal claims (e.g., lawsuit)

### Breach Notification Questions

**Q: What counts as a "data breach" under GDPR?**
A: Any unauthorized access, disclosure, or loss of personal data. Examples:
- Hacker gains access to database
- Unencrypted backup stolen
- Data accidentally emailed to wrong person
- Ransomware encrypts user data

**Q: Do I always need to notify the supervisory authority?**
A: Only if the breach is **likely to result in a risk** to rights and freedoms. Low-severity breaches (e.g., 10 anonymized IPs leaked) may not require notification.

**Q: What's the penalty for not notifying within 72 hours?**
A: Up to **€10 million or 2% of global annual revenue** (whichever is higher) under GDPR Article 83(4).

**Q: Can I delay notification if I'm still investigating?**
A: No. You must notify within 72 hours even if investigation is incomplete. You can provide updates later.

### Compliance Questions

**Q: Do I need to register with a supervisory authority?**
A: Not anymore (registration requirement removed in 2018). However, you must:
- Maintain internal records of processing (Article 30)
- Designate DPO if required (Article 37)
- Notify supervisory authority of breaches (Article 33)

**Q: What if my organization is based outside the EU?**
A: GDPR still applies if you:
- Offer goods/services to EU residents (Article 3(2)(a))
- Monitor behavior of EU residents (Article 3(2)(b))

You may need to appoint an **EU representative** (Article 27).

**Q: How often should I review GDPR compliance?**
A: **Annually** at minimum. More frequently if:
- Significant system changes
- New data processing activities
- New regulations (e.g., NIS2, DORA, ePrivacy)
- After a data breach

**Q: Can I use HookProbe for employee monitoring?**
A: ⚠️ **Caution required**. Employee monitoring has additional GDPR requirements:
- Transparent notification to employees (Article 13)
- Legitimate interest assessment (Article 6(1)(f))
- Consultation with works council (national laws)
- Minimization (only monitor what's necessary)

**Not recommended** unless you have clear legal justification and employee consent/notification.

---

## Additional Resources

### Official GDPR Resources

- **GDPR Full Text**: https://gdpr-info.eu/
- **European Data Protection Board (EDPB)**: https://edpb.europa.eu/
- **EU Commission GDPR Portal**: https://commission.europa.eu/law/law-topic/data-protection_en

### National Supervisory Authorities

- **Germany (BfDI)**: https://www.bfdi.bund.de/
- **France (CNIL)**: https://www.cnil.fr/
- **Ireland (DPC)**: https://www.dataprotection.ie/
- **Netherlands (AP)**: https://autoriteitpersoonsgegevens.nl/
- **UK (ICO)**: https://ico.org.uk/ (UK GDPR post-Brexit)

### HookProbe GDPR Documentation

- **GDPR.md** (this file) - Comprehensive compliance guide
- **SECURITY.md** - Security measures and privacy controls
- **Scripts/autonomous/install/gdpr-config.sh** - Configuration settings
- **Scripts/autonomous/install/gdpr-retention.sh** - Automated retention
- **Scripts/autonomous/qsecbit/gdpr_privacy.py** - Privacy module

### Contact

For GDPR compliance questions:
- **Email**: qsecbit@hookprobe.com
- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Security Contact**: qsecbit@hookprobe.com

---

**Document Version**: 5.0
**Last Updated**: 2025-11-23
**Next Review**: 2026-11-23
**License**: MIT

**Disclaimer**: This document provides technical guidance on GDPR compliance for HookProbe. It is not legal advice. Consult a qualified data protection lawyer for legal compliance assessment specific to your jurisdiction and use case.

---

**HookProbe v5.0** - Privacy-Preserving Cybersecurity Platform
**Built with GDPR compliance from day one** 🔒

