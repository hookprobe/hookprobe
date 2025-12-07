# MSSP Dashboard (Security Operations)

**Multi-Tenant Security Monitoring & Device Management**

The HookProbe MSSP Dashboard provides comprehensive security monitoring, threat hunting, and edge device management capabilities for Managed Security Service Providers (MSSPs) and enterprise security teams.

---

## 🎯 Overview

The MSSP Dashboard is the command center for security operations, providing:
- Real-time threat detection across multiple customer sites
- Multi-device management and monitoring
- Advanced threat hunting and investigation
- Automated incident response (SOAR)
- Cross-tenant threat intelligence correlation

### Key Features

- 🔒 **SIEM Capabilities** - Real-time security monitoring
- 📱 **Multi-Device Management** - Manage 100-1000+ edge devices
- 🎯 **Threat Hunting** - Advanced query builder and investigation tools
- 🚨 **Incident Response** - Alert management and automated playbooks
- 📊 **Analytics & Reporting** - Security metrics and compliance reports
- 🤖 **AI-Powered Detection** - Qsecbit RAG scores across all devices
- 🔗 **Cross-Tenant Intelligence** - Aggregate threat patterns

---

## 🚀 Quick Access

**URL**: `http://YOUR_IP/dashboard/`

**Authentication**: Logto SSO (POD-002)

**Required PODs**:
- POD-001 (Web DMZ) - Frontend
- POD-002 (Logto IAM) - Authentication
- POD-003 (PostgreSQL) - Database
- POD-005 (ClickHouse/Doris) - Analytics
- POD-006 (Security Detection) - IDS/IPS data
- POD-007 (Qsecbit AI) - Threat scores

---

## 📊 Dashboard Tabs

### 1. Home - Overview & Summary

The main dashboard provides at-a-glance visibility across all managed devices.

```
┌──────────────────────────────────────────────────────────┐
│             MSSP Security Operations Center              │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Active Devices: 47/50      Qsecbit Score: 0.28 🟢      │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ 3 Critical  │  │ 12 Warning  │  │ 156 Blocked │     │
│  │   Alerts    │  │   Events    │  │   Attacks   │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                          │
│  Recent Security Events                                  │
│  ────────────────────────────────────────────────────   │
│  🔴 Critical: SQL Injection - Customer: Acme Corp       │
│  🟡 Warning: Port Scan - Customer: Widget Co            │
│  🟢 Info: DDoS Mitigated - Customer: Tech Startup       │
│                                                          │
│  Top Threats (Last 24h)                                  │
│  ────────────────────────────────────────────────────   │
│  1. SQL Injection         45 events   3 customers       │
│  2. XSS Attempts          32 events   2 customers       │
│  3. Brute Force Attack    28 events   1 customer        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Widgets**:
- **Device Status Map**: Geographic view of all edge devices
- **Aggregate Qsecbit Score**: Overall security posture
- **Critical Alerts**: High-priority incidents requiring attention
- **Threat Trends**: 7-day attack pattern visualization
- **Customer Risk Matrix**: Per-tenant security scores
- **Recent Activity**: Latest security events across all tenants

### 2. Endpoints - Device Management

Manage and monitor all edge devices across customer sites.

**Device List View**:

| Device | Customer | Status | Qsecbit | Last Seen | Actions |
|--------|----------|--------|---------|-----------|---------|
| edge-acme-01 | Acme Corp | 🟢 Online | 0.32 🟢 | 2 min ago | View, Configure, SSH |
| edge-widget-01 | Widget Co | 🟡 Warning | 0.58 🟡 | 5 min ago | View, Investigate |
| edge-tech-01 | Tech Startup | 🔴 Critical | 0.78 🔴 | 1 min ago | View, Respond |
| edge-retail-02 | Retail Inc | 🟢 Online | 0.25 🟢 | 3 min ago | View, Configure |

**Device Details View**:

Click on a device to view comprehensive details:

```
┌──────────────────────────────────────────────────────────┐
│  Device: edge-acme-01                    Status: 🟢 Online│
│  Customer: Acme Corp                                     │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Qsecbit Score: 0.32 🟢 GREEN                           │
│  ┌────────────────────────────────────────────────┐     │
│  │ ████████████░░░░░░░░░░░░░░░░░░░░░░░░ 32%     │     │
│  └────────────────────────────────────────────────┘     │
│                                                          │
│  System Info               Network                       │
│  ────────────              ───────                       │
│  CPU: 8 cores             Interface: eth0               │
│  RAM: 16GB (60% used)     IP: 192.168.1.100             │
│  Disk: 512GB SSD          Uptime: 15 days               │
│  OS: Ubuntu 22.04         Bandwidth: 2.5 Gbps           │
│                                                          │
│  POD Status (7/7 Running)                                │
│  ─────────────────────────                              │
│  ✅ POD-001 Web DMZ        ✅ POD-002 IAM               │
│  ✅ POD-003 Database       ✅ POD-004 Cache             │
│  ✅ POD-005 Monitoring     ✅ POD-006 Security          │
│  ✅ POD-007 AI Response                                 │
│                                                          │
│  Recent Security Events (Last 24h)                       │
│  ──────────────────────────────────                     │
│  • 3 WAF blocks (SQL injection)                         │
│  • 1 DDoS mitigation (XDP)                              │
│  • 0 IDS critical alerts                                │
│                                                          │
│  Actions:                                                │
│  [View Logs] [SSH Access] [Configure] [Run Diagnostics] │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Device Management Features**:
- **Bulk Actions**: Update multiple devices simultaneously
- **Configuration Templates**: Apply standard configs
- **Remote Access**: SSH via Cloudflare Tunnel
- **Firmware Updates**: Push updates to edge devices
- **Device Groups**: Organize by customer, region, type

**Quick Actions**:
- **Add Device**: Onboard new edge device
- **Device Health Check**: Run diagnostics
- **Configuration Backup**: Export device config
- **Decommission Device**: Remove from monitoring

### 3. Vulnerabilities - Risk Assessment

Track and manage security vulnerabilities across all devices.

**Vulnerability Dashboard**:

```
┌──────────────────────────────────────────────────────────┐
│              Vulnerability Management                     │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Open Vulnerabilities: 23                                │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ 5 Critical  │  │ 8 High      │  │ 10 Medium   │     │
│  │   CVEs      │  │   CVEs      │  │    CVEs     │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                          │
│  Top Vulnerabilities                                     │
│  ────────────────────────────────────────────────────   │
│  CVE-2025-12345  ⚠️ Critical  12 devices affected       │
│    Type: Remote Code Execution                           │
│    CVSS: 9.8                                             │
│    Patch Available: Yes                                  │
│    [View Details] [Apply Patch] [Ignore]                │
│                                                          │
│  CVE-2025-23456  ⚠️ High      8 devices affected        │
│    Type: SQL Injection                                   │
│    CVSS: 8.1                                             │
│    Patch Available: Yes                                  │
│    [View Details] [Apply Patch] [Ignore]                │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Features**:
- **CVE Tracking**: Monitor known vulnerabilities
- **Vulnerability Scanner**: Automated scanning (Nessus, OpenVAS)
- **Patch Management**: Deploy patches to affected devices
- **Risk Scoring**: Prioritize based on CVSS and exposure
- **Compliance Reports**: PCI-DSS, NIST, ISO 27001 compliance

**Vulnerability Lifecycle**:
```
CVE Published → Detected → Assessed → Patched → Verified → Closed
```

### 4. SOAR - Automated Response

Security Orchestration, Automation and Response platform.

**Playbook Dashboard**:

```
┌──────────────────────────────────────────────────────────┐
│           SOAR - Automated Incident Response             │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Active Playbooks: 12        Executions (24h): 45       │
│                                                          │
│  Playbook Library                                        │
│  ─────────────────────────────────────────────────────  │
│                                                          │
│  🤖 SQL Injection Response                               │
│     Trigger: WAF detects SQL injection attempt           │
│     Actions:                                             │
│       1. Block attacker IP (WAF + firewall)             │
│       2. Take database snapshot                          │
│       3. Enable query logging                            │
│       4. Run integrity check                             │
│       5. Notify security team                            │
│     Last Run: 15 minutes ago                             │
│     [Edit] [Run Now] [View History]                     │
│                                                          │
│  🤖 DDoS Mitigation                                      │
│     Trigger: XDP detects traffic anomaly                 │
│     Actions:                                             │
│       1. Activate XDP filtering                          │
│       2. Rate limit suspicious IPs                       │
│       3. Enable Cloudflare DDoS protection              │
│       4. Alert on-call engineer                          │
│       5. Generate incident report                        │
│     Last Run: 2 hours ago                                │
│     [Edit] [Run Now] [View History]                     │
│                                                          │
│  🤖 Ransomware Detection & Response                      │
│     Trigger: Unusual encryption activity + network spike │
│     Actions:                                             │
│       1. Isolate affected device from network            │
│       2. Snapshot all volumes                            │
│       3. Kill suspicious processes                       │
│       4. Quarantine files                                │
│       5. Initiate forensic collection                    │
│       6. Escalate to incident response team              │
│     Last Run: Never (waiting for trigger)                │
│     [Edit] [Test] [View Details]                        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Playbook Features**:
- **Visual Workflow Builder**: Drag-and-drop playbook creation
- **Conditional Logic**: If/then branching based on conditions
- **Integration**: POD-007 (Kali Linux), POD-008 (n8n)
- **Action Library**: Pre-built actions (block IP, snapshot, alert)
- **Testing**: Dry-run mode to test playbooks
- **Audit Trail**: Complete history of all executions

**Creating a Playbook**:

1. Click **Create Playbook**
2. Define trigger (alert type, Qsecbit threshold, etc.)
3. Add actions (sequential or parallel)
4. Set conditions and branching
5. Configure notifications
6. Test playbook
7. Enable for production

**Example Playbook Actions**:
- Block IP at firewall/WAF
- Snapshot database/file system
- Run Kali Linux tool (nmap, nikto, etc.)
- Send alert (email, Slack, PagerDuty)
- Create ticket (Jira, ServiceNow)
- Isolate device from network
- Collect forensic evidence

### 5. xSOC - Extended SOC Capabilities

Advanced security operations and threat intelligence.

**xSOC Dashboard**:

```
┌──────────────────────────────────────────────────────────┐
│              Extended SOC (xSOC) Operations              │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Threat Intelligence                                     │
│  ────────────────────────────────────────────────────   │
│  • 1,234 IOCs tracked (IPs, domains, hashes)            │
│  • 45 new threat actors identified (last 7 days)        │
│  • 12 active campaigns affecting customers              │
│                                                          │
│  Cross-Tenant Correlation                                │
│  ────────────────────────────────────────────────────   │
│  🔴 Coordinated Attack Detected                          │
│     Pattern: SQL injection from 192.168.0.0/16          │
│     Affected: 3 customers (Acme, Widget, Tech)          │
│     Timeline: Started 2 hours ago                        │
│     Recommendation: Block entire subnet                  │
│     [Investigate] [Block All] [Generate Report]         │
│                                                          │
│  Advanced Analytics                                      │
│  ────────────────────────────────────────────────────   │
│  [Custom Query Builder]                                  │
│  ┌────────────────────────────────────────────────┐     │
│  │ SELECT src_ip, count(*) as attacks              │     │
│  │ FROM security_events                             │     │
│  │ WHERE timestamp >= now() - INTERVAL 7 DAY        │     │
│  │ GROUP BY src_ip                                  │     │
│  │ ORDER BY attacks DESC LIMIT 10;                  │     │
│  └────────────────────────────────────────────────┘     │
│  [Run Query] [Save Query] [Export Results]              │
│                                                          │
│  Threat Hunting Workbench                                │
│  ────────────────────────────────────────────────────   │
│  • Active investigations: 3                              │
│  • Saved queries: 28                                     │
│  • Threat hypotheses: 5                                  │
│  [New Investigation] [View Saved Queries]               │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**xSOC Features**:

**1. Threat Intelligence**:
- IOC (Indicators of Compromise) tracking
- Threat actor attribution
- Campaign monitoring
- Integration with threat feeds (MISP, STIX/TAXII)
- Custom threat intelligence enrichment

**2. Cross-Tenant Correlation**:
- Detect attacks spanning multiple customers
- Identify coordinated campaigns
- Share anonymized threat intelligence
- Early warning system for emerging threats
- Collective defense benefit

**3. Advanced Query Builder**:
- **Data Sources**: ClickHouse (edge), Apache Doris (cloud)
- **Query Languages**: SQL, Kusto Query Language (KQL)
- **Visualization**: Charts, graphs, tables
- **Export**: CSV, JSON, PDF reports
- **Scheduling**: Automated query execution

**Example Queries**:

```sql
-- Top attack types (all tenants)
SELECT attack_type, COUNT(*) as count,
       COUNT(DISTINCT tenant_id) as tenants_affected
FROM security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY attack_type
ORDER BY count DESC
LIMIT 10;

-- Qsecbit RED/AMBER alerts by customer
SELECT tenant_id, rag_status, COUNT(*) as alerts
FROM qsecbit_scores
WHERE rag_status IN ('RED', 'AMBER')
  AND timestamp >= now() - INTERVAL 7 DAY
GROUP BY tenant_id, rag_status
ORDER BY alerts DESC;

-- DDoS attack timeline
SELECT
    toStartOfHour(timestamp) as hour,
    COUNT(*) as packets,
    uniq(src_ip) as unique_ips
FROM network_flows
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY hour
ORDER BY hour ASC;
```

**4. Threat Hunting**:
- **Hypothesis-driven hunting**: Start with a threat hypothesis
- **IOC pivoting**: Pivot from one IOC to related indicators
- **Timeline analysis**: Reconstruct attack timelines
- **Behavioral analysis**: Detect anomalous patterns
- **Collaboration**: Share findings with team

**5. Investigation Workbench**:
- Create investigation cases
- Assign to analysts
- Track evidence and findings
- Timeline visualization
- Collaborate in real-time

---

## 📈 Analytics & Reporting

### Security Metrics

**Key Performance Indicators (KPIs)**:
- **Mean Time to Detect (MTTD)**: Average detection time
- **Mean Time to Respond (MTTR)**: Average response time
- **False Positive Rate**: Percentage of false alarms
- **Coverage Rate**: Percentage of devices monitored
- **Threat Exposure Score**: Overall risk level

### Compliance Reports

**Supported Frameworks**:
- **PCI-DSS**: Payment card industry compliance
- **NIST Cybersecurity Framework**: NIST CSF alignment
- **ISO 27001**: Information security management
- **GDPR**: Data protection compliance
- **SOC 2**: Service organization controls

**Report Generation**:
1. Navigate to **Reports → Generate Report**
2. Select framework (PCI-DSS, NIST, etc.)
3. Choose time period (last month, quarter, year)
4. Select customers/devices
5. Click **Generate Report**
6. Download as PDF or Word document

### Custom Dashboards

**Create Custom Views**:
1. Navigate to **xSOC → Custom Dashboards**
2. Click **Create Dashboard**
3. Add widgets (charts, tables, gauges)
4. Configure data sources and queries
5. Arrange layout
6. Save and share with team

**Example Custom Dashboard**:
- Executive summary (for management)
- Customer-specific view (for individual customers)
- SOC analyst view (for day-to-day operations)
- Compliance view (for auditors)

---

## 🔐 Access Control

### Role-Based Access Control (RBAC)

| Role | Permissions | Typical User |
|------|------------|--------------|
| **MSSP Admin** | All tenants, full access | MSSP owner, senior security architect |
| **MSSP Analyst** | All tenants, read-only | SOC analyst, security researcher |
| **Tenant Admin** | Single tenant, full access | Customer administrator |
| **Tenant Viewer** | Single tenant, read-only | Customer viewer, auditor |
| **Incident Responder** | All tenants, response actions | Security incident responder |

### Permissions Matrix

| Action | MSSP Admin | MSSP Analyst | Tenant Admin | Tenant Viewer |
|--------|------------|--------------|--------------|---------------|
| View all devices | ✅ | ✅ | ❌ (own only) | ❌ (own only) |
| Configure devices | ✅ | ❌ | ✅ (own only) | ❌ |
| Run playbooks | ✅ | ✅ | ✅ (own only) | ❌ |
| View security events | ✅ | ✅ | ✅ (own only) | ✅ (own only) |
| Export data | ✅ | ✅ | ✅ (own only) | ❌ |
| Manage users | ✅ | ❌ | ❌ | ❌ |
| Cross-tenant queries | ✅ | ✅ | ❌ | ❌ |

---

## 🛠️ Troubleshooting

### Dashboard Not Loading

```bash
# Check Django and frontend services
podman ps | grep django
podman logs hookprobe-pod-001-web-dmz-django

# Check database connection
podman exec hookprobe-pod-001-web-dmz-django python manage.py check

# Verify network connectivity
ping 10.200.3.12  # PostgreSQL POD-003
ping 10.200.5.13  # ClickHouse POD-005

# Restart services
podman restart hookprobe-pod-001-web-dmz-django
```

### Device Not Appearing

```bash
# Check device registration
podman exec hookprobe-pod-001-web-dmz-django \
    python manage.py shell
>>> from devices.models import EdgeDevice
>>> EdgeDevice.objects.all()

# Verify edge device is reporting metrics
curl http://DEVICE_IP:9100/metrics

# Check network connectivity (VXLAN)
ping 10.200.X.X  # Device IP in POD network
```

### Qsecbit Scores Not Updating

```bash
# Check Qsecbit service
curl http://localhost:8888/health
podman logs hookprobe-pod-007-ai-response-qsecbit

# Verify data ingestion
clickhouse-client --query "SELECT COUNT(*) FROM security.qsecbit_scores WHERE timestamp >= now() - INTERVAL 1 HOUR"

# Restart Qsecbit
podman restart hookprobe-pod-007-ai-response-qsecbit
```

---

## 📚 Additional Resources

- **Main README**: [../../README.md](../../README.md)
- **Dashboard Overview**: [README.md](README.md)
- **Admin Dashboard**: [admin-dashboard.md](admin-dashboard.md)
- **Security Model**: [../architecture/security-model.md](../architecture/security-model.md)
- **Qsecbit Algorithm**: [../../src/qsecbit/README.md](../../src/qsecbit/README.md)

---

## 📞 Support

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **MSSP Documentation**: [../../docs/installation/cloud-deployment.md](../../docs/installation/cloud-deployment.md)
- **Community**: [CONTRIBUTING.md](../../docs/CONTRIBUTING.md)

---

**MSSP Dashboard** - *Multi-Tenant Security Operations at Scale*

Built with ❤️ for managed security service providers and enterprise SOC teams
