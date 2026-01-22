# HookProbe Autonomous Defense – N8N Automation Framework

## 🎯 Overview

HookProbe's automation framework implements **autonomous threat detection and response** using n8n workflow orchestration, QSECBIT algorithmic scoring, and multi-database analytics.

**Mission**: Democratize autonomous cybersecurity for small businesses, smart homes, and edge devices.

**Core Loop**: **detect → learn → adapt → self-heal**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         EDGE LAYER                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ HookProbe    │  │ QSECBIT      │  │ ClickHouse   │          │
│  │ Agent        │→│ Local Engine │→│ Edge Node    │          │
│  │ (POD 006)    │  │ (POD 006)    │  │ (POD 005)    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                            ↓ Encrypted Telemetry
                            ↓ (WireGuard/Tailscale/Cloudflare)
┌─────────────────────────────────────────────────────────────────┐
│                        CLOUD LAYER                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ n8n          │  │ QSECBIT      │  │ ClickHouse   │          │
│  │ Orchestrator │←→│ Global Engine│←→│ HA Cluster   │          │
│  │ (POD 008)    │  │              │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         ↓                  ↓                  ↓                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ VictoriaMetrics│ │ Apache Doris │  │ MCP Server   │          │
│  │ Alerting     │  │ Analytics    │  │ AI Messaging │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Automation Flow Pipeline

### Step 1: Event Collection
```
Sources:
├── System Logs (journald, syslog)
├── Network Packets (Zeek, Snort)
├── Container Events (podman events)
├── File System (inotify)
└── API Calls (ModSecurity, NAXSI)
```

### Step 2: QSECBIT Pre-Filtering
```python
# Risk Scoring Algorithm
risk_score = qsecbit_engine.analyze(event)

if risk_score >= 0.7:  # High Risk Threshold
    → Deep Packet Analysis
    → Threat Correlation
else:
    → Log to ClickHouse (low priority)
```

### Step 3: Threat Intelligence Correlation
```
High-Risk Events → Query Threat Feeds:
├── Nmap Service Fingerprinting
├── Metasploit Exploit Database
├── YARA Malware Signatures
├── OSINT Feeds (AlienVault OTX, AbuseIPDB)
└── Internal Threat History (ClickHouse)
```

### Step 4: Data Storage
```
ClickHouse Tables:
├── security_events (all events)
├── threat_correlation (matched threats)
├── qsecbit_scores (risk timeline)
└── automated_responses (action log)

VictoriaMetrics Metrics:
├── hookprobe_threat_score (gauge)
├── hookprobe_events_total (counter)
└── hookprobe_response_duration (histogram)
```

### Step 5: Automated Response
```
Response Actions (based on risk score):
├── 0.9-1.0: CRITICAL → Immediate device isolation
├── 0.8-0.9: HIGH     → Block IP + Alert SOC
├── 0.7-0.8: MEDIUM   → Rate limit + Monitor
└── <0.7:    LOW      → Log only
```

---

## 📦 Deployment Models

### 1️⃣ Edge Deployment (Single-Tenant)
```yaml
Components:
  - HookProbe Agent (PODs 001-007)
  - Local QSECBIT Engine
  - ClickHouse Single Node
  - Optional: n8n (POD 008)

Use Cases:
  - Home networks
  - Small office
  - Branch offices
```

### 2️⃣ Cloud Deployment (Service Provider Multi-Tenant)
```yaml
Components:
  - n8n Cluster (3+ nodes)
  - QSECBIT Global Engine
  - ClickHouse HA (3+ replicas)
  - VictoriaMetrics Cluster
  - Apache Doris Lakehouse

Use Cases:
  - Service providers
  - Enterprise SOC
  - Multi-customer management
```

### 3️⃣ Hybrid Deployment (Recommended)
```yaml
Components:
  - Edge: Local processing + caching
  - Cloud: Centralized analytics + ML
  - Encrypted Tunnels: WireGuard/Cloudflare

Benefits:
  - Low latency edge response
  - Centralized threat intelligence
  - Privacy-preserving telemetry
```

---

## 🛡️ Modular Defense Groups

### Group A: Highest Impact (Deploy First)

#### 1. Attack Surface Mapping
```javascript
// N8N Workflow: API-Diff-Engine
Trigger: Hourly
Process:
  1. Scan all exposed endpoints (Nmap)
  2. Compare with baseline (ClickHouse)
  3. Alert on new services
  4. Auto-update firewall ACLs
```

#### 2. Credential Attack Defense
```javascript
// N8N Workflow: Adaptive-Ban-Logic
Trigger: Failed auth attempt
Process:
  1. QSECBIT score login attempt
  2. Correlate with known attack patterns
  3. Adaptive ban duration (exponential backoff)
  4. Notify admin on persistent attacks
```

#### 3. Container Runtime Guardian
```javascript
// N8N Workflow: Container-Security-Monitor
Trigger: Podman event
Process:
  1. Detect privileged containers
  2. Check image signatures
  3. Monitor runtime syscalls
  4. Alert on suspicious activity
```

#### 4. IoT Device Integrity
```javascript
// N8N Workflow: TPM-PCR-Monitor
Trigger: Device boot / periodic check
Process:
  1. Read TPM PCR values
  2. Compare with golden measurements
  3. Alert on tampering
  4. Isolate compromised devices
```

### Group B: Medium Priority

#### 5. DNS/C2 Detection
```javascript
// N8N Workflow: DNS-C2-Detector
Trigger: DNS query
Process:
  1. Analyze query patterns (DGA detection)
  2. Check against C2 IOC lists
  3. Block malicious domains
  4. Update local DNS blocklist
```

#### 6. Behavioral Analytics
```javascript
// N8N Workflow: User-Behavior-Analytics
Trigger: User activity
Process:
  1. Build user behavior baselines
  2. Detect anomalies (ML model)
  3. Flag suspicious sessions
  4. MFA challenge on high risk
```

#### 7. Lateral Movement Prediction
```javascript
// N8N Workflow: Lateral-Movement-Detector
Trigger: Network connection
Process:
  1. Map internal network topology
  2. Detect unusual peer connections
  3. Alert on lateral movement patterns
  4. Micro-segment network
```

### Group C: Learning-Focused

#### 8. Metasploit SafeMode Testing
```javascript
// N8N Workflow: Safe-Pen-Testing
Trigger: Manual / Scheduled
Process:
  1. Run Metasploit in isolated VLAN
  2. Test defense effectiveness
  3. Generate coverage reports
  4. Tune detection rules
```

#### 9. Data Exfiltration Detection
```javascript
// N8N Workflow: Exfil-Detector
Trigger: Large data transfer
Process:
  1. Monitor egress traffic volume
  2. Detect unusual patterns
  3. DLP content inspection
  4. Block suspicious transfers
```

#### 10. Wireless Threat Monitoring
```javascript
// N8N Workflow: WiFi-Threat-Monitor
Trigger: WiFi event
Process:
  1. Detect rogue access points
  2. Monitor deauth attacks
  3. Alert on evil twin attempts
  4. Auto-ban malicious devices
```

---

## 🚀 Implementation

### File Structure
```
install/addons/n8n/
├── AUTOMATION.md                    # This file
├── README.md                        # n8n setup guide
├── setup.sh                         # Installation script
├── config.sh                        # Configuration
├── workflows/                       # N8N workflow definitions
│   ├── core/
│   │   ├── event-ingestion.json
│   │   ├── qsecbit-scoring.json
│   │   ├── threat-correlation.json
│   │   └── automated-response.json
│   ├── group-a/
│   │   ├── attack-surface-mapping.json
│   │   ├── credential-defense.json
│   │   ├── container-guardian.json
│   │   └── iot-integrity.json
│   ├── group-b/
│   │   ├── dns-c2-detection.json
│   │   ├── behavioral-analytics.json
│   │   └── lateral-movement.json
│   └── group-c/
│       ├── metasploit-testing.json
│       ├── exfiltration-detection.json
│       └── wireless-monitoring.json
├── integrations/                    # Integration code
│   ├── qsecbit/
│   │   ├── client.py               # QSECBIT API client
│   │   ├── scorer.py               # Risk scoring logic
│   │   └── __init__.py
│   ├── clickhouse/
│   │   ├── client.py               # ClickHouse connector
│   │   ├── schema.sql              # Table definitions
│   │   └── queries.py              # Common queries
│   ├── victoriametrics/
│   │   ├── client.py               # VM client
│   │   └── alerts.yaml             # Alert rules
│   └── threat-intel/
│       ├── nmap_scanner.py
│       ├── metasploit_lookup.py
│       ├── yara_scanner.py
│       └── osint_feeds.py
├── tests/                           # Test suites
│   ├── test_workflows.py
│   ├── test_integrations.py
│   └── fixtures/
└── .github/
    └── workflows/
        └── n8n-ci.yml              # GitHub Actions CI/CD
```

### Quick Start

```bash
# 1. Run configuration wizard
cd hookprobe
sudo ./install.sh
# Select: [c] Configuration Wizard → [3] n8n Addon

# 2. Install n8n with automation
sudo ./install.sh
# Select: [3] Install n8n Workflow Automation

# 3. Import workflows
n8n import:workflow --input=install/addons/n8n/workflows/core/*.json

# 4. Verify installation
curl http://localhost:5678/healthz
```

---

## 📊 Monitoring & Metrics

### VictoriaMetrics Dashboards

**Threat Overview Dashboard:**
```
Panels:
├── Real-time threat score (gauge)
├── Events per second (graph)
├── Top attacked services (table)
├── Response time histogram
└── Geographical threat map
```

**QSECBIT Analytics Dashboard:**
```
Panels:
├── Score distribution (heatmap)
├── False positive rate (%)
├── Detection accuracy (%)
└── Model performance metrics
```

### ClickHouse Queries

**Top Threats (Last Hour):**
```sql
SELECT
    source_ip,
    COUNT(*) as event_count,
    AVG(qsecbit_score) as avg_score,
    MAX(qsecbit_score) as max_score
FROM security_events
WHERE timestamp >= now() - INTERVAL 1 HOUR
    AND qsecbit_score >= 0.7
GROUP BY source_ip
ORDER BY max_score DESC
LIMIT 10;
```

**Response Effectiveness:**
```sql
SELECT
    response_action,
    COUNT(*) as total_actions,
    AVG(response_duration_ms) as avg_duration,
    SUM(CASE WHEN success = true THEN 1 ELSE 0 END) / COUNT(*) * 100 as success_rate
FROM automated_responses
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY response_action;
```

---

## 🧪 Testing

### Workflow Tests
```python
# tests/test_workflows.py
def test_event_ingestion():
    """Test event ingestion workflow"""
    event = create_test_event(risk=0.9)
    result = n8n_client.trigger_workflow("event-ingestion", event)
    assert result['status'] == 'success'
    assert result['qsecbit_score'] >= 0.7

def test_automated_response():
    """Test automated response actions"""
    high_risk_event = create_critical_event()
    response = n8n_client.trigger_workflow("automated-response", high_risk_event)
    assert response['action'] == 'ISOLATE_DEVICE'
    assert response['firewall_rule_applied'] == True
```

### Integration Tests
```python
# tests/test_integrations.py
def test_qsecbit_integration():
    """Test QSECBIT API integration"""
    from integrations.qsecbit import QsecbitClient

    client = QsecbitClient(api_url="http://localhost:8888")
    score = client.score_event(test_event)
    assert 0.0 <= score <= 1.0

def test_clickhouse_ingestion():
    """Test ClickHouse data ingestion"""
    from integrations.clickhouse import ClickHouseClient

    ch = ClickHouseClient()
    ch.insert_event(test_event)
    result = ch.query("SELECT COUNT(*) FROM security_events WHERE source_ip = '192.168.1.100'")
    assert result > 0
```

---

## 🔧 CI/CD Pipeline

### GitHub Actions Workflow
```yaml
# .github/workflows/n8n-ci.yml
name: N8N Automation CI/CD

on:
  push:
    paths:
      - 'install/addons/n8n/**'
  pull_request:
    paths:
      - 'install/addons/n8n/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r install/addons/n8n/integrations/requirements.txt
          pip install pytest pytest-cov

      - name: Run tests
        run: |
          pytest install/addons/n8n/tests/ --cov --cov-report=xml

      - name: Validate workflows
        run: |
          python install/addons/n8n/tests/validate_workflows.py

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  deploy:
    needs: test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to n8n
        run: |
          # Auto-deploy workflows to production n8n instance
          echo "Deploying workflows..."
```

---

## 📈 Development Roadmap

### Phase 1: Core MVP (Weeks 1-2)
- ✅ Event ingestion pipeline
- ✅ QSECBIT integration
- ✅ ClickHouse storage
- ✅ Basic automated responses

### Phase 2: Group A Features (Weeks 3-4)
- ✅ Attack surface mapping
- ✅ Credential defense
- ✅ Container guardian
- ✅ IoT integrity monitoring

### Phase 3: Intelligence Layer (Weeks 5-6)
- 🔄 Nmap integration
- 🔄 Metasploit correlation
- 🔄 YARA scanning
- 🔄 OSINT feed ingestion

### Phase 4: Advanced Analytics (Weeks 7-8)
- 🔄 VictoriaMetrics dashboards
- 🔄 Apache Doris lakehouse
- 🔄 ML model integration
- 🔄 Behavioral analytics

### Phase 5: Group B Features (Weeks 9-10)
- ⏳ DNS/C2 detection
- ⏳ User behavior analytics
- ⏳ Lateral movement detection

### Phase 6: Group C Features (Weeks 11-12)
- ⏳ Metasploit SafeMode
- ⏳ Exfiltration detection
- ⏳ Wireless monitoring

### Phase 7: Community & Scale (Weeks 13+)
- ⏳ Threat exchange platform
- ⏳ Multi-tenancy enhancements
- ⏳ Autonomous remediation
- ⏳ Zero-trust automation

**Legend:** ✅ Complete | 🔄 In Progress | ⏳ Planned

---

## 🔐 Security Considerations

### Data Privacy
- All telemetry encrypted in transit (WireGuard/TLS)
- GDPR-compliant data retention policies
- Anonymization of sensitive data
- Edge-first processing (minimize cloud exposure)

### Access Control
- n8n workflows require authentication
- API keys rotated automatically
- Audit logs for all automation actions
- Role-based access control (RBAC)

### Resilience
- Edge autonomy (survives cloud outage)
- Workflow state persistence
- Graceful degradation on failures
- Automated health checks

---

## 🤝 Contributing

See [CONTRIBUTING.md](../../docs/CONTRIBUTING.md) for development guidelines.

**Key Areas for Contribution:**
- Additional workflow templates
- Threat intelligence integrations
- ML model improvements
- Documentation enhancements

---

## 📚 References

- [N8N Documentation](https://docs.n8n.io/)
- [QSECBIT Algorithm](../../core/qsecbit/README.md)
- [ClickHouse Quick Start](../../docs/guides/clickhouse-quick-start.md)
- [VictoriaMetrics Setup](https://victoriametrics.com/)
- [HookProbe Architecture](../../ARCHITECTURE.md)

---

## 📞 Support

- **GitHub Issues**: [hookprobe/hookprobe/issues](https://github.com/hookprobe/hookprobe/issues)
- **Documentation**: [docs/](../../docs/)
- **Community**: [Discussions](https://github.com/hookprobe/hookprobe/discussions)

---

**Last Updated**: 2025-11-26
**Version**: 5.0
**Status**: Implementation In Progress
