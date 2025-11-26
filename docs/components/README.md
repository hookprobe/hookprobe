# HookProbe POD Components

**Modular Security Architecture - Defense in Depth**

This directory contains detailed documentation for each POD (Point of Defense) in the HookProbe architecture.

---

## 📋 POD Overview

HookProbe uses a **modular POD architecture** where each POD serves a specific security or infrastructure function. All PODs communicate over **PSK-encrypted VXLAN tunnels** with **OpenFlow ACL enforcement**.

```
┌─────────────────────────────────────────────────────┐
│            HookProbe POD Architecture               │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │ POD-001  │  │ POD-002  │  │ POD-003  │         │
│  │   DMZ    │  │   IAM    │  │   DB     │         │
│  └──────────┘  └──────────┘  └──────────┘         │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │ POD-004  │  │ POD-005  │  │ POD-006  │         │
│  │  Cache   │  │ Monitor  │  │ Security │         │
│  └──────────┘  └──────────┘  └──────────┘         │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │ POD-007  │  │ POD-008  │  │ POD-009  │         │
│  │AI/Response│ │Automation│ │  Email   │         │
│  └──────────┘  └──────────┘  └──────────┘         │
│                                  (Optional)         │
└─────────────────────────────────────────────────────┘
```

---

## 🏗️ Core Infrastructure PODs (Required)

### POD-001: Web DMZ & Management
**Network**: 10.200.1.0/24 (VNI 201)

**Purpose**: Public-facing web services with WAF protection

**Components**:
- 🌐 **Nginx** - Reverse proxy and web server
- 🛡️ **NAXSI/ModSecurity WAF** - Web application firewall
- 🐍 **Django CMS** - Content management system
- 📡 **REST API** - Management and monitoring APIs

**Key Features**:
- Multi-layer DDoS protection (XDP + WAF)
- Automatic rule updates from threat intelligence
- Content delivery and caching
- Admin dashboard (AdminLTE)
- MSSP device management interface

**Documentation**: [POD-001.md](POD-001.md) *(to be created)*

---

### POD-002: Identity & Access Management
**Network**: 10.200.2.0/24 (VNI 202)

**Purpose**: Authentication, authorization, and SSO

**Components**:
- 🔐 **Logto** - Modern IAM platform
- 🎫 **OAuth 2.0 / OpenID Connect** - Token-based authentication
- 👥 **RBAC** - Role-based access control
- 🔑 **SSO** - Single sign-on across services

**Key Features**:
- JWT token verification
- Automatic user provisioning
- Social login support (Google, GitHub, etc.)
- Multi-factor authentication (MFA)
- API key management

**Documentation**: [POD-002.md](POD-002.md) | [IAM Integration Guide](../IAM-INTEGRATION-GUIDE.md)

---

### POD-003: Persistent Database
**Network**: 10.200.3.0/24 (VNI 203)

**Purpose**: Long-term data storage and persistence

**Components**:
- 🗄️ **PostgreSQL** - Relational database
- 📁 **NFS** - Network file storage (optional)
- 🔐 **RADIUS** - Network authentication (optional)

**Key Features**:
- High-availability clustering support
- Automated backups
- Encryption at rest
- Connection pooling
- Point-in-time recovery

**Documentation**: [POD-003.md](POD-003.md) *(to be created)*

---

### POD-004: Transient Database & Caching
**Network**: 10.200.4.0/24 (VNI 204)

**Purpose**: High-speed caching and session storage

**Components**:
- ⚡ **Redis** - In-memory data store
- 🔄 **Valkey** - Redis-compatible alternative (BSD license)

**Key Features**:
- Sub-millisecond latency
- Session management
- Real-time metrics caching
- Pub/Sub messaging
- Rate limiting backend

**Documentation**: [POD-004.md](POD-004.md) *(to be created)*

---

### POD-005: Monitoring & Analytics
**Network**: 10.200.5.0/24 (VNI 205)

**Purpose**: Observability, metrics, and logging

**Components**:
- 📊 **Grafana** - Dashboards and visualization
- ⏱️ **VictoriaMetrics** - Time-series metrics database
- 🗄️ **ClickHouse** - OLAP database for security analytics
- 📡 **Vector** - Log routing and transformation
- 📝 **Filebeat** - Zeek log ingestion
- 📈 **node_exporter** - Host metrics collection

**Key Features**:
- Real-time dashboards
- Long-term metrics retention
- Custom alerting rules
- Query performance for billions of events
- Multi-POD observability

**Documentation**: [POD-005.md](POD-005.md) *(to be created)*

---

### POD-006: Security Detection
**Network**: 10.200.6.0/24 (VNI 206)

**Purpose**: Intrusion detection and network monitoring

**Components**:
- 🔍 **Zeek** - Network security monitor (BSD)
- 🚨 **Snort 3** - IDS/IPS engine
- 🦅 **Suricata** - Multi-threaded IDS/IPS
- 🤖 **Qsecbit AI** - Threat analysis engine

**Key Features**:
- Signature-based detection
- Behavioral analysis
- Protocol anomaly detection
- Threat intelligence integration
- Real-time alerting

**Documentation**: [POD-006.md](POD-006.md) *(to be created)*

---

### POD-007: AI Response & Mitigation
**Network**: 10.200.7.0/24 (VNI 207)

**Purpose**: Automated threat response and countermeasures

**Components**:
- 🤖 **Qsecbit Engine** - AI threat scoring (RAG: Red/Amber/Green)
- 🐉 **Kali Linux** - On-demand security tools
- ⚡ **XDP/eBPF** - Kernel-level DDoS mitigation
- 🛡️ **Automated Response** - Threat mitigation orchestrator

**Key Features**:
- Real-time threat scoring (0-1.0 scale)
- Automated countermeasures
- On-demand tool deployment
- Network direction-aware detection
- Energy anomaly detection

**Documentation**: [POD-007.md](POD-007.md) | [../src/qsecbit/README.md](../../src/qsecbit/README.md)

---

## 🔌 Optional Extension PODs

### POD-008: Workflow Automation
**Network**: 10.200.8.0/24 (VNI 208)

**Purpose**: AI-powered automation and content generation

**Components**:
- 🔄 **n8n** - Workflow automation platform
- 🤖 **MCP Server** - AI content generation API
- 📝 **OpenAI/Anthropic Integration** - LLM support

**Key Features**:
- Automated blog post generation
- Security alert workflows
- Social media cross-posting
- Web scraping and analysis
- Custom integrations

**Documentation**: [POD-008.md](POD-008.md) | [../../install/addons/n8n/README.md](../../install/addons/n8n/README.md)

---

### POD-009: Enterprise Email System
**Network**: 10.200.9.0/24 (VNI 209)

**Purpose**: Self-hosted email with DMZ security

**Components**:
- 📧 **Postfix** - SMTP relay + mail server
- 📬 **Dovecot** - IMAP/POP3 server
- 🔐 **DKIM/SPF/DMARC** - Email authentication
- 🦅 **Suricata** - Email threat monitoring
- ☁️ **Cloudflare Tunnel** - Zero-trust access

**Key Features**:
- Dual-firewall DMZ architecture
- Email authentication (DKIM signing)
- Anti-spam and anti-phishing
- Secure remote access
- Full privacy control

**Documentation**: [POD-009.md](POD-009.md) | [../../infrastructure/pod-009-email/README.md](../../infrastructure/pod-009-email/README.md)

---

## 🔒 Security Architecture

### Network Isolation

Each POD runs in its own isolated VXLAN network (VNI):

```
┌────────────────────────────────────────────┐
│     Physical Network (eth0/wlan0)          │
└──────────────┬─────────────────────────────┘
               │
         ┌─────▼─────┐
         │OVS Bridge │
         └─────┬─────┘
               │
    ┌──────────┴──────────┐
    │PSK-Encrypted VXLAN  │
    │   (AES-256-GCM)     │
    └──────────┬──────────┘
               │
    ┌──────────┴──────────┬──────────┐
    │                     │          │
┌───▼───┐           ┌────▼──┐   ┌───▼───┐
│VNI 201│           │VNI 202│   │VNI 203│
│POD-001│           │POD-002│   │POD-003│
└───────┘           └───────┘   └───────┘
```

### OpenFlow ACLs

Each POD has specific firewall rules enforced at the OVS layer:

```bash
# Example: Allow Monitoring (POD-005) → Web (POD-001) for metrics
ovs-ofctl add-flow qsec-bridge \
  "table=0,priority=100,tun_id=205,ip,nw_dst=10.200.1.0/24,tcp,tp_dst=9100,actions=normal"

# Default deny
ovs-ofctl add-flow qsec-bridge \
  "table=0,priority=50,actions=drop"
```

### Zero Trust Principles

1. **Deny by Default**: All inter-POD traffic blocked unless explicitly allowed
2. **Least Privilege**: Each POD has minimal network access
3. **Encryption**: All POD-to-POD traffic encrypted (VXLAN PSK)
4. **Monitoring**: All traffic logged and analyzed (POD-006)
5. **Automated Response**: Threats detected and mitigated automatically (POD-007)

---

## 📊 POD Communication Matrix

| From POD | To POD | Purpose | Ports | Allowed? |
|----------|--------|---------|-------|----------|
| **001 (Web)** | 002 (IAM) | Authentication | 3000, 3001 | ✅ |
| **001 (Web)** | 003 (DB) | Database queries | 5432 | ✅ |
| **001 (Web)** | 004 (Cache) | Session storage | 6379 | ✅ |
| **005 (Monitor)** | ALL | Metrics collection | 9100, 9113 | ✅ |
| **006 (Security)** | 007 (AI) | IDS alerts | 8888 | ✅ |
| **007 (AI)** | ALL | Response actions | Various | ✅ |
| **008 (n8n)** | 001 (Web) | API access | 8000 | ✅ |
| **Default** | Any | - | - | ❌ Deny |

---

## 🚀 Quick Start

### Deploy All Core PODs

```bash
cd /home/user/hookprobe
sudo ./install.sh

# Select: 2) Select Deployment Mode
# Then: 1) Edge Deployment (or 2) MSSP Cloud Backend)
```

### Add Optional PODs

```bash
# From main menu
sudo ./install.sh

# Select: 5) Optional Extensions / Add-ons
# Choose:
#   1) POD-008: n8n Workflow Automation
#   2) POD-009: Email System & Notification
```

---

## 📈 Monitoring POD Health

All PODs export metrics to POD-005 (Grafana):

```bash
# Open Grafana
http://YOUR_IP:3000

# Key Dashboards:
# - "System Overview" - All POD health
# - "POD-001 Web DMZ" - WAF activity
# - "POD-006 Security" - IDS/IPS alerts
# - "POD-007 Qsecbit" - Threat scores
```

### Check Individual POD Status

```bash
# List all running PODs
podman pod ps

# Check specific POD
podman pod inspect hookprobe-pod-001-web-dmz

# View POD container logs
podman ps --pod --filter "pod=hookprobe-pod-001-web-dmz"
podman logs <container-name>
```

---

## 🛠️ Troubleshooting

### POD Won't Start

```bash
# Check POD status
podman pod ps -a

# Inspect POD
podman pod inspect <pod-name>

# Check logs
podman logs <container-name>

# Restart POD
podman pod restart <pod-name>
```

### Network Connectivity Issues

```bash
# Verify VXLAN tunnel
ovs-vsctl list-ports qsec-bridge

# Check OpenFlow rules
ovs-ofctl dump-flows qsec-bridge

# Test connectivity between PODs
podman exec <container> ping 10.200.X.X
```

### Performance Issues

```bash
# Check resource usage
podman stats

# View POD metrics in Grafana
http://YOUR_IP:3000

# Check disk space
df -h

# Check network throughput
iftop -i qsec-bridge
```

---

## 🤝 Contributing

Help us improve POD documentation!

### How to Contribute

1. Create detailed POD documentation (POD-001.md, POD-002.md, etc.)
2. Add deployment examples
3. Document common configurations
4. Share troubleshooting tips
5. Create integration guides

See [../../docs/CONTRIBUTING.md](../../docs/CONTRIBUTING.md) for guidelines.

---

## 📚 Additional Resources

- **Main README**: [../../README.md](../../README.md)
- **Architecture Overview**: [../architecture/security-model.md](../architecture/security-model.md)
- **Installation Guide**: [../../QUICK-START.md](../../QUICK-START.md)
- **Beginner's Guide**: [../installation/BEGINNER-GUIDE.md](../installation/BEGINNER-GUIDE.md)

---

**HookProbe POD Architecture** - *Modular Security by Design*

Built with ❤️ for defense-in-depth security by the HookProbe Team
