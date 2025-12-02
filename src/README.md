# HookProbe Source Code

**Democratizing Cybersecurity Through Edge Computing**

This directory contains the core source code for HookProbe's security and monitoring components.

---

## 📁 Directory Structure

```
src/
├── qsecbit/          # Qsecbit AI Threat Analysis Engine
├── response/         # Automated Response & Mitigation
└── web/              # Django Web Application & CMS
```

---

## 🤖 Qsecbit AI Engine (`qsecbit/`)

**Quantum Security Bit (Qsecbit)** - The heart of HookProbe's AI-powered threat detection.

### What is Qsecbit?

A cyber resilience metric measuring the smallest unit where AI-driven attack and defense reach equilibrium through continuous error correction. Think of it as a "security health score" that combines:

- **System Drift**: Deviation from baseline behavior
- **Attack Probability**: ML-predicted threat level
- **Classifier Decay**: ML confidence degradation
- **Quantum Drift**: System entropy changes
- **Energy Anomaly**: Power consumption patterns (Intel CPUs with RAPL)

### RAG Status System

- 🟢 **GREEN** (< 0.45): System resilient, all quiet
- 🟡 **AMBER** (0.45-0.70): Warning detected, defensive systems activating
- 🔴 **RED** (> 0.70): Critical threat, automated response engaged

### Features

✅ **XDP/eBPF DDoS Mitigation** - Kernel-level packet filtering
✅ **Energy Monitoring** - RAPL + per-process power tracking
✅ **Network Direction-Aware** - Detects compromised endpoints vs servers under attack
✅ **Dual-Database Support** - ClickHouse (edge) + Apache Doris (cloud)
✅ **Automated Response** - Kali Linux integration for counter-measures

**Documentation**: [src/qsecbit/README.md](qsecbit/README.md)

---

## 🛡️ Automated Response (`response/`)

**Kali Linux on-demand** - Automated threat mitigation and incident response.

### What It Does

When Qsecbit detects a threat (AMBER/RED status), the response engine automatically:

1. **Spins up Kali Linux container** (on-demand, lightweight)
2. **Analyzes the threat** using appropriate tools
3. **Implements countermeasures**:
   - Update WAF rules to block attack patterns
   - Add IP to blocklist
   - Capture network forensics
   - Generate incident reports
4. **Shuts down** when threat cleared (resource efficient)

### Supported Threat Types

| Threat | Response Actions |
|--------|------------------|
| **XSS Injection** | Update WAF rules, Block IP, Scan attacker, Generate report |
| **SQL Injection** | DB snapshot, Update WAF, Block IP, Enable logging, Integrity check |
| **Memory Overflow** | Capture diagnostics, Reduce limits, Clear caches, Safe restart |
| **DDoS Attack** | Enable XDP filtering, Rate limiting, GeoIP blocking |
| **Port Scan** | Tarpit attacker, Block subnet, Update firewall rules |

### Why Kali on-Demand?

- **Resource Efficient**: Only runs when needed (RAM savings on edge devices)
- **Always Updated**: Pulls latest image when threat detected
- **Professional Tools**: Metasploit, nmap, Wireshark, volatility
- **Automated**: No manual intervention required

**Documentation**: [src/response/README.md](response/README.md)

---

## 🌐 Web Application (`web/`)

**Django-powered CMS and Security Dashboard** - Optional web interface for HookProbe.

### Features

#### Public Website (Forty Theme)
- 🌐 Blog and content management
- 📧 Contact forms
- 📄 Static pages
- 🎨 Modern responsive design

#### Admin Dashboard (AdminLTE)
- 📊 System overview and POD health
- 🛒 Merchandise management (AI content + products)
- ✍️ Blog post editor
- 👥 User management

#### MSSP Dashboard
- 🔒 Security monitoring (SIEM)
- 📱 Multi-device management
- 📈 Real-time metrics
- 🎯 Threat hunting interface
- 🚨 Alert management

#### REST APIs
- 📡 Device registration and management
- 🔐 Security events ingestion
- 📊 Metrics collection
- 🤖 AI integration (n8n workflows)

### Why Optional?

The web server is an **addon** (not core infrastructure) because:

- Core security works without UI
- Edge devices can save resources
- MSSP can centralize web interface
- Staged deployment flexibility

### Installation

```bash
cd install/addons/webserver
sudo ./setup-webserver.sh edge
```

**Documentation**: [src/web/README.md](web/README.md) | [Setup Guide](web/SETUP_GUIDE.md)

---

## 🚀 Quick Start

### 1. Deploy Core HookProbe

```bash
cd /home/user/hookprobe
sudo ./install.sh
# Select: 2) Select Deployment Mode → 1) Edge Deployment
```

### 2. Access Qsecbit

```bash
# Check threat status
curl http://localhost:8888/status

# View current score
curl http://localhost:8888/score
```

### 3. Monitor in Grafana

Open http://YOUR_IP:3000 and look for:
- **Qsecbit Dashboard**: Real-time RAG status
- **Security Events**: IDS/IPS alerts
- **System Overview**: All POD health

---

## 🔧 Development

### Python Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r src/web/requirements.txt
pip install -r src/qsecbit/requirements.txt
```

### Running Components Locally

```bash
# Qsecbit (requires ClickHouse/Doris running)
cd src/qsecbit
python qsecbit.py --config /opt/hookprobe/config/qsecbit.conf

# Django web server (requires PostgreSQL + Redis)
cd src/web
python manage.py runserver 0.0.0.0:8000
```

### Running Tests

```bash
# Web application tests
cd src/web
python manage.py test

# Qsecbit tests
cd src/qsecbit
pytest tests/
```

---

## 🏗️ Architecture

### How Components Interact

```
┌─────────────────────────────────────────────┐
│              Network Traffic                │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────┐
│   XDP/eBPF Filter    │  ← DDoS mitigation at NIC level
│   (Qsecbit)          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   IDS/IPS Layer      │  ← Zeek, Snort, Suricata
│   (POD-006)          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Qsecbit Analysis   │  ← AI threat scoring
│   (POD-007)          │     - System drift
└──────────┬───────────┘     - Attack probability
           │                  - Energy anomalies
           │
           ├─── GREEN → Monitor only
           │
           ├─── AMBER → Kali spins up (defensive posture)
           │
           └─── RED ──┐
                      │
                      ▼
           ┌──────────────────────┐
           │  Response Engine     │  ← Automated countermeasures
           │  (Kali Container)    │     - Update WAF
           └──────────────────────┘     - Block IPs
                                         - Capture forensics
```

### Data Flow

```
1. Network Traffic → XDP Filter → IDS/IPS
                          ↓
2. Security Events → ClickHouse/Doris
                          ↓
3. Qsecbit Analysis → RAG Score → Response Decision
                          ↓
4. Kali Response → Mitigation Actions → WAF/Firewall Updates
                          ↓
5. Web Dashboard → Display Alerts → Operator Notification
```

---

## 📊 Performance

### Resource Usage (Typical Edge Deployment)

| Component | CPU (avg) | RAM | Storage | Notes |
|-----------|-----------|-----|---------|-------|
| **Qsecbit** | 5-15% | 500MB | 100MB | Spikes during analysis |
| **Response** | 0% idle | 0MB idle | 2GB image | On-demand only |
| **Web (Django)** | 2-5% | 300MB | 500MB | Optional addon |

### Scaling

- **Edge Device**: Handles 1-10 Gbps traffic, 10K events/sec
- **MSSP Backend**: 1000+ edge devices, 1M+ events/sec, 365+ day retention

---

## 🛠️ Troubleshooting

### Qsecbit Not Responding

```bash
# Check status
podman ps | grep qsecbit

# View logs
podman logs hookprobe-pod-007-ai-response-qsecbit

# Restart
podman restart hookprobe-pod-007-ai-response-qsecbit

# Test API
curl http://localhost:8888/health
```

### Response Engine Not Triggering

```bash
# Check Qsecbit score
curl http://localhost:8888/score

# Manual trigger (testing)
curl -X POST http://localhost:8888/trigger-response

# Check Kali container
podman ps -a | grep kali
```

### Web Dashboard Errors

```bash
# Check Django logs
journalctl -u hookprobe-web -n 50

# Test database connection
podman exec hookprobe-pod-003-db-persistent-postgres pg_isready

# Check Redis
podman exec hookprobe-pod-004-db-transient-redis redis-cli ping
```

---

## 🤝 Contributing

We welcome contributions to all source components!

### Areas for Contribution

- **Qsecbit Algorithm**: New threat detection methods, ML models
- **Response Actions**: Additional mitigation strategies
- **Web Interface**: New dashboards, widgets, visualizations
- **Integrations**: External tools, APIs, data sources

### Development Workflow

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Make changes
4. Test locally
5. Run CI checks (`./scripts/run-tests.sh`)
6. Submit PR with clear description

**See**: [CONTRIBUTING.md](../docs/CONTRIBUTING.md) for detailed guidelines

---

## 📚 Documentation

### Component-Specific

- **Qsecbit**: [src/qsecbit/README.md](qsecbit/README.md)
- **Response Engine**: [src/response/README.md](response/README.md)
- **Web Application**: [src/web/README.md](web/README.md) | [Setup Guide](web/SETUP_GUIDE.md)

### General

- **Architecture**: [docs/architecture/security-model.md](../docs/architecture/security-model.md)
- **Installation**: [QUICK-START.md](../QUICK-START.md)
- **Beginner's Guide**: [docs/installation/BEGINNER-GUIDE.md](../docs/installation/BEGINNER-GUIDE.md)

---

## 📄 License

All source code components are licensed under **MIT License** (HookProbe v5.0+).

- ✅ **Qsecbit Algorithm**: MIT (Andrei Toma)
- ✅ **Response Engine**: MIT (HookProbe Team)
- ✅ **Web Application**: MIT (HookProbe Team)

See [LICENSE](../LICENSE) for details.

---

## 📞 Support

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Security Contact**: qsecbit@hookprobe.com
- **Documentation**: https://github.com/hookprobe/hookprobe

---

**HookProbe** - *Democratizing Cybersecurity Through Edge Computing*

Built with ❤️ for the security community by Andrei Toma and the HookProbe Team
