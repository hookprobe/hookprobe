
# hookprobe
![Future City](images/hookprobe-future-ram-cine.png)

**"Single Board Computers (SBCs) and Security Operations Centers (SOCs): Leading the Charge in the Cybersecurity Battle"**

## 🎯 Overview

HookProbe is a comprehensive cybersecurity platform built on Single Board Computers (SBCs), providing enterprise-grade security capabilities for individuals, small businesses, and home networks. The platform combines cutting-edge AI-driven threat detection with automated response systems, making advanced cybersecurity accessible and affordable.

### Key Features

- **🤖 AI-Powered Threat Detection**: Qsecbit algorithm for real-time security analysis
- **🛡️ Automated Response**: Kali Linux on-demand threat mitigation
- **📊 Complete Monitoring**: Grafana + ClickHouse + VictoriaMetrics + Vector
- **🔒 Zero Trust Architecture**: PSK-encrypted VXLAN, OpenFlow ACLs, L2 hardening
- **🌐 Web Application Firewall**: NAXSI/ModSecurity with auto-updating rules
- **☁️ Optional Cloud Integration**: Cloudflare Tunnel for secure remote access
- **🔄 Workflow Automation**: Optional n8n integration for content generation

---

## 📖 Table of Contents

- [Background Story](#background-story)
- [Architecture](#architecture)
- [Hardware Compatibility](#hardware-compatibility)
  - [NIC Requirements for XDP/eBPF](#nic-requirements-for-xdpebpf-ddos-mitigation)
  - [Recommended Configurations](#recommended-hardware-configurations)
- [Getting Started](#getting-started)
- [Optional Features](#optional-features)
  - [n8n Workflow Automation](#n8n-workflow-automation-pod-008)
  - [LTE/5G Connectivity](#lte5g-connectivity)
- [Security Features](#security-features)
- [Monitoring & Analytics](#monitoring--analytics)
- [GDPR Compliance](#gdpr-compliance)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## 🌆 Background Story

In the year 2035, the digital landscape had evolved into a complex, interconnected web where threats lurked around every corner. Cyberattacks were no longer the domain of isolated hackers; they had become sophisticated operations executed by highly organized groups. Governments, corporations, and individuals alike were under constant siege from these digital marauders, who exploited every vulnerability to steal data, disrupt services, and wreak havoc.

In this climate of omnipresent danger, traditional security measures proved insufficient. Firewalls and antivirus software, once the mainstay of cybersecurity, could no longer keep pace with the rapid evolution of threats. The need for real-time detection and response had become paramount, and this necessity gave rise to an innovative solution: the integration of edge technology with Security Operations Centers (SOCs).

Edge technology, characterized by the use of decentralized computing resources at the "edge" of the network, offered a way to process data closer to its source, reducing latency and enabling real-time decision-making. This approach became the backbone of modern security infrastructure. Central to this transformation were single-board computers (SBCs) like Nvidia Jetson, Raspberry Pi and Banana Pi (Arm64 based SoCs) which empowered individuals to take an active role in their own digital defense.

In this new era, homes and small businesses deployed SBCs as personal security nodes. Equipped with advanced sensors and AI-driven software, these compact devices continuously monitored network traffic, identifying anomalies and potential threats with unprecedented speed and accuracy. The data collected by these SBCs was then relayed to a decentralized network of SOCs, where it was aggregated and analyzed in real-time.

Each SOC was a hub of activity, staffed by a new breed of cybersecurity analysts who used advanced tools to correlate data from thousands of edge devices. Machine learning algorithms sifted through the information, detecting patterns that indicated malicious activity. When a threat was identified, the SOC could issue immediate countermeasures, deploying patches, isolating infected devices, and even launching counter-hacks to neutralize the attackers.

In the heart of Bucharest, one such SOC was operated by a team of experts led by Andrei Toma, a former interior architect turned cybersecurity strategist. His command center was a high-tech fortress, filled with screens displaying live feeds from edge devices across the city. Andrei's team worked in shifts, ensuring 24/7 vigilance.

One evening, as HookProbe intelligence monitored the incoming data, a spike in traffic from a cluster of residential SBCs caught the intelligence eye. The pattern suggested a coordinated attack targeting smart home devices. With a few swift commands, iEYE directed the SOC's AI to analyze the data more closely. Within seconds, it identified the source: a botnet attempting root shell access in home security cameras and smart locks.

HookProbe activated the local SOC's response protocol. Alerts were sent to the affected households, activating DDoS protection by cutting down the connection, instructing residents that traffic was going to the back-up connection. Simultaneously, the SOC's AI deployed patches to seal the exploited vulnerabilities. For those already compromised, HookProbe's team used edge technology to isolate the infected devices from the rest of the network, preventing the spread of the attack.

Thanks to the decentralized nature of the edge network, the response was swift and efficient. The botnet was neutralized before it could cause significant damage, and the residents' digital lives were safeguarded.

As the crisis abated, HookProbe Team reflected on the power of this new paradigm. In a world where threats were everywhere, the combination of edge technology and SOCs provided a robust defense. Single-board computers like Nvidia Jetson, Raspberry Pi and Banana Pi had democratized cybersecurity, turning ordinary people into vigilant guardians of their digital realms. Through this collaborative effort, the digital world had become a safer place, where threats could be met and defeated in real time.

And so, in the face of ever-evolving dangers, humanity adapted and thrived, using the very technology that once made them vulnerable to create a resilient and secure digital future.

---

## 🏗️ Architecture

HookProbe v5.0 implements a **7-POD architecture** with optional 8th POD for automation:

### Core PODs (001-007)

| POD | Network | Purpose | Key Components |
|-----|---------|---------|----------------|
| **001** | 10.200.1.0/24 | Web DMZ | Django CMS, NAXSI WAF, Nginx, Cloudflare Tunnel |
| **002** | 10.200.2.0/24 | IAM/Auth | Keycloak, PostgreSQL |
| **003** | 10.200.3.0/24 | Persistent DB | PostgreSQL, NFS, RADIUS |
| **004** | 10.200.4.0/24 | Transient DB | Redis, Valkey |
| **005** | 10.200.5.0/24 | Monitoring | Grafana, VictoriaMetrics, ClickHouse, Vector, Filebeat, node_exporter |
| **006** | 10.200.6.0/24 | Security | Zeek, Snort 3, Qsecbit |
| **007** | 10.200.7.0/24 | AI Response | Honeypots, Kali Linux, Mitigation Engine |

### Optional POD (008)

| POD | Network | Purpose | Key Components |
|-----|---------|---------|----------------|
| **008** | 10.200.8.0/24 | Automation | n8n, PostgreSQL, Redis, MCP Server |

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet / WAN                           │
└──────────────────┬──────────────────────────────────────────┘
                   │
         ┌─────────▼─────────┐
         │  Physical Host    │
         │  (Intel N100)     │
         │  OVS Bridge       │
         └─────────┬─────────┘
                   │
    ┌──────────────┴──────────────┐
    │   PSK-Encrypted VXLAN       │
    │   (VNI 100-108)             │
    └──────────────┬──────────────┘
                   │
    ┏━━━━━━━━━━━━━┻━━━━━━━━━━━━━┓
    ┃    POD Network Isolation   ┃
    ┃    OpenFlow ACLs           ┃
    ┃    L2 Anti-Spoof           ┃
    ┗━━━━━━━━━━━━━┳━━━━━━━━━━━━━┛
                   │
    ┌──────────────┼──────────────┐
    │              │              │
┌───▼───┐     ┌───▼───┐     ┌───▼───┐
│POD 001│     │POD 002│ ... │POD 007│
│  DMZ  │     │  IAM  │     │  AI   │
└───────┘     └───────┘     └───────┘
                   │
              ┌────▼────┐
              │ POD 008 │ (Optional)
              │Automation│
              └─────────┘
```

### 🌐 Dual Deployment Architecture (v5.0)

HookProbe now supports **two deployment models**:

#### 1. **Edge Deployment** (Single-Tenant SBC)
```
Customer Site
┌──────────────────────┐
│ HookProbe SBC        │
│ Intel N100 (8-16GB)  │
│                      │
│ PODs 001-007:        │
│ - ClickHouse (local) │
│ - Qsecbit AI         │
│ - 0-90 day analytics │
│ - Complete isolation │
└──────────────────────┘
```

**Use Cases:**
- Home users
- Small businesses
- Branch offices
- Standalone security

#### 2. **MSSP Cloud Backend** (Multi-Tenant)
```
Cloud Infrastructure
┌────────────────────────────────────┐
│ Apache Doris Cluster (MSSP)       │
│                                    │
│ ┌────────────┐  ┌──────────────┐ │
│ │Frontend (3)│  │Backend (3+)  │ │
│ │Coordinators│  │Storage+Compute│ │
│ └────────────┘  └──────────────┘ │
│                                    │
│ Features:                          │
│ - Multi-tenant isolation           │
│ - 1000+ customer capacity          │
│ - Cross-customer threat intel      │
│ - GPU ML training (optional)       │
│ - 365+ day retention               │
└────────────────────────────────────┘
         ▲
         │ TLS Encrypted Streams
         │
    ┌────┴─────┬─────────┐
    │          │         │
┌───┴───┐  ┌───┴───┐ ┌──┴────┐
│Edge A │  │Edge B │ │Edge C │ ...
└───────┘  └───────┘ └───────┘
```

**Use Cases:**
- MSSP providers
- Enterprise multi-site
- Security research labs
- SOC operations

**See:** [Backend Deployment Guide](Documents/backend/README.md)

---

## 🖥️ Hardware Compatibility

### NIC Requirements for XDP/eBPF DDoS Mitigation

HookProbe v5.0 includes **kernel-level DDoS mitigation** via XDP (eXpress Data Path). Performance depends on NIC capabilities and XDP mode:

**XDP Modes**:
- **XDP-hw** (Layer 0): NIC hardware ASIC - Ultra-fast, rare
- **XDP-drv** (Layer 1): NIC driver - Fastest practical mode
- **XDP-skb** (Layer 1.5): Generic kernel - Universal fallback

| **Platform** | **NIC Model** | **Driver** | **XDP Mode** | **Max Throughput** | **Recommendation** |
|-------------|---------------|------------|--------------|-------------------|-------------------|
| **Raspberry Pi 4/5** | Broadcom SoC | bcmgenet | Layer 1.5 (SKB) | 1 Gbps | ⚠️ Dev/Lab only |
| **Raspberry Pi** | Realtek USB | r8152 | Layer 1.5 (SKB) | 1 Gbps | ⚠️ Limited perf |
| **Desktop** | Realtek PCIe | r8169 | Layer 1.5 (SKB) | 2.5 Gbps | ⚠️ Not production |
| **Intel N100** | **I211** | **igb** | **Layer 1 (DRV)** | **1 Gbps** | ✅ **Entry-level** |
| **Intel N100** | **I226** | **igc** | **Layer 1 (DRV)** | **2.5 Gbps** | ✅ **Best value** |
| **Server** | **X710** | **i40e** | **Layer 1 (DRV)** | **40 Gbps** | ✅ **Cloud backend** |
| **Server** | **E810** | **ice** | **Layer 1 (DRV)** | **100 Gbps** | ✅ **Enterprise** |
| **Mellanox** | **ConnectX-5/6/7** | **mlx5_core** | **Layer 0/1 (HW/DRV)** | **200 Gbps** | ✅ **Gold standard** |

**Legend**:
- **Layer 0 (XDP-hw)**: Hardware offload in NIC ASIC - Extremely rare, only Mellanox SmartNICs
- **Layer 1 (XDP-drv)**: Native driver mode - Full kernel bypass, < 1µs latency
- **Layer 1.5 (XDP-skb)**: Generic software mode - Partial bypass, 5-10µs latency, higher CPU

### Recommended Hardware Configurations

#### 💰 Budget Edge (< $300)
- **SBC**: Intel N100 (8GB RAM, ~$150)
- **NIC**: Intel I226-V (built-in, 2.5Gbps)
- **XDP**: Native DRV mode ✅
- **Performance**: 2.5 Gbps line rate DDoS filtering
- **Use Case**: Home lab, small office, development

#### 🏢 Production Edge ($300-$1000)
- **SBC**: Mini PC with Intel I211 or I226
- **NIC**: Intel I226-V (2.5Gbps)
- **XDP**: Native DRV mode ✅
- **Performance**: 1-2.5 Gbps sustained
- **Use Case**: Branch office, edge security appliance

#### ☁️ MSSP Cloud Backend ($2000+)
- **Server**: Dell R650/HP DL360 Gen11
- **NIC**: Intel X710 (40Gbps) or Mellanox ConnectX-5 (100Gbps)
- **XDP**: Native DRV + Hardware Offload ✅
- **Performance**: 40-100 Gbps aggregate
- **Use Case**: Multi-tenant MSSP, 100-1000 customers

### ⚠️ Important Notes

**Raspberry Pi Limitation**: Raspberry Pi 4/5 only supports XDP in generic (SKB) mode, which has higher CPU overhead and limited throughput. For production DDoS mitigation, use Intel N100 with I226 NIC for native XDP-DRV support.

**Intel N100 Advantage**: Best price/performance for edge deployment. Built-in I226 NIC provides full XDP-DRV support at 2.5 Gbps with minimal CPU overhead.

**See Complete Guide**: [Qsecbit XDP/eBPF Documentation](Scripts/autonomous/qsecbit/README.md)

---

## 🚀 Getting Started

Choose your deployment model:

### 📍 Option 1: Edge Deployment (Single-Tenant SBC)

**Hardware Requirements:**
- **CPU**: Intel N100 or equivalent x86_64 (4+ cores)
- **RAM**: 16GB minimum (32GB recommended)
- **Storage**: 500GB SSD minimum (1TB recommended)
- **Network**: 1Gbps NIC

**Software Requirements:**
- **OS** (automatically detected):
  - **RHEL-based**: RHEL 10, Fedora 40+, CentOS Stream 9+, Rocky Linux, AlmaLinux
  - **Debian-based**: Debian 12+, Ubuntu 22.04+/24.04+
- **Architecture**: x86_64 or ARM64 (ARMv8)
- **Root Access**: Required for installation
- **Internet**: Required for downloading container images

**Installation:**

```bash
# 1. Clone repository
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe/Scripts/autonomous/install/

# 2. Configure
nano network-config.sh
# Change: HOST_A_IP, passwords, PSK keys

# 3. Deploy
sudo ./setup.sh

# 4. Access Grafana
# http://YOUR_IP:3000 (admin/admin - change immediately!)
```

**See:** [Edge Deployment Checklist](Scripts/autonomous/install/checklist.md)

---

### ☁️ Option 2: MSSP Cloud Backend (Multi-Tenant)

**Hardware Requirements:**
- **CPU**: 32+ cores per node (128+ recommended for production)
- **RAM**: 128GB minimum (256GB+ recommended for production)
- **Storage**: 1TB NVMe SSD minimum (8TB+ recommended)
- **Network**: 10Gbps+ NIC
- **Cluster**: 3 Frontend + 3+ Backend nodes

**Software Requirements:**
- **OS** (automatically detected):
  - **RHEL-based**: RHEL 10, Fedora 40+, CentOS Stream 9+, Rocky Linux, AlmaLinux
  - **Debian-based**: Debian 12+, Ubuntu 22.04+/24.04+
  - **Virtualization**: Proxmox VE 8.x+
- **Architecture**: x86_64 only (cloud backend requires Intel Xeon/AMD EPYC)
- **Root Access**: Required
- **Podman**: 4.x+

**Installation:**

```bash
# 1. Clone repository
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe/Scripts/backend/install/

# 2. Configure
nano backend-network-config.sh
# Change: DORIS_ADMIN_PASSWORD, DORIS_BE_STORAGE, etc.

# 3. Deploy
sudo ./backend-setup.sh

# 4. Initialize Doris cluster
mysql -h 10.100.1.10 -P 9030 -uroot < /tmp/doris-init.sql

# 5. Create multi-tenant schemas
# (See Documents/backend/README.md)
```

**See:** [Backend Deployment Guide](Documents/backend/README.md)

---

### 🔗 Hybrid: Edge + Cloud (Recommended for MSSP)

Deploy edge devices at customer sites + centralized cloud backend:

1. **Deploy cloud backend** (as above)
2. **Deploy edge devices** at each customer site
3. **Configure edge → cloud streaming**:
   ```bash
   # On edge device
   export DEPLOYMENT_TYPE="edge"
   export TENANT_ID="customer_acme"
   export KAFKA_BOOTSTRAP_SERVERS="mssp.example.com:9092"
   ```

---

### 🔐 Critical Security Steps (Both Deployments)

**Before going to production:**
```bash
# Generate strong PSK keys
openssl rand -base64 32

# Change all default passwords:

3. **Deploy HookProbe**

```bash
chmod +x setup.sh
sudo ./setup.sh
```

Installation takes **15-20 minutes**.

4. **Access Services**

- **Django Admin**: http://YOUR_IP/admin (admin/admin)
- **Grafana**: http://YOUR_IP:3000 (admin/admin)
- **Logto Admin**: http://YOUR_IP:3002
- **Qsecbit API**: http://YOUR_IP:8888

⚠️ **IMPORTANT**: Change all default passwords immediately!

---

## 🔧 Optional Features

### n8n Workflow Automation (POD 008)

**Status**: Optional Extension

The n8n integration adds autonomous workflow automation capabilities to HookProbe, enabling:

- **Automated Content Generation**: AI-powered blog posts and security alerts
- **Web Scraping & Analysis**: Automated threat intelligence gathering
- **Security Workflow Automation**: Auto-publish Qsecbit alerts
- **Social Media Integration**: Cross-posting to multiple platforms
- **MCP Server**: AI content generation API with OpenAI/Anthropic support

#### Quick Start: n8n Integration

**Prerequisites:**
- Main HookProbe (PODs 001-007) must be deployed first
- Additional 4GB RAM recommended
- Ports 5678 (n8n) and 8889 (MCP) available

**Installation:**

```bash
cd hookprobe/Scripts/autonomous/install/

# Configure n8n
nano n8n_network-config.sh
# Change: N8N_BASIC_AUTH_PASSWORD, N8N_DB_POSTGRESDB_PASSWORD
# Optional: OPENAI_API_KEY, ANTHROPIC_API_KEY

# Deploy POD 008
chmod +x n8n_setup.sh
sudo ./n8n_setup.sh
```

**Access:**
- **n8n UI**: http://YOUR_IP:5678
- **MCP API**: http://YOUR_IP:8889

**Documentation**: See [N8N_README.md](../main/n8n/README.md) for complete guide

#### n8n Use Cases

1. **Autonomous Blogging**
   - Daily CVE monitoring → AI content generation → Auto-publish to Django CMS
   - Cross-post to LinkedIn, Twitter, Mastodon

2. **Security Automation**
   - Qsecbit RED alert → Generate incident report → Publish alert → Email team

3. **Threat Intelligence**
   - Monitor RSS feeds → Scrape articles → Analyze with AI → Create summaries

4. **Social Media Management**
   - New blog post → Generate captions → Cross-post to all platforms → Track engagement

**Starter Workflows Included:**
- `daily-blog-post.json` - Automated content generation
- `qsecbit-monitor.json` - Security threat monitoring

---

### LTE/5G Connectivity

**Status**: Optional Feature

Add cellular connectivity for failover, remote deployment, or primary internet access.

#### Supported Hardware

**Recommended Modems:**
- **Quectel RM520N-GL** (5G Sub-6 GHz, M.2 form factor)
- **Quectel RM502Q-AE** (5G, M.2 form factor)
- **Sierra Wireless EM9191** (5G, M.2 form factor)
- **Quectel EC25** (4G LTE Cat 4, mini PCIe)
- **Huawei ME909s-120** (4G LTE Cat 4, mini PCIe)

**Compatible SBCs with M.2 Slots:**
- Raspberry Pi 5 + M.2 HAT
- Banana Pi BPI-R3 (built-in M.2)
- Radxa ROCK 5B (M.2 E-Key slot)
- Orange Pi 5 Plus (M.2 M-Key slot)

#### Quick Setup

1. **Install Modem Hardware**

```bash
# For M.2 modems on Raspberry Pi 5
# Attach modem to M.2 HAT
# Connect antennas to modem

# For built-in M.2 (BPI-R3, ROCK 5B)
# Insert modem into M.2 slot
# Connect antennas
```

2. **Install Software**

```bash
# Install ModemManager and NetworkManager
sudo dnf install ModemManager NetworkManager

# Enable services
sudo systemctl enable --now ModemManager
sudo systemctl enable --now NetworkManager

# Verify modem detection
mmcli -L
```

3. **Configure Connection**

```bash
# Create connection profile
sudo nmcli connection add \
    type gsm \
    ifname '*' \
    con-name lte-wan \
    apn your.apn.here \
    connection.autoconnect yes

# Activate connection
sudo nmcli connection up lte-wan

# Check status
mmcli -m 0
```

4. **Configure Failover**

Edit `network-config.sh`:
```bash
# Primary WAN
PHYSICAL_HOST_INTERFACE="eth0"

# LTE Failover
LTE_INTERFACE="wwan0"
LTE_PRIORITY="100"  # Lower = higher priority

# Enable automatic failover
ENABLE_WAN_FAILOVER="true"
```

5. **Monitor Connection**

```bash
# Real-time modem status
watch -n 2 'mmcli -m 0 | grep -E "state|signal quality|operator"'

# Network metrics
nmcli device show wwan0

# Add to Grafana
# Metrics automatically exported via node_exporter
```

#### LTE Features

- **Automatic Failover**: Switch to LTE when primary WAN fails
- **Load Balancing**: Distribute traffic across WAN and LTE
- **VPN over LTE**: Full VPN support (WireGuard/OpenVPN)
- **Metrics Collection**: Signal strength, data usage, connection state
- **Grafana Dashboards**: Real-time monitoring of cellular connectivity

**Data Plans:**
- Recommended: Unlimited or >100GB/month for primary use
- Failover: 10-20GB/month typically sufficient

**Documentation**: See [LTE/README.md](../main/LTE/README.md) for detailed setup

---

## 🔒 Security Features

### Six-Layer Defense System

```
Layer 1: Kernel-Level (XDP/eBPF)
  ├─ DDoS mitigation at NIC level
  └─ Packet filtering before kernel stack

Layer 2: Network (OVS + VXLAN)
  ├─ PSK-encrypted tunnels
  ├─ OpenFlow anti-spoof ACLs
  └─ ARP/ND protection

Layer 3: Firewall (nftables)
  ├─ Default deny forwarding
  ├─ Per-service allowlist
  └─ Connection tracking + rate limiting

Layer 4: Application (WAF)
  ├─ NAXSI/ModSecurity
  ├─ XSS/SQL injection blocking
  └─ Auto-updating rulesets

Layer 5: Detection (IDS/IPS)
  ├─ Suricata + Zeek + Snort 3
  ├─ Signature-based detection
  └─ Behavioral analysis

Layer 6: AI Response (Qsecbit + Kali)
  ├─ Real-time threat scoring (RAG: Red/Amber/Green)
  ├─ Automated countermeasures
  └─ On-demand Kali Linux for mitigation
```

### Qsecbit AI Threat Analysis

**Quantum Security Bit (Qsecbit)** - A cyber resilience metric measuring the smallest unit where AI-driven attack and defense reach equilibrium through continuous error correction.

**v5.0 Features:**
- **Modular Architecture**: Clean separation of concerns (qsecbit.py, energy_monitor.py, xdp_manager.py, nic_detector.py)
- **XDP/eBPF DDoS Mitigation**: Kernel-level packet filtering with automatic NIC detection
- **Energy Monitoring**: RAPL + per-PID power tracking with anomaly detection
- **Network Direction-Aware Analysis**: Role-based traffic pattern detection (NEW in v5.0)
- **Dual-Database Support**: ClickHouse (edge) and Apache Doris (cloud)

**Algorithm Components:**

**Without Energy Monitoring** (default):
- **System Drift** (30%): Mahalanobis distance from baseline telemetry
- **Attack Probability** (30%): ML-predicted threat level
- **Classifier Decay** (20%): Rate of change in ML confidence
- **Quantum Drift** (20%): System entropy deviation

**With Energy Monitoring** (Intel CPUs with RAPL):
- **System Drift** (25%): Mahalanobis distance from baseline telemetry
- **Attack Probability** (25%): ML-predicted threat level
- **Classifier Decay** (20%): Rate of change in ML confidence
- **Quantum Drift** (15%): System entropy deviation
- **Energy Anomaly** (15%): Power consumption + network direction anomaly score

**RAG Thresholds:**
- **GREEN** (< 0.45): Normal operation - system resilient
- **AMBER** (0.45-0.70): Warning - Kali Linux spins up, defensive capacity declining
- **RED** (> 0.70): Critical - Automated response engaged, system under stress

**Network Direction-Aware Detection** (NEW v5.0):
- **Compromised Endpoints**: USER_ENDPOINT with abnormal outbound traffic (spam, DDoS)
- **Servers Under Attack**: PUBLIC_SERVER with inbound flood
- **Data Exfiltration**: PUBLIC_SERVER with abnormal outbound spike
- **Cryptomining + Network**: High energy-per-packet correlated with network activity

**Automated Response Actions:**

| Threat Type | Actions |
|-------------|---------|
| XSS Injection | Update WAF rules, Block IP, Scan attacker, Generate report |
| SQL Injection | DB snapshot, Update WAF, Block IP, Enable logging, Integrity check |
| Memory Overflow | Capture diagnostics, Reduce limits, Clear caches, Safe restart |

### Network Hardening Controls

**Per-VNI L2 Security:**
```bash
# Anti-spoofing (example for VNI 201 - Web DMZ)
ovs-ofctl add-flow qsec-bridge \
  "table=0,priority=100,tun_id=201,ip,nw_src=10.200.1.0/24,actions=normal"

# Drop spoofed traffic
ovs-ofctl add-flow qsec-bridge \
  "table=0,priority=50,tun_id=201,actions=drop"

# ARP protection
ovs-ofctl add-flow qsec-bridge \
  "table=0,priority=100,tun_id=201,arp,arp_spa=10.200.1.0/24,actions=normal"
```

**Firewall (nftables):**
```bash
# Default deny
nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'

# Allow specific service (Monitoring POD → Web DMZ for metrics)
nft add rule inet filter forward ip saddr 10.200.5.0/24 ip daddr 10.200.1.0/24 tcp dport 9100 ct state new,established accept
```

---

## 📊 Monitoring & Analytics

### Observability Stack (POD 005)

**Components:**
- **Grafana**: Dashboards and visualization
- **VictoriaMetrics**: Time-series metrics storage
- **ClickHouse**: OLAP database for security analytics and log aggregation
- **Vector**: Log and metrics routing and transformation
- **Filebeat**: Zeek log ingestion
- **node_exporter**: Host metrics collection

**Key Dashboards:**
- **System Overview**: All PODs health and resource usage
- **Qsecbit Analysis**: Real-time threat scores and historical trends
- **WAF Activity**: Blocked attacks and patterns
- **Network Traffic**: Flow analysis and top talkers
- **Security Events**: IDS/IPS alerts and incidents
- **Attack Correlation**: Multi-source threat intelligence
- **LTE Status**: Signal strength, data usage (if enabled)

**Access:**
- **Grafana**: http://YOUR_IP:3000
- **VictoriaMetrics**: http://YOUR_IP:8428
- **ClickHouse HTTP**: http://YOUR_IP:8123

**Example ClickHouse Queries:**
```sql
-- All security events (last 24h)
SELECT timestamp, source_type, src_ip, attack_type, severity
FROM security.security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
ORDER BY timestamp DESC
LIMIT 100;

-- WAF blocks
SELECT src_ip, count() AS blocks, groupArray(attack_category)
FROM security.waf_events
WHERE blocked = 1 AND timestamp >= now() - INTERVAL 1 HOUR
GROUP BY src_ip
ORDER BY blocks DESC;

-- Qsecbit RED/AMBER alerts
SELECT timestamp, rag_status, score, drift, attack_probability
FROM security.qsecbit_scores
WHERE rag_status IN ('RED', 'AMBER')
  AND timestamp >= now() - INTERVAL 7 DAY
ORDER BY timestamp DESC;

-- Top attackers
SELECT src_ip, count() AS attacks, uniq(attack_type) AS attack_types
FROM security.security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY src_ip
ORDER BY attacks DESC
LIMIT 10;
```

---

## 🔒 GDPR Compliance

**HookProbe v5.0 is GDPR-compliant by design and by default.**

### Privacy-Preserving Security

As a network security platform, HookProbe processes personal data (IP addresses, MAC addresses, network metadata) for legitimate security purposes. We've implemented comprehensive technical and organizational measures to ensure GDPR compliance while maintaining effective threat detection.

### Key Compliance Features

✅ **Privacy by Design** - Anonymization and pseudonymization built-in
✅ **Privacy by Default** - Minimal data collection, strict retention limits
✅ **Data Minimization** - Only collect what's necessary for security
✅ **Automated Retention** - Automatic deletion after retention period (30-365 days)
✅ **Data Subject Rights** - Access, erasure, portability, rectification
✅ **Security Measures** - Encryption, access controls, audit logging
✅ **Breach Detection** - Automated breach notification procedures

### What Personal Data is Processed?

| Data Type | Retention | Anonymization |
|-----------|-----------|---------------|
| **IP Addresses** | 30-90 days | ✅ Last octet masked (192.168.1.0) |
| **MAC Addresses** | 30 days | ✅ Device ID masked (keeps vendor OUI) |
| **User Accounts** | 2 years (active) | ❌ Required for authentication |
| **Network Flows** | 30 days | ✅ Anonymized at ingestion |
| **Security Logs** | 90 days | ✅ Anonymized after 90 days |

**NOT Collected:** Packet payloads, browsing history, geolocation, biometric data

### Legal Basis for Processing

**Legitimate Interests** (GDPR Article 6(1)(f)):
- Network security and fraud prevention
- Service delivery and infrastructure protection
- Security incident response

### Quick Start: GDPR Configuration

```bash
# 1. Review GDPR configuration
nano /opt/hookprobe/scripts/gdpr-config.sh

# Key settings (defaults are GDPR-compliant):
GDPR_ENABLED=true
ANONYMIZE_IP_ADDRESSES=true
ANONYMIZE_MAC_ADDRESSES=true
COLLECT_FULL_PAYLOAD=false  # NEVER enable (privacy violation)
RETENTION_NETWORK_FLOWS_DAYS=30

# 2. Enable automated data retention cleanup
sudo crontab -e
# Add: 0 2 * * * /opt/hookprobe/scripts/gdpr-retention.sh

# 3. Generate compliance report
sudo /opt/hookprobe/scripts/gdpr-retention.sh
cat /var/log/hookprobe/compliance-reports/compliance-report-$(date +%Y-%m-%d).txt
```

### Privacy-Preserving Threat Detection

**Qsecbit detects threats using patterns, not identities:**

```python
# IP anonymization preserves security analysis capability
from qsecbit.gdpr_privacy import anonymize_ip

src_ip = anonymize_ip("192.168.1.123")  # → "192.168.1.0"

# Threat detection still works:
# - DDoS from 192.168.1.0/24 subnet → detectable
# - Port scan from 10.0.0.0/24 → detectable
# - Protocol anomalies → no PII needed
```

**Privacy Benefits:**
- Subnet-level analysis (more private than individual IPs)
- No behavioral profiling of individuals
- No geolocation tracking
- No payload inspection (headers only)

### Data Subject Rights

Users can exercise their GDPR rights:

| Right | Implementation | Timeline |
|-------|----------------|----------|
| **Access (Article 15)** | Data export in JSON format | Within 30 days |
| **Erasure (Article 17)** | Account deletion + log anonymization | 7-day grace period |
| **Portability (Article 20)** | Machine-readable export (JSON) | Within 30 days |
| **Rectification (Article 16)** | Profile data correction | Immediate |
| **Object (Article 21)** | Account deletion (opt-out) | Immediate |

**Request Process:**
1. Submit request via web interface or email to DPO
2. Identity verification (prevent unauthorized access)
3. Processing within GDPR timelines (30 days max)
4. Secure delivery of data export or deletion confirmation

### Automated Data Retention

**Retention Periods (configurable):**

```bash
# Network data (minimize retention)
RETENTION_NETWORK_FLOWS_DAYS=30       # Default: 1 month
RETENTION_DNS_LOGS_DAYS=30
RETENTION_HTTP_LOGS_DAYS=30

# Security logs (balance security vs. privacy)
RETENTION_SECURITY_LOGS_DAYS=90       # Default: 3 months
RETENTION_IDS_ALERTS_DAYS=365         # Critical incidents: 1 year

# User accounts
RETENTION_INACTIVE_ACCOUNTS_DAYS=365  # Delete after 1 year inactivity
```

**What Gets Deleted:**
- Zeek network flows → File deletion + ClickHouse DELETE
- Snort3 alerts → File deletion + ClickHouse DELETE
- ModSecurity WAF logs → File deletion + ClickHouse DELETE
- Qsecbit scores → ClickHouse DELETE
- Inactive user accounts → PostgreSQL soft delete → permanent deletion

**Verification:**

```bash
# Check retention cleanup logs
tail -f /var/log/hookprobe/gdpr-retention.log

# View compliance report
cat /var/log/hookprobe/compliance-reports/compliance-report-$(date +%Y-%m-%d).txt
```

### Breach Notification

**Automated Detection & Notification:**

```bash
BREACH_DETECTION_ENABLED=true
BREACH_NOTIFICATION_DEADLINE_HOURS=72  # GDPR requirement
BREACH_NOTIFICATION_EMAIL="qsecbit@hookprobe.com"
```

**Response Timeline:**
- **T+0 hours**: Breach detected (automated alert)
- **T+1 hour**: DPO notified
- **T+24 hours**: Preliminary assessment
- **T+72 hours**: Supervisory authority notified (if required)

### Complete GDPR Documentation

**📖 [GDPR.md](GDPR.md) - Comprehensive Compliance Guide**

Includes:
- Detailed data inventory (what PII is collected)
- Legal basis justification
- Privacy by design implementation
- Data subject rights procedures
- Breach notification process
- DPIA (Data Protection Impact Assessment) template
- Compliance checklist (pre/post deployment)
- FAQ (legal and technical questions)

### Pre-Deployment GDPR Checklist

- [ ] Review `gdpr-config.sh` and set retention periods
- [ ] Verify IP/MAC anonymization is enabled
- [ ] Confirm payload collection is disabled (`COLLECT_FULL_PAYLOAD=false`)
- [ ] Configure DPO contact email (`BREACH_NOTIFICATION_EMAIL`)
- [ ] Set up automated retention cleanup (cron job)
- [ ] Prepare privacy notice for users
- [ ] Complete DPIA (if required)
- [ ] Identify supervisory authority (for EU deployments)

### Post-Deployment GDPR Verification

```bash
# 1. Verify anonymization is working
tail /opt/zeek/logs/conn.log | grep "\.0$"  # Should see .0 IPs

# 2. Test data retention cleanup
sudo /opt/hookprobe/scripts/gdpr-retention.sh

# 3. Generate compliance report
cat /var/log/hookprobe/compliance-reports/compliance-report-$(date +%Y-%m-%d).txt

# 4. Monitor GDPR audit log
tail -f /var/log/hookprobe/gdpr-audit.log
```

### Support & Contact

- **GDPR Documentation**: [GDPR.md](GDPR.md)
- **Data Protection Officer**: dpo@hookprobe.com
- **Security Contact**: qsecbit@hookprobe.com
- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues

**Disclaimer**: This documentation provides technical guidance on GDPR compliance for HookProbe. It is not legal advice. Consult a qualified data protection lawyer for legal compliance assessment specific to your jurisdiction and use case.

---

## 📚 Documentation

### Core Documentation
- **[README.md](README.md)** - This file (overview and quick start)
- **[GDPR.md](GDPR.md)** - GDPR compliance guide (privacy and data protection)
- **[setup.sh Documentation](Scripts/autonomous/install/README.md)** - Main deployment guide
- **[Security Mitigation Plan](Documents/SecurityMitigationPlan.md)** - Detailed security analysis
- **[Deployment Checklist](Scripts/autonomous/install/checklist.md)** - Pre/post deployment tasks

### Optional Feature Documentation
- **[n8n Integration](../main/n8n/README.md)** - Workflow automation setup
- **[n8n Checklist](../main/n8n/integration-checklist.md)** - N8N Integration validation
- **[Autonomous Blog Workflow](../main/n8n/AI-blogging-workflow.md)** - Advanced content pipeline
- **[LTE/5G Setup](../main/LTE/README.md)** - Cellular connectivity guide

### Configuration Files
- **[network-config.sh](Scripts/autonomous/install/network-config.sh)** - Main network configuration
- **[n8n_network-config.sh](Scripts/autonomous/install/n8n_network-config.sh)** - n8n network settings
- **[Qsecbit Algorithm](Scripts/autonomous/qsecbit.py)** - Threat analysis implementation

---

## 🛠️ Troubleshooting

### Common Issues

**PODs won't start:**
```bash
# Check logs
podman logs <pod-name>

# Restart POD
podman pod restart <pod-name>

# Check OVS
ovs-vsctl show
```

**Network connectivity issues:**
```bash
# Verify VXLAN
ovs-vsctl list-ports qsec-bridge

# Check OpenFlow rules
ovs-ofctl dump-flows qsec-bridge

# Test connectivity
ping 10.200.1.12  # Django
ping 10.200.6.12  # Qsecbit
```

**Qsecbit not responding:**
```bash
# Check status
curl http://localhost:8888/health

# View logs
podman logs hookprobe-pod-007-ai-response-qsecbit

# Restart service
podman restart hookprobe-pod-007-ai-response-qsecbit
```

**Database connection errors:**
```bash
# Test PostgreSQL
podman exec hookprobe-pod-003-db-persistent-postgres pg_isready

# Check credentials
grep POSTGRES network-config.sh
```

### Support

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Documentation**: Check relevant README files
- **Logs**: `podman logs <container-name>`
- **Community**: See CONTRIBUTING.md

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- **Security Enhancements**: New detection algorithms, hardening controls
- **Integrations**: Additional tools, services, APIs
- **Documentation**: Tutorials, guides, translations
- **Workflows**: n8n templates, automation scripts
- **Testing**: Security audits, performance testing
- **Hardware Support**: Additional SBC platforms, modems

---

## 📄 License

**HookProbe v5.0** is transitioning from GPL to **MIT License** (Q4 2025).

**Current Status (v4.x)**: GPL-3.0
**Target (v5.0)**: MIT License

All new components and scripts in v5.0 are MIT-licensed:
- ✅ Qsecbit algorithm (MIT)
- ✅ Deployment scripts (MIT)
- ✅ Configuration templates (MIT)
- ✅ n8n integration scripts (MIT)
- ✅ Documentation (MIT)

See [LICENSE](LICENSE) for details.

---

## 🎯 Project Roadmap

### v5.0 (Q4 2025) - Current
- ✅ Complete GPL elimination
- ✅ Qsecbit AI threat analysis
- ✅ Kali Linux automated response
- ✅ 7-POD architecture
- ✅ n8n workflow automation (optional)
- ⏳ LTE/5G failover support

### v5.1 (Q1 2026)
- [ ] Web UI for management
- [ ] Multi-host clustering
- [ ] Hardware security module (HSM) support
- [ ] Post-quantum cryptography
- [ ] Enhanced AI models (local LLM support)

### v6.0 (Q2 2026)
- [ ] Kubernetes orchestration option
- [ ] Cloud-native deployment
- [ ] Advanced threat hunting
- [ ] Security analytics platform
- [ ] Commercial support options

---

## 🙏 Credits

**Created by**: Andrei Toma  
**License**: MIT (v5.0+)  
**Qsecbit Algorithm**: Andrei Toma (MIT)  
**HookProbe Platform**: HookProbe Team  

**Special Thanks:**
- n8n.io - Workflow automation
- Grafana Labs - Monitoring stack
- Suricata, Zeek, Snort - IDS/IPS
- Podman - Container runtime
- Open vSwitch - Network virtualization

---

## 📞 Contact

- **GitHub**: https://github.com/hookprobe/hookprobe
- **Issues**: https://github.com/hookprobe/hookprobe/issues
- **Security**: See SECURITY.md for responsible disclosure

---

[![hookprobe budget](images/hookprobe-r&d.png)](hookprobe-r&d.md)

[![hookprobe budget](images/xSOC-HLD-v1.2.png)](Documents/SecurityMitigationPlan.md)

---

**HookProbe** - *Democratizing Cybersecurity Through Edge Computing*

**Version**: 5.0  
**Status**: Production Ready 🚀  
**Last Updated**: 2025

**Built with ❤️ for the security community**

*HookProbe - Leading the Charge in Cybersecurity*
