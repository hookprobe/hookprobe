# HookProbe Fortress

> **"Your Digital Stronghold"** - Enterprise-grade security for small businesses

## Target Market

Fortress is designed for **sole traders and small businesses** who need professional-grade network security without the complexity or cost of enterprise solutions:

| Business Type | Why Fortress? |
|--------------|---------------|
| **Flower Shops** | Protect POS systems, customer data, and prevent card skimmers |
| **Bakeries & Cafes** | Secure guest WiFi, separate POS from customers, GDPR compliance |
| **Pizza & Takeaway** | Protect online ordering systems, isolate delivery tablets |
| **Computer Repair** | Secure customer devices, isolate diagnostic networks |
| **Mobile Phone Repair** | Protect customer data, secure diagnostic equipment |
| **Hair Salons** | Secure booking systems, protect payment terminals |
| **Retail Shops** | VLAN separation for POS, staff, and guest networks |
| **Professional Services** | Client data protection, secure document handling |
| **Trades (Electricians, Plumbers)** | Secure office network, protect invoicing systems |

### The Problem We Solve

Small businesses face the same cyber threats as enterprises but lack:
- Dedicated IT staff
- Budget for enterprise firewalls ($5,000+)
- Time to learn complex security tools
- Visibility into their network

### The Fortress Solution

- **Plug-and-Play Security**: Deploy in minutes, not days
- **Visual Dashboard**: See your network health at a glance
- **Automatic Protection**: AI-powered threat detection
- **Customer WiFi Isolation**: Keep your POS separate from guests
- **Compliance Ready**: GDPR-friendly logging and reporting
- **Affordable**: Runs on $200-400 mini PC hardware

---

## Overview

Fortress is a full-featured edge gateway with local monitoring, dashboards, and automation capabilities. Built for advanced deployments requiring comprehensive visibility and control.

### What Makes Fortress Different from Guardian?

| Feature | Guardian | Fortress |
|---------|----------|----------|
| **Target** | Personal/Travel | Small Business |
| **RAM** | 1.5GB | 4GB+ |
| **Web UI** | Single-user | Multi-user with auth |
| **VLANs** | Basic | Full segmentation |
| **Reporting** | Basic stats | Business reports |
| **Dashboards** | Personal | AdminLTE professional |
| **Updates** | Manual | Scheduled + alerts |
| **Support** | Community | Priority (optional) |

---

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4GB | 8GB |
| Storage | 16GB | 32GB |
| Network | 2 ethernet | 2+ ethernet |
| CPU Cores | 4 | 8 |
| Internet | Required | Required |

## Recommended Hardware

### Budget (~$200)
- **Beelink Mini S12 Pro** (N100, 8GB, 256GB)
- **GMKtec N100** (N100, 8GB, 256GB)
- Any Intel N100/N95 mini PC

### Mid-Range (~$300)
- **ASUS ExpertCenter PN42** (N100, 16GB)
- **Intel NUC 12** (N100/N200)
- **Minisforum UN100** (N100, 16GB)

### Business (~$400+)
- **Protectli VP2420** (4 LAN ports, fanless)
- **Qotom Q355G4** (4 LAN, i5)
- **Dell OptiPlex Micro** (i5/i7)

---

## Fortress Features

### All Guardian Features, Plus:

### Admin Dashboard (AdminLTE)
- **User Authentication** — Username/password login
- **Role-Based Access** — Admin, Operator, Viewer roles
- **Professional UI** — AdminLTE 3.x responsive dashboard
- **Session Management** — Secure session handling
- **Audit Logging** — Track all admin actions

### Business Reporting
- **Weekly Security Reports** — PDF email summaries
- **Client Device Inventory** — Track all connected devices
- **Bandwidth Usage** — Per-device and per-VLAN
- **Threat Summary** — Blocked attacks overview
- **Uptime Monitoring** — Service availability

### Network Segmentation
- **VLAN Isolation** — Separate POS, Staff, Guest, IoT
- **Per-VLAN Policies** — Different protection per segment
- **Inter-VLAN Firewall** — Control traffic between segments
- **MAC-to-VLAN Assignment** — Auto-assign devices

### dnsXai Advanced
- **Full ML Classifier** — All 20 features enabled with higher accuracy
- **CNAME Uncloaking** — Deep chain resolution (5+ levels)
- **Federated Learning Hub** — Trains local models, shares with mesh
- **Advanced Analytics** — ClickHouse integration for DNS query analysis
- **Custom Blocklists** — Import enterprise blocklists
- **Per-VLAN Policies** — Different protection levels per network segment

### Mesh Coordinator
- **Regional Hub** — Aggregates threat intel from Guardian nodes
- **NAT Relay** — Provides relay services for nodes behind NAT
- **Tunnel Endpoint** — Cloudflare/ngrok tunnel for public accessibility
- **Promotion Manager** — Automatic promotion to coordinator role

### Monitoring & Analytics
- **Victoria Metrics**: Time-series database
- **Grafana**: Dashboards and visualization (pre-built dnsXai dashboards)
- **ClickHouse**: Analytics database (optional)

### Automation
- **n8n**: Workflow automation
- **MCP Integration**: Model Context Protocol
- **Webhook support**: Event-driven actions
- **dnsXai Workflows**: Auto-update blocklists, threat notifications

### Advanced Security
- Local AI threat detection
- Full IDS/IPS with logging
- Security analytics
- Threat hunting capabilities
- **dnsXai contributes 8%** to Qsecbit score

### Network
- **VLAN Segmentation** — Isolate IoT devices
- **OpenFlow SDN** — Advanced traffic control
- LTE/5G failover (optional)
- Multi-WAN support
- Advanced traffic analysis

### SDN Autopilot & Network Access Control

Fortress includes an intelligent **SDN Autopilot** system that automatically identifies, classifies, and applies network policies to devices:

| Feature | Description |
|---------|-------------|
| **Device Identification** | OUI lookup + DHCP fingerprinting + Fingerbank integration |
| **Premium Device Modal** | Click any device to see details, set policy, add tags |
| **OpenFlow Enforcement** | Real-time policy enforcement at the network switch level |
| **WiFi Signal Tracking** | See signal strength for wireless devices |
| **One-Click Actions** | Block, quarantine, or disconnect with a single click |

#### Network Policies

| Policy | Internet | LAN | Use Case |
|--------|----------|-----|----------|
| **Quarantine** | ❌ | ❌ | Unknown/suspicious devices (DHCP/DNS only) |
| **Internet Only** | ✅ | ❌ | Guest devices, POS terminals |
| **LAN Only** | ❌ | ✅ | IoT devices, printers, cameras |
| **Normal** | ✅ | ✅ | Smart home hubs (HomePod, Echo) |
| **Full Access** | ✅ | ✅ | Trusted management devices |

#### How It Works

1. **Device connects** to network (WiFi or wired)
2. **DHCP event** triggers SDN Autopilot classification
3. **OUI + fingerprinting** identifies device type
4. **Policy applied** automatically based on device category
5. **OpenFlow rules** enforced at OVS bridge level

#### Testing Policies

```bash
# View current OpenFlow rules for a device
ovs-ofctl dump-flows FTS | grep "AA:BB:CC:DD:EE:FF"

# Test quarantine (should block internet)
# Device can only get DHCP and query DNS

# Test internet_only (should reach google but not LAN)
ping 8.8.8.8       # Should work
ping 10.200.0.50   # Should fail (other LAN device)

# Test lan_only (should reach LAN but not internet)
ping 10.200.0.50   # Should work
ping 8.8.8.8       # Should fail
```

### LTE Data Usage Tracking

For businesses with LTE failover, Fortress tracks metered data usage with enterprise-grade accuracy:

| Feature | Description |
|---------|-------------|
| **Watermark Tracking** | Professional baseline method (same as ISPs) |
| **Monthly/Daily Counters** | Track usage by period |
| **Persistent Database** | SQLite-based, survives reboots |
| **Accurate Resets** | Click "Reset" and counter actually goes to 0 |
| **Data Limits** | Set monthly limits with warning thresholds |

#### How It Works

Kernel network counters are read-only (can't be reset). Fortress uses the "watermark" method:

1. Store baseline snapshot when period starts or user resets
2. Calculate usage as: `current_counter - baseline`
3. When user resets, update baseline to current (usage shows 0)

```bash
# Check current LTE usage
cat /opt/hookprobe/fortress/data/lte_usage.json

# Manual reset
/opt/hookprobe/fortress/devices/common/lte-usage-tracker.sh reset monthly

# View SQLite database
sqlite3 /var/lib/hookprobe/lte_usage.db "SELECT * FROM baselines"
```

---

## Installation

### Quick Install

```bash
sudo ./install.sh --tier fortress
```

### With Options

```bash
# Enable AIOCHI (AI Eyes - Cognitive Network Layer)
# Includes: ClickHouse, Grafana, VictoriaMetrics, Suricata, Zeek, n8n, Ollama LLM
sudo ./install.sh --tier fortress --enable-aiochi

# Enable LTE failover
sudo ./install.sh --tier fortress --enable-lte

# Full installation with all features
sudo ./install.sh --tier fortress --enable-aiochi --enable-lte
```

---

## Web Interface

### Admin Portal (https://localhost:8443)

The Fortress admin portal provides:

1. **Login Page** — Secure authentication
2. **Dashboard** — Network overview, threat status, device count
3. **Security** — QSecBit score, threat detection, blocked IPs
4. **Clients** — Device inventory with VLAN assignment
5. **Networks** — VLAN configuration, WiFi settings
6. **dnsXai** — DNS protection settings
7. **Reports** — Generate and schedule reports
8. **Settings** — System configuration, user management

### Default Credentials

| Account | Username | Password |
|---------|----------|----------|
| Admin | admin | (set during install) |

**Important**: Change the default password immediately after installation!

---

## Resource Usage

| Component | RAM | Storage |
|-----------|-----|---------|
| Core services | ~1GB | ~3GB |
| Victoria Metrics | ~512MB | ~5GB |
| Grafana | ~256MB | ~500MB |
| n8n | ~256MB | ~500MB |
| ClickHouse (optional) | ~1GB | ~10GB |

**Total**: ~2-3GB RAM under normal operation

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/hookprobe/fortress.conf` | Main configuration |
| `/etc/hookprobe/monitoring.conf` | Monitoring settings |
| `/etc/hookprobe/n8n.conf` | Automation config |
| `/etc/hookprobe/clickhouse.conf` | Analytics config |
| `/etc/hookprobe/users.json` | Admin portal users |

---

## Service Management

```bash
# Start all Fortress services
sudo systemctl start hookprobe-fortress

# Individual services
sudo systemctl start hookprobe-guardian
sudo systemctl start hookprobe-monitoring
sudo systemctl start hookprobe-n8n

# Check status
sudo hookprobe-ctl status

# View logs
sudo journalctl -u hookprobe-fortress -f
```

---

## Web Interfaces

| Interface | URL | Purpose |
|-----------|-----|---------|
| Admin Portal | https://localhost:8443 | Main admin UI |
| Grafana | http://localhost:3000 | Metrics dashboards |
| n8n | http://localhost:5678 | Workflow automation |

---

## Small Business Deployment Guide

### Step 1: Network Planning

```
Internet
    │
    ▼
[ISP Router] ──► [Fortress] ──┬── VLAN 10: Management (Admin PCs)
                              ├── VLAN 20: POS (Payment terminals)
                              ├── VLAN 30: Staff (Employee devices)
                              ├── VLAN 40: Guest WiFi (Customers)
                              └── VLAN 99: IoT (Cameras, sensors)
```

### Step 2: Device Assignment

| Device Type | Recommended VLAN |
|-------------|------------------|
| Cash registers, POS | VLAN 20 (isolated) |
| Staff laptops | VLAN 30 |
| Customer WiFi | VLAN 40 (rate limited) |
| Security cameras | VLAN 99 |
| Admin computers | VLAN 10 |

### Step 3: Configure Guest WiFi

```bash
# Guest WiFi with captive portal
hookprobe-ctl wifi guest enable --ssid "ShopName_Guest" --vlan 40

# Rate limit guest network (5 Mbps per device)
hookprobe-ctl qos set --vlan 40 --limit 5mbps
```

---

## Dashboards

Pre-configured Grafana dashboards:

- **Business Overview**: Revenue protection, uptime, bandwidth
- **Network Overview**: Traffic, connections, bandwidth
- **Security**: Threats detected, blocked attacks
- **System Health**: CPU, RAM, disk, containers
- **IDS/IPS**: Suricata/Zeek alerts

---

## n8n Automation Examples

### Daily Security Report
Automatically send daily security summary to owner's email.

### Alert to SMS
Send SMS when critical threat detected (via Twilio).

### New Device Notification
Alert when unknown device connects to network.

### Weekly Backup
Automated config backup to cloud storage.

---

## LTE/5G Failover

If your device has an LTE modem:

```bash
# Enable LTE failover
hookprobe-ctl lte enable

# Check LTE status
hookprobe-ctl lte status

# Manual failover
hookprobe-ctl lte failover
```

---

## Business Continuity with SLA AI

Fortress includes **SLA AI** - an intelligent business continuity engine that ensures your business stays online even when your primary internet fails.

### Why Business Continuity Matters

| Without SLA AI | With SLA AI |
|----------------|-------------|
| Card machines stop working | Seamless failover in < 5 seconds |
| Online orders fail | Zero transaction loss |
| Manual intervention required | Fully automated |
| Unknown when to switch back | Intelligent cost-aware failback |
| Expensive LTE bills | Optimized metered usage |

### BCO/BPO Metrics Achieved

| Metric | Target | Description |
|--------|--------|-------------|
| **Uptime** | 99.9% | Total network availability |
| **RTO** | < 5 sec | Recovery Time Objective |
| **RPO** | 0 bytes | Recovery Point Objective |
| **MTTD** | 30 sec early | Predictive failure detection |

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    SLA AI Decision Flow                          │
│                                                                  │
│  Primary WAN ──[LSTM monitors health]──┐                        │
│       │                                 │                        │
│       ▼                                 ▼                        │
│  ┌─────────┐   Failure      ┌───────────────────┐               │
│  │ HEALTHY │ ──predicted──► │ FAILOVER TO LTE   │               │
│  └─────────┘                └─────────┬─────────┘               │
│       ▲                               │                          │
│       │                               ▼                          │
│       │                     ┌───────────────────┐               │
│       └──[cost-aware]────── │ MONITOR PRIMARY   │               │
│          failback           │ Track LTE costs   │               │
│                             └───────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

### Configuration

SLA AI is automatically configured during Fortress installation:

```yaml
# /etc/hookprobe/slaai.conf
enabled: true
check_interval_s: 5

interfaces:
  primary:
    name: eth0
    type: ethernet
  backup:
    name: wwan0
    type: lte
    metered: true
    daily_budget_mb: 500
    monthly_budget_mb: 10000
    cost_per_gb: 0.50

failback:
  metered_urgency_multiplier: 1.5
  business_hours: "09:00-18:00"
```

### Key Features

1. **LSTM Prediction**: Predicts failures 30-60 seconds before they happen
2. **Cost Tracking**: Monitors LTE usage against daily/monthly budgets
3. **Smart Failback**: Returns to primary when stable (not immediately)
4. **Flap Prevention**: Maximum 4 switches per hour
5. **Business Hours**: Prioritizes failback during peak hours
6. **Adaptive DNS**: Automatically switches DNS providers if needed

### Commands

```bash
# Check SLA AI status
fortress-ctl sla status

# View failover history
fortress-ctl sla history

# Force failback (when safe)
fortress-ctl sla failback

# View cost tracking
fortress-ctl sla costs
```

### PBR Integration

SLA AI works with Fortress Policy-Based Routing (PBR):

```bash
# PBR state files
/run/fortress/slaai-recommendation.json  # SLA AI recommendations
/run/fortress/pbr-state.json              # Current PBR state

# PBR script
/opt/hookprobe/fortress/devices/common/wan-failover-pbr.sh
```

For detailed documentation, see `shared/slaai/README.md`.

---

## Ports Used

| Port | Service |
|------|---------|
| 53 | DNS |
| 80/443 | HTTP/HTTPS |
| 3000 | Grafana |
| 5678 | n8n |
| 8080 | API |
| 8443 | Admin Portal (HTTPS) |
| 8428 | Victoria Metrics |
| 9090 | Health endpoint |

---

## Data Retention

Default retention policies (GDPR compliant):

| Data Type | Retention |
|-----------|-----------|
| Metrics | 30 days |
| Logs | 14 days |
| Alerts | 90 days |
| Analytics | 180 days |

Configure in `/etc/hookprobe/retention.conf`.

---

## Upgrading from Guardian

```bash
# Backup Guardian config
sudo hookprobe-ctl backup

# Install Fortress
sudo ./install.sh --tier fortress

# Guardian config is automatically migrated
```

---

## Troubleshooting

### Cannot Access Admin Portal

```bash
# Check if service is running
sudo systemctl status hookprobe-fts-web

# Check firewall
sudo iptables -L -n | grep 8443

# View logs
sudo journalctl -u hookprobe-fts-web -f
```

### High Memory Usage

```bash
# Check container memory
podman stats

# Adjust limits in /etc/hookprobe/fortress.conf
VICTORIA_METRICS_MEM_LIMIT=1g
GRAFANA_MEM_LIMIT=512m
```

### Grafana Not Loading

```bash
# Check Grafana logs
podman logs hookprobe-grafana

# Restart Grafana
sudo systemctl restart hookprobe-monitoring
```

### n8n Workflows Not Running

```bash
# Check n8n logs
podman logs hookprobe-n8n

# Verify webhook connectivity
curl http://localhost:5678/healthz
```

---

## Support

- **Community**: Discord, GitHub Issues
- **Documentation**: https://docs.hookprobe.com
- **Priority Support**: Available with commercial license

---

## License

Fortress is dual-licensed:
- **AGPL v3.0** for open source use
- **Commercial License** for SaaS/OEM use

See `LICENSING.md` in the project root for details.
