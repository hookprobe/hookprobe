# HookProbe Deployment

> **Installation Scripts, Containers, and Add-ons**

The deploy/ directory contains everything needed to deploy HookProbe products.

```
deploy/
├── install/     # Installation scripts
├── containers/  # Podman/Docker configurations
├── edge/        # Edge-specific deployment (systemd)
├── cloud/       # Cloud deployment configs
└── addons/      # Optional add-ons
    ├── n8n/         # Workflow automation
    ├── webserver/   # Web hosting
    └── lte/         # LTE/5G failover
```

---

## Quick Start

```bash
# Choose your tier:

# IoT devices (512MB RAM)
sudo ./install.sh --tier sentinel

# Raspberry Pi travel setup (3GB RAM)
sudo ./install.sh --tier guardian

# Mini PC / Server (8GB RAM)
sudo ./install.sh --tier fortress

# Datacenter / Cloud (64GB+ RAM)
sudo ./install.sh --tier nexus
```

---

## Installation Options

### Common Options
```bash
--tier <tier>        # sentinel, guardian, fortress, nexus
--node-id <id>       # Custom node identifier
--mesh-url <url>     # Mesh backend URL
--migrate            # Migrate from previous tier
```

### Fortress Options
```bash
--enable-aiochi      # AIOCHI (AI Eyes) - Full cognitive layer
                     # Includes: n8n, Grafana, VictoriaMetrics,
                     # ClickHouse, Suricata, Zeek, Ollama LLM
--enable-lte         # LTE/5G failover
```

### Nexus Options
```bash
--enable-gpu         # NVIDIA GPU acceleration
--enable-ha          # High availability mode
--clickhouse-cluster # Clustered analytics
--tls-cert <path>    # TLS certificate
--tls-key <path>     # TLS private key
```

---

## Add-ons

### n8n — Workflow Automation

**Location:** `deploy/addons/n8n/`

Automate security responses with visual workflows.

**Example Workflows:**
- Alert to Slack/Teams when Qsecbit > 0.7
- Auto-block IPs across all devices
- Generate weekly security reports
- Sync threat intel with external feeds

```bash
# n8n is included with AIOCHI (AI Eyes)
sudo ./install.sh --tier fortress --enable-aiochi
```

### LTE — Mobile Failover

**Location:** `deploy/addons/lte/`

Automatic failover to LTE/5G when primary WAN fails.

```bash
sudo ./install.sh --tier fortress --enable-lte
```

### Webserver — Web Hosting

**Location:** `deploy/addons/webserver/`

Host websites behind HookProbe protection.

---

## Container Architecture

All services run in Podman containers for isolation:

```
┌─────────────────────────────────────────────────────────────────┐
│                     HOOKPROBE CONTAINERS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Suricata   │  │    Zeek     │  │   ModSec    │  Security   │
│  │   IDS/IPS   │  │  Analysis   │  │    WAF      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Grafana   │  │  Victoria   │  │ ClickHouse  │  Analytics  │
│  │ Dashboards  │  │  Metrics    │  │  (optional) │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │     n8n     │  │   WebUI     │  │    Kali     │  Services   │
│  │ Automation  │  │  Dashboard  │  │  Response   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Systemd Services

**Location:** `deploy/edge/systemd/`

All services are managed via systemd:

```bash
# Core services
sudo systemctl status hookprobe-guardian
sudo systemctl status hookprobe-suricata
sudo systemctl status hookprobe-zeek
sudo systemctl status hookprobe-waf
sudo systemctl status hookprobe-xdp

# View logs
sudo journalctl -u hookprobe-guardian -f
```

---

## Cloud Deployment

**Location:** `deploy/cloud/`

For large-scale Nexus and service provider deployments.

See also: `docs/deployment/` for production deployment guides.

---

**HookProbe Deploy** — *From IoT to Cloud*

MIT License
