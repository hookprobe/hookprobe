# HookProbe Fortress

> **"Your Digital Stronghold"** - Full-featured edge with monitoring

## Overview

Fortress is a full-featured edge gateway with local monitoring, dashboards, and automation capabilities. Built for advanced deployments requiring comprehensive visibility and control.

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4GB | 8GB |
| Storage | 16GB | 32GB |
| Network | 2 ethernet | 2+ ethernet |
| CPU Cores | 4 | 8 |
| Internet | Required | Required |

## Supported Platforms

- Intel N100/N95/N97 Mini PCs
- Intel NUC
- AMD Ryzen Mini PCs
- Small form factor servers
- Proxmox VMs (with passthrough)
- Any x86_64 with 4GB+ RAM

## Features

### All Guardian Features, Plus:

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

### Web Interface
- Admin dashboard
- Real-time metrics
- Alert management
- Configuration UI
- **dnsXai Control Panel** — Full DNS protection management

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

## Installation

### Quick Install

```bash
sudo ./install.sh --tier fortress
```

### With Options

```bash
# Enable all optional features
sudo ./install.sh --tier fortress \
  --enable-n8n \
  --enable-monitoring \
  --enable-clickhouse \
  --enable-lte
```

## Resource Usage

| Component | RAM | Storage |
|-----------|-----|---------|
| Core services | ~1GB | ~3GB |
| Victoria Metrics | ~512MB | ~5GB |
| Grafana | ~256MB | ~500MB |
| n8n | ~256MB | ~500MB |
| ClickHouse (optional) | ~1GB | ~10GB |

**Total**: ~2-3GB RAM under normal operation

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/hookprobe/fortress.conf` | Main configuration |
| `/etc/hookprobe/monitoring.conf` | Monitoring settings |
| `/etc/hookprobe/n8n.conf` | Automation config |
| `/etc/hookprobe/clickhouse.conf` | Analytics config |

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

## Web Interfaces

| Interface | URL | Purpose |
|-----------|-----|---------|
| Dashboard | https://localhost:8443 | Main admin UI |
| Grafana | http://localhost:3000 | Metrics dashboards |
| n8n | http://localhost:5678 | Workflow automation |

## Dashboards

Pre-configured Grafana dashboards:

- **Network Overview**: Traffic, connections, bandwidth
- **Security**: Threats detected, blocked attacks
- **System Health**: CPU, RAM, disk, containers
- **IDS/IPS**: Suricata/Zeek alerts

## n8n Automation Examples

### Alert to Slack
Automatically send security alerts to Slack when threats are detected.

### IP Blocklist Sync
Sync blocked IPs across all your Guardian devices.

### Report Generation
Generate weekly security reports automatically.

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

## Ports Used

| Port | Service |
|------|---------|
| 53 | DNS |
| 80/443 | HTTP/HTTPS |
| 3000 | Grafana |
| 5678 | n8n |
| 8080 | API |
| 8443 | Admin UI |
| 8428 | Victoria Metrics |
| 9090 | Health endpoint |

## Data Retention

Default retention policies:

| Data Type | Retention |
|-----------|-----------|
| Metrics | 30 days |
| Logs | 14 days |
| Alerts | 90 days |
| Analytics | 180 days |

Configure in `/etc/hookprobe/retention.conf`.

## Upgrading from Guardian

```bash
# Backup Guardian config
sudo hookprobe-ctl backup

# Install Fortress
sudo ./install.sh --tier fortress

# Guardian config is automatically migrated
```

## Troubleshooting

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
