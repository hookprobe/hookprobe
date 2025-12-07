# HookProbe MSSP - POC Deployment

> **"The Central Brain"** - Managed Security Service Provider Platform

## Overview

MSSP is the central federation hub for HookProbe's federated cybersecurity mesh. This POC (Proof of Concept) deployment validates the complete stack with 1 Sentinel, 1 Guardian, 1 Fortress, and 1 Nexus connecting to the MSSP.

## POC Requirements

| Resource | POC Minimum | Production |
|----------|-------------|------------|
| CPU Cores | 2 | 4+ |
| RAM | 8GB | 16GB+ |
| Storage | 50GB | 100GB+ |
| Network | 1Gbps | 1Gbps+ |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              MSSP POC STACK                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                         OVS BRIDGE (mssp-bridge)                           │ │
│  │                         Network: 10.200.0.0/16                             │ │
│  │                         OpenFlow 1.3/1.4                                   │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                          │
│         ┌────────────────────────────┼────────────────────────────┐            │
│         │                            │                            │            │
│  ┌──────┴──────┐              ┌──────┴──────┐              ┌──────┴──────┐     │
│  │   POD-001   │              │   POD-003   │              │   POD-005   │     │
│  │     DMZ     │              │   Database  │              │  Monitoring │     │
│  │ VNI: 201    │              │  VNI: 203   │              │  VNI: 205   │     │
│  ├─────────────┤              ├─────────────┤              ├─────────────┤     │
│  │ • Nginx     │              │ • Postgres  │              │ • Victoria  │     │
│  │ • Django    │              │ • ClickHouse│              │ • Grafana   │     │
│  │ • HTP       │              │ • Valkey    │              │ • Vector    │     │
│  └─────────────┘              └─────────────┘              └─────────────┘     │
│                                                                                  │
│  ┌─────────────┐              ┌─────────────┐              ┌─────────────┐     │
│  │   POD-002   │              │   POD-006   │              │   POD-008   │     │
│  │     IAM     │              │  Security   │              │ Automation  │     │
│  │ VNI: 202    │              │  VNI: 206   │              │  VNI: 208   │     │
│  ├─────────────┤              ├─────────────┤              ├─────────────┤     │
│  │ • Logto     │              │ • Qsecbit   │              │ • n8n       │     │
│  │ • OIDC/SAML │              │ • Suricata  │              │ • Webhooks  │     │
│  └─────────────┘              └─────────────┘              └─────────────┘     │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ HTP Protocol (UDP/TCP 4478)
                                       │ VXLAN VNI 1000
                                       ▼
        ┌──────────────────────────────────────────────────────────────┐
        │                      EDGE MESH (POC)                          │
        ├──────────────┬──────────────┬──────────────┬─────────────────┤
        │   SENTINEL   │   GUARDIAN   │   FORTRESS   │     NEXUS       │
        │    256MB     │    1.5GB     │     4GB      │     16GB        │
        │  Validator   │   Travel     │  Edge Router │   ML Compute    │
        └──────────────┴──────────────┴──────────────┴─────────────────┘
```

## Quick Start

### Install MSSP POC

```bash
# Clone repository
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe

# Install MSSP tier
sudo ./install.sh --tier mssp

# Or run setup directly
sudo ./products/mssp/setup.sh --poc-mode
```

### Verify Installation

```bash
# Check health
sudo ./products/mssp/scripts/health-check.sh

# View container status
podman ps -a --filter name=mssp

# Check OVS bridge
sudo ovs-vsctl show
```

## POD Architecture

| POD | Network | VNI | Purpose | Containers |
|-----|---------|-----|---------|------------|
| pod-001-dmz | 10.200.1.0/24 | 201 | Public-facing services | Nginx, Django, HTP |
| pod-002-iam | 10.200.2.0/24 | 202 | Authentication | Logto |
| pod-003-db | 10.200.3.0/24 | 203 | Data persistence | PostgreSQL, ClickHouse, Valkey |
| pod-005-monitoring | 10.200.5.0/24 | 205 | Observability | VictoriaMetrics, Grafana, Vector |
| pod-006-security | 10.200.6.0/24 | 206 | Security analysis | Qsecbit API, Suricata |
| pod-008-automation | 10.200.8.0/24 | 208 | Workflow automation | n8n |

## Services & Ports

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Nginx (HTTP) | 80 | TCP | Web frontend |
| Nginx (HTTPS) | 443 | TCP | TLS web frontend |
| Django | 8000 | TCP | Web application |
| HTP | 4478 | UDP/TCP | Edge device connectivity |
| Grafana | 3000 | TCP | Dashboards |
| Logto API | 3001 | TCP | IAM API |
| Logto Admin | 3002 | TCP | IAM admin console |
| PostgreSQL | 5432 | TCP | Primary database |
| Valkey | 6379 | TCP | Cache/session store |
| ClickHouse | 8123/9000 | TCP | Analytics database |
| VictoriaMetrics | 8428 | TCP | Metrics storage |
| Qsecbit API | 8888 | TCP | Security scoring API |
| n8n | 5678 | TCP | Workflow automation |

## Edge Device Connection

### HTP Protocol Flow

```
Edge Device                                    MSSP HTP Validator
     │                                                │
     │ ──────── HELLO (node_id, fingerprint) ───────► │
     │                                                │
     │ ◄──────── CHALLENGE (16-byte nonce) ────────── │
     │                                                │
     │ ──────── ATTEST (PoSF signature) ────────────► │
     │                                                │
     │ ◄──────── ACCEPT (session_secret) ──────────── │
     │                                                │
     │ ◄─────── DATA (encrypted telemetry) ─────────► │
     │                                                │
     │ ──────── HEARTBEAT (every 30s) ──────────────► │
     │                                                │
```

### Register Edge Device

```bash
# On the edge device (Sentinel/Guardian/Fortress/Nexus)
hookprobe-ctl register \
  --mssp-url "https://your-mssp.hookprobe.com" \
  --tenant-id "your-tenant-id" \
  --device-name "guardian-01"
```

### Validate Connection

```bash
# On MSSP - view connected devices
hookprobe-ctl devices list

# Expected output:
# NODE_ID           TYPE      QSECBIT  STATUS   LAST_SEEN
# sentinel-01       Sentinel  0.23     GREEN    5s ago
# guardian-01       Guardian  0.31     GREEN    2s ago
# fortress-01       Fortress  0.28     GREEN    8s ago
# nexus-01          Nexus     0.19     GREEN    3s ago
```

## Web Portal Access

| Interface | URL | Credentials |
|-----------|-----|-------------|
| Admin Dashboard | https://localhost/admin | Generated during install |
| MSSP Dashboard | https://localhost/mssp | Generated during install |
| Grafana | http://localhost:3000 | admin / (generated) |
| Logto Admin | http://localhost:3002 | Setup on first access |
| n8n | http://localhost:5678 | Setup on first access |

## Configuration

### Main Configuration

```bash
# View configuration
cat /etc/hookprobe/mssp/config.sh

# Edit configuration
sudo nano /etc/hookprobe/mssp/config.sh

# Restart services after changes
sudo systemctl restart hookprobe-mssp
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MSSP_DOMAIN` | localhost | MSSP domain name |
| `MSSP_ADMIN_EMAIL` | admin@example.com | Admin email |
| `POSTGRES_PASSWORD` | (generated) | Database password |
| `SECRET_KEY` | (generated) | Django secret key |
| `HTP_PSK` | (generated) | HTP pre-shared key |

### VXLAN PSK Configuration

```bash
# Generate new PSK for edge mesh
openssl rand -base64 32 > /etc/hookprobe/secrets/mssp/htp_psk.key

# Distribute to edge devices
# Each edge device needs the same PSK for VXLAN encryption
```

## POC Validation Checklist

### 1. MSSP Stack

- [ ] OVS bridge created (`sudo ovs-vsctl show`)
- [ ] All PODs running (`podman pod ps`)
- [ ] All containers healthy (`podman ps`)
- [ ] Web portal accessible (https://localhost)
- [ ] HTP endpoint listening (`ss -ulnp | grep 4478`)

### 2. Sentinel Connection

- [ ] Sentinel registered with MSSP
- [ ] Health endpoint responding (port 9090)
- [ ] Qsecbit scores reporting

### 3. Guardian Connection

- [ ] Guardian registered with MSSP
- [ ] L2-L7 detection active
- [ ] Threat events forwarding

### 4. Fortress Connection

- [ ] Fortress registered with MSSP
- [ ] VLAN telemetry reporting
- [ ] SDN flow rules syncing

### 5. Nexus Connection

- [ ] Nexus registered with MSSP
- [ ] ML model sync working
- [ ] Federated learning active

## Resource Usage (POC)

| Container | RAM | Storage | Notes |
|-----------|-----|---------|-------|
| mssp-postgres | ~256MB | ~1GB | Primary database |
| mssp-clickhouse | ~512MB | ~2GB | Analytics |
| mssp-valkey | ~64MB | ~100MB | Cache |
| mssp-victoriametrics | ~256MB | ~500MB | Metrics |
| mssp-grafana | ~128MB | ~200MB | Dashboards |
| mssp-logto | ~256MB | ~100MB | IAM |
| mssp-django | ~512MB | ~500MB | Web app |
| mssp-nginx | ~32MB | ~50MB | Reverse proxy |
| mssp-qsecbit | ~128MB | ~50MB | Scoring API |
| mssp-n8n | ~256MB | ~200MB | Automation |
| **Total** | **~2.4GB** | **~5GB** | POC footprint |

## Troubleshooting

### Common Issues

**Containers not starting:**
```bash
# Check logs
podman logs mssp-django
podman logs mssp-postgres

# Restart POD
podman pod restart pod-001-dmz
```

**OVS bridge issues:**
```bash
# Check bridge status
sudo ovs-vsctl show

# List ports
sudo ovs-vsctl list-ports mssp-bridge

# Check flows
sudo ovs-ofctl dump-flows mssp-bridge
```

**HTP connection failing:**
```bash
# Check HTP validator
podman logs mssp-htp

# Test connectivity from edge device
nc -u <mssp-ip> 4478

# Check firewall
sudo ufw status
```

**Database connection issues:**
```bash
# Check PostgreSQL
podman exec mssp-postgres pg_isready

# Check ClickHouse
curl http://localhost:8123/ping
```

### Logs

```bash
# All MSSP logs
tail -f /var/log/hookprobe/mssp/*.log

# Specific service
podman logs -f mssp-django
podman logs -f mssp-nginx

# System journal
journalctl -u hookprobe-mssp -f
```

## Uninstall

```bash
# Soft uninstall (keeps data)
sudo ./products/mssp/uninstall.sh --soft

# Complete uninstall
sudo ./products/mssp/uninstall.sh --complete

# Preserve database only
sudo ./products/mssp/uninstall.sh --preserve-db
```

## Files & Directories

```
/opt/hookprobe/mssp/           # Installation directory
/etc/hookprobe/mssp/           # Configuration files
/var/lib/hookprobe/mssp/       # Data (databases, volumes)
/var/log/hookprobe/mssp/       # Log files
/etc/hookprobe/secrets/mssp/   # Secrets (PSK, passwords)
```

## Related Documentation

- [ARCHITECTURE.md](../../ARCHITECTURE.md) - Full system architecture
- [MSSP Production Deployment](../../docs/deployment/MSSP-PRODUCTION-DEPLOYMENT.md)
- [HTP Protocol](../../docs/HTP_SECURITY_ENHANCEMENTS.md)
- [Qsecbit Algorithm](../../core/qsecbit/README.md)

---

**HookProbe MSSP v5.0** - Central Brain for Federated Cybersecurity Mesh
*One node's detection → Everyone's protection*
