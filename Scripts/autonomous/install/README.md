# HookProbe v5.0 - AI-Powered Cybersecurity Platform

**Complete 7-POD infrastructure with automated threat response**

## 🎯 Overview

HookProbe is an enterprise-grade, AI-powered cybersecurity platform featuring:
- **Automated Threat Detection**: Qsecbit AI analysis engine
- **Intelligent Response**: On-demand Kali Linux with anti-XSS/SQL injection
- **Complete Monitoring**: Grafana + Prometheus + Loki + Rsyslog
- **Web Application Firewall**: NAXSI WAF with auto-updating rules
- **Zero Trust Access**: Optional Cloudflare Tunnel integration
- **Encrypted Networks**: PSK-encrypted VXLAN tunnels between all PODs

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Start](#quick-start)
3. [Configuration Guide](#configuration-guide)
4. [Architecture Overview](#architecture-overview)
5. [Security Features](#security-features)
6. [Troubleshooting](#troubleshooting)

---

## 💻 System Requirements

### Hardware
- **CPU**: Intel N100 or equivalent x86_64 processor (4+ cores recommended)
- **RAM**: Minimum 16GB (32GB recommended for production)
- **Storage**: 500GB SSD minimum (1TB recommended)
- **Network**: 1Gbps NIC

### Software
- **OS**: RHEL 10, Fedora 38+, or CentOS Stream 9
- **Root Access**: Required for installation
- **Internet**: Required for downloading container images

### Network
- **Subnet**: 10.100.0.0/16 must be available (not in use)
- **Ports**: See [Port Mappings](#port-mappings) section

---

## 🚀 Quick Start

### 1. Download Scripts

```bash
# Download all three scripts
wget https://your-repo/network-config.sh
wget https://your-repo/setup.sh
wget https://your-repo/uninstall.sh

# Make executable
chmod +x network-config.sh setup.sh uninstall.sh
```

### 2. Edit Configuration

```bash
nano network-config.sh
```

**Minimum required changes:**
- `HOST_A_IP` - Your server's IP address
- `PHYSICAL_HOST_INTERFACE` - Your network interface (e.g., eth0)
- `OVS_PSK_MAIN` - Change all three PSK keys (generate with: `openssl rand -base64 32`)
- `POSTGRES_PASSWORD` - Strong database password
- `DJANGO_SECRET_KEY` - Django secret (generate with: `openssl rand -base64 50`)

### 3. Deploy

```bash
sudo ./setup.sh
```

Installation takes **15-20 minutes**. Monitor progress and ensure all steps complete successfully.

### 4. Access Services

- **Web Application**: http://YOUR_IP
- **Django Admin**: http://YOUR_IP/admin (admin/admin)
- **Grafana**: http://YOUR_IP:3000 (admin/admin)
- **Logto Admin**: http://YOUR_IP:3002
- **Qsecbit API**: http://YOUR_IP:8888

---

## ⚙️ Configuration Guide

### 🔐 Critical Security Settings

#### 1. Physical Host Configuration

```bash
# Edit in network-config.sh

HOST_A_IP="192.168.1.100"                    # ⚠️ CHANGE THIS
HOST_B_IP="192.168.1.101"                    # Optional: for multi-host
PHYSICAL_HOST_INTERFACE="eth0"               # ⚠️ CHANGE THIS
INTERNET_GATEWAY="192.168.1.1"               # Your gateway
```

**How to find your values:**
```bash
# Find your IP and interface
ip addr show

# Find your gateway
ip route | grep default
```

#### 2. VXLAN Encryption Keys (PSK)

```bash
# ⚠️ CRITICAL: Change all three keys

OVS_PSK_MAIN="HookProbe_Main_VXLAN_Key_2025_CHANGE_ME"
OVS_PSK_DMZ="HookProbe_DMZ_VXLAN_Key_2025_CHANGE_ME"
OVS_PSK_INTERNAL="HookProbe_Internal_VXLAN_Key_2025_CHANGE_ME"
```

**Generate strong keys:**
```bash
openssl rand -base64 32
openssl rand -base64 32
openssl rand -base64 32
```

#### 3. Database Credentials

```bash
# Main PostgreSQL Database
POSTGRES_DB="hookprobe_db"
POSTGRES_USER="hookprobe_admin"
POSTGRES_PASSWORD="CHANGE_ME_STRONG_PASSWORD_123"    # ⚠️ CHANGE THIS

# Logto IAM Database
LOGTO_DB="logto_db"
LOGTO_DB_USER="logto_admin"
LOGTO_DB_PASSWORD="CHANGE_ME_LOGTO_DB_PASSWORD"      # ⚠️ CHANGE THIS
```

**Generate strong passwords:**
```bash
openssl rand -base64 24
openssl rand -base64 24
```

#### 4. Django Configuration

```bash
DJANGO_SECRET_KEY="CHANGE_ME_DJANGO_SECRET_KEY_LONG_RANDOM_STRING"  # ⚠️ CHANGE THIS
DJANGO_DEBUG="False"                         # Keep False for production
DJANGO_ALLOWED_HOSTS="*"                     # Change to your domain in production
```

**Generate Django secret key:**
```bash
openssl rand -base64 50
```

---

### ☁️ Optional: Cloudflare Tunnel

If you want secure external access without opening ports:

#### 1. Get Cloudflare Tunnel Token

1. Go to [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/)
2. Navigate to **Access** → **Tunnels**
3. Click **Create a tunnel**
4. Name it: `hookprobe-tunnel`
5. Copy the token

#### 2. Configure in network-config.sh

```bash
CLOUDFLARE_TUNNEL_TOKEN="eyJhIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoiLCJ0IjoiMTIzNDU2Nzg5MCIsInMiOiJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiJ9"  # Your token
CLOUDFLARE_TUNNEL_NAME="hookprobe-tunnel"
CLOUDFLARE_DOMAIN="your-domain.com"          # Your Cloudflare domain
```

If you skip this, set:
```bash
CLOUDFLARE_TUNNEL_TOKEN="CHANGE_ME_GET_FROM_CLOUDFLARE_DASHBOARD"
```
The script will automatically skip Cloudflare setup.

---

### 🤖 Qsecbit AI Configuration

#### Threat Detection Thresholds

```bash
QSECBIT_AMBER_THRESHOLD=0.45    # Warning level (0.0 - 1.0)
QSECBIT_RED_THRESHOLD=0.70      # Critical level (0.0 - 1.0)
```

**Recommended values:**
- **Strict**: AMBER=0.35, RED=0.60
- **Balanced**: AMBER=0.45, RED=0.70 (default)
- **Relaxed**: AMBER=0.55, RED=0.80

#### Automated Response Settings

```bash
# Kali Linux On-Demand Configuration
KALI_ON_DEMAND=true                         # Spin up only when needed (recommended)
KALI_SPIN_UP_THRESHOLD="AMBER"              # Trigger: AMBER or RED
KALI_COOLDOWN_MINUTES=30                    # Keep running after alert
KALI_AUTO_SHUTDOWN=true                     # Auto-shutdown after cooldown

# Attack Mitigation Features
ENABLE_ANTI_XSS=true                        # XSS attack mitigation
ENABLE_ANTI_SQLI=true                       # SQL injection mitigation
ENABLE_MEMORY_PROTECTION=true               # Memory overflow protection
AUTO_UPDATE_WAF_RULES=true                  # Auto-update NAXSI rules
AUTO_BLOCK_ATTACKER_IP=true                 # Auto-block via iptables
CREATE_DB_SNAPSHOTS=true                    # Snapshot before mitigation
```

#### Component Weights

```bash
QSECBIT_ALPHA=0.30      # System drift weight
QSECBIT_BETA=0.30       # Attack probability weight
QSECBIT_GAMMA=0.20      # Classifier decay weight
QSECBIT_DELTA=0.20      # Quantum drift weight
```

These must sum to 1.0. Default balanced weights work well for most environments.

---

### 🛡️ WAF Configuration

```bash
NAXSI_LEARNING_MODE="0"     # 0=blocking, 1=learning
NAXSI_EXTENSIVE_LOG="1"     # Detailed logging
```

**Initial Setup:**
1. Start with `NAXSI_LEARNING_MODE="1"` for first week
2. Review logs in `/var/log/nginx/naxsi.log`
3. Tune rules, then switch to `NAXSI_LEARNING_MODE="0"`

---

## 🏗️ Architecture Overview

### POD Structure

| POD | Network | Purpose | Key Services |
|-----|---------|---------|--------------|
| **001** | 10.101.0.0/24 | Web DMZ | Django, NAXSI WAF, Nginx, Cloudflare |
| **002** | 10.102.0.0/24 | IAM/Auth | Logto, PostgreSQL |
| **003** | 10.103.0.0/24 | Persistent DB | PostgreSQL, NFS, RADIUS |
| **004** | 10.104.0.0/24 | Transient DB | Redis |
| **005** | 10.105.0.0/24 | Monitoring | Grafana, Prometheus, Loki, Rsyslog |
| **006** | 10.106.0.0/24 | Security | Suricata IDS/IPS |
| **007** | 10.107.0.0/24 | AI Response | Qsecbit, Kali Linux (on-demand) |

### Network Isolation

Each POD runs on its own encrypted VXLAN with unique VNI:
- VNI 100: Management
- VNI 101-107: Individual POD networks

All traffic between PODs is PSK-encrypted at the network layer.

---

## 🔒 Security Features

### Automated Threat Response

When Qsecbit detects threats, the system automatically:

#### XSS Injection Response
1. ✅ Updates NAXSI WAF rules to block pattern
2. ✅ Blocks attacker IP in firewall
3. ✅ Scans attacker infrastructure
4. ✅ Generates detailed incident report
5. ✅ Provides remediation recommendations

#### SQL Injection Response
1. ✅ Creates emergency database snapshot
2. ✅ Updates WAF with SQL injection rules
3. ✅ Blocks attacker IP
4. ✅ Enables detailed PostgreSQL logging
5. ✅ Runs database integrity check
6. ✅ Scans for additional injection points

#### Memory Overflow Response
1. ✅ Captures memory diagnostics
2. ✅ Reduces container memory limits
3. ✅ Clears caches
4. ✅ Resets connections
5. ✅ Generates safe restart script

### Defense in Depth

```
Internet
  ↓
Cloudflare Tunnel (Optional - Zero Trust)
  ↓
NAXSI WAF (Auto-updating rules)
  ↓
Nginx Reverse Proxy
  ↓
Django Application
  ↓
PostgreSQL (With snapshots)

---Monitoring Everything---
Qsecbit AI (Real-time analysis)
  ↓
Kali Linux (On-demand response)
```

---

## 📊 Port Mappings

### External Ports (Exposed on Host)

| Port | Service | Access |
|------|---------|--------|
| 80 | HTTP | Public |
| 443 | HTTPS | Public |
| 3000 | Grafana | Admin only |
| 3001 | Logto API | Internal/API |
| 3002 | Logto Admin | Admin only |
| 5432 | PostgreSQL | Optional |
| 8888 | Qsecbit API | Internal/Django |
| 9090 | Prometheus | Admin only |

### Firewall Recommendations

```bash
# Allow only necessary ports
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Restrict admin interfaces to specific IPs
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="YOUR_ADMIN_IP" port port="3000" protocol="tcp" accept'

firewall-cmd --reload
```

---

## 🔍 Monitoring & Logs

### Access Grafana Dashboards

1. **Navigate to**: http://YOUR_IP:3000
2. **Login**: admin / admin (change immediately!)
3. **Dashboards** → **Browse** → **HookProbe**

### Key Dashboards

- **System Overview**: All PODs health and metrics
- **Qsecbit Analysis**: Real-time threat scores
- **WAF Activity**: Blocked attacks and patterns
- **Database Performance**: Query times and connections
- **Security Events**: IDS/IPS alerts

### Query Logs in Loki

```
# All logs
{job=~".*"}

# Security events
{job="containerlogs"} |~ "ALERT|BLOCK|ATTACK"

# WAF blocks
{job="containerlogs"} | container_name=~".*naxsi.*" |= "BLOCK"

# Qsecbit alerts
{job="containerlogs"} | container_name=~".*qsecbit.*" |~ "RED|AMBER"

# Database errors
{job="containerlogs"} | container_name=~".*postgres.*" |~ "ERROR"
```

---

## 🔗 Django Integration

### Fetch Qsecbit Data

Add to your Django views:

```python
import requests

QSECBIT_API = 'http://10.107.0.10:8888'

def get_threat_status():
    """Get current threat level"""
    response = requests.get(f'{QSECBIT_API}/api/qsecbit/latest')
    return response.json()

def get_kali_responses():
    """Get recent attack responses"""
    response = requests.get(f'{QSECBIT_API}/api/kali/responses')
    return response.json()
```

### Display in Template

```django
{% load static %}

<div class="threat-dashboard">
    <h2>Security Status</h2>
    
    <div class="status-badge {{ qsecbit.rag_status|lower }}">
        {{ qsecbit.rag_status }}
    </div>
    
    <div class="metrics">
        <p>Threat Score: {{ qsecbit.score|floatformat:3 }}</p>
        <p>Attack Probability: {{ qsecbit.components.attack_probability|floatformat:2 }}%</p>
    </div>
    
    {% if qsecbit.rag_status == 'RED' or qsecbit.rag_status == 'AMBER' %}
    <div class="alert alert-warning">
        <h3>Active Threats Detected</h3>
        <p>Kali Linux response system engaged.</p>
    </div>
    {% endif %}
    
    <h3>Recent Responses</h3>
    <ul>
    {% for response in kali_responses %}
        <li>
            <strong>{{ response.timestamp }}</strong>: 
            {{ response.attack_type }}
            <ul>
            {% for action in response.recommended_actions %}
                <li>{{ action }}</li>
            {% endfor %}
            </ul>
        </li>
    {% endfor %}
    </ul>
</div>
```

---

## 🐛 Troubleshooting

### Check POD Status

```bash
# List all PODs
podman pod ps

# Check specific POD
podman pod ps --filter name=hookprobe-pod-007

# View POD logs
podman pod logs hookprobe-pod-007-ai-response
```

### Kali Container Not Starting

```bash
# Check if Qsecbit triggered it
podman logs hookprobe-pod-007-ai-response-qsecbit | grep -i "kali"

# Manually start Kali
podman start hookprobe-pod-007-ai-response-kali

# Check Kali logs
podman logs hookprobe-pod-007-ai-response-kali
```

### WAF Blocking Legitimate Traffic

1. Check NAXSI logs:
```bash
podman logs hookprobe-pod-001-web-dmz-nginx-naxsi | grep BLOCK
```

2. Switch to learning mode temporarily:
```bash
# Edit network-config.sh
NAXSI_LEARNING_MODE="1"

# Restart Nginx
podman restart hookprobe-pod-001-web-dmz-nginx-naxsi
```

3. Review and whitelist:
```bash
# Add whitelist rule to /tmp/naxsi-config/naxsi_whitelist.rules
BasicRule wl:1000 "mz:$URL:/your-endpoint";
```

### Database Connection Failed

```bash
# Check PostgreSQL
podman exec hookprobe-pod-003-db-persistent-postgres pg_isready

# Test connection
podman exec hookprobe-pod-001-web-dmz-django python manage.py dbshell

# Check credentials
grep POSTGRES network-config.sh
```

### High Memory Usage

```bash
# Check container stats
podman stats

# View Qsecbit analysis
curl http://localhost:8888/api/qsecbit/latest | jq

# Check for memory attack
podman logs hookprobe-pod-007-ai-response-kali | grep -i memory
```

---

## 📦 Backup & Recovery

### Create Backup

```bash
# Backup script is auto-created at:
/usr/local/bin/hookprobe-backup.sh

# Run manually
sudo /usr/local/bin/hookprobe-backup.sh

# Backups stored in:
/backup/hookprobe/YYYYMMDD-HHMMSS/
```

### Restore from Backup

```bash
# Stop all PODs
for pod in $(podman pod ls -q); do podman pod stop $pod; done

# Restore volumes
podman volume import hookprobe-postgres-data < /backup/hookprobe/YYYYMMDD/postgres.tar

# Restart
./setup.sh
```

---

## 🔄 Updating

### Update Container Images

```bash
# Pull latest images
podman pull docker.io/library/postgres:16-alpine
podman pull docker.io/grafana/grafana:latest
# ... etc

# Restart containers
podman restart hookprobe-pod-003-db-persistent-postgres
```

### Update Qsecbit Thresholds

```bash
# Edit configuration
nano network-config.sh

# Restart Qsecbit
podman restart hookprobe-pod-007-ai-response-qsecbit
```

---

## 📞 Support

### Logs Location

- **Container Logs**: `podman logs <container-name>`
- **System Logs**: `/var/log/messages`
- **Qsecbit Reports**: Inside Qsecbit container at `/data/`
- **Kali Reports**: Inside Kali container at `/reports/`

### Export Kali Reports

```bash
# Copy reports from Kali container
podman cp hookprobe-pod-007-ai-response-kali:/reports ./kali-reports/

# View recent incidents
ls -lt ./kali-reports/ | head -20
```

---

## 📄 License

MIT License - See LICENSE file

## 🙏 Credits

- **Qsecbit Algorithm**: Andrei Toma
- **HookProbe Platform**: HookProbe Team
- **Community Contributors**: See CONTRIBUTORS.md

---

## 🎯 Quick Reference Card

```
┌─────────────────────────────────────────┐
│  HOOKPROBE v4.0 QUICK REFERENCE         │
├─────────────────────────────────────────┤
│  Web App:    http://YOUR_IP             │
│  Admin:      http://YOUR_IP/admin       │
│  Grafana:    http://YOUR_IP:3000        │
│  Qsecbit:    http://YOUR_IP:8888        │
│                                          │
│  Deploy:     sudo ./setup.sh            │
│  Remove:     sudo ./uninstall.sh        │
│  Logs:       podman pod logs POD_NAME   │
│                                          │
│  Threat Status:                         │
│    GREEN  = Normal (< 0.45)             │
│    AMBER  = Warning (0.45-0.70)         │
│    RED    = Critical (> 0.70)           │
│                                          │
│  Auto-Response: Kali spins up on AMBER  │
│  Reports: /reports/ in Kali container   │
└─────────────────────────────────────────┘
```

---

**Version**: 4.0  
**Last Updated**: 2025  
**Status**: Production Ready 🚀
