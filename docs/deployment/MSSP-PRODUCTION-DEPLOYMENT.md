# MSSP Production Deployment Guide - hookprobe.com

**Version**: 1.0-Liberty
**Last Updated**: 2025-12-01
**Target**: hookprobe.com production MSSP cloud

---

## Executive Summary

This guide covers deploying the **HookProbe MSSP Cloud** to production at hookprobe.com. The MSSP cloud is the **prerequisite for all validators and edge nodes** in the HookProbe network.

**Liberty Architecture**: Simple, effective, unhackable. The MSSP cloud uses SQLite, standard Linux tools, and proven technologies.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Deployment Steps](#deployment-steps)
5. [Post-Deployment Verification](#post-deployment-verification)
6. [Validator Onboarding](#validator-onboarding)
7. [Monitoring & Maintenance](#monitoring--maintenance)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Infrastructure Requirements

**Server Specifications**:
- **CPU**: 8+ cores (16+ recommended for production)
- **RAM**: 16GB minimum (32GB recommended)
- **Storage**: 256GB SSD minimum (NVMe recommended)
- **Network**:
  - 1Gbps minimum bandwidth
  - Static public IP address
  - Firewall access for ports 80, 443, 4478

**Operating System**:
- Ubuntu 22.04 LTS or 24.04 LTS (recommended)
- Debian 11+/12+
- Raspberry Pi OS (Bookworm)

> **Note**: RHEL-based systems are not currently supported in v5.x. RHEL support is planned for a future release.

**Domain Configuration**:
- DNS A record: `hookprobe.com` → server IP
- DNS A record: `api.hookprobe.com` → server IP
- DNS A record: `mssp.hookprobe.com` → server IP
- SSL/TLS certificates ready (Let's Encrypt recommended)

### Software Prerequisites

```bash
# System updates
sudo apt update && sudo apt upgrade -y

# Required packages
sudo apt install -y \
    git curl wget \
    python3 python3-pip python3-venv \
    sqlite3 \
    nginx certbot python3-certbot-nginx \
    systemd \
    build-essential

# Optional: MaxMind GeoIP2
sudo apt install -y geoipupdate
```

### Network Configuration

**Firewall Rules**:
```bash
# HTTP/HTTPS for API endpoints
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# HTP validator communication
sudo ufw allow 4478/udp

# SSH (adjust as needed)
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
```

---

## Architecture Overview

### MSSP Cloud Components

```
┌─────────────────────────────────────────────────────────┐
│                MSSP Cloud Architecture                   │
│                  (hookprobe.com)                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────────────────────────────────────┐     │
│  │  NGINX Reverse Proxy                           │     │
│  │  - SSL/TLS termination                         │     │
│  │  - Rate limiting                               │     │
│  │  - API routing                                 │     │
│  └────────────┬───────────────────────────────────┘     │
│               │                                          │
│  ┌────────────▼───────────────────────────────────┐     │
│  │  MSSP API Server (Python/Django)               │     │
│  │  - Device registration                         │     │
│  │  - KYC workflow                                │     │
│  │  - Health checks                               │     │
│  │  - Admin dashboard                             │     │
│  └────────────┬───────────────────────────────────┘     │
│               │                                          │
│  ┌────────────▼───────────────────────────────────┐     │
│  │  MSSP Device Registry (SQLite)                 │     │
│  │  - devices table                               │     │
│  │  - device_locations table                      │     │
│  │  - Hardware fingerprint tracking               │     │
│  │  - KYC status management                       │     │
│  └────────────┬───────────────────────────────────┘     │
│               │                                          │
│  ┌────────────▼───────────────────────────────────┐     │
│  │  GeoIP Service                                 │     │
│  │  - MaxMind GeoIP2 (primary)                    │     │
│  │  - IP-API fallback                             │     │
│  │  - Location tracking                           │     │
│  └────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  HTP Validator Endpoint (UDP 4478)              │    │
│  │  - Accepts HELLO from edge nodes                │    │
│  │  - MSSP registry validation                     │    │
│  │  - Session management                           │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Database Schema

The MSSP uses SQLite for simplicity and auditability:

```sql
-- Device registry (see src/mssp/device_registry.py)
/var/lib/hookprobe/mssp/device_registry.db
  ├── devices (main device records)
  └── device_locations (location history)

-- Backups
/var/lib/hookprobe/mssp/backups/
  └── device_registry_YYYYMMDD_HHMMSS.db
```

---

## Pre-Deployment Checklist

### 1. DNS Verification

```bash
# Verify DNS records resolve correctly
dig hookprobe.com +short
dig api.hookprobe.com +short
dig mssp.hookprobe.com +short

# Should all return your server's public IP
```

### 2. SSL Certificate Setup

```bash
# Install Let's Encrypt certificates
sudo certbot --nginx -d hookprobe.com -d api.hookprobe.com -d mssp.hookprobe.com

# Verify certificate
sudo certbot certificates
```

### 3. Clone Repository

```bash
# Clone HookProbe repository
cd /opt
sudo git clone https://github.com/hookprobe/hookprobe
cd hookprobe
sudo git checkout main  # Or specific release tag
```

### 4. MaxMind GeoIP2 Setup (Optional but Recommended)

```bash
# Create MaxMind account at https://www.maxmind.com/en/geolite2/signup
# Get account ID and license key

# Configure GeoIP update
sudo tee /etc/GeoIP.conf > /dev/null <<EOF
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory /var/lib/GeoIP
EOF

# Download databases
sudo geoipupdate

# Verify databases
ls -lh /var/lib/GeoIP/
```

---

## Deployment Steps

### Step 1: Initialize MSSP Device Registry

```bash
# Create MSSP data directory
sudo mkdir -p /var/lib/hookprobe/mssp/backups
sudo chown -R hookprobe:hookprobe /var/lib/hookprobe/mssp

# Initialize device registry
cd /opt/hookprobe
python3 -c "
from src.mssp.device_registry import MSS PDeviceRegistry, DeviceType, DeviceLocation
import hashlib

# Initialize registry
registry = MSS PDeviceRegistry(db_path='/var/lib/hookprobe/mssp/device_registry.db')

# Register MSSP cloud itself
cloud_location = DeviceLocation(
    ip_address='$(curl -s ifconfig.me)',
    country='US',  # Adjust for your location
    region='Virginia',
    city='Ashburn',
    latitude=39.0438,
    longitude=-77.4874,
    asn=16509,
    isp='Amazon AWS'  # Adjust for your provider
)

registry.register_device(
    device_id='mssp-cloud-001',
    device_type=DeviceType.CLOUD,
    hardware_fingerprint=hashlib.sha256(b'$(hostname)-$(date +%s)').hexdigest(),
    public_key='mssp-cloud-pubkey',
    firmware_version='1.0-Liberty',
    location=cloud_location
)

# Approve cloud (self-approval)
registry.approve_device('mssp-cloud-001', kyc_verified=True)
print('✓ MSSP Cloud registered and activated')
"
```

### Step 2: Configure NGINX

```bash
# Create NGINX configuration
sudo tee /etc/nginx/sites-available/mssp-hookprobe > /dev/null <<'EOF'
# MSSP Cloud API
server {
    listen 80;
    listen [::]:80;
    server_name api.hookprobe.com mssp.hookprobe.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.hookprobe.com mssp.hookprobe.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/api.hookprobe.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.hookprobe.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=mssp_api:10m rate=10r/s;
    limit_req zone=mssp_api burst=20 nodelay;

    # API health check endpoint
    location /api/v1/health {
        default_type application/json;
        return 200 '{"status":"ok","service":"mssp-cloud","version":"1.0-Liberty"}';
    }

    # Device registration endpoint
    location /api/v1/register {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # KYC status endpoint
    location /api/v1/kyc {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Admin dashboard
    location /admin {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Basic auth for admin (optional)
        auth_basic "MSSP Admin";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/mssp-hookprobe /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Step 3: Deploy MSSP Cloud Service

```bash
# Create systemd service
sudo tee /etc/systemd/system/hookprobe-mssp-cloud.service > /dev/null <<'EOF'
[Unit]
Description=HookProbe MSSP Cloud Service
After=network.target

[Service]
Type=simple
User=hookprobe
Group=hookprobe
WorkingDirectory=/opt/hookprobe
Environment="PYTHONPATH=/opt/hookprobe"
ExecStart=/usr/bin/python3 /opt/hookprobe/src/mssp/mssp_cloud_service.py
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hookprobe/mssp

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable hookprobe-mssp-cloud
sudo systemctl start hookprobe-mssp-cloud
```

### Step 4: Deploy HTP Validator Service

```bash
# Create validator systemd service
sudo tee /etc/systemd/system/hookprobe-htp-validator.service > /dev/null <<'EOF'
[Unit]
Description=HookProbe HTP Validator Service (UDP 4478)
After=network.target hookprobe-mssp-cloud.service

[Service]
Type=simple
User=hookprobe
Group=hookprobe
WorkingDirectory=/opt/hookprobe
Environment="PYTHONPATH=/opt/hookprobe"
ExecStart=/usr/bin/python3 -c "
from src.neuro.transport.htp import HookProbeTransport
import sys

print('Starting HTP validator on port 4478...')
validator = HookProbeTransport(
    node_id='mssp-cloud-001',
    listen_port=4478,
    is_validator=True
)
print(f'HTP validator listening on {validator.local_address}')

# Run forever
try:
    while True:
        validator.receive_data(timeout=30.0)
except KeyboardInterrupt:
    print('Shutting down HTP validator')
    sys.exit(0)
"
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hookprobe

[Install]
WantedBy=multi-user.target
EOF

# Enable and start HTP validator
sudo systemctl daemon-reload
sudo systemctl enable hookprobe-htp-validator
sudo systemctl start hookprobe-htp-validator
```

---

## Post-Deployment Verification

### 1. Service Status Checks

```bash
# Check MSSP cloud service
sudo systemctl status hookprobe-mssp-cloud

# Check HTP validator service
sudo systemctl status hookprobe-htp-validator

# Check NGINX
sudo systemctl status nginx

# View logs
sudo journalctl -u hookprobe-mssp-cloud -f
sudo journalctl -u hookprobe-htp-validator -f
```

### 2. Health Endpoint Verification

```bash
# Test MSSP health endpoint
curl https://api.hookprobe.com/api/v1/health

# Expected response:
# {"status":"ok","service":"mssp-cloud","version":"1.0-Liberty"}
```

### 3. Database Verification

```bash
# Check device registry
sqlite3 /var/lib/hookprobe/mssp/device_registry.db <<EOF
SELECT device_id, device_type, status, kyc_verified
FROM devices
WHERE device_type = 'cloud';
EOF

# Expected output:
# mssp-cloud-001|cloud|active|1
```

### 4. Network Connectivity Test

```bash
# Test HTP validator port
sudo netstat -ulnp | grep 4478

# Expected: UDP listener on 0.0.0.0:4478
```

---

## Validator Onboarding

### 1. Validator Registration Process

When a validator operator runs `./install-validator.sh`:

1. **Script checks MSSP cloud**:
   ```bash
   curl -f https://api.hookprobe.com/api/v1/health
   ```

2. **Collects KYC information**:
   - Organization name
   - Contact email
   - Country
   - Region

3. **Generates hardware fingerprint**:
   - CPU ID, MAC addresses, disk serials, DMI UUID

4. **Registers with MSSP**:
   ```bash
   POST https://api.hookprobe.com/api/v1/register
   {
     "device_id": "validator-001",
     "device_type": "validator",
     "hardware_fingerprint": "sha256_hash",
     "public_key_ed25519": "device_pubkey",
     "firmware_version": "1.0-Liberty",
     "kyc_info": {
       "organization": "Example Corp",
       "email": "security@example.com",
       "country": "DE",
       "region": "Hesse"
     }
   }
   ```

5. **MSSP creates record**:
   - Status: PENDING
   - KYC verified: False
   - Location: IP-based geolocation

### 2. KYC Approval Workflow

**Admin dashboard** (https://api.hookprobe.com/admin):

```bash
# List pending validators
sqlite3 /var/lib/hookprobe/mssp/device_registry.db \
  "SELECT device_id, hardware_fingerprint, first_seen FROM devices WHERE status='pending' AND device_type='validator';"

# Review KYC information
# Verify organization, contact details, location

# Approve validator
python3 -c "
from src.mssp.device_registry import MSS PDeviceRegistry
registry = MSS PDeviceRegistry()
registry.approve_device('validator-001', kyc_verified=True)
"

# Validator status changes: PENDING → ACTIVE
# Validator receives notification and can start services
```

---

## Monitoring & Maintenance

### Daily Monitoring

```bash
# Device count
sqlite3 /var/lib/hookprobe/mssp/device_registry.db \
  "SELECT device_type, status, COUNT(*) FROM devices GROUP BY device_type, status;"

# Recent registrations
sqlite3 /var/lib/hookprobe/mssp/device_registry.db \
  "SELECT device_id, device_type, datetime(first_seen/1000000, 'unixepoch') FROM devices ORDER BY first_seen DESC LIMIT 10;"

# Location changes
sqlite3 /var/lib/hookprobe/mssp/device_registry.db \
  "SELECT device_id, ip_address, country, city, datetime(timestamp/1000000, 'unixepoch') FROM device_locations ORDER BY timestamp DESC LIMIT 20;"
```

### Backup Strategy

```bash
# Create daily backup cron job
sudo tee /etc/cron.daily/mssp-backup > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR="/var/lib/hookprobe/mssp/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
sqlite3 /var/lib/hookprobe/mssp/device_registry.db ".backup ${BACKUP_DIR}/device_registry_${TIMESTAMP}.db"

# Keep last 30 days
find ${BACKUP_DIR} -name "device_registry_*.db" -mtime +30 -delete
EOF

sudo chmod +x /etc/cron.daily/mssp-backup
```

### Performance Metrics

```bash
# Database size
du -h /var/lib/hookprobe/mssp/device_registry.db

# Service memory usage
ps aux | grep hookprobe

# Network connections
ss -tunap | grep 4478
```

---

## Troubleshooting

### Issue: Validator Registration Fails

**Symptom**: `install-validator.sh` reports "MSSP Cloud not deployed"

**Solution**:
```bash
# Verify MSSP health endpoint
curl -v https://api.hookprobe.com/api/v1/health

# Check NGINX logs
sudo tail -f /var/log/nginx/error.log

# Verify cloud device record
sqlite3 /var/lib/hookprobe/mssp/device_registry.db \
  "SELECT * FROM devices WHERE device_type='cloud';"
```

### Issue: HTP Validator Not Responding

**Symptom**: Edge nodes cannot connect on UDP 4478

**Solution**:
```bash
# Check service status
sudo systemctl status hookprobe-htp-validator

# Verify port is listening
sudo netstat -ulnp | grep 4478

# Check firewall
sudo ufw status | grep 4478

# Test from external host
nc -u hookprobe.com 4478
```

### Issue: GeoIP Lookups Failing

**Symptom**: Device locations show as unknown

**Solution**:
```bash
# Verify GeoIP2 databases
ls -lh /var/lib/GeoIP/

# Update databases
sudo geoipupdate

# Test geolocation service
python3 -c "
from src.mssp.geolocation import GeoIPService
geo = GeoIPService()
location = geo.geolocate('8.8.8.8')
print(location)
"
```

---

## Security Hardening

### 1. Fail2Ban Configuration

```bash
# Install fail2ban
sudo apt install fail2ban

# Configure for MSSP API
sudo tee /etc/fail2ban/jail.d/mssp.conf > /dev/null <<'EOF'
[mssp-api]
enabled = true
port = http,https
filter = mssp-api
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 3600
EOF
```

### 2. Database Encryption (Optional)

```bash
# SQLite encryption with SQLCipher
sudo apt install sqlcipher

# Encrypt existing database
sqlcipher /var/lib/hookprobe/mssp/device_registry.db \
  "PRAGMA key = 'your-encryption-key'; \
   ATTACH DATABASE '/var/lib/hookprobe/mssp/device_registry_encrypted.db' AS encrypted KEY 'your-encryption-key'; \
   SELECT sqlcipher_export('encrypted'); \
   DETACH DATABASE encrypted;"
```

### 3. Rate Limiting

Already configured in NGINX (10 req/s per IP).

---

## Next Steps

After MSSP cloud deployment:

1. ✅ **Test with first validator**:
   ```bash
   ./install-validator.sh
   # Complete KYC
   # Approve via admin dashboard
   ```

2. ✅ **Deploy edge nodes**:
   ```bash
   ./install.sh --role edge
   # Auto-register with MSSP
   ```

3. ✅ **Monitor growth**:
   - Track device registrations
   - Monitor validator health
   - Analyze location distribution

4. ✅ **Scale horizontally**:
   - Add more validator capacity
   - Implement load balancing
   - Consider multi-region deployment

---

## References

- **[HTP Protocol](../../src/neuro/transport/htp.py)** - Transport implementation
- **[Device Registry](../../src/mssp/device_registry.py)** - MSSP registry
- **[Hardware Fingerprinting](../../src/neuro/identity/hardware_fingerprint.py)** - Device identity
- **[GeoIP Service](../../src/mssp/geolocation.py)** - Geolocation

---

**Made with ❤️ and 🧠 for a safer, more equitable internet**
