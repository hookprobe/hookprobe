# Cloud Backend Deployment (MSSP Multi-Tenant)

**Centralized security analytics for managed service providers**

Deploy a scalable, multi-tenant HookProbe backend for managing 100-1000+ edge devices with long-term analytics retention.

---

## 🎯 Overview

The **MSSP Cloud Backend** provides centralized security operations for multiple customer sites using Apache Doris for high-performance analytics at scale.

### Architecture

```
┌────────────────────────────────────────┐
│   Apache Doris Cluster (Cloud)        │
│                                        │
│  ┌──────────┐      ┌──────────────┐  │
│  │Frontend  │      │   Backend    │  │
│  │   (3)    │◄────►│    (3+)      │  │
│  │Coordinat │      │Storage+Compute│  │
│  └──────────┘      └──────────────┘  │
│                                        │
│  Features:                             │
│  • 1000+ device capacity               │
│  • 365+ day retention                  │
│  • Cross-tenant threat intel           │
│  • GPU ML training (optional)          │
└────────────┬───────────────────────────┘
             │
       TLS Encrypted
             │
    ┌────────┴─────┬──────────┐
    │              │          │
┌───▼────┐   ┌─────▼───┐  ┌──▼─────┐
│Edge A  │   │ Edge B  │  │Edge C  │
│Customer│   │Customer │  │Customer│
│  Site  │   │  Site   │  │  Site  │
└────────┘   └─────────┘  └────────┘
```

### Use Cases

- ✅ **MSSP Providers**: Manage security for multiple customers
- ✅ **Enterprise Multi-Site**: Centralize security across branch offices
- ✅ **Security Research**: Aggregate threat intelligence
- ✅ **SOC Operations**: 24/7 monitoring and incident response

---

## 💻 Hardware Requirements

### Minimum (Testing/Development)

- **CPU**: 16+ cores per node
- **RAM**: 64GB per node
- **Storage**: 500GB SSD
- **Network**: 1Gbps NIC
- **Cluster**: 1 Frontend + 1 Backend node

### Recommended (Production)

- **CPU**: 32-128 cores per node (Intel Xeon / AMD EPYC)
- **RAM**: 128-512GB per node
- **Storage**: 2TB+ NVMe SSD per backend node
- **Network**: 10-40Gbps NIC (Intel X710 or Mellanox)
- **Cluster**: 3 Frontend + 3+ Backend nodes

---

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Supported OS (v5.x - Debian-based only)
- Ubuntu 22.04+/24.04+
- Debian 11+/12+
- Raspberry Pi OS (Bookworm)
- Proxmox VE 8.x+

# Note: RHEL-based systems not yet supported in v5.x

# Install Podman 4.x+
sudo apt install podman podman-compose  # Debian/Ubuntu
```

### 2. Configure

```bash
cd /home/user/hookprobe
sudo ./install.sh

# Select: 2) Select Deployment Mode
# Then: 2) MSSP Cloud Backend [Multi-Tenant]
```

Or manually:

```bash
cd install/cloud
nano config.sh

# Update key settings:
DORIS_ADMIN_PASSWORD="your-strong-password"
DORIS_FE_NODE_IPS=("192.168.1.10" "192.168.1.11" "192.168.1.12")
DORIS_BE_NODE_IPS=("192.168.1.20" "192.168.1.21" "192.168.1.22")
```

### 3. Deploy

```bash
sudo ./setup.sh
```

### 4. Initialize Cluster

```bash
# Add backend nodes
mysql -h 10.100.1.10 -P 9030 -uroot -p"${DORIS_ADMIN_PASSWORD}" << EOF
ALTER SYSTEM ADD BACKEND "10.100.1.20:9050";
ALTER SYSTEM ADD BACKEND "10.100.1.21:9050";
ALTER SYSTEM ADD BACKEND "10.100.1.22:9050";
EOF

# Verify cluster
mysql -h 10.100.1.10 -P 9030 -uroot -p"${DORIS_ADMIN_PASSWORD}" -e "SHOW BACKENDS\\G"
```

---

## 📊 Multi-Tenant Schema

### Tenant Isolation

Each customer gets isolated database/schemas:

```sql
-- Create tenant database
CREATE DATABASE IF NOT EXISTS tenant_acme;

-- Create security events table
CREATE TABLE tenant_acme.security_events (
    event_id BIGINT,
    timestamp DATETIME,
    source_type VARCHAR(50),
    severity VARCHAR(20),
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    attack_type VARCHAR(100),
    blocked BOOLEAN
) DUPLICATE KEY(event_id, timestamp)
DISTRIBUTED BY HASH(event_id) BUCKETS 32
PROPERTIES("replication_num" = "3");
```

### Cross-Tenant Analytics

Aggregate threat intelligence across all tenants:

```sql
-- Top attack types (all tenants)
SELECT attack_type, COUNT(*) as count
FROM (
    SELECT attack_type FROM tenant_acme.security_events
    UNION ALL
    SELECT attack_type FROM tenant_widgets.security_events
)
GROUP BY attack_type
ORDER BY count DESC
LIMIT 10;
```

---

## 🔌 Edge Device Integration

### Configure Edge to Stream to Cloud

On each edge device:

```bash
# Edit config
nano /opt/hookprobe/config/qsecbit.conf

# Add cloud backend
[cloud]
enabled = true
backend_url = https://mssp.yourcompany.com
tenant_id = customer_acme
api_key = your-api-key
stream_events = true
retention_days = 90  # Local retention before upload
```

### Secure Communication

- TLS 1.3 encryption
- Mutual TLS authentication (optional)
- API key + JWT tokens
- IP allowlist (edge device IPs)

---

## 📈 Scaling

### Add Backend Nodes

```sql
-- Add new backend node dynamically
ALTER SYSTEM ADD BACKEND "10.100.1.23:9050";

-- Verify
SHOW BACKENDS;
```

### Storage Expansion

```bash
# Add additional disk to backend node
DORIS_BE_STORAGE="/data1,/data2,/data3"  # config.sh
```

### Performance Tuning

```sql
-- Adjust bucket count for large tables
ALTER TABLE security_events
DISTRIBUTED BY HASH(event_id) BUCKETS 64;

-- Enable materialized views for common queries
CREATE MATERIALIZED VIEW mv_hourly_attacks AS
SELECT
    date_trunc(timestamp, 'hour') as hour,
    attack_type,
    COUNT(*) as count
FROM security_events
GROUP BY hour, attack_type;
```

---

## 📊 Monitoring

Access Grafana for cloud backend monitoring:

```bash
http://CLOUD_BACKEND_IP:3000

# Key metrics:
- Doris cluster health
- Query performance
- Storage utilization
- Ingestion rate (events/sec)
- Per-tenant resource usage
```

---

## 🛠️ Troubleshooting

### Frontend Won't Start

```bash
podman logs hookprobe-doris-fe
# Check logs for port conflicts or config errors
```

### Backend Not Joining Cluster

```bash
# Verify network connectivity
ping 10.100.1.20

# Check backend logs
podman logs hookprobe-doris-be

# Force re-add backend
mysql -h 10.100.1.10 -P 9030 -uroot -e "ALTER SYSTEM DROPP BACKEND '10.100.1.20:9050';"
mysql -h 10.100.1.10 -P 9030 -uroot -e "ALTER SYSTEM ADD BACKEND '10.100.1.20:9050';"
```

---

## 📚 Documentation

- **Full Deployment Guide**: [../../docs/installation/cloud-deployment.md](../../docs/installation/cloud-deployment.md)
- **Main README**: [../../README.md](../../README.md)
- **Architecture**: [../../docs/architecture/security-model.md](../../docs/architecture/security-model.md)

---

**MSSP Cloud Backend** - *Centralized Security at Scale*

Built with ❤️ for managed security service providers
