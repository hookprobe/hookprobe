# HookProbe MSSP Cloud Backend Deployment Guide

**Version**: 5.0
**Purpose**: Deploy Apache Doris cluster for multi-tenant MSSP operations
**License**: MIT

---

![Hookprobe Cloud Orchestrator](../images/hookprobe-cloud-orchestrator.png)

---

## 📋 Overview

The HookProbe backend is a centralized cloud infrastructure for managing security data from hundreds or thousands of edge HookProbe deployments. It provides:

- **Multi-tenant data isolation** via Apache Doris row-level security
- **Centralized analytics** across all customer deployments
- **Cross-customer threat intelligence**
- **GPU-accelerated ML training** (optional)
- **Customer self-service dashboards**

---

## 🏗️ Architecture

```
Edge Devices (Customers)          Cloud Backend (MSSP)
┌──────────────────┐              ┌──────────────────────┐
│ HookProbe SBC    │──TLS────────▶│ Apache Doris Cluster │
│ - ClickHouse     │              │ - 3 Frontend Nodes   │
│ - Qsecbit        │              │ - 3+ Backend Nodes   │
│ - Local Analytics│              │ - Kafka Ingestion    │
└──────────────────┘              │ - Multi-Tenant DB    │
                                  └──────────────────────┘
```

---

## ⚙️ System Requirements

### Minimum (Development/Testing)
- **CPU**: 32 cores (64 threads)
- **RAM**: 128 GB
- **Storage**: 1 TB NVMe SSD
- **Network**: 10 Gbps
- **OS**: Ubuntu 22.04+, Debian 11+/12+ (RHEL-based systems not supported due to OVS limitations)

### Production (100+ customers)
- **CPU**: 128+ cores per backend node
- **RAM**: 256 GB per backend node
- **Storage**: 8 TB+ NVMe SSD per backend node
- **Network**: 25 Gbps+
- **Cluster**: 3 Frontend + 10+ Backend nodes

---

## 🚀 Quick Start

### 1. Configure

```bash
cd /home/user/hookprobe/Scripts/backend/install
nano backend-network-config.sh
```

**Critical settings to change**:
- `DORIS_ADMIN_PASSWORD` - Set strong password
- `LOCAL_HOST_IP` - Auto-detected, verify correct
- `DORIS_BE_STORAGE` - Storage path (default: /mnt/doris)

### 2. Deploy

```bash
sudo ./backend-setup.sh
```

Deployment takes ~10-15 minutes depending on hardware.

### 3. Initialize Doris Cluster

```bash
# Connect to Doris and run initialization SQL
mysql -h 10.100.1.10 -P 9030 -uroot < /tmp/doris-init.sql

# Set root password
mysql -h 10.100.1.10 -P 9030 -uroot
SET PASSWORD FOR 'root'@'%' = PASSWORD('YOUR_STRONG_PASSWORD');
```

### 4. Create Multi-Tenant Schema

```sql
-- Create security database
CREATE DATABASE IF NOT EXISTS security;

-- Create qsecbit_scores table with multi-tenancy
CREATE TABLE security.qsecbit_scores (
    tenant_id VARCHAR(64) NOT NULL,
    timestamp DATETIME NOT NULL,
    score FLOAT,
    rag_status VARCHAR(20),
    drift FLOAT,
    attack_probability FLOAT,
    classifier_decay FLOAT,
    quantum_drift FLOAT,
    cpu_usage FLOAT,
    memory_usage FLOAT,
    network_traffic FLOAT,
    disk_io FLOAT,
    host VARCHAR(255),
    pod VARCHAR(255)
)
DUPLICATE KEY(tenant_id, timestamp)
DISTRIBUTED BY HASH(tenant_id) BUCKETS 32
PROPERTIES (
    "replication_num" = "3",
    "compression" = "ZSTD"
);
```

---

## 🔐 Multi-Tenant Setup

### Create Tenant User

```sql
-- Create customer-specific user
CREATE USER 'customer_acme'@'%' IDENTIFIED BY 'strong_password';

-- Grant access only to their data
GRANT SELECT ON security.* TO 'customer_acme'@'%'
WHERE tenant_id = 'acme_corp';
```

### Set Resource Quotas

```sql
ALTER USER 'customer_acme'@'%'
SET PROPERTY (
    "max_user_connections" = "100",
    "cpu_resource_limit" = "10%",
    "memory_limit" = "10GB"
);
```

---

## 📊 Grafana Multi-Tenant Dashboards

Access Grafana: `http://YOUR_IP:3000`

**Default credentials**: admin / (from config file)

### Add Doris Datasource

1. Navigate to **Configuration** → **Data Sources**
2. Add **MySQL** datasource
3. Configure:
   - **Host**: `10.100.1.10:9030`
   - **Database**: `security`
   - **User**: `customer_specific_user`
   - **Password**: (from tenant setup)

---

## 🔧 Operations

### Check Cluster Status

```bash
# Frontend nodes
podman ps | grep doris-fe

# Backend nodes
podman ps | grep doris-be

# Doris cluster status
mysql -h 10.100.1.10 -P 9030 -uroot -p -e "SHOW FRONTENDS;"
mysql -h 10.100.1.10 -P 9030 -uroot -p -e "SHOW BACKENDS;"
```

### View Logs

```bash
journalctl -u podman-doris-fe-1 -f
journalctl -u podman-doris-be-1 -f
```

### Backup

```bash
# Manual backup
mysql -h 10.100.1.10 -P 9030 -uroot -p -e "BACKUP SNAPSHOT security.backup_$(date +%Y%m%d) TO 's3://your-bucket/backups';"
```

---

## 🧪 Testing

### Test Doris Query

```sql
-- Count qsecbit scores
SELECT tenant_id, COUNT(*) as scores
FROM security.qsecbit_scores
GROUP BY tenant_id;

-- Average threat score by tenant (last 24h)
SELECT
    tenant_id,
    AVG(score) as avg_score,
    COUNT(CASE WHEN rag_status='RED' THEN 1 END) as red_alerts
FROM security.qsecbit_scores
WHERE timestamp >= NOW() - INTERVAL 24 HOUR
GROUP BY tenant_id
ORDER BY avg_score DESC;
```

---

## 🔥 Troubleshooting

### Issue: Frontend won't start

**Symptoms**: `doris-fe-1` container exits

**Solution**:
```bash
# Check logs
podman logs doris-fe-1

# Verify Java memory settings
# Reduce DORIS_FE_MEMORY in backend-network-config.sh if low RAM
```

### Issue: Backend not registering

**Symptoms**: `SHOW BACKENDS` returns empty

**Solution**:
```bash
# Manually add backends
mysql -h 10.100.1.10 -P 9030 -uroot -p
ALTER SYSTEM ADD BACKEND "10.100.2.10:9050";
ALTER SYSTEM ADD BACKEND "10.100.2.11:9050";
ALTER SYSTEM ADD BACKEND "10.100.2.12:9050";
```

### Issue: Out of disk space

**Solution**:
```bash
# Check storage usage
df -h /mnt/doris

# Clean old data (adjust retention)
mysql -h 10.100.1.10 -P 9030 -uroot -p
ALTER TABLE security.qsecbit_scores
SET ("storage_cooldown_time" = "2025-01-01 00:00:00");
```

---

## 🌐 Edge Device Configuration

Configure edge HookProbe devices to stream data to backend:

```bash
# On edge device (customer site)
export DEPLOYMENT_TYPE="edge"
export DORIS_ENABLED="false"            # Don't connect to Doris from edge
export CLICKHOUSE_ENABLED="true"        # Use local ClickHouse
export KAFKA_BOOTSTRAP_SERVERS="mssp.hookprobe.com:9092"
export TENANT_ID="customer_acme"
```

Vector will stream data from edge ClickHouse → Backend Kafka → Backend Doris.

---

## 📚 Additional Resources

- [Apache Doris Documentation](https://doris.apache.org/docs/summary/basic-summary)
- [HookProbe Main README](../../../README.md)
- [ClickHouse Integration Guide](../guides/clickhouse-integration.md)
- [ClickHouse Quick Start](../guides/clickhouse-quick-start.md)

---

## 🆘 Support

**Issues**: https://github.com/hookprobe/hookprobe/issues
**Security**: qsecbit@hookprobe.com
**Documentation**: [CLAUDE.md](../../../CLAUDE.md)

---

**HookProbe v5.0** - Democratizing Cybersecurity Through Edge Computing + Cloud Analytics
