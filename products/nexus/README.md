# HookProbe Nexus

> **"The ML/AI Compute Hub"** - Enterprise analytics and threat intelligence

## Overview

Nexus is an ML/AI compute hub for advanced threat detection, analytics, and intelligence processing. It provides GPU-accelerated machine learning, long-term data retention, and advanced analytics for security operations.

> **Note**: Nexus focuses on compute-intensive AI/ML workloads and provides mesh federation services.

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU Cores | 4 | 8+ |
| RAM | 16GB | 32GB |
| Storage | 256GB | 1TB+ NVMe |
| Network | 1Gbps | 10Gbps |
| GPU | Optional | NVIDIA recommended |

## Supported Platforms

- Datacenter servers
- Cloud instances (AWS, GCP, Azure)
- Dedicated hardware
- Proxmox/VMware VMs (with resources)
- Kubernetes clusters

## Features

### Multi-Tenant Management
- Tenant isolation (RBAC)
- Per-tenant dashboards
- Quota management
- Custom branding

### Analytics
- **ClickHouse**: High-performance analytics
- **Long-term retention**: Years of data
- **Real-time queries**: Sub-second response
- **Custom reports**: Automated generation

### Edge Orchestration
- Centralized policy management
- Signature distribution
- Remote configuration
- Fleet management

### Security Operations
- Centralized SIEM
- Threat intelligence
- Incident management
- Compliance reporting

### AI/ML (GPU-accelerated)
- Advanced threat detection
- Anomaly detection
- Behavioral analysis
- Automated response

## Installation

### Prerequisites

```bash
# Ensure system meets requirements
sudo ./install.sh --check

# Install dependencies
sudo apt install -y podman python3-pip nvidia-container-toolkit
```

### Quick Install

```bash
sudo ./install.sh --tier nexus
```

### Production Install

```bash
# With all production features
sudo ./install.sh --tier nexus \
  --enable-ha \
  --enable-gpu \
  --clickhouse-cluster \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           NEXUS BACKEND             │
                    ├─────────────────────────────────────┤
                    │  ┌─────────┐  ┌─────────────────┐  │
                    │  │ API GW  │  │  Web Dashboard  │  │
                    │  └────┬────┘  └────────┬────────┘  │
                    │       │                │           │
                    │  ┌────┴────────────────┴────┐      │
                    │  │      Core Services       │      │
                    │  │  - Tenant Manager        │      │
                    │  │  - Policy Engine         │      │
                    │  │  - Signature Distributor │      │
                    │  └──────────┬───────────────┘      │
                    │             │                      │
                    │  ┌──────────┴───────────────┐      │
                    │  │     Data Layer           │      │
                    │  │  - ClickHouse Cluster    │      │
                    │  │  - PostgreSQL            │      │
                    │  │  - Redis/Valkey          │      │
                    │  └──────────────────────────┘      │
                    └─────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
              ┌─────┴─────┐    ┌─────┴─────┐    ┌─────┴─────┐
              │ Guardian  │    │ Fortress  │    │ Sentinel  │
              │  (Edge)   │    │  (Edge)   │    │  (Edge)   │
              └───────────┘    └───────────┘    └───────────┘
```

## Configuration

### Main Configuration

`/etc/hookprobe/nexus.conf`:
```bash
# Cluster settings
CLUSTER_NAME=nexus-prod
NODE_ID=nexus-01

# Database
CLICKHOUSE_HOSTS=ch1.internal,ch2.internal,ch3.internal
POSTGRES_HOST=pg.internal
REDIS_HOST=redis.internal

# TLS
TLS_ENABLED=true
TLS_CERT=/etc/hookprobe/tls/cert.pem
TLS_KEY=/etc/hookprobe/tls/key.pem

# GPU
GPU_ENABLED=true
GPU_DEVICE=0
```

### Tenant Configuration

Tenants are managed via API or UI:
```bash
# Create tenant
hookprobe-ctl tenant create \
  --name "Acme Corp" \
  --id acme-001 \
  --quota-edges 100 \
  --quota-storage 500GB

# List tenants
hookprobe-ctl tenant list

# Disable tenant
hookprobe-ctl tenant disable acme-001
```

## Service Management

```bash
# Start all Nexus services
sudo systemctl start hookprobe-nexus

# Individual services
sudo systemctl start hookprobe-nexus-api
sudo systemctl start hookprobe-nexus-worker
sudo systemctl start hookprobe-nexus-scheduler

# Check cluster status
hookprobe-ctl cluster status
```

## Web Interfaces

| Interface | URL | Purpose |
|-----------|-----|---------|
| Dashboard | https://localhost:8443 | Main SOC dashboard |
| Admin | https://localhost:8443/admin | System administration |
| API Docs | https://localhost:8443/api/docs | API documentation |
| Grafana | https://localhost:3000 | Metrics |

## API

Full REST API for integration:

```bash
# Authenticate
curl -X POST https://nexus.example.com/api/v1/auth/token \
  -d '{"username": "admin", "password": "secret"}'

# List edges
curl -H "Authorization: Bearer $TOKEN" \
  https://nexus.example.com/api/v1/edges

# Push policy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://nexus.example.com/api/v1/policies \
  -d @policy.json
```

## High Availability

For production deployments:

```yaml
# docker-compose.ha.yml
services:
  nexus-api:
    replicas: 3
    deploy:
      placement:
        constraints:
          - node.role == manager

  clickhouse:
    replicas: 3
    # Sharded + replicated

  postgres:
    # Primary + replica
```

## GPU Acceleration

For AI workloads with NVIDIA GPU:

```bash
# Verify GPU detection
nvidia-smi

# Enable in config
echo "GPU_ENABLED=true" >> /etc/hookprobe/nexus.conf

# Restart services
sudo systemctl restart hookprobe-nexus
```

## Data Retention

| Data Type | Default Retention | Configurable |
|-----------|-------------------|--------------|
| Raw logs | 30 days | Yes |
| Metrics | 90 days | Yes |
| Alerts | 1 year | Yes |
| Analytics | 2 years | Yes |
| Audit logs | 7 years | Per compliance |

## Backup & Recovery

```bash
# Full backup
hookprobe-ctl backup create --type full --dest s3://bucket/backups/

# Incremental backup
hookprobe-ctl backup create --type incremental

# Restore
hookprobe-ctl backup restore --from s3://bucket/backups/full-20240101.tar.gz
```

## Scaling

### Horizontal Scaling

```bash
# Add worker node
hookprobe-ctl cluster add-node \
  --host worker2.internal \
  --role worker

# Add ClickHouse node
hookprobe-ctl cluster add-node \
  --host ch3.internal \
  --role clickhouse
```

### Vertical Scaling

Adjust resource limits in `/etc/hookprobe/nexus.conf`:
```bash
API_WORKERS=16
CLICKHOUSE_MAX_MEMORY=64g
AI_GPU_MEMORY=16g
```

## Monitoring

Built-in monitoring for:
- Cluster health
- Edge connectivity
- Data ingestion rate
- Query performance
- GPU utilization

## Troubleshooting

### ClickHouse Performance
```bash
# Check query log
clickhouse-client --query "SELECT * FROM system.query_log ORDER BY event_time DESC LIMIT 10"

# Check replication
clickhouse-client --query "SELECT * FROM system.replicas"
```

### Edge Connectivity Issues
```bash
# Check edge registration
hookprobe-ctl edges list --status disconnected

# Test connectivity
hookprobe-ctl edges ping edge-001
```

### High Memory Usage
```bash
# Check container memory
podman stats

# Analyze ClickHouse memory
clickhouse-client --query "SELECT * FROM system.memory_tracking"
```
