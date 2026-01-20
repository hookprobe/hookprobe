# MSSP Architecture Documentation

**Version:** 5.2
**Last Updated:** 2026-01-20

## Overview

The MSSP (Managed Security Service Provider) tier is HookProbe's cloud-based central management platform. It provides multi-tenant device management, security monitoring, and unified IAM via Logto.

## Container Architecture

### Deployment Modes

| Mode | Command | Use Case |
|------|---------|----------|
| **Standalone (ROOT)** | `sudo ./setup.sh --standalone` | Production with OVS/SDN |
| **HookProbe-COM Integration (ROOTLESS)** | `./setup.sh` (auto-detects) | Shared proxy with website |

**CRITICAL:** Do not mix root and rootless containers that need to communicate!

### Current Architecture (Hybrid Host Networking)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL ACCESS (Internet)                            │
│                              Port 80/443                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ROOTLESS NAMESPACE (ubuntu user)                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  hookprobe-proxy (nginx:1.25)                                        │   │
│  │  - Routes hookprobe.com → hookprobe-website                          │   │
│  │  - Routes mssp.hookprobe.com → host.containers.internal:8000         │   │
│  │  - Routes /oidc/* → host.containers.internal:3001                    │   │
│  │  Network: 172.30.0.2 (hookprobe-public)                              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  hookprobe-website (Django CMS)                                      │   │
│  │  Network: 172.30.0.10 (hookprobe-public)                             │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                          host.containers.internal
                        (localhost from rootless POV)
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ROOT NAMESPACE (sudo)                                │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                  HOST NETWORK CONTAINERS                               │  │
│  │  ┌────────────────────┐  ┌────────────────────┐                       │  │
│  │  │    mssp-django     │  │    mssp-logto      │                       │  │
│  │  │  localhost:8000    │  │  localhost:3001    │                       │  │
│  │  │  localhost:3002    │  │  (Admin portal)    │                       │  │
│  │  └────────────────────┘  └────────────────────┘                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                           │              │                                   │
│              ┌────────────┴──────────────┴────────────┐                     │
│              ▼                                        ▼                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    POD NETWORKS (172.20.x.x)                          │  │
│  │                                                                        │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │  │
│  │  │mssp-postgres│ │ mssp-valkey │ │mssp-celery  │ │mssp-qsecbit │     │  │
│  │  │172.20.3.10  │ │172.20.4.10  │ │172.20.1.11  │ │172.20.6.10  │     │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘     │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │  │
│  │  │mssp-click   │ │mssp-victoria│ │mssp-grafana │ │  mssp-n8n   │     │  │
│  │  │172.20.5.11  │ │172.20.5.10  │ │172.20.5.12  │ │172.20.8.10  │     │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘     │  │
│  │                                                                        │  │
│  │  ┌─────────────┐                                                      │  │
│  │  │  mssp-htp   │  Host network for mesh connectivity                  │  │
│  │  │  Port 4478  │                                                      │  │
│  │  └─────────────┘                                                      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Container Functions

### Core Services

| Container | Purpose | Data Managed | Port | Network |
|-----------|---------|--------------|------|---------|
| **mssp-django** | Web application | HTTP requests, API | 8000 | host |
| **mssp-postgres** | Primary database | User data, devices, configs | 5432 | pod-003-db |
| **mssp-valkey** | Cache/sessions | Sessions, rate limits | 6379 | pod-004-cache |
| **mssp-celery** | Background jobs | Async tasks, scheduled jobs | - | pod-001-dmz |

### IAM & Authentication

| Container | Purpose | Data Managed | Port | Network |
|-----------|---------|--------------|------|---------|
| **mssp-logto** | OIDC/IAM provider | User identity, SSO | 3001, 3002 | host |

### Monitoring & Analytics

| Container | Purpose | Data Managed | Port | Network |
|-----------|---------|--------------|------|---------|
| **mssp-clickhouse** | Analytics database | Time-series events | 8123, 9000 | pod-005-monitoring |
| **mssp-victoriametrics** | Metrics storage | Prometheus metrics | 8428 | pod-005-monitoring |
| **mssp-grafana** | Dashboards | Visualizations | 3000 | pod-005-monitoring |

### Security & Automation

| Container | Purpose | Data Managed | Port | Network |
|-----------|---------|--------------|------|---------|
| **mssp-qsecbit** | Security scoring | Threat scores, RAG status | 8888 | pod-006-security |
| **mssp-n8n** | Workflow automation | Webhooks, automations | 5678 | pod-008-automation |
| **mssp-htp** | Mesh transport | Edge device connections | 4478 | host |

## Technology Notes

### Valkey (Redis-Compatible Cache)

MSSP uses **Valkey 7.2** as its cache and session store. Valkey is a community fork of Redis that maintains 100% protocol compatibility:

- **Container**: `mssp-valkey`
- **Image**: `docker.io/valkey/valkey:7.2-alpine`
- **Port**: 6379 (standard Redis port)
- **Protocol**: `redis://` URL scheme (compatible with Django's redis cache backend)

**Django Configuration:**
```python
# Django uses REDIS_* environment variables for compatibility
REDIS_HOST = os.getenv('REDIS_HOST')  # Points to Valkey container
REDIS_PORT = os.getenv('REDIS_PORT')  # 6379

# Cache backend uses redis:// URL scheme
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': f'redis://{REDIS_HOST}:{REDIS_PORT}/1',
    }
}
```

**Why Valkey over Redis?**
- Community-driven, fully open source (BSD license)
- No licensing concerns post-Redis 7.4
- Active development and security updates
- 100% drop-in replacement for Redis 7.x

## Data Flow

### Request Flow (User → Dashboard)

```
User Browser
    │
    ▼
nginx (hookprobe-proxy) - SSL termination, routing
    │
    ├── /oidc/* → mssp-logto:3001 (authentication)
    │
    └── /* → mssp-django:8000 (application)
              │
              ├── Session check → mssp-valkey
              │
              ├── Database queries → mssp-postgres
              │
              ├── Security score → mssp-qsecbit
              │
              └── Async jobs → mssp-celery → mssp-valkey
```

### Metrics Flow

```
Edge Devices (Guardian/Fortress)
    │
    ▼
mssp-htp (HTP protocol)
    │
    ├── Events → mssp-clickhouse
    │
    └── Metrics → mssp-victoriametrics
                        │
                        ▼
                  mssp-grafana (dashboards)
```

## Network Configuration

### Pod Networks (Root Podman)

| Network | Subnet | VLAN | Purpose |
|---------|--------|------|---------|
| mssp-pod-001-dmz | 172.20.1.0/24 | 201 | DMZ/Web services |
| mssp-pod-002-iam | 172.20.2.0/24 | 202 | IAM services |
| mssp-pod-003-db | 172.20.3.0/24 | 203 | Database services |
| mssp-pod-004-cache | 172.20.4.0/24 | 204 | Cache services |
| mssp-pod-005-monitoring | 172.20.5.0/24 | 205 | Monitoring services |
| mssp-pod-006-security | 172.20.6.0/24 | 206 | Security services |
| mssp-pod-007-response | 172.20.7.0/24 | 207 | Response services |
| mssp-pod-008-automation | 172.20.8.0/24 | 208 | Automation services |

### External Network (Rootless Podman)

| Network | Subnet | Purpose |
|---------|--------|---------|
| hookprobe-public | 172.30.0.0/24 | Proxy and website |

## When to Use sudo vs Non-sudo

### Use ROOT (sudo) for:
- MSSP production deployment with OVS/SDN
- Services requiring raw sockets (mssp-htp)
- Services requiring privileged ports (<1024)
- OVS bridge management
- VXLAN tunnel configuration

### Use ROOTLESS (non-sudo) for:
- Development/testing
- HookProbe-COM integrated deployment
- When running alongside rootless website
- When root access is not available

## Fresh Install Guide

### Option 1: Standalone Production (ROOT)

```bash
# Full MSSP with OVS/SDN networking
sudo ./products/mssp/setup.sh --standalone

# This creates:
# - All containers as root
# - OVS bridge for SDN
# - VXLAN tunnels for mesh
# - All pod networks
```

### Option 2: HookProbe-COM Integration (ROOTLESS)

```bash
# First, ensure hookprobe-com is running
cd /home/ubuntu/hookprobe-com
podman-compose up -d

# Then deploy MSSP (auto-detects hookprobe-com)
cd /home/ubuntu/hookprobe/products/mssp
./setup.sh  # Runs as rootless, integrates with proxy
```

### Option 3: Hybrid Mode (Current Setup)

When you need both external access via rootless proxy AND root container features:

1. Keep nginx proxy as rootless (hookprobe-com)
2. Run MSSP containers as root with host networking for cross-namespace access
3. Update nginx to use `host.containers.internal` for MSSP upstreams

```nginx
# In nginx.conf
upstream mssp {
    server host.containers.internal:8000;  # Django on host network
}

upstream logto {
    server host.containers.internal:3001;  # Logto on host network
}
```

## Security Configuration

### Django ALLOWED_HOSTS

**CRITICAL SECURITY RULE:** Never include `localhost`, `127.0.0.1`, or `host.containers.internal` in Django's `ALLOWED_HOSTS` for production deployments.

**Reason:** Allowing localhost-style hosts can enable Host Header Injection attacks where an attacker could:
- Bypass security controls
- Poison caches
- Manipulate password reset links
- Exploit SSRF vulnerabilities

**Correct Configuration:**
```bash
# /etc/hookprobe/mssp/django.env
DJANGO_ALLOWED_HOSTS=mssp.hookprobe.com,mssp.local,172.20.1.10
```

**Wrong Configuration (VULNERABLE):**
```bash
# DO NOT USE - Security vulnerability!
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,host.containers.internal,mssp.hookprobe.com
```

**Nginx must always pass the correct Host header:**
```nginx
proxy_set_header Host $host;  # Passes original request Host
```

### Internal vs External Access

| Access Type | Allowed Host | Security Level |
|-------------|--------------|----------------|
| External (Internet) | mssp.hookprobe.com | High (TLS + Host validation) |
| Internal (Admin) | mssp.local | Medium (VPN only) |
| Container-to-container | 172.20.x.x | Low (Pod network isolation) |

### Health Checks Exception

Health check endpoints bypass host validation by returning a simple response. The `/health/` endpoint returns `mssp-healthy` or `mssp-proxy-healthy` without requiring Host header validation.

## Troubleshooting

### 502 Bad Gateway

**Symptom:** mssp.hookprobe.com returns 502

**Cause:** nginx (rootless) can't reach Django (root) due to network namespace isolation

**Fix:**
1. Check if Django is on host network: `sudo podman inspect mssp-django --format '{{.HostConfig.NetworkMode}}'`
2. If not host, recreate: `sudo podman run --network host ...`
3. Update nginx upstream to use `host.containers.internal:8000`

### Container Can't Reach Database

**Symptom:** Django logs show "connection refused" to PostgreSQL

**Fix:**
1. Check Django is connected to pod-003-db network
2. Verify PostgreSQL IP: `sudo podman inspect mssp-postgres --format '{{.NetworkSettings.Networks}}'`
3. Update Django env: `POSTGRES_HOST=172.20.3.10`

### Mixed Namespace Issues

**Symptom:** Some containers work, others can't communicate

**Fix:**
1. List all containers by namespace:
   - `sudo podman ps -a` (root)
   - `podman ps -a` (rootless)
2. Choose ONE namespace for all MSSP containers
3. Migrate containers to chosen namespace

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/hookprobe/mssp/django.env` | Django environment variables |
| `/etc/hookprobe/secrets/mssp/` | Secrets (passwords, keys) |
| `/home/ubuntu/hookprobe-com/containers/proxy/nginx.conf` | Nginx routing config |
| `/var/lib/hookprobe/mssp/` | Persistent data volumes |

## Maintenance Commands

```bash
# Check all MSSP containers
sudo podman ps --filter "name=mssp"

# View container logs
sudo podman logs --tail 50 mssp-django

# Restart a service
sudo podman restart mssp-django

# Check network connectivity
sudo podman exec mssp-django curl -s http://172.20.3.10:5432 || echo "Can't reach postgres"

# Database backup
sudo podman exec mssp-postgres pg_dump -U hookprobe hookprobe > backup.sql
```
