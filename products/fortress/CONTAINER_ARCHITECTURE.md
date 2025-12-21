# Fortress Container Architecture Plan

**Version**: 1.0
**Status**: Proposed
**Date**: 2025-12-18

---

## Executive Summary

Fortress needs clean containerization to:
1. **Isolate ML/AI dependencies** (numpy, scipy, sklearn, torch) from host OS
2. **Eliminate system-wide pip installs** - everything in containers
3. **Enable reproducible deployments** across hardware platforms
4. **Simplify updates** - container images vs system packages

---

## Current State Analysis

### What Exists
| Component | Status | Notes |
|-----------|--------|-------|
| `Containerfile.web` | ✅ Complete | Flask app with gunicorn |
| `podman-compose.yml` | ✅ Complete | Orchestration defined |
| PostgreSQL container | ✅ Defined | postgres:15-alpine |
| Redis container | ✅ Defined | redis:7-alpine |

### What's Missing
| Component | Status | Impact |
|-----------|--------|--------|
| `Containerfile.agent` | ❌ Missing | Qsecbit agent can't containerize |
| `Containerfile.ml` | ❌ Missing | ML services run on host |
| `Containerfile.dnsxai` | ❌ Missing | DNS ML runs on host |
| System pip cleanup | ❌ Not done | Packages pollute host |

### ML/AI Dependencies Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PYTHON ML/AI DEPENDENCIES                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │   numpy     │───▶│   scipy     │───▶│  sklearn    │             │
│  │  (1.24.0+)  │    │  (1.10.0+)  │    │  (1.3.0+)   │             │
│  └──────┬──────┘    └─────────────┘    └──────┬──────┘             │
│         │                                      │                    │
│         ▼                                      ▼                    │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │                    USED BY                               │       │
│  │  • qsecbit.py (numpy, scipy)                            │       │
│  │  • unified_engine.py (numpy)                            │       │
│  │  • ml/classifier.py (numpy, sklearn)                    │       │
│  │  • energy_monitor.py (numpy)                            │       │
│  │  • dfs_intelligence.py (numpy, sklearn)                 │       │
│  │  • dnsXai/engine.py (numpy)                             │       │
│  │  • lstm_threat_detector.py (numpy, torch)               │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐                                │
│  │   torch     │    │   psutil    │                                │
│  │ (optional)  │    │  (5.9.0+)   │                                │
│  └─────────────┘    └─────────────┘                                │
│        │                   │                                        │
│        ▼                   ▼                                        │
│  lstm_threat_detector   energy_monitor                              │
│  (LSTM neural nets)     (power tracking)                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Proposed Container Groups

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FORTRESS CONTAINER POD                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    CONTAINER GROUP: DATA                          │   │
│  │  ┌─────────────┐  ┌─────────────┐                                │   │
│  │  │  postgres   │  │    redis    │                                │   │
│  │  │  (db)       │  │   (cache)   │                                │   │
│  │  │  Port: 5432 │  │  Port: 6379 │                                │   │
│  │  └─────────────┘  └─────────────┘                                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    CONTAINER GROUP: WEB                           │   │
│  │  ┌─────────────────────────────────────────────────────────────┐ │   │
│  │  │  fortress-web (Flask + Gunicorn)                            │ │   │
│  │  │  Port: 8443 (HTTPS)                                         │ │   │
│  │  │  Dependencies: flask, gunicorn, bcrypt, requests            │ │   │
│  │  │  NO ML LIBRARIES                                            │ │   │
│  │  └─────────────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    CONTAINER GROUP: ML/AI                         │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │   │
│  │  │ qsecbit-    │  │  dnsxai-    │  │   dfs-      │              │   │
│  │  │   agent     │  │   engine    │  │ intelligence│              │   │
│  │  │             │  │             │  │             │              │   │
│  │  │ numpy,scipy │  │ numpy       │  │ numpy,      │              │   │
│  │  │ sklearn     │  │ dnslib      │  │ sklearn     │              │   │
│  │  │ psutil      │  │             │  │             │              │   │
│  │  │             │  │             │  │             │              │   │
│  │  │ Port: 9090  │  │ Port: 5353  │  │ Port: 8050  │              │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │   │
│  │                                                                   │   │
│  │  ┌─────────────────────────────────────────────────────────────┐ │   │
│  │  │  lstm-trainer (scheduled job, not always running)           │ │   │
│  │  │  torch, numpy                                               │ │   │
│  │  └─────────────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    HOST OS SERVICES (NOT CONTAINERIZED)                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐             │
│  │   hostapd      │  │   dnsmasq      │  │   nftables     │             │
│  │   (WiFi AP)    │  │   (DHCP/DNS)   │  │   (firewall)   │             │
│  │   Hardware     │  │   Port 53      │  │   Kernel       │             │
│  └────────────────┘  └────────────────┘  └────────────────┘             │
│                                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐             │
│  │  OVS Bridge    │  │  LTE Manager   │  │  WAN Failover  │             │
│  │  (br-lan)      │  │  (ModemMgr)    │  │  (routing)     │             │
│  └────────────────┘  └────────────────┘  └────────────────┘             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Container Definitions

### 1. Data Group (Existing - No Changes)

Already defined in `podman-compose.yml`:
- **postgres**: `postgres:15-alpine`
- **redis**: `redis:7-alpine`

### 2. Web Group (Existing - Minor Updates)

**Containerfile.web** - Already exists, needs minor updates:
- Remove any ML dependencies
- Keep: Flask, Gunicorn, bcrypt, requests, psutil

### 3. ML/AI Group (NEW - To Be Created)

#### 3.1 Containerfile.agent (Qsecbit Agent)

```dockerfile
# Base ML image with numpy/scipy/sklearn
FROM python:3.11-slim-bookworm AS base

# System dependencies for numpy/scipy compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# ML dependencies
COPY requirements-ml.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements-ml.txt

# Qsecbit agent
COPY core/qsecbit/ /opt/hookprobe/core/qsecbit/
COPY products/fortress/qsecbit/ /opt/hookprobe/fortress/qsecbit/

USER 1000:1000
ENTRYPOINT ["python3", "/opt/hookprobe/fortress/qsecbit/fortress_agent.py"]
```

**requirements-ml.txt**:
```
numpy>=1.24.0,<2.0.0
scipy>=1.10.0,<2.0.0
scikit-learn>=1.3.0,<2.0.0
psutil>=5.9.0
```

#### 3.2 Containerfile.dnsxai (DNS ML Engine)

```dockerfile
FROM python:3.11-slim-bookworm

RUN pip install --no-cache-dir \
    numpy>=1.24.0 \
    dnslib>=0.9.0

COPY shared/dnsXai/ /opt/hookprobe/dnsXai/

EXPOSE 5353/udp
USER 1000:1000
ENTRYPOINT ["python3", "/opt/hookprobe/dnsXai/engine.py", "--listen", "0.0.0.0:5353"]
```

#### 3.3 Containerfile.dfs (DFS Intelligence)

```dockerfile
FROM python:3.11-slim-bookworm

RUN pip install --no-cache-dir \
    numpy>=1.24.0 \
    scikit-learn>=1.3.0 \
    flask>=2.3.0 \
    gunicorn>=21.0.0

COPY shared/wireless/ /opt/hookprobe/wireless/

EXPOSE 8050
USER 1000:1000
ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:8050", "dfs_api:app"]
```

#### 3.4 Containerfile.lstm (LSTM Trainer - Scheduled Job)

```dockerfile
FROM python:3.11-slim-bookworm

# PyTorch (CPU-only for edge devices)
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu \
    numpy>=1.24.0

COPY products/fortress/lib/lstm_threat_detector.py /opt/hookprobe/

USER 1000:1000
ENTRYPOINT ["python3", "/opt/hookprobe/lstm_threat_detector.py", "--train"]
```

---

## Updated podman-compose.yml

```yaml
version: "3.8"

services:
  # ============================================
  # DATA GROUP
  # ============================================
  postgres:
    image: postgres:15-alpine
    container_name: fortress-postgres
    environment:
      POSTGRES_DB: fortress
      POSTGRES_USER: fortress
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    secrets:
      - postgres_password
    networks:
      - fortress-data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fortress"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: fortress-redis
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - fortress-data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ============================================
  # WEB GROUP
  # ============================================
  web:
    image: localhost/fortress-web:latest
    build:
      context: ..
      dockerfile: containers/Containerfile.web
    container_name: fortress-web
    ports:
      - "8443:8443"
    environment:
      FLASK_ENV: production
      DATABASE_URL: postgresql://fortress@postgres:5432/fortress
      REDIS_URL: redis://redis:6379/0
    volumes:
      - web_data:/opt/hookprobe/fortress/data
      - web_logs:/var/log/hookprobe
      - /etc/hookprobe:/etc/hookprobe:ro
    secrets:
      - postgres_password
      - flask_secret
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - fortress-data
      - fortress-external
    healthcheck:
      test: ["CMD", "curl", "-fk", "https://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ============================================
  # ML/AI GROUP
  # ============================================
  qsecbit-agent:
    image: localhost/fortress-agent:latest
    build:
      context: ../..
      dockerfile: products/fortress/containers/Containerfile.agent
    container_name: fortress-qsecbit
    network_mode: host  # Required for traffic analysis
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - agent_data:/opt/hookprobe/fortress/data
      - /etc/hookprobe:/etc/hookprobe:ro
      - /sys/class/powercap:/sys/class/powercap:ro  # RAPL energy
    environment:
      QSECBIT_MODE: fortress
      DATABASE_URL: postgresql://fortress@localhost:5432/fortress
    depends_on:
      postgres:
        condition: service_healthy
    profiles:
      - full
    restart: unless-stopped

  dnsxai-engine:
    image: localhost/fortress-dnsxai:latest
    build:
      context: ../..
      dockerfile: products/fortress/containers/Containerfile.dnsxai
    container_name: fortress-dnsxai
    ports:
      - "5353:5353/udp"
    volumes:
      - dnsxai_data:/opt/hookprobe/dnsXai/data
      - /etc/hookprobe/dnsxai:/etc/hookprobe/dnsxai:ro
    networks:
      - fortress-data
    profiles:
      - full
    restart: unless-stopped

  dfs-intelligence:
    image: localhost/fortress-dfs:latest
    build:
      context: ../..
      dockerfile: products/fortress/containers/Containerfile.dfs
    container_name: fortress-dfs
    ports:
      - "8050:8050"
    volumes:
      - dfs_data:/opt/hookprobe/wireless/data
      - /etc/hookprobe/wireless:/etc/hookprobe/wireless:ro
    networks:
      - fortress-data
    profiles:
      - full
    restart: unless-stopped

  # LSTM trainer runs as scheduled job (not always-on)
  lstm-trainer:
    image: localhost/fortress-lstm:latest
    build:
      context: ../..
      dockerfile: products/fortress/containers/Containerfile.lstm
    container_name: fortress-lstm-trainer
    volumes:
      - ml_models:/opt/hookprobe/fortress/data/ml-models
      - agent_data:/opt/hookprobe/fortress/data:ro
    networks:
      - fortress-data
    profiles:
      - training  # Only run with: podman-compose --profile training up lstm-trainer
    restart: "no"

# ============================================
# NETWORKS
# ============================================
networks:
  fortress-data:
    driver: bridge
    ipam:
      config:
        - subnet: 10.250.100.0/24
  fortress-external:
    driver: bridge
    ipam:
      config:
        - subnet: 10.250.101.0/24

# ============================================
# VOLUMES
# ============================================
volumes:
  postgres_data:
  redis_data:
  web_data:
  web_logs:
  agent_data:
  dnsxai_data:
  dfs_data:
  ml_models:

# ============================================
# SECRETS
# ============================================
secrets:
  postgres_password:
    file: /etc/hookprobe/secrets/postgres_password
  flask_secret:
    file: /etc/hookprobe/secrets/flask_secret
```

---

## Migration Plan

### Phase 1: Create Missing Containerfiles (Week 1)

1. Create `Containerfile.agent` for Qsecbit
2. Create `Containerfile.dnsxai` for DNS ML
3. Create `Containerfile.dfs` for DFS intelligence
4. Create `Containerfile.lstm` for LSTM training
5. Create `requirements-ml.txt` with pinned versions

### Phase 2: Update install-container.sh (Week 1-2)

1. Remove system-wide pip installs for ML packages
2. Add container build steps during installation
3. Create systemd units to manage podman containers
4. Add `fortress-containers.service` to start all containers

### Phase 3: Integration Testing (Week 2)

1. Verify web container connects to PostgreSQL/Redis
2. Verify qsecbit-agent can analyze traffic with host network
3. Verify dnsxai-engine responds to DNS queries
4. Verify dfs-intelligence API works
5. Test LSTM training job execution

### Phase 4: Documentation & Cleanup (Week 2-3)

1. Update DEVELOPMENT_PLAN.md
2. Remove deprecated system pip install code
3. Add container troubleshooting guide
4. Create container update procedures

---

## Service Communication

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    INTER-CONTAINER COMMUNICATION                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐       │
│  │    web      │◀───────▶│  postgres   │◀───────▶│ qsecbit-    │       │
│  │  :8443      │  SQL    │   :5432     │   SQL   │   agent     │       │
│  └─────────────┘         └─────────────┘         └─────────────┘       │
│         │                                               │               │
│         │ HTTP/API                                      │ Unix Socket   │
│         ▼                                               ▼               │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐       │
│  │   redis     │         │  dnsxai-    │         │    dfs-     │       │
│  │   :6379     │         │   engine    │         │intelligence │       │
│  │   (cache)   │         │   :5353     │         │   :8050     │       │
│  └─────────────┘         └─────────────┘         └─────────────┘       │
│                                                                          │
│  All containers on fortress-data network (10.250.100.0/24)              │
│  Web additionally on fortress-external for HTTPS access                  │
│  qsecbit-agent uses host network for traffic capture                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    HOST ↔ CONTAINER COMMUNICATION                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  HOST OS                           CONTAINERS                            │
│  ────────                          ──────────                            │
│                                                                          │
│  ┌─────────────┐                   ┌─────────────┐                      │
│  │  dnsmasq    │───DNS Forward────▶│  dnsxai-    │                      │
│  │  :53        │    (port 5353)    │   engine    │                      │
│  └─────────────┘                   └─────────────┘                      │
│                                                                          │
│  ┌─────────────┐                   ┌─────────────┐                      │
│  │  hostapd    │───WiFi Config────▶│    dfs-     │                      │
│  │  (ctrl)     │    (API :8050)    │intelligence │                      │
│  └─────────────┘                   └─────────────┘                      │
│                                                                          │
│  ┌─────────────┐                   ┌─────────────┐                      │
│  │  nftables   │◀──Block Rules─────│ qsecbit-    │                      │
│  │  (kernel)   │   (nft command)   │   agent     │                      │
│  └─────────────┘                   └─────────────┘                      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Host OS Minimal Requirements

After containerization, the host OS only needs:

### Required Packages
```bash
# Container runtime
podman
podman-compose

# Network services (cannot containerize)
hostapd
dnsmasq
nftables
openvswitch-switch

# Hardware support
wireless-regdb
crda
usb-modeswitch  # LTE modems

# System utilities
systemd
iproute2
```

### NOT Required on Host
```bash
# These move to containers
python3-numpy      # → ML containers
python3-scipy      # → ML containers
python3-sklearn    # → ML containers
python3-flask      # → web container
python3-torch      # → lstm container
```

---

## Systemd Integration

### fortress-pod.service
```ini
[Unit]
Description=Fortress Container Pod
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/hookprobe/fortress/containers
ExecStart=/usr/bin/podman-compose up -d
ExecStop=/usr/bin/podman-compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

### fortress-pod-full.service (with ML)
```ini
[Unit]
Description=Fortress Container Pod (Full ML)
After=fortress-pod.service
Requires=fortress-pod.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/hookprobe/fortress/containers
ExecStart=/usr/bin/podman-compose --profile full up -d
ExecStop=/usr/bin/podman-compose --profile full down

[Install]
WantedBy=multi-user.target
```

### fortress-lstm-train.timer (Daily Training)
```ini
[Unit]
Description=Daily LSTM Model Training

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true
RandomizedDelaySec=1800

[Install]
WantedBy=timers.target
```

### fortress-lstm-train.service
```ini
[Unit]
Description=LSTM Model Training Job

[Service]
Type=oneshot
WorkingDirectory=/opt/hookprobe/fortress/containers
ExecStart=/usr/bin/podman-compose --profile training run --rm lstm-trainer
TimeoutStartSec=3600
```

---

## Benefits of This Architecture

| Benefit | Description |
|---------|-------------|
| **Isolation** | ML dependencies don't pollute host OS |
| **Reproducibility** | Same containers run on any hardware |
| **Updates** | Pull new container images, no apt/pip conflicts |
| **Security** | Containers run as non-root user |
| **Resource Control** | Can limit CPU/memory per container |
| **Rollback** | Keep previous image versions |
| **Development** | Test ML changes without affecting host |

---

## Next Steps

1. [ ] Review and approve this architecture plan
2. [ ] Create the 4 new Containerfiles
3. [ ] Update podman-compose.yml
4. [ ] Modify install-container.sh to build containers instead of pip install
5. [ ] Test on clean Debian 12 installation
6. [ ] Update documentation

---

*This architecture ensures Fortress runs cleanly with all ML/AI in containers while keeping essential network services on the host OS where they require hardware access.*
