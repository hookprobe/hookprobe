# Web Server Deployment Guide

**Choosing the Right Deployment Strategy for Your HookProbe Installation**

This guide helps you decide **when** and **how** to deploy the HookProbe web server based on your specific use case.

## 🤔 Decision Tree

```
Do you need a web interface?
├─ No → Skip web server installation
│        Use APIs for monitoring (Grafana, Qsecbit API)
│
└─ Yes → Continue
         │
         Where should the web server run?
         │
         ├─ On the edge device
         │  │
         │  ├─ Do you have sufficient resources? (16GB+ RAM)
         │  │  ├─ Yes → Edge Deployment (Podman)
         │  │  └─ No → Edge Headless + Cloud Centralized
         │  │
         │  └─ Single site or multiple sites?
         │     ├─ Single → Edge Deployment
         │     └─ Multiple (Service Provider) → Cloud Centralized
         │
         └─ On a separate server/cloud
            └─ Cloud Centralized (Multi-Tenant)
```

## 📊 Deployment Scenarios Comparison

| Scenario | Hardware | Use Case | Pros | Cons |
|----------|----------|----------|------|------|
| **Edge with UI** | 16GB+ RAM edge device | Home users, SMB | Full local control, no cloud dependency | Higher resource usage |
| **Edge Headless** | 8GB RAM edge device | Constrained hardware | Lower resource usage | No local web UI |
| **Cloud Centralized** | Dedicated cloud server | Service Provider managing 10+ sites | Centralized management, multi-tenant | Requires internet for management |
| **Hybrid** | Mix of both | Large Service Provider | Flexibility, redundancy | More complex setup |
| **Development** | Local workstation | Testing, development | Easy testing | Not for production |

## 🏠 Scenario 1: Edge Deployment (Full UI on Edge)

### When to Use

- **Home users** who want full local control
- **Small businesses** with a single location
- **Remote sites** with dedicated hardware (16GB+ RAM)
- **Privacy-conscious** deployments (no cloud dependency)

### Requirements

- **Hardware:** Intel N100/N200 (16GB RAM) or better
- **Network:** Static IP or DDNS for remote access
- **Resources:** Additional 2GB RAM + 10GB disk on top of base HookProbe

### Installation

```bash
cd install/addons/webserver
sudo ./setup-webserver-podman.sh edge
```

### Architecture

```
┌─────────────────────────────────┐
│  Edge Device (Single SBC)       │
│                                  │
│  ┌────────────────────────────┐ │
│  │ PODs 001-007 (Base)        │ │
│  │ - Security                 │ │
│  │ - Monitoring               │ │
│  │ - Database                 │ │
│  └────────────────────────────┘ │
│                                  │
│  ┌────────────────────────────┐ │
│  │ Web Server (Addon)         │ │
│  │ - Django CMS               │ │
│  │ - Admin Dashboard          │ │
│  │ - Local UI                 │ │
│  └────────────────────────────┘ │
└─────────────────────────────────┘
          ↓
    Users access locally
    (http://edge-ip/)
```

### Pros

- ✅ Full local control
- ✅ No cloud dependency
- ✅ All data stays on-premises
- ✅ Low latency for local access
- ✅ Works offline

### Cons

- ⚠️ Requires more RAM on edge device
- ⚠️ Management per device
- ⚠️ No centralized view for multiple sites

## ☁️ Scenario 2: Cloud Centralized (Service Provider Multi-Tenant)

### When to Use

- **Service Provider providers** managing multiple customer sites
- **Enterprise** with many branch offices
- **Service providers** offering managed security
- **Centralized management** of 10+ edge devices

### Requirements

- **Cloud Server:** 4+ cores, 8GB+ RAM, 50GB+ disk
- **Edge Devices:** HookProbe base installation only (no web server)
- **Network:** VPN or secure connection between edge and cloud

### Installation

**On Cloud Server:**

```bash
cd install/addons/webserver

# Configure for cloud
export DEPLOYMENT_TYPE=cloud
export MULTITENANT_ENABLED=true
export POSTGRES_HOST=10.100.1.10  # Cloud PostgreSQL
export REDIS_HOST=10.100.1.11     # Cloud Redis

sudo ./setup-webserver-podman.sh cloud
```

**On Each Edge Device:**

```bash
# Only install base HookProbe (no web server)
sudo ./install.sh
# Select: 1) Edge Deployment

# Skip web server installation
# APIs will report to cloud backend
```

### Architecture

```
┌─────────────────────────────────┐
│  Cloud Server (Centralized)     │
│                                  │
│  ┌────────────────────────────┐ │
│  │ Apache Doris (Multi-Tenant)│ │
│  │ - Customer A data          │ │
│  │ - Customer B data          │ │
│  │ - Customer C data          │ │
│  └────────────────────────────┘ │
│                                  │
│  ┌────────────────────────────┐ │
│  │ Web Server                 │ │
│  │ - Multi-tenant UI          │ │
│  │ - Centralized Dashboard    │ │
│  │ - All sites management     │ │
│  └────────────────────────────┘ │
└─────────────────────────────────┘
       ▲          ▲          ▲
       │          │          │
    ┌──┘          │          └──┐
    │             │             │
┌───┴───┐    ┌───┴───┐    ┌───┴───┐
│Edge A │    │Edge B │    │Edge C │
│(Base) │    │(Base) │    │(Base) │
└───────┘    └───────┘    └───────┘
  Customer    Customer     Customer
     A            B            C
```

### Pros

- ✅ Centralized management for all sites
- ✅ Lower resource usage on edge devices
- ✅ Multi-tenant isolation
- ✅ Easier updates (single location)
- ✅ Cross-customer threat intelligence

### Cons

- ⚠️ Requires cloud infrastructure
- ⚠️ Internet dependency for management
- ⚠️ Data leaves customer premises (compliance consideration)

## 🔀 Scenario 3: Hybrid (Edge + Cloud)

### When to Use

- **Large Service Provider** with mix of customer requirements
- **High-value customers** who want local UI + cloud management
- **Redundancy** requirements
- **Flexible deployment** options

### Installation

**On Cloud Server:**

```bash
# Install cloud web server (as in Scenario 2)
sudo ./setup-webserver-podman.sh cloud
```

**On High-Value Edge Devices:**

```bash
# Install base + web server
sudo ./install.sh
cd install/addons/webserver
sudo ./setup-webserver-podman.sh edge

# Configure dual reporting (edge UI + cloud backend)
```

**On Standard Edge Devices:**

```bash
# Install base only (report to cloud)
sudo ./install.sh
```

### Architecture

```
┌─────────────────────────────────┐
│  Cloud Server (Aggregation)     │
│  - All customer data            │
│  - Centralized dashboards       │
└─────────────────────────────────┘
       ▲          ▲          ▲
       │          │          │
    ┌──┴──┐    ┌──┴──┐   ┌──┴──┐
    │     │    │     │   │     │
┌───┴───┐│ ┌──┴──┐  │ ┌─┴────┐│
│Edge A ││ │Edge B│  │ │Edge C││
│+ Web  ││ │(Base)│  │ │+ Web ││
└───────┘│ └──────┘  │ └──────┘│
         │           │         │
    High-Value    Standard  High-Value
    (Local+Cloud) (Cloud)   (Local+Cloud)
```

### Pros

- ✅ Maximum flexibility
- ✅ Both local and centralized access
- ✅ Redundancy for critical sites
- ✅ Customer choice (local vs cloud)

### Cons

- ⚠️ More complex to manage
- ⚠️ Higher total resource usage
- ⚠️ Potential data duplication

## 🛠️ Scenario 4: Edge Headless (API-Only)

### When to Use

- **Resource-constrained** edge devices (Raspberry Pi 4, 8GB)
- **Minimal overhead** required
- **API-driven** monitoring (Grafana only)
- **No need for web UI**

### Installation

```bash
# Install base HookProbe only
sudo ./install.sh

# Do NOT install web server addon

# Access services via APIs:
# - Grafana: http://edge-ip:3000
# - Qsecbit API: http://edge-ip:8888
# - Prometheus metrics: http://edge-ip:9090
```

### Architecture

```
┌─────────────────────────────────┐
│  Edge Device (Headless)         │
│                                  │
│  ┌────────────────────────────┐ │
│  │ PODs 001-007 (Base)        │ │
│  │ - Security ✓               │ │
│  │ - Monitoring ✓             │ │
│  │ - Database ✓               │ │
│  └────────────────────────────┘ │
│                                  │
│  NO Web Server                   │
│                                  │
│  APIs Only:                      │
│  - Qsecbit API (8888)           │
│  - Grafana (3000)               │
│  - Prometheus (9090)            │
└─────────────────────────────────┘
```

### Pros

- ✅ Minimum resource usage
- ✅ Works on 8GB RAM devices
- ✅ Faster installation
- ✅ Lower attack surface

### Cons

- ⚠️ No web-based management
- ⚠️ Grafana only for visualization
- ⚠️ No blog/CMS features
- ⚠️ No Service Provider device management UI

## 💻 Scenario 5: Development/Testing

### When to Use

- **Development** environment
- **Testing** new features
- **CI/CD** pipelines
- **Learning** HookProbe

### Installation

```bash
cd install/addons/webserver

# Use standalone mode
sudo ./setup-webserver-podman.sh standalone

# Or for development without containers:
cd ../../../src/web
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8000
```

### Pros

- ✅ Easy setup
- ✅ Fast iteration
- ✅ No production constraints

### Cons

- ⚠️ Not suitable for production
- ⚠️ No SSL/security hardening
- ⚠️ SQLite database option

## 🎯 Recommendations by Use Case

### Home User (Single Site)

**Recommended:** Edge with UI (Podman)

```bash
cd install/addons/webserver
sudo ./setup-webserver-podman.sh edge
```

**Why:** Full local control, easy to use, works offline.

---

### Small Business (1-3 Sites)

**Recommended:** Edge with UI per site

```bash
# On each site
cd install/addons/webserver
sudo ./setup-webserver-podman.sh edge
```

**Why:** Simple management, no cloud costs, data stays local.

---

### Service Provider (10+ Customer Sites)

**Recommended:** Cloud Centralized

```bash
# On cloud server
cd install/addons/webserver
sudo ./setup-webserver-podman.sh cloud

# On each edge (base only)
sudo ./install.sh
```

**Why:** Centralized management, multi-tenant, scalable.

---

### Enterprise (Multiple Branches)

**Recommended:** Hybrid (Cloud + Selective Edge UI)

```bash
# Cloud for centralized view
sudo ./setup-webserver-podman.sh cloud

# Edge UI for HQ and critical sites
sudo ./setup-webserver-podman.sh edge

# Base only for standard branches
sudo ./install.sh
```

**Why:** Flexibility, redundancy, choice per site.

---

### Budget/Learning (Limited Resources)

**Recommended:** Edge Headless (API-Only)

```bash
# Base installation only
sudo ./install.sh

# Access via Grafana
http://edge-ip:3000
```

**Why:** Minimum cost, runs on 8GB RAM, core features work.

## 📝 Installation Checklist

### Pre-Installation

- [ ] Decide on deployment scenario
- [ ] Check hardware requirements
- [ ] Verify HookProbe base is running
- [ ] Test PostgreSQL connectivity
- [ ] Test Redis connectivity
- [ ] Generate strong passwords

### Post-Installation

- [ ] Create Django superuser
- [ ] Change Django secret key
- [ ] Update ALLOWED_HOSTS
- [ ] Configure firewall
- [ ] Enable SSL/HTTPS (production)
- [ ] Test web interface access
- [ ] Configure email (optional)
- [ ] Set up backups

## 🆘 Need Help Deciding?

Ask yourself:

1. **How many sites?**
   - Single → Edge with UI
   - Multiple → Cloud Centralized

2. **How much RAM?**
   - 8GB → Headless (no web)
   - 16GB+ → Full web server

3. **Data location requirements?**
   - Must stay local → Edge
   - Can be cloud → Cloud Centralized

4. **Budget?**
   - Tight → Headless or single edge
   - Flexible → Cloud or hybrid

5. **Technical expertise?**
   - Beginner → Edge with UI
   - Advanced → Any scenario

## 📚 Additional Resources

- [Web Server README](README.md) - Complete feature documentation
- [Quick Start Guide](QUICKSTART.md) - 5-minute setup
- [Main HookProbe Docs](../../../README.md) - Overall project
- [Cloud Deployment Guide](../../cloud/README.md) - Cloud backend setup

---

**Still unsure?** Start with **Edge Headless** (base only), then add web server later if needed. The beauty of the post-installation addon approach is you can always deploy it later!
