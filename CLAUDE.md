# CLAUDE.md - AI Assistant Guide for HookProbe

**Version**: 5.0
**Last Updated**: 2025-11-22
**Purpose**: Comprehensive guide for AI assistants working with the HookProbe codebase

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Codebase Structure](#codebase-structure)
- [Architecture Fundamentals](#architecture-fundamentals)
- [Development Workflows](#development-workflows)
- [Key Conventions](#key-conventions)
- [Common Tasks](#common-tasks)
- [Security Considerations](#security-considerations)
- [Testing Guidelines](#testing-guidelines)
- [Important Files Reference](#important-files-reference)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Project Overview

### What is HookProbe?

HookProbe is a **containerized cybersecurity platform** built for Single Board Computers (SBCs) and edge infrastructure. It provides enterprise-grade security capabilities through AI-driven threat detection and automated response systems.

**Project Type**: Infrastructure-as-Code / Security Operations Platform
**Primary Language**: Bash (deployment scripts), Python (AI/security logic)
**Deployment**: Podman containers with OVS networking
**Supported OS**:
- **RHEL-based**: RHEL 10, Fedora 40+, CentOS Stream 9+, Rocky Linux, AlmaLinux
- **Debian-based**: Debian 12+, Ubuntu 22.04+/24.04+
**Architectures**: x86_64 (Intel/AMD), ARM64 (Raspberry Pi, Rockchip SBCs)
**License**: MIT (v5.0+), transitioning from GPL

### Key Capabilities

1. **AI-Powered Threat Detection**: Qsecbit algorithm for real-time security analysis
2. **Automated Response**: Kali Linux on-demand mitigation
3. **Multi-Layer Defense**: WAF, IDS/IPS, honeypots, behavioral analysis
4. **Complete Observability**: Grafana, VictoriaMetrics, Loki stack
5. **Zero Trust Network**: PSK-encrypted VXLAN, OpenFlow ACLs, L2 hardening
6. **Optional Automation**: n8n workflow engine (POD 008)

### Critical Context for AI Assistants

⚠️ **This is NOT a traditional software application**. It is:
- Infrastructure deployment automation
- Security orchestration platform
- Network configuration system
- Container orchestration setup

**DO NOT** treat this like a web app, API service, or typical software project.

### Platform Detection and Compatibility

**HookProbe v5.0** automatically detects and configures itself based on:

1. **Operating System**: RHEL-based (dnf) vs Debian-based (apt)
2. **Architecture**: x86_64 vs ARM64
3. **Hardware Platform**: Intel N100, Raspberry Pi, Generic SBC, Virtual Machine
4. **NIC Capabilities**: XDP-hw, XDP-drv, or XDP-skb mode selection

**Deployment Script** (`setup.sh`) performs comprehensive detection at startup:
- OS family detection (via `/etc/os-release`)
- Hardware platform identification (CPU model, SBC detection)
- Virtualization detection (KVM, VMware, LXC, Docker, etc.)
- NIC driver detection and XDP capability assessment
- Platform-specific package installation (dnf vs apt)

**Supported Deployment Targets**:
- **Physical Hardware**: Intel N100 Mini PCs, Raspberry Pi 4/5, Rockchip SBCs, x86_64 desktops
- **Virtual Machines**: KVM, VMware, VirtualBox, Proxmox VMs
- **Cloud**: AWS, Azure, GCP (with appropriate OS)

**Unsupported**:
- ARMv7 (32-bit ARM) - Use ARM64 (ARMv8) instead
- Docker containers (networking conflicts with OVS)
- LXC containers (networking limitations)

---

## 📁 Codebase Structure

```
hookprobe/
├── Scripts/
│   ├── autonomous/
│   │   ├── install/
│   │   │   ├── setup.sh              # MAIN DEPLOYMENT SCRIPT
│   │   │   ├── network-config.sh     # NETWORK & SERVICE CONFIGURATION
│   │   │   ├── uninstall.sh          # Cleanup script
│   │   │   ├── kali-response-scripts.sh  # Automated response logic
│   │   │   ├── n8n_setup.sh          # Optional POD 008 deployment
│   │   │   ├── n8n_network-config.sh # n8n configuration
│   │   │   ├── README.md             # Deployment guide
│   │   │   └── checklist.md          # Pre/post deployment checklist
│   │   └── qsecbit/
│   │       ├── qsecbit.py            # AI THREAT ANALYSIS ENGINE + XDP/eBPF
│   │       └── README.md             # Qsecbit documentation
│   ├── backend/
│   │   └── install/
│   │       ├── backend-setup.sh      # MSSP cloud backend deployment
│   │       ├── backend-network-config.sh  # Multi-tenant configuration
│   │       └── backend-uninstall.sh  # Cloud backend cleanup
│   ├── honeypot/
│   │   ├── attack-mitigation-orchestrator.sh
│   │   ├── mitigation-maintenance.sh
│   │   ├── mitigation-config.conf
│   │   └── README.md
│   └── webApp/
│       └── templates/
│           ├── qsecbit.py            # Web interface version
│           └── qsecbit.html
├── Documents/
│   ├── backend/
│   │   └── README.md                 # MSSP cloud backend guide
│   ├── SecurityMitigationPlan.md     # Detailed security architecture
│   ├── ClickHouse-Integration-Analysis.md  # OLAP database integration guide
│   ├── ClickHouse-Quick-Start.md     # Quick deployment guide
│   └── autonomous/
│       └── ai-business.md            # AI/automation context
├── n8n/
│   ├── README.md                     # n8n integration guide
│   ├── AI-blogging-workflow.md       # Workflow automation examples
│   ├── integration-checklist.md      # Validation checklist
│   ├── n8n_setup.sh                  # Deployment script (copy)
│   ├── n8n_uninstall.sh
│   └── n8n_network-config.sh         # Configuration (copy)
├── LTE/
│   └── README.md                     # LTE/5G connectivity guide
├── images/
│   └── *.png                         # Documentation images
├── README.md                         # MAIN DOCUMENTATION
├── CONTRIBUTING.md                   # Contribution guidelines
├── SECURITY.md                       # Security policy
├── CLAUDE.md                         # AI ASSISTANT GUIDE (this file)
├── CHANGELOG.md                      # Version history
├── LICENSE                           # MIT License
├── requirements.txt                  # Python dependencies
├── 3rd-party-licenses.md            # Dependency licenses
└── hookprobe-r&d.md                 # R&D roadmap

```

### File Type Distribution

| Type | Purpose | Key Files |
|------|---------|-----------|
| **Bash Scripts** | Deployment automation | `setup.sh`, `uninstall.sh`, `network-config.sh`, `kali-response-scripts.sh` |
| **Python** | AI/security logic | `qsecbit.py` |
| **Markdown** | Documentation | `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, all `*/README.md` |
| **Config** | Service configuration | `*.conf`, `network-config.sh` |

**NO TypeScript, JavaScript, Java, or traditional application code.**

---

## 🏗️ Architecture Fundamentals

### POD-Based Architecture

HookProbe uses a **7-POD containerized architecture** (+ optional 8th POD for automation):

| POD | VNI | Network | Purpose | Key Services |
|-----|-----|---------|---------|--------------|
| **001** | 201 | 10.200.1.0/24 | Web DMZ | Django CMS, Nginx, NAXSI WAF, ModSecurity, Cloudflare Tunnel |
| **002** | 202 | 10.200.2.0/24 | IAM/Auth | Keycloak, PostgreSQL |
| **003** | 203 | 10.200.3.0/24 | Database | PostgreSQL, NFS, RADIUS |
| **004** | 204 | 10.200.4.0/24 | Cache | Redis, Valkey |
| **005** | 205 | 10.200.5.0/24 | Monitoring | Grafana, VictoriaMetrics, VictoriaLogs, Vector, node_exporter |
| **006** | 206 | 10.200.6.0/24 | Security | Zeek, Snort3, Qsecbit |
| **007** | 207 | 10.200.7.0/24 | Honeypot/Response | Honeypots, Kali Linux, Mitigation Engine |
| **008** | 208 | 10.200.8.0/24 | Automation (Optional) | n8n, PostgreSQL, Redis, MCP Server |

### Network Architecture

```
┌─────────────────────┐
│   Physical Host     │
│   (Intel N100)      │
│   eth0: 192.168.x.x │
└──────────┬──────────┘
           │
    ┌──────▼──────┐
    │ OVS Bridge  │
    │ qsec-bridge │
    │ 10.200.0.1  │
    └──────┬──────┘
           │
    ┌──────▼──────────┐
    │ PSK VXLAN (VNI) │
    │ Encrypted Layer │
    └──────┬──────────┘
           │
    ┌──────▼──────────────┐
    │ OpenFlow ACLs       │
    │ L2 Anti-Spoof       │
    │ Firewall (nftables) │
    └──────┬──────────────┘
           │
    ┌──────┴────────┬─────────┬─────────┐
    │               │         │         │
┌───▼───┐      ┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│POD 001│      │POD 002│ │POD 003│ │POD 004│
│  DMZ  │ ...  │  IAM  │ │  DB   │ │ Cache │ ...
└───────┘      └───────┘ └───────┘ └───────┘
```

### Six-Layer Security Model

1. **Layer 1 (Kernel)**: XDP/eBPF for DDoS mitigation
2. **Layer 2 (Network)**: VXLAN encryption + OVS ACLs
3. **Layer 3 (Firewall)**: nftables with default-deny
4. **Layer 4 (Application)**: WAF (NAXSI/ModSecurity)
5. **Layer 5 (Detection)**: IDS/IPS (Zeek/Snort3/Suricata)
6. **Layer 6 (AI Response)**: Qsecbit + Kali Linux automation

### Qsecbit AI Threat Analysis

**Qsecbit (Quantum Security Bit)** is the core AI threat detection engine.

**Location**: `Scripts/autonomous/qsecbit/qsecbit.py`

**Algorithm Components**:
- **System Drift** (30%): Mahalanobis distance from baseline telemetry
- **Attack Probability** (30%): ML-predicted threat level
- **Classifier Decay** (20%): Rate of change in ML confidence
- **Quantum Drift** (20%): System entropy deviation

**RAG Status (Red/Amber/Green)**:
- **GREEN** (< 0.45): Normal operation
- **AMBER** (0.45-0.70): Warning - Kali Linux spins up
- **RED** (> 0.70): Critical - Automated response engaged

**Automated Actions**:
- Update WAF rules
- Block attacker IPs
- Capture forensics
- Generate incident reports
- Email alerts to qsecbit@hookprobe.com

### XDP/eBPF DDoS Mitigation

**Qsecbit v5.0** includes kernel-level DDoS mitigation via XDP (eXpress Data Path):

**XDP Modes and Layers**:

XDP operates at different layers of the network stack, providing varying levels of performance:

| **Mode** | **Where it runs** | **Kernel bypass** | **Layer** | **Performance** | **Notes** |
|----------|------------------|-------------------|-----------|-----------------|-----------|
| **XDP-hw** | NIC hardware ASIC | Full | Layer 0 | Ultra-fast | Rare; requires programmable NICs (Mellanox SmartNIC, Intel IPU) |
| **XDP-drv** | NIC driver | Full | Layer 1 | Fastest practical | Native driver mode, requires driver support |
| **XDP-skb** | Generic SKB layer | Partial | Layer 1.5 | Moderate | Universal fallback, works on all NICs |

**Key Differences**:
- **XDP-hw (Layer 0)**: Packet processing happens directly in NIC hardware ASIC before reaching CPU. Extremely rare, requires specialized SmartNICs.
- **XDP-drv (Layer 1)**: Packet processing in NIC driver before Linux kernel network stack. Full kernel bypass. Requires XDP-capable driver.
- **XDP-skb (Layer 1.5)**: Packet processing after kernel allocates socket buffers (SKBs). Partial bypass. Universal compatibility.

**Features**:
- **Automatic NIC Detection**: Detects primary interface and driver capabilities
- **Intelligent Mode Selection**: XDP-DRV (native) for capable NICs, XDP-SKB (generic) fallback
- **Rate Limiting**: 1000 packets/sec per source IP
- **Dynamic IP Blocking**: Real-time attacker blacklisting at kernel level
- **Protocol Flood Detection**: TCP SYN, UDP, ICMP monitoring
- **Malformed Packet Filtering**: Automatic drop of invalid packets
- **Real-Time Statistics**: Total packets, drops, floods tracked and stored

**Enable XDP** (environment variable):
```bash
export XDP_ENABLED=true
```

**Supported NICs** (See NIC Compatibility Matrix below for complete list):
- **XDP-DRV (Layer 1)**: Intel I211/I226, X710, E810, Mellanox ConnectX-4/5/6/7
- **XDP-SKB (Layer 1.5)**: Raspberry Pi (bcmgenet), Realtek (r8152, r8169), Intel X520
- **XDP-HW (Layer 0)**: Mellanox ConnectX-5/6/7, BlueField-2/3 SmartNICs

### NIC Compatibility Matrix

**Hardware Requirements for Optimal XDP Performance**:

| **Platform** | **NIC Model** | **Driver** | **XDP-SKB** | **XDP-DRV** | **XDP-HW** | **Max Throughput** | **Recommended** |
|-------------|---------------|------------|-------------|-------------|------------|-------------------|----------------|
| **Raspberry Pi 4/5** | Broadcom SoC | bcmgenet | ✅ | ❌ | ❌ | 1 Gbps | ⚠️ Development only |
| **Raspberry Pi** | Realtek USB | r8152 | ✅ | ❌ | ❌ | 1 Gbps | ⚠️ Limited performance |
| **Desktop** | Realtek PCIe | r8169 | ✅ | ❌ | ❌ | 2.5 Gbps | ⚠️ Not for production |
| **Intel N100** | **I211** | **igb** | ✅ | ✅ | ❌ | **1 Gbps** | ✅ **Entry-level edge** |
| **Intel N100** | **I226** | **igc** | ✅ | ✅ | ❌ | **2.5 Gbps** | ✅ **Best value edge** |
| **Intel Server** | X520 (82599) | ixgbe | ✅ | ❌ | ❌ | 10 Gbps | ⚠️ AF_XDP only |
| **Intel Server** | **X710** | **i40e** | ✅ | ✅ | ❌ | **40 Gbps** | ✅ **Cloud backend** |
| **Intel Server** | **E810** | **ice** | ✅ | ✅ | ❌ | **100 Gbps** | ✅ **Enterprise** |
| **Mellanox** | **ConnectX-3** | **mlx4_en** | ✅ | ❌ | ❌ | **40 Gbps** | ✅ **Cloud backend** |
| **Mellanox** | **ConnectX-4/5/6/7** | **mlx5_core** | ✅ | ✅ | ✅ | **200 Gbps** | ✅ **Gold standard** |
| **Mellanox SmartNIC** | **BlueField-2/3** | **mlx5_core** | ✅ | ✅ | ✅ | **400 Gbps** | ✅ **Enterprise** |

**Legend**:
- ✅ **Supported** / **Recommended**
- ❌ **Not supported**
- ⚠️ **Limited** (SKB mode only, higher CPU usage)

**XDP-HW Note**: Hardware offload (XDP-hw) is extremely rare and only supported by:
- Mellanox ConnectX-5/6/7 (limited offload capabilities)
- Mellanox BlueField-2/3 SmartNICs (full programmable pipeline)
- Intel IPU (Infrastructure Processing Unit)
- Netronome Agilio SmartNICs

For 99% of deployments, **XDP-drv (Layer 1)** is the fastest practical mode.

**Hardware Recommendations**:

1. **Budget Edge Deployment** (< $300):
   - **SBC**: Intel N100 (8GB RAM)
   - **NIC**: Intel I226-V (built-in, 2.5Gbps)
   - **XDP Mode**: XDP-DRV ✅
   - **Performance**: 2.5 Gbps line rate filtering

2. **Production Edge** ($300-$1000):
   - **Option A**: Mini PC with Intel I211/I226
   - **Option B**: Raspberry Pi 5 + USB adapter (⚠️ SKB only)
   - **XDP Mode**: XDP-DRV ✅ (Option A), XDP-SKB (Option B)

3. **Cloud Backend** ($2000+):
   - **Server**: Dell/HP with Intel X710 or Mellanox ConnectX-5
   - **XDP Mode**: XDP-DRV ✅ + Hardware Offload
   - **Performance**: 40-100 Gbps line rate

⚠️ **Important Notes**:
- **Raspberry Pi**: Only supports XDP-SKB (software mode). For production DDoS mitigation at scale, use Intel N100 with I226 NIC.
- **Intel N100**: Best value for edge deployment. Built-in I226 NIC supports full XDP-DRV mode.
- **Mellanox ConnectX**: Enterprise-grade. Full XDP-DRV, AF_XDP, and hardware offload for maximum performance.

**See**: `Scripts/autonomous/qsecbit/README.md` for complete XDP/eBPF documentation.

---

## 🔧 Development Workflows

### Primary Workflow: Infrastructure Changes

**HookProbe development is NOT traditional software development.** Changes typically involve:

1. **Network Configuration** (`network-config.sh`)
2. **Deployment Logic** (`setup.sh`)
3. **Security Rules** (OpenFlow, nftables, WAF)
4. **AI Logic** (`qsecbit/qsecbit.py`)
5. **Response Scripts** (`kali-response-scripts.sh`)
6. **Documentation** (Markdown files)

### Making Changes to Deployment Scripts

**IMPORTANT**: Always test deployment changes in a **clean environment**.

```bash
# 1. Make changes to setup.sh or network-config.sh
nano Scripts/autonomous/install/setup.sh

# 2. Test deployment (requires root)
cd Scripts/autonomous/install/
sudo ./setup.sh

# 3. Verify all PODs are running
podman pod ps
podman ps -a

# 4. Check service health
curl http://localhost/admin          # Django
curl http://localhost:3000           # Grafana
curl http://localhost:8888/health    # Qsecbit

# 5. Test functionality
# - Access Grafana dashboards
# - Check security monitoring
# - Verify network isolation

# 6. Clean up test environment
sudo ./uninstall.sh

# 7. Verify complete removal
podman pod ps  # Should be empty
ovs-vsctl show # Should show minimal config
```

### Making Changes to Qsecbit Algorithm

**Location**: `Scripts/autonomous/qsecbit/qsecbit.py`

**Testing Workflow**:

```bash
# 1. Modify qsecbit.py
nano Scripts/autonomous/qsecbit/qsecbit.py

# 2. Run unit tests (if available)
cd Scripts/autonomous/qsecbit/
python3 -m pytest tests/

# 3. Test with synthetic data
python3 qsecbit.py --test

# 4. Deploy and test in container
podman build -t qsecbit:test -f Containerfile.qsecbit .
podman run --rm qsecbit:test

# 5. Monitor real-world performance
# - Check Grafana "Qsecbit Analysis" dashboard
# - Review alerts in Loki logs
# - Verify RAG status accuracy
# - Monitor XDP statistics (if enabled)
```

### Making Documentation Changes

```bash
# 1. Edit markdown files
nano README.md

# 2. Verify markdown syntax
markdownlint README.md

# 3. Check links
markdown-link-check README.md

# 4. Preview (if possible)
# Use VS Code, GitHub preview, or grip

# 5. Commit with clear message
git add README.md
git commit -m "docs: update deployment instructions for LTE setup"
```

### Git Workflow

**Branch Naming Convention**:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `security/` - Security enhancements
- `refactor/` - Code refactoring

**Commit Message Format**:
```
type(scope): brief description

Detailed explanation (if needed)

Fixes: #123
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

**Example Commits**:
```bash
git commit -m "feat(security): add XDP rate limiting for DNS"
git commit -m "fix(setup): correct PostgreSQL connection string in POD 003"
git commit -m "docs(readme): add troubleshooting section for n8n integration"
git commit -m "security(waf): update ModSecurity rules to CRS 4.0"
```

---

## 📝 Key Conventions

### Bash Script Conventions

**Required Headers**:
```bash
#!/bin/bash
#
# script-name.sh - Brief description
# Version: X.Y.Z
# License: MIT
#

set -e  # Exit on error
set -u  # Exit on undefined variable
```

**Variable Naming**:
- `UPPERCASE_WITH_UNDERSCORES` for configuration variables
- `lowercase_with_underscores` for local variables
- Descriptive names (no abbreviations unless obvious)

**Good Examples**:
```bash
POSTGRES_PASSWORD="..."
POD_NAME="hookprobe-web-dmz"
container_ip="10.200.1.10"
```

**Bad Examples**:
```bash
pp="..."           # Too cryptic
pod="..."          # Too generic
ctr_ip="..."       # Unnecessary abbreviation
```

**Function Conventions**:
```bash
# Use descriptive function names
create_vxlan_tunnel() {
    local vni=$1
    local remote_ip=$2

    # Implementation
}

# Add comments for complex logic
# This function creates encrypted VXLAN tunnel with PSK
setup_secure_networking() {
    # ...
}
```

**Error Handling**:
```bash
# Check command success
if ! podman pod create --name "$POD_NAME"; then
    echo "ERROR: Failed to create pod $POD_NAME"
    exit 1
fi

# Verify file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file not found: $CONFIG_FILE"
    exit 1
fi
```

### Python Conventions (Qsecbit)

**Follow PEP 8** with these specifics:

```python
#!/usr/bin/env python3
"""
Module docstring explaining purpose.

Author: Name
License: MIT
"""

import os
from typing import Optional, Dict, List
import numpy as np

# Constants in UPPER_CASE
DEFAULT_THRESHOLD = 0.45
API_ENDPOINT = "http://localhost:8888"


class QsecbitAnalyzer:
    """Class-level docstring."""

    def __init__(self, config: Dict):
        """Initialize with configuration."""
        self.config = config

    def analyze_threat(self, data: Dict) -> Optional[float]:
        """
        Analyze threat data and return score.

        Args:
            data: Telemetry data dictionary

        Returns:
            Threat score between 0.0 and 1.0, or None if error
        """
        try:
            # Implementation
            pass
        except Exception as e:
            print(f"Error analyzing data: {e}")
            return None
```

**Type Hints**: Always use type hints for function signatures
**Docstrings**: Google-style docstrings for all public functions
**Error Handling**: Explicit try/except with meaningful messages

### Configuration File Conventions

**network-config.sh Structure**:

1. **Physical Host Config** (Lines 10-20)
2. **OVS Bridge Config** (Lines 20-30)
3. **VXLAN Encryption** (Lines 30-40)
4. **VNI Definitions** (Lines 40-50)
5. **IP Subnets** (Lines 50-200)
6. **Container Images** (Lines 200-250)
7. **Service Credentials** (Lines 250-300)
8. **Feature Flags** (Lines 300-350)

**Always include**:
- Section headers with `# ===...===`
- Inline comments for non-obvious settings
- Default values with CHANGE_ME markers
- Examples for complex configurations

### Documentation Conventions

**Markdown Style**:
- Use ATX-style headers (`#`, `##`, not underlines)
- Maximum line length: 100 characters (exceptions for links/tables)
- Use fenced code blocks with language specifiers
- Include table of contents for files > 200 lines
- Add horizontal rules (`---`) between major sections

**Code Examples**:
- Always include language identifier: ` ```bash `, ` ```python `
- Show complete, working examples
- Include expected output when helpful
- Add comments for complex commands

**Links**:
- Use relative links for internal documentation
- Use absolute URLs for external resources
- Verify all links work before committing

---

## 🔨 Common Tasks

### Task 1: Add a New Service to a POD

**Example**: Add Elasticsearch to POD 005 (Monitoring)

```bash
# 1. Edit network-config.sh
nano Scripts/autonomous/install/network-config.sh

# Add IP allocation
IP_ELASTICSEARCH="10.200.5.15"

# Add container image
IMAGE_ELASTICSEARCH="docker.io/elasticsearch:8.11.0"

# 2. Edit setup.sh
nano Scripts/autonomous/install/setup.sh

# Find POD 005 creation section (search for "POD 005")
# Add container creation:

echo "Creating Elasticsearch container..."
podman run -d \
  --name hookprobe-monitoring-elasticsearch \
  --pod hookprobe-pod-005-monitoring \
  --ip "$IP_ELASTICSEARCH" \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -v elasticsearch-data:/usr/share/elasticsearch/data \
  "$IMAGE_ELASTICSEARCH"

# 3. Add OpenFlow rules (if needed for inter-POD communication)
# 4. Add firewall rules (if exposing to other PODs)
# 5. Update documentation
# 6. Test deployment
```

### Task 2: Modify Qsecbit Thresholds

```bash
# Edit qsecbit.py configuration
nano Scripts/autonomous/qsecbit/qsecbit.py

# Modify QsecbitConfig dataclass:
@dataclass
class QsecbitConfig:
    # Change thresholds
    amber_threshold: float = 0.40  # Was 0.45
    red_threshold: float = 0.65    # Was 0.70

    # Adjust component weights
    alpha: float = 0.35   # System drift (was 0.30)
    beta: float = 0.25    # Attack probability (was 0.30)
    gamma: float = 0.20   # Classifier decay
    delta: float = 0.20   # Quantum drift

# Redeploy Qsecbit container
podman restart hookprobe-pod-006-security-qsecbit

# Monitor impact in Grafana
```

### Task 3: Update WAF Rules

```bash
# 1. Edit ModSecurity configuration
# Note: Configuration is typically in container volume or ConfigMap
# For HookProbe, rules are updated via setup.sh

# 2. Edit setup.sh to add new rule
nano Scripts/autonomous/install/setup.sh

# Find ModSecurity container section
# Add custom rule file mounting:

podman run -d \
  --name hookprobe-waf-modsecurity \
  --pod hookprobe-pod-001-web \
  -v /opt/hookprobe/waf/custom-rules.conf:/etc/modsecurity/custom-rules.conf:ro \
  "$IMAGE_MODSECURITY"

# 3. Create custom rules file
cat > /opt/hookprobe/waf/custom-rules.conf << 'EOF'
# Block known bad user agents
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
    "id:1001,phase:1,deny,status:403,msg:'SQLMap detected'"

# Rate limiting
SecAction "id:1002,phase:1,nolog,pass,\
    setvar:ip.requests=+1,\
    expirevar:ip.requests=60"

SecRule IP:REQUESTS "@gt 100" \
    "id:1003,phase:1,deny,status:429,msg:'Rate limit exceeded'"
EOF

# 4. Restart WAF container
podman restart hookprobe-waf-modsecurity

# 5. Monitor blocks in Grafana
```

### Task 4: Add LTE/5G Failover

See `LTE/README.md` for complete guide. Quick summary:

```bash
# 1. Install hardware (Quectel RM520N-GL or similar)
# 2. Install ModemManager
dnf install -y ModemManager NetworkManager

# 3. Edit network-config.sh
nano Scripts/autonomous/install/network-config.sh

# Add LTE config:
LTE_ENABLED=true
LTE_INTERFACE="wwan0"
LTE_APN="internet.provider.com"
LTE_PRIORITY=100  # Higher number = lower priority

# 4. Redeploy with LTE support
sudo ./setup.sh

# 5. Configure connection
nmcli connection add type gsm ifname '*' \
  con-name lte-wan apn "$LTE_APN" \
  connection.autoconnect yes

# 6. Monitor in Grafana
```

### Task 5: Deploy n8n Workflow Automation (POD 008)

```bash
# 1. Ensure main deployment (PODs 001-007) is complete
podman pod ps | grep hookprobe

# 2. Configure n8n
cd Scripts/autonomous/install/
nano n8n_network-config.sh

# Change credentials:
N8N_BASIC_AUTH_USER="admin"
N8N_BASIC_AUTH_PASSWORD="STRONG_PASSWORD_HERE"
N8N_DB_POSTGRESDB_PASSWORD="DB_PASSWORD_HERE"

# Optional: Add AI API keys
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."

# 3. Deploy POD 008
chmod +x n8n_setup.sh
sudo ./n8n_setup.sh

# 4. Access n8n
# http://YOUR_IP:5678
# Login with credentials from step 2

# 5. Import workflows (see n8n/README.md)
```

### Task 6: Update Container Images

```bash
# 1. Edit network-config.sh with new versions
nano Scripts/autonomous/install/network-config.sh

# Example: Update Grafana
IMAGE_GRAFANA="docker.io/grafana/grafana:11.5.0"  # Was 11.4.0

# 2. Pull new images
podman pull "$IMAGE_GRAFANA"

# 3. Recreate affected containers
podman stop hookprobe-monitoring-grafana
podman rm hookprobe-monitoring-grafana

# Run create command from setup.sh
podman run -d \
  --name hookprobe-monitoring-grafana \
  --pod hookprobe-pod-005-monitoring \
  --ip "$IP_GRAFANA" \
  -v grafana-data:/var/lib/grafana \
  "$IMAGE_GRAFANA"

# 4. Verify
curl http://localhost:3000
```

### Task 7: Integrate ClickHouse for High-Performance Analytics

**Why**: ClickHouse provides 100-1000x faster queries for security event analysis compared to PostgreSQL or file-based logs. It's essential for:
- Real-time threat hunting
- Historical Qsecbit analysis
- Attack correlation across multiple sources
- Forensics investigations

**See Complete Guide**: `Documents/ClickHouse-Integration-Analysis.md`
**Quick Start**: `Documents/ClickHouse-Quick-Start.md`

**Quick Deployment** (30 minutes):

```bash
# 1. Update network-config.sh
nano Scripts/autonomous/install/network-config.sh

# Add ClickHouse configuration:
IP_CLICKHOUSE="10.200.5.15"
IMAGE_CLICKHOUSE="docker.io/clickhouse/clickhouse-server:24.11"
VOLUME_CLICKHOUSE_DATA="hookprobe-clickhouse-v5"
CLICKHOUSE_PASSWORD="STRONG_PASSWORD_HERE"

# 2. Deploy ClickHouse container (see Quick-Start guide)
# 3. Create database schemas
# 4. Integrate with Qsecbit
# 5. Add Grafana datasource
# 6. Create security dashboards

# Verify deployment:
curl http://10.200.5.15:8123/ping
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "SELECT version()"

# Test query:
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT count() FROM security.security_events
"
```

**Benefits**:
- **100-1000x faster** analytical queries
- **90% storage reduction** (10-20x compression)
- **Unified security platform** - all events queryable in one system
- **Sub-second forensics** on billions of events
- **Better Grafana dashboards** with complex visualizations

**Data Sources to Migrate**:
1. Zeek IDS logs → ClickHouse network_flows table
2. Snort3 alerts → ClickHouse security_events table
3. ModSecurity WAF → ClickHouse waf_events table
4. Qsecbit scores → ClickHouse qsecbit_scores table
5. Honeypot data → ClickHouse honeypot_attacks table

**Common Queries**:

```sql
-- Top attacking IPs (last 24h)
SELECT
    src_ip,
    count() AS attacks,
    countIf(blocked=1) AS blocked
FROM security.security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY src_ip
ORDER BY attacks DESC
LIMIT 10;

-- Qsecbit RAG status trend (last 7 days)
SELECT
    toDate(timestamp) AS day,
    rag_status,
    count() AS samples,
    avg(score) AS avg_score
FROM security.qsecbit_scores
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY day, rag_status
ORDER BY day DESC;

-- Multi-vector attack correlation
SELECT
    src_ip,
    uniq(source_type) AS attack_vectors,
    groupArray(attack_type) AS attack_types,
    count() AS total_events
FROM security.security_events
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY src_ip
HAVING attack_vectors >= 3
ORDER BY total_events DESC;
```

**Performance Comparison**:

| Query Type | PostgreSQL/Files | ClickHouse | Improvement |
|------------|------------------|------------|-------------|
| Count (24h, 10M rows) | 15-30 sec | 0.1 sec | **150-300x** |
| Top attackers (30d, 1B rows) | Timeout | 2-5 sec | **∞** |
| Attack correlation | Manual (hours) | 2-5 sec | **1000x+** |
| Qsecbit trends (90d) | Not possible | 0.5 sec | **∞** |

**Monitoring ClickHouse**:

```bash
# Check health
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "SELECT 1"

# Database size
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT
    database,
    formatReadableSize(sum(bytes_on_disk)) AS size,
    sum(rows) AS rows
FROM system.parts
GROUP BY database
"

# Slow queries
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "
SELECT
    query,
    query_duration_ms
FROM system.query_log
WHERE query_duration_ms > 1000
ORDER BY event_time DESC
LIMIT 10
"
```

**Important Notes**:
- ClickHouse is columnar OLAP database - NOT a replacement for PostgreSQL (keep for Django/Keycloak)
- Keep VictoriaMetrics for metrics (it's excellent at that)
- ClickHouse complements existing stack, doesn't replace it
- Compression is automatic - 10-20x better than gzip
- TTL handles old data deletion automatically
- Partitioning by date is critical for performance

---

## 🔒 Security Considerations

### When Modifying Code

**CRITICAL SECURITY RULES**:

1. **NEVER hardcode credentials** in scripts
   - Use variables from `network-config.sh`
   - Generate strong random values: `openssl rand -base64 32`

2. **NEVER disable security features** without explicit justification
   - Don't comment out firewall rules
   - Don't disable VXLAN encryption
   - Don't skip SSL/TLS verification

3. **ALWAYS validate user input** in Python scripts
   - Sanitize file paths (no `../` traversal)
   - Validate IP addresses and ports
   - Escape shell commands

4. **AVOID command injection** vulnerabilities
   ```bash
   # BAD - command injection risk
   podman run --name $USER_INPUT ...

   # GOOD - quoted and validated
   CONTAINER_NAME="hookprobe-${SERVICE_NAME}"
   podman run --name "$CONTAINER_NAME" ...
   ```

5. **CHECK for secrets before committing**
   ```bash
   # Before git commit
   git diff | grep -i "password\|secret\|key\|token"
   ```

### Default Credentials

**ALL default credentials MUST be changed in production**:

| Service | Default User | Default Pass | Config Location |
|---------|-------------|--------------|-----------------|
| Django Admin | admin | admin | POD 001 - Change via admin panel |
| Grafana | admin | admin | POD 005 - Change on first login |
| PostgreSQL | hookprobe_admin | CHANGE_ME_... | `network-config.sh:128` |
| Keycloak | admin | CHANGE_ME_... | `network-config.sh:146` |
| Redis | (no auth) | - | Add AUTH in production |

**Always document credential changes** in deployment notes.

### Sensitive Files

**Files containing secrets** (NEVER commit with real values):
- `Scripts/autonomous/install/network-config.sh` - All credentials
- `Scripts/autonomous/install/n8n_network-config.sh` - n8n credentials

**Safe to commit**:
- `setup.sh`, `uninstall.sh` - Logic only
- `qsecbit.py` - Algorithm only
- Documentation files

### Security Testing

**Before committing security changes**:

```bash
# 1. Static analysis
shellcheck Scripts/autonomous/install/*.sh

# Python security scan
pip install bandit
bandit -r Scripts/autonomous/

# 2. Container scanning
trivy image hookprobe-django:v5
trivy image hookprobe-qsecbit:v5

# 3. Network security test
nmap -sV localhost
nmap -sV 10.200.1.0/24

# 4. WAF testing
nikto -h http://localhost

# 5. Penetration testing (if changes affect security)
# Consider using OWASP ZAP or Burp Suite
```

---

## 🧪 Testing Guidelines

### Pre-Deployment Testing

**ALWAYS test in a clean environment**:

```bash
# 1. Clean existing deployment
sudo ./Scripts/autonomous/install/uninstall.sh

# 2. Verify cleanup
podman pod ps  # Should be empty
podman ps -a   # Should be empty
ovs-vsctl show # Should show minimal state

# 3. Fresh deployment
sudo ./Scripts/autonomous/install/setup.sh

# 4. Monitor deployment
# Watch for errors in output
# Check all PODs start successfully

# 5. Validation checklist (see below)
```

### Post-Deployment Validation

**Use the deployment checklist**: `Scripts/autonomous/install/checklist.md`

**Quick validation**:

```bash
# 1. Verify all PODs are running
podman pod ps
# Should show 7 PODs (or 8 if n8n deployed)

# 2. Check all containers are healthy
podman ps -a | grep -v "Up"
# Should show no stopped containers

# 3. Test web services
curl -I http://localhost/             # Django (80)
curl -I http://localhost:3000/        # Grafana (3000)
curl http://localhost:8888/health     # Qsecbit (8888)

# 4. Test database connectivity
podman exec hookprobe-pod-003-db-persistent-postgres \
  pg_isready -U hookprobe_admin

# 5. Verify network isolation
podman exec hookprobe-pod-001-web-dmz-django \
  ping -c 1 10.200.5.10  # Should reach monitoring POD

# 6. Check OVS configuration
ovs-vsctl show
ovs-ofctl dump-flows qsec-bridge

# 7. Review logs for errors
podman logs hookprobe-pod-001-web-dmz-django 2>&1 | grep -i error
```

### n8n Integration Testing

After deploying POD 008:

```bash
# 1. Verify n8n is accessible
curl http://localhost:5678

# 2. Check database connection
podman exec hookprobe-pod-008-n8n-postgres pg_isready

# 3. Test MCP server (if AI features enabled)
curl http://localhost:8889/health

# 4. Import test workflow
# - Access n8n UI
# - Import workflow from n8n/workflows/
# - Execute test run
# - Verify no errors

# See n8n/integration-checklist.md for complete validation
```

### Qsecbit Algorithm Testing

```bash
# 1. Unit tests (if available)
cd Scripts/autonomous/
python3 -m pytest test_qsecbit.py

# 2. Synthetic data test
python3 qsecbit.py --test-mode

# 3. Live monitoring
# - Access Grafana (http://localhost:3000)
# - Open "Qsecbit Analysis" dashboard
# - Verify metrics are updating
# - Check RAG status is calculated

# 4. Alert testing
# - Trigger test alert (if test mode available)
# - Verify email notification sent
# - Check Kali container spins up on AMBER/RED
```

### Security Testing

**Regression tests for security changes**:

```bash
# 1. Verify VXLAN encryption is active
ovs-vsctl list interface | grep -A 10 vxlan
# Should show encryption enabled

# 2. Test firewall rules
nmap -sV localhost
# Should only show intended open ports

# 3. Test WAF blocking
curl -X POST http://localhost/ \
  -d "username=admin' OR '1'='1"
# Should be blocked by WAF

# 4. Verify network isolation
podman exec hookprobe-pod-001-web-dmz-django \
  ping -c 1 10.200.7.10
# Should FAIL (web DMZ cannot reach honeypot)

# 5. Test rate limiting
for i in {1..100}; do
  curl http://localhost/ &
done
# Should hit rate limit
```

---

## 📚 Important Files Reference

### Critical Configuration Files

| File | Purpose | When to Edit |
|------|---------|--------------|
| `Scripts/autonomous/install/network-config.sh` | **MAIN CONFIGURATION** - All network, IPs, credentials, images | Every deployment |
| `Scripts/autonomous/install/setup.sh` | **MAIN DEPLOYMENT SCRIPT** - Creates all PODs, containers, networks | Adding services, changing deployment logic |
| `Scripts/autonomous/qsecbit/qsecbit.py` | **AI THREAT ENGINE** - Qsecbit algorithm + XDP/eBPF DDoS mitigation | Adjusting thresholds, changing analysis logic, XDP configuration |
| `Scripts/autonomous/qsecbit/README.md` | **QSECBIT DOCUMENTATION** - Complete guide to qsecbit module | Understanding qsecbit architecture, NIC compatibility |
| `Scripts/autonomous/install/kali-response-scripts.sh` | **AUTOMATED RESPONSE** - Kali Linux mitigation scripts | Adding new attack responses |

### Optional Feature Configuration

| File | Purpose | When to Edit |
|------|---------|--------------|
| `Scripts/autonomous/install/n8n_network-config.sh` | n8n POD 008 configuration | Deploying workflow automation |
| `Scripts/autonomous/install/n8n_setup.sh` | n8n deployment script | Customizing n8n setup |
| `LTE/README.md` | LTE/5G connectivity guide | Adding cellular failover |

### Documentation Files

| File | Purpose | Audience |
|------|---------|----------|
| `README.md` | **MAIN DOCUMENTATION** - Overview, features, quick start | End users, new contributors |
| `CONTRIBUTING.md` | Contribution guidelines, coding standards, PR process | Contributors |
| `SECURITY.md` | Security policy, vulnerability reporting, hardening guide | Security researchers, operators |
| `CLAUDE.md` | **THIS FILE** - AI assistant guide | AI assistants working with codebase |
| `CHANGELOG.md` | Version history and release notes | Users tracking versions |

### Deployment Documentation

| File | Purpose | Audience |
|------|---------|----------|
| `Scripts/autonomous/install/README.md` | Detailed deployment guide | System administrators |
| `Scripts/autonomous/install/checklist.md` | Pre/post deployment validation | Operators |
| `n8n/README.md` | n8n integration guide | Automation users |
| `n8n/integration-checklist.md` | n8n validation checklist | n8n operators |
| `Documents/SecurityMitigationPlan.md` | Detailed security architecture | Security architects |

### Maintenance Scripts

| File | Purpose | When to Run |
|------|---------|-------------|
| `Scripts/autonomous/install/uninstall.sh` | Clean removal of all PODs/containers | Testing, troubleshooting, fresh install |
| `Scripts/autonomous/install/n8n_uninstall.sh` | Remove POD 008 only | Removing n8n |
| `Scripts/honeypot/mitigation-maintenance.sh` | Honeypot cleanup and maintenance | Scheduled (weekly/monthly) |

---

## 🔍 Troubleshooting

### Common Issues and Solutions

#### Issue 1: PODs Won't Start

**Symptoms**: `podman pod ps` shows no PODs or some PODs missing

**Diagnosis**:
```bash
# Check Podman errors
podman pod ps -a
podman ps -a | grep Exit

# View container logs
podman logs <container-name>

# Check system resources
df -h  # Disk space
free -h  # Memory
```

**Solutions**:
```bash
# Clean up and retry
sudo ./uninstall.sh
sudo ./setup.sh

# If disk full, clean Podman storage
podman system prune -a --volumes

# If memory issue, increase swap or reduce PODs
```

#### Issue 2: Network Connectivity Between PODs Fails

**Symptoms**: Containers cannot ping each other, service errors

**Diagnosis**:
```bash
# Check OVS bridge status
ovs-vsctl show

# Verify VXLAN tunnels
ovs-vsctl list interface | grep vxlan

# Check OpenFlow rules
ovs-ofctl dump-flows qsec-bridge

# Test connectivity
podman exec <container> ping <target-ip>
```

**Solutions**:
```bash
# Restart OVS
systemctl restart openvswitch

# Recreate bridge
ovs-vsctl del-br qsec-bridge
# Then re-run setup.sh

# Check firewall isn't blocking
nft list ruleset | grep 10.200
```

#### Issue 3: Qsecbit Not Responding

**Symptoms**: `/health` endpoint fails, no metrics in Grafana

**Diagnosis**:
```bash
# Check container status
podman ps -a | grep qsecbit

# View logs
podman logs hookprobe-pod-006-security-qsecbit

# Test manually
curl http://10.200.6.12:8888/health
```

**Solutions**:
```bash
# Restart container
podman restart hookprobe-pod-006-security-qsecbit

# Check Python dependencies
podman exec hookprobe-pod-006-security-qsecbit \
  pip list | grep -E "numpy|scipy"

# Verify configuration
podman exec hookprobe-pod-006-security-qsecbit \
  python3 -c "import qsecbit; print(qsecbit.__version__)"
```

#### Issue 4: Web Services Not Accessible

**Symptoms**: Cannot access Django, Grafana from browser

**Diagnosis**:
```bash
# Check services are listening
ss -tlnp | grep -E "80|3000|8888"

# Test locally
curl http://localhost/
curl http://localhost:3000/

# Check Nginx/Django logs
podman logs hookprobe-pod-001-web-dmz-nginx
podman logs hookprobe-pod-001-web-dmz-django
```

**Solutions**:
```bash
# Verify firewall allows access
firewall-cmd --list-all

# Add rules if needed
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=3000/tcp
firewall-cmd --reload

# Check SELinux (if enabled)
getenforce  # If Enforcing, check for denials
ausearch -m avc -ts recent
```

#### Issue 5: Database Connection Errors

**Symptoms**: Services fail with "connection refused" or "authentication failed"

**Diagnosis**:
```bash
# Check PostgreSQL is running
podman exec hookprobe-pod-003-db-persistent-postgres pg_isready

# Verify credentials
grep POSTGRES_ Scripts/autonomous/install/network-config.sh

# Test connection
podman exec hookprobe-pod-003-db-persistent-postgres \
  psql -U hookprobe_admin -d hookprobe_db -c "SELECT 1;"
```

**Solutions**:
```bash
# Reset PostgreSQL password
podman exec hookprobe-pod-003-db-persistent-postgres \
  psql -U postgres -c \
  "ALTER USER hookprobe_admin PASSWORD 'NEW_PASSWORD';"

# Update network-config.sh with new password
# Recreate dependent containers

# Check PostgreSQL logs
podman logs hookprobe-pod-003-db-persistent-postgres
```

#### Issue 6: High Memory/CPU Usage

**Symptoms**: System slow, services unresponsive

**Diagnosis**:
```bash
# Check resource usage
podman stats

# Identify heavy containers
podman ps --format "{{.Names}}" | while read container; do
  echo "$container:"
  podman stats --no-stream "$container"
done

# Check system load
top
htop  # If available
```

**Solutions**:
```bash
# Add resource limits to containers
# Edit setup.sh and add --memory and --cpus flags:

podman run -d \
  --memory="2g" \
  --cpus="2" \
  --name <container> \
  ...

# Restart affected containers
podman restart <container>

# Consider hardware upgrade if persistent
```

### Getting Help

**Order of escalation**:

1. **Check this CLAUDE.md** - Comprehensive troubleshooting
2. **Review Documentation** - README.md, SECURITY.md, setup guides
3. **Check Logs** - `podman logs <container-name>`
4. **Search Issues** - https://github.com/hookprobe/hookprobe/issues
5. **Ask Community** - GitHub Discussions
6. **Report Bug** - GitHub Issues (use template from CONTRIBUTING.md)
7. **Contact Security** - qsecbit@hookprobe.com (security issues only)

---

## 🚀 Quick Reference Commands

### Deployment Commands

```bash
# Fresh install
cd Scripts/autonomous/install/
sudo ./setup.sh

# Add n8n (POD 008)
sudo ./n8n_setup.sh

# Remove everything
sudo ./uninstall.sh

# Remove only n8n
sudo ./n8n_uninstall.sh
```

### Monitoring Commands

```bash
# List all PODs
podman pod ps

# List all containers
podman ps -a

# Check specific container
podman logs <container-name>
podman inspect <container-name>

# Resource usage
podman stats

# Network status
ovs-vsctl show
ovs-ofctl dump-flows qsec-bridge
```

### Service Access

```bash
# Web services
curl http://localhost/              # Django
curl http://localhost:3000/         # Grafana
curl http://localhost:8888/health   # Qsecbit
curl http://localhost:5678/         # n8n (if deployed)

# Database
podman exec hookprobe-pod-003-db-persistent-postgres \
  psql -U hookprobe_admin -d hookprobe_db

# Redis
podman exec hookprobe-pod-004-cache-redis redis-cli ping
```

### Maintenance Commands

```bash
# Update container images
podman pull <image-name>

# Restart services
podman restart <container-name>
podman pod restart <pod-name>

# Clean up
podman system prune
podman volume prune

# Backup
tar -czf hookprobe-backup-$(date +%Y%m%d).tar.gz \
  /opt/hookprobe/ /var/lib/hookprobe/
```

---

## 📊 Metrics and Monitoring

### Key Metrics to Monitor

**System Health**:
- CPU usage per POD/container
- Memory usage per POD/container
- Disk I/O and space
- Network throughput

**Security Metrics**:
- Qsecbit RAG status (GREEN/AMBER/RED)
- WAF blocks per minute
- IDS/IPS alerts
- Honeypot attack attempts
- Failed authentication attempts

**Service Availability**:
- Django response time
- Database query performance
- Redis hit/miss ratio
- Grafana dashboard load time

### Grafana Dashboards

**Default Dashboards**:
1. **System Overview** - All PODs health and resources
2. **Qsecbit Analysis** - Threat scores, RAG status, trends
3. **WAF Activity** - Blocked attacks, patterns, top attackers
4. **Network Traffic** - Flow analysis, bandwidth, top talkers
5. **Security Events** - IDS/IPS alerts, honeypot activity
6. **Database Performance** - Query stats, connection pools
7. **LTE Status** - Signal strength, data usage (if enabled)

**Access Grafana**: http://localhost:3000 (admin/admin - change this!)

---

## 🎯 Best Practices for AI Assistants

### When Working with This Codebase

1. **ALWAYS read configuration before suggesting changes**
   - Review `network-config.sh` for current settings
   - Check `setup.sh` for deployment logic
   - Understand existing architecture before modifying

2. **NEVER assume traditional software patterns**
   - This is infrastructure-as-code, not an application
   - No MVC, REST APIs, or typical web frameworks
   - Focus on deployment, networking, containers

3. **ALWAYS consider security implications**
   - This is a security platform - security is paramount
   - Never suggest removing or weakening security features
   - Validate all changes against security best practices

4. **TEST before committing**
   - Run `./setup.sh` in clean environment
   - Verify all PODs start successfully
   - Check services are accessible
   - Run `./uninstall.sh` to verify cleanup

5. **DOCUMENT all changes**
   - Update README.md if user-facing
   - Update CLAUDE.md if affecting AI workflows
   - Add inline comments for complex logic
   - Update CHANGELOG.md

6. **FOLLOW existing conventions**
   - Use established variable naming
   - Match existing code style
   - Keep bash scripts consistent
   - Follow PEP 8 for Python

7. **RESPECT the architecture**
   - Don't merge PODs without justification
   - Don't break network isolation
   - Don't bypass security layers
   - Maintain six-layer defense model

### When User Requests Are Unclear

**ASK clarifying questions**:
- "Which POD should this service be added to?"
- "What security requirements does this have?"
- "Should this be accessible from other PODs?"
- "What are the resource requirements?"

**DON'T assume**:
- Default to most secure option
- Document assumptions made
- Provide alternatives when possible

### When Making Suggestions

**DO**:
- Explain the reasoning behind suggestions
- Consider security, performance, maintainability
- Provide complete, tested examples
- Reference existing code patterns
- Explain trade-offs

**DON'T**:
- Suggest incomplete solutions
- Ignore security considerations
- Recommend untested approaches
- Break existing functionality
- Add unnecessary complexity

---

## 📞 Support and Resources

### Documentation Hierarchy

1. **This file (CLAUDE.md)** - AI assistant guide
2. **README.md** - User documentation and quick start
3. **SECURITY.md** - Security policy and hardening
4. **CONTRIBUTING.md** - Contribution guidelines
5. **Component READMEs** - Specific feature documentation
   - `Scripts/autonomous/install/README.md`
   - `n8n/README.md`
   - `LTE/README.md`

### External Resources

- **GitHub Repository**: https://github.com/hookprobe/hookprobe
- **Issue Tracker**: https://github.com/hookprobe/hookprobe/issues
- **Security Contact**: qsecbit@hookprobe.com
- **License**: MIT (see LICENSE file)

### Related Technologies

- **Podman**: https://docs.podman.io/
- **Open vSwitch**: https://docs.openvswitch.org/
- **VXLAN**: RFC 7348
- **nftables**: https://wiki.nftables.org/
- **Grafana**: https://grafana.com/docs/
- **VictoriaMetrics**: https://docs.victoriametrics.com/
- **Zeek**: https://docs.zeek.org/
- **Snort3**: https://www.snort.org/documents
- **n8n**: https://docs.n8n.io/

---

## 🔄 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-22 | Initial CLAUDE.md creation |

---

## ✅ AI Assistant Checklist

Before completing work on this codebase:

- [ ] Read and understood this CLAUDE.md file
- [ ] Reviewed relevant configuration files
- [ ] Tested changes in clean environment
- [ ] Verified security implications
- [ ] Updated documentation
- [ ] Followed coding conventions
- [ ] Committed with clear message
- [ ] Considered impact on all PODs
- [ ] Validated deployment still works
- [ ] Checked for exposed secrets

---

**HookProbe v5.0** - Democratizing Cybersecurity Through Edge Computing
**Built with ❤️ for the security community**

*For questions about this guide, open an issue or contribute improvements via PR.*

---

**END OF CLAUDE.MD**
