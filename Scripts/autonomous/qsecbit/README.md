# Qsecbit: Quantum Security Bit

**Version**: 5.0
**License**: MIT
**Author**: Andrei Toma

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [XDP/eBPF DDoS Mitigation](#xdpebpf-ddos-mitigation)
- [NIC Compatibility Matrix](#nic-compatibility-matrix)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

**Qsecbit (Quantum Security Bit)** is an AI-driven threat detection engine that measures cyber resilience as the smallest unit where AI-driven attack and defense reach equilibrium through continuous error correction.

### Key Features

- **Multi-Component Threat Analysis**: Combines statistical drift, ML predictions, classifier decay, and system entropy
- **RAG Status System**: Real-time Red/Amber/Green threat classification
- **XDP/eBPF Integration**: Kernel-level DDoS mitigation with automatic NIC detection
- **Dual-Database Support**: ClickHouse (edge) and Apache Doris (cloud) integration
- **Automatic NIC Detection**: Intelligent XDP mode selection based on hardware capabilities
- **Multi-Tenant Support**: Built for MSSP cloud deployments with tenant isolation

### Qsecbit Algorithm

The Qsecbit score (R) is calculated as a weighted combination of four components:

```
R = α·drift + β·p_attack + γ·decay + δ·q_drift
```

Where:
- **drift** (30%): Mahalanobis distance from baseline telemetry
- **p_attack** (30%): ML-predicted attack probability
- **decay** (20%): Rate of change in classifier confidence
- **q_drift** (20%): System entropy deviation

**RAG Classification**:
- **GREEN** (< 0.45): Normal operation
- **AMBER** (0.45-0.70): Warning state - automated response initiated
- **RED** (> 0.70): Critical - full mitigation engaged

---

## 🏗️ Architecture

### Deployment Models

**Edge Deployment** (Single-Tenant):
```
┌────────────────────────────────────┐
│   Intel N100 / Raspberry Pi SBC   │
│   ┌──────────┐    ┌─────────────┐ │
│   │ Qsecbit  │───→│ ClickHouse  │ │
│   │  + XDP   │    │  (0-90 days)│ │
│   └──────────┘    └─────────────┘ │
└────────────────────────────────────┘
```

**Cloud Backend** (Multi-Tenant MSSP):
```
┌──────────────────────────────────────────┐
│  Proxmox / RHEL / Ubuntu Server          │
│  ┌──────────┐    ┌────────────────────┐ │
│  │ Qsecbit  │───→│ Apache Doris       │ │
│  │ (N-Pods) │    │ (1000+ tenants)    │ │
│  └──────────┘    │ (365+ days)        │ │
│                  └────────────────────┘ │
└──────────────────────────────────────────┘
```

### Component Overview

```
qsecbit/
├── qsecbit.py          # Main module
├── README.md           # This file
└── __init__.py         # Package initializer (future)
```

**Main Classes**:
- `Qsecbit`: Core threat analysis engine
- `XDPManager`: XDP/eBPF program lifecycle management
- `NICDetector`: Hardware capability detection
- `QsecbitConfig`: Configuration dataclass
- `QsecbitSample`: Individual measurement

---

## 🚀 XDP/eBPF DDoS Mitigation

### Overview

Qsecbit includes **kernel-level packet filtering** via XDP (eXpress Data Path) for ultra-low latency DDoS mitigation:

- **Packet filtering before network stack**: Sub-microsecond decisions
- **Rate limiting**: 1000 packets/sec per source IP
- **Dynamic IP blocking**: Real-time attacker blacklisting
- **Protocol flood detection**: TCP SYN, UDP, ICMP monitoring
- **Malformed packet filtering**: Automatic drop of invalid packets

### XDP Modes

| Mode | Description | Performance | NIC Requirement |
|------|-------------|-------------|-----------------|
| **XDP-DRV** | Native driver mode | Highest (line rate) | Driver support required |
| **XDP-SKB** | Generic software mode | Moderate | Works on all NICs |
| **XDP-HW** | Hardware offload | Best | Advanced NICs only |

Qsecbit **automatically detects** your NIC capabilities and selects the optimal mode.

### XDP Features

```python
# Automatic IP blocking at kernel level
qsecbit.xdp_manager.block_ip("192.168.1.100")

# Get real-time statistics
stats = qsecbit.xdp_manager.get_stats()
print(f"Total packets: {stats.total_packets}")
print(f"Dropped (rate-limited): {stats.dropped_rate_limit}")
print(f"TCP SYN floods: {stats.tcp_syn_flood}")
```

**Statistics Tracked**:
- Total packets processed
- Dropped packets (blocked IPs, rate-limited, malformed)
- TCP SYN flood attempts
- UDP flood attempts
- ICMP flood attempts

---

## 🖥️ NIC Compatibility Matrix

### XDP-Ready NIC Comparison

| **Platform** | **NIC Model** | **Driver** | **XDP** | **eBPF** | **XDP-DRV** | **Max Throughput** |
|-------------|---------------|------------|---------|----------|-------------|-------------------|
| **Raspberry Pi 4/5** | Broadcom SoC | bcmgenet | ✅ | ❌ | ❌ | 1 Gbps |
| **Raspberry Pi** | Realtek USB | r8152 | ✅ | ❌ | ❌ | 1 Gbps |
| **Desktop** | Realtek PCIe | r8169 | ✅ | ❌ | ❌ | 2.5 Gbps |
| **Intel N100** | **I211** | **igb** | ✅ | ✅ | ✅ | **1 Gbps** |
| **Intel N100** | **I226** | **igc** | ✅ | ✅ | ✅ | **2.5 Gbps** |
| **Intel Server** | X520 (82599) | ixgbe | ✅ | ✅ | ❌ | 10 Gbps |
| **Intel Server** | **X710** | **i40e** | ✅ | ✅ | ✅ | **40 Gbps** |
| **Intel Server** | **E810** | **ice** | ✅ | ✅ | ✅ | **100 Gbps** |
| **Mellanox** | **ConnectX-3** | **mlx4_en** | ✅ | ✅ | ✅ | **40 Gbps** |
| **Mellanox** | **ConnectX-4/5/6/7** | **mlx5_core** | ✅ | ✅ | ✅ | **200 Gbps** |

**Legend**:
- ✅ **Supported**
- ❌ **Not supported**

### Recommended Hardware

#### **Budget Edge Deployment** (< $300)
- **SBC**: Intel N100 (8GB RAM)
- **NIC**: Intel I226-V (built-in, 2.5Gbps)
- **XDP Mode**: XDP-DRV ✅
- **Performance**: 2.5 Gbps line rate filtering

#### **Mid-Range Edge** ($300-$1000)
- **SBC**: Raspberry Pi 5 (8GB) + Intel I226 USB adapter
- **Alternative**: Mini PC with Intel I211/I226
- **XDP Mode**: XDP-DRV ✅
- **Performance**: 1-2.5 Gbps

#### **High-Performance Cloud Backend** ($2000+)
- **Server**: Dell/HP with Intel X710 or Mellanox ConnectX-5
- **XDP Mode**: XDP-DRV ✅ + Hardware Offload
- **Performance**: 40-100 Gbps line rate

### Important Notes

⚠️ **Raspberry Pi Limitation**: Only supports XDP-SKB mode (software). For production DDoS mitigation, consider Intel N100 with I226 NIC for native XDP-DRV support.

✅ **Intel N100**: Best value for edge deployment. Built-in I226 NIC supports full XDP-DRV mode at 2.5 Gbps.

🏆 **Mellanox ConnectX**: Gold standard for enterprise. Full XDP-DRV, AF_XDP, and hardware offload.

---

## 📦 Installation

### System Requirements

**Minimum (Edge Deployment)**:
- OS: RHEL 10, Fedora 40+, CentOS Stream 9+, Ubuntu 22.04+
- CPU: 2 cores (ARM64 or x86_64)
- RAM: 4GB minimum, 8GB recommended
- Storage: 20GB (0-90 day retention)
- NIC: Any (XDP-SKB mode)

**Recommended (Edge with XDP-DRV)**:
- CPU: Intel N100 (4 cores, 3.4 GHz)
- RAM: 8-16GB
- NIC: Intel I226-V (2.5Gbps) or I211 (1Gbps)
- Storage: 50GB SSD

**Cloud Backend (MSSP)**:
- CPU: 16+ cores
- RAM: 64GB minimum (256GB for 1000+ tenants)
- Storage: 2TB+ NVMe SSD
- NIC: Intel X710 (40Gbps) or Mellanox ConnectX-5 (100Gbps)

### Software Dependencies

**Core Dependencies**:
```bash
pip install numpy>=1.24.0 scipy>=1.10.0
```

**Database Support**:
```bash
# ClickHouse (edge)
pip install clickhouse-driver>=0.2.6

# Apache Doris (cloud backend)
pip install pymysql>=1.1.0
```

**XDP/eBPF Support** (RHEL/Fedora):
```bash
dnf install -y bcc python3-bcc kernel-devel
dnf install -y clang llvm
```

**XDP/eBPF Support** (Ubuntu/Debian):
```bash
apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
apt-get install -y clang llvm
```

### Verify Installation

```python
#!/usr/bin/env python3
from qsecbit import Qsecbit, XDPManager, NICDetector

# Check BCC availability
try:
    from bcc import BPF
    print("✓ BCC/eBPF available")
except ImportError:
    print("✗ BCC not installed")

# Detect NIC capabilities
interface = NICDetector.get_primary_interface()
if interface:
    capability = NICDetector.detect_capability(interface)
    print(f"✓ Detected: {capability.vendor} {capability.model}")
    print(f"  XDP-DRV: {'✓' if capability.xdp_drv else '✗'}")
```

---

## 🔧 Usage

### Basic Usage (No XDP)

```python
#!/usr/bin/env python3
import numpy as np
from qsecbit import Qsecbit, QsecbitConfig

# Define baseline system profile
baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])  # CPU, Memory, Network, Disk
baseline_cov = np.eye(4) * 0.02
quantum_anchor = 6.144  # Baseline entropy

# Initialize qsecbit
config = QsecbitConfig(
    alpha=0.30,  # System drift weight
    beta=0.30,   # Attack probability weight
    gamma=0.20,  # Classifier decay weight
    delta=0.20,  # Quantum drift weight
    amber_threshold=0.45,
    red_threshold=0.70
)

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor, config)

# Analyze current system state
current_telemetry = np.array([0.25, 0.42, 0.35, 0.45])
attack_probability = 0.72  # From ML model
classifier_confidence = np.array([0.76, 0.71, 0.73])

sample = qsecbit.calculate(
    x_t=current_telemetry,
    p_attack=attack_probability,
    c_t=classifier_confidence,
    dt=1.0
)

print(f"Qsecbit Score: {sample.score:.4f}")
print(f"RAG Status: {sample.rag_status}")
print(f"Components: {sample.components}")
```

### With XDP/eBPF Integration

```python
#!/usr/bin/env python3
import os
import numpy as np
from qsecbit import Qsecbit, QsecbitConfig

# Enable XDP for edge deployment
os.environ['XDP_ENABLED'] = 'true'
os.environ['DEPLOYMENT_TYPE'] = 'edge'
os.environ['CLICKHOUSE_ENABLED'] = 'true'
os.environ['CLICKHOUSE_HOST'] = '10.200.5.11'

# Initialize qsecbit (XDP auto-loads)
baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])
baseline_cov = np.eye(4) * 0.02
quantum_anchor = 6.144

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor)

# Output:
# ✓ NIC Detected: Intel I226
#   - Interface: eth0
#   - Driver: igc
#   - XDP Mode: xdp-drv
#   - Max Throughput: 2.5Gbps
#   - Notes: Intel N100 typical NIC. Full XDP-DRV support.
# ✓ XDP program loaded on eth0 (xdp-drv)
# ✓ XDP/eBPF DDoS mitigation enabled
# ✓ ClickHouse integration enabled (edge deployment)

# Block attacker IPs dynamically
if qsecbit.xdp_manager:
    qsecbit.xdp_manager.block_ip("192.168.1.100")
    qsecbit.xdp_manager.block_ip("10.0.0.50")

    # Get XDP statistics
    stats = qsecbit.xdp_manager.get_stats()
    print(f"Total packets: {stats.total_packets}")
    print(f"Dropped (blocked): {stats.dropped_blocked}")
    print(f"Dropped (rate-limited): {stats.dropped_rate_limit}")

# Analyze threats (XDP stats automatically included)
sample = qsecbit.calculate(
    x_t=np.array([0.25, 0.42, 0.35, 0.45]),
    p_attack=0.72,
    c_t=np.array([0.76, 0.71, 0.73])
)

# Data automatically saved to ClickHouse with XDP metrics
```

### Cloud Backend (MSSP Multi-Tenant)

```python
#!/usr/bin/env python3
import os
from qsecbit import Qsecbit

# Configure for cloud backend
os.environ['DEPLOYMENT_TYPE'] = 'cloud-backend'
os.environ['TENANT_ID'] = 'customer-12345'
os.environ['DORIS_ENABLED'] = 'true'
os.environ['DORIS_HOST'] = '10.100.1.10'
os.environ['DORIS_PORT'] = '9030'
os.environ['DORIS_USER'] = 'root'
os.environ['DORIS_PASSWORD'] = 'secure_password'

# Initialize (no XDP in cloud)
qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor)

# Output:
# ✓ Doris integration enabled (cloud backend, tenant: customer-12345)

# All data automatically isolated by tenant_id in Doris
sample = qsecbit.calculate(...)
# Data saved to Doris with automatic tenant_id filtering
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `DEPLOYMENT_TYPE` | `edge`, `cloud-backend` | `edge` | Deployment mode |
| `XDP_ENABLED` | `true`, `false` | `false` | Enable XDP/eBPF DDoS mitigation |
| `CLICKHOUSE_ENABLED` | `true`, `false` | `true` | Enable ClickHouse (edge) |
| `CLICKHOUSE_HOST` | IP address | `10.200.5.11` | ClickHouse server |
| `CLICKHOUSE_PORT` | Port | `9001` | ClickHouse native protocol port |
| `CLICKHOUSE_DB` | Database name | `security` | ClickHouse database |
| `DORIS_ENABLED` | `true`, `false` | `true` | Enable Doris (cloud) |
| `DORIS_HOST` | IP address | `10.100.1.10` | Doris frontend server |
| `DORIS_PORT` | Port | `9030` | Doris MySQL protocol port |
| `DORIS_DB` | Database name | `security` | Doris database |
| `TENANT_ID` | String | `default` | Multi-tenant identifier (cloud) |
| `POD_NAME` | String | `unknown` | Pod/container name |

### QsecbitConfig Parameters

```python
config = QsecbitConfig(
    # Component weights (must sum to 1.0)
    alpha=0.30,          # System drift weight
    beta=0.30,           # Attack probability weight
    gamma=0.20,          # Classifier decay weight
    delta=0.20,          # Quantum drift weight

    # RAG thresholds
    amber_threshold=0.45,  # Warning threshold
    red_threshold=0.70,    # Critical threshold

    # Normalization parameters
    lambda_crit=0.15,      # Classifier drift threshold
    q_crit=0.25,           # Quantum drift threshold
    drift_slope=3.5,       # Logistic function slope
    drift_center=2.0,      # Logistic function center

    # History management
    max_history_size=1000,      # Maximum samples to retain
    convergence_window=10       # Samples for convergence analysis
)
```

---

## 📊 API Reference

### Qsecbit Class

**Methods**:
- `calculate(x_t, p_attack, c_t, q_t=None, dt=1.0, metadata=None)` → `QsecbitSample`
- `convergence_rate(window=None)` → `float | None`
- `trend(window=20)` → `str`  # 'IMPROVING', 'STABLE', 'DEGRADING'
- `export_history(filepath)` → `None`
- `summary_stats()` → `Dict`

### XDPManager Class

**Methods**:
- `load_program(program_code=None)` → `bool`
- `unload_program()` → `bool`
- `get_stats()` → `XDPStats | None`
- `block_ip(ip_address)` → `bool`
- `unblock_ip(ip_address)` → `bool`

### NICDetector Class

**Static Methods**:
- `get_primary_interface()` → `str | None`
- `get_driver(interface)` → `str | None`
- `detect_capability(interface)` → `NICCapability`
- `select_xdp_mode(capability, prefer_drv=True)` → `XDPMode`

---

## ⚡ Performance

### XDP Performance Benchmarks

| **NIC** | **Mode** | **Throughput** | **CPU Usage** | **Latency** |
|---------|----------|----------------|---------------|-------------|
| Intel I226 | XDP-DRV | 2.5 Gbps | 5-10% | < 1 µs |
| Intel I226 | XDP-SKB | 1.5 Gbps | 15-20% | 2-5 µs |
| Raspberry Pi 4 | XDP-SKB | 800 Mbps | 25-30% | 5-10 µs |
| Intel X710 | XDP-DRV | 40 Gbps | < 2% | < 0.5 µs |
| Mellanox CX-5 | XDP-DRV | 100 Gbps | < 1% | < 0.2 µs |

### Database Performance

| **Database** | **Deployment** | **Write Speed** | **Query Speed** |
|--------------|----------------|-----------------|-----------------|
| ClickHouse | Edge (1 device) | 100k rows/sec | 0.1-0.5 sec |
| Doris | Cloud (1000 tenants) | 500k rows/sec | 2-5 sec |

---

## 🔍 Troubleshooting

### XDP Not Loading

**Problem**: `XDP/eBPF support disabled` message

**Solutions**:
```bash
# Check BCC installation
python3 -c "from bcc import BPF; print('BCC OK')"

# Install if missing (RHEL/Fedora)
dnf install -y bcc python3-bcc kernel-devel

# Check kernel support
uname -r  # Should be 4.8+ for XDP
zgrep CONFIG_BPF /proc/config.gz  # Should show =y
```

### XDP-DRV Mode Not Available

**Problem**: Falls back to XDP-SKB even with compatible NIC

**Solutions**:
```bash
# Check driver version
ethtool -i eth0

# Update driver (Intel I226 example)
dnf update -y intel-igc-kmod

# Verify XDP support in driver
ip link set dev eth0 xdpdrv obj /dev/null  # Test command
```

### Database Connection Failures

**Problem**: `Failed to save to clickhouse/doris`

**Solutions**:
```bash
# ClickHouse (edge)
curl http://10.200.5.11:8123/ping
podman exec hookprobe-monitoring-clickhouse clickhouse-client --query "SELECT 1"

# Doris (cloud)
mysql -h 10.100.1.10 -P 9030 -u root -p
```

### High CPU Usage with XDP-SKB

**Problem**: CPU usage > 30% with XDP enabled

**Solution**: Upgrade to NIC with XDP-DRV support (Intel I211/I226, X710, or Mellanox ConnectX).

---

## 📚 Additional Resources

- **Main Documentation**: `/home/user/hookprobe/README.md`
- **CLAUDE.md**: AI assistant guide
- **Backend Deployment**: `Documents/backend/README.md`
- **ClickHouse Integration**: `Documents/ClickHouse-Quick-Start.md`

---

## 📝 License

MIT License - See `LICENSE` file in repository root.

---

## 👤 Author

**Andrei Toma**
HookProbe Project
qsecbit@hookprobe.com

---

**HookProbe v5.0** - Democratizing Cybersecurity Through Edge Computing
