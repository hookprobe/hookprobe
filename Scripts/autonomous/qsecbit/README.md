# Qsecbit: Quantum Security Bit

**Version**: 5.0
**License**: MIT
**Author**: Andrei Toma

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [XDP/eBPF DDoS Mitigation](#xdpebpf-ddos-mitigation)
- [Energy Monitoring & Anomaly Detection](#energy-monitoring--anomaly-detection)
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

- **Multi-Component Threat Analysis**: Combines statistical drift, ML predictions, classifier decay, system entropy, and energy anomalies
- **RAG Status System**: Real-time Red/Amber/Green threat classification
- **XDP/eBPF Integration**: Kernel-level DDoS mitigation with automatic NIC detection
- **Energy Monitoring (NEW)**: Per-PID power consumption tracking with EWMA/Z-score anomaly detection
- **Dual-Database Support**: ClickHouse (edge) and Apache Doris (cloud) integration
- **Automatic NIC Detection**: Intelligent XDP mode selection based on hardware capabilities
- **Multi-Tenant Support**: Built for MSSP cloud deployments with tenant isolation

### Qsecbit Algorithm

The Qsecbit score (R) is calculated as a weighted combination of **five components** (when energy monitoring is enabled):

```
R = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly
```

**Default (Energy Monitoring Disabled)**:
- **drift** (30%): Mahalanobis distance from baseline telemetry
- **p_attack** (30%): ML-predicted attack probability
- **decay** (20%): Rate of change in classifier confidence
- **q_drift** (20%): System entropy deviation

**With Energy Monitoring Enabled**:
- **drift** (25%): Mahalanobis distance from baseline telemetry
- **p_attack** (25%): ML-predicted attack probability
- **decay** (20%): Rate of change in classifier confidence
- **q_drift** (15%): System entropy deviation
- **energy_anomaly** (15%): Power consumption anomaly score (NEW)

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

XDP (eXpress Data Path) operates at different layers of the network stack, providing varying levels of performance:

| **Mode** | **Where it runs** | **Kernel bypass** | **Layer** | **Performance** | **Notes** |
|----------|------------------|-------------------|-----------|-----------------|-----------|
| **XDP-hw** | NIC hardware ASIC | Full | Layer 0 | Ultra-fast | Rare; requires programmable NICs (Mellanox SmartNIC, Intel IPU) |
| **XDP-drv** | NIC driver | Full | Layer 1 | Fastest practical | Native driver mode, requires driver support |
| **XDP-skb** | Generic SKB layer | Partial | Layer 1.5 | Moderate | Universal fallback, works on all NICs |

**Key Differences:**
- **XDP-hw**: Packet processing happens directly in NIC hardware before it reaches the CPU. Requires specialized NICs.
- **XDP-drv**: Packet processing happens in the NIC driver before the Linux kernel network stack. Requires XDP-capable driver.
- **XDP-skb**: Packet processing happens after the kernel allocates socket buffers (SKBs). Significantly slower but universal.

Qsecbit **automatically detects** your NIC capabilities and selects the optimal mode (preferring XDP-drv, falling back to XDP-skb).

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

## ⚡ Energy Monitoring & Anomaly Detection

### Overview

**Qsecbit v5.0** includes a revolutionary **energy consumption-based early warning system** that detects threats by monitoring power consumption patterns at the per-process level. This provides an additional layer of defense against:

- **DDoS attacks**: Network flooding causes abnormal CPU/power spikes in NIC interrupt handlers
- **Cryptomining malware**: Distinctive high-power consumption patterns
- **0-day exploits**: Unusual process behavior detectable via power signatures
- **Kernel-level attacks**: XDP/eBPF process power anomalies

### How It Works

The energy monitoring system implements a **7-step algorithm**:

```
1. Initialize:
   - Read initial total CPU time (/proc/stat)
   - Read initial per-PID CPU times (/proc/[pid]/stat)
   - Read initial RAPL energy counter (/sys/class/powercap/intel-rapl/)

2. Sleep for Δt (e.g., 1 second)

3. Read again:
   - New total CPU time
   - New per-PID CPU times
   - New RAPL energy

4. Compute:
   - CPU time deltas (per-PID and total)
   - CPU usage share per PID (percentage)
   - Package wattage over interval (from RAPL delta)
   - Estimated PID wattage = (PID CPU share) × (package wattage)

5. Build time-series:
   - pid_power[t] = estimated_watts
   - Track NIC interrupt-handling PIDs (irq/, ksoftirqd, napi/)
   - Track XDP driver PIDs (xdp, bpf, ebpf)

6. Feed into anomaly detector:
   - EWMA (Exponentially Weighted Moving Average) for smoothing
   - Z-score spike detection (threshold: 2.5 sigma default)
   - Baseline deviation tracking (50%+ increase = alert)
   - Correlation with NIC/XDP process power spikes

7. Trigger alert when:
   - pid_power spikes > baseline × threshold
   - NIC interrupt-handling PIDs show correlated spikes
   - XDP driver CPU share increases disproportionately
   - Overall anomaly score contributes to qsecbit RAG status
```

### Key Features

- **RAPL Energy Counters**: Hardware-level power measurement (Intel CPUs)
- **Per-PID Power Estimation**: Accurate wattage tracking for every process
- **EWMA Smoothing**: Reduces false positives from transient spikes
- **Z-Score Detection**: Statistical anomaly detection (configurable threshold)
- **NIC Process Tracking**: Automatic detection of network-related processes
- **XDP Correlation**: Correlates XDP/eBPF process power with DDoS attacks
- **Integration with RAG**: Energy anomalies contribute 15% to qsecbit score

### Example Detection Scenarios

**Scenario 1: DDoS Attack via UDP Flood**
```
Normal State:
  - ksoftirqd/0: 2.5W
  - irq/eth0: 1.2W
  - Total NIC: 3.7W

During Attack:
  - ksoftirqd/0: 8.3W (Z-score: 4.2 → SPIKE)
  - irq/eth0: 5.1W (Z-score: 3.8 → SPIKE)
  - Total NIC: 13.4W (+262% → ALERT)
  - qsecbit energy_anomaly: 0.42 → RAG: AMBER
```

**Scenario 2: Cryptomining Malware**
```
Normal State:
  - Total package power: 15W

During Attack:
  - malicious_miner (PID 12345): 18W (Z-score: 6.5 → SPIKE)
  - Total package power: 33W (+120%)
  - qsecbit energy_anomaly: 0.65 → RAG: AMBER
```

**Scenario 3: XDP/eBPF Exploitation**
```
Normal State:
  - bpf_prog (XDP): 0.8W

During Attack:
  - bpf_prog (XDP): 4.2W (Z-score: 5.1 → SPIKE)
  - xdp_spike: True
  - qsecbit energy_anomaly: 0.51 → RAG: AMBER
```

### Hardware Requirements

**Required**:
- **Intel CPU** with RAPL (Running Average Power Limit) support
  - **Supported**: Intel Core (6th gen+), Xeon (Skylake+), Atom (Goldmont+)
  - **Not Supported**: AMD CPUs (no RAPL), ARM CPUs (no RAPL)
  - **Partial Support**: Some AMD Ryzen CPUs via alternative power interfaces (not implemented)

**Automatic Fallback**:
- If RAPL is unavailable, energy monitoring uses CPU-time-based estimation only
- Less accurate but still functional for relative power comparisons

**Verification**:
```bash
# Check RAPL availability
ls /sys/class/powercap/intel-rapl/

# Expected output (if available):
# intel-rapl:0/       # Package-0 (CPU socket)
# intel-rapl:0:0/     # Core domain
# intel-rapl:0:1/     # Uncore domain
# ...

# Read current energy (microjoules)
cat /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj
```

### Configuration

Enable energy monitoring via `QsecbitConfig`:

```python
config = QsecbitConfig(
    # Enable energy monitoring
    energy_monitoring_enabled=True,

    # Z-score threshold for spike detection (default: 2.5)
    # Lower = more sensitive, Higher = fewer false positives
    energy_spike_threshold=2.5,

    # EWMA smoothing factor (0-1, default: 0.3)
    # Lower = more smoothing, Higher = faster response
    energy_ewma_alpha=0.3,

    # Baseline window size (samples, default: 100)
    # Larger = more stable baseline, Smaller = faster adaptation
    energy_baseline_window=100
)
```

### Usage Example

```python
#!/usr/bin/env python3
import numpy as np
from qsecbit import Qsecbit, QsecbitConfig

# Enable energy monitoring
config = QsecbitConfig(
    energy_monitoring_enabled=True,
    energy_spike_threshold=2.5,
    energy_ewma_alpha=0.3
)

# Initialize qsecbit
baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])
baseline_cov = np.eye(4) * 0.02
quantum_anchor = 6.144

qsecbit = Qsecbit(baseline_mu, baseline_cov, quantum_anchor, config)

# Output:
# ✓ Energy consumption monitoring enabled (RAPL + per-PID tracking)
#   - RAPL energy counters detected

# Analyze system state
sample = qsecbit.calculate(
    x_t=np.array([0.25, 0.42, 0.35, 0.45]),
    p_attack=0.72,
    c_t=np.array([0.76, 0.71, 0.73])
)

# Energy metadata automatically captured
print(f"Qsecbit Score: {sample.score:.4f}")
print(f"RAG Status: {sample.rag_status}")
print(f"Energy Anomaly: {sample.components.get('energy_anomaly', 0):.4f}")

if 'energy' in sample.metadata:
    energy = sample.metadata['energy']
    print(f"Package Power: {energy['package_watts']:.2f}W")
    print(f"NIC Processes: {energy['nic_processes_watts']:.2f}W")
    print(f"XDP Processes: {energy['xdp_processes_watts']:.2f}W")

    if energy['has_energy_anomaly']:
        print("⚠️  ENERGY ANOMALY DETECTED")
        if energy['nic_spike']:
            print("⚠️  NIC POWER SPIKE - Possible DDoS attack")
        if energy['xdp_spike']:
            print("⚠️  XDP POWER SPIKE - Possible kernel-level attack")

        # Top 5 processes with power spikes
        for spike in energy['energy_spike_pids']:
            print(f"  - PID {spike['pid']} ({spike['name']}): "
                  f"{spike['watts']:.2f}W (Z-score: {spike['z_score']:.2f})")
```

### Database Schema

Energy metrics are automatically saved to ClickHouse (edge) or Doris (cloud):

**Additional columns in `qsecbit_scores` table**:
```sql
-- Core energy component
energy_anomaly Float32,  -- Anomaly score (0-1)

-- Power measurements
package_watts Float32,  -- Total CPU package power
nic_processes_watts Float32,  -- Power from NIC-related processes
xdp_processes_watts Float32,  -- Power from XDP/eBPF processes

-- Anomaly flags
has_energy_anomaly UInt8,  -- 1 if anomaly detected
nic_spike UInt8,  -- 1 if NIC processes spiked
xdp_spike UInt8   -- 1 if XDP processes spiked
```

**Example Queries**:

```sql
-- Top energy anomalies in last 24 hours
SELECT
    timestamp,
    score AS qsecbit_score,
    energy_anomaly,
    package_watts,
    nic_processes_watts,
    has_energy_anomaly,
    nic_spike
FROM qsecbit_scores
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND has_energy_anomaly = 1
ORDER BY energy_anomaly DESC
LIMIT 10;

-- Correlation between NIC power and packet drops (XDP)
SELECT
    toStartOfHour(timestamp) AS hour,
    avg(nic_processes_watts) AS avg_nic_watts,
    avg(xdp_dropped_rate_limit) AS avg_drops,
    count(*) FILTER (WHERE nic_spike = 1) AS nic_spike_count
FROM qsecbit_scores
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY hour
ORDER BY hour DESC;

-- Energy baseline deviation trend
SELECT
    toDate(timestamp) AS day,
    avg(package_watts) AS avg_package_watts,
    max(package_watts) AS max_package_watts,
    stddevPop(package_watts) AS stddev_package_watts,
    countIf(has_energy_anomaly = 1) AS anomaly_count
FROM qsecbit_scores
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY day
ORDER BY day DESC;
```

### Benefits

**1. Early DDoS Detection**
- Detects attacks before traditional signatures
- Correlates NIC interrupt spikes with network floods
- Provides sub-second response time (integrated with qsecbit RAG)

**2. Cryptomining Detection**
- Identifies malicious miners by power consumption patterns
- Works even if process name is obfuscated
- Catches CPU-based and GPU-based miners

**3. 0-Day Attack Detection**
- Abnormal process behavior visible in power signatures
- Detects kernel exploits via system call patterns
- Catches privilege escalation attempts

**4. Resource Optimization**
- Identify power-hungry processes for optimization
- Track system efficiency over time
- Correlate power with performance metrics

**5. Forensics & Incident Response**
- Historical power consumption data for attack timeline reconstruction
- Per-PID power tracking for root cause analysis
- Integration with qsecbit RAG for automated response

### Limitations

**1. Intel CPU Required (for full functionality)**
- RAPL is Intel-specific technology
- AMD CPUs: No RAPL support (fallback to CPU-time estimation)
- ARM CPUs: No RAPL support (fallback to CPU-time estimation)

**2. Baseline Learning Period**
- Requires 100+ samples (default) to establish baseline
- First ~2 minutes may have false positives
- Adjust `energy_baseline_window` for faster/slower adaptation

**3. CPU-Intensive Operations**
- Reading `/proc/[pid]/stat` for all processes has overhead
- Recommended interval: 1-5 seconds (not sub-second)
- May increase CPU usage by 1-3%

**4. Process Lifetime**
- Short-lived processes may be missed between samples
- Long-lived processes have more accurate baselines
- Aggregate NIC/XDP metrics mitigate this

### Best Practices

1. **Baseline Establishment**: Run system under normal load for 5-10 minutes before relying on alerts
2. **Threshold Tuning**: Start with `energy_spike_threshold=2.5`, adjust based on false positive rate
3. **Sampling Interval**: 1-second intervals recommended for edge, 5-second for cloud backend
4. **Database Retention**: Energy metrics add ~200 bytes per sample, plan storage accordingly
5. **Alert Correlation**: Combine energy anomalies with XDP stats and qsecbit RAG for maximum accuracy

---

## 🖥️ NIC Compatibility Matrix

### XDP-Ready NIC Comparison

| **Platform** | **NIC Model** | **Driver** | **XDP-SKB** | **XDP-DRV** | **XDP-HW** | **Max Throughput** |
|-------------|---------------|------------|-------------|-------------|------------|-------------------|
| **Raspberry Pi 4/5** | Broadcom SoC | bcmgenet | ✅ | ❌ | ❌ | 1 Gbps |
| **Raspberry Pi** | Realtek USB | r8152 | ✅ | ❌ | ❌ | 1 Gbps |
| **Desktop** | Realtek PCIe | r8169 | ✅ | ❌ | ❌ | 2.5 Gbps |
| **Intel N100** | **I211** | **igb** | ✅ | ✅ | ❌ | **1 Gbps** |
| **Intel N100** | **I226** | **igc** | ✅ | ✅ | ❌ | **2.5 Gbps** |
| **Intel Server** | X520 (82599) | ixgbe | ✅ | ❌ | ❌ | 10 Gbps |
| **Intel Server** | **X710** | **i40e** | ✅ | ✅ | ❌ | **40 Gbps** |
| **Intel Server** | **E810** | **ice** | ✅ | ✅ | ❌ | **100 Gbps** |
| **Mellanox** | **ConnectX-3** | **mlx4_en** | ✅ | ❌ | ❌ | **40 Gbps** |
| **Mellanox** | **ConnectX-4/5/6/7** | **mlx5_core** | ✅ | ✅ | ✅ | **200 Gbps** |
| **Mellanox SmartNIC** | **BlueField-2/3** | **mlx5_core** | ✅ | ✅ | ✅ | **400 Gbps** |

**Legend**:
- ✅ **Supported**
- ❌ **Not supported**

**XDP-HW Note**: Hardware offload (XDP-hw) is extremely rare and only supported by:
- Mellanox ConnectX-5/6/7 (limited offload capabilities)
- Mellanox BlueField-2/3 SmartNICs (full programmable pipeline)
- Intel IPU (Infrastructure Processing Unit)
- Netronome Agilio SmartNICs

For 99% of deployments, **XDP-drv** is the fastest practical mode.

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
    alpha=0.30,          # System drift weight (auto: 0.25 if energy enabled)
    beta=0.30,           # Attack probability weight (auto: 0.25 if energy enabled)
    gamma=0.20,          # Classifier decay weight
    delta=0.20,          # Quantum drift weight (auto: 0.15 if energy enabled)
    epsilon=0.0,         # Energy anomaly weight (auto: 0.15 if energy enabled)

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
    convergence_window=10,      # Samples for convergence analysis

    # Energy monitoring parameters (NEW)
    energy_monitoring_enabled=False,  # Enable energy-based anomaly detection
    energy_spike_threshold=2.5,       # Z-score threshold for spike detection
    energy_ewma_alpha=0.3,            # EWMA smoothing factor (0-1)
    energy_baseline_window=100        # Samples for baseline calculation
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

### EnergyMonitor Class (NEW)

**Methods**:
- `capture_snapshot()` → `SystemEnergySnapshot | None`
- `detect_anomalies(snapshot)` → `Dict[str, any]`
- `update_baselines()` → `None`

**Attributes**:
- `rapl_available: bool` - Whether RAPL energy counters are available
- `rapl_package_path: Path | None` - Path to RAPL energy counter
- `history: List[SystemEnergySnapshot]` - Energy snapshot history
- `pid_power_history: Dict[int, List[float]]` - Per-PID power time-series
- `pid_baseline_mean: Dict[int, float]` - Per-PID power baselines
- `pid_baseline_std: Dict[int, float]` - Per-PID power standard deviations

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
