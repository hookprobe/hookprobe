"""
Qsecbit: Quantum Security Bit
A resilience metric for AI-driven cybersecurity systems

Author: Andrei Toma
License: MIT
"""

import numpy as np
from scipy.spatial.distance import mahalanobis
from scipy.special import expit as logistic
from scipy.stats import entropy
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, List
from datetime import datetime
import json
import os
import socket
import subprocess
import re
from pathlib import Path
from enum import Enum

# Optional ClickHouse integration (for edge deployments)
try:
    from clickhouse_driver import Client as ClickHouseClient
    CLICKHOUSE_AVAILABLE = True
except ImportError:
    CLICKHOUSE_AVAILABLE = False

# Optional Doris integration (for cloud backend)
try:
    import pymysql
    DORIS_AVAILABLE = True
except ImportError:
    DORIS_AVAILABLE = False

# Optional BCC/eBPF integration for XDP (for edge deployments)
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


# ===============================================================================
# XDP/eBPF NIC DETECTION AND CAPABILITY MANAGEMENT
# ===============================================================================

class XDPMode(Enum):
    """XDP attachment modes"""
    DISABLED = "disabled"
    SKB = "xdp-skb"      # Generic XDP (software mode, works on all NICs)
    DRV = "xdp-drv"      # Native XDP (driver mode, requires NIC support)
    HW = "xdp-hw"        # Hardware offload (requires advanced NICs)


@dataclass
class NICCapability:
    """NIC XDP/eBPF capability profile"""
    vendor: str
    model: str
    driver: str
    xdp_skb: bool = True   # All NICs support generic XDP
    xdp_drv: bool = False  # Native driver mode
    af_xdp: bool = False   # AF_XDP zero-copy sockets
    hw_offload: bool = False  # Hardware offload
    max_throughput: str = "1Gbps"
    notes: str = ""


# ✅ NIC Capability Matrix for XDP/eBPF Support
NIC_CAPABILITY_MATRIX = {
    # Raspberry Pi NICs (SKB only)
    "bcmgenet": NICCapability(
        vendor="Broadcom",
        model="RPi 4/5 SoC NIC",
        driver="bcmgenet",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="1Gbps",
        notes="Raspberry Pi internal NIC. SKB mode only."
    ),
    "r8152": NICCapability(
        vendor="Realtek",
        model="RTL8152/RTL8153 USB",
        driver="r8152",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="1Gbps",
        notes="USB NIC. Cannot use DRV mode. Limited throughput."
    ),

    # Realtek PCIe NICs (SKB only)
    "r8169": NICCapability(
        vendor="Realtek",
        model="RTL8111/8168/8125",
        driver="r8169",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="2.5Gbps",
        notes="Consumer NIC. SKB mode only. Not suitable for high-speed XDP."
    ),

    # Intel Entry-Level NICs (1Gbps - SKB only)
    "igb": NICCapability(
        vendor="Intel",
        model="I211/I219",
        driver="igb",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="1Gbps",
        notes="Entry-level Intel. No DRV support."
    ),
    "igc": NICCapability(
        vendor="Intel",
        model="I225/I226",
        driver="igc",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=False,
        hw_offload=False,
        max_throughput="2.5Gbps",
        notes="Intel N100 typical NIC. SKB mode only."
    ),

    # Intel Server NICs (10Gbps+ - Full XDP Support)
    "ixgbe": NICCapability(
        vendor="Intel",
        model="82599/X520 10GbE",
        driver="ixgbe",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=True,
        hw_offload=False,
        max_throughput="10Gbps",
        notes="Older 10G. AF_XDP supported but no DRV mode."
    ),
    "i40e": NICCapability(
        vendor="Intel",
        model="X710/XL710",
        driver="i40e",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=True,
        max_throughput="40Gbps",
        notes="Full XDP support. First Intel NIC with DRV mode."
    ),
    "ice": NICCapability(
        vendor="Intel",
        model="E810",
        driver="ice",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=True,
        max_throughput="100Gbps",
        notes="Modern Intel NIC. Best XDP performance."
    ),

    # Mellanox/NVIDIA ConnectX (Best XDP Support)
    "mlx4_en": NICCapability(
        vendor="Mellanox",
        model="ConnectX-3",
        driver="mlx4_en",
        xdp_skb=True,
        xdp_drv=False,
        af_xdp=True,
        hw_offload=False,
        max_throughput="40Gbps",
        notes="Older Mellanox. AF_XDP only."
    ),
    "mlx5_core": NICCapability(
        vendor="Mellanox",
        model="ConnectX-4/5/6/7",
        driver="mlx5_core",
        xdp_skb=True,
        xdp_drv=True,
        af_xdp=True,
        hw_offload=True,
        max_throughput="200Gbps",
        notes="Gold standard for XDP. Programmable pipelines."
    ),
}


class NICDetector:
    """Detect NIC hardware and XDP capabilities"""

    @staticmethod
    def get_primary_interface() -> Optional[str]:
        """Get primary network interface (non-loopback, has IP)"""
        try:
            # Get default route interface
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(r'dev\s+(\S+)', result.stdout)
                if match:
                    return match.group(1)

            # Fallback: first non-loopback interface with IP
            result = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'lo' not in line:
                        match = re.search(r'^\d+:\s+(\S+)', line)
                        if match:
                            return match.group(1)
        except Exception as e:
            print(f"Warning: Failed to detect primary interface: {e}")

        return None

    @staticmethod
    def get_driver(interface: str) -> Optional[str]:
        """Get NIC driver name for interface"""
        try:
            driver_path = Path(f"/sys/class/net/{interface}/device/driver")
            if driver_path.exists():
                driver_link = driver_path.resolve()
                return driver_link.name
        except Exception as e:
            print(f"Warning: Failed to detect driver for {interface}: {e}")

        return None

    @staticmethod
    def get_nic_info(interface: str) -> Dict[str, str]:
        """Get detailed NIC information"""
        info = {
            'interface': interface,
            'driver': None,
            'vendor': 'Unknown',
            'model': 'Unknown'
        }

        # Get driver
        info['driver'] = NICDetector.get_driver(interface)

        # Try to get vendor/model from ethtool
        try:
            result = subprocess.run(
                ["ethtool", "-i", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("driver:"):
                        info['driver'] = line.split(":", 1)[1].strip()
                    elif line.startswith("bus-info:"):
                        info['model'] = line.split(":", 1)[1].strip()
        except Exception:
            pass

        return info

    @staticmethod
    def detect_capability(interface: str) -> NICCapability:
        """Detect XDP capability for interface"""
        nic_info = NICDetector.get_nic_info(interface)
        driver = nic_info.get('driver')

        if driver and driver in NIC_CAPABILITY_MATRIX:
            return NIC_CAPABILITY_MATRIX[driver]

        # Unknown NIC - assume SKB only
        return NICCapability(
            vendor="Unknown",
            model=nic_info.get('model', 'Unknown'),
            driver=driver or "unknown",
            xdp_skb=True,
            xdp_drv=False,
            af_xdp=False,
            hw_offload=False,
            max_throughput="Unknown",
            notes=f"Unknown NIC. Defaulting to SKB mode only."
        )

    @staticmethod
    def select_xdp_mode(capability: NICCapability, prefer_drv: bool = True) -> XDPMode:
        """Select best XDP mode for NIC capability"""
        if prefer_drv and capability.xdp_drv:
            return XDPMode.DRV
        elif capability.xdp_skb:
            return XDPMode.SKB
        else:
            return XDPMode.DISABLED


# eBPF/XDP Program for DDoS Mitigation
XDP_DDOS_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

// Rate limiting map: source IP -> packet count
BPF_HASH(rate_limit, u32, u64, 65536);

// Blocked IPs map
BPF_HASH(blocked_ips, u32, u8, 65536);

// Statistics counters
BPF_ARRAY(stats, u64, 8);

// Statistics indices
enum {
    STAT_TOTAL_PACKETS = 0,
    STAT_DROPPED_BLOCKED = 1,
    STAT_DROPPED_RATE_LIMIT = 2,
    STAT_DROPPED_MALFORMED = 3,
    STAT_PASSED = 4,
    STAT_TCP_SYN_FLOOD = 5,
    STAT_UDP_FLOOD = 6,
    STAT_ICMP_FLOOD = 7,
};

// Configuration (packets per second per IP)
#define RATE_LIMIT_PPS 1000
#define RATE_WINDOW_NS 1000000000ULL  // 1 second

// XDP main function
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Statistics
    u64 *total_packets = stats.lookup(&(u32){STAT_TOTAL_PACKETS});
    if (total_packets) {
        __sync_fetch_and_add(total_packets, 1);
    }

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        u64 *malformed = stats.lookup(&(u32){STAT_DROPPED_MALFORMED});
        if (malformed) __sync_fetch_and_add(malformed, 1);
        return XDP_DROP;
    }

    // Only process IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        u64 *malformed = stats.lookup(&(u32){STAT_DROPPED_MALFORMED});
        if (malformed) __sync_fetch_and_add(malformed, 1);
        return XDP_DROP;
    }

    u32 src_ip = ip->saddr;

    // Check if IP is blocked
    u8 *blocked = blocked_ips.lookup(&src_ip);
    if (blocked && *blocked == 1) {
        u64 *dropped_blocked = stats.lookup(&(u32){STAT_DROPPED_BLOCKED});
        if (dropped_blocked) __sync_fetch_and_add(dropped_blocked, 1);
        return XDP_DROP;
    }

    // Rate limiting
    u64 now = bpf_ktime_get_ns();
    u64 *last_time = rate_limit.lookup(&src_ip);

    if (last_time) {
        u64 elapsed = now - *last_time;

        // Reset counter every second
        if (elapsed > RATE_WINDOW_NS) {
            rate_limit.update(&src_ip, &now);
        } else {
            // Count packets in current window
            u64 count = 1;
            u64 *pkt_count = rate_limit.lookup(&src_ip);
            if (pkt_count) {
                count = *pkt_count + 1;
            }

            if (count > RATE_LIMIT_PPS) {
                // Rate limit exceeded - drop packet
                u64 *dropped_rate = stats.lookup(&(u32){STAT_DROPPED_RATE_LIMIT});
                if (dropped_rate) __sync_fetch_and_add(dropped_rate, 1);
                return XDP_DROP;
            }

            rate_limit.update(&src_ip, &count);
        }
    } else {
        // First packet from this IP
        rate_limit.update(&src_ip, &now);
    }

    // Protocol-specific flood detection
    u8 protocol = ip->protocol;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_DROP;
        }

        // Detect SYN flood
        if (tcp->syn && !tcp->ack) {
            u64 *syn_flood = stats.lookup(&(u32){STAT_TCP_SYN_FLOOD});
            if (syn_flood) __sync_fetch_and_add(syn_flood, 1);

            // Could implement SYN cookie logic here
        }
    } else if (protocol == IPPROTO_UDP) {
        u64 *udp_flood = stats.lookup(&(u32){STAT_UDP_FLOOD});
        if (udp_flood) __sync_fetch_and_add(udp_flood, 1);

    } else if (protocol == IPPROTO_ICMP) {
        u64 *icmp_flood = stats.lookup(&(u32){STAT_ICMP_FLOOD});
        if (icmp_flood) __sync_fetch_and_add(icmp_flood, 1);
    }

    // Packet passed all filters
    u64 *passed = stats.lookup(&(u32){STAT_PASSED});
    if (passed) __sync_fetch_and_add(passed, 1);

    return XDP_PASS;
}
"""


@dataclass
class XDPStats:
    """XDP statistics"""
    total_packets: int = 0
    dropped_blocked: int = 0
    dropped_rate_limit: int = 0
    dropped_malformed: int = 0
    passed: int = 0
    tcp_syn_flood: int = 0
    udp_flood: int = 0
    icmp_flood: int = 0
    timestamp: datetime = field(default_factory=datetime.now)


class XDPManager:
    """Manage XDP/eBPF programs for DDoS mitigation"""

    def __init__(self, interface: Optional[str] = None, auto_detect: bool = True):
        """
        Initialize XDP manager

        Args:
            interface: Network interface to attach XDP (auto-detected if None)
            auto_detect: Automatically detect NIC capabilities
        """
        self.interface = interface
        self.capability: Optional[NICCapability] = None
        self.xdp_mode: XDPMode = XDPMode.DISABLED
        self.bpf: Optional[BPF] = None
        self.enabled = False
        self.stats_history: List[XDPStats] = []

        if not BCC_AVAILABLE:
            print("Warning: BCC not available. XDP/eBPF support disabled.")
            print("Install with: pip install bcc")
            return

        # Auto-detect interface if not provided
        if not self.interface and auto_detect:
            self.interface = NICDetector.get_primary_interface()
            if not self.interface:
                print("Warning: Could not detect primary network interface")
                return

        # Detect NIC capabilities
        if auto_detect and self.interface:
            self.capability = NICDetector.detect_capability(self.interface)
            self.xdp_mode = NICDetector.select_xdp_mode(self.capability)

            print(f"✓ NIC Detected: {self.capability.vendor} {self.capability.model}")
            print(f"  - Interface: {self.interface}")
            print(f"  - Driver: {self.capability.driver}")
            print(f"  - XDP Mode: {self.xdp_mode.value}")
            print(f"  - Max Throughput: {self.capability.max_throughput}")
            if self.capability.notes:
                print(f"  - Notes: {self.capability.notes}")

    def load_program(self, program_code: Optional[str] = None) -> bool:
        """
        Load XDP/eBPF program

        Args:
            program_code: eBPF C code (uses default DDoS program if None)

        Returns:
            True if loaded successfully
        """
        if not BCC_AVAILABLE:
            print("Error: BCC not available")
            return False

        if not self.interface:
            print("Error: No network interface specified")
            return False

        if self.xdp_mode == XDPMode.DISABLED:
            print("Error: XDP not supported on this NIC")
            return False

        try:
            # Use default DDoS mitigation program if not provided
            code = program_code or XDP_DDOS_PROGRAM

            # Compile and load BPF program
            self.bpf = BPF(text=code)

            # Get main function
            fn = self.bpf.load_func("xdp_ddos_filter", BPF.XDP)

            # Attach to interface
            flags = 0
            if self.xdp_mode == XDPMode.SKB:
                flags = 1 << 1  # XDP_FLAGS_SKB_MODE
            elif self.xdp_mode == XDPMode.DRV:
                flags = 1 << 2  # XDP_FLAGS_DRV_MODE

            self.bpf.attach_xdp(self.interface, fn, flags)

            self.enabled = True
            print(f"✓ XDP program loaded on {self.interface} ({self.xdp_mode.value})")
            return True

        except Exception as e:
            print(f"Error loading XDP program: {e}")
            return False

    def unload_program(self) -> bool:
        """Unload XDP program from interface"""
        if not self.bpf or not self.interface:
            return False

        try:
            self.bpf.remove_xdp(self.interface)
            self.enabled = False
            print(f"✓ XDP program unloaded from {self.interface}")
            return True
        except Exception as e:
            print(f"Error unloading XDP program: {e}")
            return False

    def get_stats(self) -> Optional[XDPStats]:
        """Get current XDP statistics"""
        if not self.enabled or not self.bpf:
            return None

        try:
            stats_map = self.bpf["stats"]

            stats = XDPStats(
                total_packets=stats_map[0].value if 0 in stats_map else 0,
                dropped_blocked=stats_map[1].value if 1 in stats_map else 0,
                dropped_rate_limit=stats_map[2].value if 2 in stats_map else 0,
                dropped_malformed=stats_map[3].value if 3 in stats_map else 0,
                passed=stats_map[4].value if 4 in stats_map else 0,
                tcp_syn_flood=stats_map[5].value if 5 in stats_map else 0,
                udp_flood=stats_map[6].value if 6 in stats_map else 0,
                icmp_flood=stats_map[7].value if 7 in stats_map else 0,
                timestamp=datetime.now()
            )

            self.stats_history.append(stats)
            if len(self.stats_history) > 1000:
                self.stats_history.pop(0)

            return stats

        except Exception as e:
            print(f"Error getting XDP stats: {e}")
            return None

    def block_ip(self, ip_address: str) -> bool:
        """Block an IP address at XDP layer"""
        if not self.enabled or not self.bpf:
            return False

        try:
            import socket
            import struct

            # Convert IP string to integer
            ip_int = struct.unpack("!I", socket.inet_aton(ip_address))[0]

            # Update blocked_ips map
            blocked_map = self.bpf["blocked_ips"]
            blocked_map[blocked_map.Key(ip_int)] = blocked_map.Leaf(1)

            print(f"✓ Blocked IP {ip_address} at XDP layer")
            return True

        except Exception as e:
            print(f"Error blocking IP {ip_address}: {e}")
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        if not self.enabled or not self.bpf:
            return False

        try:
            import socket
            import struct

            ip_int = struct.unpack("!I", socket.inet_aton(ip_address))[0]

            blocked_map = self.bpf["blocked_ips"]
            del blocked_map[blocked_map.Key(ip_int)]

            print(f"✓ Unblocked IP {ip_address}")
            return True

        except Exception as e:
            print(f"Error unblocking IP {ip_address}: {e}")
            return False

    def __del__(self):
        """Cleanup: unload XDP program on deletion"""
        if self.enabled:
            self.unload_program()


@dataclass
class QsecbitConfig:
    """Configuration for Qsecbit calculation"""
    # Normalization thresholds
    lambda_crit: float = 0.15  # Critical classifier drift threshold
    q_crit: float = 0.25       # Critical quantum drift threshold
    
    # Component weights (must sum to 1.0)
    alpha: float = 0.30   # System drift weight
    beta: float = 0.30    # Attack probability weight
    gamma: float = 0.20   # Classifier decay weight
    delta: float = 0.20   # Quantum drift weight
    
    # RAG (Red/Amber/Green) thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.70
    
    # Logistic function parameters for drift normalization
    drift_slope: float = 3.5
    drift_center: float = 2.0
    
    # Temporal parameters
    max_history_size: int = 1000
    convergence_window: int = 10  # Number of samples to check convergence
    
    def __post_init__(self):
        """Validate configuration"""
        weight_sum = self.alpha + self.beta + self.gamma + self.delta
        if not np.isclose(weight_sum, 1.0, atol=0.01):
            raise ValueError(f"Weights must sum to 1.0, got {weight_sum}")
        
        if not 0 < self.amber_threshold < self.red_threshold < 1:
            raise ValueError("Thresholds must satisfy: 0 < amber < red < 1")


@dataclass
class QsecbitSample:
    """Single qsecbit measurement"""
    timestamp: datetime
    score: float
    components: Dict[str, float]
    rag_status: str
    system_state: np.ndarray
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'score': float(self.score),
            'components': {k: float(v) for k, v in self.components.items()},
            'rag_status': self.rag_status,
            'system_state': self.system_state.tolist(),
            'metadata': self.metadata
        }


class Qsecbit:
    """
    Qsecbit: Quantum Security Bit
    
    Measures cyber resilience as the smallest unit where AI-driven attack 
    and defense reach equilibrium through continuous error correction.
    
    The metric combines:
    - Statistical drift from baseline (Mahalanobis distance)
    - ML-predicted attack probability
    - Classifier confidence decay rate
    - System entropy deviation (quantum drift)
    """
    
    def __init__(
        self,
        baseline_mu: np.ndarray,
        baseline_cov: np.ndarray,
        quantum_anchor: float,
        config: Optional[QsecbitConfig] = None
    ):
        """
        Initialize Qsecbit calculator

        Args:
            baseline_mu: Mean vector of baseline system telemetry
            baseline_cov: Covariance matrix of baseline system
            quantum_anchor: Baseline system entropy value
            config: Configuration object (uses defaults if None)
        """
        self.mu = np.array(baseline_mu)
        self.cov = np.array(baseline_cov)
        self.q_anchor = float(quantum_anchor)
        self.config = config or QsecbitConfig()

        # Precompute inverse covariance for efficiency
        self.inv_cov = np.linalg.inv(self.cov)

        # State tracking
        self.prev_classifier: Optional[np.ndarray] = None
        self.history: List[QsecbitSample] = []
        self.baseline_entropy = self._calculate_baseline_entropy()

        # System metadata
        self.hostname = socket.gethostname()
        self.pod_name = os.getenv('POD_NAME', 'unknown')
        self.tenant_id = os.getenv('TENANT_ID', 'default')  # For MSSP multi-tenancy
        self.deployment_type = os.getenv('DEPLOYMENT_TYPE', 'edge')  # 'edge' or 'cloud-backend'

        # XDP/eBPF integration (for edge deployments)
        self.xdp_enabled = False
        self.xdp_manager: Optional[XDPManager] = None

        if self.deployment_type == 'edge' and os.getenv('XDP_ENABLED', 'false').lower() == 'true':
            try:
                self.xdp_manager = XDPManager(auto_detect=True)
                if self.xdp_manager.interface:
                    if self.xdp_manager.load_program():
                        self.xdp_enabled = True
                        print("✓ XDP/eBPF DDoS mitigation enabled")
            except Exception as e:
                print(f"Warning: XDP initialization failed: {e}")

        # Database integration (auto-detect edge vs cloud)
        self.db_enabled = False
        self.db_type = None
        self.db_client = None

        # ClickHouse integration (for edge deployments)
        if self.deployment_type == 'edge' and CLICKHOUSE_AVAILABLE and os.getenv('CLICKHOUSE_ENABLED', 'true').lower() == 'true':
            try:
                self.db_client = ClickHouseClient(
                    host=os.getenv('CLICKHOUSE_HOST', '10.200.5.11'),
                    port=int(os.getenv('CLICKHOUSE_PORT', '9001')),
                    database=os.getenv('CLICKHOUSE_DB', 'security'),
                    user=os.getenv('CLICKHOUSE_USER', 'hookprobe'),
                    password=os.getenv('CLICKHOUSE_PASSWORD', '')
                )
                # Test connection
                self.db_client.execute('SELECT 1')
                self.db_enabled = True
                self.db_type = 'clickhouse'
                print("✓ ClickHouse integration enabled (edge deployment)")
            except Exception as e:
                print(f"Warning: ClickHouse not available: {e}")
                self.db_enabled = False

        # Doris integration (for cloud backend MSSP deployments)
        elif self.deployment_type == 'cloud-backend' and DORIS_AVAILABLE and os.getenv('DORIS_ENABLED', 'true').lower() == 'true':
            try:
                self.db_client = pymysql.connect(
                    host=os.getenv('DORIS_HOST', '10.100.1.10'),
                    port=int(os.getenv('DORIS_PORT', '9030')),
                    user=os.getenv('DORIS_USER', 'root'),
                    password=os.getenv('DORIS_PASSWORD', ''),
                    database=os.getenv('DORIS_DB', 'security'),
                    autocommit=True
                )
                # Test connection
                with self.db_client.cursor() as cursor:
                    cursor.execute('SELECT 1')
                self.db_enabled = True
                self.db_type = 'doris'
                print(f"✓ Doris integration enabled (cloud backend, tenant: {self.tenant_id})")
            except Exception as e:
                print(f"Warning: Doris not available: {e}")
                self.db_enabled = False
        
    def _calculate_baseline_entropy(self) -> float:
        """Calculate theoretical baseline entropy from covariance"""
        # Differential entropy for multivariate Gaussian
        k = len(self.mu)
        det_cov = np.linalg.det(self.cov)
        return 0.5 * k * (1 + np.log(2 * np.pi)) + 0.5 * np.log(det_cov)
    
    def _drift(self, x_t: np.ndarray) -> float:
        """
        Compute normalized Mahalanobis drift from baseline
        
        Mahalanobis distance accounts for correlations in the data,
        making it more robust than Euclidean distance.
        Normalized via logistic function to [0, 1] range.
        """
        d = mahalanobis(x_t, self.mu, self.inv_cov)
        k = self.config.drift_slope
        theta = self.config.drift_center
        return float(logistic(k * (d - theta)))
    
    def _classifier_decay(self, c_t: np.ndarray, dt: float) -> float:
        """
        Compute normalized rate of change in classifier confidence
        
        Measures how quickly the AI classifier's predictions are changing,
        which indicates either adversarial manipulation or concept drift.
        """
        if self.prev_classifier is None:
            self.prev_classifier = c_t.copy()
            return 0.0
        
        # Rate of change in confidence vector
        delta = np.linalg.norm(c_t - self.prev_classifier) / max(dt, 1e-9)
        self.prev_classifier = c_t.copy()
        
        # Normalize to [0, 1]
        return float(min(1.0, delta / self.config.lambda_crit))
    
    def _quantum_drift(self, q_t: float) -> float:
        """
        Compute normalized entropy drift from baseline
        
        System entropy deviation indicates disorder or adversarial
        manipulation at the information-theoretic level.
        """
        q = abs(q_t - self.q_anchor)
        return float(min(1.0, q / self.config.q_crit))
    
    def _system_entropy(self, x_t: np.ndarray) -> float:
        """
        Calculate current system entropy

        Uses Shannon entropy of discretized telemetry values
        """
        # Discretize continuous values for entropy calculation
        bins = 10
        hist, _ = np.histogram(x_t, bins=bins, density=True)
        hist = hist + 1e-10  # Avoid log(0)
        return float(entropy(hist))

    def _get_xdp_metrics(self) -> Dict[str, int]:
        """Get current XDP statistics"""
        if not self.xdp_enabled or not self.xdp_manager:
            return {}

        stats = self.xdp_manager.get_stats()
        if not stats:
            return {}

        return {
            'xdp_total_packets': stats.total_packets,
            'xdp_dropped_blocked': stats.dropped_blocked,
            'xdp_dropped_rate_limit': stats.dropped_rate_limit,
            'xdp_dropped_malformed': stats.dropped_malformed,
            'xdp_passed': stats.passed,
            'xdp_tcp_syn_flood': stats.tcp_syn_flood,
            'xdp_udp_flood': stats.udp_flood,
            'xdp_icmp_flood': stats.icmp_flood
        }

    def _save_to_database(self, sample: QsecbitSample, x_t: np.ndarray):
        """
        Save qsecbit sample to database (ClickHouse for edge, Doris for cloud)

        Args:
            sample: QsecbitSample object to save
            x_t: System telemetry vector (CPU, Memory, Network, Disk)
        """
        if not self.db_enabled:
            return

        try:
            # Extract telemetry values (assume 4-element vector: CPU, Memory, Network, Disk)
            cpu_usage = float(x_t[0]) if len(x_t) > 0 else 0.0
            memory_usage = float(x_t[1]) if len(x_t) > 1 else 0.0
            network_traffic = float(x_t[2]) if len(x_t) > 2 else 0.0
            disk_io = float(x_t[3]) if len(x_t) > 3 else 0.0

            # Get XDP metrics (if enabled)
            xdp_metrics = self._get_xdp_metrics()

            if self.db_type == 'clickhouse':
                # ClickHouse insertion (edge deployment)
                data = [{
                    'timestamp': sample.timestamp,
                    'score': float(sample.score),
                    'rag_status': sample.rag_status,
                    'drift': float(sample.components['drift']),
                    'attack_probability': float(sample.components['attack_probability']),
                    'classifier_decay': float(sample.components['classifier_decay']),
                    'quantum_drift': float(sample.components['quantum_drift']),
                    'cpu_usage': cpu_usage,
                    'memory_usage': memory_usage,
                    'network_traffic': network_traffic,
                    'disk_io': disk_io,
                    'host': self.hostname,
                    'pod': self.pod_name,
                    # XDP metrics (0 if not enabled)
                    'xdp_total_packets': xdp_metrics.get('xdp_total_packets', 0),
                    'xdp_dropped_blocked': xdp_metrics.get('xdp_dropped_blocked', 0),
                    'xdp_dropped_rate_limit': xdp_metrics.get('xdp_dropped_rate_limit', 0),
                    'xdp_dropped_malformed': xdp_metrics.get('xdp_dropped_malformed', 0),
                    'xdp_passed': xdp_metrics.get('xdp_passed', 0),
                    'xdp_tcp_syn_flood': xdp_metrics.get('xdp_tcp_syn_flood', 0),
                    'xdp_udp_flood': xdp_metrics.get('xdp_udp_flood', 0),
                    'xdp_icmp_flood': xdp_metrics.get('xdp_icmp_flood', 0)
                }]

                self.db_client.execute(
                    'INSERT INTO qsecbit_scores VALUES',
                    data
                )

            elif self.db_type == 'doris':
                # Doris insertion (cloud backend with multi-tenancy)
                with self.db_client.cursor() as cursor:
                    sql = """
                    INSERT INTO qsecbit_scores (
                        tenant_id, timestamp, score, rag_status,
                        drift, attack_probability, classifier_decay, quantum_drift,
                        cpu_usage, memory_usage, network_traffic, disk_io,
                        host, pod,
                        xdp_total_packets, xdp_dropped_blocked, xdp_dropped_rate_limit,
                        xdp_dropped_malformed, xdp_passed, xdp_tcp_syn_flood,
                        xdp_udp_flood, xdp_icmp_flood
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(sql, (
                        self.tenant_id,
                        sample.timestamp,
                        float(sample.score),
                        sample.rag_status,
                        float(sample.components['drift']),
                        float(sample.components['attack_probability']),
                        float(sample.components['classifier_decay']),
                        float(sample.components['quantum_drift']),
                        cpu_usage,
                        memory_usage,
                        network_traffic,
                        disk_io,
                        self.hostname,
                        self.pod_name,
                        # XDP metrics
                        xdp_metrics.get('xdp_total_packets', 0),
                        xdp_metrics.get('xdp_dropped_blocked', 0),
                        xdp_metrics.get('xdp_dropped_rate_limit', 0),
                        xdp_metrics.get('xdp_dropped_malformed', 0),
                        xdp_metrics.get('xdp_passed', 0),
                        xdp_metrics.get('xdp_tcp_syn_flood', 0),
                        xdp_metrics.get('xdp_udp_flood', 0),
                        xdp_metrics.get('xdp_icmp_flood', 0)
                    ))

        except Exception as e:
            # Don't fail if database is unavailable
            print(f"Warning: Failed to save to {self.db_type}: {e}")

    def calculate(
        self,
        x_t: np.ndarray,
        p_attack: float,
        c_t: np.ndarray,
        q_t: Optional[float] = None,
        dt: float = 1.0,
        metadata: Optional[Dict] = None
    ) -> QsecbitSample:
        """
        Calculate qsecbit score for current system state
        
        Args:
            x_t: Current system telemetry vector
            p_attack: Predicted attack probability from ML model [0, 1]
            c_t: Classifier confidence vector
            q_t: Current system entropy (calculated if None)
            dt: Time elapsed since last measurement
            metadata: Additional context to store with sample
            
        Returns:
            QsecbitSample object with score and components
        """
        # Calculate entropy if not provided
        if q_t is None:
            q_t = self._system_entropy(x_t)
        
        # Compute components
        drift = self._drift(x_t)
        decay = self._classifier_decay(c_t, dt)
        qdrift = self._quantum_drift(q_t)
        
        # Weighted combination
        R = (
            self.config.alpha * drift +
            self.config.beta * p_attack +
            self.config.gamma * decay +
            self.config.delta * qdrift
        )
        
        # RAG classification
        rag = self._classify_rag(R)
        
        # Create sample
        sample = QsecbitSample(
            timestamp=datetime.now(),
            score=float(R),
            components={
                'drift': float(drift),
                'attack_probability': float(p_attack),
                'classifier_decay': float(decay),
                'quantum_drift': float(qdrift)
            },
            rag_status=rag,
            system_state=x_t.copy(),
            metadata=metadata or {}
        )

        # Save to database (ClickHouse for edge, Doris for cloud)
        self._save_to_database(sample, x_t)

        # Store in history
        self.history.append(sample)
        if len(self.history) > self.config.max_history_size:
            self.history.pop(0)

        return sample
    
    def _classify_rag(self, R: float) -> str:
        """Classify score into Red/Amber/Green status"""
        if R >= self.config.red_threshold:
            return "RED"
        elif R >= self.config.amber_threshold:
            return "AMBER"
        return "GREEN"
    
    def convergence_rate(self, window: Optional[int] = None) -> Optional[float]:
        """
        Calculate convergence rate (how quickly system returns to safe state)
        
        This is the key metric: time to return to GREEN status after RED/AMBER
        
        Returns:
            Average time to convergence in the recent window, or None if insufficient data
        """
        window = window or self.config.convergence_window
        
        if len(self.history) < window:
            return None
        
        recent = self.history[-window:]
        
        # Find transitions from RED/AMBER to GREEN
        convergence_times = []
        in_alert = False
        alert_start = None
        
        for i, sample in enumerate(recent):
            if sample.rag_status in ['RED', 'AMBER'] and not in_alert:
                in_alert = True
                alert_start = i
            elif sample.rag_status == 'GREEN' and in_alert:
                convergence_time = i - alert_start
                convergence_times.append(convergence_time)
                in_alert = False
        
        if not convergence_times:
            return None
        
        return float(np.mean(convergence_times))
    
    def trend(self, window: int = 20) -> str:
        """
        Analyze trend in recent qsecbit scores
        
        Returns: 'IMPROVING', 'STABLE', or 'DEGRADING'
        """
        if len(self.history) < window:
            return "INSUFFICIENT_DATA"
        
        recent_scores = [s.score for s in self.history[-window:]]
        
        # Linear regression on recent scores
        x = np.arange(len(recent_scores))
        slope, _ = np.polyfit(x, recent_scores, 1)
        
        if slope < -0.01:
            return "IMPROVING"
        elif slope > 0.01:
            return "DEGRADING"
        return "STABLE"
    
    def export_history(self, filepath: str):
        """Export measurement history to JSON"""
        data = {
            'config': {
                'alpha': self.config.alpha,
                'beta': self.config.beta,
                'gamma': self.config.gamma,
                'delta': self.config.delta,
                'amber_threshold': self.config.amber_threshold,
                'red_threshold': self.config.red_threshold
            },
            'baseline': {
                'mu': self.mu.tolist(),
                'cov': self.cov.tolist(),
                'quantum_anchor': self.q_anchor
            },
            'history': [s.to_dict() for s in self.history]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def summary_stats(self) -> Dict:
        """Get summary statistics of qsecbit measurements"""
        if not self.history:
            return {}
        
        scores = [s.score for s in self.history]
        rag_counts = {'GREEN': 0, 'AMBER': 0, 'RED': 0}
        for s in self.history:
            rag_counts[s.rag_status] += 1
        
        return {
            'mean_score': float(np.mean(scores)),
            'std_score': float(np.std(scores)),
            'min_score': float(np.min(scores)),
            'max_score': float(np.max(scores)),
            'rag_distribution': rag_counts,
            'convergence_rate': self.convergence_rate(),
            'trend': self.trend(),
            'total_samples': len(self.history)
        }


# ===============================================================================
# EXAMPLE USAGE
# ===============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("QSECBIT DEMONSTRATION")
    print("Quantum Security Bit: AI-Era Cyber Resilience Metric")
    print("=" * 70)
    
    # Define baseline system profile
    mu = np.array([0.1, 0.2, 0.15, 0.33])  # CPU, Memory, Network, Disk I/O
    cov = np.eye(4) * 0.02  # Low variance in normal operation
    quantum_anchor = 6.144  # Baseline entropy
    
    # Initialize qsecbit calculator
    config = QsecbitConfig(
        alpha=0.30,
        beta=0.30,
        gamma=0.20,
        delta=0.20,
        amber_threshold=0.45,
        red_threshold=0.70
    )
    
    q = Qsecbit(mu, cov, quantum_anchor, config)
    
    # Simulate attack scenario
    print("\n" + "-" * 70)
    print("SCENARIO: Simulating XSS → Memory Overflow → Orchestrator Pivot")
    print("-" * 70)
    
    scenarios = [
        {
            'name': 'Normal Operation',
            'x_t': np.array([0.12, 0.21, 0.16, 0.34]),
            'p_attack': 0.05,
            'c_t': np.array([0.95, 0.93, 0.94]),
            'q_t': 6.15
        },
        {
            'name': 'XSS Injection Detected',
            'x_t': np.array([0.15, 0.24, 0.22, 0.36]),
            'p_attack': 0.35,
            'c_t': np.array([0.88, 0.85, 0.87]),
            'q_t': 6.30
        },
        {
            'name': 'Memory Overflow Attempt',
            'x_t': np.array([0.25, 0.42, 0.35, 0.45]),
            'p_attack': 0.72,
            'c_t': np.array([0.76, 0.71, 0.73]),
            'q_t': 6.65
        },
        {
            'name': 'Orchestrator Pivot (Critical)',
            'x_t': np.array([0.45, 0.68, 0.55, 0.62]),
            'p_attack': 0.91,
            'c_t': np.array([0.62, 0.58, 0.60]),
            'q_t': 7.20
        },
        {
            'name': 'Containment + Mitigation',
            'x_t': np.array([0.28, 0.38, 0.32, 0.42]),
            'p_attack': 0.48,
            'c_t': np.array([0.81, 0.79, 0.80]),
            'q_t': 6.45
        },
        {
            'name': 'System Recovery',
            'x_t': np.array([0.14, 0.23, 0.18, 0.35]),
            'p_attack': 0.12,
            'c_t': np.array([0.92, 0.90, 0.91]),
            'q_t': 6.20
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        sample = q.calculate(
            x_t=scenario['x_t'],
            p_attack=scenario['p_attack'],
            c_t=scenario['c_t'],
            q_t=scenario['q_t'],
            dt=1.0,
            metadata={'scenario': scenario['name']}
        )
        
        print(f"\nStep {i}: {scenario['name']}")
        print(f"  Qsecbit Score:      {sample.score:.4f}")
        print(f"  RAG Status:         {sample.rag_status}")
        print(f"  Components:")
        print(f"    - Drift:          {sample.components['drift']:.4f}")
        print(f"    - Attack Prob:    {sample.components['attack_probability']:.4f}")
        print(f"    - Classifier:     {sample.components['classifier_decay']:.4f}")
        print(f"    - Quantum:        {sample.components['quantum_drift']:.4f}")
    
    # Summary statistics
    print("\n" + "=" * 70)
    print("SUMMARY STATISTICS")
    print("=" * 70)
    stats = q.summary_stats()
    print(f"Mean Score:           {stats['mean_score']:.4f}")
    print(f"Std Deviation:        {stats['std_score']:.4f}")
    print(f"Score Range:          [{stats['min_score']:.4f}, {stats['max_score']:.4f}]")
    print(f"Convergence Rate:     {stats['convergence_rate']:.2f} steps" if stats['convergence_rate'] else "N/A")
    print(f"Trend:                {stats['trend']}")
    print(f"RAG Distribution:     {stats['rag_distribution']}")
    
    print("\n" + "=" * 70)
    print("Qsecbit calculation complete. Export with q.export_history('qsecbit.json')")
    print("=" * 70)
