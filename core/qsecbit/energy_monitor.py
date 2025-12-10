"""
Energy Consumption Monitoring and Anomaly Detection

Provides early warning system by detecting anomalous power consumption patterns,
especially useful for DDoS detection and cryptomining malware.

Algorithm:
1. Read RAPL energy counters (Intel CPUs)
2. Track per-PID CPU time from /proc/[pid]/stat
3. Calculate power share per PID based on CPU usage
4. Build time-series of PID power consumption
5. Detect anomalies using EWMA + Z-score
6. Alert on spikes correlated with NIC/XDP processes
7. Network direction-aware energy efficiency analysis (NEW v5.0)

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 5.0.0
"""

import os
import psutil
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict
from collections import deque
from enum import Enum
import numpy as np


class DeploymentRole(Enum):
    """
    Deployment role for network direction analysis

    PUBLIC_SERVER: Expects IN > OUT (web servers, APIs)
    USER_ENDPOINT: Expects OUT > IN (clients, workstations)
    """
    PUBLIC_SERVER = "PUBLIC_SERVER"
    USER_ENDPOINT = "USER_ENDPOINT"


@dataclass
class PIDEnergyStats:
    """Per-PID energy consumption statistics"""
    pid: int
    name: str
    cpu_time: float  # Total CPU time in seconds
    cpu_share: float  # CPU usage percentage
    estimated_watts: float  # Estimated power consumption
    is_nic_related: bool = False  # NIC interrupt handler or driver
    is_xdp_related: bool = False  # XDP/eBPF related process
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class NetworkEnergyStats:
    """
    Network direction-aware energy efficiency statistics

    Tracks Energy-Per-Packet (EPP) and traffic direction for role-based anomaly detection.
    This helps detect:
    - Compromised endpoints sending spam/DDoS (OUT spike on USER_ENDPOINT)
    - Servers under attack (IN spike on PUBLIC_SERVER)
    - Data exfiltration (abnormal OUT traffic pattern)
    - Cryptomining + network activity correlation
    """
    timestamp: datetime
    interface: str
    packets_sent: int
    packets_recv: int
    delta_packets_sent: int = 0
    delta_packets_recv: int = 0
    delta_energy_mj: float = 0.0  # Energy delta in millijoules
    epp: float = 0.0  # Energy per packet (mJ/packet)
    out_in_ratio: float = 0.0  # Traffic direction ratio
    total_packets: int = 0  # Total packets in interval
    anomaly_score: float = 0.0  # Normalized 0-100 score


@dataclass
class SystemEnergySnapshot:
    """System-wide energy snapshot"""
    timestamp: datetime
    total_cpu_time: float
    rapl_energy_uj: int  # RAPL energy in microjoules
    package_watts: float  # Estimated package wattage
    pid_stats: List[PIDEnergyStats]
    nic_processes_watts: float = 0.0  # Total power from NIC-related processes
    xdp_processes_watts: float = 0.0  # Total power from XDP-related processes
    network_stats: Optional[NetworkEnergyStats] = None  # Network energy efficiency (NEW)


class EnergyMonitor:
    """
    Monitor system energy consumption via RAPL and per-PID CPU tracking.

    v5.0 Enhancement: Network direction-aware energy efficiency analysis
    """

    def __init__(
        self,
        ewma_alpha: float = 0.3,
        spike_threshold: float = 2.5,
        baseline_window: int = 100,
        network_interface: Optional[str] = None,
        deployment_role: DeploymentRole = DeploymentRole.PUBLIC_SERVER,
        network_monitoring_enabled: bool = True
    ):
        """
        Initialize energy monitor

        Args:
            ewma_alpha: EWMA smoothing factor (0-1, lower = more smoothing)
            spike_threshold: Z-score threshold for spike detection
            baseline_window: Number of samples for baseline calculation
            network_interface: Network interface to monitor (auto-detect if None)
            deployment_role: PUBLIC_SERVER or USER_ENDPOINT for direction analysis
            network_monitoring_enabled: Enable network energy efficiency tracking
        """
        self.ewma_alpha = ewma_alpha
        self.spike_threshold = spike_threshold
        self.baseline_window = baseline_window
        self.deployment_role = deployment_role
        self.network_monitoring_enabled = network_monitoring_enabled

        # State tracking
        self.prev_snapshot: Optional[SystemEnergySnapshot] = None
        self.history: List[SystemEnergySnapshot] = []
        self.pid_power_history: Dict[int, List[float]] = {}  # PID -> [watts over time]
        self.pid_ewma: Dict[int, float] = {}  # PID -> EWMA of power
        self.pid_baseline_mean: Dict[int, float] = {}
        self.pid_baseline_std: Dict[int, float] = {}

        # Network energy efficiency tracking (NEW v5.0)
        self.network_interface = network_interface or self._detect_primary_interface()
        self.epp_history: deque = deque(maxlen=50)  # Energy-per-packet history
        self.packet_history: deque = deque(maxlen=50)  # Packet count history
        self.prev_net_stats: Optional[tuple] = None  # (packets_sent, packets_recv)

        # RAPL availability
        self.rapl_available = False
        self.rapl_package_path: Optional[Path] = None
        self._detect_rapl()

        # NIC and XDP process patterns
        self.nic_process_patterns = [
            'irq/',  # Interrupt handlers
            'ksoftirqd',  # Soft IRQ daemon
            'napi/',  # NAPI polling threads
        ]
        self.xdp_process_patterns = [
            'xdp',
            'bpf',
            'ebpf',
        ]

    def _detect_primary_interface(self) -> str:
        """
        Auto-detect primary network interface (highest packet count)

        Returns:
            Primary interface name (e.g., 'eth0', 'enp1s0', 'wlan0')
        """
        try:
            net_io = psutil.net_io_counters(pernic=True)
            # Filter out loopback
            interfaces = {name: stats for name, stats in net_io.items() if not name.startswith('lo')}

            if not interfaces:
                return "eth0"  # Fallback

            # Select interface with highest total packet count
            primary = max(interfaces.items(), key=lambda x: x[1].packets_sent + x[1].packets_recv)
            print(f"✓ Primary network interface detected: {primary[0]}")
            return primary[0]
        except Exception as e:
            print(f"Warning: Failed to detect primary interface: {e}")
            return "eth0"

    def _detect_rapl(self):
        """Detect RAPL (Running Average Power Limit) support"""
        rapl_base = Path("/sys/class/powercap/intel-rapl")
        if not rapl_base.exists():
            print("Warning: RAPL not available (Intel CPU required)")
            return

        # Find package energy counter (usually intel-rapl:0)
        for rapl_dir in rapl_base.glob("intel-rapl:*"):
            name_file = rapl_dir / "name"
            if name_file.exists():
                name = name_file.read_text().strip()
                if name == "package-0":  # Primary CPU package
                    energy_file = rapl_dir / "energy_uj"
                    if energy_file.exists():
                        self.rapl_package_path = energy_file
                        self.rapl_available = True
                        print(f"✓ RAPL energy monitoring enabled: {rapl_dir}")
                        return

        print("Warning: RAPL package energy counter not found")

    def _read_rapl_energy(self) -> int:
        """Read RAPL energy counter in microjoules"""
        if not self.rapl_available or not self.rapl_package_path:
            return 0

        try:
            return int(self.rapl_package_path.read_text().strip())
        except Exception as e:
            print(f"Warning: Failed to read RAPL energy: {e}")
            return 0

    def _get_total_cpu_time(self) -> float:
        """Get total CPU time from /proc/stat"""
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()  # First line is total CPU stats
                fields = line.split()[1:]  # Skip 'cpu' label
                # Sum all CPU time fields (user, nice, system, idle, iowait, irq, softirq, ...)
                return sum(float(x) for x in fields) / os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        except Exception as e:
            print(f"Warning: Failed to read /proc/stat: {e}")
            return 0.0

    def _get_pid_stats(self) -> List[PIDEnergyStats]:
        """Get CPU usage stats for all processes"""
        pid_stats = []

        try:
            for pid_dir in Path('/proc').glob('[0-9]*'):
                try:
                    pid = int(pid_dir.name)
                    stat_file = pid_dir / 'stat'

                    if not stat_file.exists():
                        continue

                    stat_content = stat_file.read_text()
                    # Parse /proc/[pid]/stat format
                    parts = stat_content.split(')')
                    if len(parts) < 2:
                        continue

                    comm = stat_content.split('(')[1].split(')')[0]
                    fields = parts[1].split()

                    # utime is at index 11 (0-indexed after removing comm)
                    # stime is at index 12
                    if len(fields) < 13:
                        continue

                    utime = int(fields[11])  # User mode CPU time
                    stime = int(fields[12])  # Kernel mode CPU time
                    total_time = (utime + stime) / os.sysconf(os.sysconf_names['SC_CLK_TCK'])

                    # Check if NIC or XDP related
                    is_nic_related = any(pattern in comm for pattern in self.nic_process_patterns)
                    is_xdp_related = any(pattern in comm.lower() for pattern in self.xdp_process_patterns)

                    pid_stats.append(PIDEnergyStats(
                        pid=pid,
                        name=comm,
                        cpu_time=total_time,
                        cpu_share=0.0,  # Calculated later
                        estimated_watts=0.0,  # Calculated later
                        is_nic_related=is_nic_related,
                        is_xdp_related=is_xdp_related
                    ))

                except (ValueError, FileNotFoundError, PermissionError):
                    continue

        except Exception as e:
            print(f"Warning: Failed to read process stats: {e}")

        return pid_stats

    def _get_nic_packets(self) -> tuple[int, int]:
        """
        Get current packet counts for primary network interface

        Returns:
            Tuple of (packets_sent, packets_recv)
        """
        try:
            net_io = psutil.net_io_counters(pernic=True)
            stats = net_io.get(self.network_interface)
            if stats:
                return (stats.packets_sent, stats.packets_recv)
            return (0, 0)
        except Exception as e:
            print(f"Warning: Failed to read NIC packets: {e}")
            return (0, 0)

    def _compute_epp(self, delta_energy_mj: float, delta_packets: int) -> float:
        """
        Calculate Energy-Per-Packet (EPP)

        Args:
            delta_energy_mj: Energy consumed in millijoules
            delta_packets: Total packets sent+received

        Returns:
            EPP in millijoules per packet
        """
        if delta_packets <= 0:
            return 0.0
        return delta_energy_mj / delta_packets

    def _compute_out_in_ratio(self, packets_sent: int, packets_recv: int) -> float:
        """
        Calculate OUT/IN traffic ratio

        Args:
            packets_sent: Packets sent
            packets_recv: Packets received

        Returns:
            OUT/IN ratio (1.0 = balanced, >1 = more outbound, <1 = more inbound)
        """
        if packets_recv == 0:
            return float('inf') if packets_sent > 0 else 0.0
        return packets_sent / packets_recv

    def _compute_network_anomaly_score(
        self,
        epp: float,
        out_in_ratio: float,
        packet_burst: int
    ) -> float:
        """
        Compute role-aware network anomaly score

        Detects:
        - High EPP (energy-inefficient, possible cryptomining + network activity)
        - Direction anomalies based on deployment role
        - Packet bursts (DDoS, data exfiltration)

        Args:
            epp: Energy per packet (mJ/packet)
            out_in_ratio: OUT/IN traffic ratio
            packet_burst: Packets in current interval

        Returns:
            Anomaly score 0-100 (0=normal, 100=critical)
        """
        # Component weights
        W_EPP = 0.5      # Energy efficiency
        W_RATIO = 0.3    # Direction anomaly
        W_BURST = 0.2    # Packet burst

        # EPP normalization (suspicious if > 5 mJ/packet)
        epp_norm = min(epp / 5.0, 1.0)

        # Direction anomaly (role-aware)
        if self.deployment_role == DeploymentRole.PUBLIC_SERVER:
            # Expect IN > OUT (ratio < 1), anomaly if OUT > IN
            ratio_deviation = max(0, out_in_ratio - 1.0)  # Anomaly if ratio > 1
        else:  # USER_ENDPOINT
            # Expect OUT > IN (ratio > 1), anomaly if IN > OUT
            ratio_deviation = max(0, 1.0 - out_in_ratio)  # Anomaly if ratio < 1

        ratio_norm = min(ratio_deviation / 3.0, 1.0)  # Cap at 3x deviation

        # Packet burst normalization (suspicious if > 5000 packets/interval)
        burst_norm = min(packet_burst / 5000.0, 1.0)

        # Weighted score (0-100)
        score = 100 * (W_EPP * epp_norm + W_RATIO * ratio_norm + W_BURST * burst_norm)

        return score

    def capture_snapshot(self) -> Optional[SystemEnergySnapshot]:
        """
        Capture current system energy snapshot

        Returns:
            SystemEnergySnapshot with RAPL and per-PID power estimates
        """
        now = datetime.now()
        rapl_energy = self._read_rapl_energy()
        total_cpu_time = self._get_total_cpu_time()
        pid_stats = self._get_pid_stats()

        snapshot = SystemEnergySnapshot(
            timestamp=now,
            total_cpu_time=total_cpu_time,
            rapl_energy_uj=rapl_energy,
            package_watts=0.0,  # Calculated below
            pid_stats=pid_stats
        )

        # Calculate deltas from previous snapshot
        if self.prev_snapshot:
            dt = (now - self.prev_snapshot.timestamp).total_seconds()
            if dt > 0:
                # Calculate package wattage from RAPL
                energy_delta_uj = rapl_energy - self.prev_snapshot.rapl_energy_uj
                # Handle RAPL counter overflow (typically 32-bit or 64-bit)
                if energy_delta_uj < 0:
                    # Assume 64-bit counter overflow
                    energy_delta_uj += 2**64

                energy_delta_j = energy_delta_uj / 1_000_000  # Convert µJ to J
                package_watts = energy_delta_j / dt
                snapshot.package_watts = package_watts

                # Calculate per-PID CPU share and power estimate
                total_cpu_delta = total_cpu_time - self.prev_snapshot.total_cpu_time

                if total_cpu_delta > 0:
                    nic_total_watts = 0.0
                    xdp_total_watts = 0.0

                    for current_stat in pid_stats:
                        # Find previous stat for this PID
                        prev_stat = next(
                            (s for s in self.prev_snapshot.pid_stats if s.pid == current_stat.pid),
                            None
                        )

                        if prev_stat:
                            cpu_time_delta = current_stat.cpu_time - prev_stat.cpu_time
                            cpu_share = (cpu_time_delta / total_cpu_delta) * 100  # Percentage
                            estimated_watts = (cpu_time_delta / total_cpu_delta) * package_watts

                            current_stat.cpu_share = cpu_share
                            current_stat.estimated_watts = estimated_watts

                            # Track NIC and XDP process power
                            if current_stat.is_nic_related:
                                nic_total_watts += estimated_watts
                            if current_stat.is_xdp_related:
                                xdp_total_watts += estimated_watts

                            # Update PID power history
                            if current_stat.pid not in self.pid_power_history:
                                self.pid_power_history[current_stat.pid] = []
                            self.pid_power_history[current_stat.pid].append(estimated_watts)

                            # Keep history bounded
                            if len(self.pid_power_history[current_stat.pid]) > 1000:
                                self.pid_power_history[current_stat.pid].pop(0)

                    snapshot.nic_processes_watts = nic_total_watts
                    snapshot.xdp_processes_watts = xdp_total_watts

                # Network energy efficiency analysis (NEW v5.0)
                if self.network_monitoring_enabled and self.rapl_available:
                    packets_sent, packets_recv = self._get_nic_packets()

                    # Calculate network stats if we have previous data
                    if self.prev_net_stats:
                        prev_sent, prev_recv = self.prev_net_stats

                        delta_sent = packets_sent - prev_sent
                        delta_recv = packets_recv - prev_recv
                        delta_packets = delta_sent + delta_recv

                        # Energy consumed during this interval (mJ)
                        delta_energy_mj = energy_delta_j * 1000  # J to mJ

                        # Calculate metrics
                        epp = self._compute_epp(delta_energy_mj, delta_packets)
                        out_in_ratio = self._compute_out_in_ratio(delta_sent, delta_recv)
                        anomaly_score = self._compute_network_anomaly_score(epp, out_in_ratio, delta_packets)

                        # Store in history
                        self.epp_history.append(epp)
                        self.packet_history.append(delta_packets)

                        # Create network stats
                        snapshot.network_stats = NetworkEnergyStats(
                            timestamp=now,
                            interface=self.network_interface,
                            packets_sent=packets_sent,
                            packets_recv=packets_recv,
                            delta_packets_sent=delta_sent,
                            delta_packets_recv=delta_recv,
                            delta_energy_mj=delta_energy_mj,
                            epp=epp,
                            out_in_ratio=out_in_ratio,
                            total_packets=delta_packets,
                            anomaly_score=anomaly_score
                        )

                    # Store current stats for next iteration
                    self.prev_net_stats = (packets_sent, packets_recv)

        self.prev_snapshot = snapshot
        self.history.append(snapshot)

        # Keep history bounded
        if len(self.history) > 1000:
            self.history.pop(0)

        return snapshot

    def update_baselines(self):
        """Update baseline statistics for all tracked PIDs"""
        for pid, power_history in self.pid_power_history.items():
            if len(power_history) >= self.baseline_window:
                recent = power_history[-self.baseline_window:]
                self.pid_baseline_mean[pid] = np.mean(recent)
                self.pid_baseline_std[pid] = np.std(recent)

    def detect_anomalies(self, snapshot: SystemEnergySnapshot) -> Dict[str, any]:
        """
        Detect power consumption anomalies using EWMA and Z-score

        Returns:
            Dictionary with anomaly detection results
        """
        anomalies = {
            'has_anomaly': False,
            'anomaly_score': 0.0,  # Normalized 0-1
            'spike_pids': [],
            'nic_spike': False,
            'xdp_spike': False,
            'baseline_deviation': 0.0
        }

        # Update EWMA for all current PIDs
        for stat in snapshot.pid_stats:
            pid = stat.pid
            watts = stat.estimated_watts

            if pid not in self.pid_ewma:
                self.pid_ewma[pid] = watts
            else:
                # Exponentially weighted moving average
                self.pid_ewma[pid] = self.ewma_alpha * watts + (1 - self.ewma_alpha) * self.pid_ewma[pid]

        # Update baselines periodically
        self.update_baselines()

        # Detect spikes using Z-score
        spike_scores = []
        for stat in snapshot.pid_stats:
            pid = stat.pid

            if pid in self.pid_baseline_mean and pid in self.pid_baseline_std:
                mean = self.pid_baseline_mean[pid]
                std = self.pid_baseline_std[pid]

                if std > 0:
                    z_score = (stat.estimated_watts - mean) / std

                    if z_score > self.spike_threshold:
                        anomalies['spike_pids'].append({
                            'pid': pid,
                            'name': stat.name,
                            'watts': stat.estimated_watts,
                            'baseline': mean,
                            'z_score': z_score,
                            'is_nic_related': stat.is_nic_related,
                            'is_xdp_related': stat.is_xdp_related
                        })
                        spike_scores.append(z_score)

                        if stat.is_nic_related:
                            anomalies['nic_spike'] = True
                        if stat.is_xdp_related:
                            anomalies['xdp_spike'] = True

        # Calculate overall anomaly score (normalized)
        if spike_scores:
            anomalies['has_anomaly'] = True
            # Max Z-score normalized to 0-1 (cap at 10 sigma)
            anomalies['anomaly_score'] = min(1.0, max(spike_scores) / 10.0)

        # Check for baseline deviation in NIC/XDP processes
        if len(self.history) >= 2:
            prev_nic_watts = self.history[-2].nic_processes_watts
            curr_nic_watts = snapshot.nic_processes_watts

            if prev_nic_watts > 0:
                nic_deviation = (curr_nic_watts - prev_nic_watts) / prev_nic_watts
                anomalies['baseline_deviation'] = nic_deviation

                # Flag if NIC power increased by >50%
                if nic_deviation > 0.5:
                    anomalies['nic_spike'] = True
                    anomalies['has_anomaly'] = True

        return anomalies
