"""
Qsecbit: Quantum Security Bit - Cyber Resilience Metric

A resilience metric that measures the smallest unit where AI-driven attack
and defense reach equilibrium through continuous error correction.

Version 6.0 adds unified threat detection across OSI layers L2-L7:
- Layer 2: ARP Spoofing, MAC Flooding, VLAN Hopping, Evil Twin, Rogue DHCP
- Layer 3: IP Spoofing, ICMP Flood, Smurf Attack, Routing Attacks
- Layer 4: SYN Flood, Port Scan, TCP Reset, Session Hijack, UDP Flood
- Layer 5: SSL Strip, TLS Downgrade, Cert Pinning Bypass, Auth Bypass
- Layer 7: SQL Injection, XSS, DNS Tunneling, HTTP Flood, Malware C2

Author: Andrei Toma
License: Proprietary - see LICENSE in this directory
Version: 5.0.0
"""

import numpy as np
from scipy.spatial.distance import mahalanobis
from scipy.special import expit as logistic
from scipy.stats import entropy
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, List, TYPE_CHECKING
from datetime import datetime

if TYPE_CHECKING:
    from .threat_types import QsecbitUnifiedScore
import json
import os
import socket

# Import qsecbit submodules
from .nic_detector import NICDetector, NICCapability, XDPMode
from .xdp_manager import XDPManager, XDPStats
from .energy_monitor import EnergyMonitor, SystemEnergySnapshot, PIDEnergyStats

# Unified Engine (lazy import to avoid circular imports)
_unified_engine_module = None

def _get_unified_engine():
    """Lazy import of unified engine module."""
    global _unified_engine_module
    if _unified_engine_module is None:
        from . import unified_engine as _unified_engine_module
    return _unified_engine_module

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
    epsilon: float = 0.0  # Energy anomaly weight (0.0 = disabled, auto-adjusted if energy_monitoring_enabled)

    # RAG (Red/Amber/Green) thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.70

    # Logistic function parameters for drift normalization
    drift_slope: float = 3.5
    drift_center: float = 2.0

    # Temporal parameters
    max_history_size: int = 1000
    convergence_window: int = 10  # Number of samples to check convergence

    # Energy monitoring parameters
    energy_monitoring_enabled: bool = False
    energy_spike_threshold: float = 2.5  # Z-score threshold for spike detection
    energy_ewma_alpha: float = 0.3       # EWMA smoothing factor (0-1)
    energy_baseline_window: int = 100    # Samples for baseline calculation

    def __post_init__(self):
        """Validate configuration"""
        # If energy monitoring is enabled, auto-adjust weights
        if self.energy_monitoring_enabled and self.epsilon == 0.0:
            # Redistribute weights to include energy component (15%)
            self.alpha = 0.25   # System drift (was 30%)
            self.beta = 0.25    # Attack probability (was 30%)
            self.gamma = 0.20   # Classifier decay
            self.delta = 0.15   # Quantum drift (was 20%)
            self.epsilon = 0.15 # Energy anomaly (new)

        weight_sum = self.alpha + self.beta + self.gamma + self.delta + self.epsilon
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
    Qsecbit: Quantum Security Bit - Cyber Resilience Metric

    Measures cyber resilience as the smallest unit where AI-driven attack
    and defense reach equilibrium through continuous error correction.

    The metric combines:
    - Statistical drift from baseline (Mahalanobis distance)
    - ML-predicted attack probability
    - Classifier confidence decay rate
    - System entropy deviation (quantum drift)
    - Energy consumption anomalies (optional)
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

        # Energy monitoring integration (RAPL + per-PID power tracking)
        self.energy_monitoring_enabled = self.config.energy_monitoring_enabled
        self.energy_monitor: Optional[EnergyMonitor] = None

        if self.energy_monitoring_enabled:
            try:
                self.energy_monitor = EnergyMonitor(
                    ewma_alpha=self.config.energy_ewma_alpha,
                    spike_threshold=self.config.energy_spike_threshold,
                    baseline_window=self.config.energy_baseline_window
                )
                # Capture initial snapshot
                self.energy_monitor.capture_snapshot()
                print("✓ Energy consumption monitoring enabled (RAPL + per-PID tracking)")
                if self.energy_monitor.rapl_available:
                    print("  - RAPL energy counters detected")
                else:
                    print("  - RAPL not available, using CPU-based estimation only")
            except Exception as e:
                print(f"Warning: Energy monitoring initialization failed: {e}")
                self.energy_monitoring_enabled = False

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

            # Get energy metrics (if enabled)
            energy_metrics = sample.metadata.get('energy', {})

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
                    'energy_anomaly': float(sample.components.get('energy_anomaly', 0.0)),
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
                    'xdp_icmp_flood': xdp_metrics.get('xdp_icmp_flood', 0),
                    # Energy metrics (0 if not enabled)
                    'package_watts': float(energy_metrics.get('package_watts', 0.0)),
                    'nic_processes_watts': float(energy_metrics.get('nic_processes_watts', 0.0)),
                    'xdp_processes_watts': float(energy_metrics.get('xdp_processes_watts', 0.0)),
                    'has_energy_anomaly': int(energy_metrics.get('has_energy_anomaly', False)),
                    'nic_spike': int(energy_metrics.get('nic_spike', False)),
                    'xdp_spike': int(energy_metrics.get('xdp_spike', False))
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
                        drift, attack_probability, classifier_decay, quantum_drift, energy_anomaly,
                        cpu_usage, memory_usage, network_traffic, disk_io,
                        host, pod,
                        xdp_total_packets, xdp_dropped_blocked, xdp_dropped_rate_limit,
                        xdp_dropped_malformed, xdp_passed, xdp_tcp_syn_flood,
                        xdp_udp_flood, xdp_icmp_flood,
                        package_watts, nic_processes_watts, xdp_processes_watts,
                        has_energy_anomaly, nic_spike, xdp_spike
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                        float(sample.components.get('energy_anomaly', 0.0)),
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
                        xdp_metrics.get('xdp_icmp_flood', 0),
                        # Energy metrics
                        float(energy_metrics.get('package_watts', 0.0)),
                        float(energy_metrics.get('nic_processes_watts', 0.0)),
                        float(energy_metrics.get('xdp_processes_watts', 0.0)),
                        int(energy_metrics.get('has_energy_anomaly', False)),
                        int(energy_metrics.get('nic_spike', False)),
                        int(energy_metrics.get('xdp_spike', False))
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

        # Energy anomaly component (if enabled)
        energy_anomaly = 0.0
        energy_metadata = {}

        if self.energy_monitoring_enabled and self.energy_monitor:
            try:
                # Capture energy snapshot
                snapshot = self.energy_monitor.capture_snapshot()

                if snapshot:
                    # Detect anomalies
                    anomalies = self.energy_monitor.detect_anomalies(snapshot)
                    energy_anomaly = anomalies['anomaly_score']

                    # Add energy metadata
                    energy_metadata = {
                        'package_watts': snapshot.package_watts,
                        'nic_processes_watts': snapshot.nic_processes_watts,
                        'xdp_processes_watts': snapshot.xdp_processes_watts,
                        'has_energy_anomaly': anomalies['has_anomaly'],
                        'nic_spike': anomalies['nic_spike'],
                        'xdp_spike': anomalies['xdp_spike'],
                        'energy_spike_pids': [
                            {'pid': p['pid'], 'name': p['name'], 'watts': p['watts'], 'z_score': p['z_score']}
                            for p in anomalies['spike_pids'][:5]  # Top 5 spikes
                        ]
                    }

            except Exception as e:
                print(f"Warning: Energy monitoring failed: {e}")

        # Weighted combination
        R = (
            self.config.alpha * drift +
            self.config.beta * p_attack +
            self.config.gamma * decay +
            self.config.delta * qdrift +
            self.config.epsilon * energy_anomaly
        )

        # RAG classification
        rag = self._classify_rag(R)

        # Create sample with energy metadata
        components = {
            'drift': float(drift),
            'attack_probability': float(p_attack),
            'classifier_decay': float(decay),
            'quantum_drift': float(qdrift)
        }

        if self.energy_monitoring_enabled:
            components['energy_anomaly'] = float(energy_anomaly)

        # Merge metadata
        final_metadata = metadata or {}
        if energy_metadata:
            final_metadata['energy'] = energy_metadata

        sample = QsecbitSample(
            timestamp=datetime.now(),
            score=float(R),
            components=components,
            rag_status=rag,
            system_state=x_t.copy(),
            metadata=final_metadata
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

    # ==========================================================================
    # UNIFIED THREAT DETECTION
    # ==========================================================================

    def create_unified_engine(
        self,
        deployment_type: str = 'guardian',
        enable_response: bool = False,
        data_dir: str = '/opt/hookprobe/data'
    ):
        """
        Create a UnifiedThreatEngine instance with this Qsecbit's XDP manager.

        The unified engine provides comprehensive threat detection across OSI
        layers L2-L7, including ML-based classification and automated response.

        Args:
            deployment_type: One of 'guardian', 'fortress', 'nexus', 'mssp'
            enable_response: Enable automated threat response
            data_dir: Directory for detector state

        Returns:
            UnifiedThreatEngine instance

        Example:
            engine = qsecbit.create_unified_engine(deployment_type='guardian')
            score = engine.detect()
            print(f"Unified Score: {score.score} ({score.rag_status})")
            for threat in score.threats:
                print(f"  - {threat.attack_type.name}: {threat.description}")
        """
        unified = _get_unified_engine()

        # Map string to DeploymentType enum
        deployment_map = {
            'guardian': unified.DeploymentType.GUARDIAN,
            'fortress': unified.DeploymentType.FORTRESS,
            'nexus': unified.DeploymentType.NEXUS,
            'mssp': unified.DeploymentType.MSSP,
        }
        deployment = deployment_map.get(deployment_type.lower(), unified.DeploymentType.GUARDIAN)

        # Create config with deployment-specific weights
        config = unified.UnifiedEngineConfig(deployment_type=deployment)

        # Create unified engine with same XDP manager
        engine = unified.UnifiedThreatEngine(
            xdp_manager=self.xdp_manager,
            energy_monitor=self.energy_monitor,
            config=config,
            data_dir=data_dir
        )

        return engine

    def detect_threats(
        self,
        deployment_type: str = 'guardian',
        enable_response: bool = False
    ) -> 'QsecbitUnifiedScore':
        """
        Perform comprehensive threat detection using unified engine.

        This is the single-source-of-truth for threat detection, combining:
        - Layer 2: ARP Spoofing, MAC Flooding, VLAN Hopping, Evil Twin
        - Layer 3: IP Spoofing, ICMP Flood, Smurf Attack
        - Layer 4: SYN Flood, Port Scan, TCP Reset, Session Hijack
        - Layer 5: SSL Strip, TLS Downgrade, Cert Pinning Bypass
        - Layer 7: SQL Injection, XSS, DNS Tunneling, HTTP Flood

        Args:
            deployment_type: One of 'guardian', 'fortress', 'nexus', 'mssp'
            enable_response: Enable automated threat response

        Returns:
            QsecbitUnifiedScore with detected threats and unified score

        Example:
            score = qsecbit.detect_threats(deployment_type='fortress')
            if score.rag_status == 'RED':
                print(f"CRITICAL: {len(score.threats)} active threats!")
                for threat in score.threats:
                    print(f"  [{threat.severity.name}] {threat.attack_type.name}")
        """
        if not hasattr(self, '_unified_engine') or self._unified_engine is None:
            self._unified_engine = self.create_unified_engine(
                deployment_type=deployment_type,
                enable_response=enable_response
            )

        return self._unified_engine.detect()

    def get_threat_summary(self) -> Dict:
        """
        Get summary of detected threats from unified engine.

        Returns:
            Dict with threat statistics by layer and type
        """
        if not hasattr(self, '_unified_engine') or self._unified_engine is None:
            return {'error': 'Unified engine not initialized. Call detect_threats() first.'}

        return self._unified_engine.get_statistics()


# ===============================================================================
# EXAMPLE USAGE
# ===============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Qsecbit Unified - Unified Threat Detection')
    parser.add_argument('--mode', choices=['legacy', 'unified', 'both'], default='both',
                        help='Detection mode: legacy (v5.0), unified (Unified), or both')
    parser.add_argument('--deployment', choices=['guardian', 'fortress', 'nexus', 'mssp'],
                        default='guardian', help='Deployment type for unified engine')
    args = parser.parse_args()

    print("=" * 70)
    print("QSECBIT 5.0 DEMONSTRATION")
    print("Quantum Security Bit: Unified Cyber Resilience Metric")
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
        red_threshold=0.70,
        energy_monitoring_enabled=False,
    )

    q = Qsecbit(mu, cov, quantum_anchor, config)

    # =========================================================================
    # v5.0 LEGACY MODE - Telemetry-based resilience scoring
    # =========================================================================
    if args.mode in ['legacy', 'both']:
        print("\n" + "-" * 70)
        print("v5.0 LEGACY MODE: Telemetry-Based Resilience Scoring")
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
        stats = q.summary_stats()
        print(f"\nLegacy Summary: Mean={stats['mean_score']:.3f}, Trend={stats['trend']}")

    # =========================================================================
    # UNIFIED MODE - Comprehensive OSI Layer Detection
    # =========================================================================
    if args.mode in ['unified', 'both']:
        print("\n" + "-" * 70)
        print(f"UNIFIED MODE: OSI Layer L2-L7 Threat Detection")
        print(f"Deployment Type: {args.deployment.upper()}")
        print("-" * 70)

        print("\nInitializing unified engine...")

        # Create unified engine
        engine = q.create_unified_engine(
            deployment_type=args.deployment,
            enable_response=False  # Set True for automated response
        )

        print("Running comprehensive threat detection...")

        # Run detection
        score = engine.detect()

        print(f"\n{'=' * 50}")
        print(f"UNIFIED QSECBIT SCORE: {score.score:.4f}")
        print(f"RAG STATUS: {score.rag_status}")
        print(f"{'=' * 50}")

        # Layer breakdown
        print("\nLAYER BREAKDOWN:")
        for layer_score in score.layer_scores:
            status_icon = {
                'GREEN': '✓',
                'AMBER': '⚠',
                'RED': '✗'
            }.get(layer_score.rag_status, '?')
            print(f"  {status_icon} {layer_score.layer.name}: {layer_score.score:.3f} ({layer_score.rag_status})")
            print(f"      Weight: {layer_score.weight:.2f}, Threats: {layer_score.threat_count}")

        # Detected threats
        if score.threats:
            print(f"\nDETECTED THREATS ({len(score.threats)}):")
            for threat in score.threats[:10]:  # Show first 10
                severity_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(threat.severity.name, '⚪')
                print(f"  {severity_color} [{threat.severity.name}] {threat.attack_type.name}")
                print(f"      {threat.description[:60]}...")
                if threat.source_ip:
                    print(f"      Source: {threat.source_ip}")
        else:
            print("\n✓ No active threats detected")

        # Additional metrics
        print(f"\nADDITIONAL METRICS:")
        print(f"  Energy Score:       {score.energy_score:.3f}")
        print(f"  Behavioral Score:   {score.behavioral_score:.3f}")
        print(f"  Chain Correlation:  {score.chain_correlation:.3f}")
        print(f"  Trend:              {score.trend}")
        if score.convergence_rate:
            print(f"  Convergence Rate:   {score.convergence_rate:.2f}")

        # Statistics
        stats = engine.get_statistics()
        print(f"\nSTATISTICS:")
        print(f"  Total Detection Runs: {stats['total_detections']}")
        print(f"  Total Threats Found:  {stats['total_threats']}")
        print(f"  By Severity:")
        for sev, count in stats.get('threats_by_severity', {}).items():
            if count > 0:
                print(f"    - {sev}: {count}")

    print("\n" + "=" * 70)
    print("Qsecbit Unified - Single Source of Truth for Cyber Protection")
    print("=" * 70)
