"""
AIOCHI Real Metrics Engine
Unified metrics collection, storage, and analysis for the AIOCHI dashboard.

Philosophy: Real data, not placeholders. Every metric should come from
actual network measurements or be clearly marked as unavailable.

Data Flow:
1. SLA AI Collector (high-fidelity, if available)
2. Direct measurements (ping, /proc/net/dev)
3. Cached values (with staleness tracking)
4. ClickHouse storage (time-series analytics)
"""

import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class MetricSource(Enum):
    """Source of metrics data."""
    SLAAI = "slaai"           # SLA AI high-fidelity collector
    DIRECT = "direct"         # Direct measurement (ping, proc)
    CACHED = "cached"         # Cached from previous collection
    UNAVAILABLE = "unavailable"


@dataclass
class RealMetrics:
    """Real network metrics with source tracking."""
    # Core metrics
    health_score: int = 0              # 0-100 overall health
    latency_ms: float = 0.0            # RTT to gateway/internet
    jitter_ms: float = 0.0             # Latency variation
    packet_loss_pct: float = 0.0       # Packet loss percentage
    bandwidth_rx_mbps: float = 0.0     # Download bandwidth
    bandwidth_tx_mbps: float = 0.0     # Upload bandwidth
    bandwidth_used_pct: float = 0.0    # Bandwidth utilization
    uptime_pct: float = 100.0          # Network uptime

    # Security metrics
    threats_blocked: int = 0           # Blocked threats count
    dns_queries_blocked: int = 0       # Blocked DNS queries
    active_connections: int = 0        # Active connection count

    # WiFi metrics (if applicable)
    signal_dbm: int = -100             # WiFi signal strength
    interference_score: float = 0.0    # WiFi interference (0-1)

    # Meta
    source: MetricSource = MetricSource.UNAVAILABLE
    timestamp: datetime = field(default_factory=datetime.now)
    collection_time_ms: float = 0.0    # How long collection took

    def to_dict(self) -> Dict[str, Any]:
        return {
            "health_score": self.health_score,
            "latency_ms": round(self.latency_ms, 2),
            "jitter_ms": round(self.jitter_ms, 2),
            "packet_loss_pct": round(self.packet_loss_pct, 2),
            "bandwidth_rx_mbps": round(self.bandwidth_rx_mbps, 2),
            "bandwidth_tx_mbps": round(self.bandwidth_tx_mbps, 2),
            "bandwidth_used_pct": round(self.bandwidth_used_pct, 1),
            "uptime_pct": round(self.uptime_pct, 2),
            "threats_blocked": self.threats_blocked,
            "dns_queries_blocked": self.dns_queries_blocked,
            "active_connections": self.active_connections,
            "signal_dbm": self.signal_dbm,
            "interference_score": round(self.interference_score, 2),
            "source": self.source.value,
            "timestamp": self.timestamp.isoformat(),
            "collection_time_ms": round(self.collection_time_ms, 1),
        }


# Health score calculation weights
HEALTH_WEIGHTS = {
    "latency": 0.30,       # RTT impact (lower is better)
    "packet_loss": 0.25,   # Loss impact (lower is better)
    "load": 0.20,          # System load impact
    "bandwidth": 0.25,     # Headroom impact (higher is better)
}

# Thresholds for scoring
LATENCY_THRESHOLDS = {"excellent": 20, "good": 50, "fair": 100, "poor": 200}
LOSS_THRESHOLDS = {"excellent": 0.1, "good": 1.0, "fair": 3.0, "poor": 5.0}


class RealMetricsEngine:
    """
    Real Metrics Engine for AIOCHI.

    Features:
    - Multi-source collection (SLA AI → direct → cached)
    - ClickHouse persistence
    - Background collection thread
    - Device-specific metrics
    - Historical trend analysis
    """

    def __init__(
        self,
        clickhouse_host: str = "localhost",
        clickhouse_port: int = 9000,
        collection_interval: int = 60,  # seconds
        enable_background: bool = True,
    ):
        """
        Initialize the Real Metrics Engine.

        Args:
            clickhouse_host: ClickHouse server host
            clickhouse_port: ClickHouse native protocol port
            collection_interval: How often to collect metrics (seconds)
            enable_background: Enable background collection thread
        """
        self.clickhouse_host = clickhouse_host
        self.clickhouse_port = clickhouse_port
        self.collection_interval = collection_interval

        # Cached metrics
        self._cache: Optional[RealMetrics] = None
        self._cache_time: Optional[datetime] = None
        self._cache_ttl = timedelta(seconds=30)

        # Device-specific metrics
        self._device_cache: Dict[str, RealMetrics] = {}

        # Bandwidth measurement state
        self._bandwidth_state: Dict[str, Tuple[float, int, int]] = {}

        # ClickHouse client (lazy init)
        self._ch_client = None

        # SLA AI collector (lazy init)
        self._slaai_collector = None

        # Background collection thread
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_running = False
        self._bg_lock = threading.Lock()

        # Listeners for real-time updates
        self._listeners: List[Callable[[RealMetrics], None]] = []

        # Statistics
        self._stats = {
            "collections": 0,
            "slaai_hits": 0,
            "direct_hits": 0,
            "cache_hits": 0,
            "errors": 0,
            "clickhouse_writes": 0,
        }

        if enable_background:
            self.start_background_collection()

    def get_current_metrics(self, force_refresh: bool = False) -> RealMetrics:
        """
        Get current network metrics.

        Uses fallback chain: SLA AI → direct measurement → cached values.

        Args:
            force_refresh: Force collection even if cache is fresh

        Returns:
            RealMetrics with current values
        """
        # Check cache first (unless forced)
        if not force_refresh and self._cache and self._cache_time:
            if datetime.now() - self._cache_time < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return self._cache

        start_time = time.time()
        metrics = RealMetrics()

        # Try SLA AI first (highest fidelity)
        slaai_metrics = self._try_slaai_collection()
        if slaai_metrics:
            metrics.latency_ms = slaai_metrics.get("rtt_ms", 0)
            metrics.jitter_ms = slaai_metrics.get("jitter_ms", 0)
            metrics.packet_loss_pct = slaai_metrics.get("packet_loss_pct", 0)
            metrics.source = MetricSource.SLAAI
            self._stats["slaai_hits"] += 1
        else:
            # Fall back to direct measurements
            direct_metrics = self._try_direct_measurements()
            if direct_metrics:
                metrics.latency_ms = direct_metrics.get("latency_ms", 0)
                metrics.packet_loss_pct = direct_metrics.get("packet_loss_pct", 0)
                metrics.source = MetricSource.DIRECT
                self._stats["direct_hits"] += 1
            elif self._cache:
                # Use cached values
                metrics = RealMetrics(**self._cache.to_dict())
                metrics.source = MetricSource.CACHED
                self._stats["cache_hits"] += 1

        # Collect bandwidth (always direct)
        bw_rx, bw_tx = self._measure_bandwidth()
        metrics.bandwidth_rx_mbps = bw_rx
        metrics.bandwidth_tx_mbps = bw_tx
        metrics.bandwidth_used_pct = self._calculate_bandwidth_usage(bw_rx, bw_tx)

        # Collect security metrics
        security = self._collect_security_metrics()
        metrics.threats_blocked = security.get("threats_blocked", 0)
        metrics.dns_queries_blocked = security.get("dns_blocked", 0)
        metrics.active_connections = security.get("active_connections", 0)

        # Calculate health score
        metrics.health_score = self._calculate_health_score(metrics)

        # Update metadata
        metrics.timestamp = datetime.now()
        metrics.collection_time_ms = (time.time() - start_time) * 1000

        # Update cache
        self._cache = metrics
        self._cache_time = datetime.now()
        self._stats["collections"] += 1

        # Write to ClickHouse (async)
        self._write_to_clickhouse(metrics)

        # Notify listeners
        self._notify_listeners(metrics)

        return metrics

    def get_device_metrics(self, mac: str) -> Optional[RealMetrics]:
        """Get metrics for a specific device."""
        mac = mac.upper().replace("-", ":")
        return self._device_cache.get(mac)

    def update_device_metrics(
        self,
        mac: str,
        latency_ms: Optional[float] = None,
        signal_dbm: Optional[int] = None,
        bandwidth_mbps: Optional[float] = None,
    ) -> None:
        """Update metrics for a specific device (called by presence sensor, etc.)."""
        mac = mac.upper().replace("-", ":")

        if mac not in self._device_cache:
            self._device_cache[mac] = RealMetrics()

        device = self._device_cache[mac]
        if latency_ms is not None:
            device.latency_ms = latency_ms
        if signal_dbm is not None:
            device.signal_dbm = signal_dbm
        if bandwidth_mbps is not None:
            device.bandwidth_rx_mbps = bandwidth_mbps

        device.timestamp = datetime.now()
        device.source = MetricSource.DIRECT

    def get_historical_metrics(
        self,
        hours: int = 24,
        interval_minutes: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Get historical metrics from ClickHouse.

        Args:
            hours: How many hours of history
            interval_minutes: Aggregation interval

        Returns:
            List of metric dictionaries
        """
        try:
            client = self._get_clickhouse_client()
            if not client:
                return []

            query = f"""
            SELECT
                toStartOfInterval(timestamp, INTERVAL {interval_minutes} MINUTE) AS ts,
                avg(health_score) AS health_score,
                avg(latency_ms) AS latency_ms,
                avg(packet_loss_pct) AS packet_loss_pct,
                avg(bandwidth_mbps) AS bandwidth_mbps
            FROM aiochi.performance_metrics
            WHERE timestamp > now() - INTERVAL {hours} HOUR
              AND device_mac = ''
            GROUP BY ts
            ORDER BY ts
            """

            result = client.execute(query)
            return [
                {
                    "timestamp": row[0].isoformat(),
                    "health_score": int(row[1]) if row[1] else 0,
                    "latency_ms": float(row[2]) if row[2] else 0,
                    "packet_loss_pct": float(row[3]) if row[3] else 0,
                    "bandwidth_mbps": float(row[4]) if row[4] else 0,
                }
                for row in result
            ]
        except Exception as e:
            logger.error(f"Failed to get historical metrics: {e}")
            return []

    def add_listener(self, callback: Callable[[RealMetrics], None]) -> None:
        """Add a listener for real-time metrics updates."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[RealMetrics], None]) -> None:
        """Remove a metrics listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    def start_background_collection(self) -> None:
        """Start background metrics collection thread."""
        if self._bg_running:
            return

        self._bg_running = True
        self._bg_thread = threading.Thread(
            target=self._background_collection_loop,
            daemon=True,
            name="aiochi-metrics-engine",
        )
        self._bg_thread.start()
        logger.info(f"Started background metrics collection (interval: {self.collection_interval}s)")

    def stop_background_collection(self) -> None:
        """Stop background metrics collection."""
        self._bg_running = False
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=5)
        logger.info("Stopped background metrics collection")

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            **self._stats,
            "cache_age_seconds": (
                (datetime.now() - self._cache_time).total_seconds()
                if self._cache_time else None
            ),
            "device_count": len(self._device_cache),
            "listeners_count": len(self._listeners),
            "background_running": self._bg_running,
        }

    # =========================================================================
    # Private: Collection Methods
    # =========================================================================

    def _try_slaai_collection(self) -> Optional[Dict[str, Any]]:
        """Try to collect metrics from SLA AI."""
        try:
            if self._slaai_collector is None:
                from shared.slaai.metrics_collector import MetricsCollector
                self._slaai_collector = MetricsCollector()

            wan_metrics = self._slaai_collector.collect()
            return {
                "rtt_ms": wan_metrics.rtt_ms,
                "jitter_ms": wan_metrics.jitter_ms,
                "packet_loss_pct": wan_metrics.packet_loss_pct,
                "bandwidth_mbps": wan_metrics.bandwidth_mbps,
            }
        except ImportError:
            logger.debug("SLA AI not available")
        except Exception as e:
            logger.debug(f"SLA AI collection failed: {e}")
        return None

    def _try_direct_measurements(self) -> Optional[Dict[str, Any]]:
        """Fall back to direct ping measurements."""
        try:
            # Get gateway for ping target
            gateway = self._get_gateway()
            if not gateway:
                gateway = "8.8.8.8"  # Fallback to Google DNS

            # Run ping
            result = subprocess.run(
                ["ping", "-c", "5", "-W", "2", gateway],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                # Parse ping output
                lines = result.stdout.split('\n')
                for line in lines:
                    if "rtt min/avg/max" in line or "round-trip" in line:
                        # Format: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms
                        parts = line.split('=')[-1].strip().split('/')
                        if len(parts) >= 2:
                            return {
                                "latency_ms": float(parts[1]),
                                "packet_loss_pct": self._parse_packet_loss(result.stdout),
                            }

                # Parse packet stats as fallback
                return {"latency_ms": 0, "packet_loss_pct": self._parse_packet_loss(result.stdout)}

        except subprocess.TimeoutExpired:
            logger.debug("Ping timeout")
        except Exception as e:
            logger.debug(f"Direct measurement failed: {e}")

        return None

    def _parse_packet_loss(self, ping_output: str) -> float:
        """Parse packet loss percentage from ping output."""
        try:
            for line in ping_output.split('\n'):
                if "packet loss" in line:
                    # Format: "5 packets transmitted, 5 received, 0% packet loss"
                    parts = line.split(',')
                    for part in parts:
                        if 'packet loss' in part:
                            pct = part.strip().split('%')[0].split()[-1]
                            return float(pct)
        except Exception:
            pass
        return 0.0

    def _get_gateway(self) -> Optional[str]:
        """Get default gateway IP."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except Exception:
            pass
        return None

    def _measure_bandwidth(self) -> Tuple[float, float]:
        """Measure current bandwidth usage from /proc/net/dev."""
        interface = self._get_wan_interface()
        if not interface:
            return 0.0, 0.0

        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if interface in line:
                        parts = line.split(':')[1].split()
                        rx_bytes = int(parts[0])
                        tx_bytes = int(parts[8])

                        now = time.time()

                        if interface in self._bandwidth_state:
                            prev_time, prev_rx, prev_tx = self._bandwidth_state[interface]
                            elapsed = now - prev_time

                            if elapsed > 0.5:  # Avoid division by zero
                                rx_mbps = ((rx_bytes - prev_rx) * 8) / (elapsed * 1_000_000)
                                tx_mbps = ((tx_bytes - prev_tx) * 8) / (elapsed * 1_000_000)

                                self._bandwidth_state[interface] = (now, rx_bytes, tx_bytes)
                                return max(0, rx_mbps), max(0, tx_mbps)

                        self._bandwidth_state[interface] = (now, rx_bytes, tx_bytes)
                        return 0.0, 0.0

        except Exception as e:
            logger.debug(f"Bandwidth measurement failed: {e}")

        return 0.0, 0.0

    def _get_wan_interface(self) -> Optional[str]:
        """Detect WAN interface."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except Exception:
            pass

        # Fallback to common names
        for iface in ["eth0", "eno1", "wan0"]:
            if os.path.exists(f"/sys/class/net/{iface}"):
                return iface

        return None

    def _calculate_bandwidth_usage(self, rx_mbps: float, tx_mbps: float) -> float:
        """Calculate bandwidth usage percentage (assuming 1Gbps max)."""
        # TODO: Read actual link speed from /sys/class/net/<iface>/speed
        max_mbps = 1000.0
        total_mbps = rx_mbps + tx_mbps
        return min(100.0, (total_mbps / max_mbps) * 100)

    def _collect_security_metrics(self) -> Dict[str, Any]:
        """Collect security-related metrics."""
        metrics = {
            "threats_blocked": 0,
            "dns_blocked": 0,
            "active_connections": 0,
        }

        # Try dnsXai stats
        try:
            import requests
            resp = requests.get("http://localhost:8053/api/stats", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                metrics["dns_blocked"] = data.get("blocked_total", 0)
        except Exception:
            pass

        # Try QSecBit threat count
        try:
            state_file = "/run/fortress/qsecbit-state.json"
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    data = json.load(f)
                    metrics["threats_blocked"] = data.get("blocked_count", 0)
        except Exception:
            pass

        # Count active connections
        try:
            result = subprocess.run(
                ["ss", "-tun", "state", "established"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Count lines (minus header)
                lines = [x for x in result.stdout.strip().split('\n') if x]
                metrics["active_connections"] = max(0, len(lines) - 1)
        except Exception:
            pass

        return metrics

    def _calculate_health_score(self, metrics: RealMetrics) -> int:
        """Calculate overall health score 0-100."""
        scores = {}

        # Latency score (lower is better)
        if metrics.latency_ms <= LATENCY_THRESHOLDS["excellent"]:
            scores["latency"] = 100
        elif metrics.latency_ms <= LATENCY_THRESHOLDS["good"]:
            scores["latency"] = 85
        elif metrics.latency_ms <= LATENCY_THRESHOLDS["fair"]:
            scores["latency"] = 65
        elif metrics.latency_ms <= LATENCY_THRESHOLDS["poor"]:
            scores["latency"] = 40
        else:
            scores["latency"] = 20

        # Packet loss score (lower is better)
        if metrics.packet_loss_pct <= LOSS_THRESHOLDS["excellent"]:
            scores["packet_loss"] = 100
        elif metrics.packet_loss_pct <= LOSS_THRESHOLDS["good"]:
            scores["packet_loss"] = 85
        elif metrics.packet_loss_pct <= LOSS_THRESHOLDS["fair"]:
            scores["packet_loss"] = 65
        elif metrics.packet_loss_pct <= LOSS_THRESHOLDS["poor"]:
            scores["packet_loss"] = 40
        else:
            scores["packet_loss"] = 20

        # Load score (from /proc/loadavg)
        try:
            with open('/proc/loadavg', 'r') as f:
                load_1min = float(f.read().split()[0])
            cpu_count = os.cpu_count() or 1
            load_ratio = load_1min / cpu_count
            if load_ratio < 0.5:
                scores["load"] = 100
            elif load_ratio < 1.0:
                scores["load"] = 80
            elif load_ratio < 2.0:
                scores["load"] = 60
            else:
                scores["load"] = 40
        except Exception:
            scores["load"] = 100

        # Bandwidth headroom (higher unused is better)
        headroom = 100 - metrics.bandwidth_used_pct
        scores["bandwidth"] = max(20, min(100, headroom))

        # Weighted average
        total = 0.0
        for metric, weight in HEALTH_WEIGHTS.items():
            total += scores.get(metric, 100) * weight

        return int(round(total))

    # =========================================================================
    # Private: ClickHouse Integration
    # =========================================================================

    def _get_clickhouse_client(self):
        """Get or create ClickHouse client."""
        if self._ch_client is not None:
            return self._ch_client

        try:
            from clickhouse_driver import Client
            self._ch_client = Client(
                host=self.clickhouse_host,
                port=self.clickhouse_port,
                database='aiochi',
                user='aiochi',
                password='',
            )
            # Test connection
            self._ch_client.execute("SELECT 1")
            logger.info("Connected to ClickHouse")
            return self._ch_client
        except ImportError:
            logger.debug("clickhouse-driver not installed")
        except Exception as e:
            logger.debug(f"ClickHouse connection failed: {e}")

        return None

    def _write_to_clickhouse(self, metrics: RealMetrics) -> None:
        """Write metrics to ClickHouse (non-blocking)."""
        def _write():
            try:
                client = self._get_clickhouse_client()
                if not client:
                    return

                client.execute(
                    """
                    INSERT INTO aiochi.performance_metrics
                    (timestamp, device_mac, latency_ms, jitter_ms, packet_loss_pct,
                     signal_dbm, bandwidth_mbps, interference_score, congestion_score,
                     health_score)
                    VALUES
                    """,
                    [(
                        metrics.timestamp,
                        '',  # Network-wide metric (no specific device)
                        metrics.latency_ms,
                        metrics.jitter_ms,
                        metrics.packet_loss_pct,
                        metrics.signal_dbm,
                        metrics.bandwidth_rx_mbps,
                        metrics.interference_score,
                        0.0,  # congestion_score - could add later
                        metrics.health_score,
                    )],
                )
                self._stats["clickhouse_writes"] += 1
            except Exception as e:
                logger.debug(f"ClickHouse write failed: {e}")
                self._stats["errors"] += 1

        # Run in background thread
        threading.Thread(target=_write, daemon=True).start()

    # =========================================================================
    # Private: Background Collection
    # =========================================================================

    def _background_collection_loop(self) -> None:
        """Background thread for periodic metrics collection."""
        while self._bg_running:
            try:
                with self._bg_lock:
                    self.get_current_metrics(force_refresh=True)
            except Exception as e:
                logger.error(f"Background collection error: {e}")
                self._stats["errors"] += 1

            # Sleep for interval
            for _ in range(self.collection_interval):
                if not self._bg_running:
                    break
                time.sleep(1)

    def _notify_listeners(self, metrics: RealMetrics) -> None:
        """Notify all registered listeners."""
        for callback in self._listeners:
            try:
                callback(metrics)
            except Exception as e:
                logger.error(f"Listener callback error: {e}")


# Singleton instance
_engine_instance: Optional[RealMetricsEngine] = None


def get_metrics_engine(
    clickhouse_host: str = "localhost",
    enable_background: bool = True,
) -> RealMetricsEngine:
    """Get or create the singleton metrics engine instance."""
    global _engine_instance

    if _engine_instance is None:
        _engine_instance = RealMetricsEngine(
            clickhouse_host=clickhouse_host,
            enable_background=enable_background,
        )

    return _engine_instance


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    engine = RealMetricsEngine(enable_background=False)

    print("Collecting metrics...")
    metrics = engine.get_current_metrics()

    print(f"\nHealth Score: {metrics.health_score}/100")
    print(f"Source: {metrics.source.value}")
    print(f"Latency: {metrics.latency_ms:.1f}ms")
    print(f"Packet Loss: {metrics.packet_loss_pct:.2f}%")
    print(f"Bandwidth RX: {metrics.bandwidth_rx_mbps:.1f} Mbps")
    print(f"Bandwidth TX: {metrics.bandwidth_tx_mbps:.1f} Mbps")
    print(f"Threats Blocked: {metrics.threats_blocked}")
    print(f"DNS Blocked: {metrics.dns_queries_blocked}")
    print(f"Collection Time: {metrics.collection_time_ms:.0f}ms")

    print(f"\nStats: {engine.get_stats()}")
