"""
SLA AI Metrics Collector

Collects real-time network health metrics from WAN interfaces.
Supports Ethernet, LTE/WWAN, and WiFi interfaces.
"""

import asyncio
import subprocess
import time
import re
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class WANMetrics:
    """Container for WAN interface metrics."""

    timestamp: datetime = field(default_factory=datetime.now)
    interface: str = ""

    # Latency metrics
    rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    packet_loss_pct: float = 0.0

    # LTE-specific metrics
    signal_rssi_dbm: Optional[int] = None  # -113 to -51 dBm
    signal_rsrp_dbm: Optional[int] = None  # -140 to -44 dBm (4G)
    signal_rsrq_db: Optional[int] = None  # -20 to -3 dB (4G quality)
    network_type: str = "unknown"  # ethernet, lte-4g, lte-5g, 3g, etc.

    # DNS metrics
    dns_response_ms: Optional[float] = None

    # HTTP metrics
    http_response_ms: Optional[float] = None

    # Interface health
    interface_errors: int = 0
    gateway_arp_ms: Optional[float] = None

    # Bandwidth tracking (for cost)
    bytes_sent: int = 0
    bytes_received: int = 0

    # Derived health score (0-1, 1 = healthy)
    health_score: float = 1.0

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return asdict(self)

    def calculate_health_score(self) -> float:
        """
        Calculate composite health score from metrics.

        Factors:
            - RTT (40%): Lower is better, >500ms is critical
            - Packet loss (30%): Any loss is concerning
            - Signal strength (20%): LTE only
            - Jitter (10%): High jitter indicates instability

        Returns:
            Health score between 0 (failed) and 1 (healthy)
        """
        score = 1.0
        weights_used = 0.0

        # RTT component (40%)
        if self.rtt_ms is not None:
            if self.rtt_ms < 50:
                rtt_score = 1.0
            elif self.rtt_ms < 100:
                rtt_score = 0.9
            elif self.rtt_ms < 200:
                rtt_score = 0.7
            elif self.rtt_ms < 500:
                rtt_score = 0.4
            else:
                rtt_score = 0.1
            score = score * 0.6 + rtt_score * 0.4
            weights_used += 0.4

        # Packet loss component (30%)
        if self.packet_loss_pct is not None:
            if self.packet_loss_pct == 0:
                loss_score = 1.0
            elif self.packet_loss_pct < 1:
                loss_score = 0.9
            elif self.packet_loss_pct < 5:
                loss_score = 0.6
            elif self.packet_loss_pct < 20:
                loss_score = 0.3
            else:
                loss_score = 0.0
            score = score * 0.7 + loss_score * 0.3
            weights_used += 0.3

        # Signal strength component (20%) - LTE only
        if self.signal_rssi_dbm is not None:
            if self.signal_rssi_dbm > -70:
                signal_score = 1.0
            elif self.signal_rssi_dbm > -85:
                signal_score = 0.8
            elif self.signal_rssi_dbm > -100:
                signal_score = 0.5
            else:
                signal_score = 0.2
            score = score * 0.8 + signal_score * 0.2
            weights_used += 0.2

        # Jitter component (10%)
        if self.jitter_ms is not None:
            if self.jitter_ms < 10:
                jitter_score = 1.0
            elif self.jitter_ms < 30:
                jitter_score = 0.8
            elif self.jitter_ms < 50:
                jitter_score = 0.5
            else:
                jitter_score = 0.2
            score = score * 0.9 + jitter_score * 0.1
            weights_used += 0.1

        self.health_score = max(0.0, min(1.0, score))
        return self.health_score


class MetricsCollector:
    """
    Collects network health metrics from WAN interfaces.

    Features:
        - ICMP ping for RTT and packet loss
        - LTE signal strength via ModemManager
        - DNS and HTTP response times
        - Interface error counters
        - Bandwidth tracking
    """

    def __init__(
        self,
        ping_targets: List[str] = None,
        ping_count: int = 2,
        ping_timeout: int = 3,
        dns_server: str = "1.1.1.1",
        http_url: str = "http://httpbin.org/ip",
    ):
        """
        Initialize metrics collector.

        Args:
            ping_targets: List of IPs to ping
            ping_count: Number of pings per target
            ping_timeout: Ping timeout in seconds
            dns_server: DNS server to test
            http_url: HTTP URL to test
        """
        self.ping_targets = ping_targets or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.ping_count = ping_count
        self.ping_timeout = ping_timeout
        self.dns_server = dns_server
        self.http_url = http_url

        # Track previous byte counts for delta calculation
        self._prev_bytes: Dict[str, Tuple[int, int]] = {}

    async def collect(self, interface: str) -> WANMetrics:
        """
        Collect all metrics for an interface.

        Args:
            interface: Network interface name (e.g., eth0, wwan0)

        Returns:
            WANMetrics instance with all collected metrics
        """
        metrics = WANMetrics(
            timestamp=datetime.now(),
            interface=interface,
        )

        # Detect interface type
        metrics.network_type = self._detect_interface_type(interface)

        # Get interface IP for proper source binding
        iface_ip = self._get_interface_ip(interface)
        if not iface_ip:
            logger.warning(f"No IP address on {interface}")
            metrics.health_score = 0.0
            return metrics

        # Collect metrics in parallel where possible
        try:
            # These can run in parallel
            ping_task = asyncio.create_task(
                self._collect_ping_metrics(interface, iface_ip)
            )
            dns_task = asyncio.create_task(
                self._collect_dns_metrics(interface, iface_ip)
            )

            ping_result = await ping_task
            dns_result = await dns_task

            # Apply ping results
            if ping_result:
                metrics.rtt_ms = ping_result.get("rtt_ms")
                metrics.jitter_ms = ping_result.get("jitter_ms")
                metrics.packet_loss_pct = ping_result.get("packet_loss_pct", 100.0)

            # Apply DNS results
            if dns_result:
                metrics.dns_response_ms = dns_result.get("response_ms")

        except Exception as e:
            logger.error(f"Error collecting metrics for {interface}: {e}")

        # Collect LTE-specific metrics if applicable
        if metrics.network_type.startswith("lte") or interface.startswith(
            ("wwan", "wwp")
        ):
            try:
                lte_metrics = await self._collect_lte_metrics(interface)
                if lte_metrics:
                    metrics.signal_rssi_dbm = lte_metrics.get("rssi_dbm")
                    metrics.signal_rsrp_dbm = lte_metrics.get("rsrp_dbm")
                    metrics.signal_rsrq_db = lte_metrics.get("rsrq_db")
                    if lte_metrics.get("network_type"):
                        metrics.network_type = lte_metrics["network_type"]
            except Exception as e:
                logger.debug(f"LTE metrics collection failed: {e}")

        # Collect interface errors
        metrics.interface_errors = self._get_interface_errors(interface)

        # Collect bandwidth (delta from last check)
        tx, rx = self._get_interface_bytes(interface)
        if interface in self._prev_bytes:
            prev_tx, prev_rx = self._prev_bytes[interface]
            metrics.bytes_sent = max(0, tx - prev_tx)
            metrics.bytes_received = max(0, rx - prev_rx)
        self._prev_bytes[interface] = (tx, rx)

        # Calculate composite health score
        metrics.calculate_health_score()

        return metrics

    async def collect_quick(self, interface: str) -> WANMetrics:
        """
        Quick metrics collection - only ping, no DNS/HTTP.

        Args:
            interface: Network interface name

        Returns:
            WANMetrics with basic ping data
        """
        metrics = WANMetrics(
            timestamp=datetime.now(),
            interface=interface,
        )

        iface_ip = self._get_interface_ip(interface)
        if not iface_ip:
            metrics.health_score = 0.0
            return metrics

        # Just do a quick ping
        try:
            ping_result = await self._collect_ping_metrics(
                interface, iface_ip, quick=True
            )
            if ping_result:
                metrics.rtt_ms = ping_result.get("rtt_ms")
                metrics.packet_loss_pct = ping_result.get("packet_loss_pct", 100.0)
        except Exception as e:
            logger.debug(f"Quick ping failed for {interface}: {e}")
            metrics.packet_loss_pct = 100.0

        metrics.calculate_health_score()
        return metrics

    def _detect_interface_type(self, interface: str) -> str:
        """Detect interface type from name and driver."""
        if interface.startswith(("wwan", "wwp")):
            return "lte"
        if interface.startswith("wl"):
            return "wifi"
        if interface.startswith(("eth", "en", "em")):
            return "ethernet"
        if interface.startswith("usb"):
            # Check if USB modem
            driver = self._get_interface_driver(interface)
            if driver in ("cdc_ether", "cdc_ncm", "qmi_wwan", "option"):
                return "lte"
            return "usb"
        return "unknown"

    def _get_interface_driver(self, interface: str) -> Optional[str]:
        """Get driver name for interface."""
        try:
            driver_path = f"/sys/class/net/{interface}/device/driver"
            if os.path.exists(driver_path):
                return os.path.basename(os.readlink(driver_path))
        except Exception:
            pass
        return None

    def _get_interface_ip(self, interface: str) -> Optional[str]:
        """Get primary IPv4 address for interface."""
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", interface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    def _get_interface_errors(self, interface: str) -> int:
        """Get total interface error count."""
        errors = 0
        stats_path = f"/sys/class/net/{interface}/statistics"

        for stat in ["rx_errors", "tx_errors", "rx_dropped", "tx_dropped"]:
            try:
                with open(f"{stats_path}/{stat}") as f:
                    errors += int(f.read().strip())
            except Exception:
                pass

        return errors

    def _get_interface_bytes(self, interface: str) -> Tuple[int, int]:
        """Get TX and RX bytes for interface."""
        stats_path = f"/sys/class/net/{interface}/statistics"
        tx_bytes = rx_bytes = 0

        try:
            with open(f"{stats_path}/tx_bytes") as f:
                tx_bytes = int(f.read().strip())
            with open(f"{stats_path}/rx_bytes") as f:
                rx_bytes = int(f.read().strip())
        except Exception:
            pass

        return tx_bytes, rx_bytes

    async def _collect_ping_metrics(
        self, interface: str, source_ip: str, quick: bool = False
    ) -> Optional[Dict]:
        """
        Collect ICMP ping metrics.

        Args:
            interface: Interface to use
            source_ip: Source IP for binding
            quick: If True, only ping first target once

        Returns:
            Dictionary with rtt_ms, jitter_ms, packet_loss_pct
        """
        targets = self.ping_targets[:1] if quick else self.ping_targets
        count = 1 if quick else self.ping_count

        rtt_values = []
        total_sent = 0
        total_received = 0

        for target in targets:
            try:
                # Use source IP binding to trigger proper routing
                result = await asyncio.create_subprocess_exec(
                    "ping",
                    "-c", str(count),
                    "-W", str(self.ping_timeout),
                    "-I", source_ip,
                    "-q",  # Quiet mode
                    target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    result.communicate(), timeout=self.ping_timeout * count + 2
                )
                output = stdout.decode()

                # Parse ping output
                # "2 packets transmitted, 2 received, 0% packet loss"
                stats_match = re.search(
                    r"(\d+) packets transmitted, (\d+) received", output
                )
                if stats_match:
                    sent = int(stats_match.group(1))
                    received = int(stats_match.group(2))
                    total_sent += sent
                    total_received += received

                # "rtt min/avg/max/mdev = 10.5/15.2/20.1/3.2 ms"
                rtt_match = re.search(
                    r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output
                )
                if rtt_match:
                    rtt_values.append(float(rtt_match.group(2)))  # avg

            except asyncio.TimeoutError:
                total_sent += count
            except Exception as e:
                logger.debug(f"Ping to {target} failed: {e}")
                total_sent += count

        if not rtt_values and total_sent > 0:
            return {"packet_loss_pct": 100.0}

        if rtt_values:
            avg_rtt = sum(rtt_values) / len(rtt_values)
            jitter = (
                sum(abs(r - avg_rtt) for r in rtt_values) / len(rtt_values)
                if len(rtt_values) > 1
                else 0
            )
            packet_loss = (
                ((total_sent - total_received) / total_sent * 100)
                if total_sent > 0
                else 0
            )

            return {
                "rtt_ms": avg_rtt,
                "jitter_ms": jitter,
                "packet_loss_pct": packet_loss,
            }

        return None

    async def _collect_dns_metrics(
        self, interface: str, source_ip: str
    ) -> Optional[Dict]:
        """
        Collect DNS response time metrics.

        Args:
            interface: Interface to use
            source_ip: Source IP for binding

        Returns:
            Dictionary with response_ms
        """
        try:
            start = time.perf_counter()

            # Use dig with interface binding
            result = await asyncio.create_subprocess_exec(
                "dig",
                f"@{self.dns_server}",
                "google.com",
                "+short",
                "+time=2",
                "+tries=1",
                f"-b{source_ip}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=5)

            elapsed = (time.perf_counter() - start) * 1000

            if stdout.strip():
                return {"response_ms": elapsed}

        except Exception as e:
            logger.debug(f"DNS check failed: {e}")

        return None

    async def _collect_lte_metrics(self, interface: str) -> Optional[Dict]:
        """
        Collect LTE-specific metrics via ModemManager.

        Args:
            interface: WWAN interface name

        Returns:
            Dictionary with signal metrics
        """
        if not self._check_command_exists("mmcli"):
            return None

        try:
            # Find modem index
            result = await asyncio.create_subprocess_exec(
                "mmcli", "-L",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=5)

            match = re.search(r"/Modem/(\d+)", stdout.decode())
            if not match:
                return None

            modem_idx = match.group(1)

            # Get signal quality
            result = await asyncio.create_subprocess_exec(
                "mmcli", "-m", modem_idx, "--signal-get",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=5)
            signal_output = stdout.decode()

            metrics = {}

            # Parse RSSI
            rssi_match = re.search(r"rssi:\s*([-\d.]+)\s*dBm", signal_output)
            if rssi_match:
                metrics["rssi_dbm"] = int(float(rssi_match.group(1)))

            # Parse RSRP (4G)
            rsrp_match = re.search(r"rsrp:\s*([-\d.]+)\s*dBm", signal_output)
            if rsrp_match:
                metrics["rsrp_dbm"] = int(float(rsrp_match.group(1)))

            # Parse RSRQ (4G)
            rsrq_match = re.search(r"rsrq:\s*([-\d.]+)\s*dB", signal_output)
            if rsrq_match:
                metrics["rsrq_db"] = int(float(rsrq_match.group(1)))

            # Get access technology
            result = await asyncio.create_subprocess_exec(
                "mmcli", "-m", modem_idx,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=5)
            modem_output = stdout.decode()

            tech_match = re.search(r"access tech:\s*(\S+)", modem_output.lower())
            if tech_match:
                tech = tech_match.group(1)
                if "lte" in tech or "4g" in tech:
                    metrics["network_type"] = "lte-4g"
                elif "5g" in tech or "nr" in tech:
                    metrics["network_type"] = "lte-5g"
                elif "3g" in tech or "umts" in tech or "hspa" in tech:
                    metrics["network_type"] = "3g"
                else:
                    metrics["network_type"] = f"lte-{tech}"

            return metrics if metrics else None

        except Exception as e:
            logger.debug(f"LTE metrics collection failed: {e}")
            return None

    def _check_command_exists(self, cmd: str) -> bool:
        """Check if a command exists in PATH."""
        try:
            subprocess.run(
                ["which", cmd],
                capture_output=True,
                timeout=2,
            )
            return True
        except Exception:
            return False
