"""
SLA AI DNS Intelligence

Adaptive DNS provider selection with:
- Multi-provider health monitoring
- Response time tracking
- Automatic failover on degradation
- Regional preference learning
- Integration with dnsmasq
"""

import asyncio
import socket
import time
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


@dataclass
class DNSProvider:
    """DNS provider configuration."""
    name: str
    primary: str
    secondary: Optional[str] = None
    priority: int = 1  # Lower = higher priority
    is_doh: bool = False
    is_dot: bool = False


@dataclass
class DNSHealth:
    """Health status for a DNS provider."""
    provider_name: str
    ip: str
    response_time_ms: float
    is_healthy: bool
    last_check: datetime
    success_rate: float = 1.0  # Recent success rate
    avg_response_ms: float = 0.0  # Rolling average

    def to_dict(self) -> Dict:
        return {
            "provider": self.provider_name,
            "ip": self.ip,
            "response_time_ms": self.response_time_ms,
            "is_healthy": self.is_healthy,
            "last_check": self.last_check.isoformat(),
            "success_rate": self.success_rate,
            "avg_response_ms": self.avg_response_ms,
        }


class DNSStatus(Enum):
    """DNS provider status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


# Default DNS providers
DEFAULT_PROVIDERS = [
    DNSProvider(name="cloudflare", primary="1.1.1.1", secondary="1.0.0.1", priority=1),
    DNSProvider(name="google", primary="8.8.8.8", secondary="8.8.4.4", priority=2),
    DNSProvider(name="quad9", primary="9.9.9.9", secondary="149.112.112.112", priority=3),
    DNSProvider(name="opendns", primary="208.67.222.222", secondary="208.67.220.220", priority=4),
]


class DNSIntelligence:
    """
    Intelligent DNS provider management.

    Features:
        - Health monitoring of multiple DNS providers
        - Automatic failover when primary degrades
        - Response time-based ranking
        - dnsmasq configuration integration
        - Learning regional preferences
    """

    # Thresholds
    HEALTHY_RESPONSE_MS = 50
    DEGRADED_RESPONSE_MS = 200
    TIMEOUT_MS = 2000
    MIN_SUCCESS_RATE = 0.8

    # Test domains for health checks
    TEST_DOMAINS = [
        "google.com",
        "cloudflare.com",
        "microsoft.com",
    ]

    def __init__(
        self,
        providers: Optional[List[DNSProvider]] = None,
        database=None,
        check_interval_s: int = 60,
        dnsmasq_config_path: Optional[str] = None,
    ):
        """
        Initialize DNS intelligence.

        Args:
            providers: List of DNS providers to use
            database: SLAAIDatabase for persistent storage
            check_interval_s: Health check interval
            dnsmasq_config_path: Path to dnsmasq upstream config
        """
        self.providers = providers or DEFAULT_PROVIDERS.copy()
        self.database = database
        self.check_interval_s = check_interval_s
        self.dnsmasq_config_path = dnsmasq_config_path or "/etc/dnsmasq.d/slaai-upstream.conf"

        # Health tracking per IP
        self._health: Dict[str, List[DNSHealth]] = {}  # IP -> history
        self._current_primary: Optional[str] = None
        self._current_secondary: Optional[str] = None

        # Performance metrics
        self._response_times: Dict[str, List[float]] = {}  # IP -> recent times
        self._failure_counts: Dict[str, int] = {}

        # Initialize with first provider
        if self.providers:
            self._current_primary = self.providers[0].primary
            self._current_secondary = self.providers[0].secondary

    async def check_all(self) -> Dict[str, DNSHealth]:
        """
        Check health of all DNS providers.

        Returns:
            Dict of IP -> DNSHealth
        """
        results = {}
        tasks = []

        for provider in self.providers:
            tasks.append(self._check_provider(provider))

        health_lists = await asyncio.gather(*tasks, return_exceptions=True)

        for health_list in health_lists:
            if isinstance(health_list, Exception):
                logger.warning(f"Provider check failed: {health_list}")
                continue
            for health in health_list:
                results[health.ip] = health
                self._update_health_history(health)

        return results

    async def _check_provider(self, provider: DNSProvider) -> List[DNSHealth]:
        """Check health of a single provider."""
        results = []

        for ip in [provider.primary, provider.secondary]:
            if not ip:
                continue

            try:
                response_time, is_healthy = await self._dns_query(ip)

                # Update running statistics
                self._update_response_times(ip, response_time)

                health = DNSHealth(
                    provider_name=provider.name,
                    ip=ip,
                    response_time_ms=response_time,
                    is_healthy=is_healthy,
                    last_check=datetime.now(),
                    success_rate=self._get_success_rate(ip),
                    avg_response_ms=self._get_avg_response(ip),
                )

                results.append(health)

                # Store in database
                if self.database:
                    try:
                        self.database.store_dns_health(
                            provider=health.provider_name,
                            server=health.ip,
                            response_ms=health.response_time_ms,
                            success=health.is_healthy,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to store DNS health: {e}")

            except Exception as e:
                logger.warning(f"DNS check failed for {ip}: {e}")
                self._record_failure(ip)

                health = DNSHealth(
                    provider_name=provider.name,
                    ip=ip,
                    response_time_ms=self.TIMEOUT_MS,
                    is_healthy=False,
                    last_check=datetime.now(),
                    success_rate=self._get_success_rate(ip),
                    avg_response_ms=self._get_avg_response(ip),
                )
                results.append(health)

        return results

    async def _dns_query(self, dns_ip: str) -> Tuple[float, bool]:
        """
        Perform DNS query and measure response time.

        Returns:
            Tuple of (response_time_ms, is_healthy)
        """
        import random

        domain = random.choice(self.TEST_DOMAINS)

        start = time.monotonic()

        try:
            # Create UDP socket for DNS query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.TIMEOUT_MS / 1000)

            # Build simple DNS query
            query = self._build_dns_query(domain)

            # Send query
            sock.sendto(query, (dns_ip, 53))

            # Receive response
            response, _ = sock.recvfrom(512)

            elapsed_ms = (time.monotonic() - start) * 1000

            # Check if response is valid (has answer section)
            is_valid = len(response) > 12 and response[2] & 0x80  # QR bit set

            is_healthy = is_valid and elapsed_ms < self.DEGRADED_RESPONSE_MS

            sock.close()
            return elapsed_ms, is_healthy

        except socket.timeout:
            return self.TIMEOUT_MS, False
        except Exception as e:
            logger.debug(f"DNS query to {dns_ip} failed: {e}")
            return self.TIMEOUT_MS, False

    def _build_dns_query(self, domain: str) -> bytes:
        """Build a simple DNS A record query."""
        import struct
        import random

        # Transaction ID
        tid = random.randint(0, 65535)

        # Flags: standard query
        flags = 0x0100

        # Questions: 1, Answers: 0, Auth: 0, Additional: 0
        header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)

        # Query name
        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"

        # Query type (A) and class (IN)
        query = qname + struct.pack(">HH", 1, 1)

        return header + query

    def _update_response_times(self, ip: str, response_ms: float) -> None:
        """Update running response time statistics."""
        if ip not in self._response_times:
            self._response_times[ip] = []

        self._response_times[ip].append(response_ms)

        # Keep last 20 samples
        if len(self._response_times[ip]) > 20:
            self._response_times[ip] = self._response_times[ip][-20:]

        # Reset failure count on success
        if response_ms < self.TIMEOUT_MS:
            self._failure_counts[ip] = 0

    def _record_failure(self, ip: str) -> None:
        """Record a failure for an IP."""
        self._failure_counts[ip] = self._failure_counts.get(ip, 0) + 1

    def _get_success_rate(self, ip: str) -> float:
        """Get recent success rate for an IP."""
        times = self._response_times.get(ip, [])
        if not times:
            return 1.0

        successes = sum(1 for t in times if t < self.TIMEOUT_MS)
        return successes / len(times)

    def _get_avg_response(self, ip: str) -> float:
        """Get average response time for an IP."""
        times = self._response_times.get(ip, [])
        if not times:
            return 0.0

        # Exclude timeouts from average
        valid_times = [t for t in times if t < self.TIMEOUT_MS]
        if not valid_times:
            return self.TIMEOUT_MS

        return sum(valid_times) / len(valid_times)

    def _update_health_history(self, health: DNSHealth) -> None:
        """Update health history for an IP."""
        if health.ip not in self._health:
            self._health[health.ip] = []

        self._health[health.ip].append(health)

        # Keep last 100 samples
        if len(self._health[health.ip]) > 100:
            self._health[health.ip] = self._health[health.ip][-100:]

    def get_best_dns(self) -> Tuple[str, Optional[str]]:
        """
        Get best DNS servers based on current health.

        Returns:
            Tuple of (primary_ip, secondary_ip)
        """
        # Score all IPs
        scores: Dict[str, float] = {}

        for provider in self.providers:
            for ip in [provider.primary, provider.secondary]:
                if not ip:
                    continue

                score = self._calculate_score(ip, provider.priority)
                scores[ip] = score

        # Sort by score (higher is better)
        sorted_ips = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)

        if not sorted_ips:
            # Fallback to Cloudflare
            return "1.1.1.1", "1.0.0.1"

        primary = sorted_ips[0]
        secondary = sorted_ips[1] if len(sorted_ips) > 1 else None

        return primary, secondary

    def _calculate_score(self, ip: str, priority: int) -> float:
        """
        Calculate score for a DNS IP.

        Higher score = better.
        """
        score = 100.0

        # Priority penalty (lower priority = higher penalty)
        score -= priority * 5

        # Success rate bonus
        success_rate = self._get_success_rate(ip)
        score += success_rate * 30

        # Response time penalty
        avg_response = self._get_avg_response(ip)
        if avg_response > 0:
            # Normalize: 0ms = 0 penalty, 200ms = 20 penalty
            score -= min(20, avg_response / 10)

        # Recent failure penalty
        failures = self._failure_counts.get(ip, 0)
        score -= failures * 10

        # Bonus for being current (stability)
        if ip == self._current_primary:
            score += 5

        return max(0, score)

    async def update_if_needed(self) -> bool:
        """
        Check health and update DNS if needed.

        Returns:
            True if DNS was changed
        """
        await self.check_all()

        best_primary, best_secondary = self.get_best_dns()

        if best_primary != self._current_primary:
            old_primary = self._current_primary
            self._current_primary = best_primary
            self._current_secondary = best_secondary

            logger.info(
                f"DNS changed: {old_primary} -> {best_primary} "
                f"(secondary: {best_secondary})"
            )

            # Update dnsmasq config
            self._update_dnsmasq_config()

            return True

        return False

    def _update_dnsmasq_config(self) -> None:
        """Update dnsmasq upstream configuration."""
        if not self._current_primary:
            return

        try:
            config_lines = [
                "# SLA AI managed upstream DNS",
                f"# Updated: {datetime.now().isoformat()}",
                f"server={self._current_primary}",
            ]

            if self._current_secondary:
                config_lines.append(f"server={self._current_secondary}")

            config_content = "\n".join(config_lines) + "\n"

            with open(self.dnsmasq_config_path, "w") as f:
                f.write(config_content)

            logger.info(f"Updated dnsmasq config: {self.dnsmasq_config_path}")

            # Signal dnsmasq to reload
            self._reload_dnsmasq()

        except Exception as e:
            logger.error(f"Failed to update dnsmasq config: {e}")

    def _reload_dnsmasq(self) -> None:
        """Signal dnsmasq to reload configuration."""
        import subprocess

        try:
            # Send SIGHUP to reload
            subprocess.run(
                ["pkill", "-HUP", "dnsmasq"],
                capture_output=True,
                timeout=5,
            )
            logger.debug("Sent SIGHUP to dnsmasq")
        except Exception as e:
            logger.warning(f"Failed to reload dnsmasq: {e}")

    def get_status(self, ip: str) -> DNSStatus:
        """Get status for a DNS IP."""
        if ip not in self._response_times:
            return DNSStatus.UNKNOWN

        avg_response = self._get_avg_response(ip)
        success_rate = self._get_success_rate(ip)

        if success_rate < self.MIN_SUCCESS_RATE:
            return DNSStatus.FAILED

        if avg_response > self.DEGRADED_RESPONSE_MS:
            return DNSStatus.DEGRADED

        return DNSStatus.HEALTHY

    async def monitor(self, on_change: Optional[callable] = None) -> None:
        """
        Continuous monitoring loop.

        Args:
            on_change: Callback when DNS changes
        """
        while True:
            try:
                changed = await self.update_if_needed()

                if changed and on_change:
                    if asyncio.iscoroutinefunction(on_change):
                        await on_change(self._current_primary, self._current_secondary)
                    else:
                        on_change(self._current_primary, self._current_secondary)

            except Exception as e:
                logger.error(f"DNS monitoring error: {e}")

            await asyncio.sleep(self.check_interval_s)

    def get_summary(self) -> Dict:
        """Get summary of DNS health for all providers."""
        summary = {
            "current_primary": self._current_primary,
            "current_secondary": self._current_secondary,
            "providers": {},
        }

        for provider in self.providers:
            provider_summary = {
                "name": provider.name,
                "priority": provider.priority,
                "servers": {},
            }

            for ip in [provider.primary, provider.secondary]:
                if not ip:
                    continue

                provider_summary["servers"][ip] = {
                    "status": self.get_status(ip).value,
                    "avg_response_ms": self._get_avg_response(ip),
                    "success_rate": self._get_success_rate(ip),
                    "score": self._calculate_score(ip, provider.priority),
                }

            summary["providers"][provider.name] = provider_summary

        return summary

    def add_provider(self, provider: DNSProvider) -> None:
        """Add a DNS provider."""
        # Check if already exists
        for existing in self.providers:
            if existing.name == provider.name:
                logger.warning(f"Provider {provider.name} already exists")
                return

        self.providers.append(provider)
        logger.info(f"Added DNS provider: {provider.name}")

    def remove_provider(self, name: str) -> None:
        """Remove a DNS provider by name."""
        self.providers = [p for p in self.providers if p.name != name]
        logger.info(f"Removed DNS provider: {name}")
