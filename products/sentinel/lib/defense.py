"""
Sentinel Defense Engine — Standalone nftables/dnsmasq Actions

Provides local defense capabilities for Sentinel nodes without
requiring NAPSE or heavy IDS. Works within 256MB RAM budget.

Actions:
    - IP blocking via nftables
    - DNS sinkhole via dnsmasq blocklist
    - Rate limiting via nftables
    - Connection termination via conntrack
"""

import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Paths
NFTABLES_CONF = Path("/etc/hookprobe/sentinel-nftables.conf")
SINKHOLE_FILE = Path("/etc/hookprobe/sentinel-sinkhole.list")
BLOCKED_IPS_FILE = Path("/var/lib/hookprobe/sentinel-blocked.json")

# Safety limits
MAX_BLOCKED_IPS = 500
MAX_SINKHOLED_DOMAINS = 1000
MAX_BLOCK_DURATION = 86400  # 24 hours

# Input validation patterns
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')


def _validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    if not ip or not IP_PATTERN.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def _validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_PATTERN.match(domain))


class SentinelDefenseEngine:
    """Lightweight defense engine for Sentinel nodes.

    Uses nftables for IP blocking and rate limiting.
    Uses dnsmasq blocklist for DNS sinkholes.
    All actions are audited and time-limited.
    """

    def __init__(self):
        self._blocked_ips: Dict[str, Dict] = {}  # ip -> {reason, expires, timestamp}
        self._sinkholed: Dict[str, str] = {}  # domain -> reason
        self._lock = threading.Lock()
        self._audit_log: List[Dict] = []

        # Start cleanup thread
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True,
        )
        self._cleanup_thread.start()

    def block_ip(self, ip: str, duration: int = 3600, reason: str = "") -> bool:
        """Block an IP address via nftables.

        Args:
            ip: IPv4 address to block.
            duration: Block duration in seconds (max 24h).
            reason: Human-readable reason for the block.

        Returns:
            True if the block was applied.
        """
        if not _validate_ip(ip):
            logger.warning("Invalid IP address: %s", ip)
            return False

        # Don't block RFC 1918 private ranges or loopback
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                          '172.20.', '172.21.', '172.22.', '172.23.',
                          '172.24.', '172.25.', '172.26.', '172.27.',
                          '172.28.', '172.29.', '172.30.', '172.31.',
                          '192.168.', '127.')):
            logger.warning("Refusing to block private/loopback IP: %s", ip)
            return False

        duration = min(duration, MAX_BLOCK_DURATION)

        with self._lock:
            if len(self._blocked_ips) >= MAX_BLOCKED_IPS:
                logger.warning("Max blocked IPs reached (%d)", MAX_BLOCKED_IPS)
                return False

            self._blocked_ips[ip] = {
                "reason": reason,
                "expires": time.time() + duration,
                "timestamp": time.time(),
            }

        # Apply nftables rule
        try:
            subprocess.run(
                ["nft", "add", "rule", "inet", "sentinel", "input",
                 "ip", "saddr", ip, "drop"],
                capture_output=True, timeout=5, check=False,
            )
            self._audit("block_ip", ip, reason, duration)
            logger.info("Blocked IP %s for %ds: %s", ip, duration, reason)
            return True
        except Exception as e:
            logger.error("nftables block failed for %s: %s", ip, e)
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP block."""
        if not _validate_ip(ip):
            return False

        with self._lock:
            self._blocked_ips.pop(ip, None)

        try:
            # Flush and re-add all remaining blocks
            self._rebuild_nftables()
            self._audit("unblock_ip", ip, "manual unblock", 0)
            logger.info("Unblocked IP %s", ip)
            return True
        except Exception as e:
            logger.error("nftables unblock failed for %s: %s", ip, e)
            return False

    def dns_sinkhole(self, domain: str, reason: str = "") -> bool:
        """Add a domain to the DNS sinkhole via dnsmasq.

        Args:
            domain: Domain name to sinkhole.
            reason: Reason for sinkheling.

        Returns:
            True if the sinkhole was applied.
        """
        if not _validate_domain(domain):
            logger.warning("Invalid domain: %s", domain)
            return False

        with self._lock:
            if len(self._sinkholed) >= MAX_SINKHOLED_DOMAINS:
                logger.warning("Max sinkholed domains reached")
                return False
            self._sinkholed[domain] = reason

        try:
            self._write_sinkhole_file()
            # Signal dnsmasq to reload
            subprocess.run(
                ["killall", "-HUP", "dnsmasq"],
                capture_output=True, timeout=5, check=False,
            )
            self._audit("dns_sinkhole", domain, reason, 0)
            logger.info("Sinkholed domain %s: %s", domain, reason)
            return True
        except Exception as e:
            logger.error("DNS sinkhole failed for %s: %s", domain, e)
            return False

    def rate_limit(self, ip: str, reason: str = "", pps: int = 50) -> bool:
        """Apply rate limiting to an IP address.

        Args:
            ip: IPv4 address to rate limit.
            reason: Reason for rate limiting.
            pps: Packets per second limit.

        Returns:
            True if rate limit was applied.
        """
        if not _validate_ip(ip):
            logger.warning("Invalid IP for rate limit: %s", ip)
            return False

        pps = max(10, min(pps, 1000))  # Clamp to sane range

        try:
            subprocess.run(
                ["nft", "add", "rule", "inet", "sentinel", "input",
                 "ip", "saddr", ip, "limit", "rate", f"{pps}/second", "accept"],
                capture_output=True, timeout=5, check=False,
            )
            self._audit("rate_limit", ip, f"{reason} ({pps} pps)", 3600)
            logger.info("Rate limited %s to %d pps: %s", ip, pps, reason)
            return True
        except Exception as e:
            logger.error("Rate limit failed for %s: %s", ip, e)
            return False

    def terminate_connection(self, ip: str) -> bool:
        """Terminate active connections from an IP via conntrack."""
        if not _validate_ip(ip):
            return False

        try:
            subprocess.run(
                ["conntrack", "-D", "-s", ip],
                capture_output=True, timeout=5, check=False,
            )
            self._audit("terminate_connection", ip, "connection terminated", 0)
            return True
        except Exception as e:
            logger.error("Connection termination failed for %s: %s", ip, e)
            return False

    def get_blocked(self) -> Dict[str, Dict]:
        """Get all currently blocked IPs."""
        with self._lock:
            return dict(self._blocked_ips)

    def get_sinkholed(self) -> Dict[str, str]:
        """Get all sinkholed domains."""
        with self._lock:
            return dict(self._sinkholed)

    def get_stats(self) -> Dict:
        """Get defense engine statistics."""
        with self._lock:
            return {
                "blocked_ips": len(self._blocked_ips),
                "sinkholed_domains": len(self._sinkholed),
                "audit_entries": len(self._audit_log),
                "running": self._running,
            }

    def stop(self) -> None:
        """Stop the defense engine."""
        self._running = False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _audit(self, action: str, target: str, reason: str, duration: int) -> None:
        """Log an action to the audit trail."""
        entry = {
            "action": action,
            "target": target,
            "reason": reason,
            "duration": duration,
            "timestamp": time.time(),
        }
        self._audit_log.append(entry)
        # Keep last 1000 entries
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-1000:]

    def _write_sinkhole_file(self) -> None:
        """Write sinkhole domains to dnsmasq config file."""
        SINKHOLE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SINKHOLE_FILE, 'w') as f:
            for domain in self._sinkholed:
                f.write(f"address=/{domain}/0.0.0.0\n")

    def _rebuild_nftables(self) -> None:
        """Rebuild nftables rules from current blocked IPs."""
        subprocess.run(
            ["nft", "flush", "chain", "inet", "sentinel", "input"],
            capture_output=True, timeout=5, check=False,
        )
        with self._lock:
            for ip in self._blocked_ips:
                subprocess.run(
                    ["nft", "add", "rule", "inet", "sentinel", "input",
                     "ip", "saddr", ip, "drop"],
                    capture_output=True, timeout=5, check=False,
                )

    def _cleanup_loop(self) -> None:
        """Periodically remove expired blocks."""
        while self._running:
            time.sleep(60)
            now = time.time()
            expired = []

            with self._lock:
                for ip, info in self._blocked_ips.items():
                    if info["expires"] <= now:
                        expired.append(ip)

            for ip in expired:
                self.unblock_ip(ip)
                logger.info("Auto-unblocked expired IP: %s", ip)
