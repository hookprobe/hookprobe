#!/usr/bin/env python3
"""
HookProbe Sentinel Security Module
"The Watchful Eye" - Lightweight protection for edge validators
Version: 5.0.0

Features:
- Rate limiting with token bucket algorithm
- Threat pattern detection
- File integrity monitoring
- Firewall management (iptables)

Memory target: ~10MB additional overhead
"""

import os
import sys
import json
import time
import hashlib
import logging
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, Tuple, List

logger = logging.getLogger("sentinel.security")


class RateLimiter:
    """Token bucket rate limiter for DDoS protection"""

    def __init__(self, rate: int = 100, burst: int = 200):
        """
        Initialize rate limiter.

        Args:
            rate: Requests per second allowed
            burst: Maximum burst size (bucket capacity)
        """
        self.rate = rate
        self.burst = burst
        self.tokens: Dict[str, float] = defaultdict(lambda: burst)
        self.last_update: Dict[str, float] = defaultdict(time.time)

    def allow(self, client_ip: str) -> bool:
        """
        Check if request from client_ip should be allowed.

        Returns:
            True if request allowed, False if rate limited
        """
        now = time.time()
        elapsed = now - self.last_update[client_ip]
        self.last_update[client_ip] = now

        # Add tokens based on elapsed time
        self.tokens[client_ip] = min(
            self.burst,
            self.tokens[client_ip] + elapsed * self.rate
        )

        if self.tokens[client_ip] >= 1:
            self.tokens[client_ip] -= 1
            return True
        return False

    def cleanup(self, max_age: int = 3600):
        """Remove entries older than max_age seconds"""
        now = time.time()
        expired = [ip for ip, ts in self.last_update.items() if now - ts > max_age]
        for ip in expired:
            del self.tokens[ip]
            del self.last_update[ip]

    def get_stats(self) -> dict:
        """Get rate limiter statistics"""
        return {
            "tracked_ips": len(self.tokens),
            "rate": self.rate,
            "burst": self.burst,
        }


class ThreatDetector:
    """Lightweight threat detection for edge validators"""

    # Known malicious patterns (lowercase for case-insensitive matching)
    SUSPICIOUS_PATTERNS = [
        b"../",           # Path traversal
        b"..%2f",         # Encoded path traversal
        b"%2e%2e/",       # Double-encoded path traversal
        b"<script",       # XSS attempt
        b"javascript:",   # XSS protocol
        b"onerror=",      # XSS event handler
        b"select ",       # SQL injection
        b"union ",        # SQL injection
        b"; drop",        # SQL injection
        b"insert into",   # SQL injection
        b"eval(",         # Code injection
        b"exec(",         # Code injection
        b"system(",       # Code injection
        b"/etc/passwd",   # Sensitive file access
        b"/etc/shadow",   # Sensitive file access
        b"cmd.exe",       # Windows command
        b"powershell",    # Windows PowerShell
        b".env",          # Environment file
        b".git/",         # Git directory
    ]

    # Scanner user agents to detect
    SCANNER_SIGNATURES = [
        b"nikto",
        b"sqlmap",
        b"nmap",
        b"masscan",
        b"dirbuster",
        b"gobuster",
        b"wfuzz",
        b"burp",
        b"zap",
    ]

    # Thresholds
    THRESHOLD_REQUESTS_PER_MIN = 300
    THRESHOLD_ERRORS_PER_MIN = 50
    THRESHOLD_UNIQUE_PATHS = 100

    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.path_counts: Dict[str, Set[str]] = defaultdict(set)
        self.last_reset = time.time()
        self.alert_callback = None
        self.stats = {
            "threats_detected": 0,
            "patterns_matched": 0,
            "scanners_detected": 0,
        }

    def check_request(self, client_ip: str, path: str = "/", body: bytes = b"",
                      headers: dict = None) -> Tuple[bool, str]:
        """
        Check if request should be allowed.

        Args:
            client_ip: Client IP address
            path: Request path
            body: Request body bytes
            headers: Request headers dict

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        # Check if IP is already blocked
        if client_ip in self.blocked_ips:
            return False, "IP blocked"

        # Reset counters every minute
        now = time.time()
        if now - self.last_reset > 60:
            self.request_counts.clear()
            self.error_counts.clear()
            self.path_counts.clear()
            self.last_reset = now

        # Check request rate
        self.request_counts[client_ip] += 1
        if self.request_counts[client_ip] > self.THRESHOLD_REQUESTS_PER_MIN:
            self._block_ip(client_ip, "Rate limit exceeded")
            return False, "Rate limit"

        # Check path scanning (too many unique paths = scanner)
        self.path_counts[client_ip].add(path)
        if len(self.path_counts[client_ip]) > self.THRESHOLD_UNIQUE_PATHS:
            self._block_ip(client_ip, "Path scanning detected")
            self.stats["scanners_detected"] += 1
            return False, "Path scanning"

        # Check for malicious patterns in path and body
        combined = path.encode() + body
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.lower() in combined.lower():
                self._block_ip(client_ip, f"Malicious pattern: {pattern.decode(errors='ignore')}")
                self.stats["patterns_matched"] += 1
                return False, "Malicious pattern"

        # Check headers for scanner signatures
        if headers:
            user_agent = headers.get("user-agent", "").lower().encode()
            for sig in self.SCANNER_SIGNATURES:
                if sig in user_agent:
                    self._block_ip(client_ip, f"Scanner detected: {sig.decode()}")
                    self.stats["scanners_detected"] += 1
                    return False, "Scanner detected"

        return True, "OK"

    def record_error(self, client_ip: str):
        """Record an error from this IP (too many errors = suspicious)"""
        self.error_counts[client_ip] += 1
        if self.error_counts[client_ip] > self.THRESHOLD_ERRORS_PER_MIN:
            self._block_ip(client_ip, "Too many errors")

    def _block_ip(self, ip: str, reason: str):
        """Block an IP address"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.stats["threats_detected"] += 1
            logger.warning(f"[SECURITY] Blocked IP {ip}: {reason}")
            if self.alert_callback:
                try:
                    self.alert_callback("ip_blocked", {"ip": ip, "reason": reason})
                except Exception:
                    pass

    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        self.blocked_ips.discard(ip)
        logger.info(f"[SECURITY] Unblocked IP {ip}")

    def get_blocked_ips(self) -> Set[str]:
        """Get set of currently blocked IPs"""
        return self.blocked_ips.copy()

    def get_stats(self) -> dict:
        """Get threat detector statistics"""
        return {
            **self.stats,
            "blocked_ips_count": len(self.blocked_ips),
            "tracked_ips": len(self.request_counts),
        }


class IntegrityChecker:
    """File integrity monitoring for critical files"""

    DEFAULT_WATCH_PATHS = [
        "/opt/hookprobe/sentinel/sentinel.py",
        "/opt/hookprobe/sentinel/sentinel_security.py",
        "/etc/hookprobe/sentinel.env",
    ]

    def __init__(self, watch_paths: List[str] = None):
        """
        Initialize integrity checker.

        Args:
            watch_paths: List of file paths to monitor
        """
        self.watch_paths = watch_paths or self.DEFAULT_WATCH_PATHS
        self.hashes: Dict[str, str] = {}
        self.last_check = time.time()
        self._compute_initial_hashes()

    def _compute_initial_hashes(self):
        """Compute initial file hashes"""
        for path in self.watch_paths:
            if os.path.exists(path):
                self.hashes[path] = self._hash_file(path)
                logger.debug(f"[INTEGRITY] Tracking: {path}")

    def _hash_file(self, path: str) -> str:
        """Compute SHA256 hash of file"""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"[INTEGRITY] Failed to hash {path}: {e}")
            return ""

    def check_integrity(self) -> List[dict]:
        """
        Check if any watched files have changed.

        Returns:
            List of change records with path, old_hash, new_hash
        """
        changes = []
        self.last_check = time.time()

        for path in self.watch_paths:
            if os.path.exists(path):
                current_hash = self._hash_file(path)
                if path in self.hashes:
                    if current_hash != self.hashes[path]:
                        change = {
                            "path": path,
                            "old_hash": self.hashes[path][:16],
                            "new_hash": current_hash[:16],
                            "detected_at": datetime.now().isoformat(),
                        }
                        changes.append(change)
                        logger.warning(f"[INTEGRITY] File changed: {path}")
                else:
                    # New file being tracked
                    self.hashes[path] = current_hash
            elif path in self.hashes:
                # File was deleted
                changes.append({
                    "path": path,
                    "old_hash": self.hashes[path][:16],
                    "new_hash": "DELETED",
                    "detected_at": datetime.now().isoformat(),
                })
                logger.warning(f"[INTEGRITY] File deleted: {path}")

        return changes

    def update_baseline(self, path: str = None):
        """Update baseline hash for a file (after legitimate update)"""
        if path:
            if os.path.exists(path):
                self.hashes[path] = self._hash_file(path)
        else:
            self._compute_initial_hashes()


class FirewallManager:
    """Manage iptables rules for protection"""

    CHAIN_NAME = "HOOKPROBE"

    @classmethod
    def setup_basic_rules(cls, health_port: int = 9090):
        """Setup basic firewall protection rules"""
        rules = [
            # Allow established connections
            f"-A {cls.CHAIN_NAME} -m state --state ESTABLISHED,RELATED -j ACCEPT",
            # Allow loopback
            f"-A {cls.CHAIN_NAME} -i lo -j ACCEPT",
            # Allow health check port
            f"-A {cls.CHAIN_NAME} -p tcp --dport {health_port} -j ACCEPT",
            # Rate limit new TCP connections
            f"-A {cls.CHAIN_NAME} -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT",
            # Drop invalid packets
            f"-A {cls.CHAIN_NAME} -m state --state INVALID -j DROP",
        ]

        # Create chain if it doesn't exist
        cls._run_iptables(f"-N {cls.CHAIN_NAME}")

        for rule in rules:
            cls._run_iptables(rule)

        logger.info("[FIREWALL] Basic rules configured")

    @classmethod
    def block_ip(cls, ip: str, reason: str = ""):
        """Block an IP address at firewall level"""
        if cls._run_iptables(f"-I INPUT -s {ip} -j DROP"):
            logger.info(f"[FIREWALL] Blocked IP {ip}" + (f": {reason}" if reason else ""))
            return True
        return False

    @classmethod
    def unblock_ip(cls, ip: str):
        """Unblock an IP address"""
        if cls._run_iptables(f"-D INPUT -s {ip} -j DROP"):
            logger.info(f"[FIREWALL] Unblocked IP {ip}")
            return True
        return False

    @classmethod
    def list_blocked(cls) -> List[str]:
        """List all blocked IPs"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                capture_output=True, text=True, timeout=5
            )
            blocked = []
            for line in result.stdout.split("\n"):
                if "DROP" in line and "anywhere" not in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        blocked.append(parts[3])
            return blocked
        except Exception:
            return []

    @staticmethod
    def _run_iptables(rule: str) -> bool:
        """Run an iptables command"""
        try:
            cmd = f"iptables {rule}"
            result = subprocess.run(
                cmd.split(), capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"[FIREWALL] Command failed: {e}")
            return False


class SecurityManager:
    """
    Main security manager combining all protection components.

    Usage:
        security = SecurityManager({
            "rate_limit": 100,
            "rate_burst": 200,
            "firewall_enabled": True,
        })

        # Check each incoming request
        allowed, reason = security.check_request(client_ip, path, body)
        if not allowed:
            # Reject request
            pass
    """

    def __init__(self, config: dict = None):
        """
        Initialize security manager.

        Args:
            config: Configuration dict with optional keys:
                - rate_limit: Requests per second (default: 100)
                - rate_burst: Burst size (default: 200)
                - firewall_enabled: Enable iptables blocking (default: True)
                - watch_paths: List of files to monitor integrity
        """
        self.config = config or {}

        # Initialize components
        self.rate_limiter = RateLimiter(
            rate=self.config.get("rate_limit", 100),
            burst=self.config.get("rate_burst", 200)
        )
        self.threat_detector = ThreatDetector()
        self.integrity_checker = IntegrityChecker(
            watch_paths=self.config.get("watch_paths")
        )

        self.firewall_enabled = self.config.get("firewall_enabled", True)

        # Statistics
        self.stats = {
            "requests_total": 0,
            "requests_blocked": 0,
            "attacks_detected": 0,
            "ips_blocked": 0,
            "start_time": time.time(),
        }

        logger.info("[SECURITY] Security manager initialized")

    def check_request(self, client_ip: str, path: str = "/",
                      body: bytes = b"", headers: dict = None) -> Tuple[bool, str]:
        """
        Check if a request should be allowed.

        Args:
            client_ip: Client IP address
            path: Request path
            body: Request body
            headers: Request headers

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        self.stats["requests_total"] += 1

        # Rate limiting check
        if not self.rate_limiter.allow(client_ip):
            self.stats["requests_blocked"] += 1
            return False, "Rate limited"

        # Threat detection check
        allowed, reason = self.threat_detector.check_request(
            client_ip, path, body, headers
        )
        if not allowed:
            self.stats["requests_blocked"] += 1
            self.stats["attacks_detected"] += 1

            # Block at firewall level for persistent threats
            if self.firewall_enabled:
                if FirewallManager.block_ip(client_ip, reason):
                    self.stats["ips_blocked"] += 1

            return False, reason

        return True, "OK"

    def get_stats(self) -> dict:
        """Get comprehensive security statistics"""
        uptime = time.time() - self.stats["start_time"]
        integrity_changes = self.integrity_checker.check_integrity()

        return {
            **self.stats,
            "uptime": int(uptime),
            "blocked_ips": list(self.threat_detector.get_blocked_ips()),
            "integrity_changes": integrity_changes,
            "rate_limiter": self.rate_limiter.get_stats(),
            "threat_detector": self.threat_detector.get_stats(),
        }

    def periodic_cleanup(self):
        """Periodic cleanup tasks (call every minute or so)"""
        self.rate_limiter.cleanup()
        # Integrity check runs automatically in get_stats()

    def unblock_ip(self, ip: str):
        """Unblock an IP from all protection layers"""
        self.threat_detector.unblock_ip(ip)
        if self.firewall_enabled:
            FirewallManager.unblock_ip(ip)


# Export main classes
__all__ = [
    "SecurityManager",
    "RateLimiter",
    "ThreatDetector",
    "IntegrityChecker",
    "FirewallManager"
]


# CLI for testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    print("HookProbe Sentinel Security Module v5.0.0")
    print("-" * 40)

    security = SecurityManager({
        "rate_limit": 10,
        "rate_burst": 20,
        "firewall_enabled": False,  # Don't modify iptables in test
    })

    # Test rate limiting
    print("\nTesting rate limiter:")
    test_ip = "192.168.1.100"
    for i in range(25):
        allowed, reason = security.check_request(test_ip, "/test")
        if not allowed:
            print(f"  Request {i+1}: BLOCKED ({reason})")
            break
        print(f"  Request {i+1}: allowed")

    # Test threat detection
    print("\nTesting threat detection:")
    attacks = [
        ("/admin/../../../etc/passwd", b""),
        ("/api", b"SELECT * FROM users"),
        ("/page", b"<script>alert('xss')</script>"),
    ]
    for path, body in attacks:
        allowed, reason = security.check_request("10.0.0." + str(hash(path) % 255), path, body)
        print(f"  {path[:30]:30} -> {'BLOCKED' if not allowed else 'allowed'} ({reason})")

    # Print stats
    print("\nSecurity Stats:")
    stats = security.get_stats()
    for key, value in stats.items():
        if not isinstance(value, (list, dict)):
            print(f"  {key}: {value}")
