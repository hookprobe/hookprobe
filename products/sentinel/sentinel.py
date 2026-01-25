#!/usr/bin/env python3
"""
HookProbe Sentinel - "The Watchful Eye"
Ultra-Lightweight Edge Validator with Security Protection
Version: 5.0.0

Standalone validator for constrained devices:
- Raspberry Pi 3/Zero/Pico
- Low-power ARM/IoT gateways
- LTE/mobile network deployments

Features:
- Edge device validation
- Rate limiting / DDoS protection
- Threat detection
- Integrity monitoring
- Minimal footprint (~50MB)

Memory target: 128-384MB
"""

import os
import sys
import time
import json
import socket
import hashlib
import signal
import gc
import logging
import logging.handlers
from datetime import datetime, timezone
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

# ============================================================
# CONFIGURATION (from environment with bounds checking)
# ============================================================


def safe_int_env(name: str, default: int, min_val: int = 0, max_val: int = 65535) -> int:
    """
    Safely parse integer from environment variable with bounds checking.

    Args:
        name: Environment variable name
        default: Default value if not set or invalid
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        Bounded integer value
    """
    try:
        value = int(os.environ.get(name, str(default)))
        return max(min_val, min(max_val, value))
    except (ValueError, TypeError):
        return default


def sanitize_node_id(node_id: str) -> str:
    """Sanitize node ID to prevent log injection and invalid characters."""
    import re
    # Only allow alphanumeric, hyphens, underscores
    sanitized = re.sub(r'[^a-zA-Z0-9\-_]', '', node_id)
    return sanitized[:64] if sanitized else "sentinel-unknown"


NODE_ID = sanitize_node_id(os.environ.get("SENTINEL_NODE_ID", f"sentinel-{socket.gethostname()}"))
MESH_ENDPOINT = os.environ.get("MESH_ENDPOINT", "mesh.hookprobe.com")
MESH_PORT = safe_int_env("MESH_PORT", 8443, 1, 65535)
LISTEN_PORT = safe_int_env("SENTINEL_PORT", 8443, 1, 65535)
METRICS_PORT = safe_int_env("METRICS_PORT", 9090, 1, 65535)
REGION = sanitize_node_id(os.environ.get("SENTINEL_REGION", "unknown"))
TIER = os.environ.get("SENTINEL_TIER", "community")
if TIER not in ("community", "professional", "enterprise"):
    TIER = "community"
MEMORY_LIMIT = safe_int_env("MEMORY_LIMIT_MB", 256, 64, 4096)
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Memory optimization
CACHE_MAX = 500
CACHE_TTL = 300
EDGE_LIMIT = 50
GC_INTERVAL = 60

# Rate limits
RATE_LIMITS = {"community": 100, "professional": 1000, "enterprise": 10000}

# Security settings
SECURITY_ENABLED = os.environ.get("ENABLE_THREAT_DETECTION", "true").lower() == "true"
RATE_LIMITING_ENABLED = os.environ.get("ENABLE_RATE_LIMITING", "true").lower() == "true"
BLOCK_ON_ATTACK = os.environ.get("BLOCK_ON_ATTACK", "true").lower() == "true"
# CWE-20: Bounds validation for rate limiting parameters
RATE_LIMIT_REQUESTS = safe_int_env("RATE_LIMIT_REQUESTS", 100, min_val=1, max_val=10000)
RATE_LIMIT_BURST = safe_int_env("RATE_LIMIT_BURST", 200, min_val=1, max_val=20000)

# QSecBit - Quantum-Safe Security Capabilities
QSECBIT_ENABLED = os.environ.get("QSECBIT_ENABLED", "true").lower() == "true"

# SECURITY FIX: Validate HMAC algorithm against allowlist (CWE-327)
ALLOWED_HMAC_ALGOS = {'sha3-256', 'sha256', 'sha384', 'sha512'}
QSECBIT_HMAC_ALGO = os.environ.get("QSECBIT_HMAC_ALGO", "sha3-256")
if QSECBIT_HMAC_ALGO not in ALLOWED_HMAC_ALGOS:
    raise ValueError(f"Invalid HMAC algorithm: {QSECBIT_HMAC_ALGO}. Allowed: {ALLOWED_HMAC_ALGOS}")

QSECBIT_KEY_ROTATION_HOURS = safe_int_env("QSECBIT_KEY_ROTATION_HOURS", 24, min_val=1, max_val=8760)
QSECBIT_SESSION_TIMEOUT = safe_int_env("QSECBIT_SESSION_TIMEOUT", 3600, min_val=60, max_val=86400)

# SECURITY FIX: Signature enforcement mode for backward compatibility
# "WARN" = log invalid signatures but allow (migration period)
# "REJECT" = block invalid signatures (production)
SIGNATURE_ENFORCEMENT_MODE = os.environ.get("SIGNATURE_ENFORCEMENT_MODE", "REJECT")
if SIGNATURE_ENFORCEMENT_MODE not in ("WARN", "REJECT"):
    SIGNATURE_ENFORCEMENT_MODE = "REJECT"

# Shared secret for HMAC (must be set in production)
QSECBIT_SHARED_SECRET = os.environ.get("QSECBIT_SHARED_SECRET", None)

# ============================================================
# LOGGING
# ============================================================

log_handlers = [logging.StreamHandler(sys.stdout)]
if os.path.exists('/var/log/hookprobe'):
    log_handlers.append(logging.handlers.RotatingFileHandler(
        '/var/log/hookprobe/sentinel.log',
        maxBytes=1024*1024, backupCount=2
    ))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=log_handlers
)
log = logging.getLogger("sentinel")

# ============================================================
# LRU CACHE (memory-efficient)
# ============================================================

class LRUCache:
    """
    Minimal LRU cache with TTL.

    SECURITY: Fixed memory bounding to prevent DoS via memory exhaustion (CWE-400).
    Uses collections.deque for O(1) operations instead of list.
    """

    def __init__(self, max_size=500, ttl=300):
        from collections import OrderedDict
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict = OrderedDict()  # Maintains insertion order

    def get(self, key):
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['t'] < self.ttl:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return entry['v']
            # Expired - remove
            del self.cache[key]
        return None

    def set(self, key, value):
        # If key exists, update and move to end
        if key in self.cache:
            self.cache[key] = {'v': value, 't': time.time()}
            self.cache.move_to_end(key)
            return

        # Evict oldest entries if at capacity
        while len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)  # Remove oldest

        # Add new entry
        self.cache[key] = {'v': value, 't': time.time()}

    def cleanup(self):
        now = time.time()
        # Create list of expired keys (can't modify dict during iteration)
        expired = [k for k, v in self.cache.items() if now - v['t'] > self.ttl]
        for k in expired:
            del self.cache[k]

# ============================================================
# SECURITY MODULE (optional - loads if available)
# ============================================================

security_manager = None
try:
    from sentinel_security import SecurityManager
    security_manager = SecurityManager({
        "rate_limit": RATE_LIMIT_REQUESTS,
        "rate_burst": RATE_LIMIT_BURST,
        "firewall_enabled": BLOCK_ON_ATTACK,
    })
    log.info("Security module loaded")
except ImportError:
    log.warning("Security module not available - running without protection")
except Exception as e:
    log.warning(f"Failed to load security module: {e}")

# ============================================================
# MESH MODULE (optional - loads if available)
# ============================================================

MESH_ENABLED = os.environ.get("ENABLE_MESH", "true").lower() == "true"
mesh_agent = None

if MESH_ENABLED:
    try:
        from lib.mesh_integration import SentinelMeshAgent, SentinelMeshConfig
        mesh_config = SentinelMeshConfig.from_env()
        mesh_agent = SentinelMeshAgent(mesh_config)
        log.info("Mesh module loaded")
    except ImportError:
        log.info("Mesh module not available - running standalone")
    except Exception as e:
        log.warning(f"Failed to load mesh module: {e}")

# ============================================================
# MSSP MODULE (optional - export metrics to MSSP dashboard)
# ============================================================

MSSP_ENABLED = os.environ.get("ENABLE_MSSP", "true").lower() == "true"
MSSP_URL = os.environ.get("MSSP_URL", "https://mssp.hookprobe.com")
MSSP_DEVICE_ID = os.environ.get("MSSP_DEVICE_ID", f"sentinel-{NODE_ID}")
MSSP_AUTH_TOKEN = os.environ.get("MSSP_AUTH_TOKEN", "")
MSSP_HEARTBEAT_INTERVAL = safe_int_env("MSSP_HEARTBEAT_INTERVAL", 60, min_val=30, max_val=600)


# ============================================================
# MSSP CLIENT (lightweight, stdlib-only)
# ============================================================

class SentinelMSSPClient:
    """
    Lightweight MSSP client for Sentinel edge devices.

    Uses only stdlib to minimize memory footprint.
    Exports metrics to MSSP dashboard for central monitoring.
    """

    def __init__(self, mssp_url: str, device_id: str, auth_token: str = '', timeout: int = 10):
        self.mssp_url = mssp_url.rstrip('/')
        self.device_id = device_id
        self.auth_token = auth_token
        self.timeout = timeout
        self._stats = {'heartbeats_sent': 0, 'heartbeats_failed': 0, 'threats_reported': 0}
        self._last_heartbeat = None

    def send_heartbeat(self, metrics: dict) -> bool:
        """
        Send heartbeat with metrics to MSSP.

        Args:
            metrics: Dict with cpu_usage, ram_usage, qsecbit_score, etc.

        Returns:
            True if successful
        """
        url = f"{self.mssp_url}/api/v1/devices/{self.device_id}/heartbeat/"

        payload = {
            'status': metrics.get('status', 'online'),
            'cpu_usage': metrics.get('cpu_usage', 0),
            'ram_usage': metrics.get('ram_usage', 0),
            'disk_usage': metrics.get('disk_usage', 0),
            'uptime_seconds': metrics.get('uptime_seconds', 0),
            'qsecbit_score': metrics.get('qsecbit_score'),
            'threat_events_count': metrics.get('threat_events_count', 0),
        }

        try:
            import urllib.request
            import urllib.error

            data = json.dumps(payload).encode('utf-8')
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Sentinel-MSSP-Client/1.0',
            }
            if self.auth_token:
                headers['Authorization'] = f'Token {self.auth_token}'

            req = urllib.request.Request(url, data=data, headers=headers, method='POST')

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status in (200, 201):
                    self._stats['heartbeats_sent'] += 1
                    self._last_heartbeat = datetime.now(timezone.utc)
                    log.debug(f"[MSSP] Heartbeat sent: CPU={payload['cpu_usage']:.1f}%")
                    return True

        except urllib.error.HTTPError as e:
            log.warning(f"[MSSP] HTTP error: {e.code}")
        except urllib.error.URLError as e:
            log.debug(f"[MSSP] Connection error: {e.reason}")
        except Exception as e:
            log.debug(f"[MSSP] Request error: {e}")

        self._stats['heartbeats_failed'] += 1
        return False

    def report_threat(self, threat_type: str, severity: str, source_ip: str, detection_method: str, details: dict = None) -> bool:
        """
        Report a threat event to MSSP.

        Args:
            threat_type: Type of threat (e.g., 'invalid_signature', 'rate_abuse')
            severity: 'critical', 'high', 'medium', 'low', 'info'
            source_ip: Source IP of the threat
            detection_method: How it was detected
            details: Additional context

        Returns:
            True if successful
        """
        url = f"{self.mssp_url}/api/v1/security/threats/ingest/"

        payload = {
            'source': 'sentinel',
            'device_id': self.device_id,
            'threats': [{
                'event_id': f"SENTINEL-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')[:17]}",
                'threat_type': threat_type,
                'severity': severity,
                'source_ip': source_ip,
                'description': f"Sentinel detected: {threat_type}",
                'detection_method': detection_method,
                'confidence': details.get('confidence', 0.8) if details else 0.8,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'raw_data': {
                    'node_id': NODE_ID,
                    'region': REGION,
                    **(details or {}),
                },
            }],
        }

        try:
            import urllib.request
            import urllib.error

            data = json.dumps(payload).encode('utf-8')
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Sentinel-MSSP-Client/1.0',
            }
            if self.auth_token:
                headers['Authorization'] = f'Token {self.auth_token}'

            req = urllib.request.Request(url, data=data, headers=headers, method='POST')

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status in (200, 201, 207):
                    self._stats['threats_reported'] += 1
                    log.info(f"[MSSP] Threat reported: {threat_type} from {source_ip}")
                    return True

        except Exception as e:
            log.debug(f"[MSSP] Threat report error: {e}")

        return False

    def get_stats(self) -> dict:
        """Get MSSP client statistics."""
        return {
            **self._stats,
            'last_heartbeat': self._last_heartbeat.isoformat() if self._last_heartbeat else None,
        }


# Initialize MSSP client if enabled
mssp_client = None
if MSSP_ENABLED:
    try:
        mssp_client = SentinelMSSPClient(
            mssp_url=MSSP_URL,
            device_id=MSSP_DEVICE_ID,
            auth_token=MSSP_AUTH_TOKEN,
        )
        log.info(f"MSSP client initialized: {MSSP_URL}")
    except Exception as e:
        log.warning(f"Failed to initialize MSSP client: {e}")


# ============================================================
# SENTINEL VALIDATOR
# ============================================================

class Sentinel:
    """Lightweight edge device validator with security protection and mesh connectivity"""

    def __init__(self):
        self.cache = LRUCache(CACHE_MAX, CACHE_TTL)
        self.rates = defaultdict(int)
        self.rate_window = 0
        self.stats = {'ok': 0, 'fail': 0, 'err': 0, 'blocked': 0, 'start': time.time()}
        self.edges = []
        self.security = security_manager
        self.mesh = mesh_agent
        self.mssp = mssp_client

        # Start mesh agent if available
        if self.mesh:
            self.mesh.start()
            # Register threat handler
            self.mesh.on_threat(self._handle_mesh_threat)

    def _handle_mesh_threat(self, intel):
        """Handle threat intelligence from mesh"""
        # SECURITY: Sanitize log input to prevent log injection (CWE-117)
        safe_type = str(intel.threat_type)[:30] if intel.threat_type else "unknown"
        safe_ioc = str(intel.ioc_value)[:20] if intel.ioc_value else ""
        # Remove control characters
        import re
        safe_type = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', safe_type)
        safe_ioc = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', safe_ioc)

        log.info(f"[MESH] Threat received: {safe_type} - {safe_ioc}... (severity: {intel.severity})")

        # Could trigger local blocking if severity is critical
        if intel.severity <= 1 and self.security:
            self.security.threat_detector._block_ip(intel.ioc_value, f"mesh:{safe_type}")

        # Report to MSSP for central tracking
        if self.mssp:
            severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}
            self.report_threat_to_mssp(
                threat_type=safe_type,
                severity=severity_map.get(intel.severity, 'medium'),
                source_ip=safe_ioc,
                detection_method='mesh_intelligence',
                details={'original_severity': intel.severity},
            )

    # ================================================================
    # SECURITY FIX: HMAC Signature Verification (CWE-326, CWE-285)
    # ================================================================

    def _get_hmac_key(self, edge_id: bytes) -> bytes:
        """
        Derive HMAC key for edge device.

        In production, this should use a key derivation function (KDF)
        with the edge_id and a master secret.
        """
        import hmac
        if QSECBIT_SHARED_SECRET:
            # Derive per-edge key from shared secret
            master = QSECBIT_SHARED_SECRET.encode() if isinstance(QSECBIT_SHARED_SECRET, str) else QSECBIT_SHARED_SECRET
            return hmac.new(master, edge_id, hashlib.sha256).digest()
        else:
            # WARN: No shared secret configured - using edge_id as key (insecure for production)
            log.warning("[SECURITY] No QSECBIT_SHARED_SECRET set - signature verification weakened")
            return hashlib.sha256(edge_id).digest()

    def _verify_signature(self, message: bytes, signature: bytes, key: bytes) -> bool:
        """
        Verify HMAC signature using configured algorithm.

        SECURITY FIX: Actually verify the signature that was previously ignored (CWE-347).

        Args:
            message: The data that was signed (edge_id + timestamp)
            signature: The 8-byte signature from the message
            key: The HMAC key for this edge device

        Returns:
            True if signature is valid, False otherwise
        """
        import hmac

        # Map algorithm names to hashlib functions
        algo_map = {
            'sha3-256': hashlib.sha3_256,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
        }

        algo = algo_map.get(QSECBIT_HMAC_ALGO, hashlib.sha3_256)
        expected = hmac.new(key, message, algo).digest()[:8]  # First 8 bytes

        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(signature, expected)

    def validate(self, data: bytes, addr: tuple) -> dict:
        """
        Validate HTP message from edge device with security checks.

        SECURITY FIX: Reordered validation flow (CWE-285, CWE-400):
        1. Parse message (no state changes)
        2. SIGNATURE VERIFICATION (before any rate limiting!)
        3. Cache lookup (only after authentication)
        4. Rate limiting (per authenticated edge_id)
        5. Timestamp and additional checks
        6. Security module checks
        """
        client_ip = addr[0] if addr else "unknown"

        try:
            # ============================================================
            # STEP 1: Parse message (no state changes, no rate limiting)
            # ============================================================
            if len(data) < 32:
                self.stats['fail'] += 1
                return {'valid': False, 'reason': 'short'}

            edge_id_bytes = data[:16]
            ts_bytes = data[16:24]
            sig_bytes = data[24:32]

            edge_id = edge_id_bytes.hex()

            # ============================================================
            # STEP 2: SIGNATURE VERIFICATION (before rate limiting!)
            # SECURITY FIX: This was completely missing before (CWE-347)
            # ============================================================
            if QSECBIT_ENABLED:
                message = edge_id_bytes + ts_bytes  # What was signed
                key = self._get_hmac_key(edge_id_bytes)

                if not self._verify_signature(message, sig_bytes, key):
                    self.stats['fail'] += 1

                    if SIGNATURE_ENFORCEMENT_MODE == "REJECT":
                        log.warning(f"[SECURITY] Invalid signature from {client_ip} (edge: {edge_id[:12]}...)")
                        # Report to mesh but don't trigger rate limiting
                        if self.mesh:
                            self.mesh.report_threat(client_ip, "invalid_signature", severity=3,
                                                  context={"edge_id": edge_id[:16]})
                        return {'valid': False, 'reason': 'invalid_signature'}
                    else:
                        # WARN mode - log but continue (migration period)
                        log.warning(f"[SECURITY] Invalid signature WARN from {client_ip} (edge: {edge_id[:12]}...) - allowing for migration")

            # ============================================================
            # STEP 3: Cache lookup (only after signature verification)
            # ============================================================
            cache_key = hashlib.sha256(data[:24]).hexdigest()[:16]
            cached = self.cache.get(cache_key)
            if cached:
                return cached

            # ============================================================
            # STEP 4: Rate limiting (per AUTHENTICATED edge_id)
            # SECURITY FIX: Now only counts authenticated requests (CWE-400)
            # ============================================================
            window = int(time.time() / 60)
            if window != self.rate_window:
                self.rates.clear()
                self.rate_window = window

            self.rates[edge_id[:16]] += 1
            if self.rates[edge_id[:16]] > RATE_LIMITS.get(TIER, 100):
                # Report rate abuse to mesh
                if self.mesh:
                    self.mesh.report_threat(client_ip, "rate_abuse", severity=3,
                                          context={"edge_id": edge_id[:16]})
                return {'valid': False, 'reason': 'rate'}

            # ============================================================
            # STEP 5: Timestamp and additional validation
            # ============================================================
            result = self._check(edge_id, ts_bytes, addr)
            self.cache.set(cache_key, result)

            # ============================================================
            # STEP 6: Security module checks (pattern matching, etc.)
            # ============================================================
            if result['valid'] and self.security and SECURITY_ENABLED:
                allowed, reason = self.security.check_request(client_ip, "/validate", data)
                if not allowed:
                    self.stats['blocked'] += 1
                    log.warning(f"[SECURITY] Blocked {client_ip}: {reason}")
                    if self.mesh:
                        self.mesh.report_threat(client_ip, "malicious_request", severity=2,
                                              context={"reason": reason})
                    return {'valid': False, 'reason': 'blocked', 'security': reason}

            if result['valid']:
                self.stats['ok'] += 1
                self._track(edge_id)
            else:
                self.stats['fail'] += 1
                if self.security:
                    self.security.threat_detector.record_error(client_ip)

            return result

        except Exception as e:
            self.stats['err'] += 1
            log.error(f"Validation error: {e}")
            return {'valid': False, 'reason': 'error'}

    def _check(self, edge_id: str, ts_bytes: bytes, addr: tuple) -> dict:
        """
        Internal validation checks (timestamp only).

        NOTE: Rate limiting is now handled in validate() AFTER signature verification.
        This method only handles timestamp validation.
        """
        if len(edge_id) != 32:
            return {'valid': False, 'reason': 'bad_id'}

        try:
            ts = int.from_bytes(ts_bytes, 'big')
            if abs(int(time.time()) - ts) > 300:
                return {'valid': False, 'reason': 'stale'}
        except (ValueError, OverflowError, TypeError) as e:
            # SECURITY: Avoid bare except (CWE-754)
            log.debug(f"Timestamp parse error: {type(e).__name__}")
            return {'valid': False, 'reason': 'bad_ts'}

        # Rate limiting removed - now handled in validate() after signature verification

        return {'valid': True, 'edge_id': edge_id, 'ts': ts, 'sentinel': NODE_ID}

    def _track(self, edge_id: str):
        """Track active edges"""
        if edge_id not in self.edges:
            self.edges.append(edge_id)
            if len(self.edges) > EDGE_LIMIT:
                self.edges.pop(0)

    def cleanup(self):
        """Periodic cleanup"""
        self.cache.cleanup()
        if self.security:
            self.security.periodic_cleanup()
        gc.collect()

    def export_metrics_to_mssp(self) -> bool:
        """
        Export current metrics to MSSP dashboard.

        Called periodically by background task.
        """
        if not self.mssp:
            return False

        # Collect metrics
        metrics = self._collect_metrics()

        # Send heartbeat
        return self.mssp.send_heartbeat(metrics)

    def _collect_metrics(self) -> dict:
        """Collect current system and validation metrics."""
        metrics = {
            'status': 'online',
            'cpu_usage': 0.0,
            'ram_usage': 0.0,
            'disk_usage': 0.0,
            'uptime_seconds': int(time.time() - self.stats['start']),
            'qsecbit_score': None,
            'threat_events_count': self.stats.get('blocked', 0),
        }

        # CPU usage (simplified)
        try:
            with open('/proc/stat', 'r') as f:
                cpu_line = f.readline()
                cpu_times = list(map(int, cpu_line.split()[1:5]))
                idle = cpu_times[3]
                total = sum(cpu_times)
                metrics['cpu_usage'] = min(100, max(0, (1 - idle / max(total, 1)) * 100))
        except Exception:
            pass

        # Memory usage
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = int(parts[1].strip().split()[0])
                        meminfo[key] = value

                total = meminfo.get('MemTotal', 1)
                available = meminfo.get('MemAvailable', 0)
                metrics['ram_usage'] = min(100, max(0, (1 - available / total) * 100))
        except Exception:
            pass

        # Calculate QSecBit score based on validation success rate
        total_validations = self.stats['ok'] + self.stats['fail']
        if total_validations > 0:
            success_rate = self.stats['ok'] / total_validations
            # QSecBit = base score adjusted by validation health
            metrics['qsecbit_score'] = round(0.5 + (success_rate * 0.5), 2)

        return metrics

    def report_threat_to_mssp(self, threat_type: str, severity: str, source_ip: str,
                               detection_method: str, details: dict = None) -> bool:
        """
        Report a detected threat to MSSP dashboard.

        Args:
            threat_type: Type of threat
            severity: 'critical', 'high', 'medium', 'low', 'info'
            source_ip: Source of the threat
            detection_method: How it was detected
            details: Additional context

        Returns:
            True if reported successfully
        """
        if not self.mssp:
            return False

        return self.mssp.report_threat(
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            detection_method=detection_method,
            details=details,
        )

# ============================================================
# METRICS HTTP SERVER
# ============================================================

sentinel = None  # Global reference

class MetricsHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for /metrics and /health"""

    def log_message(self, *args):
        pass  # Suppress logs

    def do_GET(self):
        if self.path == '/metrics':
            self._metrics()
        elif self.path == '/health':
            self._health()
        else:
            self.send_error(404)

    def _metrics(self):
        s = sentinel.stats
        up = time.time() - s['start']

        # Security stats
        sec_stats = sentinel.security.get_stats() if sentinel.security else {}
        blocked_count = s.get('blocked', 0)
        attacks = sec_stats.get('attacks_detected', 0)
        blocked_ips = len(sec_stats.get('blocked_ips', []))

        m = f"""# HELP sentinel_validated Total validated
# TYPE sentinel_validated counter
sentinel_validated {s['ok']}
# HELP sentinel_rejected Total rejected
# TYPE sentinel_rejected counter
sentinel_rejected {s['fail']}
# HELP sentinel_errors Total errors
# TYPE sentinel_errors counter
sentinel_errors {s['err']}
# HELP sentinel_blocked Total blocked by security
# TYPE sentinel_blocked counter
sentinel_blocked {blocked_count}
# HELP sentinel_attacks_detected Attacks detected
# TYPE sentinel_attacks_detected counter
sentinel_attacks_detected {attacks}
# HELP sentinel_blocked_ips Number of blocked IPs
# TYPE sentinel_blocked_ips gauge
sentinel_blocked_ips {blocked_ips}
# HELP sentinel_edges Active edges
# TYPE sentinel_edges gauge
sentinel_edges {len(sentinel.edges)}
# HELP sentinel_uptime Uptime seconds
# TYPE sentinel_uptime gauge
sentinel_uptime {up:.0f}
# HELP sentinel_security_enabled Security protection enabled
# TYPE sentinel_security_enabled gauge
sentinel_security_enabled {1 if sentinel.security else 0}
# HELP sentinel_info Info
# TYPE sentinel_info gauge
sentinel_info{{node="{NODE_ID}",region="{REGION}",tier="{TIER}"}} 1
"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(m.encode())

    def _health(self):
        s = sentinel.stats
        sec_stats = sentinel.security.get_stats() if sentinel.security else {}
        mesh_status = sentinel.mesh.get_status() if sentinel.mesh else {}
        mssp_stats = sentinel.mssp.get_stats() if sentinel.mssp else {}

        h = {
            'status': 'healthy',
            'version': '5.0.0',
            'node_id': NODE_ID,
            'region': REGION,
            'tier': TIER,
            'uptime': int(time.time() - s['start']),
            'validated': s['ok'],
            'rejected': s['fail'],
            'blocked': s.get('blocked', 0),
            'edges': len(sentinel.edges),
            'memory_mb': MEMORY_LIMIT,
            'security': {
                'enabled': sentinel.security is not None,
                'attacks_detected': sec_stats.get('attacks_detected', 0),
                'blocked_ips': len(sec_stats.get('blocked_ips', [])),
                'integrity_ok': len(sec_stats.get('integrity_changes', [])) == 0
            },
            'mesh': {
                'enabled': sentinel.mesh is not None,
                'state': mesh_status.get('state', 'disabled'),
                'peers': mesh_status.get('peers', 0),
                'threats_received': mesh_status.get('stats', {}).get('threats_received', 0),
                'threats_shared': mesh_status.get('stats', {}).get('threats_shared', 0),
            },
            'mssp': {
                'enabled': sentinel.mssp is not None,
                'heartbeats_sent': mssp_stats.get('heartbeats_sent', 0),
                'heartbeats_failed': mssp_stats.get('heartbeats_failed', 0),
                'threats_reported': mssp_stats.get('threats_reported', 0),
                'last_heartbeat': mssp_stats.get('last_heartbeat'),
            }
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(h).encode())

# ============================================================
# BACKGROUND TASKS
# ============================================================

def mesh_reporter():
    """Report to mesh every minute"""
    while True:
        try:
            time.sleep(60)
            s = sentinel.stats
            report = {
                'id': NODE_ID,
                'region': REGION,
                'tier': TIER,
                'type': 'lite',
                'ts': datetime.now(timezone.utc).isoformat(),
                'stats': {'ok': s['ok'], 'fail': s['fail'], 'err': s['err'], 'edges': len(sentinel.edges)}
            }
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            header = NODE_ID.encode()[:16].ljust(16, b'\x00')
            sock.sendto(header + json.dumps(report).encode(), (MESH_ENDPOINT, MESH_PORT))
            sock.close()
            log.debug(f"Report sent: {len(sentinel.edges)} edges")
        except Exception as e:
            log.warning(f"Mesh report failed: {e}")

def memory_monitor():
    """Periodic cleanup"""
    while True:
        time.sleep(GC_INTERVAL)
        sentinel.cleanup()


def mssp_heartbeat():
    """Periodic MSSP heartbeat export"""
    while True:
        try:
            time.sleep(MSSP_HEARTBEAT_INTERVAL)
            if sentinel and sentinel.mssp:
                sentinel.export_metrics_to_mssp()
        except Exception as e:
            log.warning(f"MSSP heartbeat failed: {e}")

# ============================================================
# MAIN
# ============================================================

def main():
    global sentinel

    log.info("=" * 50)
    log.info("HookProbe Sentinel v5.0.0")
    log.info("\"The Watchful Eye\"")
    log.info("=" * 50)
    log.info(f"Node:     {NODE_ID}")
    log.info(f"Region:   {REGION}")
    log.info(f"Tier:     {TIER}")
    log.info(f"Listen:   UDP:{LISTEN_PORT}")
    log.info(f"Metrics:  HTTP:{METRICS_PORT}")
    log.info(f"Mesh:     {MESH_ENDPOINT}:{MESH_PORT}")
    log.info(f"Memory:   {MEMORY_LIMIT}MB limit")
    log.info("-" * 50)
    log.info(f"Security: {'ENABLED' if security_manager else 'DISABLED'}")
    if security_manager:
        log.info(f"  Rate Limit: {RATE_LIMIT_REQUESTS}/s (burst: {RATE_LIMIT_BURST})")
        log.info(f"  Threat Detection: {SECURITY_ENABLED}")
        log.info(f"  Block on Attack: {BLOCK_ON_ATTACK}")
    log.info(f"QSecBit:  {'ENABLED' if QSECBIT_ENABLED else 'DISABLED'}")
    if QSECBIT_ENABLED:
        log.info(f"  HMAC Algorithm: {QSECBIT_HMAC_ALGO}")
        log.info(f"  Key Rotation: {QSECBIT_KEY_ROTATION_HOURS}h")
    log.info(f"Mesh:     {'ENABLED' if mesh_agent else 'DISABLED'}")
    if mesh_agent:
        log.info(f"  Role: SENTINEL (Validator)")
        log.info(f"  Max Peers: {mesh_agent.config.max_peers}")
    log.info(f"MSSP:     {'ENABLED' if mssp_client else 'DISABLED'}")
    if mssp_client:
        log.info(f"  URL: {MSSP_URL}")
        log.info(f"  Device ID: {MSSP_DEVICE_ID}")
        log.info(f"  Heartbeat: {MSSP_HEARTBEAT_INTERVAL}s")
    log.info("=" * 50)

    sentinel = Sentinel()

    # Start metrics server
    http = HTTPServer(('0.0.0.0', METRICS_PORT), MetricsHandler)
    Thread(target=http.serve_forever, daemon=True).start()
    log.info(f"Metrics: http://localhost:{METRICS_PORT}/health")

    # Start background tasks
    Thread(target=mesh_reporter, daemon=True).start()
    Thread(target=memory_monitor, daemon=True).start()
    if mssp_client:
        Thread(target=mssp_heartbeat, daemon=True).start()
        log.info(f"MSSP heartbeat: every {MSSP_HEARTBEAT_INTERVAL}s")

    # UDP validation socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', LISTEN_PORT))
    log.info(f"Listening on UDP port {LISTEN_PORT}")
    log.info("Ready...")

    # Graceful shutdown
    def shutdown(sig, frame):
        log.info("Shutting down...")
        if sentinel.mesh:
            sentinel.mesh.stop()
        sock.close()
        http.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Main loop
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            result = sentinel.validate(data, addr)
            sock.sendto(json.dumps(result).encode(), addr)

            if result['valid']:
                log.debug(f"OK: {result.get('edge_id', '?')[:12]}... from {addr[0]}")
            else:
                log.debug(f"FAIL: {result.get('reason', '?')} from {addr[0]}")
        except socket.error:
            break
        except Exception as e:
            log.error(f"Error: {e}")

if __name__ == "__main__":
    main()
