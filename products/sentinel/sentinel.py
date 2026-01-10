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
MSSP_ENDPOINT = os.environ.get("MSSP_ENDPOINT", "mssp.hookprobe.com")
MSSP_PORT = safe_int_env("MSSP_PORT", 8443, 1, 65535)
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
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", "200"))

# QSecBit - Quantum-Safe Security Capabilities
QSECBIT_ENABLED = os.environ.get("QSECBIT_ENABLED", "true").lower() == "true"
QSECBIT_HMAC_ALGO = os.environ.get("QSECBIT_HMAC_ALGO", "sha3-256")
QSECBIT_KEY_ROTATION_HOURS = int(os.environ.get("QSECBIT_KEY_ROTATION_HOURS", "24"))
QSECBIT_SESSION_TIMEOUT = int(os.environ.get("QSECBIT_SESSION_TIMEOUT", "3600"))

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

    def validate(self, data: bytes, addr: tuple) -> dict:
        """Validate HTP message from edge device with security checks"""
        client_ip = addr[0] if addr else "unknown"

        try:
            # Security check first (if enabled)
            if self.security and SECURITY_ENABLED:
                allowed, reason = self.security.check_request(client_ip, "/validate", data)
                if not allowed:
                    self.stats['blocked'] += 1
                    log.warning(f"[SECURITY] Blocked {client_ip}: {reason}")
                    # Share threat with mesh
                    if self.mesh:
                        self.mesh.report_threat(client_ip, "malicious_request", severity=2,
                                              context={"reason": reason})
                    return {'valid': False, 'reason': 'blocked', 'security': reason}

            if len(data) < 32:
                self.stats['fail'] += 1
                if self.security:
                    self.security.threat_detector.record_error(client_ip)
                return {'valid': False, 'reason': 'short'}

            edge_id = data[:16].hex()
            ts_bytes = data[16:24]
            sig = data[24:32].hex()

            # Check cache
            key = f"{edge_id}:{sig[:8]}"
            cached = self.cache.get(key)
            if cached:
                return cached

            # Validate
            result = self._check(edge_id, ts_bytes, addr)
            self.cache.set(key, result)

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
        """Internal validation checks"""
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

        # Rate limit
        window = int(time.time() / 60)
        if window != self.rate_window:
            self.rates.clear()
            self.rate_window = window

        self.rates[edge_id[:16]] += 1
        if self.rates[edge_id[:16]] > RATE_LIMITS.get(TIER, 100):
            # Report rate limit abuse to mesh (potential DDoS)
            if self.mesh and addr:
                self.mesh.report_threat(addr[0], "rate_abuse", severity=3,
                                      context={"edge_id": edge_id[:16]})
            return {'valid': False, 'reason': 'rate'}

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
            }
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(h).encode())

# ============================================================
# BACKGROUND TASKS
# ============================================================

def mssp_reporter():
    """Report to MSSP every minute"""
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
            sock.sendto(header + json.dumps(report).encode(), (MSSP_ENDPOINT, MSSP_PORT))
            sock.close()
            log.debug(f"Report sent: {len(sentinel.edges)} edges")
        except Exception as e:
            log.warning(f"MSSP report failed: {e}")

def memory_monitor():
    """Periodic cleanup"""
    while True:
        time.sleep(GC_INTERVAL)
        sentinel.cleanup()

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
    log.info(f"MSSP:     {MSSP_ENDPOINT}:{MSSP_PORT}")
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
    log.info("=" * 50)

    sentinel = Sentinel()

    # Start metrics server
    http = HTTPServer(('0.0.0.0', METRICS_PORT), MetricsHandler)
    Thread(target=http.serve_forever, daemon=True).start()
    log.info(f"Metrics: http://localhost:{METRICS_PORT}/health")

    # Start background tasks
    Thread(target=mssp_reporter, daemon=True).start()
    Thread(target=memory_monitor, daemon=True).start()

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
