"""
HookProbe Universal MSSP Client

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Universal MSSP client for all product tiers. Handles:
- Device heartbeat with metrics
- Threat finding submission (v2 intelligence API)
- Recommendation polling
- Execution feedback reporting
- Legacy v1 threat/alert forwarding (backward compat)

Architecture:
    Edge Node (any tier) → MSSP Dashboard (Central)
    - Edge collects local metrics, threats, and AEGIS intelligence
    - MSSP aggregates, routes to Nexus for deep analysis
    - Recommendations flow back for local execution + mesh propagation

Endpoints:
    POST /api/v1/devices/{device_id}/heartbeat/        - Device metrics (legacy)
    POST /api/v1/security/threats/ingest/              - Threat reports (legacy)
    POST /api/v1/security/alerts/ingest/               - IDS alerts (legacy)
    POST /api/v2/intel/findings/                       - Intelligence findings (new)
    GET  /api/v2/intel/recommendations/                - Poll recommendations (new)
    POST /api/v2/intel/recommendations/{id}/ack        - Acknowledge recommendation (new)
    POST /api/v2/intel/feedback/                       - Execution feedback (new)
"""

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .types import (
    DeviceMetrics,
    ExecutionFeedback,
    RecommendedAction,
    ThreatFinding,
)

logger = logging.getLogger(__name__)

# Configuration
DEFAULT_MSSP_URL = 'https://mssp.hookprobe.com'
DEFAULT_TIMEOUT = 10
HEARTBEAT_INTERVAL = 60
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY = 5


def _load_config_value(key: str, default: str, config_file: Path = None) -> str:
    """Load a config value from environment or config file."""
    env_value = os.environ.get(key)
    if env_value:
        return env_value

    if config_file is None:
        # Auto-detect tier config
        for path in [
            Path('/etc/hookprobe/fortress.conf'),
            Path('/etc/hookprobe/guardian.conf'),
            Path('/etc/hookprobe/sentinel.conf'),
            Path('/etc/hookprobe/nexus.conf'),
        ]:
            if path.exists():
                config_file = path
                break

    if config_file and config_file.exists():
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith(f'{key}='):
                        value = stripped.split('=', 1)[1].strip().strip('"\'')
                        if value and value.lower() != 'none':
                            return value
        except Exception as e:
            logger.debug("Could not load config %s: %s", key, e)

    return default


def _validate_mssp_url(url: str) -> str:
    """Validate MSSP URL to prevent SSRF against internal services."""
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)

    if parsed.scheme != 'https':
        logger.warning("MSSP URL must use HTTPS, got: %s. Falling back to default.", parsed.scheme)
        return DEFAULT_MSSP_URL

    hostname = parsed.hostname or ''

    # Block private/internal IPs
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            logger.warning("MSSP URL points to private/reserved IP. Falling back to default.")
            return DEFAULT_MSSP_URL
    except ValueError:
        pass

    # Block localhost variants
    if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
        logger.warning("MSSP URL points to localhost. Falling back to default.")
        return DEFAULT_MSSP_URL

    # Block cloud metadata endpoints
    if hostname in ('169.254.169.254', 'metadata.google.internal'):
        logger.warning("MSSP URL points to cloud metadata endpoint. Falling back to default.")
        return DEFAULT_MSSP_URL

    return url


def _generate_device_id(tier: str = "unknown") -> str:
    """Generate a unique device ID from hostname and MAC."""
    import hashlib
    import socket

    hostname = socket.gethostname()
    mac = 'unknown'
    try:
        import uuid as _uuid
        mac = ':'.join(f'{(_uuid.getnode() >> i) & 0xff:02x}' for i in range(0, 48, 8))
    except Exception:
        pass

    unique_string = f"{hostname}-{mac}"
    return f"{tier}-{hashlib.sha256(unique_string.encode()).hexdigest()[:12]}"


class HookProbeMSSPClient:
    """Universal MSSP client for all HookProbe product tiers.

    Handles both legacy v1 API (heartbeat, threats, alerts) and
    new v2 intelligence API (findings, recommendations, feedback).
    """

    VERSION = '2.0.0'

    def __init__(
        self,
        tier: str = "fortress",
        mssp_url: str = None,
        device_id: str = None,
        auth_token: str = None,
        config_file: Path = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.tier = tier
        raw_url = mssp_url or _load_config_value('MSSP_URL', DEFAULT_MSSP_URL, config_file)
        self.mssp_url = _validate_mssp_url(raw_url)
        self.device_id = device_id or _load_config_value(
            'DEVICE_ID', _generate_device_id(tier), config_file
        )
        self.auth_token = auth_token or _load_config_value('MSSP_AUTH_TOKEN', '', config_file)
        self.timeout = timeout

        # Background heartbeat
        self._heartbeat_running = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._last_heartbeat: Optional[datetime] = None
        self._metrics_callback: Optional[Callable[[], DeviceMetrics]] = None

        # Statistics
        self._stats = {
            'heartbeats_sent': 0,
            'heartbeats_failed': 0,
            'findings_submitted': 0,
            'findings_failed': 0,
            'recommendations_received': 0,
            'feedback_sent': 0,
            'threats_reported': 0,
            'threats_failed': 0,
        }

        logger.info(
            "MSSP client initialized: %s (tier=%s, device=%s)",
            self.mssp_url, self.tier, self.device_id,
        )

    # =========================================================================
    # HTTP Transport
    # =========================================================================

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
        retry: bool = True,
    ) -> Optional[Dict]:
        """Make HTTP request to MSSP with retry logic."""
        url = f"{self.mssp_url.rstrip('/')}{endpoint}"
        attempts = MAX_RETRY_ATTEMPTS if retry else 1

        for attempt in range(attempts):
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': f'HookProbe-MSSP-Client/{self.VERSION} ({self.tier})',
                    'X-HookProbe-Tier': self.tier,
                    'X-HookProbe-Device': self.device_id,
                }
                if self.auth_token:
                    headers['Authorization'] = f'Token {self.auth_token}'

                if data:
                    payload = json.dumps(data).encode('utf-8')
                    request = urllib.request.Request(
                        url, data=payload, method=method, headers=headers,
                    )
                else:
                    request = urllib.request.Request(url, method=method, headers=headers)

                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    if response.status in (200, 201):
                        return json.loads(response.read().decode('utf-8'))
                    else:
                        logger.warning("MSSP returned %d for %s", response.status, endpoint)
                        return None

            except urllib.error.HTTPError as e:
                logger.warning("MSSP HTTP error: %d for %s", e.code, endpoint)
                if e.code in (401, 403):
                    logger.error("MSSP authentication failed — check MSSP_AUTH_TOKEN")
                    return None
                if e.code == 404:
                    return None
            except urllib.error.URLError as e:
                logger.debug("MSSP connection error (attempt %d): %s", attempt + 1, e.reason)
            except Exception as e:
                logger.debug("MSSP request error (attempt %d): %s", attempt + 1, e)

            if attempt < attempts - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))

        return None

    # =========================================================================
    # V2 Intelligence API — Findings
    # =========================================================================

    def submit_finding(self, finding: ThreatFinding) -> Optional[Dict]:
        """Submit a threat finding to MSSP for analysis.

        POST /api/v2/intel/findings/

        Returns:
            Response dict with finding_id and status, or None on failure
        """
        if not finding.source_node_id:
            finding.source_node_id = self.device_id
        if not finding.source_tier:
            finding.source_tier = self.tier

        payload = finding.to_dict()
        response = self._request('POST', '/api/v2/intel/findings/', payload)

        if response is not None:
            self._stats['findings_submitted'] += 1
            logger.info(
                "Finding submitted: %s (%s, %s)",
                finding.finding_id, finding.threat_type, finding.severity,
            )
            return response

        self._stats['findings_failed'] += 1
        return None

    def get_finding_status(self, finding_id: str) -> Optional[Dict]:
        """Get the status and recommendations for a finding.

        GET /api/v2/intel/findings/{finding_id}/
        """
        return self._request('GET', f'/api/v2/intel/findings/{finding_id}/')

    # =========================================================================
    # V2 Intelligence API — Recommendations
    # =========================================================================

    def poll_recommendations(self) -> List[RecommendedAction]:
        """Poll MSSP for new recommendations for this device.

        GET /api/v2/intel/recommendations/?device_id={device_id}

        Returns:
            List of RecommendedAction objects
        """
        response = self._request(
            'GET',
            f'/api/v2/intel/recommendations/?device_id={self.device_id}',
            retry=False,
        )

        if response is None:
            return []

        actions = []
        for item in response.get('recommendations', []):
            try:
                action = RecommendedAction.from_dict(item)
                actions.append(action)
            except Exception as e:
                logger.warning("Failed to parse recommendation: %s", e)

        if actions:
            self._stats['recommendations_received'] += len(actions)
            logger.info("Received %d recommendation(s) from MSSP", len(actions))

        return actions

    def acknowledge_recommendation(self, action_id: str) -> bool:
        """Acknowledge receipt of a recommendation.

        POST /api/v2/intel/recommendations/{action_id}/ack
        """
        response = self._request(
            'POST',
            f'/api/v2/intel/recommendations/{action_id}/ack',
            {'device_id': self.device_id},
        )
        return response is not None

    # =========================================================================
    # V2 Intelligence API — Feedback
    # =========================================================================

    def submit_feedback(self, feedback: ExecutionFeedback) -> bool:
        """Submit execution feedback to MSSP for continuous learning.

        POST /api/v2/intel/feedback/
        """
        if not feedback.node_id:
            feedback.node_id = self.device_id

        response = self._request('POST', '/api/v2/intel/feedback/', feedback.to_dict())
        if response is not None:
            self._stats['feedback_sent'] += 1
            return True
        return False

    # =========================================================================
    # V1 Legacy API — Heartbeat
    # =========================================================================

    def send_heartbeat(self, metrics: DeviceMetrics = None) -> bool:
        """Send device heartbeat with metrics to MSSP.

        POST /api/v1/devices/{device_id}/heartbeat/
        """
        if metrics is None:
            if self._metrics_callback:
                metrics = self._metrics_callback()
            else:
                metrics = self._collect_local_metrics()

        payload = metrics.to_dict()
        endpoint = f'/api/v1/devices/{self.device_id}/heartbeat/'

        response = self._request('POST', endpoint, payload)
        if response is not None:
            self._last_heartbeat = datetime.now()
            self._stats['heartbeats_sent'] += 1
            return True

        self._stats['heartbeats_failed'] += 1
        return False

    def _collect_local_metrics(self) -> DeviceMetrics:
        """Collect local system metrics."""
        metrics = DeviceMetrics(aegis_tier=self.tier)

        try:
            with open('/proc/stat', 'r') as f:
                cpu_line = f.readline()
                cpu_times = list(map(int, cpu_line.split()[1:5]))
                idle = cpu_times[3]
                total = sum(cpu_times)
                metrics.cpu_usage = min(100, max(0, (1 - idle / max(total, 1)) * 100))
        except Exception:
            pass

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
                metrics.ram_usage = min(100, max(0, (1 - available / total) * 100))
        except Exception:
            pass

        try:
            stat = os.statvfs('/')
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bfree * stat.f_frsize
            metrics.disk_usage = min(100, max(0, (1 - free / max(total, 1)) * 100))
        except Exception:
            pass

        try:
            with open('/proc/uptime', 'r') as f:
                metrics.uptime_seconds = int(float(f.read().split()[0]))
        except Exception:
            pass

        return metrics

    def set_metrics_callback(self, callback: Callable[[], DeviceMetrics]) -> None:
        self._metrics_callback = callback

    def start_heartbeat(self, interval: int = HEARTBEAT_INTERVAL) -> None:
        if self._heartbeat_running:
            return
        self._heartbeat_running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, args=(interval,), daemon=True,
        )
        self._heartbeat_thread.start()
        logger.info("Background heartbeat started (interval: %ds)", interval)

    def _heartbeat_loop(self, interval: int) -> None:
        while self._heartbeat_running:
            try:
                self.send_heartbeat()
            except Exception as e:
                logger.warning("Heartbeat error: %s", e)
            time.sleep(interval)

    def stop_heartbeat(self) -> None:
        self._heartbeat_running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5.0)

    # =========================================================================
    # V1 Legacy API — Threats & Alerts
    # =========================================================================

    def report_threats(self, threats: List[Dict]) -> bool:
        """Report threat events to MSSP (legacy v1 format).

        POST /api/v1/security/threats/ingest/
        """
        if not threats:
            return True

        payload = {
            'source': self.tier,
            'device_id': self.device_id,
            'threats': threats,
        }

        response = self._request('POST', '/api/v1/security/threats/ingest/', payload)
        if response is not None:
            self._stats['threats_reported'] += len(threats)
            return True

        self._stats['threats_failed'] += len(threats)
        return False

    def forward_ids_alerts(
        self,
        source: str,
        events: List[Dict],
        log_type: str = 'alert',
    ) -> bool:
        """Forward IDS alerts to MSSP (NAPSE EVE JSON format).

        POST /api/v1/security/alerts/ingest/
        """
        if not events:
            return True

        payload = {'source': source, 'log_type': log_type, 'events': events}
        response = self._request('POST', '/api/v1/security/alerts/ingest/', payload)
        return response is not None

    # =========================================================================
    # Health & Stats
    # =========================================================================

    def health_check(self) -> Dict:
        response = self._request('GET', '/health/', retry=False)
        connected = response is not None
        return {
            'connected': connected,
            'mssp_url': self.mssp_url,
            'device_id': self.device_id,
            'tier': self.tier,
            'mssp_status': response.get('status') if response else None,
            'last_heartbeat': self._last_heartbeat.isoformat() if self._last_heartbeat else None,
            'stats': self._stats.copy(),
        }

    def get_stats(self) -> Dict:
        return {
            **self._stats,
            'last_heartbeat': self._last_heartbeat.isoformat() if self._last_heartbeat else None,
            'heartbeat_running': self._heartbeat_running,
            'tier': self.tier,
        }


# =============================================================================
# Singleton per tier
# =============================================================================

_clients: Dict[str, HookProbeMSSPClient] = {}
_client_lock = threading.Lock()


def get_mssp_client(tier: str = "fortress", **kwargs) -> HookProbeMSSPClient:
    """Get or create the singleton MSSP client for a tier."""
    with _client_lock:
        if tier not in _clients:
            _clients[tier] = HookProbeMSSPClient(tier=tier, **kwargs)
        return _clients[tier]
