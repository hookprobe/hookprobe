#!/usr/bin/env python3
"""
Fortress MSSP Client

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module provides a client for Fortress to push telemetry
to the MSSP dashboard:
- Device heartbeat with metrics
- Threat event reporting
- QSecBit score updates

Architecture:
    Fortress (Edge) → MSSP Dashboard (Central)
    - Fortress collects local metrics and threat data
    - MSSP aggregates and displays across all deployments
    - Enables centralized monitoring and alerting

Endpoints Used:
    POST /api/v1/devices/{device_id}/heartbeat/  - Device metrics
    POST /api/v1/security/threats/ingest/        - Guardian threat reports
    POST /api/v1/security/alerts/ingest/         - IDS alert ingestion
"""

import json
import logging
import os
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Configuration
CONFIG_FILE = Path('/etc/hookprobe/fortress.conf')
DEFAULT_MSSP_URL = 'https://mssp.hookprobe.com'
DEFAULT_TIMEOUT = 10  # seconds
HEARTBEAT_INTERVAL = 60  # seconds between heartbeats
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY = 5  # seconds


@dataclass
class DeviceMetrics:
    """Device telemetry metrics for heartbeat."""
    status: str = 'online'
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    disk_usage: float = 0.0
    uptime_seconds: int = 0
    qsecbit_score: Optional[float] = None
    threat_events_count: int = 0
    network_rx_rate: float = 0.0
    network_tx_rate: float = 0.0

    def to_dict(self) -> Dict:
        """Convert to dictionary for API payload."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ThreatEvent:
    """Threat event for reporting to MSSP."""
    event_id: str
    threat_type: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str = ''
    detection_method: str = ''
    confidence: float = 0.0
    timestamp: Optional[str] = None
    raw_data: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for API payload."""
        data = asdict(self)
        if self.timestamp is None:
            data['timestamp'] = datetime.now().isoformat()
        return {k: v for k, v in data.items() if v is not None}


class FortressMSSPClient:
    """
    Client for pushing telemetry from Fortress to MSSP dashboard.

    Handles:
    - Periodic heartbeat with device metrics
    - Threat event reporting
    - IDS alert forwarding
    - Retry logic with exponential backoff
    """

    def __init__(
        self,
        mssp_url: str = None,
        device_id: str = None,
        auth_token: str = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        """
        Initialize MSSP client.

        Args:
            mssp_url: MSSP dashboard URL (defaults to config/env)
            device_id: Unique device identifier (defaults to config/env)
            auth_token: API authentication token (defaults to config/env)
            timeout: Request timeout in seconds
        """
        raw_url = mssp_url or self._load_config('MSSP_URL', DEFAULT_MSSP_URL)
        self.mssp_url = self._validate_url(raw_url)
        self.device_id = device_id or self._load_config('DEVICE_ID', self._generate_device_id())
        self.auth_token = auth_token or self._load_config('MSSP_AUTH_TOKEN', '')
        self.timeout = timeout

        # Background heartbeat state
        self._heartbeat_running = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._last_heartbeat: Optional[datetime] = None
        self._metrics_callback: Optional[callable] = None

        # Statistics
        self._stats = {
            'heartbeats_sent': 0,
            'heartbeats_failed': 0,
            'threats_reported': 0,
            'threats_failed': 0,
        }

        logger.info(f"MSSP client initialized: {self.mssp_url} (device: {self.device_id})")

    def _load_config(self, key: str, default: str) -> str:
        """Load configuration from file or environment."""
        # Check environment first
        env_value = os.environ.get(key)
        if env_value:
            return env_value

        # Check config file
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f:
                    for line in f:
                        if line.strip().startswith(f'{key}='):
                            value = line.split('=', 1)[1].strip().strip('"\'')
                            if value and value.lower() != 'none':
                                return value
        except Exception as e:
            logger.debug(f"Could not load config {key}: {e}")

        return default

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate MSSP URL to prevent SSRF against internal services."""
        from urllib.parse import urlparse
        import ipaddress

        parsed = urlparse(url)

        # Must be HTTPS
        if parsed.scheme != 'https':
            logger.warning(f"MSSP URL must use HTTPS, got: {parsed.scheme}. Falling back to default.")
            return DEFAULT_MSSP_URL

        hostname = parsed.hostname or ''

        # Block private/internal IPs
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                logger.warning(f"MSSP URL points to private/reserved IP. Falling back to default.")
                return DEFAULT_MSSP_URL
        except ValueError:
            pass  # Not an IP, it's a hostname — that's fine

        # Block localhost variants
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
            logger.warning(f"MSSP URL points to localhost. Falling back to default.")
            return DEFAULT_MSSP_URL

        # Block metadata endpoints (cloud SSRF)
        if hostname in ('169.254.169.254', 'metadata.google.internal'):
            logger.warning(f"MSSP URL points to cloud metadata endpoint. Falling back to default.")
            return DEFAULT_MSSP_URL

        return url

    def _generate_device_id(self) -> str:
        """Generate a unique device ID from hostname and MAC."""
        import socket
        import hashlib

        hostname = socket.gethostname()
        # Try to get first MAC address
        mac = 'unknown'
        try:
            import uuid
            mac = ':'.join(f'{(uuid.getnode() >> i) & 0xff:02x}' for i in range(0, 48, 8))
        except Exception:
            pass

        unique_string = f"{hostname}-{mac}"
        return f"fortress-{hashlib.sha256(unique_string.encode()).hexdigest()[:12]}"

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
        retry: bool = True,
    ) -> Optional[Dict]:
        """
        Make HTTP request to MSSP.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request payload
            retry: Whether to retry on failure

        Returns:
            Response JSON or None on failure
        """
        url = f"{self.mssp_url.rstrip('/')}{endpoint}"
        attempts = MAX_RETRY_ATTEMPTS if retry else 1

        for attempt in range(attempts):
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Fortress-MSSP-Client/1.0',
                }
                if self.auth_token:
                    headers['Authorization'] = f'Token {self.auth_token}'

                if data:
                    payload = json.dumps(data).encode('utf-8')
                    request = urllib.request.Request(
                        url,
                        data=payload,
                        method=method,
                        headers=headers,
                    )
                else:
                    request = urllib.request.Request(url, method=method, headers=headers)

                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    if response.status in (200, 201):
                        return json.loads(response.read().decode('utf-8'))
                    else:
                        logger.warning(f"MSSP returned {response.status} for {endpoint}")
                        return None

            except urllib.error.HTTPError as e:
                logger.warning(f"MSSP HTTP error: {e.code} for {endpoint}")
                if e.code == 401:
                    logger.error("MSSP authentication failed - check MSSP_AUTH_TOKEN")
                    return None  # Don't retry auth errors
                if e.code == 404:
                    return None  # Don't retry not found
            except urllib.error.URLError as e:
                logger.debug(f"MSSP connection error (attempt {attempt + 1}): {e.reason}")
            except Exception as e:
                logger.debug(f"MSSP request error (attempt {attempt + 1}): {e}")

            if attempt < attempts - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))

        return None

    # =========================================================================
    # HEARTBEAT
    # =========================================================================

    def send_heartbeat(self, metrics: DeviceMetrics = None) -> bool:
        """
        Send device heartbeat with metrics to MSSP.

        POST /api/v1/devices/{device_id}/heartbeat/

        Args:
            metrics: Device metrics (or use callback if set)

        Returns:
            True if successful
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
            logger.debug(f"Heartbeat sent: CPU={metrics.cpu_usage:.1f}% QSecBit={metrics.qsecbit_score}")
            return True

        self._stats['heartbeats_failed'] += 1
        return False

    def _collect_local_metrics(self) -> DeviceMetrics:
        """Collect local system metrics."""
        metrics = DeviceMetrics()

        try:
            # CPU usage
            with open('/proc/stat', 'r') as f:
                cpu_line = f.readline()
                cpu_times = list(map(int, cpu_line.split()[1:5]))
                idle = cpu_times[3]
                total = sum(cpu_times)
                # Simplified - would need delta calculation for accuracy
                metrics.cpu_usage = min(100, max(0, (1 - idle / max(total, 1)) * 100))
        except Exception:
            pass

        try:
            # Memory usage
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
            # Disk usage
            import os
            stat = os.statvfs('/')
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bfree * stat.f_frsize
            metrics.disk_usage = min(100, max(0, (1 - free / max(total, 1)) * 100))
        except Exception:
            pass

        try:
            # Uptime
            with open('/proc/uptime', 'r') as f:
                metrics.uptime_seconds = int(float(f.read().split()[0]))
        except Exception:
            pass

        # QSecBit score from file
        try:
            qsecbit_file = Path('/opt/hookprobe/fortress/data/qsecbit_stats.json')
            if qsecbit_file.exists():
                with open(qsecbit_file, 'r') as f:
                    qs = json.load(f)
                    metrics.qsecbit_score = float(qs.get('score', 0.85))
                    metrics.threat_events_count = int(qs.get('threats_detected', 0))
        except Exception:
            pass

        return metrics

    def set_metrics_callback(self, callback: callable) -> None:
        """Set callback function to collect metrics for heartbeat."""
        self._metrics_callback = callback

    def start_heartbeat(self, interval: int = HEARTBEAT_INTERVAL) -> None:
        """Start background heartbeat thread."""
        if self._heartbeat_running:
            return

        self._heartbeat_running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(interval,),
            daemon=True,
        )
        self._heartbeat_thread.start()
        logger.info(f"Background heartbeat started (interval: {interval}s)")

    def _heartbeat_loop(self, interval: int) -> None:
        """Background heartbeat loop."""
        while self._heartbeat_running:
            try:
                self.send_heartbeat()
            except Exception as e:
                logger.warning(f"Heartbeat error: {e}")

            time.sleep(interval)

    def stop_heartbeat(self) -> None:
        """Stop background heartbeat thread."""
        self._heartbeat_running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5.0)

    # =========================================================================
    # THREAT REPORTING
    # =========================================================================

    def report_threats(self, threats: List[ThreatEvent]) -> bool:
        """
        Report threat events to MSSP.

        POST /api/v1/security/threats/ingest/

        Args:
            threats: List of threat events

        Returns:
            True if all threats reported successfully
        """
        if not threats:
            return True

        payload = {
            'source': 'fortress',
            'device_id': self.device_id,
            'threats': [t.to_dict() for t in threats],
        }

        endpoint = '/api/v1/security/threats/ingest/'
        response = self._request('POST', endpoint, payload)

        if response is not None:
            self._stats['threats_reported'] += len(threats)
            logger.info(f"Reported {len(threats)} threats to MSSP")
            return True

        self._stats['threats_failed'] += len(threats)
        return False

    def report_single_threat(self, threat: ThreatEvent) -> bool:
        """Report a single threat event."""
        return self.report_threats([threat])

    # =========================================================================
    # IDS ALERT FORWARDING
    # =========================================================================

    def forward_ids_alerts(
        self,
        source: str,
        events: List[Dict],
        log_type: str = 'alert',
    ) -> bool:
        """
        Forward IDS alerts to MSSP (NAPSE EVE JSON format).

        POST /api/v1/security/alerts/ingest/

        Args:
            source: 'napse' (only NAPSE is supported)
            events: Raw alert events
            log_type: Log type ('conn', 'http', 'dns', etc.)

        Returns:
            True if successful
        """
        if not events:
            return True

        payload = {
            'source': source,
            'log_type': log_type,
            'events': events,
        }

        endpoint = '/api/v1/security/alerts/ingest/'
        response = self._request('POST', endpoint, payload)

        if response is not None:
            processed = response.get('processed', 0)
            quarantined = response.get('quarantined', 0)
            logger.info(f"Forwarded {processed} IDS alerts to MSSP (quarantined: {quarantined})")
            return True

        return False

    # =========================================================================
    # GUARDIAN THREAT REPORT (HTP Bridge)
    # =========================================================================

    def report_guardian_threat(
        self,
        threat_type: str,
        severity: str,
        mac_address: str,
        detection_method: str,
        details: Dict = None,
    ) -> bool:
        """
        Report Guardian threat via HTP bridge to MSSP.

        POST /api/v1/security/threats/ingest/

        Args:
            threat_type: Type of threat (e.g., 'ter_replay', 'mac_impersonation')
            severity: Severity level ('critical', 'high', 'medium', 'low')
            mac_address: Target device MAC
            detection_method: How the threat was detected
            details: Additional threat context

        Returns:
            True if successful
        """
        threat = ThreatEvent(
            event_id=f"GUARDIAN-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}",
            threat_type=threat_type,
            severity=severity,
            source_ip=mac_address,  # Use MAC as source identifier
            description=f"Guardian detected: {threat_type}",
            detection_method=detection_method,
            confidence=details.get('confidence', 0.8) if details else 0.8,
            raw_data={
                'source': 'guardian',
                'mac_address': mac_address,
                **(details or {}),
            }
        )

        return self.report_single_threat(threat)

    # =========================================================================
    # HEALTH & STATS
    # =========================================================================

    def health_check(self) -> Dict:
        """Check MSSP connectivity and return status."""
        response = self._request('GET', '/health/', retry=False)

        if response:
            return {
                'connected': True,
                'mssp_url': self.mssp_url,
                'device_id': self.device_id,
                'mssp_status': response.get('status'),
                'last_heartbeat': self._last_heartbeat.isoformat() if self._last_heartbeat else None,
                'stats': self._stats.copy(),
            }

        return {
            'connected': False,
            'mssp_url': self.mssp_url,
            'device_id': self.device_id,
            'error': 'Cannot connect to MSSP dashboard',
            'stats': self._stats.copy(),
        }

    def get_stats(self) -> Dict:
        """Get client statistics."""
        return {
            **self._stats,
            'last_heartbeat': self._last_heartbeat.isoformat() if self._last_heartbeat else None,
            'heartbeat_running': self._heartbeat_running,
        }


# =============================================================================
# SINGLETON
# =============================================================================

_client: Optional[FortressMSSPClient] = None
_client_lock = threading.Lock()


def get_mssp_client() -> FortressMSSPClient:
    """Get the singleton MSSP client."""
    global _client

    with _client_lock:
        if _client is None:
            _client = FortressMSSPClient()
        return _client


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Fortress MSSP Client')
    parser.add_argument('command', choices=['health', 'heartbeat', 'threat', 'stats'])
    parser.add_argument('--url', help='MSSP URL override')
    parser.add_argument('--device-id', help='Device ID override')
    parser.add_argument('--token', help='Auth token override')
    args = parser.parse_args()

    client = FortressMSSPClient(
        mssp_url=args.url,
        device_id=args.device_id,
        auth_token=args.token,
    )

    if args.command == 'health':
        status = client.health_check()
        print("MSSP Connection Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")

    elif args.command == 'heartbeat':
        success = client.send_heartbeat()
        print(f"Heartbeat: {'success' if success else 'failed'}")

    elif args.command == 'threat':
        threat = ThreatEvent(
            event_id='TEST-001',
            threat_type='test_threat',
            severity='low',
            source_ip='192.168.1.100',
            description='Test threat event',
            detection_method='manual_test',
            confidence=1.0,
        )
        success = client.report_single_threat(threat)
        print(f"Threat report: {'success' if success else 'failed'}")

    elif args.command == 'stats':
        stats = client.get_stats()
        print("Client Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
