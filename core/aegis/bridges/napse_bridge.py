"""
NAPSE Bridge — Consumes NAPSE IDS/IPS/NSM events for AEGIS.

Watches NAPSE eve.json output and normalizes alerts, anomalies,
DNS events, flow records, and file detections into AEGIS StandardSignals.

NAPSE replaces legacy Zeek/Suricata/Snort as HookProbe's AI-native
IDS/IPS/NSM. This bridge is the missing link between NAPSE detection
and AEGIS reasoning.

Event Mapping:
    NAPSE event_type → AEGIS StandardSignal
    ─────────────────────────────────────────
    alert           → ids_alert (HIGH/CRITICAL)
    anomaly         → anomaly_detected (MEDIUM)
    dns             → dns_suspicious (LOW-HIGH)
    flow            → flow_event (INFO)
    fileinfo        → file_detected (LOW-MEDIUM)
    tls             → tls_event (INFO-HIGH)
    http            → http_event (INFO-MEDIUM)
    stats           → (ignored — too noisy)
"""

import json
import logging
import math
import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from .base_bridge import BaseBridge
from ..types import StandardSignal

logger = logging.getLogger(__name__)

# Default NAPSE eve.json locations (checked in order)
EVE_LOG_PATHS = [
    '/var/log/napse/eve.json',
    '/var/log/hookprobe/napse/eve.json',
    '/opt/hookprobe/fortress/data/napse/eve.json',
]

# NAPSE event types to AEGIS signal mapping
EVENT_TYPE_MAP = {
    'alert': 'ids_alert',
    'anomaly': 'anomaly_detected',
    'dns': 'dns_event',
    'flow': 'flow_event',
    'fileinfo': 'file_detected',
    'tls': 'tls_event',
    'http': 'http_event',
}

# Events to ignore (too noisy for AEGIS reasoning)
IGNORED_EVENTS = {'stats', 'drop', 'netflow'}

# NAPSE severity mapping
SEVERITY_MAP = {
    1: 'CRITICAL',
    2: 'HIGH',
    3: 'MEDIUM',
    4: 'LOW',
}


class NAPSEBridge(BaseBridge):
    """Consumes NAPSE eve.json and feeds events to AEGIS Signal Fabric.

    Tails the eve.json file using file offset tracking (like tail -f).
    Only reads new lines since last poll to avoid duplicate processing.
    """

    name = "napse"
    poll_interval = 1.0  # 1 second — IDS events need fast response

    def __init__(self, eve_log_path: str = ""):
        super().__init__()
        self._eve_path = self._resolve_eve_path(eve_log_path)
        self._file_offset: int = 0
        self._inode: int = 0
        self._events_processed: int = 0
        self._events_errors: int = 0

    @staticmethod
    def _resolve_eve_path(custom_path: str) -> str:
        """Find the NAPSE eve.json file."""
        if custom_path and Path(custom_path).exists():
            return custom_path

        # Check environment variable
        env_path = os.environ.get('NAPSE_EVE_LOG')
        if env_path and Path(env_path).exists():
            return env_path

        # Check standard locations
        for path in EVE_LOG_PATHS:
            if Path(path).exists():
                return path

        # Default — will be checked each poll
        return EVE_LOG_PATHS[0]

    def poll(self) -> List[StandardSignal]:
        """Read new lines from eve.json and convert to signals."""
        eve_path = Path(self._eve_path)
        if not eve_path.exists():
            return []

        signals = []

        try:
            stat = eve_path.stat()
            current_inode = stat.st_ino

            # File was rotated — reset offset
            if current_inode != self._inode:
                self._file_offset = 0
                self._inode = current_inode

            # File was truncated
            if stat.st_size < self._file_offset:
                self._file_offset = 0

            # No new data
            if stat.st_size <= self._file_offset:
                return []

            with open(eve_path, 'r') as f:
                f.seek(self._file_offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    signal = self._parse_event(line)
                    if signal is not None:
                        signals.append(signal)
                        self._events_processed += 1

                self._file_offset = f.tell()

        except Exception as e:
            logger.error("NAPSE bridge poll error: %s", e)
            self._events_errors += 1

        return signals

    def _parse_event(self, line: str) -> Optional[StandardSignal]:
        """Parse a single NAPSE eve.json line into a StandardSignal."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            self._events_errors += 1
            return None

        event_type = event.get('event_type', '')

        # Skip ignored event types
        if event_type in IGNORED_EVENTS:
            return None

        # Map to AEGIS event type
        aegis_event = EVENT_TYPE_MAP.get(event_type)
        if aegis_event is None:
            return None

        # Determine severity
        severity = self._determine_severity(event, event_type)

        # Extract key fields for signal data
        data = self._extract_signal_data(event, event_type)

        return StandardSignal(
            source="napse",
            event_type=aegis_event,
            severity=severity,
            data=data,
        )

    def _determine_severity(self, event: Dict, event_type: str) -> str:
        """Determine AEGIS severity from NAPSE event."""
        if event_type == 'alert':
            # NAPSE alerts have severity 1-4
            napse_severity = event.get('alert', {}).get('severity', 3)
            return SEVERITY_MAP.get(napse_severity, 'MEDIUM')

        if event_type == 'anomaly':
            return 'MEDIUM'

        if event_type == 'dns':
            # Check for DGA, tunneling indicators using Shannon entropy
            dns_data = event.get('dns', {})
            query = dns_data.get('rrname', '')
            entropy = self._shannon_entropy(query)
            if entropy > 3.5 and len(query) > 40:
                return 'HIGH'   # High entropy + long = likely DGA/tunneling
            if len(query) > 80:
                return 'MEDIUM'  # Very long domain even with low entropy
            return 'LOW'

        if event_type == 'tls':
            # Check for TLS downgrade, expired certs
            tls_data = event.get('tls', {})
            version = tls_data.get('version', '')
            if version in ('TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3'):
                return 'MEDIUM'
            return 'INFO'

        if event_type == 'http':
            # Check for suspicious HTTP patterns
            http_data = event.get('http', {})
            status = http_data.get('status', 0)
            if status in (403, 404) and event.get('alert'):
                return 'MEDIUM'
            return 'INFO'

        if event_type == 'fileinfo':
            return 'LOW'

        return 'INFO'

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _extract_signal_data(self, event: Dict, event_type: str) -> Dict:
        """Extract relevant fields from NAPSE event for AEGIS signal data."""
        data: Dict = {
            'napse_event_type': event_type,
            'src_ip': event.get('src_ip', ''),
            'dest_ip': event.get('dest_ip', ''),
            'src_port': event.get('src_port', 0),
            'dest_port': event.get('dest_port', 0),
            'proto': event.get('proto', ''),
            'timestamp': event.get('timestamp', ''),
        }

        if event_type == 'alert':
            alert = event.get('alert', {})
            data.update({
                'signature_id': alert.get('signature_id', 0),
                'signature': alert.get('signature', ''),
                'category': alert.get('category', ''),
                'action': alert.get('action', ''),
                'mitre_attack': alert.get('metadata', {}).get('mitre_attack', []),
            })

        elif event_type == 'dns':
            dns = event.get('dns', {})
            data.update({
                'query': dns.get('rrname', ''),
                'query_type': dns.get('rrtype', ''),
                'rcode': dns.get('rcode', ''),
                'answers': dns.get('answers', []),
            })

        elif event_type == 'tls':
            tls = event.get('tls', {})
            data.update({
                'tls_version': tls.get('version', ''),
                'sni': tls.get('sni', ''),
                'subject': tls.get('subject', ''),
                'issuer': tls.get('issuerdn', ''),
                'ja3_hash': tls.get('ja3', {}).get('hash', ''),
            })

        elif event_type == 'http':
            http = event.get('http', {})
            data.update({
                'hostname': http.get('hostname', ''),
                'url': http.get('url', ''),
                'method': http.get('http_method', ''),
                'status': http.get('status', 0),
                'user_agent': http.get('http_user_agent', ''),
            })

        elif event_type == 'fileinfo':
            fileinfo = event.get('fileinfo', {})
            data.update({
                'filename': fileinfo.get('filename', ''),
                'size': fileinfo.get('size', 0),
                'md5': fileinfo.get('md5', ''),
                'sha256': fileinfo.get('sha256', ''),
            })

        elif event_type == 'anomaly':
            anomaly = event.get('anomaly', {})
            data.update({
                'anomaly_type': anomaly.get('type', ''),
                'event': anomaly.get('event', ''),
            })

        # Remove empty values
        return {k: v for k, v in data.items() if v}

    def get_stats(self) -> Dict:
        """Get bridge statistics."""
        return {
            'eve_path': self._eve_path,
            'file_offset': self._file_offset,
            'events_processed': self._events_processed,
            'events_errors': self._events_errors,
            'running': self.is_running,
        }
