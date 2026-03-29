"""
App Tracker — Motor Cortex Anomaly Detection

Learns normal application behavioral profiles and detects deviations:
    - Database server reaching the public internet = "involuntary spasm"
    - Web server opening IRC connections = C2 indicator
    - DNS resolver querying unusual TLDs = tunnel/recon
    - Internal service contacting external IP not in allowlist = exfiltration

Profiles are built from historical flow data in ClickHouse. Deviations
are published as APP_DEVIATION events to the EventBus / SynapticController.

Data source: ClickHouse napse_flows (historical baselines)
Output: SynapticEvents with detected application anomalies

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

from .types import BrainLayer, SynapticEvent, SynapticRoute

logger = logging.getLogger(__name__)

# ClickHouse config
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Validate CH_DB is a safe identifier
if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# Known service port → application type mapping
SERVICE_PROFILES = {
    # Databases — should NEVER initiate outbound connections to public IPs
    'database': {
        'ports': {5432, 3306, 1433, 27017, 6379, 9200, 8123, 9000},
        'expected_behavior': 'accept_only',    # Only accept inbound
        'outbound_alert': True,                # Alert on any outbound
        'severity': 'high',
    },
    # Web servers — outbound OK to specific APIs, not to unknown IPs
    'web_server': {
        'ports': {80, 443, 8080, 8443, 3000, 8000},
        'expected_behavior': 'accept_and_limited_outbound',
        'outbound_alert': False,
        'severity': 'medium',
    },
    # DNS resolvers — should only query known upstream resolvers
    'dns': {
        'ports': {53},
        'expected_behavior': 'query_known_upstreams',
        'outbound_alert': False,
        'severity': 'medium',
    },
    # SSH — accept inbound only (servers), outbound only (admin workstations)
    'ssh': {
        'ports': {22},
        'expected_behavior': 'accept_only',
        'outbound_alert': True,
        'severity': 'high',
    },
    # Mail — outbound only to configured SMTP relays
    'mail': {
        'ports': {25, 465, 587},
        'expected_behavior': 'outbound_to_relay',
        'outbound_alert': True,
        'severity': 'medium',
    },
}

# Suspicious outbound port patterns
SUSPICIOUS_OUTBOUND_PORTS = {
    6667: 'IRC',               # IRC — classic C2 channel
    6697: 'IRC-TLS',           # IRC over TLS
    4444: 'Metasploit',        # Default Metasploit handler
    5555: 'Android-Debug',     # Android debug bridge
    8888: 'Proxy',             # Common proxy port
    1080: 'SOCKS',             # SOCKS proxy
    9050: 'Tor-SOCKS',         # Tor SOCKS proxy
    9051: 'Tor-Control',       # Tor control port
    31337: 'Back-Orifice',     # Classic backdoor
}

# RFC1918 private ranges
_PRIVATE_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                     '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                     '172.30.', '172.31.', '192.168.', '127.')

PROFILE_WINDOW_S = 3600         # 1-hour window for profile building
ANALYSIS_INTERVAL_S = 60        # Analyze every 60 seconds
PROFILE_REBUILD_S = 3600        # Rebuild profiles every hour


def _is_private(ip: str) -> bool:
    """Check if an IP is in RFC1918 private space."""
    return ip.startswith(_PRIVATE_PREFIXES)


class AppProfile:
    """Learned behavioral profile for an application/service."""

    def __init__(self, app_type: str, listen_ip: str, listen_port: int):
        self.app_type = app_type
        self.listen_ip = listen_ip
        self.listen_port = listen_port

        # Learned normal behavior
        self.known_peers: Set[str] = set()          # IPs this app normally talks to
        self.known_outbound_ports: Set[int] = set()  # Ports this app normally connects to
        self.avg_flow_rate: float = 0.0              # Average flows/minute
        self.max_flow_rate: float = 0.0              # Peak flows/minute
        self.last_updated: float = 0.0

    def is_outbound_anomaly(self, dst_ip: str, dst_port: int) -> Optional[str]:
        """Check if an outbound connection is anomalous for this profile.

        Returns anomaly description or None if normal.
        """
        # Check suspicious ports FIRST — always alert regardless of known peers
        if dst_port in SUSPICIOUS_OUTBOUND_PORTS:
            service_name = SUSPICIOUS_OUTBOUND_PORTS[dst_port]
            return (f"{self.app_type} ({self.listen_ip}:{self.listen_port}) "
                    f"connecting to suspicious port {dst_port} ({service_name})")

        config = SERVICE_PROFILES.get(self.app_type, {})

        # Database/SSH making outbound connections to unknown public IPs
        if config.get('outbound_alert') and not _is_private(dst_ip):
            if dst_ip not in self.known_peers:
                return (f"{self.app_type} ({self.listen_ip}:{self.listen_port}) "
                        f"connecting to unknown public IP {dst_ip}:{dst_port}")

        return None


class AppTracker:
    """Learns application profiles and detects behavioral deviations.

    The "motor cortex" — knows how each application should behave
    and flags when something acts out of character.
    """

    def __init__(self, submit_event=None):
        """Initialize app tracker.

        Args:
            submit_event: Callback to submit SynapticEvents.
        """
        self._submit = submit_event
        self._profiles: Dict[str, AppProfile] = {}  # "ip:port" → profile
        self._last_profile_build = 0.0  # Forces build on first analyze_cycle()

        self._stats = {
            'analyses': 0,
            'profiles_built': 0,
            'deviations_detected': 0,
            'outbound_anomalies': 0,
            'suspicious_port_alerts': 0,
        }

        logger.info("AppTracker initialized")

    # ------------------------------------------------------------------
    # Profile Building
    # ------------------------------------------------------------------

    def build_profiles(self) -> int:
        """Build/refresh application profiles from ClickHouse flow data.

        Identifies listening services and their normal communication patterns.
        Returns count of profiles built.
        """
        # Find services by their listening ports (most flows to well-known ports)
        query = (
            f"SELECT dst_ip, dst_port, count(*) AS flows, "
            f"uniq(src_ip) AS unique_clients "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE start_time > now() - INTERVAL {PROFILE_WINDOW_S} SECOND "
            f"AND dst_port < 10000 "
            f"GROUP BY dst_ip, dst_port "
            f"HAVING flows >= 5 "
            f"ORDER BY flows DESC "
            f"LIMIT 50"
        )
        result = _ch_query(query)
        if not result:
            return 0

        count = 0
        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 4:
                continue

            dst_ip = parts[0]
            dst_port = int(parts[1] or 0)

            # Classify service type
            app_type = self._classify_service(dst_port)
            if not app_type:
                continue

            key = f"{dst_ip}:{dst_port}"
            if key not in self._profiles:
                self._profiles[key] = AppProfile(app_type, dst_ip, dst_port)
                count += 1

            profile = self._profiles[key]
            profile.last_updated = time.time()

        # Learn normal peers for each profiled service
        for key, profile in self._profiles.items():
            self._learn_peers(profile)

        self._stats['profiles_built'] += count
        self._last_profile_build = time.time()
        logger.info("AppTracker: built/refreshed %d profiles (total %d)",
                     count, len(self._profiles))
        return count

    def _classify_service(self, port: int) -> Optional[str]:
        """Classify a listening port into a service type."""
        for app_type, config in SERVICE_PROFILES.items():
            if port in config['ports']:
                return app_type
        return None

    def _learn_peers(self, profile: AppProfile) -> None:
        """Learn which IPs this service normally communicates with."""
        # Find outbound connections FROM this service's IP
        query = (
            f"SELECT dst_ip, dst_port, count(*) AS flows "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE start_time > now() - INTERVAL {PROFILE_WINDOW_S} SECOND "
            f"AND src_ip = '{_safe_ip(profile.listen_ip)}' "
            f"GROUP BY dst_ip, dst_port "
            f"HAVING flows >= 2 "
            f"LIMIT 50"
        )
        result = _ch_query(query)
        if result:
            for line in result.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    try:
                        profile.known_peers.add(_safe_ip(parts[0]))
                    except ValueError:
                        continue
                    if len(parts) >= 3:
                        profile.known_outbound_ports.add(int(parts[1] or 0))

    # ------------------------------------------------------------------
    # Anomaly Detection
    # ------------------------------------------------------------------

    def analyze_cycle(self) -> Dict[str, int]:
        """Run one anomaly detection cycle.

        Checks recent outbound connections against learned profiles.
        Returns counts of detected anomalies.
        """
        self._stats['analyses'] += 1
        findings = {'outbound_anomalies': 0, 'suspicious_ports': 0}

        # Rebuild profiles periodically
        if time.time() - self._last_profile_build > PROFILE_REBUILD_S:
            self.build_profiles()

        if not self._profiles:
            return findings

        # Get recent outbound connections from profiled services
        profiled_ips = set(p.listen_ip for p in self._profiles.values())
        if not profiled_ips:
            return findings

        # Query outbound connections from profiled IPs
        # Use a single query for all profiled IPs
        query = (
            f"SELECT src_ip, dst_ip, dst_port, src_port, count(*) AS flows "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE start_time > now() - INTERVAL 300 SECOND "
            f"AND src_port > 1024 "
            f"AND dst_port < 10000 "
            f"GROUP BY src_ip, dst_ip, dst_port, src_port "
            f"LIMIT 200"
        )
        result = _ch_query(query)
        if not result:
            return findings

        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 5:
                continue

            src_ip = parts[0]
            dst_ip = parts[1]
            dst_port = int(parts[2] or 0)

            # Check against all profiles for this source IP
            for key, profile in self._profiles.items():
                if profile.listen_ip != src_ip:
                    continue

                anomaly = profile.is_outbound_anomaly(dst_ip, dst_port)
                if anomaly:
                    self._stats['deviations_detected'] += 1

                    if dst_port in SUSPICIOUS_OUTBOUND_PORTS:
                        findings['suspicious_ports'] += 1
                        self._stats['suspicious_port_alerts'] += 1
                        priority = 1
                    else:
                        findings['outbound_anomalies'] += 1
                        self._stats['outbound_anomalies'] += 1
                        priority = 2

                    self._emit_deviation(
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        dest_port=dst_port,
                        app_type=profile.app_type,
                        anomaly=anomaly,
                        priority=priority,
                    )

        return findings

    def _emit_deviation(self, source_ip: str, dest_ip: str, dest_port: int,
                        app_type: str, anomaly: str, priority: int) -> None:
        """Emit an application deviation event."""
        logger.warning("APP DEVIATION: %s", anomaly)

        if not self._submit:
            return

        self._submit(
            source_layer=BrainLayer.CEREBELLUM,
            route=SynapticRoute.COGNITIVE_DEFENSE,
            event_type='app.deviation',
            priority=priority,
            source_ip=source_ip,
            payload={
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'app_type': app_type,
                'anomaly': anomaly,
                'mitre_technique': 'T1071 - Application Layer Protocol'
                if dest_port not in SUSPICIOUS_OUTBOUND_PORTS
                else f'T1571 - Non-Standard Port ({SUSPICIOUS_OUTBOUND_PORTS.get(dest_port, "")})',
            },
        )

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            'profiles_count': len(self._profiles),
            'profiled_services': [
                {'key': k, 'type': p.app_type, 'known_peers': len(p.known_peers)}
                for k, p in list(self._profiles.items())[:10]
            ],
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_IPV4_RE_SAFE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

def _safe_ip(ip: str) -> str:
    if not ip or not _IPV4_RE_SAFE.match(ip):
        raise ValueError(f"Invalid IPv4: {ip!r}")
    return ip


def _ch_query(query: str) -> Optional[str]:
    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        data = query.encode('utf-8')
        req = Request(url, data=data)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        req.add_header('X-ClickHouse-Database', CH_DB)
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None
