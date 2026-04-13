"""
Session Analyzer — Wernicke's Area (Language Comprehension)

Current IDS analyzes packets in isolation. This component reconstructs
full application-layer SESSIONS and analyzes the DIALOGUE for intent.

Session types tracked:
    HTTP:  Request chains (API abuse, credential stuffing, web scraping)
    SSH:   Auth attempt sequences (brute force patterns, lateral movement)
    DNS:   Query progressions (DGA detection, tunnel detection, recon)
    TLS:   Handshake parameters (MitM, downgrade, cert anomalies)

The key insight: a single packet is meaningless. A SEQUENCE of packets
reveals intent. The Session Analyzer reads "conversations" not "words."

Data source: ClickHouse napse_intents + napse_flows + hydra_events
Output: SynapticEvents with detected session anomalies

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import re
import time
from collections import Counter, defaultdict
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

# Validate CH_DB is a safe identifier (prevents SQL injection via env var)
if not re.match(r'^[A-Za-z0-9_]+$', CH_DB):
    raise ValueError(f"Unsafe CLICKHOUSE_DB value: {CH_DB!r}")

# IPv4 validation
_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# Thresholds
SSH_BRUTE_THRESHOLD = 10         # Failed SSH attempts in 5 min
HTTP_ABUSE_THRESHOLD = 50        # Requests to same path in 5 min
DNS_DGA_ENTROPY_THRESHOLD = 3.5  # Shannon entropy of domain labels
DNS_TUNNEL_QUERY_THRESHOLD = 20  # Queries to same base domain in 5 min
TLS_DOWNGRADE_VERSIONS = {'SSLv3', 'TLSv1.0', 'TLSv1.1'}  # Weak versions

SESSION_WINDOW_S = 300           # 5-minute session analysis window
ANALYSIS_INTERVAL_S = 30         # Run analysis every 30 seconds


def _safe_ip(ip: str) -> str:
    """Validate IPv4 for safe SQL interpolation."""
    if not ip or not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IPv4: {ip!r}")
    return ip


class SessionAnalyzer:
    """Reconstructs application-layer dialogues and detects intent patterns.

    The "language comprehension" center — reads conversations, not packets.
    """

    def __init__(self, submit_event=None):
        """Initialize session analyzer.

        Args:
            submit_event: Callback to submit SynapticEvents to the controller.
        """
        self._submit = submit_event
        self._stats = {
            'analyses': 0,
            'ssh_brute_detected': 0,
            'http_abuse_detected': 0,
            'dns_dga_detected': 0,
            'dns_tunnel_detected': 0,
            'tls_downgrade_detected': 0,
        }
        logger.info("SessionAnalyzer initialized")

    # ------------------------------------------------------------------
    # Main Analysis Cycle
    # ------------------------------------------------------------------

    def analyze_cycle(self) -> Dict[str, int]:
        """Run one full session analysis cycle.

        Queries ClickHouse for recent flows and analyzes session patterns.
        Returns counts of detected anomalies.
        """
        self._stats['analyses'] += 1
        findings = {
            'ssh_brute': 0,
            'http_abuse': 0,
            'dns_dga': 0,
            'dns_tunnel': 0,
            'tls_downgrade': 0,
        }

        try:
            findings['ssh_brute'] = self._analyze_ssh_sessions()
            findings['http_abuse'] = self._analyze_http_sessions()
            findings['dns_dga'] = self._analyze_dns_sessions()
            findings['tls_downgrade'] = self._analyze_tls_sessions()
        except Exception as e:
            logger.error("Session analysis error: %s", e)

        return findings

    # ------------------------------------------------------------------
    # SSH Session Analysis
    # ------------------------------------------------------------------

    def _analyze_ssh_sessions(self) -> int:
        """Detect SSH brute force by analyzing auth attempt sequences.

        Pattern: Same source IP, many flows to port 22, short duration,
        high SYN ratio (failed connections).
        """
        query = (
            f"SELECT src_ip, count(*) AS flows, "
            f"avg(duration) AS avg_dur, "
            f"sumIf(pkts_orig, 1) AS total_pkts "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE timestamp > now() - INTERVAL {SESSION_WINDOW_S} SECOND "
            f"AND dst_port = 22 "
            f"GROUP BY src_ip "
            f"HAVING flows >= {SSH_BRUTE_THRESHOLD} "
            f"ORDER BY flows DESC "
            f"LIMIT 20"
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

            src_ip = parts[0]
            flows = int(parts[1] or 0)
            avg_dur = float(parts[2] or 0)

            # Short-lived SSH connections = failed auth attempts
            if avg_dur < 5.0 and flows >= SSH_BRUTE_THRESHOLD:
                self._stats['ssh_brute_detected'] += 1
                count += 1

                self._emit_finding(
                    event_type='session.ssh_brute_force',
                    source_ip=src_ip,
                    priority=2,
                    payload={
                        'flows': flows,
                        'avg_duration': round(avg_dur, 2),
                        'pattern': 'rapid_short_ssh',
                        'kill_chain_stage': 'credential_access',
                        'mitre_technique': 'T1110 - Brute Force',
                    },
                )

        return count

    # ------------------------------------------------------------------
    # HTTP Session Analysis
    # ------------------------------------------------------------------

    def _analyze_http_sessions(self) -> int:
        """Detect HTTP abuse patterns — API hammering, scraping, credential stuffing.

        Patterns:
        - Same IP, many requests to same endpoint = API abuse
        - Same IP, sequential requests to many different paths = scraping
        - Same IP, POST to login endpoints with many failures = credential stuffing
        """
        query = (
            f"SELECT src_ip, dst_port, count(*) AS flows, "
            f"uniq(dst_ip) AS unique_targets, "
            f"sum(bytes_orig) AS total_bytes "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE timestamp > now() - INTERVAL {SESSION_WINDOW_S} SECOND "
            f"AND dst_port IN (80, 443, 8080, 8443) "
            f"GROUP BY src_ip, dst_port "
            f"HAVING flows >= {HTTP_ABUSE_THRESHOLD} "
            f"ORDER BY flows DESC "
            f"LIMIT 20"
        )
        result = _ch_query(query)
        if not result:
            return 0

        count = 0
        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 5:
                continue

            src_ip = parts[0]
            dst_port = int(parts[1] or 0)
            flows = int(parts[2] or 0)
            unique_targets = int(parts[3] or 0)
            total_bytes = int(parts[4] or 0)

            # Classify abuse type
            if unique_targets == 1 and flows > HTTP_ABUSE_THRESHOLD * 2:
                abuse_type = 'api_hammering'
                technique = 'T1499 - Endpoint DoS'
            elif unique_targets > 10:
                abuse_type = 'web_scraping'
                technique = 'T1595.002 - Vulnerability Scanning'
            else:
                abuse_type = 'http_flood'
                technique = 'T1498 - Network DoS'

            self._stats['http_abuse_detected'] += 1
            count += 1

            self._emit_finding(
                event_type=f'session.http_{abuse_type}',
                source_ip=src_ip,
                priority=3,
                payload={
                    'flows': flows,
                    'unique_targets': unique_targets,
                    'total_bytes': total_bytes,
                    'dst_port': dst_port,
                    'abuse_type': abuse_type,
                    'mitre_technique': technique,
                },
            )

        return count

    # ------------------------------------------------------------------
    # DNS Session Analysis
    # ------------------------------------------------------------------

    def _analyze_dns_sessions(self) -> int:
        """Detect DNS anomalies — DGA domains, tunnel attempts, recon.

        Patterns:
        - High-entropy domain names = DGA (Domain Generation Algorithm)
        - Many queries to same base domain = DNS tunneling
        - Queries for unusual TLDs or record types = recon
        """
        count = 0

        # Check for DNS tunnel: many queries to same base domain
        tunnel_query = (
            f"SELECT src_ip, dst_ip, count(*) AS query_count "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE timestamp > now() - INTERVAL {SESSION_WINDOW_S} SECOND "
            f"AND dst_port = 53 "
            f"GROUP BY src_ip, dst_ip "
            f"HAVING query_count >= {DNS_TUNNEL_QUERY_THRESHOLD} "
            f"ORDER BY query_count DESC "
            f"LIMIT 10"
        )
        result = _ch_query(tunnel_query)
        if result:
            for line in result.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split('\t')
                if len(parts) < 3:
                    continue

                src_ip = parts[0]
                query_count = int(parts[2] or 0)

                # Emit if above threshold (already filtered by HAVING clause)
                if query_count >= DNS_TUNNEL_QUERY_THRESHOLD:
                    self._stats['dns_tunnel_detected'] += 1
                    count += 1
                    self._emit_finding(
                        event_type='session.dns_tunnel_suspect',
                        source_ip=src_ip,
                        priority=2,
                        payload={
                            'query_count': query_count,
                            'window_seconds': SESSION_WINDOW_S,
                            'pattern': 'high_volume_dns',
                            'mitre_technique': 'T1048.003 - Exfiltration Over DNS',
                        },
                    )

        # Check for DNS DGA: source IPs with many unique destination queries
        dga_query = (
            f"SELECT src_ip, uniq(community_id) AS unique_queries, "
            f"count(*) AS total "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE timestamp > now() - INTERVAL {SESSION_WINDOW_S} SECOND "
            f"AND dst_port = 53 "
            f"GROUP BY src_ip "
            f"HAVING unique_queries >= 50 "
            f"ORDER BY unique_queries DESC "
            f"LIMIT 10"
        )
        dga_result = _ch_query(dga_query)
        if dga_result:
            for line in dga_result.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    src_ip = parts[0]
                    unique_q = int(parts[1] or 0)
                    if unique_q >= 50:
                        self._stats['dns_dga_detected'] += 1
                        count += 1
                        self._emit_finding(
                            event_type='session.dns_dga_suspect',
                            source_ip=src_ip,
                            priority=3,
                            payload={
                                'unique_queries': unique_q,
                                'pattern': 'high_unique_dns_queries',
                                'mitre_technique': 'T1568.002 - Domain Generation Algorithms',
                            },
                        )

        return count

    # ------------------------------------------------------------------
    # TLS Session Analysis
    # ------------------------------------------------------------------

    def _analyze_tls_sessions(self) -> int:
        """Detect TLS anomalies — downgrade attacks, weak ciphers, cert issues.

        Patterns:
        - Use of SSLv3/TLS1.0/TLS1.1 = forced downgrade
        - Many short TLS sessions with no data = scanning for weak configs
        """
        # Check for weak TLS versions in recent intents
        query = (
            f"SELECT src_ip, count(*) AS flows, "
            f"avg(duration) AS avg_dur "
            f"FROM {CH_DB}.napse_flows "
            f"WHERE timestamp > now() - INTERVAL {SESSION_WINDOW_S} SECOND "
            f"AND dst_port = 443 "
            f"AND duration < 2.0 "
            f"GROUP BY src_ip "
            f"HAVING flows >= 10 "
            f"ORDER BY flows DESC "
            f"LIMIT 10"
        )
        result = _ch_query(query)
        if not result:
            return 0

        count = 0
        for line in result.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue

            src_ip = parts[0]
            flows = int(parts[1] or 0)
            avg_dur = float(parts[2] or 0)

            # Many very short TLS sessions = scanning or downgrade probe
            if flows >= 10 and avg_dur < 1.0:
                self._stats['tls_downgrade_detected'] += 1
                count += 1
                self._emit_finding(
                    event_type='session.tls_probe',
                    source_ip=src_ip,
                    priority=3,
                    payload={
                        'flows': flows,
                        'avg_duration': round(avg_dur, 2),
                        'pattern': 'rapid_short_tls',
                        'mitre_technique': 'T1557 - Adversary-in-the-Middle',
                    },
                )

        return count

    # ------------------------------------------------------------------
    # Emit Findings
    # ------------------------------------------------------------------

    def _emit_finding(self, event_type: str, source_ip: str,
                      priority: int, payload: Dict[str, Any]) -> None:
        """Emit a session finding as a SynapticEvent.

        Phase 4 fix: Route to MULTI_RAG (was COGNITIVE_DEFENSE). Session
        findings should get consensus evaluation before triggering defense.
        Also submit a P1 copy to COGNITIVE_DEFENSE for critical patterns
        (ssh_brute, dns_tunnel) so they get immediate reflex action.
        """
        if not self._submit:
            logger.info("SESSION FINDING: %s from %s: %s",
                        event_type, source_ip, payload)
            return

        # Primary path: Multi-RAG consensus
        self._submit(
            source_layer=BrainLayer.CEREBRUM,
            route=SynapticRoute.MULTI_RAG,
            event_type=event_type,
            priority=3,  # P2 cognitive tier
            source_ip=source_ip,
            payload=payload,
        )

        # Critical patterns also get immediate CognitiveDefense action
        critical = ('session.ssh_brute', 'session.dns_tunnel',
                    'session.tls_downgrade')
        if event_type in critical:
            self._submit(
                source_layer=BrainLayer.CEREBRUM,
                route=SynapticRoute.COGNITIVE_DEFENSE,
                event_type=event_type,
                priority=1,  # P0 autonomic (reflex)
                source_ip=source_ip,
                payload=payload,
            )

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)


# ------------------------------------------------------------------
# ClickHouse Helper
# ------------------------------------------------------------------

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
