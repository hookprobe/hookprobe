"""
Qsecbit Unified - Layer 7 (Application) Threat Detector

Detects Layer 7 attacks:
- SQL Injection (SQLI patterns)
- Cross-Site Scripting (XSS patterns)
- DNS Tunneling (long queries, entropy analysis)
- HTTP Flood (request rate, L7 DDoS)
- Malware C2 Communication
- Command Injection
- Path Traversal

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import re
import math
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Set
from collections import defaultdict

from .base import BaseDetector
from ..threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer
)


class L7ApplicationDetector(BaseDetector):
    """
    Layer 7 (Application) threat detector.

    Monitors application-layer traffic for web attacks, DNS anomalies,
    HTTP floods, and malware communication.
    """

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/data",
        dns_tunnel_query_length: int = 50,
        dns_tunnel_entropy_threshold: float = 3.5,
        http_flood_threshold: int = 100,
        http_flood_window_seconds: int = 10
    ):
        super().__init__(
            name="L7ApplicationDetector",
            layer=OSILayer.L7_APPLICATION,
            data_dir=data_dir
        )

        self.dns_tunnel_query_length = dns_tunnel_query_length
        self.dns_tunnel_entropy_threshold = dns_tunnel_entropy_threshold
        self.http_flood_threshold = http_flood_threshold
        self.http_flood_window_seconds = http_flood_window_seconds

        # HTTP request tracking for flood detection
        self.http_requests: Dict[str, List[datetime]] = defaultdict(list)  # IP -> [timestamps]

        # DNS query patterns
        self.dns_query_lengths: List[int] = []

    def detect(self) -> List[ThreatEvent]:
        """Run all L7 detection methods."""
        threats = []

        threats.extend(self._detect_sql_injection())
        threats.extend(self._detect_xss())
        threats.extend(self._detect_dns_tunneling())
        threats.extend(self._detect_http_flood())
        threats.extend(self._detect_malware_c2())
        threats.extend(self._detect_command_injection())
        threats.extend(self._detect_path_traversal())

        return threats

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)

        return entropy

    def _detect_sql_injection(self) -> List[ThreatEvent]:
        """
        Detect SQL injection attacks.

        Checks for:
        - NAPSE SQLI signatures
        - Common SQLI patterns in HTTP traffic
        """
        threats = []

        # Check NAPSE alerts for SQL injection
        alerts = self._get_napse_alerts([
            'sql.?inject', 'sqli', 'select.*from', 'union.*select',
            'drop.*table', 'or.1.?=.?1', 'and.1.?=.?1', '--',
            'information_schema', 'benchmark\\(', 'sleep\\('
        ])

        for alert in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.SQL_INJECTION,
                description=f"SQL Injection: {alert.alert_signature or 'SQLI pattern'}",
                confidence=0.9,
                source_ip=alert.src_ip or None,
                dest_ip=alert.dest_ip or None,
                dest_port=alert.dest_port or None,
                evidence={'napse_sig_id': alert.alert_signature_id, 'category': alert.alert_category}
            )

            if self._add_threat(threat):
                threats.append(threat)

        # Check NAPSE HTTP events for SQLI patterns
        http_events = self._get_napse_events("HTTP")
        sqli_patterns = [
            r"'.*or.*'.*=.*'",
            r"union\s+select",
            r";\s*drop\s+",
            r";\s*delete\s+",
            r"--\s*$",
            r"benchmark\s*\(",
            r"sleep\s*\(",
            r"waitfor\s+delay",
        ]

        for record in http_events:
            uri = getattr(record, 'uri', '')

            for pattern in sqli_patterns:
                if re.search(pattern, uri.lower(), re.IGNORECASE):
                    threat = self._create_threat_event(
                        attack_type=AttackType.SQL_INJECTION,
                        description=f"SQL Injection pattern in HTTP request",
                        confidence=0.85,
                        source_ip=getattr(record, 'id_orig_h', None),
                        dest_ip=getattr(record, 'id_resp_h', None),
                        evidence={
                            'uri': uri[:200],
                            'pattern_matched': pattern
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)
                    break

        return threats

    def _detect_xss(self) -> List[ThreatEvent]:
        """
        Detect Cross-Site Scripting (XSS) attacks.
        """
        threats = []

        # Check NAPSE alerts for XSS
        alerts = self._get_napse_alerts([
            'xss', 'cross.?site', '<script', 'javascript:',
            'onerror', 'onload', 'onclick', 'document\\.cookie',
            'alert\\(', 'eval\\('
        ])

        for alert in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.XSS,
                description=f"XSS Attack: {alert.alert_signature or 'XSS pattern'}",
                confidence=0.85,
                source_ip=alert.src_ip or None,
                dest_ip=alert.dest_ip or None,
                dest_port=alert.dest_port or None,
                evidence={'napse_sig_id': alert.alert_signature_id, 'category': alert.alert_category}
            )

            if self._add_threat(threat):
                threats.append(threat)

        # Check NAPSE HTTP events for XSS patterns
        xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'document\.cookie',
            r'eval\s*\(',
            r'alert\s*\(',
        ]

        http_events = self._get_napse_events("HTTP")
        for record in http_events:
            uri = getattr(record, 'uri', '')

            for pattern in xss_patterns:
                if re.search(pattern, uri, re.IGNORECASE):
                    threat = self._create_threat_event(
                        attack_type=AttackType.XSS,
                        description=f"XSS pattern in HTTP request",
                        confidence=0.8,
                        source_ip=getattr(record, 'id_orig_h', None),
                        dest_ip=getattr(record, 'id_resp_h', None),
                        evidence={
                            'uri': uri[:200],
                            'pattern_matched': pattern
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)
                    break

        return threats

    def _detect_dns_tunneling(self) -> List[ThreatEvent]:
        """
        Detect DNS tunneling by analyzing DNS query patterns.

        Indicators:
        - Unusually long DNS queries
        - High entropy in query names (encoded data)
        - Unusual TXT record queries
        - High query volume to single domain
        """
        threats = []

        # Check NAPSE DNS events
        dns_events = self._get_napse_events("DNS")

        long_queries = []
        high_entropy_queries = []
        txt_queries = []
        domain_query_count: Dict[str, int] = defaultdict(int)

        for record in dns_events:
            query = getattr(record, 'query', '')
            qtype = getattr(record, 'qtype_name', '')

            if not query:
                continue

            # Track query length
            if len(query) > self.dns_tunnel_query_length:
                long_queries.append(query)

            # Calculate entropy
            entropy = self._calculate_entropy(query.split('.')[0])
            if entropy > self.dns_tunnel_entropy_threshold:
                high_entropy_queries.append((query, entropy))

            # Track TXT queries (often used for tunneling)
            if qtype == 'TXT':
                txt_queries.append(query)

            # Track domain frequency
            domain = '.'.join(query.split('.')[-2:]) if '.' in query else query
            domain_query_count[domain] += 1

        # Generate threats based on findings
        if len(long_queries) > 10:
            threat = self._create_threat_event(
                attack_type=AttackType.DNS_TUNNELING,
                description=f"DNS tunneling: {len(long_queries)} long queries detected (>{self.dns_tunnel_query_length} chars)",
                confidence=0.75,
                dest_port=53,
                evidence={
                    'long_query_count': len(long_queries),
                    'sample_queries': long_queries[:5],
                    'threshold': self.dns_tunnel_query_length
                }
            )

            if self._add_threat(threat):
                threats.append(threat)

        if len(high_entropy_queries) > 10:
            threat = self._create_threat_event(
                attack_type=AttackType.DNS_TUNNELING,
                description=f"DNS tunneling: {len(high_entropy_queries)} high-entropy queries (encoded data)",
                confidence=0.8,
                dest_port=53,
                evidence={
                    'high_entropy_count': len(high_entropy_queries),
                    'sample_queries': high_entropy_queries[:5],
                    'entropy_threshold': self.dns_tunnel_entropy_threshold
                }
            )

            if self._add_threat(threat):
                threats.append(threat)

        # Check for suspicious domain query volumes
        for domain, count in domain_query_count.items():
            if count > 100:  # More than 100 queries to single domain
                threat = self._create_threat_event(
                    attack_type=AttackType.DNS_TUNNELING,
                    description=f"Suspicious DNS activity: {count} queries to {domain}",
                    confidence=0.7,
                    dest_port=53,
                    evidence={
                        'domain': domain,
                        'query_count': count
                    }
                )

                if self._add_threat(threat):
                    threats.append(threat)

        return threats

    def _detect_http_flood(self) -> List[ThreatEvent]:
        """
        Detect HTTP flood (L7 DDoS) attacks.

        Monitors request rate per source IP.
        """
        threats = []
        now = datetime.now()

        # Clean old entries
        cutoff = now - timedelta(seconds=self.http_flood_window_seconds)
        for ip in list(self.http_requests.keys()):
            self.http_requests[ip] = [t for t in self.http_requests[ip] if t > cutoff]
            if not self.http_requests[ip]:
                del self.http_requests[ip]

        # Parse NAPSE HTTP events
        http_events = self._get_napse_events("HTTP")

        for record in http_events:
            src_ip = getattr(record, 'id_orig_h', None)
            if src_ip:
                self.http_requests[src_ip].append(now)

        # Check for flood
        for ip, timestamps in self.http_requests.items():
            if len(timestamps) > self.http_flood_threshold:
                rate = len(timestamps) / self.http_flood_window_seconds

                threat = self._create_threat_event(
                    attack_type=AttackType.HTTP_FLOOD,
                    description=f"HTTP flood from {ip}: {rate:.0f} requests/sec",
                    confidence=min(0.95, 0.6 + rate / 100),
                    source_ip=ip,
                    dest_port=80,
                    evidence={
                        'request_count': len(timestamps),
                        'window_seconds': self.http_flood_window_seconds,
                        'rate_per_second': rate,
                        'threshold': self.http_flood_threshold
                    }
                )

                if self._add_threat(threat):
                    threats.append(threat)

        return threats

    def _detect_malware_c2(self) -> List[ThreatEvent]:
        """
        Detect malware Command & Control communication.
        """
        threats = []

        alerts = self._get_napse_alerts([
            'command.?control', 'c2', 'beacon', 'rat',
            'trojan', 'botnet', 'backdoor', 'malware',
            'cobalt.?strike', 'metasploit', 'meterpreter'
        ])

        for alert in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.MALWARE_C2,
                description=f"Malware C2: {alert.alert_signature or 'C2 communication'}",
                confidence=0.9,
                source_ip=alert.src_ip or None,
                dest_ip=alert.dest_ip or None,
                dest_port=alert.dest_port or None,
                evidence={'napse_sig_id': alert.alert_signature_id, 'category': alert.alert_category}
            )

            if self._add_threat(threat):
                threats.append(threat)

        return threats

    def _detect_command_injection(self) -> List[ThreatEvent]:
        """
        Detect OS command injection attacks.
        """
        threats = []

        alerts = self._get_napse_alerts([
            'command.?inject', 'cmd.?inject', 'rce',
            'remote.?code', 'os.?command', '\\|.*id',
            '\\;.*cat', '\\`.*\\`'
        ])

        for alert in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.COMMAND_INJECTION,
                description=f"Command Injection: {alert.alert_signature or 'RCE attempt'}",
                confidence=0.9,
                source_ip=alert.src_ip or None,
                dest_ip=alert.dest_ip or None,
                dest_port=alert.dest_port or None,
                evidence={'napse_sig_id': alert.alert_signature_id, 'category': alert.alert_category}
            )

            if self._add_threat(threat):
                threats.append(threat)

        return threats

    def _detect_path_traversal(self) -> List[ThreatEvent]:
        """
        Detect path traversal attacks (LFI/RFI).
        """
        threats = []

        alerts = self._get_napse_alerts([
            'path.?traversal', 'directory.?traversal',
            'lfi', 'rfi', '\\.\\./\\.\\.',
            '/etc/passwd', '/etc/shadow', 'file.?inclusion'
        ])

        for alert in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.PATH_TRAVERSAL,
                description=f"Path Traversal: {alert.alert_signature or 'Directory traversal'}",
                confidence=0.85,
                source_ip=alert.src_ip or None,
                dest_ip=alert.dest_ip or None,
                dest_port=alert.dest_port or None,
                evidence={'napse_sig_id': alert.alert_signature_id, 'category': alert.alert_category}
            )

            if self._add_threat(threat):
                threats.append(threat)

        # Check NAPSE HTTP events for traversal patterns
        http_events = self._get_napse_events("HTTP")
        traversal_patterns = [
            r'\.\./\.\.',
            r'\.\.\\\.\\',
            r'/etc/passwd',
            r'/etc/shadow',
            r'c:\\windows',
            r'%2e%2e',
        ]

        for record in http_events:
            uri = getattr(record, 'uri', '')

            for pattern in traversal_patterns:
                if re.search(pattern, uri, re.IGNORECASE):
                    threat = self._create_threat_event(
                        attack_type=AttackType.PATH_TRAVERSAL,
                        description=f"Path traversal pattern in HTTP request",
                        confidence=0.85,
                        source_ip=getattr(record, 'id_orig_h', None),
                        dest_ip=getattr(record, 'id_resp_h', None),
                        evidence={
                            'uri': uri[:200],
                            'pattern_matched': pattern
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)
                    break

        return threats
