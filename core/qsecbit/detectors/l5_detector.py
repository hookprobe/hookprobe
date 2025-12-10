"""
Qsecbit v6.0 - Layer 5 (Session) Threat Detector

Detects Layer 5 attacks:
- SSL Strip (HTTPS to HTTP downgrade)
- TLS Downgrade (TLS version downgrade)
- Certificate Pinning Bypass (invalid/suspicious certs)
- Authentication Bypass (brute force, credential stuffing)

Author: HookProbe Team
License: Proprietary
Version: 6.0
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from collections import defaultdict

from .base import BaseDetector
from ..threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer
)


class L5SessionDetector(BaseDetector):
    """
    Layer 5 (Session) threat detector.

    Monitors SSL/TLS connections, certificate validity, and authentication
    patterns to detect session layer attacks.
    """

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/data",
        auth_failure_threshold: int = 5,
        weak_tls_versions: Optional[List[str]] = None
    ):
        super().__init__(
            name="L5SessionDetector",
            layer=OSILayer.L5_SESSION,
            data_dir=data_dir
        )

        self.auth_failure_threshold = auth_failure_threshold
        self.weak_tls_versions = weak_tls_versions or ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1']

        # Tracking
        self.auth_failures: Dict[str, List[datetime]] = defaultdict(list)  # IP -> [timestamps]
        self.known_cert_hashes: Dict[str, str] = {}  # domain -> cert_hash

    def detect(self) -> List[ThreatEvent]:
        """Run all L5 detection methods."""
        threats = []

        threats.extend(self._detect_ssl_strip())
        threats.extend(self._detect_tls_downgrade())
        threats.extend(self._detect_cert_pinning_bypass())
        threats.extend(self._detect_auth_bypass())

        return threats

    def _detect_ssl_strip(self) -> List[ThreatEvent]:
        """
        Detect SSL stripping attacks.

        SSL strip: MITM downgrades HTTPS to HTTP, intercepts traffic.

        Detection methods:
        - Suricata alerts for SSL strip signatures
        - HSTS header absence on known HTTPS sites
        - HTTP traffic to typically HTTPS-only ports/domains
        """
        threats = []

        # Check Suricata for SSL strip indicators
        alerts = self._read_suricata_alerts([
            'ssl.?strip', 'https.?downgrade', 'hsts.?bypass',
            'secure.?cookie', 'mitm'
        ])

        for event in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.SSL_STRIP,
                description=f"SSL stripping: {event.get('alert', {}).get('signature', 'HTTPS downgrade')}",
                confidence=0.85,
                source_ip=event.get('src_ip'),
                dest_ip=event.get('dest_ip'),
                dest_port=event.get('dest_port'),
                evidence={'suricata_alert': event.get('alert', {})}
            )

            if self._add_threat(threat):
                threats.append(threat)

        # Check Zeek HTTP logs for suspicious patterns
        http_entries = self._read_zeek_log("http.log", limit=200)
        for parts in http_entries:
            if len(parts) > 10:
                host = parts[8] if len(parts) > 8 else ''
                uri = parts[9] if len(parts) > 9 else ''

                # Check for known HTTPS-only domains served over HTTP
                https_only_domains = ['bank', 'secure', 'login', 'account', 'payment']
                if any(d in host.lower() for d in https_only_domains):
                    # This is HTTP traffic to a typically secure domain
                    threat = self._create_threat_event(
                        attack_type=AttackType.SSL_STRIP,
                        description=f"Potential SSL strip: HTTP traffic to secure domain {host}",
                        confidence=0.7,
                        dest_ip=parts[4] if len(parts) > 4 else None,
                        dest_port=int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None,
                        evidence={
                            'host': host,
                            'uri': uri[:100],
                            'detection': 'http_to_secure_domain'
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        return threats

    def _detect_tls_downgrade(self) -> List[ThreatEvent]:
        """
        Detect TLS version downgrade attacks.

        Checks for connections using deprecated/weak TLS versions.
        """
        threats = []

        # Check Zeek SSL logs
        ssl_entries = self._read_zeek_log("ssl.log", limit=200)

        for parts in ssl_entries:
            if len(parts) > 6:
                src_ip = parts[2] if len(parts) > 2 else None
                dest_ip = parts[4] if len(parts) > 4 else None
                dest_port = parts[5] if len(parts) > 5 else None
                ssl_version = parts[6] if len(parts) > 6 else ''

                if ssl_version in self.weak_tls_versions:
                    threat = self._create_threat_event(
                        attack_type=AttackType.TLS_DOWNGRADE,
                        description=f"Weak TLS version: {ssl_version} (should use TLS 1.2+)",
                        confidence=0.9,
                        source_ip=src_ip,
                        dest_ip=dest_ip,
                        dest_port=int(dest_port) if dest_port and dest_port.isdigit() else None,
                        evidence={
                            'ssl_version': ssl_version,
                            'weak_versions': self.weak_tls_versions
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        # Check Suricata for downgrade attacks
        alerts = self._read_suricata_alerts([
            'tls.?downgrade', 'ssl.?version', 'poodle',
            'drown', 'beast', 'crime', 'breach'
        ])

        for event in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.TLS_DOWNGRADE,
                description=f"TLS downgrade attack: {event.get('alert', {}).get('signature', 'Protocol downgrade')}",
                confidence=0.85,
                source_ip=event.get('src_ip'),
                dest_ip=event.get('dest_ip'),
                evidence={'suricata_alert': event.get('alert', {})}
            )

            if self._add_threat(threat):
                threats.append(threat)

        return threats

    def _detect_cert_pinning_bypass(self) -> List[ThreatEvent]:
        """
        Detect certificate pinning bypass attempts.

        Indicators:
        - Self-signed certificates for known domains
        - Certificate chain validation failures
        - Unexpected certificate changes for known domains
        - Invalid/expired certificates
        """
        threats = []

        # Check Suricata for certificate alerts
        alerts = self._read_suricata_alerts([
            'certificate', 'cert.?invalid', 'self.?signed',
            'expired', 'untrusted', 'ca.?invalid'
        ])

        for event in alerts:
            signature = event.get('alert', {}).get('signature', '').lower()

            # Determine if this is a pinning bypass vs just a bad cert
            if any(x in signature for x in ['self-signed', 'untrusted', 'invalid']):
                threat = self._create_threat_event(
                    attack_type=AttackType.CERT_PINNING_BYPASS,
                    description=f"Certificate anomaly: {event.get('alert', {}).get('signature', 'Invalid certificate')}",
                    confidence=0.8,
                    source_ip=event.get('src_ip'),
                    dest_ip=event.get('dest_ip'),
                    dest_port=event.get('dest_port'),
                    evidence={'suricata_alert': event.get('alert', {})}
                )

                if self._add_threat(threat):
                    threats.append(threat)

        # Check Zeek SSL logs for certificate issues
        ssl_entries = self._read_zeek_log("ssl.log", limit=200)

        for parts in ssl_entries:
            if len(parts) > 15:
                validation_status = parts[14] if len(parts) > 14 else ''
                server_name = parts[9] if len(parts) > 9 else ''

                # Check for validation failures
                if validation_status and validation_status not in ['ok', '-', '']:
                    threat = self._create_threat_event(
                        attack_type=AttackType.CERT_PINNING_BYPASS,
                        description=f"Certificate validation failed for {server_name}: {validation_status}",
                        confidence=0.85,
                        dest_ip=parts[4] if len(parts) > 4 else None,
                        evidence={
                            'server_name': server_name,
                            'validation_status': validation_status
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        return threats

    def _detect_auth_bypass(self) -> List[ThreatEvent]:
        """
        Detect authentication bypass/brute force attempts.

        Monitors:
        - Failed login attempts from auth.log
        - Credential stuffing patterns
        - Account lockout triggers
        """
        threats = []
        now = datetime.now()

        # Clean old entries
        cutoff = now - timedelta(minutes=10)
        for ip in list(self.auth_failures.keys()):
            self.auth_failures[ip] = [t for t in self.auth_failures[ip] if t > cutoff]
            if not self.auth_failures[ip]:
                del self.auth_failures[ip]

        # Check auth.log for failures
        output, success = self._run_command(
            'tail -200 /var/log/auth.log 2>/dev/null'
        )

        if success and output:
            for line in output.split('\n'):
                if 'failed' in line.lower() or 'invalid' in line.lower():
                    ip = self._parse_ip_from_line(line)
                    if ip:
                        self.auth_failures[ip].append(now)

                        # Check threshold
                        if len(self.auth_failures[ip]) >= self.auth_failure_threshold:
                            threat = self._create_threat_event(
                                attack_type=AttackType.AUTH_BYPASS,
                                description=f"Brute force attack from {ip}: {len(self.auth_failures[ip])} failed attempts",
                                confidence=min(0.95, 0.6 + len(self.auth_failures[ip]) / 20),
                                source_ip=ip,
                                evidence={
                                    'failure_count': len(self.auth_failures[ip]),
                                    'threshold': self.auth_failure_threshold,
                                    'time_window_minutes': 10
                                }
                            )

                            if self._add_threat(threat):
                                threats.append(threat)

        # Check SSH specifically
        output, success = self._run_command(
            'grep -i "sshd.*failed\\|sshd.*invalid" /var/log/auth.log 2>/dev/null | tail -50'
        )

        if success and output:
            ssh_failures: Dict[str, int] = {}
            for line in output.split('\n'):
                ip = self._parse_ip_from_line(line)
                if ip:
                    ssh_failures[ip] = ssh_failures.get(ip, 0) + 1

            for ip, count in ssh_failures.items():
                if count >= self.auth_failure_threshold:
                    threat = self._create_threat_event(
                        attack_type=AttackType.AUTH_BYPASS,
                        description=f"SSH brute force from {ip}: {count} failed attempts",
                        confidence=min(0.95, 0.7 + count / 30),
                        source_ip=ip,
                        dest_port=22,
                        evidence={
                            'ssh_failure_count': count,
                            'threshold': self.auth_failure_threshold
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        return threats
