#!/usr/bin/env python3
"""
Deep Packet Inspection (DPI) Analyzer for dnsXai

Extends dnsXai with TLS intelligence:
- TLS SNI (Server Name Indication) extraction
- JA3/JA3S fingerprinting for client/server identification
- NAPSE integration for TLS metadata
- Malicious TLS pattern detection

Author: HookProbe Team
Version: 5.2.0
License: Proprietary - see LICENSE in this directory
"""

import os
import re
import json
import struct
import hashlib
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Set, Any
from pathlib import Path
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


# =============================================================================
# TLS Constants
# =============================================================================

# TLS Content Types
CONTENT_TYPE_HANDSHAKE = 0x16

# TLS Handshake Types
HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02

# TLS Extensions
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a
EXT_EC_POINT_FORMATS = 0x000b
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_SUPPORTED_VERSIONS = 0x002b


# Known malicious JA3 fingerprints (common malware/C2 patterns)
MALICIOUS_JA3_DB = {
    # Cobalt Strike variants
    '72a589da586844d7f0818ce684948eea': 'CobaltStrike',
    'a0e9f5d64349fb13191bc781f81f42e1': 'CobaltStrike-4.x',
    # Metasploit
    '3b5074b1b5d032e5620f69f9f700ff0e': 'Metasploit',
    'fc54e0d16d9764783542f0146a98b300': 'Metasploit-HTTPS',
    # Empire
    '315b27e8b4d08f3ba6534dc84f0d9c2c': 'Empire',
    # TrickBot
    '6734f37431670b3ab4292b8f60f29984': 'TrickBot',
    # Emotet
    '51c64c77e60f3980eea90869b68c58a8': 'Emotet',
    # Generic suspicious patterns
    '87a4cc6de46dd48de9b68e7bb7f8ecd2': 'SuspiciousPython',
    '9e10692f1b7f78228b2d4e424db3a98c': 'SuspiciousGo',
}


class ThreatCategory(Enum):
    """TLS threat categories."""
    LEGITIMATE = 0
    SUSPICIOUS_FINGERPRINT = 1
    KNOWN_MALWARE = 2
    SELF_SIGNED = 3
    CERT_MISMATCH = 4
    DOWNGRADE_ATTACK = 5
    UNKNOWN_CA = 6


@dataclass
class JA3Fingerprint:
    """JA3 fingerprint data."""
    ja3_hash: str
    ja3_string: str
    tls_version: str
    cipher_suites: List[int]
    extensions: List[int]
    elliptic_curves: List[int]
    ec_point_formats: List[int]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class TLSConnectionInfo:
    """TLS connection metadata."""
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    sni: Optional[str] = None
    ja3_client: Optional[JA3Fingerprint] = None
    ja3s_server: Optional[JA3Fingerprint] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_valid: bool = True
    threat_category: ThreatCategory = ThreatCategory.LEGITIMATE
    threat_detail: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'sni': self.sni,
            'ja3_hash': self.ja3_client.ja3_hash if self.ja3_client else None,
            'ja3s_hash': self.ja3s_server.ja3_hash if self.ja3s_server else None,
            'cert_subject': self.cert_subject,
            'cert_issuer': self.cert_issuer,
            'cert_valid': self.cert_valid,
            'threat_category': self.threat_category.name,
            'threat_detail': self.threat_detail,
            'timestamp': self.timestamp.isoformat(),
        }


# =============================================================================
# TLS Parser
# =============================================================================

class TLSParser:
    """
    Parse TLS packets to extract SNI and JA3 fingerprint.

    JA3 Format:
    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    Example: 769,47-53-5-10-49161-49162,0-5-10-11-35-13,23-24,0
    """

    @staticmethod
    def parse_client_hello(data: bytes) -> Optional[Tuple[str, JA3Fingerprint]]:
        """
        Parse TLS ClientHello to extract SNI and JA3.

        Args:
            data: Raw TLS record data (starting from TLS record header)

        Returns:
            Tuple of (SNI hostname, JA3Fingerprint) or None if parse fails
        """
        try:
            if len(data) < 5:
                return None

            # TLS Record Header
            content_type = data[0]
            if content_type != CONTENT_TYPE_HANDSHAKE:
                return None

            tls_version = struct.unpack('>H', data[1:3])[0]
            record_length = struct.unpack('>H', data[3:5])[0]

            if len(data) < 5 + record_length:
                return None

            # Handshake header
            offset = 5
            handshake_type = data[offset]
            if handshake_type != HANDSHAKE_CLIENT_HELLO:
                return None

            # Skip handshake length (3 bytes)
            offset += 4

            # Client version
            client_version = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            # Skip random (32 bytes)
            offset += 32

            # Session ID
            session_id_length = data[offset]
            offset += 1 + session_id_length

            # Cipher suites
            cipher_suites_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            cipher_suites = []
            for i in range(0, cipher_suites_length, 2):
                suite = struct.unpack('>H', data[offset+i:offset+i+2])[0]
                # Filter GREASE values (0x?a?a pattern)
                if (suite & 0x0f0f) != 0x0a0a:
                    cipher_suites.append(suite)
            offset += cipher_suites_length

            # Compression methods
            compression_length = data[offset]
            offset += 1 + compression_length

            # Extensions
            sni = None
            extensions = []
            elliptic_curves = []
            ec_point_formats = []

            if offset < len(data) - 2:
                extensions_length = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                extensions_end = offset + extensions_length

                while offset < extensions_end - 4:
                    ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                    ext_length = struct.unpack('>H', data[offset+2:offset+4])[0]
                    offset += 4

                    # Filter GREASE values
                    if (ext_type & 0x0f0f) != 0x0a0a:
                        extensions.append(ext_type)

                    # Parse SNI extension
                    if ext_type == EXT_SERVER_NAME and ext_length > 5:
                        sni_list_length = struct.unpack('>H', data[offset:offset+2])[0]
                        sni_type = data[offset+2]
                        sni_length = struct.unpack('>H', data[offset+3:offset+5])[0]
                        if sni_type == 0:  # Host name
                            sni = data[offset+5:offset+5+sni_length].decode('ascii', errors='ignore')

                    # Parse supported groups (elliptic curves)
                    elif ext_type == EXT_SUPPORTED_GROUPS and ext_length > 2:
                        groups_length = struct.unpack('>H', data[offset:offset+2])[0]
                        for i in range(2, groups_length + 2, 2):
                            if offset + i + 2 <= offset + ext_length:
                                group = struct.unpack('>H', data[offset+i:offset+i+2])[0]
                                if (group & 0x0f0f) != 0x0a0a:
                                    elliptic_curves.append(group)

                    # Parse EC point formats
                    elif ext_type == EXT_EC_POINT_FORMATS and ext_length > 1:
                        formats_length = data[offset]
                        for i in range(1, formats_length + 1):
                            if offset + i < offset + ext_length:
                                ec_point_formats.append(data[offset+i])

                    offset += ext_length

            # Build JA3 string
            ja3_parts = [
                str(client_version),
                '-'.join(str(s) for s in cipher_suites),
                '-'.join(str(e) for e in extensions),
                '-'.join(str(c) for c in elliptic_curves),
                '-'.join(str(f) for f in ec_point_formats),
            ]
            ja3_string = ','.join(ja3_parts)
            # JA3 fingerprint uses MD5 by standard spec (not for security)
            ja3_hash = hashlib.md5(ja3_string.encode(), usedforsecurity=False).hexdigest()

            # Map version
            version_map = {
                0x0300: 'SSL 3.0',
                0x0301: 'TLS 1.0',
                0x0302: 'TLS 1.1',
                0x0303: 'TLS 1.2',
                0x0304: 'TLS 1.3',
            }
            tls_version_str = version_map.get(client_version, f'0x{client_version:04x}')

            fingerprint = JA3Fingerprint(
                ja3_hash=ja3_hash,
                ja3_string=ja3_string,
                tls_version=tls_version_str,
                cipher_suites=cipher_suites,
                extensions=extensions,
                elliptic_curves=elliptic_curves,
                ec_point_formats=ec_point_formats,
            )

            return (sni, fingerprint)

        except Exception as e:
            logger.debug(f"Failed to parse ClientHello: {e}")
            return None


# =============================================================================
# TLS Log Integration
# =============================================================================

class TLSLogAnalyzer:
    """
    Analyze TLS logs for SNI and JA3 data.

    Parses TLS connection logs with:
    - ssl.log: SNI, certificate info, validation status
    - conn.log: Connection metadata
    - ja3.log: JA3 fingerprints
    """

    def __init__(self, log_dir: str = "/var/log/napse/tls"):
        self.log_dir = Path(log_dir)
        self.tls_cache: Dict[str, TLSConnectionInfo] = {}
        self.ja3_stats: Dict[str, int] = defaultdict(int)  # JA3 -> count
        self.sni_stats: Dict[str, int] = defaultdict(int)  # SNI -> count

    def parse_ssl_log(self, limit: int = 500) -> List[TLSConnectionInfo]:
        """
        Parse ssl.log for TLS connection info.

        Returns list of TLSConnectionInfo objects.
        """
        ssl_log = self.log_dir / "ssl.log"
        if not ssl_log.exists():
            return []

        connections = []
        try:
            with open(ssl_log, 'r') as f:
                # Read header to get field positions
                fields = None
                for line in f:
                    if line.startswith('#fields'):
                        fields = line.strip().split('\t')[1:]
                        break

                if not fields:
                    return []

                # Read last N lines
                f.seek(0, 2)  # End of file
                file_size = f.tell()
                f.seek(max(0, file_size - 100000))  # Read last 100KB

                for line in f:
                    if line.startswith('#'):
                        continue

                    parts = line.strip().split('\t')
                    if len(parts) < len(fields):
                        continue

                    data = dict(zip(fields, parts))

                    conn = TLSConnectionInfo(
                        source_ip=data.get('id.orig_h', ''),
                        source_port=int(data.get('id.orig_p', 0)),
                        dest_ip=data.get('id.resp_h', ''),
                        dest_port=int(data.get('id.resp_p', 0)),
                        sni=data.get('server_name', '-') if data.get('server_name') != '-' else None,
                        cert_subject=data.get('subject', None),
                        cert_issuer=data.get('issuer', None),
                        cert_valid=data.get('validation_status', '-') == 'ok',
                    )

                    # Check for threats
                    self._analyze_connection(conn)
                    connections.append(conn)
                    self.sni_stats[conn.sni or 'unknown'] += 1

                    if len(connections) >= limit:
                        break

        except Exception as e:
            logger.warning(f"Failed to parse ssl.log: {e}")

        return connections

    def parse_ja3_log(self, limit: int = 500) -> List[Dict]:
        """
        Parse ja3.log for JA3 fingerprints.
        """
        ja3_log = self.log_dir / "ja3.log"
        if not ja3_log.exists():
            # Try alternate locations
            alt_paths = [
                self.log_dir / "intel" / "ja3.log",
                self.log_dir.parent / "ja3" / "ja3.log",
            ]
            for alt in alt_paths:
                if alt.exists():
                    ja3_log = alt
                    break
            else:
                return []

        results = []
        try:
            with open(ja3_log, 'r') as f:
                fields = None
                for line in f:
                    if line.startswith('#fields'):
                        fields = line.strip().split('\t')[1:]
                        break

                if not fields:
                    return []

                # Read from end
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(max(0, file_size - 50000))

                for line in f:
                    if line.startswith('#'):
                        continue

                    parts = line.strip().split('\t')
                    if len(parts) < len(fields):
                        continue

                    data = dict(zip(fields, parts))
                    ja3_hash = data.get('ja3', '')

                    result = {
                        'source_ip': data.get('id.orig_h', ''),
                        'dest_ip': data.get('id.resp_h', ''),
                        'dest_port': int(data.get('id.resp_p', 0)),
                        'ja3': ja3_hash,
                        'ja3_desc': data.get('ja3_desc', ''),
                    }

                    # Check against malicious database
                    if ja3_hash in MALICIOUS_JA3_DB:
                        result['threat'] = MALICIOUS_JA3_DB[ja3_hash]
                        result['malicious'] = True
                    else:
                        result['malicious'] = False

                    results.append(result)
                    self.ja3_stats[ja3_hash] += 1

                    if len(results) >= limit:
                        break

        except Exception as e:
            logger.warning(f"Failed to parse ja3.log: {e}")

        return results

    def _analyze_connection(self, conn: TLSConnectionInfo):
        """Analyze connection for threats."""
        # Check for suspicious patterns
        if conn.ja3_client:
            ja3_hash = conn.ja3_client.ja3_hash
            if ja3_hash in MALICIOUS_JA3_DB:
                conn.threat_category = ThreatCategory.KNOWN_MALWARE
                conn.threat_detail = f"Known malware JA3: {MALICIOUS_JA3_DB[ja3_hash]}"

        # Check certificate
        if not conn.cert_valid:
            if 'self-signed' in (conn.cert_issuer or '').lower():
                conn.threat_category = ThreatCategory.SELF_SIGNED
                conn.threat_detail = "Self-signed certificate detected"
            else:
                conn.threat_category = ThreatCategory.UNKNOWN_CA
                conn.threat_detail = "Certificate validation failed"

        # Check for SNI/cert mismatch
        if conn.sni and conn.cert_subject:
            cert_cn = conn.cert_subject.split('CN=')[-1].split(',')[0] if 'CN=' in conn.cert_subject else ''
            if conn.sni not in cert_cn and '*' not in cert_cn:
                conn.threat_category = ThreatCategory.CERT_MISMATCH
                conn.threat_detail = f"SNI {conn.sni} doesn't match cert {cert_cn}"

    def get_statistics(self) -> Dict[str, Any]:
        """Get DPI statistics."""
        # Top JA3 fingerprints
        top_ja3 = sorted(self.ja3_stats.items(), key=lambda x: -x[1])[:10]

        # Known malicious matches
        malicious = [
            (ja3, count, MALICIOUS_JA3_DB.get(ja3))
            for ja3, count in self.ja3_stats.items()
            if ja3 in MALICIOUS_JA3_DB
        ]

        return {
            'total_tls_connections': sum(self.sni_stats.values()),
            'unique_snis': len(self.sni_stats),
            'unique_ja3': len(self.ja3_stats),
            'top_ja3': top_ja3,
            'malicious_ja3_detected': malicious,
            'malicious_count': sum(c for _, c, _ in malicious),
        }


# =============================================================================
# DPI Analyzer (Main Class)
# =============================================================================

class DPIAnalyzer:
    """
    Deep Packet Inspection analyzer for TLS intelligence.

    Integrates:
    - TLS packet parsing for SNI/JA3
    - TLS log analysis
    - Malicious pattern detection
    - Integration with dnsXai for domain correlation
    """

    def __init__(
        self,
        tls_log_dir: str = "/var/log/napse/tls",
        data_dir: str = "/opt/hookprobe/shared/dnsXai/data"
    ):
        self.tls_analyzer = TLSLogAnalyzer(tls_log_dir)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Cache for quick lookups
        self.sni_cache: Dict[str, List[str]] = {}  # SNI -> [source_ips]
        self.ja3_cache: Dict[str, List[str]] = {}  # JA3 -> [source_ips]

        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'malicious_detected': 0,
            'suspicious_detected': 0,
        }

    def analyze_packet(self, data: bytes, src_ip: str, src_port: int,
                      dst_ip: str, dst_port: int) -> Optional[TLSConnectionInfo]:
        """
        Analyze a TLS packet.

        Args:
            data: Raw packet data
            src_ip, src_port: Source address
            dst_ip, dst_port: Destination address

        Returns:
            TLSConnectionInfo if TLS handshake detected
        """
        result = TLSParser.parse_client_hello(data)
        if not result:
            return None

        sni, ja3 = result

        conn = TLSConnectionInfo(
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            sni=sni,
            ja3_client=ja3,
        )

        # Check for malicious JA3
        if ja3.ja3_hash in MALICIOUS_JA3_DB:
            conn.threat_category = ThreatCategory.KNOWN_MALWARE
            conn.threat_detail = f"Known malware: {MALICIOUS_JA3_DB[ja3.ja3_hash]}"
            self.stats['malicious_detected'] += 1

        self.stats['total_analyzed'] += 1

        # Update caches
        if sni:
            if sni not in self.sni_cache:
                self.sni_cache[sni] = []
            self.sni_cache[sni].append(src_ip)

        if ja3.ja3_hash not in self.ja3_cache:
            self.ja3_cache[ja3.ja3_hash] = []
        self.ja3_cache[ja3.ja3_hash].append(src_ip)

        return conn

    def analyze_tls_logs(self) -> Dict[str, Any]:
        """
        Analyze TLS logs for intelligence.

        Returns:
            Dictionary with analysis results
        """
        connections = self.tls_analyzer.parse_ssl_log()
        ja3_data = self.tls_analyzer.parse_ja3_log()

        # Count threats
        threats = [c for c in connections if c.threat_category != ThreatCategory.LEGITIMATE]

        return {
            'connections_analyzed': len(connections),
            'threats_found': len(threats),
            'threat_breakdown': {
                cat.name: sum(1 for c in connections if c.threat_category == cat)
                for cat in ThreatCategory
            },
            'ja3_fingerprints': len(ja3_data),
            'malicious_ja3': sum(1 for j in ja3_data if j.get('malicious')),
            'statistics': self.tls_analyzer.get_statistics(),
        }

    def get_sni_for_domain(self, domain: str) -> List[str]:
        """Get SNI connections matching a domain."""
        matching = []
        for sni in self.sni_cache.keys():
            if domain in sni or sni.endswith('.' + domain):
                matching.extend(self.sni_cache[sni])
        return list(set(matching))

    def is_ja3_malicious(self, ja3_hash: str) -> Tuple[bool, Optional[str]]:
        """Check if JA3 fingerprint is known malicious."""
        if ja3_hash in MALICIOUS_JA3_DB:
            return True, MALICIOUS_JA3_DB[ja3_hash]
        return False, None

    def get_stats(self) -> Dict[str, Any]:
        """Get DPI analyzer statistics."""
        return {
            **self.stats,
            'unique_snis': len(self.sni_cache),
            'unique_ja3': len(self.ja3_cache),
            'tls_stats': self.tls_analyzer.get_statistics(),
        }

    def save_state(self):
        """Save analyzer state to disk."""
        state = {
            'stats': self.stats,
            'timestamp': datetime.now().isoformat(),
        }
        state_file = self.data_dir / 'dpi_state.json'
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def load_state(self):
        """Load analyzer state from disk."""
        state_file = self.data_dir / 'dpi_state.json'
        if state_file.exists():
            with open(state_file, 'r') as f:
                state = json.load(f)
                self.stats = state.get('stats', self.stats)


# =============================================================================
# Main / CLI
# =============================================================================

def main():
    """CLI for DPI analyzer."""
    import argparse

    parser = argparse.ArgumentParser(description='DPI Analyzer for TLS Intelligence')
    parser.add_argument('--tls-dir', default='/var/log/napse/tls',
                       help='TLS log directory')
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze TLS logs')
    parser.add_argument('--check-ja3', metavar='HASH',
                       help='Check if JA3 hash is malicious')
    parser.add_argument('--stats', action='store_true',
                       help='Show statistics')

    args = parser.parse_args()

    analyzer = DPIAnalyzer(tls_log_dir=args.tls_dir)

    if args.check_ja3:
        is_mal, name = analyzer.is_ja3_malicious(args.check_ja3)
        if is_mal:
            print(f"MALICIOUS: {args.check_ja3} -> {name}")
        else:
            print(f"Unknown: {args.check_ja3}")

    elif args.analyze:
        results = analyzer.analyze_tls_logs()
        print(json.dumps(results, indent=2))

    elif args.stats:
        stats = analyzer.get_stats()
        print(json.dumps(stats, indent=2))

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
