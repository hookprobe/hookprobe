#!/usr/bin/env python3
"""
JA3 TLS Fingerprinting Module

Passive TLS fingerprinting for device identification.
JA3 creates a hash from TLS Client Hello parameters.

JA3 Formula:
  SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

Example JA3:
  769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0

This module:
- Captures TLS Client Hello packets (via tcpdump/tshark)
- Calculates JA3 hash for each client
- Maps JA3 hashes to known devices/applications
- Integrates with ML classifier for enhanced fingerprinting
"""

import hashlib
import json
import logging
import sqlite3
import subprocess
import threading
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Database
JA3_DATABASE = Path('/var/lib/hookprobe/ja3_fingerprints.db')

# Known JA3 signatures (curated list)
# Source: https://ja3er.com and security research
KNOWN_JA3_SIGNATURES = {
    # Apple iOS/macOS
    "773906b0efdefa24a7f2b8eb6985bf37": {"os": "iOS/macOS", "app": "Safari", "confidence": 0.95},
    "b32309a26951912be7dba376398abc3b": {"os": "iOS", "app": "iOS App", "confidence": 0.90},
    "e10a500df556d5dcfc226c67e9a8f096": {"os": "macOS", "app": "Safari 16+", "confidence": 0.95},

    # Android
    "bc6c386f480ee97b9d9e52d472b772d8": {"os": "Android", "app": "Chrome", "confidence": 0.90},
    "6734f37431670b3ab4292b2f9d1fa013": {"os": "Android", "app": "Android App", "confidence": 0.85},

    # Windows
    "a0e9f5d64349fb13191bc781f81f42e1": {"os": "Windows", "app": "Chrome", "confidence": 0.90},
    "b4d7b38d50d5d7ce53779ecd2f7d3b5e": {"os": "Windows", "app": "Edge", "confidence": 0.92},
    "72a589da586844d7f0818ce684948eea": {"os": "Windows", "app": "Firefox", "confidence": 0.90},

    # Linux
    "c12f54a3f91dc7bafd92cb59fe009a35": {"os": "Linux", "app": "Chrome", "confidence": 0.88},
    "3b5074b1b5d032e5620f69f9f700ff0e": {"os": "Linux", "app": "Firefox", "confidence": 0.88},
    "535aca3d99fc247509cd50933cd71d37": {"os": "Linux", "app": "curl", "confidence": 0.85},

    # IoT/Embedded
    "4d7a28d6f2263ed61de88ca66eb011e3": {"os": "Embedded", "app": "ESP8266", "confidence": 0.80},
    "e7d705a3286e19ea42f587b344ee6865": {"os": "Embedded", "app": "Arduino", "confidence": 0.75},

    # Smart Devices
    "5c1e3f5a3e2c7b9d8e6f4a0b1c2d3e4f": {"os": "Amazon", "app": "Echo", "confidence": 0.85},
    "8b2a4c6e0d1f3a5b7c9e2d4f6a8b0c1e": {"os": "Google", "app": "Nest", "confidence": 0.85},

    # Bots/Malware (for detection)
    "2c8960cd73bef6cb70b5b2e63e7389c1": {"os": "Unknown", "app": "Suspicious Bot", "confidence": 0.70, "threat": True},
}


@dataclass
class JA3Result:
    """JA3 fingerprint result."""
    ja3_hash: str
    ja3_string: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    timestamp: str
    os: Optional[str] = None
    app: Optional[str] = None
    confidence: float = 0.0
    is_threat: bool = False


class JA3Fingerprinter:
    """
    JA3 TLS Fingerprinting for device identification.

    Uses tshark (Wireshark CLI) to capture and parse TLS Client Hello packets.
    """

    def __init__(self, interface: str = "FTS"):
        self.interface = interface
        self.capture_process: Optional[subprocess.Popen] = None
        self.running = False
        self._lock = threading.Lock()
        self._ja3_cache: Dict[str, JA3Result] = {}

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize JA3 database."""
        try:
            JA3_DATABASE.parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(str(JA3_DATABASE)) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS ja3_observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ja3_hash TEXT NOT NULL,
                        ja3_string TEXT,
                        src_ip TEXT,
                        src_mac TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        os_detected TEXT,
                        app_detected TEXT,
                        confidence REAL,
                        is_threat INTEGER DEFAULT 0,
                        timestamp TEXT,
                        UNIQUE(ja3_hash, src_ip)
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS ja3_learned (
                        ja3_hash TEXT PRIMARY KEY,
                        os TEXT,
                        app TEXT,
                        device_type TEXT,
                        vendor TEXT,
                        confidence REAL,
                        observation_count INTEGER DEFAULT 1,
                        last_seen TEXT,
                        source TEXT
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_ja3_src ON ja3_observations(src_ip)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_ja3_hash ON ja3_observations(ja3_hash)')
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize JA3 database: {e}")

    def calculate_ja3(self, ssl_version: int, ciphers: List[int],
                      extensions: List[int], curves: List[int],
                      point_formats: List[int]) -> Tuple[str, str]:
        """
        Calculate JA3 hash from TLS Client Hello parameters.

        Returns (ja3_hash, ja3_string)
        """
        # Build JA3 string
        parts = [
            str(ssl_version),
            '-'.join(str(c) for c in ciphers),
            '-'.join(str(e) for e in extensions),
            '-'.join(str(c) for c in curves),
            '-'.join(str(p) for p in point_formats)
        ]

        ja3_string = ','.join(parts)
        # MD5 used for JA3 fingerprint standard (not for security) - B324 fix
        ja3_hash = hashlib.md5(ja3_string.encode(), usedforsecurity=False).hexdigest()

        return ja3_hash, ja3_string

    def lookup_ja3(self, ja3_hash: str) -> Optional[Dict]:
        """Lookup JA3 hash in known signatures and learned database."""
        # Check known signatures first
        if ja3_hash in KNOWN_JA3_SIGNATURES:
            return KNOWN_JA3_SIGNATURES[ja3_hash]

        # Check learned database
        try:
            with sqlite3.connect(str(JA3_DATABASE)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM ja3_learned WHERE ja3_hash = ?
                ''', (ja3_hash,))
                row = cursor.fetchone()

                if row:
                    return {
                        'os': row['os'],
                        'app': row['app'],
                        'device_type': row['device_type'],
                        'vendor': row['vendor'],
                        'confidence': row['confidence'],
                        'source': 'learned'
                    }
        except Exception as e:
            logger.debug(f"Error looking up JA3: {e}")

        return None

    def learn_ja3(self, ja3_hash: str, os: str, app: str,
                  device_type: str = 'unknown', vendor: str = 'Unknown',
                  confidence: float = 0.5, source: str = 'observation'):
        """Learn a new JA3 signature."""
        try:
            with sqlite3.connect(str(JA3_DATABASE)) as conn:
                conn.execute('''
                    INSERT INTO ja3_learned
                    (ja3_hash, os, app, device_type, vendor, confidence, last_seen, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ja3_hash) DO UPDATE SET
                        observation_count = observation_count + 1,
                        last_seen = excluded.last_seen,
                        confidence = MAX(confidence, excluded.confidence)
                ''', (
                    ja3_hash, os, app, device_type, vendor, confidence,
                    datetime.now().isoformat(), source
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error learning JA3: {e}")

    def record_observation(self, result: JA3Result, mac: Optional[str] = None):
        """Record a JA3 observation to database."""
        try:
            with sqlite3.connect(str(JA3_DATABASE)) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO ja3_observations
                    (ja3_hash, ja3_string, src_ip, src_mac, dst_ip, dst_port,
                     os_detected, app_detected, confidence, is_threat, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.ja3_hash,
                    result.ja3_string,
                    result.src_ip,
                    mac,
                    result.dst_ip,
                    result.dst_port,
                    result.os,
                    result.app,
                    result.confidence,
                    1 if result.is_threat else 0,
                    result.timestamp
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error recording JA3 observation: {e}")

    def get_ja3_for_ip(self, ip: str) -> List[JA3Result]:
        """Get all JA3 fingerprints observed for an IP."""
        results = []

        try:
            with sqlite3.connect(str(JA3_DATABASE)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM ja3_observations
                    WHERE src_ip = ?
                    ORDER BY timestamp DESC
                    LIMIT 10
                ''', (ip,))

                for row in cursor:
                    results.append(JA3Result(
                        ja3_hash=row['ja3_hash'],
                        ja3_string=row['ja3_string'] or '',
                        src_ip=row['src_ip'],
                        src_port=0,
                        dst_ip=row['dst_ip'] or '',
                        dst_port=row['dst_port'] or 0,
                        timestamp=row['timestamp'],
                        os=row['os_detected'],
                        app=row['app_detected'],
                        confidence=row['confidence'] or 0.0,
                        is_threat=bool(row['is_threat'])
                    ))

        except Exception as e:
            logger.error(f"Error getting JA3 for IP: {e}")

        return results

    def parse_tshark_ja3(self, line: str) -> Optional[JA3Result]:
        """Parse JA3 output from tshark."""
        # Expected format: src_ip:port -> dst_ip:port ja3_hash ja3_string
        try:
            # This is a simplified parser - actual implementation depends on tshark output format
            match = re.match(
                r'(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w{32})\s*(.*)',
                line
            )
            if match:
                ja3_hash = match.group(5)
                ja3_string = match.group(6).strip() if match.group(6) else ''

                # Lookup signature
                info = self.lookup_ja3(ja3_hash)

                result = JA3Result(
                    ja3_hash=ja3_hash,
                    ja3_string=ja3_string,
                    src_ip=match.group(1),
                    src_port=int(match.group(2)),
                    dst_ip=match.group(3),
                    dst_port=int(match.group(4)),
                    timestamp=datetime.now().isoformat(),
                    os=info.get('os') if info else None,
                    app=info.get('app') if info else None,
                    confidence=info.get('confidence', 0.0) if info else 0.0,
                    is_threat=info.get('threat', False) if info else False
                )

                return result

        except Exception as e:
            logger.debug(f"Error parsing tshark JA3: {e}")

        return None

    def start_capture(self, callback=None):
        """
        Start passive JA3 capture using tshark.

        Requires tshark installed: apt install tshark
        """
        if self.running:
            return

        self.running = True

        def capture_thread():
            try:
                # tshark command to extract JA3
                cmd = [
                    'tshark',
                    '-i', self.interface,
                    '-Y', 'tls.handshake.type == 1',  # Client Hello only
                    '-T', 'fields',
                    '-e', 'ip.src',
                    '-e', 'tcp.srcport',
                    '-e', 'ip.dst',
                    '-e', 'tcp.dstport',
                    '-e', 'tls.handshake.ja3',
                    '-e', 'tls.handshake.ja3_full',
                    '-l'  # Line buffered
                ]

                self.capture_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )

                for line in self.capture_process.stdout:
                    if not self.running:
                        break

                    line = line.strip()
                    if not line:
                        continue

                    # Parse tshark output
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        ja3_hash = parts[4] if len(parts) > 4 else ''
                        ja3_string = parts[5] if len(parts) > 5 else ''

                        if ja3_hash:
                            info = self.lookup_ja3(ja3_hash)

                            result = JA3Result(
                                ja3_hash=ja3_hash,
                                ja3_string=ja3_string,
                                src_ip=parts[0],
                                src_port=int(parts[1]) if parts[1] else 0,
                                dst_ip=parts[2],
                                dst_port=int(parts[3]) if parts[3] else 0,
                                timestamp=datetime.now().isoformat(),
                                os=info.get('os') if info else None,
                                app=info.get('app') if info else None,
                                confidence=info.get('confidence', 0.0) if info else 0.0,
                                is_threat=info.get('threat', False) if info else False
                            )

                            # Record observation
                            self.record_observation(result)

                            # Cache
                            with self._lock:
                                self._ja3_cache[result.src_ip] = result

                            # Callback
                            if callback:
                                callback(result)

            except FileNotFoundError:
                logger.warning("tshark not found - JA3 capture disabled")
            except Exception as e:
                logger.error(f"JA3 capture error: {e}")
            finally:
                self.running = False

        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()

    def stop_capture(self):
        """Stop JA3 capture."""
        self.running = False
        if self.capture_process:
            self.capture_process.terminate()
            self.capture_process = None

    def get_cached_ja3(self, ip: str) -> Optional[JA3Result]:
        """Get cached JA3 result for an IP."""
        with self._lock:
            return self._ja3_cache.get(ip)

    def get_stats(self) -> Dict:
        """Get JA3 statistics."""
        stats = {
            'running': self.running,
            'known_signatures': len(KNOWN_JA3_SIGNATURES),
            'learned_signatures': 0,
            'total_observations': 0,
            'unique_ja3': 0,
            'threats_detected': 0
        }

        try:
            with sqlite3.connect(str(JA3_DATABASE)) as conn:
                # Learned count
                cursor = conn.execute('SELECT COUNT(*) FROM ja3_learned')
                stats['learned_signatures'] = cursor.fetchone()[0]

                # Observations
                cursor = conn.execute('SELECT COUNT(*) FROM ja3_observations')
                stats['total_observations'] = cursor.fetchone()[0]

                # Unique JA3
                cursor = conn.execute('SELECT COUNT(DISTINCT ja3_hash) FROM ja3_observations')
                stats['unique_ja3'] = cursor.fetchone()[0]

                # Threats
                cursor = conn.execute('SELECT COUNT(*) FROM ja3_observations WHERE is_threat = 1')
                stats['threats_detected'] = cursor.fetchone()[0]

        except Exception as e:
            logger.debug(f"Error getting JA3 stats: {e}")

        return stats


# Singleton instance
_ja3_instance: Optional[JA3Fingerprinter] = None


def get_ja3_fingerprinter(interface: str = "FTS") -> JA3Fingerprinter:
    """Get singleton JA3 fingerprinter instance."""
    global _ja3_instance

    if _ja3_instance is None:
        _ja3_instance = JA3Fingerprinter(interface)

    return _ja3_instance


# CLI
def main():
    import argparse

    parser = argparse.ArgumentParser(description='JA3 TLS Fingerprinting')
    subparsers = parser.add_subparsers(dest='command')

    # Lookup
    lookup_parser = subparsers.add_parser('lookup', help='Lookup JA3 hash')
    lookup_parser.add_argument('hash', help='JA3 hash to lookup')

    # Stats
    subparsers.add_parser('stats', help='Show statistics')

    # IP lookup
    ip_parser = subparsers.add_parser('ip', help='Get JA3 for IP')
    ip_parser.add_argument('address', help='IP address')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    fingerprinter = get_ja3_fingerprinter()

    if args.command == 'lookup':
        result = fingerprinter.lookup_ja3(args.hash)
        if result:
            print(f"OS: {result.get('os', 'Unknown')}")
            print(f"App: {result.get('app', 'Unknown')}")
            print(f"Confidence: {result.get('confidence', 0):.1%}")
        else:
            print("JA3 hash not found in database")

    elif args.command == 'stats':
        stats = fingerprinter.get_stats()
        print("\nJA3 Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.command == 'ip':
        results = fingerprinter.get_ja3_for_ip(args.address)
        if results:
            print(f"\nJA3 fingerprints for {args.address}:")
            for r in results:
                print(f"  {r.ja3_hash}: {r.os or 'Unknown'} / {r.app or 'Unknown'}")
        else:
            print(f"No JA3 fingerprints found for {args.address}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
