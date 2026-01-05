#!/usr/bin/env python3
"""
On-Demand Probe Service - Burst packet capture for device fingerprinting.

This module provides targeted, time-limited packet capture for specific MAC
addresses. Instead of continuous monitoring, it captures only what's needed
for device fingerprinting and bubble assignment.

Key Features:
- 60-second burst capture (configurable)
- MAC-filtered to reduce noise
- Focus on discovery protocols (mDNS, SSDP, DHCP, ARP)
- Async processing for minimal blocking
- Auto-cleanup of capture files

CPU Impact: 10% during capture (60s burst), 0% otherwise
RAM Impact: ~50MB during capture

Copyright (c) 2024-2026 HookProbe Security
"""

import os
import sys
import json
import asyncio
import subprocess
import tempfile
import logging
from pathlib import Path
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from threading import Thread, Lock
import re
import shutil

# Configuration
CAPTURE_DIR = Path(os.getenv('CAPTURE_DIR', '/var/lib/hookprobe/captures'))
PROBE_TIMEOUT = int(os.getenv('PROBE_TIMEOUT', '60'))  # seconds
CAPTURE_INTERFACE = os.getenv('CAPTURE_INTERFACE', 'vlan100')
LOG_FILE = Path('/var/log/fortress/probe-service.log')

# Capture filter for discovery protocols
DISCOVERY_FILTER = (
    '(udp port 5353) or '   # mDNS
    '(udp port 1900) or '   # SSDP/UPnP
    '(udp port 67 or udp port 68) or '  # DHCP
    '(arp) or '              # ARP
    '(udp port 137) or '     # NetBIOS
    '(tcp port 443) or '     # HTTPS (for SNI fingerprinting)
    '(udp port 123)'         # NTP (for timing patterns)
)

# Ecosystem detection patterns in mDNS/SSDP
ECOSYSTEM_PATTERNS = {
    'apple': [
        '_airplay._tcp', '_companion-link._tcp', '_homekit._tcp',
        '_apple-mobdev2._tcp', '_raop._tcp', '_airport._tcp',
        'Apple', 'iPhone', 'iPad', 'MacBook', 'iMac', 'AirPods',
    ],
    'samsung': [
        '_samsungtvrc._tcp', '_samsung_otn._tcp',
        'Samsung', 'Galaxy', 'SmartThings',
    ],
    'google': [
        '_googlecast._tcp', '_googlerpc._tcp',
        'Chromecast', 'Google Home', 'Nest', 'Android',
    ],
    'amazon': [
        '_amzn-alexa._tcp', '_amzn-wplay._tcp',
        'Echo', 'Fire', 'Alexa', 'Amazon',
    ],
    'xiaomi': [
        '_miio._udp', '_mi-connect._tcp',
        'Xiaomi', 'Mi ', 'Redmi',
    ],
}

logger = logging.getLogger('probe_service')


@dataclass
class ProbeConfig:
    """Configuration for a probe capture."""
    mac: str
    interface: str = CAPTURE_INTERFACE
    duration: int = PROBE_TIMEOUT
    filter_expr: Optional[str] = None
    include_https: bool = True
    max_packets: int = 1000

    def get_filter(self) -> str:
        """Generate tcpdump/tshark filter expression."""
        mac_filter = f"ether host {self.mac}"

        if self.filter_expr:
            return f"({mac_filter}) and ({self.filter_expr})"

        discovery = DISCOVERY_FILTER
        if not self.include_https:
            discovery = discovery.replace('(tcp port 443) or ', '')

        return f"({mac_filter}) and ({discovery})"


@dataclass
class ProbeResult:
    """Results from a probe capture."""
    mac: str
    capture_file: Optional[Path] = None
    duration: float = 0.0
    packet_count: int = 0
    bytes_captured: int = 0

    # Fingerprinting results
    ecosystem: Optional[str] = None
    device_type: Optional[str] = None
    hostname: Optional[str] = None
    services: List[str] = field(default_factory=list)
    d2d_targets: List[str] = field(default_factory=list)  # MACs it communicates with

    # mDNS/SSDP discovery
    mdns_queries: List[str] = field(default_factory=list)
    mdns_responses: List[str] = field(default_factory=list)
    ssdp_searches: List[str] = field(default_factory=list)

    # TLS fingerprinting
    tls_sni: List[str] = field(default_factory=list)

    # Timing patterns
    first_packet_time: Optional[datetime] = None
    last_packet_time: Optional[datetime] = None

    # Confidence
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'mac': self.mac,
            'ecosystem': self.ecosystem,
            'device_type': self.device_type,
            'hostname': self.hostname,
            'services': self.services,
            'd2d_targets': self.d2d_targets,
            'mdns_queries': self.mdns_queries,
            'mdns_responses': self.mdns_responses,
            'ssdp_searches': self.ssdp_searches,
            'tls_sni': self.tls_sni,
            'packet_count': self.packet_count,
            'duration': self.duration,
            'confidence': self.confidence,
        }


class OnDemandProbe:
    """
    On-demand packet capture and analysis service.

    Captures targeted traffic for device fingerprinting without
    continuous monitoring overhead.
    """

    def __init__(self, capture_dir: Path = CAPTURE_DIR):
        self.capture_dir = capture_dir
        self._active_probes: Dict[str, asyncio.Task] = {}
        self._lock = Lock()

        self._init_logging()
        self.capture_dir.mkdir(parents=True, exist_ok=True)

        # Check available capture tools
        self._tshark_available = self._check_tool('tshark')
        self._tcpdump_available = self._check_tool('tcpdump')

        if not self._tshark_available and not self._tcpdump_available:
            logger.warning("No capture tool available (tshark or tcpdump)")

    def _init_logging(self):
        """Initialize logging."""
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(LOG_FILE)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def _check_tool(self, name: str) -> bool:
        """Check if capture tool is available."""
        return shutil.which(name) is not None

    async def capture_async(self, config: ProbeConfig) -> ProbeResult:
        """
        Perform async packet capture.

        Returns ProbeResult with fingerprinting analysis.
        """
        mac = config.mac.upper()
        result = ProbeResult(mac=mac)

        # Check if already capturing this MAC
        with self._lock:
            if mac in self._active_probes:
                logger.warning(f"Already capturing {mac}")
                return result

        # Generate capture filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        capture_file = self.capture_dir / f"probe_{mac.replace(':', '')}_{timestamp}.pcap"

        try:
            logger.info(f"Starting probe capture for {mac}, duration={config.duration}s")
            result.capture_file = capture_file

            # Capture packets
            if self._tshark_available:
                await self._capture_tshark(config, capture_file)
            elif self._tcpdump_available:
                await self._capture_tcpdump(config, capture_file)
            else:
                logger.error("No capture tool available")
                return result

            # Analyze capture
            if capture_file.exists() and capture_file.stat().st_size > 0:
                result = await self._analyze_capture(capture_file, result)

            # Determine ecosystem
            result.ecosystem = self._detect_ecosystem(result)
            result.confidence = self._calculate_confidence(result)

            logger.info(f"Probe complete for {mac}: ecosystem={result.ecosystem}, "
                       f"confidence={result.confidence:.0%}")

        except asyncio.CancelledError:
            logger.info(f"Probe cancelled for {mac}")
        except Exception as e:
            logger.error(f"Probe error for {mac}: {e}")
        finally:
            with self._lock:
                self._active_probes.pop(mac, None)

            # Cleanup capture file after analysis
            self._cleanup_capture(capture_file)

        return result

    async def _capture_tshark(self, config: ProbeConfig, output: Path):
        """Capture using tshark."""
        cmd = [
            'tshark',
            '-i', config.interface,
            '-f', config.get_filter(),
            '-a', f'duration:{config.duration}',
            '-c', str(config.max_packets),
            '-w', str(output),
            '-q',  # Quiet
        ]

        logger.debug(f"Running: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        _, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=config.duration + 10
        )

        if proc.returncode != 0 and stderr:
            logger.warning(f"tshark stderr: {stderr.decode()}")

    async def _capture_tcpdump(self, config: ProbeConfig, output: Path):
        """Capture using tcpdump."""
        cmd = [
            'tcpdump',
            '-i', config.interface,
            '-c', str(config.max_packets),
            '-w', str(output),
            '-G', str(config.duration),
            '-W', '1',  # Single file
            config.get_filter(),
        ]

        logger.debug(f"Running: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            await asyncio.wait_for(
                proc.communicate(),
                timeout=config.duration + 10
            )
        except asyncio.TimeoutExpired:
            proc.kill()

    async def _analyze_capture(self, capture_file: Path, result: ProbeResult) -> ProbeResult:
        """Analyze captured packets for fingerprinting."""
        if not self._tshark_available:
            return result

        # Get packet count
        count_cmd = ['tshark', '-r', str(capture_file), '-T', 'fields', '-e', 'frame.number']
        try:
            proc = await asyncio.create_subprocess_exec(
                *count_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            result.packet_count = len(stdout.decode().strip().split('\n'))
        except Exception:
            pass

        result.bytes_captured = capture_file.stat().st_size

        # Extract mDNS queries
        result.mdns_queries = await self._extract_mdns_queries(capture_file)
        result.mdns_responses = await self._extract_mdns_responses(capture_file)

        # Extract SSDP searches
        result.ssdp_searches = await self._extract_ssdp(capture_file)

        # Extract TLS SNI
        result.tls_sni = await self._extract_tls_sni(capture_file)

        # Extract D2D targets
        result.d2d_targets = await self._extract_d2d_targets(capture_file, result.mac)

        # Extract hostname from mDNS
        result.hostname = self._extract_hostname(result)

        # Compile services list
        result.services = list(set(result.mdns_queries + result.ssdp_searches))

        return result

    async def _extract_mdns_queries(self, capture_file: Path) -> List[str]:
        """Extract mDNS query names."""
        cmd = [
            'tshark', '-r', str(capture_file),
            '-Y', 'mdns && dns.flags.response == 0',
            '-T', 'fields',
            '-e', 'dns.qry.name',
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            queries = stdout.decode().strip().split('\n')
            return [q for q in queries if q and '_' in q]  # Filter service types
        except Exception:
            return []

    async def _extract_mdns_responses(self, capture_file: Path) -> List[str]:
        """Extract mDNS response names."""
        cmd = [
            'tshark', '-r', str(capture_file),
            '-Y', 'mdns && dns.flags.response == 1',
            '-T', 'fields',
            '-e', 'dns.resp.name',
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            responses = stdout.decode().strip().split('\n')
            return [r for r in responses if r]
        except Exception:
            return []

    async def _extract_ssdp(self, capture_file: Path) -> List[str]:
        """Extract SSDP search targets."""
        cmd = [
            'tshark', '-r', str(capture_file),
            '-Y', 'ssdp',
            '-T', 'fields',
            '-e', 'http.request.uri',
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            return [s for s in stdout.decode().strip().split('\n') if s]
        except Exception:
            return []

    async def _extract_tls_sni(self, capture_file: Path) -> List[str]:
        """Extract TLS Server Name Indication values."""
        cmd = [
            'tshark', '-r', str(capture_file),
            '-Y', 'tls.handshake.extensions_server_name',
            '-T', 'fields',
            '-e', 'tls.handshake.extensions_server_name',
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            return list(set(s for s in stdout.decode().strip().split('\n') if s))
        except Exception:
            return []

    async def _extract_d2d_targets(self, capture_file: Path, source_mac: str) -> List[str]:
        """Extract destination MACs this device communicates with."""
        cmd = [
            'tshark', '-r', str(capture_file),
            '-T', 'fields',
            '-e', 'eth.src',
            '-e', 'eth.dst',
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()

            targets = set()
            source_upper = source_mac.upper()

            for line in stdout.decode().strip().split('\n'):
                if '\t' in line:
                    src, dst = line.split('\t', 1)
                    src = src.upper()
                    dst = dst.upper()

                    if src == source_upper and dst != 'FF:FF:FF:FF:FF:FF':
                        targets.add(dst)
                    elif dst == source_upper:
                        targets.add(src)

            # Exclude broadcast/multicast
            targets = {t for t in targets if not t.startswith('01:') and not t.startswith('33:')}

            return list(targets)[:10]  # Limit to top 10
        except Exception:
            return []

    def _extract_hostname(self, result: ProbeResult) -> Optional[str]:
        """Extract hostname from mDNS data."""
        for response in result.mdns_responses:
            # Look for .local hostname
            if '.local' in response and not response.startswith('_'):
                hostname = response.split('.local')[0]
                # Clean up service prefix
                if '.' in hostname:
                    hostname = hostname.split('.')[-1]
                return hostname

        return None

    def _detect_ecosystem(self, result: ProbeResult) -> Optional[str]:
        """Detect device ecosystem from captured data."""
        all_data = ' '.join(
            result.mdns_queries +
            result.mdns_responses +
            result.ssdp_searches +
            result.tls_sni
        )

        scores = {}
        for ecosystem, patterns in ECOSYSTEM_PATTERNS.items():
            score = 0
            for pattern in patterns:
                if pattern.lower() in all_data.lower():
                    score += 1
            if score > 0:
                scores[ecosystem] = score

        if scores:
            return max(scores, key=scores.get)

        return None

    def _calculate_confidence(self, result: ProbeResult) -> float:
        """Calculate confidence score for fingerprinting."""
        confidence = 0.0

        # Ecosystem detection
        if result.ecosystem:
            confidence += 0.3

        # Hostname found
        if result.hostname:
            confidence += 0.2

        # mDNS services
        if result.mdns_queries:
            confidence += min(len(result.mdns_queries) * 0.05, 0.2)

        # D2D communication
        if result.d2d_targets:
            confidence += min(len(result.d2d_targets) * 0.05, 0.15)

        # TLS SNI
        if result.tls_sni:
            confidence += 0.15

        return min(confidence, 1.0)

    def _cleanup_capture(self, capture_file: Path):
        """Remove capture file after analysis."""
        try:
            if capture_file.exists():
                capture_file.unlink()
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")

    def probe(self, mac: str, duration: int = PROBE_TIMEOUT) -> ProbeResult:
        """Synchronous probe wrapper."""
        config = ProbeConfig(mac=mac, duration=duration)
        return asyncio.run(self.capture_async(config))

    async def probe_multiple(self, macs: List[str], duration: int = PROBE_TIMEOUT) -> Dict[str, ProbeResult]:
        """Probe multiple MACs concurrently."""
        tasks = []
        for mac in macs:
            config = ProbeConfig(mac=mac, duration=duration)
            tasks.append(self.capture_async(config))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            mac: result if not isinstance(result, Exception) else ProbeResult(mac=mac)
            for mac, result in zip(macs, results)
        }

    def is_probing(self, mac: str) -> bool:
        """Check if MAC is currently being probed."""
        return mac.upper() in self._active_probes

    def get_stats(self) -> Dict[str, Any]:
        """Get probe service statistics."""
        capture_files = list(self.capture_dir.glob('probe_*.pcap'))

        return {
            'active_probes': list(self._active_probes.keys()),
            'pending_captures': len(capture_files),
            'tshark_available': self._tshark_available,
            'tcpdump_available': self._tcpdump_available,
            'capture_dir': str(self.capture_dir),
        }


# Singleton instance
_probe_instance: Optional[OnDemandProbe] = None
_probe_lock = Lock()


def get_probe_service() -> OnDemandProbe:
    """Get singleton probe service instance."""
    global _probe_instance
    with _probe_lock:
        if _probe_instance is None:
            _probe_instance = OnDemandProbe()
        return _probe_instance


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='On-Demand Probe Service')
    parser.add_argument('mac', nargs='?', help='MAC address to probe')
    parser.add_argument('--duration', type=int, default=60, help='Capture duration')
    parser.add_argument('--interface', default=CAPTURE_INTERFACE, help='Capture interface')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    probe = get_probe_service()

    if args.stats:
        print(json.dumps(probe.get_stats(), indent=2))
        return

    if not args.mac:
        parser.error("MAC address required")

    config = ProbeConfig(
        mac=args.mac,
        interface=args.interface,
        duration=args.duration,
    )

    print(f"Probing {args.mac} for {args.duration} seconds...")
    result = asyncio.run(probe.capture_async(config))

    print(json.dumps(result.to_dict(), indent=2))


if __name__ == '__main__':
    main()
