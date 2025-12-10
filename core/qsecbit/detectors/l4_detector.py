"""
Qsecbit Unified - Layer 4 (Transport) Threat Detector

Detects Layer 4 attacks:
- SYN Flood (SYN_RECV state monitoring)
- Port Scan (connection pattern analysis)
- TCP Reset Attack (RST anomaly detection)
- Session Hijacking (sequence number anomalies)
- UDP Flood (datagram rate monitoring)

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Any
from collections import defaultdict

from .base import BaseDetector
from ..threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer
)


class L4TransportDetector(BaseDetector):
    """
    Layer 4 (Transport) threat detector.

    Monitors TCP/UDP traffic patterns for SYN floods, port scans,
    reset attacks, session hijacking, and UDP floods.
    """

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/data",
        syn_flood_threshold: int = 100,
        port_scan_threshold: int = 50,
        rst_anomaly_threshold: int = 5000,
        udp_flood_threshold: int = 50000
    ):
        super().__init__(
            name="L4TransportDetector",
            layer=OSILayer.L4_TRANSPORT,
            data_dir=data_dir
        )

        self.syn_flood_threshold = syn_flood_threshold
        self.port_scan_threshold = port_scan_threshold
        self.rst_anomaly_threshold = rst_anomaly_threshold
        self.udp_flood_threshold = udp_flood_threshold

        # Tracking
        self.port_scan_tracker: Dict[str, Set[str]] = defaultdict(set)  # src_ip -> {ports}
        self.prev_tcp_stats: Optional[Dict[str, int]] = None
        self.prev_udp_stats: Optional[Dict[str, int]] = None
        self.prev_stat_time: Optional[datetime] = None

    def detect(self) -> List[ThreatEvent]:
        """Run all L4 detection methods."""
        threats = []

        threats.extend(self._detect_syn_flood())
        threats.extend(self._detect_port_scans())
        threats.extend(self._detect_tcp_reset_attack())
        threats.extend(self._detect_session_hijacking())
        threats.extend(self._detect_udp_flood())

        return threats

    def _detect_syn_flood(self) -> List[ThreatEvent]:
        """
        Detect SYN flood attacks by monitoring half-open connections.

        SYN flood is detected when there are many connections in SYN_RECV state,
        indicating attackers sending SYN packets without completing handshake.
        """
        threats = []

        # Use ss to check socket states
        output, success = self._run_command('ss -s')
        if not success:
            return threats

        # Look for SYN_RECV count
        match = re.search(r'(\d+)\s+(?:SYN[_-]RECV|synrecv)', output, re.IGNORECASE)
        if match:
            syn_recv_count = int(match.group(1))

            if syn_recv_count > self.syn_flood_threshold:
                severity = ThreatSeverity.CRITICAL if syn_recv_count > self.syn_flood_threshold * 3 else ThreatSeverity.HIGH

                threat = self._create_threat_event(
                    attack_type=AttackType.SYN_FLOOD,
                    description=f"SYN flood detected: {syn_recv_count} connections in SYN_RECV (threshold: {self.syn_flood_threshold})",
                    confidence=min(0.95, 0.7 + (syn_recv_count / self.syn_flood_threshold) * 0.1),
                    evidence={
                        'syn_recv_count': syn_recv_count,
                        'threshold': self.syn_flood_threshold,
                        'ss_output': output[:500]
                    },
                    severity_override=severity
                )

                if self._add_threat(threat):
                    threats.append(threat)

        # Also check XDP stats if available (will be populated by XDP manager)
        alerts = self._read_suricata_alerts(['syn.?flood', 'syn.?attack', 'tcp.?syn'])
        for event in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.SYN_FLOOD,
                description=f"SYN flood: {event.get('alert', {}).get('signature', 'SYN attack')}",
                confidence=0.85,
                source_ip=event.get('src_ip'),
                dest_ip=event.get('dest_ip'),
                dest_port=event.get('dest_port'),
                evidence={'suricata_alert': event.get('alert', {})}
            )

            if self._add_threat(threat):
                threats.append(threat)

        return threats

    def _detect_port_scans(self) -> List[ThreatEvent]:
        """
        Detect port scanning by analyzing connection patterns.

        Port scan is detected when a single source IP connects to
        many different destination ports in a short time window.
        """
        threats = []

        # Reset tracker periodically (every detection run acts as a window)
        self.port_scan_tracker.clear()

        # Analyze Zeek conn.log for connection patterns
        entries = self._read_zeek_log("conn.log", limit=1000)

        for parts in entries:
            if len(parts) > 5:
                src_ip = parts[2] if len(parts) > 2 else None
                dst_port = parts[5] if len(parts) > 5 else None

                if src_ip and dst_port and dst_port != '-':
                    self.port_scan_tracker[src_ip].add(dst_port)

        # Check for scanners
        for src_ip, ports in self.port_scan_tracker.items():
            if len(ports) > self.port_scan_threshold:
                # Determine scan type
                common_ports = {'22', '23', '80', '443', '8080', '21', '25', '3389'}
                scanned_common = len(ports & common_ports)

                threat = self._create_threat_event(
                    attack_type=AttackType.PORT_SCAN,
                    description=f"Port scan from {src_ip}: {len(ports)} unique ports scanned",
                    confidence=min(0.95, 0.6 + len(ports) / 100 * 0.2),
                    source_ip=src_ip,
                    evidence={
                        'unique_ports': len(ports),
                        'threshold': self.port_scan_threshold,
                        'sample_ports': list(ports)[:30],
                        'common_ports_hit': scanned_common
                    }
                )

                if self._add_threat(threat):
                    threats.append(threat)

        return threats

    def _detect_tcp_reset_attack(self) -> List[ThreatEvent]:
        """
        Detect TCP Reset (RST) attacks by monitoring reset statistics.

        High RST counts can indicate:
        - Connection reset attacks (DoS)
        - Network issues
        - Port scanning aftermath
        """
        threats = []

        content, success = self._read_proc_file('/proc/net/snmp')
        if not success:
            return threats

        # Parse TCP stats
        lines = content.split('\n')
        tcp_stats = {}

        for i, line in enumerate(lines):
            if line.startswith('Tcp:'):
                if i + 1 < len(lines):
                    headers = line.split()
                    values = lines[i + 1].split()
                    for j, header in enumerate(headers):
                        if j < len(values):
                            try:
                                tcp_stats[header] = int(values[j])
                            except ValueError:
                                pass
                break

        now = datetime.now()

        # Calculate RST rate
        if self.prev_tcp_stats and self.prev_stat_time:
            delta_time = (now - self.prev_stat_time).total_seconds()
            if delta_time > 0:
                out_rsts = tcp_stats.get('OutRsts', 0)
                prev_rsts = self.prev_tcp_stats.get('OutRsts', 0)
                rst_rate = (out_rsts - prev_rsts) / delta_time

                if rst_rate > self.rst_anomaly_threshold / 60:  # per second threshold
                    threat = self._create_threat_event(
                        attack_type=AttackType.TCP_RESET_ATTACK,
                        description=f"TCP Reset anomaly: {rst_rate:.0f} RST/sec",
                        confidence=0.7,
                        evidence={
                            'rst_rate': rst_rate,
                            'total_out_rsts': out_rsts,
                            'delta_time': delta_time
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        self.prev_tcp_stats = tcp_stats
        self.prev_stat_time = now

        return threats

    def _detect_session_hijacking(self) -> List[ThreatEvent]:
        """
        Detect TCP session hijacking attempts.

        Session hijacking indicators:
        - Sequence number anomalies
        - ACK storms
        - Connection state inconsistencies

        Relies on Suricata/Zeek for deep inspection.
        """
        threats = []

        # Check Suricata for session-related alerts
        alerts = self._read_suricata_alerts([
            'session.?hijack', 'seq.?num', 'ack.?storm',
            'tcp.?state', 'connection.?reset'
        ])

        for event in alerts:
            signature = event.get('alert', {}).get('signature', '').lower()

            # Distinguish between hijacking and reset attacks
            if 'hijack' in signature or 'seq' in signature:
                threat = self._create_threat_event(
                    attack_type=AttackType.SESSION_HIJACK,
                    description=f"Session hijacking: {event.get('alert', {}).get('signature', 'TCP anomaly')}",
                    confidence=0.8,
                    source_ip=event.get('src_ip'),
                    dest_ip=event.get('dest_ip'),
                    dest_port=event.get('dest_port'),
                    evidence={'suricata_alert': event.get('alert', {})}
                )

                if self._add_threat(threat):
                    threats.append(threat)

        return threats

    def _detect_udp_flood(self) -> List[ThreatEvent]:
        """
        Detect UDP flood attacks by monitoring UDP datagram statistics.
        """
        threats = []

        content, success = self._read_proc_file('/proc/net/snmp')
        if not success:
            return threats

        # Parse UDP stats
        lines = content.split('\n')
        udp_stats = {}

        for i, line in enumerate(lines):
            if line.startswith('Udp:'):
                if i + 1 < len(lines):
                    headers = line.split()
                    values = lines[i + 1].split()
                    for j, header in enumerate(headers):
                        if j < len(values):
                            try:
                                udp_stats[header] = int(values[j])
                            except ValueError:
                                pass
                break

        now = datetime.now()

        if self.prev_udp_stats and self.prev_stat_time:
            delta_time = (now - self.prev_stat_time).total_seconds()
            if delta_time > 0:
                in_dgrams = udp_stats.get('InDatagrams', 0)
                prev_dgrams = self.prev_udp_stats.get('InDatagrams', 0)
                dgram_rate = (in_dgrams - prev_dgrams) / delta_time

                if dgram_rate > self.udp_flood_threshold / 60:
                    threat = self._create_threat_event(
                        attack_type=AttackType.UDP_FLOOD,
                        description=f"UDP flood detected: {dgram_rate:.0f} datagrams/sec",
                        confidence=min(0.9, 0.6 + dgram_rate / self.udp_flood_threshold * 0.2),
                        evidence={
                            'dgram_rate': dgram_rate,
                            'threshold': self.udp_flood_threshold,
                            'total_datagrams': in_dgrams
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        self.prev_udp_stats = udp_stats

        return threats
