"""
Qsecbit Unified - Layer 3 (Network) Threat Detector

Detects Layer 3 attacks:
- IP Spoofing (martian packet detection, bogon filtering)
- ICMP Flood (ping flood, ICMP amplification)
- Smurf Attack (broadcast ICMP amplification)
- Routing Attacks (route hijacking, BGP issues)
- IP Fragmentation Attacks (teardrop, overlapping fragments)

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from collections import deque

from .base import BaseDetector
from ..threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer
)


class L3NetworkDetector(BaseDetector):
    """
    Layer 3 (Network) threat detector.

    Monitors network layer for IP spoofing, ICMP attacks, Smurf attacks,
    and routing anomalies.
    """

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/data",
        icmp_flood_threshold: int = 5000,
        smurf_threshold: int = 1000
    ):
        super().__init__(
            name="L3NetworkDetector",
            layer=OSILayer.L3_NETWORK,
            data_dir=data_dir
        )

        self.icmp_flood_threshold = icmp_flood_threshold
        self.smurf_threshold = smurf_threshold

        # Tracking
        self.prev_icmp_count: Optional[int] = None
        self.prev_icmp_time: Optional[datetime] = None
        self.route_snapshot: Optional[List[str]] = None
        self.broadcast_icmp_sources: Dict[str, int] = {}  # IP -> count

    def detect(self) -> List[ThreatEvent]:
        """Run all L3 detection methods."""
        threats = []

        threats.extend(self._detect_ip_spoofing())
        threats.extend(self._detect_icmp_flood())
        threats.extend(self._detect_smurf_attack())
        threats.extend(self._detect_routing_attacks())
        threats.extend(self._detect_fragmentation_attacks())

        return threats

    def _detect_ip_spoofing(self) -> List[ThreatEvent]:
        """
        Detect IP spoofing via kernel martian packet logs.

        Martian packets are packets with impossible source addresses
        (RFC 1918 private from WAN, localhost from network, etc.)
        """
        threats = []

        # Check kernel logs for martian packets
        output, success = self._run_command(
            'journalctl -k -n 200 --no-pager 2>/dev/null'
        )
        if success and output:
            for line in output.split('\n'):
                if 'martian' in line.lower() or 'spoofed' in line.lower():
                    src_ip = self._parse_ip_from_line(line)

                    threat = self._create_threat_event(
                        attack_type=AttackType.IP_SPOOFING,
                        description=f"IP spoofing detected: martian/spoofed packet from {src_ip or 'unknown'}",
                        confidence=0.85,
                        source_ip=src_ip,
                        evidence={
                            'kernel_log': line[:300],
                            'detection_method': 'martian_packet'
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        # Check Suricata for spoofing alerts
        alerts = self._read_suricata_alerts(['spoof', 'bogon', 'martian', 'impossible.source'])
        for event in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.IP_SPOOFING,
                description=f"IP spoofing: {event.get('alert', {}).get('signature', 'Spoofed packet')}",
                confidence=0.8,
                source_ip=event.get('src_ip'),
                dest_ip=event.get('dest_ip'),
                evidence={'suricata_alert': event.get('alert', {})}
            )

            if self._add_threat(threat):
                threats.append(threat)

        return threats

    def _detect_icmp_flood(self) -> List[ThreatEvent]:
        """
        Detect ICMP flood attacks by monitoring ICMP message counts.

        Tracks ICMP InMsgs from /proc/net/snmp and alerts on rapid increase.
        """
        threats = []

        content, success = self._read_proc_file('/proc/net/snmp')
        if not success:
            return threats

        # Parse ICMP InMsgs
        lines = content.split('\n')
        icmp_in_msgs = None

        for i, line in enumerate(lines):
            if line.startswith('Icmp:'):
                if i + 1 < len(lines):
                    headers = line.split()
                    values = lines[i + 1].split()
                    try:
                        idx = headers.index('InMsgs')
                        icmp_in_msgs = int(values[idx])
                    except (ValueError, IndexError):
                        pass
                break

        if icmp_in_msgs is None:
            return threats

        now = datetime.now()

        # Calculate rate if we have previous measurement
        if self.prev_icmp_count is not None and self.prev_icmp_time is not None:
            delta_time = (now - self.prev_icmp_time).total_seconds()
            if delta_time > 0:
                delta_count = icmp_in_msgs - self.prev_icmp_count
                rate = delta_count / delta_time

                if rate > self.icmp_flood_threshold:
                    threat = self._create_threat_event(
                        attack_type=AttackType.ICMP_FLOOD,
                        description=f"ICMP flood detected: {rate:.0f} ICMP/sec (threshold: {self.icmp_flood_threshold})",
                        confidence=min(0.95, 0.6 + (rate / self.icmp_flood_threshold) * 0.2),
                        evidence={
                            'icmp_rate': rate,
                            'threshold': self.icmp_flood_threshold,
                            'delta_count': delta_count,
                            'delta_time': delta_time,
                            'total_icmp': icmp_in_msgs
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        self.prev_icmp_count = icmp_in_msgs
        self.prev_icmp_time = now

        return threats

    def _detect_smurf_attack(self) -> List[ThreatEvent]:
        """
        Detect Smurf attacks (ICMP amplification via broadcast).

        Smurf attack: Attacker sends ICMP echo requests to broadcast address
        with spoofed source (victim's IP). All hosts respond to victim.

        Detection: Look for many ICMP replies from broadcast destinations
        or ICMP traffic patterns indicating amplification.
        """
        threats = []

        # Check Suricata for Smurf indicators
        alerts = self._read_suricata_alerts(['smurf', 'icmp.*.broadcast', 'amplification'])
        for event in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.SMURF_ATTACK,
                description=f"Smurf attack: {event.get('alert', {}).get('signature', 'ICMP amplification')}",
                confidence=0.85,
                source_ip=event.get('src_ip'),
                dest_ip=event.get('dest_ip'),
                evidence={'suricata_alert': event.get('alert', {})}
            )

            if self._add_threat(threat):
                threats.append(threat)

        # Check for broadcast ICMP patterns in Zeek
        conn_entries = self._read_zeek_log("conn.log", limit=500)
        for parts in conn_entries:
            if len(parts) > 7:
                proto = parts[6] if len(parts) > 6 else ''
                dest_ip = parts[4] if len(parts) > 4 else ''
                src_ip = parts[2] if len(parts) > 2 else ''

                # Check for broadcast destinations with ICMP
                if proto == 'icmp' and dest_ip:
                    if dest_ip.endswith('.255') or dest_ip == '255.255.255.255':
                        # Track source IPs sending to broadcast
                        self.broadcast_icmp_sources[src_ip] = self.broadcast_icmp_sources.get(src_ip, 0) + 1

                        if self.broadcast_icmp_sources[src_ip] > self.smurf_threshold:
                            threat = self._create_threat_event(
                                attack_type=AttackType.SMURF_ATTACK,
                                description=f"Smurf attack pattern: {src_ip} sending ICMP to broadcast {dest_ip}",
                                confidence=0.8,
                                source_ip=src_ip,
                                dest_ip=dest_ip,
                                evidence={
                                    'broadcast_icmp_count': self.broadcast_icmp_sources[src_ip],
                                    'threshold': self.smurf_threshold
                                }
                            )

                            if self._add_threat(threat):
                                threats.append(threat)

        return threats

    def _detect_routing_attacks(self) -> List[ThreatEvent]:
        """
        Detect routing attacks by monitoring routing table changes.

        Detects:
        - Multiple default gateways (potential route hijacking)
        - Unexpected route changes
        - Suspicious static routes
        """
        threats = []

        output, success = self._run_command('ip route show')
        if not success:
            return threats

        routes = output.split('\n')
        default_routes = [r for r in routes if r.startswith('default')]

        # Multiple default routes = suspicious
        if len(default_routes) > 1:
            threat = self._create_threat_event(
                attack_type=AttackType.ROUTING_ATTACK,
                description=f"Multiple default gateways detected ({len(default_routes)}): potential route hijacking",
                confidence=0.75,
                evidence={
                    'default_routes': default_routes,
                    'route_count': len(default_routes)
                }
            )

            if self._add_threat(threat):
                threats.append(threat)

        # Check for unexpected route changes
        if self.route_snapshot is not None:
            added = set(routes) - set(self.route_snapshot)
            removed = set(self.route_snapshot) - set(routes)

            if added or removed:
                # Only alert on significant changes
                significant_changes = [r for r in added if 'default' in r or '/0' in r]
                if significant_changes:
                    threat = self._create_threat_event(
                        attack_type=AttackType.ROUTING_ATTACK,
                        description=f"Routing table changed: {len(added)} added, {len(removed)} removed",
                        confidence=0.7,
                        evidence={
                            'routes_added': list(added)[:10],
                            'routes_removed': list(removed)[:10]
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

        self.route_snapshot = routes

        return threats

    def _detect_fragmentation_attacks(self) -> List[ThreatEvent]:
        """
        Detect IP fragmentation attacks (teardrop, overlapping fragments).

        Checks Suricata for fragmentation-related alerts.
        """
        threats = []

        alerts = self._read_suricata_alerts(['frag', 'teardrop', 'overlap', 'reassembly'])
        for event in alerts:
            threat = self._create_threat_event(
                attack_type=AttackType.FRAGMENTATION_ATTACK,
                description=f"Fragmentation attack: {event.get('alert', {}).get('signature', 'Malformed fragments')}",
                confidence=0.8,
                source_ip=event.get('src_ip'),
                dest_ip=event.get('dest_ip'),
                evidence={'suricata_alert': event.get('alert', {})}
            )

            if self._add_threat(threat):
                threats.append(threat)

        return threats
