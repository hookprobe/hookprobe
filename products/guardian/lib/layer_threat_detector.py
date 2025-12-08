#!/usr/bin/env python3
"""
Layer Threat Detector - OSI Layer-Based Threat Detection Engine

Provides comprehensive threat detection across all OSI layers (L2-L7)
with integration to QSecBit for unified threat scoring.

This module is designed to protect mobile users when connecting to
untrusted networks like hotel WiFi, airports, and public hotspots.

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0 - see LICENSE in this directory
"""

import os
import re
import json
import time
import socket
import struct
import hashlib
import subprocess
import shlex
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any, Union
from enum import Enum
from pathlib import Path


class ThreatSeverity(Enum):
    """Threat severity levels aligned with CVSS"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class OSILayer(Enum):
    """OSI Model Layers"""
    L2_DATA_LINK = 2
    L3_NETWORK = 3
    L4_TRANSPORT = 4
    L5_SESSION = 5
    L6_PRESENTATION = 6
    L7_APPLICATION = 7


@dataclass
class ThreatEvent:
    """Represents a detected threat"""
    timestamp: datetime
    layer: OSILayer
    severity: ThreatSeverity
    threat_type: str
    source_ip: Optional[str]
    source_mac: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_attack_id: Optional[str] = None
    recommended_action: str = "Monitor"
    blocked: bool = False

    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'layer': self.layer.name,
            'layer_num': self.layer.value,
            'severity': self.severity.name,
            'severity_num': self.severity.value,
            'threat_type': self.threat_type,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'description': self.description,
            'evidence': self.evidence,
            'mitre_attack_id': self.mitre_attack_id,
            'recommended_action': self.recommended_action,
            'blocked': self.blocked
        }


@dataclass
class LayerThreatStats:
    """Statistics for threats by OSI layer"""
    layer: OSILayer
    total_threats: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    blocked_count: int = 0
    last_threat_time: Optional[datetime] = None
    threat_types: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'layer': self.layer.name,
            'layer_num': self.layer.value,
            'total_threats': self.total_threats,
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
            'info': self.info_count,
            'blocked': self.blocked_count,
            'last_threat': self.last_threat_time.isoformat() if self.last_threat_time else None,
            'threat_types': self.threat_types
        }


class LayerThreatDetector:
    """
    OSI Layer-Based Threat Detection Engine

    Detects and categorizes threats across L2-L7:
    - L2 (Data Link): ARP spoofing, MAC flooding, VLAN hopping, rogue APs
    - L3 (Network): IP spoofing, ICMP attacks, routing attacks
    - L4 (Transport): Port scans, SYN floods, TCP hijacking
    - L5 (Session): Session hijacking, SSL/TLS attacks, auth bypass
    - L6 (Presentation): Encoding attacks, malformed data, crypto attacks
    - L7 (Application): Web attacks, malware C2, DNS tunneling
    """

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/guardian/data",
        suricata_log: str = "/var/log/suricata/eve.json",
        zeek_log_dir: str = "/var/log/zeek/current",
        max_history: int = 10000
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.suricata_log = Path(suricata_log)
        self.zeek_log_dir = Path(zeek_log_dir)
        self.max_history = max_history

        # Threat tracking
        self.threats: List[ThreatEvent] = []
        self.layer_stats: Dict[OSILayer, LayerThreatStats] = {
            layer: LayerThreatStats(layer=layer) for layer in OSILayer
        }

        # ARP cache for spoofing detection
        self.arp_cache: Dict[str, Tuple[str, datetime]] = {}  # IP -> (MAC, timestamp)
        self.arp_history: Dict[str, List[str]] = {}  # IP -> [MAC history]

        # Known legitimate gateways
        self.trusted_gateways: Dict[str, str] = {}  # IP -> MAC

        # Evil twin detection
        self.known_ssids: Dict[str, Dict[str, Any]] = {}  # SSID -> {bssid, channel, etc}

        # Port scan tracking
        self.port_scan_tracker: Dict[str, Dict[str, Any]] = {}  # source_ip -> {ports, timestamps}

        # Session tracking for L5
        self.session_tracker: Dict[str, Dict[str, Any]] = {}

        # Load previous state if exists
        self._load_state()

        # MITRE ATT&CK mappings for common threats
        self.mitre_mappings = {
            'arp_spoofing': 'T1557.002',
            'mac_flooding': 'T1499.001',
            'evil_twin': 'T1557.001',
            'vlan_hopping': 'T1599',
            'ip_spoofing': 'T1090',
            'icmp_flood': 'T1498.001',
            'syn_flood': 'T1498.001',
            'port_scan': 'T1046',
            'session_hijack': 'T1563',
            'ssl_strip': 'T1557.002',
            'dns_tunneling': 'T1071.004',
            'sql_injection': 'T1190',
            'xss': 'T1059.007',
            'command_injection': 'T1059',
            'malware_c2': 'T1071.001',
        }

    def _load_state(self):
        """Load previous threat state from disk"""
        state_file = self.data_dir / "layer_threats_state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    state = json.load(f)
                    self.trusted_gateways = state.get('trusted_gateways', {})
                    self.known_ssids = state.get('known_ssids', {})
            except Exception:
                pass

    def _save_state(self):
        """Save threat state to disk"""
        state_file = self.data_dir / "layer_threats_state.json"
        try:
            with open(state_file, 'w') as f:
                json.dump({
                    'trusted_gateways': self.trusted_gateways,
                    'known_ssids': self.known_ssids,
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception:
            pass

    def _run_command(self, cmd: Union[str, List[str]], timeout: int = 10) -> Tuple[str, bool]:
        """Run command safely without shell=True to prevent command injection"""
        try:
            # Convert string to list for safe execution
            if isinstance(cmd, str):
                cmd_list = shlex.split(cmd)
            else:
                cmd_list = cmd

            result = subprocess.run(
                cmd_list, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip(), result.returncode == 0
        except Exception as e:
            return str(e), False

    def _add_threat(self, threat: ThreatEvent):
        """Add a threat event and update statistics"""
        self.threats.append(threat)

        # Trim history if needed
        if len(self.threats) > self.max_history:
            self.threats = self.threats[-self.max_history:]

        # Update layer stats
        stats = self.layer_stats[threat.layer]
        stats.total_threats += 1
        stats.last_threat_time = threat.timestamp

        if threat.severity == ThreatSeverity.CRITICAL:
            stats.critical_count += 1
        elif threat.severity == ThreatSeverity.HIGH:
            stats.high_count += 1
        elif threat.severity == ThreatSeverity.MEDIUM:
            stats.medium_count += 1
        elif threat.severity == ThreatSeverity.LOW:
            stats.low_count += 1
        else:
            stats.info_count += 1

        if threat.blocked:
            stats.blocked_count += 1

        # Track threat types
        if threat.threat_type not in stats.threat_types:
            stats.threat_types[threat.threat_type] = 0
        stats.threat_types[threat.threat_type] += 1

        # Log to threats file (JSONL format)
        threats_file = self.data_dir / "threats.json"
        try:
            with open(threats_file, 'a') as f:
                f.write(json.dumps(threat.to_dict()) + '\n')
        except Exception:
            pass

    # =========================================================================
    # L2 - DATA LINK LAYER DETECTION
    # =========================================================================

    def detect_l2_threats(self) -> List[ThreatEvent]:
        """Detect Layer 2 (Data Link) threats"""
        threats = []

        # ARP Spoofing Detection
        threats.extend(self._detect_arp_spoofing())

        # MAC Flooding Detection
        threats.extend(self._detect_mac_flooding())

        # Evil Twin / Rogue AP Detection
        threats.extend(self._detect_evil_twin())

        # VLAN Hopping Detection
        threats.extend(self._detect_vlan_hopping())

        # Rogue DHCP Server Detection
        threats.extend(self._detect_rogue_dhcp())

        return threats

    def _detect_arp_spoofing(self) -> List[ThreatEvent]:
        """Detect ARP spoofing attacks"""
        threats = []

        # Get current ARP cache
        output, success = self._run_command('ip neigh show')
        if not success or not output:
            return threats

        current_time = datetime.now()

        for line in output.split('\n'):
            if not line.strip():
                continue

            # Parse: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            parts = line.split()
            if len(parts) < 4:
                continue

            ip = parts[0]
            mac = None
            for i, p in enumerate(parts):
                if p == 'lladdr' and i + 1 < len(parts):
                    mac = parts[i + 1].lower()
                    break

            if not mac or mac == '00:00:00:00:00:00':
                continue

            # Check for MAC changes (potential ARP spoofing)
            if ip in self.arp_cache:
                old_mac, old_time = self.arp_cache[ip]
                if old_mac != mac:
                    # MAC changed - potential ARP spoofing
                    if ip not in self.arp_history:
                        self.arp_history[ip] = []
                    self.arp_history[ip].append(mac)

                    # Check if this is a gateway (higher severity)
                    is_gateway = self._is_gateway_ip(ip)
                    severity = ThreatSeverity.CRITICAL if is_gateway else ThreatSeverity.HIGH

                    threat = ThreatEvent(
                        timestamp=current_time,
                        layer=OSILayer.L2_DATA_LINK,
                        severity=severity,
                        threat_type="ARP Spoofing",
                        source_ip=ip,
                        source_mac=mac,
                        destination_ip=None,
                        destination_port=None,
                        description=f"MAC address changed for {ip}: {old_mac} -> {mac}",
                        evidence={
                            'old_mac': old_mac,
                            'new_mac': mac,
                            'is_gateway': is_gateway,
                            'mac_history': self.arp_history.get(ip, [])
                        },
                        mitre_attack_id=self.mitre_mappings['arp_spoofing'],
                        recommended_action="Block suspicious MAC, verify gateway"
                    )
                    threats.append(threat)
                    self._add_threat(threat)

            # Update ARP cache
            self.arp_cache[ip] = (mac, current_time)

        return threats

    def _is_gateway_ip(self, ip: str) -> bool:
        """Check if IP is the default gateway"""
        output, success = self._run_command('ip route | grep default')
        if success and output:
            return ip in output
        return False

    def _detect_mac_flooding(self) -> List[ThreatEvent]:
        """Detect MAC flooding attacks on switches"""
        threats = []

        # Check bridge FDB table size
        output, success = self._run_command('bridge fdb show 2>/dev/null | wc -l')
        if success and output:
            try:
                fdb_count = int(output)
                # Alert if FDB table is unusually large (potential MAC flood)
                if fdb_count > 1000:
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L2_DATA_LINK,
                        severity=ThreatSeverity.HIGH,
                        threat_type="MAC Flooding",
                        source_ip=None,
                        source_mac=None,
                        destination_ip=None,
                        destination_port=None,
                        description=f"Unusually high MAC addresses in FDB table: {fdb_count}",
                        evidence={'fdb_count': fdb_count},
                        mitre_attack_id=self.mitre_mappings['mac_flooding'],
                        recommended_action="Enable port security, limit MAC per port"
                    )
                    threats.append(threat)
                    self._add_threat(threat)
            except ValueError:
                pass

        return threats

    def _detect_evil_twin(self) -> List[ThreatEvent]:
        """Detect evil twin / rogue access points"""
        threats = []

        # Scan for nearby WiFi networks
        for iface in ['wlan0', 'wlan1']:
            output, success = self._run_command(f'sudo iw dev {iface} scan 2>/dev/null')
            if not success or not output:
                continue

            current_ssid = None
            current_bssid = None
            current_channel = None
            current_signal = None

            for line in output.split('\n'):
                line = line.strip()

                if line.startswith('BSS '):
                    # Save previous entry if complete
                    if current_ssid and current_bssid:
                        self._check_evil_twin(
                            current_ssid, current_bssid,
                            current_channel, current_signal, threats
                        )

                    # Start new entry
                    match = re.search(r'BSS ([0-9a-f:]+)', line)
                    current_bssid = match.group(1) if match else None
                    current_ssid = None
                    current_channel = None
                    current_signal = None

                elif line.startswith('SSID:'):
                    current_ssid = line.split(':', 1)[1].strip()
                elif line.startswith('freq:'):
                    try:
                        freq = int(line.split(':', 1)[1].strip())
                        if 2412 <= freq <= 2484:
                            current_channel = (freq - 2407) // 5
                        elif freq >= 5180:
                            current_channel = (freq - 5000) // 5
                    except ValueError:
                        pass
                elif line.startswith('signal:'):
                    try:
                        current_signal = float(line.split(':')[1].split()[0])
                    except (ValueError, IndexError):
                        pass

            # Check last entry
            if current_ssid and current_bssid:
                self._check_evil_twin(
                    current_ssid, current_bssid,
                    current_channel, current_signal, threats
                )

        return threats

    def _check_evil_twin(
        self, ssid: str, bssid: str,
        channel: Optional[int], signal: Optional[float],
        threats: List[ThreatEvent]
    ):
        """Check if AP might be an evil twin"""
        bssid = bssid.lower()

        if ssid in self.known_ssids:
            known = self.known_ssids[ssid]
            known_bssid = known.get('bssid', '').lower()

            # Different BSSID for same SSID = potential evil twin
            if known_bssid and known_bssid != bssid:
                # Check if this is a new potential evil twin
                if bssid not in known.get('seen_bssids', []):
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L2_DATA_LINK,
                        severity=ThreatSeverity.CRITICAL,
                        threat_type="Evil Twin AP",
                        source_ip=None,
                        source_mac=bssid,
                        destination_ip=None,
                        destination_port=None,
                        description=f"Potential evil twin for SSID '{ssid}': "
                                   f"Known BSSID {known_bssid}, suspicious BSSID {bssid}",
                        evidence={
                            'ssid': ssid,
                            'known_bssid': known_bssid,
                            'suspicious_bssid': bssid,
                            'channel': channel,
                            'signal': signal
                        },
                        mitre_attack_id=self.mitre_mappings['evil_twin'],
                        recommended_action="Do NOT connect to this network, verify with IT"
                    )
                    threats.append(threat)
                    self._add_threat(threat)

                    # Track seen BSSIDs
                    if 'seen_bssids' not in known:
                        known['seen_bssids'] = []
                    known['seen_bssids'].append(bssid)
        else:
            # First time seeing this SSID - record it
            self.known_ssids[ssid] = {
                'bssid': bssid,
                'channel': channel,
                'signal': signal,
                'first_seen': datetime.now().isoformat(),
                'seen_bssids': [bssid]
            }

        self._save_state()

    def _detect_vlan_hopping(self) -> List[ThreatEvent]:
        """Detect VLAN hopping attempts"""
        threats = []

        # Check for double-tagged frames (802.1Q-in-Q)
        # This would typically be detected via Suricata or tcpdump
        output, success = self._run_command(
            'grep -i "vlan" /var/log/suricata/eve.json 2>/dev/null | tail -10'
        )
        if success and output:
            for line in output.split('\n'):
                try:
                    event = json.loads(line)
                    if 'vlan' in str(event).lower() and event.get('event_type') == 'alert':
                        threat = ThreatEvent(
                            timestamp=datetime.now(),
                            layer=OSILayer.L2_DATA_LINK,
                            severity=ThreatSeverity.HIGH,
                            threat_type="VLAN Hopping",
                            source_ip=event.get('src_ip'),
                            source_mac=None,
                            destination_ip=event.get('dest_ip'),
                            destination_port=event.get('dest_port'),
                            description="Potential VLAN hopping attack detected",
                            evidence={'suricata_event': event},
                            mitre_attack_id=self.mitre_mappings['vlan_hopping'],
                            recommended_action="Disable DTP, configure static VLAN access"
                        )
                        threats.append(threat)
                        self._add_threat(threat)
                except json.JSONDecodeError:
                    pass

        return threats

    def _detect_rogue_dhcp(self) -> List[ThreatEvent]:
        """Detect rogue DHCP servers"""
        threats = []

        # Check Zeek DHCP logs for multiple DHCP servers
        dhcp_log = self.zeek_log_dir / "dhcp.log"
        if dhcp_log.exists():
            try:
                output, _ = self._run_command(f'tail -100 {dhcp_log}')
                if output:
                    dhcp_servers = set()
                    for line in output.split('\n'):
                        if line.startswith('#'):
                            continue
                        parts = line.split('\t')
                        if len(parts) > 5:
                            # server_addr is typically field 5
                            server_ip = parts[4] if len(parts) > 4 else None
                            if server_ip and server_ip != '-':
                                dhcp_servers.add(server_ip)

                    # Multiple DHCP servers = potential rogue
                    if len(dhcp_servers) > 1:
                        threat = ThreatEvent(
                            timestamp=datetime.now(),
                            layer=OSILayer.L2_DATA_LINK,
                            severity=ThreatSeverity.CRITICAL,
                            threat_type="Rogue DHCP Server",
                            source_ip=None,
                            source_mac=None,
                            destination_ip=None,
                            destination_port=None,
                            description=f"Multiple DHCP servers detected: {', '.join(dhcp_servers)}",
                            evidence={'dhcp_servers': list(dhcp_servers)},
                            mitre_attack_id='T1557.003',
                            recommended_action="Identify legitimate DHCP server, block rogues"
                        )
                        threats.append(threat)
                        self._add_threat(threat)
            except Exception:
                pass

        return threats

    # =========================================================================
    # L3 - NETWORK LAYER DETECTION
    # =========================================================================

    def detect_l3_threats(self) -> List[ThreatEvent]:
        """Detect Layer 3 (Network) threats"""
        threats = []

        # IP Spoofing Detection
        threats.extend(self._detect_ip_spoofing())

        # ICMP Attacks
        threats.extend(self._detect_icmp_attacks())

        # Routing Attacks
        threats.extend(self._detect_routing_attacks())

        # IP Fragmentation Attacks
        threats.extend(self._detect_fragmentation_attacks())

        return threats

    def _detect_ip_spoofing(self) -> List[ThreatEvent]:
        """Detect IP spoofing attacks"""
        threats = []

        # Check for packets with source IP matching our local network
        # coming from external interface (basic bogon filtering)

        # Get local networks
        output, success = self._run_command('ip addr show | grep "inet "')
        if not success:
            return threats

        local_networks = []
        for line in output.split('\n'):
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if match:
                local_networks.append((match.group(1), match.group(2)))

        # Check nftables/iptables logs for spoofing attempts
        output, success = self._run_command(
            'journalctl -k -n 100 --no-pager 2>/dev/null | grep -i "martian\\|spoofed"'
        )
        if success and output:
            for line in output.split('\n'):
                if 'martian' in line.lower() or 'spoofed' in line.lower():
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L3_NETWORK,
                        severity=ThreatSeverity.HIGH,
                        threat_type="IP Spoofing",
                        source_ip=None,
                        source_mac=None,
                        destination_ip=None,
                        destination_port=None,
                        description="Martian/spoofed packet detected by kernel",
                        evidence={'kernel_log': line[:200]},
                        mitre_attack_id=self.mitre_mappings['ip_spoofing'],
                        recommended_action="Enable reverse path filtering"
                    )
                    threats.append(threat)
                    self._add_threat(threat)

        return threats

    def _detect_icmp_attacks(self) -> List[ThreatEvent]:
        """Detect ICMP-based attacks"""
        threats = []

        # Check for ICMP flood via netstat/ss
        output, success = self._run_command(
            'cat /proc/net/snmp | grep Icmp'
        )
        if success and output:
            lines = output.split('\n')
            if len(lines) >= 2:
                headers = lines[0].split()
                values = lines[1].split()

                # Find InMsgs index
                try:
                    in_msgs_idx = headers.index('InMsgs')
                    in_msgs = int(values[in_msgs_idx])

                    # High ICMP could indicate flood (this is a simple heuristic)
                    if in_msgs > 10000:
                        threat = ThreatEvent(
                            timestamp=datetime.now(),
                            layer=OSILayer.L3_NETWORK,
                            severity=ThreatSeverity.MEDIUM,
                            threat_type="ICMP Flood",
                            source_ip=None,
                            source_mac=None,
                            destination_ip=None,
                            destination_port=None,
                            description=f"High ICMP traffic detected: {in_msgs} messages",
                            evidence={'icmp_in_msgs': in_msgs},
                            mitre_attack_id=self.mitre_mappings['icmp_flood'],
                            recommended_action="Rate limit ICMP traffic"
                        )
                        threats.append(threat)
                        self._add_threat(threat)
                except (ValueError, IndexError):
                    pass

        return threats

    def _detect_routing_attacks(self) -> List[ThreatEvent]:
        """Detect routing-based attacks"""
        threats = []

        # Check for unexpected route changes
        output, success = self._run_command('ip route show')
        if success and output:
            # Look for suspicious routes (e.g., multiple default gateways)
            default_routes = [l for l in output.split('\n') if l.startswith('default')]
            if len(default_routes) > 1:
                threat = ThreatEvent(
                    timestamp=datetime.now(),
                    layer=OSILayer.L3_NETWORK,
                    severity=ThreatSeverity.HIGH,
                    threat_type="Routing Attack",
                    source_ip=None,
                    source_mac=None,
                    destination_ip=None,
                    destination_port=None,
                    description=f"Multiple default routes detected: potential route hijacking",
                    evidence={'default_routes': default_routes},
                    mitre_attack_id='T1599.001',
                    recommended_action="Verify routing table, remove unauthorized routes"
                )
                threats.append(threat)
                self._add_threat(threat)

        return threats

    def _detect_fragmentation_attacks(self) -> List[ThreatEvent]:
        """Detect IP fragmentation attacks"""
        threats = []

        # Check Suricata for fragmentation alerts
        if self.suricata_log.exists():
            output, success = self._run_command(
                f'grep -i "frag" {self.suricata_log} 2>/dev/null | tail -10'
            )
            if success and output:
                for line in output.split('\n'):
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            threat = ThreatEvent(
                                timestamp=datetime.now(),
                                layer=OSILayer.L3_NETWORK,
                                severity=ThreatSeverity.MEDIUM,
                                threat_type="Fragmentation Attack",
                                source_ip=event.get('src_ip'),
                                source_mac=None,
                                destination_ip=event.get('dest_ip'),
                                destination_port=event.get('dest_port'),
                                description=f"IP fragmentation attack: {event.get('alert', {}).get('signature', 'Unknown')}",
                                evidence={'suricata_alert': event.get('alert', {})},
                                mitre_attack_id='T1499.001',
                                recommended_action="Block malformed fragments"
                            )
                            threats.append(threat)
                            self._add_threat(threat)
                    except json.JSONDecodeError:
                        pass

        return threats

    # =========================================================================
    # L4 - TRANSPORT LAYER DETECTION
    # =========================================================================

    def detect_l4_threats(self) -> List[ThreatEvent]:
        """Detect Layer 4 (Transport) threats"""
        threats = []

        # Port Scan Detection
        threats.extend(self._detect_port_scans())

        # SYN Flood Detection
        threats.extend(self._detect_syn_flood())

        # TCP Session Anomalies
        threats.extend(self._detect_tcp_anomalies())

        # UDP Flood Detection
        threats.extend(self._detect_udp_flood())

        return threats

    def _detect_port_scans(self) -> List[ThreatEvent]:
        """Detect port scanning activity"""
        threats = []

        # Check Zeek conn.log for port scan patterns
        conn_log = self.zeek_log_dir / "conn.log"
        if conn_log.exists():
            output, success = self._run_command(f'tail -1000 {conn_log}')
            if success and output:
                # Track connections by source IP
                source_connections: Dict[str, set] = {}

                for line in output.split('\n'):
                    if line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) > 5:
                        src_ip = parts[2] if len(parts) > 2 else None
                        dst_port = parts[5] if len(parts) > 5 else None

                        if src_ip and dst_port and dst_port != '-':
                            if src_ip not in source_connections:
                                source_connections[src_ip] = set()
                            source_connections[src_ip].add(dst_port)

                # Detect port scans (many ports from single source)
                for src_ip, ports in source_connections.items():
                    if len(ports) > 50:  # Threshold for port scan
                        threat = ThreatEvent(
                            timestamp=datetime.now(),
                            layer=OSILayer.L4_TRANSPORT,
                            severity=ThreatSeverity.HIGH,
                            threat_type="Port Scan",
                            source_ip=src_ip,
                            source_mac=None,
                            destination_ip=None,
                            destination_port=None,
                            description=f"Port scan detected from {src_ip}: {len(ports)} unique ports",
                            evidence={'port_count': len(ports), 'sample_ports': list(ports)[:20]},
                            mitre_attack_id=self.mitre_mappings['port_scan'],
                            recommended_action="Block source IP, investigate"
                        )
                        threats.append(threat)
                        self._add_threat(threat)

        return threats

    def _detect_syn_flood(self) -> List[ThreatEvent]:
        """Detect SYN flood attacks"""
        threats = []

        # Check TCP statistics for SYN floods
        output, success = self._run_command('ss -s')
        if success and output:
            # Look for high number of SYN_RECV states
            match = re.search(r'(\d+)\s+SYN[_-]RECV', output, re.IGNORECASE)
            if match:
                syn_recv_count = int(match.group(1))
                if syn_recv_count > 100:
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L4_TRANSPORT,
                        severity=ThreatSeverity.CRITICAL,
                        threat_type="SYN Flood",
                        source_ip=None,
                        source_mac=None,
                        destination_ip=None,
                        destination_port=None,
                        description=f"Potential SYN flood: {syn_recv_count} connections in SYN_RECV state",
                        evidence={'syn_recv_count': syn_recv_count},
                        mitre_attack_id=self.mitre_mappings['syn_flood'],
                        recommended_action="Enable SYN cookies, rate limit",
                        blocked=False
                    )
                    threats.append(threat)
                    self._add_threat(threat)

        return threats

    def _detect_tcp_anomalies(self) -> List[ThreatEvent]:
        """Detect TCP session anomalies"""
        threats = []

        # Check for TCP RST floods (potential connection reset attack)
        output, success = self._run_command('cat /proc/net/snmp | grep Tcp')
        if success and output:
            lines = output.split('\n')
            if len(lines) >= 2:
                headers = lines[0].split()
                values = lines[1].split()

                try:
                    # Check OutRsts (TCP resets sent)
                    rst_idx = headers.index('OutRsts')
                    out_rsts = int(values[rst_idx])

                    # High RST count could indicate attack or being attacked
                    if out_rsts > 5000:
                        threat = ThreatEvent(
                            timestamp=datetime.now(),
                            layer=OSILayer.L4_TRANSPORT,
                            severity=ThreatSeverity.MEDIUM,
                            threat_type="TCP RST Anomaly",
                            source_ip=None,
                            source_mac=None,
                            destination_ip=None,
                            destination_port=None,
                            description=f"High TCP reset count: {out_rsts}",
                            evidence={'out_rsts': out_rsts},
                            mitre_attack_id='T1090.001',
                            recommended_action="Investigate connections being reset"
                        )
                        threats.append(threat)
                        self._add_threat(threat)
                except (ValueError, IndexError):
                    pass

        return threats

    def _detect_udp_flood(self) -> List[ThreatEvent]:
        """Detect UDP flood attacks"""
        threats = []

        # Check UDP statistics
        output, success = self._run_command('cat /proc/net/snmp | grep Udp')
        if success and output:
            lines = output.split('\n')
            if len(lines) >= 2:
                headers = lines[0].split()
                values = lines[1].split()

                try:
                    in_dgrams_idx = headers.index('InDatagrams')
                    in_dgrams = int(values[in_dgrams_idx])

                    # High UDP could indicate flood
                    if in_dgrams > 100000:
                        threat = ThreatEvent(
                            timestamp=datetime.now(),
                            layer=OSILayer.L4_TRANSPORT,
                            severity=ThreatSeverity.MEDIUM,
                            threat_type="UDP Flood",
                            source_ip=None,
                            source_mac=None,
                            destination_ip=None,
                            destination_port=None,
                            description=f"High UDP traffic: {in_dgrams} datagrams",
                            evidence={'udp_in_datagrams': in_dgrams},
                            mitre_attack_id='T1498.001',
                            recommended_action="Rate limit UDP traffic"
                        )
                        threats.append(threat)
                        self._add_threat(threat)
                except (ValueError, IndexError):
                    pass

        return threats

    # =========================================================================
    # L5 - SESSION LAYER DETECTION
    # =========================================================================

    def detect_l5_threats(self) -> List[ThreatEvent]:
        """Detect Layer 5 (Session) threats"""
        threats = []

        # SSL/TLS Attacks
        threats.extend(self._detect_ssl_attacks())

        # Session Hijacking
        threats.extend(self._detect_session_hijacking())

        # Authentication Bypass
        threats.extend(self._detect_auth_bypass())

        return threats

    def _detect_ssl_attacks(self) -> List[ThreatEvent]:
        """Detect SSL/TLS attacks"""
        threats = []

        # Check Zeek SSL logs for downgrade attacks
        ssl_log = self.zeek_log_dir / "ssl.log"
        if ssl_log.exists():
            output, success = self._run_command(f'tail -100 {ssl_log}')
            if success and output:
                for line in output.split('\n'):
                    if line.startswith('#'):
                        continue
                    parts = line.split('\t')

                    # Check for weak SSL versions
                    if len(parts) > 6:
                        ssl_version = parts[6] if len(parts) > 6 else ''

                        if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                            threat = ThreatEvent(
                                timestamp=datetime.now(),
                                layer=OSILayer.L5_SESSION,
                                severity=ThreatSeverity.HIGH,
                                threat_type="SSL Downgrade",
                                source_ip=parts[2] if len(parts) > 2 else None,
                                source_mac=None,
                                destination_ip=parts[4] if len(parts) > 4 else None,
                                destination_port=int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None,
                                description=f"Weak SSL/TLS version detected: {ssl_version}",
                                evidence={'ssl_version': ssl_version},
                                mitre_attack_id='T1557.002',
                                recommended_action="Upgrade to TLS 1.2 or higher"
                            )
                            threats.append(threat)
                            self._add_threat(threat)

        # Check Suricata for SSL stripping
        if self.suricata_log.exists():
            output, success = self._run_command(
                f'grep -i "ssl\\|tls\\|certificate" {self.suricata_log} 2>/dev/null | tail -20'
            )
            if success and output:
                for line in output.split('\n'):
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            sig = event.get('alert', {}).get('signature', '').lower()
                            if 'invalid' in sig or 'expired' in sig or 'self-signed' in sig:
                                threat = ThreatEvent(
                                    timestamp=datetime.now(),
                                    layer=OSILayer.L5_SESSION,
                                    severity=ThreatSeverity.HIGH,
                                    threat_type="Certificate Anomaly",
                                    source_ip=event.get('src_ip'),
                                    source_mac=None,
                                    destination_ip=event.get('dest_ip'),
                                    destination_port=event.get('dest_port'),
                                    description=f"SSL/TLS certificate issue: {event.get('alert', {}).get('signature', 'Unknown')}",
                                    evidence={'suricata_alert': event.get('alert', {})},
                                    mitre_attack_id=self.mitre_mappings['ssl_strip'],
                                    recommended_action="Verify certificate validity"
                                )
                                threats.append(threat)
                                self._add_threat(threat)
                    except json.JSONDecodeError:
                        pass

        return threats

    def _detect_session_hijacking(self) -> List[ThreatEvent]:
        """Detect session hijacking attempts"""
        threats = []

        # This would typically be detected by monitoring for:
        # - Session token reuse from different IPs
        # - Session fixation patterns
        # - Cookie manipulation

        # Check ModSecurity logs for session-related attacks
        output, success = self._run_command(
            'grep -i "session\\|cookie\\|csrf" /var/log/modsecurity/modsec_audit.log 2>/dev/null | tail -20'
        )
        if success and output:
            for line in output.split('\n'):
                if 'session' in line.lower() and ('hijack' in line.lower() or 'fixation' in line.lower()):
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L5_SESSION,
                        severity=ThreatSeverity.CRITICAL,
                        threat_type="Session Hijacking",
                        source_ip=None,
                        source_mac=None,
                        destination_ip=None,
                        destination_port=None,
                        description="Potential session hijacking detected",
                        evidence={'log_entry': line[:200]},
                        mitre_attack_id=self.mitre_mappings['session_hijack'],
                        recommended_action="Invalidate session, force re-authentication"
                    )
                    threats.append(threat)
                    self._add_threat(threat)

        return threats

    def _detect_auth_bypass(self) -> List[ThreatEvent]:
        """Detect authentication bypass attempts"""
        threats = []

        # Check for repeated failed authentication attempts
        output, success = self._run_command(
            'grep -i "authentication\\|login\\|failed" /var/log/auth.log 2>/dev/null | tail -50'
        )
        if success and output:
            failed_ips: Dict[str, int] = {}
            for line in output.split('\n'):
                if 'failed' in line.lower():
                    # Extract IP
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_ips[ip] = failed_ips.get(ip, 0) + 1

            # Alert on IPs with many failures
            for ip, count in failed_ips.items():
                if count >= 5:
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L5_SESSION,
                        severity=ThreatSeverity.HIGH,
                        threat_type="Brute Force Attack",
                        source_ip=ip,
                        source_mac=None,
                        destination_ip=None,
                        destination_port=None,
                        description=f"Multiple failed authentication attempts from {ip}: {count} failures",
                        evidence={'failed_count': count, 'source_ip': ip},
                        mitre_attack_id='T1110',
                        recommended_action="Block IP, implement account lockout"
                    )
                    threats.append(threat)
                    self._add_threat(threat)

        return threats

    # =========================================================================
    # L6 - PRESENTATION LAYER DETECTION
    # =========================================================================

    def detect_l6_threats(self) -> List[ThreatEvent]:
        """Detect Layer 6 (Presentation) threats"""
        threats = []

        # Encoding Attacks
        threats.extend(self._detect_encoding_attacks())

        # Data Format Exploits
        threats.extend(self._detect_format_exploits())

        # Cryptographic Attacks
        threats.extend(self._detect_crypto_attacks())

        return threats

    def _detect_encoding_attacks(self) -> List[ThreatEvent]:
        """Detect encoding-based attacks (double encoding, unicode attacks)"""
        threats = []

        # Check ModSecurity/Suricata for encoding attacks
        if self.suricata_log.exists():
            output, success = self._run_command(
                f'grep -iE "encod|unicode|utf|%[0-9a-f]{{2}}" {self.suricata_log} 2>/dev/null | tail -10'
            )
            if success and output:
                for line in output.split('\n'):
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            sig = event.get('alert', {}).get('signature', '')
                            if 'encod' in sig.lower() or 'unicode' in sig.lower():
                                threat = ThreatEvent(
                                    timestamp=datetime.now(),
                                    layer=OSILayer.L6_PRESENTATION,
                                    severity=ThreatSeverity.MEDIUM,
                                    threat_type="Encoding Attack",
                                    source_ip=event.get('src_ip'),
                                    source_mac=None,
                                    destination_ip=event.get('dest_ip'),
                                    destination_port=event.get('dest_port'),
                                    description=f"Encoding-based attack detected: {sig}",
                                    evidence={'suricata_alert': event.get('alert', {})},
                                    mitre_attack_id='T1027',
                                    recommended_action="Normalize and validate input"
                                )
                                threats.append(threat)
                                self._add_threat(threat)
                    except json.JSONDecodeError:
                        pass

        return threats

    def _detect_format_exploits(self) -> List[ThreatEvent]:
        """Detect data format exploits (XML bombs, JSON injection)"""
        threats = []

        # Check for XML-related attacks
        if self.suricata_log.exists():
            output, success = self._run_command(
                f'grep -iE "xml|xxe|entity|dtd" {self.suricata_log} 2>/dev/null | tail -10'
            )
            if success and output:
                for line in output.split('\n'):
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            threat = ThreatEvent(
                                timestamp=datetime.now(),
                                layer=OSILayer.L6_PRESENTATION,
                                severity=ThreatSeverity.HIGH,
                                threat_type="XML Injection",
                                source_ip=event.get('src_ip'),
                                source_mac=None,
                                destination_ip=event.get('dest_ip'),
                                destination_port=event.get('dest_port'),
                                description=f"XML-based attack: {event.get('alert', {}).get('signature', 'Unknown')}",
                                evidence={'suricata_alert': event.get('alert', {})},
                                mitre_attack_id='T1059.009',
                                recommended_action="Disable external entities, validate XML"
                            )
                            threats.append(threat)
                            self._add_threat(threat)
                    except json.JSONDecodeError:
                        pass

        return threats

    def _detect_crypto_attacks(self) -> List[ThreatEvent]:
        """Detect cryptographic attacks"""
        threats = []

        # Check for weak crypto algorithms in use
        output, success = self._run_command(
            'grep -rh "MD5\\|SHA1\\|DES\\|RC4" /etc/ssl/certs/*.pem 2>/dev/null | head -5'
        )
        if success and output:
            threat = ThreatEvent(
                timestamp=datetime.now(),
                layer=OSILayer.L6_PRESENTATION,
                severity=ThreatSeverity.MEDIUM,
                threat_type="Weak Cryptography",
                source_ip=None,
                source_mac=None,
                destination_ip=None,
                destination_port=None,
                description="Weak cryptographic algorithms detected in certificates",
                evidence={'algorithms_found': output[:500]},
                mitre_attack_id='T1600',
                recommended_action="Upgrade to SHA-256 or stronger"
            )
            threats.append(threat)
            self._add_threat(threat)

        return threats

    # =========================================================================
    # L7 - APPLICATION LAYER DETECTION
    # =========================================================================

    def detect_l7_threats(self) -> List[ThreatEvent]:
        """Detect Layer 7 (Application) threats"""
        threats = []

        # Web Application Attacks
        threats.extend(self._detect_web_attacks())

        # DNS-Based Threats
        threats.extend(self._detect_dns_threats())

        # Malware C2 Communication
        threats.extend(self._detect_malware_c2())

        # Application Protocol Abuse
        threats.extend(self._detect_protocol_abuse())

        return threats

    def _detect_web_attacks(self) -> List[ThreatEvent]:
        """Detect web application attacks (SQLi, XSS, etc.)"""
        threats = []

        # Check Suricata for web attacks
        if self.suricata_log.exists():
            output, success = self._run_command(
                f'grep -iE "sql|xss|injection|traversal|rfi|lfi" {self.suricata_log} 2>/dev/null | tail -20'
            )
            if success and output:
                for line in output.split('\n'):
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            sig = event.get('alert', {}).get('signature', '').lower()

                            # Determine attack type
                            if 'sql' in sig:
                                attack_type = "SQL Injection"
                                mitre_id = self.mitre_mappings['sql_injection']
                            elif 'xss' in sig:
                                attack_type = "Cross-Site Scripting (XSS)"
                                mitre_id = self.mitre_mappings['xss']
                            elif 'traversal' in sig or 'lfi' in sig or 'rfi' in sig:
                                attack_type = "Path Traversal"
                                mitre_id = 'T1083'
                            else:
                                attack_type = "Web Attack"
                                mitre_id = 'T1190'

                            threat = ThreatEvent(
                                timestamp=datetime.now(),
                                layer=OSILayer.L7_APPLICATION,
                                severity=ThreatSeverity.CRITICAL,
                                threat_type=attack_type,
                                source_ip=event.get('src_ip'),
                                source_mac=None,
                                destination_ip=event.get('dest_ip'),
                                destination_port=event.get('dest_port'),
                                description=f"{attack_type} detected: {event.get('alert', {}).get('signature', 'Unknown')}",
                                evidence={'suricata_alert': event.get('alert', {})},
                                mitre_attack_id=mitre_id,
                                recommended_action="Block source, review WAF rules"
                            )
                            threats.append(threat)
                            self._add_threat(threat)
                    except json.JSONDecodeError:
                        pass

        return threats

    def _detect_dns_threats(self) -> List[ThreatEvent]:
        """Detect DNS-based threats (tunneling, spoofing)"""
        threats = []

        # Check Zeek DNS logs for anomalies
        dns_log = self.zeek_log_dir / "dns.log"
        if dns_log.exists():
            output, success = self._run_command(f'tail -200 {dns_log}')
            if success and output:
                # Look for DNS tunneling indicators
                long_queries = []
                for line in output.split('\n'):
                    if line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) > 9:
                        query = parts[9] if len(parts) > 9 else ''
                        # Long query names could indicate DNS tunneling
                        if len(query) > 50:
                            long_queries.append(query)

                if len(long_queries) > 10:
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L7_APPLICATION,
                        severity=ThreatSeverity.HIGH,
                        threat_type="DNS Tunneling",
                        source_ip=None,
                        source_mac=None,
                        destination_ip=None,
                        destination_port=53,
                        description=f"Potential DNS tunneling: {len(long_queries)} long DNS queries detected",
                        evidence={'long_query_count': len(long_queries), 'sample_queries': long_queries[:5]},
                        mitre_attack_id=self.mitre_mappings['dns_tunneling'],
                        recommended_action="Block suspicious domains, investigate"
                    )
                    threats.append(threat)
                    self._add_threat(threat)

        return threats

    def _detect_malware_c2(self) -> List[ThreatEvent]:
        """Detect malware command and control communication"""
        threats = []

        # Check Suricata for C2 indicators
        if self.suricata_log.exists():
            output, success = self._run_command(
                f'grep -iE "command|control|c2|beacon|rat|trojan|botnet" {self.suricata_log} 2>/dev/null | tail -20'
            )
            if success and output:
                for line in output.split('\n'):
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            threat = ThreatEvent(
                                timestamp=datetime.now(),
                                layer=OSILayer.L7_APPLICATION,
                                severity=ThreatSeverity.CRITICAL,
                                threat_type="Malware C2",
                                source_ip=event.get('src_ip'),
                                source_mac=None,
                                destination_ip=event.get('dest_ip'),
                                destination_port=event.get('dest_port'),
                                description=f"Malware C2 communication detected: {event.get('alert', {}).get('signature', 'Unknown')}",
                                evidence={'suricata_alert': event.get('alert', {})},
                                mitre_attack_id=self.mitre_mappings['malware_c2'],
                                recommended_action="Quarantine device, block destination"
                            )
                            threats.append(threat)
                            self._add_threat(threat)
                    except json.JSONDecodeError:
                        pass

        return threats

    def _detect_protocol_abuse(self) -> List[ThreatEvent]:
        """Detect application protocol abuse"""
        threats = []

        # Check for unusual protocol usage (e.g., HTTP over non-standard ports)
        conn_log = self.zeek_log_dir / "conn.log"
        if conn_log.exists():
            output, success = self._run_command(f'tail -500 {conn_log}')
            if success and output:
                # Track unusual protocol/port combinations
                unusual = []
                for line in output.split('\n'):
                    if line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) > 7:
                        proto = parts[6] if len(parts) > 6 else ''
                        dst_port = parts[5] if len(parts) > 5 else ''
                        service = parts[7] if len(parts) > 7 else ''

                        # HTTP on non-standard port
                        if service == 'http' and dst_port not in ['80', '8080', '8000', '8888']:
                            unusual.append(f"HTTP on port {dst_port}")

                if len(unusual) > 5:
                    threat = ThreatEvent(
                        timestamp=datetime.now(),
                        layer=OSILayer.L7_APPLICATION,
                        severity=ThreatSeverity.MEDIUM,
                        threat_type="Protocol Abuse",
                        source_ip=None,
                        source_mac=None,
                        destination_ip=None,
                        destination_port=None,
                        description=f"Unusual protocol usage detected: {len(unusual)} instances",
                        evidence={'unusual_patterns': unusual[:10]},
                        mitre_attack_id='T1071',
                        recommended_action="Investigate unusual traffic patterns"
                    )
                    threats.append(threat)
                    self._add_threat(threat)

        return threats

    # =========================================================================
    # UNIFIED DETECTION & REPORTING
    # =========================================================================

    def detect_all_threats(self) -> Dict[str, Any]:
        """Run detection for all layers and return comprehensive report"""
        all_threats = []

        # Detect threats at each layer
        all_threats.extend(self.detect_l2_threats())
        all_threats.extend(self.detect_l3_threats())
        all_threats.extend(self.detect_l4_threats())
        all_threats.extend(self.detect_l5_threats())
        all_threats.extend(self.detect_l6_threats())
        all_threats.extend(self.detect_l7_threats())

        # Generate report
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive threat report with layer breakdown"""

        # Calculate severity counts across all threats
        total_critical = sum(s.critical_count for s in self.layer_stats.values())
        total_high = sum(s.high_count for s in self.layer_stats.values())
        total_medium = sum(s.medium_count for s in self.layer_stats.values())
        total_low = sum(s.low_count for s in self.layer_stats.values())
        total_info = sum(s.info_count for s in self.layer_stats.values())
        total_blocked = sum(s.blocked_count for s in self.layer_stats.values())
        total_threats = sum(s.total_threats for s in self.layer_stats.values())

        # Calculate RAG status
        if total_critical > 0 or total_high > 5:
            rag_status = "RED"
        elif total_high > 0 or total_medium > 10:
            rag_status = "AMBER"
        else:
            rag_status = "GREEN"

        # Layer breakdown
        layer_breakdown = {}
        for layer in OSILayer:
            stats = self.layer_stats[layer]
            layer_breakdown[layer.name] = stats.to_dict()

        # Recent threats (last 20)
        recent_threats = [t.to_dict() for t in self.threats[-20:]]

        # Get most common threat types
        all_threat_types: Dict[str, int] = {}
        for stats in self.layer_stats.values():
            for threat_type, count in stats.threat_types.items():
                if threat_type not in all_threat_types:
                    all_threat_types[threat_type] = 0
                all_threat_types[threat_type] += count

        top_threat_types = sorted(
            all_threat_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            'timestamp': datetime.now().isoformat(),
            'rag_status': rag_status,
            'summary': {
                'total_threats': total_threats,
                'critical': total_critical,
                'high': total_high,
                'medium': total_medium,
                'low': total_low,
                'info': total_info,
                'blocked': total_blocked
            },
            'layer_breakdown': layer_breakdown,
            'recent_threats': recent_threats,
            'top_threat_types': dict(top_threat_types),
            'detection_coverage': {
                'l2_data_link': ['ARP Spoofing', 'MAC Flooding', 'Evil Twin', 'VLAN Hopping', 'Rogue DHCP'],
                'l3_network': ['IP Spoofing', 'ICMP Attacks', 'Routing Attacks', 'Fragmentation'],
                'l4_transport': ['Port Scans', 'SYN Flood', 'TCP Anomalies', 'UDP Flood'],
                'l5_session': ['SSL Attacks', 'Session Hijacking', 'Auth Bypass'],
                'l6_presentation': ['Encoding Attacks', 'Format Exploits', 'Crypto Attacks'],
                'l7_application': ['Web Attacks', 'DNS Threats', 'Malware C2', 'Protocol Abuse']
            }
        }

    def get_qsecbit_threat_score(self) -> float:
        """Calculate threat score for QSecBit integration (0.0 - 1.0)"""
        total_critical = sum(s.critical_count for s in self.layer_stats.values())
        total_high = sum(s.high_count for s in self.layer_stats.values())
        total_medium = sum(s.medium_count for s in self.layer_stats.values())
        total_low = sum(s.low_count for s in self.layer_stats.values())

        # Weighted score calculation
        weighted_score = (
            total_critical * 1.0 +
            total_high * 0.7 +
            total_medium * 0.4 +
            total_low * 0.1
        )

        # Normalize to 0-1 range (cap at 10 weighted threats for max score)
        normalized = min(1.0, weighted_score / 10.0)

        return round(normalized, 4)


# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("LAYER THREAT DETECTOR - OSI L2-L7 Threat Detection Engine")
    print("=" * 70)

    detector = LayerThreatDetector()

    print("\nRunning threat detection across all layers...")
    report = detector.detect_all_threats()

    print(f"\n--- THREAT REPORT ---")
    print(f"Timestamp: {report['timestamp']}")
    print(f"RAG Status: {report['rag_status']}")
    print(f"\nSummary:")
    print(f"  Total Threats: {report['summary']['total_threats']}")
    print(f"  Critical: {report['summary']['critical']}")
    print(f"  High: {report['summary']['high']}")
    print(f"  Medium: {report['summary']['medium']}")
    print(f"  Low: {report['summary']['low']}")
    print(f"  Blocked: {report['summary']['blocked']}")

    print(f"\nLayer Breakdown:")
    for layer_name, stats in report['layer_breakdown'].items():
        print(f"  {layer_name}: {stats['total_threats']} threats")

    print(f"\nQSecBit Threat Score: {detector.get_qsecbit_threat_score()}")
    print("=" * 70)
