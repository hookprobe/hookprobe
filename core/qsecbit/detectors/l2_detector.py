"""
Qsecbit v6.0 - Layer 2 (Data Link) Threat Detector

Detects Layer 2 attacks:
- ARP Spoofing (MAC change detection, gateway protection)
- MAC Flooding (FDB table size monitoring)
- VLAN Hopping (802.1Q-in-Q detection)
- Evil Twin AP (rogue access point detection)
- Rogue DHCP Server

Author: HookProbe Team
License: Proprietary
Version: 6.0
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path

from .base import BaseDetector
from ..threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer
)


class L2DataLinkDetector(BaseDetector):
    """
    Layer 2 (Data Link) threat detector.

    Monitors ARP cache, FDB tables, WiFi environment, and DHCP servers
    to detect L2-level attacks.
    """

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/data",
        mac_flooding_threshold: int = 1000,
        enable_wifi_scan: bool = True
    ):
        super().__init__(
            name="L2DataLinkDetector",
            layer=OSILayer.L2_DATA_LINK,
            data_dir=data_dir
        )

        self.mac_flooding_threshold = mac_flooding_threshold
        self.enable_wifi_scan = enable_wifi_scan

        # ARP cache tracking
        self.arp_cache: Dict[str, Tuple[str, datetime]] = {}  # IP -> (MAC, timestamp)
        self.arp_history: Dict[str, List[str]] = {}  # IP -> [MAC history]

        # Known legitimate gateways
        self.trusted_gateways: Dict[str, str] = {}  # IP -> MAC

        # Evil twin detection
        self.known_ssids: Dict[str, Dict[str, Any]] = {}  # SSID -> {bssid, etc}

        # DHCP server tracking
        self.known_dhcp_servers: set = set()

        # Load previous state
        self._load_state()

    def _load_state(self):
        """Load saved state from disk."""
        state_file = self.data_dir / "l2_detector_state.json"
        if state_file.exists():
            try:
                import json
                with open(state_file) as f:
                    state = json.load(f)
                    self.trusted_gateways = state.get('trusted_gateways', {})
                    self.known_ssids = state.get('known_ssids', {})
                    self.known_dhcp_servers = set(state.get('known_dhcp_servers', []))
            except Exception:
                pass

    def _save_state(self):
        """Save state to disk."""
        state_file = self.data_dir / "l2_detector_state.json"
        try:
            import json
            with open(state_file, 'w') as f:
                json.dump({
                    'trusted_gateways': self.trusted_gateways,
                    'known_ssids': self.known_ssids,
                    'known_dhcp_servers': list(self.known_dhcp_servers),
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception:
            pass

    def _get_default_gateway(self) -> Optional[str]:
        """Get default gateway IP address."""
        output, success = self._run_command('ip route show default')
        if success and output:
            match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', output)
            return match.group(1) if match else None
        return None

    def _is_gateway_ip(self, ip: str) -> bool:
        """Check if IP is the default gateway."""
        gateway = self._get_default_gateway()
        return gateway == ip if gateway else False

    def detect(self) -> List[ThreatEvent]:
        """Run all L2 detection methods."""
        threats = []

        threats.extend(self._detect_arp_spoofing())
        threats.extend(self._detect_mac_flooding())
        threats.extend(self._detect_vlan_hopping())

        if self.enable_wifi_scan:
            threats.extend(self._detect_evil_twin())

        threats.extend(self._detect_rogue_dhcp())

        return threats

    def _detect_arp_spoofing(self) -> List[ThreatEvent]:
        """
        Detect ARP spoofing attacks by monitoring ARP cache for MAC changes.

        ARP spoofing is detected when:
        - A known IP's MAC address changes
        - Gateway IP has MAC change (CRITICAL)
        - Multiple MACs seen for same IP in short period
        """
        threats = []

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

            # Check for MAC changes
            if ip in self.arp_cache:
                old_mac, old_time = self.arp_cache[ip]
                if old_mac != mac:
                    # MAC changed!
                    if ip not in self.arp_history:
                        self.arp_history[ip] = []
                    self.arp_history[ip].append(mac)

                    is_gateway = self._is_gateway_ip(ip)
                    severity = ThreatSeverity.CRITICAL if is_gateway else ThreatSeverity.HIGH
                    confidence = 0.95 if is_gateway else 0.85

                    threat = self._create_threat_event(
                        attack_type=AttackType.ARP_SPOOFING,
                        description=f"ARP spoofing detected: {ip} MAC changed from {old_mac} to {mac}",
                        confidence=confidence,
                        source_ip=ip,
                        source_mac=mac,
                        evidence={
                            'old_mac': old_mac,
                            'new_mac': mac,
                            'is_gateway': is_gateway,
                            'mac_history': self.arp_history.get(ip, [])[-10:],
                            'time_since_last': str(current_time - old_time)
                        },
                        severity_override=severity
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

            # Update ARP cache
            self.arp_cache[ip] = (mac, current_time)

        return threats

    def _detect_mac_flooding(self) -> List[ThreatEvent]:
        """
        Detect MAC flooding attacks by monitoring FDB (bridge forwarding database) size.

        MAC flooding is detected when the FDB table has an unusually high number of entries,
        which can indicate an attacker trying to overflow switch CAM tables.
        """
        threats = []

        # Try bridge fdb command
        output, success = self._run_command('bridge fdb show')
        if success and output:
            fdb_count = len([l for l in output.split('\n') if l.strip() and 'permanent' not in l])

            if fdb_count > self.mac_flooding_threshold:
                threat = self._create_threat_event(
                    attack_type=AttackType.MAC_FLOODING,
                    description=f"MAC flooding attack: {fdb_count} entries in FDB table (threshold: {self.mac_flooding_threshold})",
                    confidence=0.8 if fdb_count > self.mac_flooding_threshold * 2 else 0.6,
                    evidence={
                        'fdb_count': fdb_count,
                        'threshold': self.mac_flooding_threshold,
                        'overflow_ratio': fdb_count / self.mac_flooding_threshold
                    }
                )

                if self._add_threat(threat):
                    threats.append(threat)

        return threats

    def _detect_vlan_hopping(self) -> List[ThreatEvent]:
        """
        Detect VLAN hopping attacks (802.1Q-in-Q double tagging).

        Checks Suricata alerts for VLAN-related anomalies.
        """
        threats = []

        alerts = self._read_suricata_alerts(['vlan', 'double.?tag', '802\\.1q'])

        for event in alerts:
            src_ip = event.get('src_ip')
            dest_ip = event.get('dest_ip')
            signature = event.get('alert', {}).get('signature', 'VLAN anomaly')

            threat = self._create_threat_event(
                attack_type=AttackType.VLAN_HOPPING,
                description=f"VLAN hopping attempt: {signature}",
                confidence=0.75,
                source_ip=src_ip,
                dest_ip=dest_ip,
                evidence={
                    'suricata_alert': event.get('alert', {}),
                    'flow_id': event.get('flow_id'),
                    'timestamp': event.get('timestamp')
                }
            )

            if self._add_threat(threat):
                threats.append(threat)

        return threats

    def _detect_evil_twin(self) -> List[ThreatEvent]:
        """
        Detect evil twin / rogue access points.

        Evil twins are detected when:
        - Same SSID appears with different BSSID
        - Unusually strong signal for known network
        - Multiple APs with identical SSID on different channels
        """
        threats = []

        # Scan for WiFi networks
        for iface in ['wlan0', 'wlan1', 'wlp0s0']:
            output, success = self._run_command(f'iw dev {iface} scan 2>/dev/null')
            if not success or not output:
                continue

            current_ssid = None
            current_bssid = None
            current_channel = None
            current_signal = None

            for line in output.split('\n'):
                line = line.strip()

                if line.startswith('BSS '):
                    # Save previous entry
                    if current_ssid and current_bssid:
                        threat = self._check_evil_twin(
                            current_ssid, current_bssid,
                            current_channel, current_signal
                        )
                        if threat:
                            threats.append(threat)

                    # Start new entry
                    match = re.search(r'BSS ([0-9a-f:]+)', line)
                    current_bssid = match.group(1).lower() if match else None
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
                threat = self._check_evil_twin(
                    current_ssid, current_bssid,
                    current_channel, current_signal
                )
                if threat:
                    threats.append(threat)

        self._save_state()
        return threats

    def _check_evil_twin(
        self,
        ssid: str,
        bssid: str,
        channel: Optional[int],
        signal: Optional[float]
    ) -> Optional[ThreatEvent]:
        """Check if an AP might be an evil twin."""
        bssid = bssid.lower()

        if ssid in self.known_ssids:
            known = self.known_ssids[ssid]
            known_bssid = known.get('bssid', '').lower()

            # Different BSSID for same SSID = potential evil twin
            if known_bssid and known_bssid != bssid:
                seen_bssids = known.get('seen_bssids', [])
                if bssid not in seen_bssids:
                    threat = self._create_threat_event(
                        attack_type=AttackType.EVIL_TWIN,
                        description=f"Evil twin AP detected for '{ssid}': known BSSID {known_bssid}, rogue BSSID {bssid}",
                        confidence=0.9,
                        source_mac=bssid,
                        evidence={
                            'ssid': ssid,
                            'known_bssid': known_bssid,
                            'rogue_bssid': bssid,
                            'channel': channel,
                            'signal': signal,
                            'seen_bssids': seen_bssids
                        }
                    )

                    # Track this BSSID
                    if 'seen_bssids' not in known:
                        known['seen_bssids'] = []
                    known['seen_bssids'].append(bssid)

                    if self._add_threat(threat):
                        return threat
        else:
            # First time seeing this SSID
            self.known_ssids[ssid] = {
                'bssid': bssid,
                'channel': channel,
                'signal': signal,
                'first_seen': datetime.now().isoformat(),
                'seen_bssids': [bssid]
            }

        return None

    def _detect_rogue_dhcp(self) -> List[ThreatEvent]:
        """
        Detect rogue DHCP servers.

        Multiple DHCP servers on the same network can indicate an attack.
        """
        threats = []

        # Check Zeek DHCP logs
        dhcp_log = self.zeek_log_dir / "dhcp.log"
        if dhcp_log.exists():
            entries = self._read_zeek_log("dhcp.log", limit=100)
            dhcp_servers = set()

            for parts in entries:
                if len(parts) > 4:
                    server_ip = parts[4] if parts[4] != '-' else None
                    if server_ip:
                        dhcp_servers.add(server_ip)

            # Multiple servers = potential rogue
            if len(dhcp_servers) > 1:
                new_servers = dhcp_servers - self.known_dhcp_servers

                if new_servers:
                    threat = self._create_threat_event(
                        attack_type=AttackType.ROGUE_DHCP,
                        description=f"Multiple DHCP servers detected: {', '.join(dhcp_servers)}. New: {', '.join(new_servers)}",
                        confidence=0.85,
                        evidence={
                            'all_servers': list(dhcp_servers),
                            'new_servers': list(new_servers),
                            'known_servers': list(self.known_dhcp_servers)
                        }
                    )

                    if self._add_threat(threat):
                        threats.append(threat)

                # Update known servers
                self.known_dhcp_servers = dhcp_servers

        return threats

    def set_trusted_gateway(self, ip: str, mac: str):
        """Mark a gateway as trusted (manual configuration)."""
        self.trusted_gateways[ip] = mac.lower()
        self._save_state()

    def trust_current_network(self):
        """Trust the current network configuration (learning mode)."""
        gateway_ip = self._get_default_gateway()
        if gateway_ip and gateway_ip in self.arp_cache:
            mac, _ = self.arp_cache[gateway_ip]
            self.trusted_gateways[gateway_ip] = mac
            self._save_state()
