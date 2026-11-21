#!/usr/bin/env python3
"""
HookProbe Guardian - Evil Twin AP Detector

Detects rogue access points that impersonate legitimate WiFi networks.
Uses RF scanning to identify duplicate SSIDs, security downgrades,
and signal anomalies that indicate evil twin attacks.

Detection heuristics:
1. Duplicate SSID on different BSSIDs
2. Security downgrade (WPA3->WPA2, WPA2->Open)
3. Signal anomaly (known BSSID with different signal strength)
4. New BSSID appearing for known/connected SSID

Usage:
    from products.guardian.lib.evil_twin_detector import EvilTwinDetector

    detector = EvilTwinDetector()
    alerts = detector.scan()
    for alert in alerts:
        print(f"Evil twin: {alert.ssid} on {alert.bssid} ({alert.reason})")
"""

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Set

logger = logging.getLogger(__name__)

TRUSTED_NETWORKS_FILE = Path('/etc/hookprobe/trusted_networks.json')

# Signal strength deviation threshold (dB) to flag anomaly
SIGNAL_DEVIATION_THRESHOLD = 20

# Security level ordering (higher = more secure)
SECURITY_LEVELS = {
    'open': 0,
    'wep': 1,
    'wpa': 2,
    'wpa2': 3,
    'wpa2/wpa3': 4,
    'wpa3': 5,
}


class AlertSeverity(Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class EvilTwinAlert:
    """An evil twin detection alert."""
    ssid: str
    bssid: str
    channel: int
    signal_strength: int
    reason: str
    severity: AlertSeverity
    details: str = ''
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            'ssid': self.ssid,
            'bssid': self.bssid,
            'channel': self.channel,
            'signal_strength': self.signal_strength,
            'reason': self.reason,
            'severity': self.severity.value,
            'details': self.details,
            'timestamp': self.timestamp,
        }


@dataclass
class TrustedNetwork:
    """A known trusted WiFi network."""
    ssid: str
    bssid: str
    security: str
    signal_strength: int  # typical signal when connected
    last_seen: float


class EvilTwinDetector:
    """Detects evil twin access points via RF scanning.

    Compares current WiFi environment against trusted network database
    to detect rogue APs impersonating known networks.
    """

    def __init__(self, wan_interface: str = 'wlan0'):
        self.wan_interface = wan_interface
        self.trusted: Dict[str, List[TrustedNetwork]] = {}  # ssid -> [trusted networks]
        self._load_trusted_networks()

    def scan(self) -> List[EvilTwinAlert]:
        """Scan WiFi environment and check for evil twin APs.

        Returns list of EvilTwinAlert for any suspicious APs detected.
        """
        alerts = []

        try:
            from shared.wireless.channel_scanner import WiFiChannelScanner
        except ImportError:
            logger.warning("WiFiChannelScanner not available, skipping evil twin scan")
            return alerts

        scanner = WiFiChannelScanner(interface=self.wan_interface)
        result = scanner.scan()

        if result.error:
            logger.warning("WiFi scan failed: %s", result.error)
            return alerts

        if not result.networks:
            logger.debug("No networks found in scan")
            return alerts

        # Group scanned networks by SSID
        ssid_groups: Dict[str, list] = {}
        for net in result.networks:
            if net.ssid:  # skip hidden SSIDs
                ssid_groups.setdefault(net.ssid, []).append(net)

        # Check each SSID group for evil twin indicators
        for ssid, networks in ssid_groups.items():
            # Check 1: Duplicate SSID on multiple BSSIDs
            if len(networks) > 1:
                alerts.extend(self._check_duplicate_ssid(ssid, networks))

            # Check 2: Security downgrade from trusted
            if ssid in self.trusted:
                alerts.extend(self._check_security_downgrade(ssid, networks))

            # Check 3: Signal anomaly for known BSSIDs
            if ssid in self.trusted:
                alerts.extend(self._check_signal_anomaly(ssid, networks))

            # Check 4: New BSSID for connected SSID
            alerts.extend(self._check_new_bssid(ssid, networks))

        if alerts:
            logger.warning("Evil twin scan: %d alert(s) detected", len(alerts))
        else:
            logger.debug("Evil twin scan: clean (%d SSIDs checked)", len(ssid_groups))

        return alerts

    def record_trusted(self, ssid: str, bssid: str, security: str, signal: int):
        """Record a trusted network (call after successful connection)."""
        net = TrustedNetwork(
            ssid=ssid, bssid=bssid.lower(), security=self._normalize_security(security),
            signal_strength=signal, last_seen=time.time()
        )
        if ssid not in self.trusted:
            self.trusted[ssid] = []

        # Update existing or add new
        for i, existing in enumerate(self.trusted[ssid]):
            if existing.bssid == net.bssid:
                self.trusted[ssid][i] = net
                self._save_trusted_networks()
                return
        self.trusted[ssid].append(net)
        self._save_trusted_networks()
        logger.info("Recorded trusted network: %s (%s)", ssid, bssid)

    def _check_duplicate_ssid(self, ssid: str, networks: list) -> List[EvilTwinAlert]:
        """Check for duplicate SSIDs on different BSSIDs."""
        alerts = []

        # Only alert if one has significantly different security
        security_set = set()
        for net in networks:
            sec = self._normalize_security(net.security)
            security_set.add(sec)

        if len(security_set) > 1 and 'open' in security_set:
            # Mixed security with an open network = suspicious
            for net in networks:
                if self._normalize_security(net.security) == 'open':
                    alerts.append(EvilTwinAlert(
                        ssid=ssid, bssid=net.bssid, channel=net.channel,
                        signal_strength=net.signal_strength,
                        reason='open_duplicate',
                        severity=AlertSeverity.HIGH,
                        details=f"Open AP with same SSID as encrypted network ({len(networks)} BSSIDs total)",
                    ))
        return alerts

    def _check_security_downgrade(self, ssid: str, networks: list) -> List[EvilTwinAlert]:
        """Check if a known network appears with weaker security."""
        alerts = []
        trusted_nets = self.trusted.get(ssid, [])
        if not trusted_nets:
            return alerts

        # Get the highest security level from trusted
        max_trusted_level = max(
            SECURITY_LEVELS.get(t.security, 0) for t in trusted_nets
        )

        for net in networks:
            net_sec = self._normalize_security(net.security)
            net_level = SECURITY_LEVELS.get(net_sec, 0)

            # Alert if security is lower than trusted
            if net_level < max_trusted_level and net.bssid.lower() not in {t.bssid for t in trusted_nets}:
                alerts.append(EvilTwinAlert(
                    ssid=ssid, bssid=net.bssid, channel=net.channel,
                    signal_strength=net.signal_strength,
                    reason='security_downgrade',
                    severity=AlertSeverity.CRITICAL,
                    details=f"Security downgrade: trusted={max_trusted_level} scanned={net_sec} ({net_level})",
                ))
        return alerts

    def _check_signal_anomaly(self, ssid: str, networks: list) -> List[EvilTwinAlert]:
        """Check for signal strength anomalies on known BSSIDs."""
        alerts = []
        trusted_nets = {t.bssid: t for t in self.trusted.get(ssid, [])}

        for net in networks:
            bssid = net.bssid.lower()
            if bssid in trusted_nets:
                trusted = trusted_nets[bssid]
                deviation = abs(net.signal_strength - trusted.signal_strength)
                if deviation > SIGNAL_DEVIATION_THRESHOLD:
                    alerts.append(EvilTwinAlert(
                        ssid=ssid, bssid=net.bssid, channel=net.channel,
                        signal_strength=net.signal_strength,
                        reason='signal_anomaly',
                        severity=AlertSeverity.MEDIUM,
                        details=f"Signal deviation: expected ~{trusted.signal_strength}dBm, got {net.signal_strength}dBm (delta={deviation}dB)",
                    ))
        return alerts

    def _check_new_bssid(self, ssid: str, networks: list) -> List[EvilTwinAlert]:
        """Check for new BSSIDs appearing for a trusted SSID."""
        alerts = []
        trusted_nets = self.trusted.get(ssid)
        if not trusted_nets:
            return alerts

        known_bssids = {t.bssid for t in trusted_nets}

        for net in networks:
            bssid = net.bssid.lower()
            if bssid not in known_bssids:
                alerts.append(EvilTwinAlert(
                    ssid=ssid, bssid=net.bssid, channel=net.channel,
                    signal_strength=net.signal_strength,
                    reason='new_bssid',
                    severity=AlertSeverity.LOW,
                    details=f"Unknown BSSID for trusted SSID (known: {len(known_bssids)} BSSIDs)",
                ))
        return alerts

    def _normalize_security(self, security: str) -> str:
        """Normalize security string to a standard form."""
        sec = security.lower().strip()
        if 'wpa3' in sec:
            if 'wpa2' in sec:
                return 'wpa2/wpa3'
            return 'wpa3'
        if 'wpa2' in sec:
            return 'wpa2'
        if 'wpa' in sec:
            return 'wpa'
        if 'wep' in sec:
            return 'wep'
        return 'open'

    def _load_trusted_networks(self):
        """Load trusted networks from JSON file."""
        if not TRUSTED_NETWORKS_FILE.exists():
            return

        try:
            data = json.loads(TRUSTED_NETWORKS_FILE.read_text())
            for ssid, nets in data.items():
                self.trusted[ssid] = [
                    TrustedNetwork(
                        ssid=ssid,
                        bssid=n['bssid'],
                        security=n['security'],
                        signal_strength=n.get('signal_strength', -60),
                        last_seen=n.get('last_seen', 0),
                    )
                    for n in nets
                ]
            logger.debug("Loaded %d trusted SSIDs", len(self.trusted))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to load trusted networks: %s", e)

    def _save_trusted_networks(self):
        """Save trusted networks to JSON file."""
        data = {}
        for ssid, nets in self.trusted.items():
            data[ssid] = [
                {
                    'bssid': n.bssid,
                    'security': n.security,
                    'signal_strength': n.signal_strength,
                    'last_seen': n.last_seen,
                }
                for n in nets
            ]
        try:
            TRUSTED_NETWORKS_FILE.parent.mkdir(parents=True, exist_ok=True)
            TRUSTED_NETWORKS_FILE.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.warning("Failed to save trusted networks: %s", e)
