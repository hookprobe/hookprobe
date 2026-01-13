"""
AIOCHI POS Protection Mode
Critical Asset Protection for Small Business Payment Systems.

Philosophy: A flower shop's credit card terminal deserves the same protection
as an enterprise POS system. Every card swipe should be secure.

Features:
- Critical Asset tagging (POS, payment terminals, cash registers)
- PCI-DSS aware traffic monitoring
- Card data exfiltration detection
- Payment network isolation
- Suspicious connection alerts
- Automatic quarantine for compromised terminals
"""

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class AssetType(Enum):
    """Types of critical assets."""
    POS_TERMINAL = "pos_terminal"         # Credit card terminals (Square, Clover)
    PAYMENT_GATEWAY = "payment_gateway"   # Payment processing systems
    CASH_REGISTER = "cash_register"       # Cash register with integrated payments
    INVENTORY_SYSTEM = "inventory_system" # Inventory management
    CUSTOMER_DATABASE = "customer_db"     # Customer data storage
    ACCOUNTING = "accounting"             # QuickBooks, etc.
    SECURITY_CAMERA = "security_camera"   # Physical security cameras


class ThreatLevel(Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProtectionStatus(Enum):
    """Protection status for an asset."""
    PROTECTED = "protected"       # All checks pass
    MONITORING = "monitoring"     # Potential issue detected
    ALERT = "alert"               # Active threat detected
    QUARANTINED = "quarantined"   # Isolated due to compromise


@dataclass
class CriticalAsset:
    """A critical business asset."""
    mac: str
    name: str                      # Human label: "Main POS Terminal"
    asset_type: AssetType
    ip_address: str = ""
    vendor: str = ""               # "Square", "Clover", "Verifone"
    vlan_id: int = 0               # Dedicated VLAN for PCI compliance
    protection_status: ProtectionStatus = ProtectionStatus.PROTECTED
    allowed_destinations: Set[str] = field(default_factory=set)  # Whitelisted IPs/domains
    last_activity: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "name": self.name,
            "asset_type": self.asset_type.value,
            "ip_address": self.ip_address,
            "vendor": self.vendor,
            "vlan_id": self.vlan_id,
            "protection_status": self.protection_status.value,
            "allowed_destinations": list(self.allowed_destinations),
            "last_activity": self.last_activity.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "notes": self.notes,
        }


@dataclass
class POSAlert:
    """Security alert for POS system."""
    id: str
    timestamp: datetime
    asset_mac: str
    asset_name: str
    threat_level: ThreatLevel
    threat_type: str              # "card_data_exfil", "unauthorized_connection", etc.
    headline: str                 # Human-readable headline
    description: str              # Detailed description
    evidence: Dict[str, Any] = field(default_factory=dict)
    action_taken: str = ""
    resolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "asset_mac": self.asset_mac,
            "asset_name": self.asset_name,
            "threat_level": self.threat_level.value,
            "threat_type": self.threat_type,
            "headline": self.headline,
            "description": self.description,
            "evidence": self.evidence,
            "action_taken": self.action_taken,
            "resolved": self.resolved,
        }


# Known POS/Payment vendor OUI prefixes
POS_VENDOR_OUIS = {
    # Square
    "74:75:48": "Square",
    "00:E0:04": "Square",
    # Clover
    "98:DA:C4": "Clover",
    "00:24:E4": "Clover",
    # Verifone
    "00:0D:F0": "Verifone",
    "00:17:7C": "Verifone",
    # Ingenico
    "00:07:81": "Ingenico",
    "B8:2A:DC": "Ingenico",
    # PAX Technology
    "F4:B5:49": "PAX",
    # Dejavoo
    "84:25:3F": "Dejavoo",
    # NCR
    "00:00:74": "NCR",
    "00:06:69": "NCR",
}

# Allowed payment processor destinations (whitelist for POS traffic)
PAYMENT_PROCESSOR_DOMAINS = {
    # Square
    "square.com", "squareup.com", "squarecdn.com",
    # Stripe
    "stripe.com", "stripe.network",
    # PayPal / Braintree
    "paypal.com", "braintreegateway.com", "braintreepayments.com",
    # Heartland
    "heartlandpaymentsystems.com", "e-hps.com",
    # First Data / Fiserv
    "firstdata.com", "fiserv.com",
    # Chase Paymentech
    "chase.com", "jpmorgan.com",
    # Worldpay
    "worldpay.com", "fisglobal.com",
    # Elavon
    "elavon.com",
    # TSYS
    "tsys.com", "transfirst.com",
}

# Suspicious patterns for card data exfiltration
CARD_DATA_PATTERNS = [
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b',           # Visa
    r'\b(?:5[1-5][0-9]{14})\b',                    # Mastercard
    r'\b(?:3[47][0-9]{13})\b',                     # Amex
    r'\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b',        # Discover
    r'\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b',     # Diners
]

# Suspicious destination indicators
SUSPICIOUS_INDICATORS = {
    "tor_exit": [".onion", "torproject.org"],
    "known_bad_tlds": [".xyz", ".top", ".tk", ".pw", ".cc", ".su"],
    "data_exfil_ports": [21, 22, 23, 25, 69, 445, 1433, 3306, 5432, 6379],
    "crypto_mining_pools": ["pool.", "mining.", "miner.", "stratum+tcp://"],
}


class POSProtectionManager:
    """
    POS Protection Mode Manager.

    Features:
    - Critical asset registry
    - Payment traffic monitoring
    - Suspicious activity detection
    - Automatic quarantine
    - PCI-DSS compliance helpers
    """

    OVS_BRIDGE = "FTS"
    POS_VLAN = 125  # Dedicated VLAN for POS devices

    def __init__(
        self,
        config_path: str = "/etc/hookprobe/pos-protection.json",
        use_ovs: bool = True,
    ):
        """
        Initialize POS Protection Manager.

        Args:
            config_path: Path to configuration file
            use_ovs: Enable OVS network rules
        """
        self.config_path = config_path
        self.use_ovs = use_ovs

        # Critical assets registry
        self._assets: Dict[str, CriticalAsset] = {}

        # Alert history
        self._alerts: List[POSAlert] = []
        self._max_alerts = 1000

        # Load saved configuration
        self._load_config()

        logger.info(f"POS Protection initialized with {len(self._assets)} assets")

    # =========================================================================
    # Asset Management
    # =========================================================================

    def register_asset(
        self,
        mac: str,
        name: str,
        asset_type: AssetType,
        vendor: str = "",
        notes: str = "",
    ) -> CriticalAsset:
        """
        Register a new critical asset.

        Args:
            mac: Device MAC address
            name: Human-friendly name
            asset_type: Type of asset
            vendor: Vendor name (auto-detected if empty)
            notes: Optional notes

        Returns:
            Registered CriticalAsset
        """
        mac = self._normalize_mac(mac)

        # Auto-detect vendor from OUI
        if not vendor:
            vendor = self._detect_pos_vendor(mac)

        asset = CriticalAsset(
            mac=mac,
            name=name,
            asset_type=asset_type,
            vendor=vendor,
            vlan_id=self.POS_VLAN if asset_type in [AssetType.POS_TERMINAL, AssetType.PAYMENT_GATEWAY] else 0,
            notes=notes,
        )

        self._assets[mac] = asset

        # Apply protection rules
        self._apply_asset_protection(asset)

        # Save config
        self._save_config()

        logger.info(f"Registered critical asset: {name} ({mac}) - {asset_type.value}")

        return asset

    def unregister_asset(self, mac: str) -> bool:
        """Remove an asset from protection."""
        mac = self._normalize_mac(mac)

        if mac not in self._assets:
            return False

        asset = self._assets[mac]

        # Remove protection rules
        self._remove_asset_protection(asset)

        del self._assets[mac]
        self._save_config()

        logger.info(f"Unregistered asset: {asset.name} ({mac})")
        return True

    def get_asset(self, mac: str) -> Optional[CriticalAsset]:
        """Get an asset by MAC address."""
        return self._assets.get(self._normalize_mac(mac))

    def get_all_assets(self) -> List[CriticalAsset]:
        """Get all registered assets."""
        return list(self._assets.values())

    def update_asset_status(
        self,
        mac: str,
        status: ProtectionStatus,
        reason: str = "",
    ) -> bool:
        """Update protection status for an asset."""
        mac = self._normalize_mac(mac)
        asset = self._assets.get(mac)

        if not asset:
            return False

        old_status = asset.protection_status
        asset.protection_status = status

        if status == ProtectionStatus.QUARANTINED:
            self._quarantine_asset(asset, reason)
        elif old_status == ProtectionStatus.QUARANTINED:
            self._release_from_quarantine(asset)

        self._save_config()
        return True

    def is_critical_asset(self, mac: str) -> bool:
        """Check if a MAC belongs to a critical asset."""
        return self._normalize_mac(mac) in self._assets

    def auto_detect_pos_devices(self) -> List[Dict[str, Any]]:
        """
        Scan network for potential POS devices.

        Returns:
            List of detected potential POS devices
        """
        detected = []

        # Get all connected devices from ARP table
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) >= 5 and "lladdr" in parts:
                        ip = parts[0]
                        mac_idx = parts.index("lladdr") + 1
                        if mac_idx < len(parts):
                            mac = self._normalize_mac(parts[mac_idx])

                            # Check if this looks like a POS device
                            vendor = self._detect_pos_vendor(mac)
                            if vendor:
                                detected.append({
                                    "mac": mac,
                                    "ip": ip,
                                    "vendor": vendor,
                                    "suggested_type": AssetType.POS_TERMINAL.value,
                                    "already_registered": mac in self._assets,
                                })

        except Exception as e:
            logger.error(f"Auto-detection failed: {e}")

        return detected

    # =========================================================================
    # Threat Detection
    # =========================================================================

    def analyze_connection(
        self,
        src_mac: str,
        dst_ip: str,
        dst_port: int,
        dst_domain: str = "",
        payload_sample: bytes = b"",
    ) -> Optional[POSAlert]:
        """
        Analyze a connection from a critical asset.

        Args:
            src_mac: Source MAC address
            dst_ip: Destination IP
            dst_port: Destination port
            dst_domain: Destination domain (if resolved)
            payload_sample: Sample of payload data (for pattern detection)

        Returns:
            POSAlert if suspicious, None otherwise
        """
        src_mac = self._normalize_mac(src_mac)
        asset = self._assets.get(src_mac)

        if not asset:
            return None  # Not a critical asset

        # Update last activity
        asset.last_activity = datetime.now()

        # Check for suspicious patterns
        alert = None

        # 1. Check for unauthorized destination
        if dst_domain and not self._is_allowed_destination(asset, dst_domain):
            alert = self._create_alert(
                asset=asset,
                threat_level=ThreatLevel.MEDIUM,
                threat_type="unauthorized_destination",
                headline=f"{asset.name} connecting to unexpected destination",
                description=f"POS terminal attempting to connect to {dst_domain} ({dst_ip}:{dst_port}), "
                           f"which is not in the allowed payment processor list.",
                evidence={"dst_domain": dst_domain, "dst_ip": dst_ip, "dst_port": dst_port},
            )

        # 2. Check for suspicious ports
        if dst_port in SUSPICIOUS_INDICATORS["data_exfil_ports"]:
            alert = self._create_alert(
                asset=asset,
                threat_level=ThreatLevel.HIGH,
                threat_type="suspicious_port",
                headline=f"{asset.name} using suspicious port {dst_port}",
                description=f"POS terminal connecting to {dst_ip} on port {dst_port}, "
                           f"which is commonly used for data exfiltration.",
                evidence={"dst_ip": dst_ip, "dst_port": dst_port},
            )

        # 3. Check for suspicious TLDs
        if dst_domain:
            for tld in SUSPICIOUS_INDICATORS["known_bad_tlds"]:
                if dst_domain.endswith(tld):
                    alert = self._create_alert(
                        asset=asset,
                        threat_level=ThreatLevel.HIGH,
                        threat_type="suspicious_tld",
                        headline=f"{asset.name} connecting to suspicious domain",
                        description=f"POS terminal attempting to connect to {dst_domain}, "
                                   f"which uses a TLD commonly associated with malicious activity.",
                        evidence={"dst_domain": dst_domain},
                    )
                    break

        # 4. Check payload for card data patterns (only if we have payload)
        if payload_sample:
            for pattern in CARD_DATA_PATTERNS:
                if re.search(pattern, payload_sample.decode('utf-8', errors='ignore')):
                    alert = self._create_alert(
                        asset=asset,
                        threat_level=ThreatLevel.CRITICAL,
                        threat_type="card_data_exfil",
                        headline=f"CRITICAL: Card data detected in traffic from {asset.name}",
                        description=f"Payment card data patterns detected in outbound traffic. "
                                   f"This may indicate a POS malware infection or data breach. "
                                   f"Device has been quarantined.",
                        evidence={"dst_ip": dst_ip, "dst_port": dst_port},
                    )
                    # Auto-quarantine on card data detection
                    self.update_asset_status(asset.mac, ProtectionStatus.QUARANTINED, "Card data exfiltration detected")
                    break

        if alert:
            self._alerts.append(alert)
            if len(self._alerts) > self._max_alerts:
                self._alerts.pop(0)

        return alert

    def analyze_dns_query(
        self,
        src_mac: str,
        domain: str,
    ) -> Optional[POSAlert]:
        """
        Analyze DNS query from a critical asset.

        Args:
            src_mac: Source MAC address
            domain: Domain being queried

        Returns:
            POSAlert if suspicious, None otherwise
        """
        src_mac = self._normalize_mac(src_mac)
        asset = self._assets.get(src_mac)

        if not asset:
            return None

        # Check for DGA-like domains (long random-looking strings)
        domain_parts = domain.split('.')
        for part in domain_parts[:-1]:  # Skip TLD
            if len(part) > 15 and self._looks_random(part):
                alert = self._create_alert(
                    asset=asset,
                    threat_level=ThreatLevel.HIGH,
                    threat_type="dga_domain",
                    headline=f"{asset.name} querying suspicious domain",
                    description=f"POS terminal queried {domain}, which appears to be "
                               f"a domain generation algorithm (DGA) domain commonly used by malware.",
                    evidence={"domain": domain},
                )
                self._alerts.append(alert)
                return alert

        return None

    def _looks_random(self, s: str) -> bool:
        """Check if a string looks randomly generated."""
        # High consonant ratio suggests randomness
        consonants = sum(1 for c in s.lower() if c in 'bcdfghjklmnpqrstvwxyz')
        vowels = sum(1 for c in s.lower() if c in 'aeiou')

        if len(s) < 5:
            return False

        # High ratio of consonants to vowels
        if vowels > 0 and consonants / vowels > 4:
            return True

        # Many digit-letter transitions
        transitions = sum(1 for i in range(len(s)-1) if s[i].isdigit() != s[i+1].isdigit())
        if transitions > 3:
            return True

        return False

    def _is_allowed_destination(self, asset: CriticalAsset, domain: str) -> bool:
        """Check if a destination is allowed for this asset."""
        # Check custom whitelist
        for allowed in asset.allowed_destinations:
            if domain.endswith(allowed):
                return True

        # Check payment processor whitelist
        for processor_domain in PAYMENT_PROCESSOR_DOMAINS:
            if domain.endswith(processor_domain):
                return True

        return False

    # =========================================================================
    # Network Protection
    # =========================================================================

    def _apply_asset_protection(self, asset: CriticalAsset) -> None:
        """Apply network protection rules for an asset."""
        if not self.use_ovs:
            logger.info(f"[DRY RUN] Would apply protection for {asset.mac}")
            return

        # Move to POS VLAN
        if asset.vlan_id > 0:
            try:
                # Tag traffic from this MAC with POS VLAN
                cmd = [
                    "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                    f"priority=200,dl_src={asset.mac},actions=mod_vlan_vid:{asset.vlan_id},NORMAL"
                ]
                subprocess.run(cmd, capture_output=True, timeout=5)

                logger.info(f"Applied VLAN {asset.vlan_id} for {asset.name}")
            except Exception as e:
                logger.error(f"Failed to apply VLAN for {asset.name}: {e}")

        # Add traffic monitoring rule (mirror to Suricata)
        try:
            cmd = [
                "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                f"priority=150,dl_src={asset.mac},actions=NORMAL,output:FTS-mirror"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception as e:
            logger.debug(f"Mirror rule failed (mirror port may not exist): {e}")

    def _remove_asset_protection(self, asset: CriticalAsset) -> None:
        """Remove network protection rules for an asset."""
        if not self.use_ovs:
            return

        try:
            # Remove VLAN tagging rule
            cmd = [
                "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                f"dl_src={asset.mac}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)
            logger.info(f"Removed protection rules for {asset.name}")
        except Exception as e:
            logger.error(f"Failed to remove rules for {asset.name}: {e}")

    def _quarantine_asset(self, asset: CriticalAsset, reason: str) -> None:
        """Quarantine a compromised asset."""
        logger.warning(f"QUARANTINING {asset.name} ({asset.mac}): {reason}")

        if not self.use_ovs:
            logger.info(f"[DRY RUN] Would quarantine {asset.mac}")
            return

        try:
            # Drop all traffic from this MAC
            cmd = [
                "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                f"priority=1000,dl_src={asset.mac},actions=drop"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            # Also drop traffic TO this MAC
            cmd = [
                "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                f"priority=1000,dl_dst={asset.mac},actions=drop"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            logger.warning(f"Asset {asset.name} has been isolated from network")

            # Create critical alert
            alert = self._create_alert(
                asset=asset,
                threat_level=ThreatLevel.CRITICAL,
                threat_type="quarantine",
                headline=f"CRITICAL: {asset.name} has been quarantined",
                description=f"The POS terminal has been isolated from the network due to: {reason}. "
                           f"All traffic to and from this device is being blocked.",
                evidence={"reason": reason},
            )
            alert.action_taken = "Device quarantined (network isolated)"
            self._alerts.append(alert)

        except Exception as e:
            logger.error(f"Failed to quarantine {asset.name}: {e}")

    def _release_from_quarantine(self, asset: CriticalAsset) -> None:
        """Release an asset from quarantine."""
        logger.info(f"Releasing {asset.name} ({asset.mac}) from quarantine")

        if not self.use_ovs:
            return

        try:
            # Remove drop rules
            cmd = [
                "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                f"priority=1000,dl_src={asset.mac}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            cmd = [
                "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                f"priority=1000,dl_dst={asset.mac}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            # Reapply normal protection
            self._apply_asset_protection(asset)

            logger.info(f"Asset {asset.name} released from quarantine")

        except Exception as e:
            logger.error(f"Failed to release {asset.name}: {e}")

    # =========================================================================
    # Alerts
    # =========================================================================

    def get_alerts(
        self,
        hours: int = 24,
        threat_level: Optional[ThreatLevel] = None,
        resolved: Optional[bool] = None,
    ) -> List[POSAlert]:
        """Get recent alerts."""
        cutoff = datetime.now() - timedelta(hours=hours)

        alerts = [a for a in self._alerts if a.timestamp > cutoff]

        if threat_level:
            alerts = [a for a in alerts if a.threat_level == threat_level]

        if resolved is not None:
            alerts = [a for a in alerts if a.resolved == resolved]

        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)

    def resolve_alert(self, alert_id: str, notes: str = "") -> bool:
        """Mark an alert as resolved."""
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.resolved = True
                if notes:
                    alert.action_taken = notes
                return True
        return False

    def _create_alert(
        self,
        asset: CriticalAsset,
        threat_level: ThreatLevel,
        threat_type: str,
        headline: str,
        description: str,
        evidence: Dict[str, Any],
    ) -> POSAlert:
        """Create a new alert."""
        import uuid

        return POSAlert(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            asset_mac=asset.mac,
            asset_name=asset.name,
            threat_level=threat_level,
            threat_type=threat_type,
            headline=headline,
            description=description,
            evidence=evidence,
        )

    # =========================================================================
    # Utilities
    # =========================================================================

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format."""
        return mac.upper().replace("-", ":")

    def _detect_pos_vendor(self, mac: str) -> str:
        """Detect POS vendor from MAC OUI."""
        mac = self._normalize_mac(mac)
        oui = mac[:8]
        return POS_VENDOR_OUIS.get(oui, "")

    def _load_config(self) -> None:
        """Load saved configuration."""
        if not os.path.exists(self.config_path):
            return

        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)

            for asset_data in data.get("assets", []):
                mac = asset_data.get("mac")
                if mac:
                    self._assets[mac] = CriticalAsset(
                        mac=mac,
                        name=asset_data.get("name", "Unknown"),
                        asset_type=AssetType(asset_data.get("asset_type", "pos_terminal")),
                        ip_address=asset_data.get("ip_address", ""),
                        vendor=asset_data.get("vendor", ""),
                        vlan_id=asset_data.get("vlan_id", 0),
                        protection_status=ProtectionStatus(asset_data.get("protection_status", "protected")),
                        allowed_destinations=set(asset_data.get("allowed_destinations", [])),
                        notes=asset_data.get("notes", ""),
                    )

            logger.info(f"Loaded {len(self._assets)} assets from config")

        except Exception as e:
            logger.error(f"Failed to load config: {e}")

    def _save_config(self) -> None:
        """Save current configuration."""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)

            data = {
                "version": "1.0",
                "updated": datetime.now().isoformat(),
                "assets": [asset.to_dict() for asset in self._assets.values()],
            }

            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """Get POS protection summary for dashboard."""
        assets = list(self._assets.values())
        recent_alerts = self.get_alerts(hours=24)

        return {
            "enabled": True,
            "total_assets": len(assets),
            "protected": sum(1 for a in assets if a.protection_status == ProtectionStatus.PROTECTED),
            "monitoring": sum(1 for a in assets if a.protection_status == ProtectionStatus.MONITORING),
            "quarantined": sum(1 for a in assets if a.protection_status == ProtectionStatus.QUARANTINED),
            "alerts_24h": len(recent_alerts),
            "critical_alerts": sum(1 for a in recent_alerts if a.threat_level == ThreatLevel.CRITICAL),
            "assets": [a.to_dict() for a in assets],
        }


# Singleton instance
_pos_manager: Optional[POSProtectionManager] = None


def get_pos_protection_manager(use_ovs: bool = True) -> POSProtectionManager:
    """Get or create the singleton POS Protection Manager."""
    global _pos_manager

    if _pos_manager is None:
        _pos_manager = POSProtectionManager(use_ovs=use_ovs)

    return _pos_manager


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    manager = POSProtectionManager(use_ovs=False)

    # Auto-detect POS devices
    print("Scanning for POS devices...")
    detected = manager.auto_detect_pos_devices()
    for d in detected:
        print(f"  Found: {d['vendor']} at {d['mac']} ({d['ip']})")

    # Register a test asset
    asset = manager.register_asset(
        mac="98:DA:C4:00:11:22",
        name="Front Counter POS",
        asset_type=AssetType.POS_TERMINAL,
        notes="Main checkout terminal",
    )

    print(f"\nRegistered: {asset.name}")
    print(f"  Vendor: {asset.vendor}")
    print(f"  VLAN: {asset.vlan_id}")
    print(f"  Status: {asset.protection_status.value}")

    # Simulate suspicious connection
    print("\nAnalyzing suspicious connection...")
    alert = manager.analyze_connection(
        src_mac="98:DA:C4:00:11:22",
        dst_ip="185.220.101.1",
        dst_port=6379,
        dst_domain="suspicious.xyz",
    )

    if alert:
        print(f"  ALERT: {alert.headline}")
        print(f"  Level: {alert.threat_level.value}")

    # Summary
    print(f"\nSummary: {manager.get_summary()}")
