"""
AIOCHI Identity Engine
Transforms raw device fingerprints into human-readable identities.

This engine watches for new devices and events, pulls fingerprint data,
and enriches devices with human labels and ecosystem bubbles.

The goal: Turn "AA:BB:CC:DD:EE:FF" into "Dad's iPhone 15 Pro"
"""

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class Ecosystem(Enum):
    """Device ecosystem types for bubble grouping."""
    APPLE = "apple"
    GOOGLE = "google"
    AMAZON = "amazon"
    SAMSUNG = "samsung"
    MICROSOFT = "microsoft"
    UNKNOWN = "unknown"


class TrustLevel(Enum):
    """Device trust levels (from Device Trust Framework)."""
    L0_UNTRUSTED = 0   # Unknown device, quarantine
    L1_MINIMAL = 1     # MAC only, guest access
    L2_STANDARD = 2    # MAC + OUI + behavior
    L3_HIGH = 3        # MAC + attestation
    L4_ENTERPRISE = 4  # MAC + TPM + Neuro


@dataclass
class DeviceIdentity:
    """Human-readable device identity."""
    mac: str
    human_label: str = ""           # "Dad's iPhone"
    device_type: str = ""           # "iPhone 15 Pro"
    vendor: str = ""                # "Apple"
    ecosystem: Ecosystem = Ecosystem.UNKNOWN
    bubble_id: str = ""             # "family_dad"
    trust_level: TrustLevel = TrustLevel.L0_UNTRUSTED
    confidence: float = 0.0         # 0.0 - 1.0
    fingerprint_hash: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    hostname: str = ""
    ip_address: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON/ClickHouse storage."""
        return {
            "mac": self.mac,
            "human_label": self.human_label,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "ecosystem": self.ecosystem.value,
            "bubble_id": self.bubble_id,
            "trust_level": self.trust_level.value,
            "confidence": self.confidence,
            "fingerprint_hash": self.fingerprint_hash,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceIdentity":
        """Create from dictionary."""
        return cls(
            mac=data.get("mac", ""),
            human_label=data.get("human_label", ""),
            device_type=data.get("device_type", ""),
            vendor=data.get("vendor", ""),
            ecosystem=Ecosystem(data.get("ecosystem", "unknown")),
            bubble_id=data.get("bubble_id", ""),
            trust_level=TrustLevel(data.get("trust_level", 0)),
            confidence=data.get("confidence", 0.0),
            fingerprint_hash=data.get("fingerprint_hash", ""),
            first_seen=datetime.fromisoformat(data["first_seen"]) if data.get("first_seen") else None,
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
            hostname=data.get("hostname", ""),
            ip_address=data.get("ip_address", ""),
        )


# Common device type patterns for fast matching
DEVICE_PATTERNS = {
    # Apple devices
    r"(?i)iphone": ("iPhone", "Apple", Ecosystem.APPLE),
    r"(?i)ipad": ("iPad", "Apple", Ecosystem.APPLE),
    r"(?i)macbook": ("MacBook", "Apple", Ecosystem.APPLE),
    r"(?i)imac": ("iMac", "Apple", Ecosystem.APPLE),
    r"(?i)apple.*watch": ("Apple Watch", "Apple", Ecosystem.APPLE),
    r"(?i)apple.*tv": ("Apple TV", "Apple", Ecosystem.APPLE),
    r"(?i)homepod": ("HomePod", "Apple", Ecosystem.APPLE),
    r"(?i)airpods": ("AirPods", "Apple", Ecosystem.APPLE),

    # Google devices
    r"(?i)pixel": ("Google Pixel", "Google", Ecosystem.GOOGLE),
    r"(?i)chromebook": ("Chromebook", "Google", Ecosystem.GOOGLE),
    r"(?i)nest": ("Nest Device", "Google", Ecosystem.GOOGLE),
    r"(?i)google.*home": ("Google Home", "Google", Ecosystem.GOOGLE),
    r"(?i)chromecast": ("Chromecast", "Google", Ecosystem.GOOGLE),

    # Amazon devices
    r"(?i)echo": ("Amazon Echo", "Amazon", Ecosystem.AMAZON),
    r"(?i)fire.*tv": ("Fire TV", "Amazon", Ecosystem.AMAZON),
    r"(?i)kindle": ("Kindle", "Amazon", Ecosystem.AMAZON),
    r"(?i)ring": ("Ring Device", "Amazon", Ecosystem.AMAZON),

    # Samsung devices
    r"(?i)galaxy": ("Samsung Galaxy", "Samsung", Ecosystem.SAMSUNG),
    r"(?i)samsung.*tv": ("Samsung TV", "Samsung", Ecosystem.SAMSUNG),
    r"(?i)smartthings": ("SmartThings Hub", "Samsung", Ecosystem.SAMSUNG),

    # Microsoft devices
    r"(?i)surface": ("Microsoft Surface", "Microsoft", Ecosystem.MICROSOFT),
    r"(?i)xbox": ("Xbox", "Microsoft", Ecosystem.MICROSOFT),

    # Generic devices
    r"(?i)android": ("Android Device", "Unknown", Ecosystem.GOOGLE),
    r"(?i)windows": ("Windows PC", "Unknown", Ecosystem.MICROSOFT),
    r"(?i)linux": ("Linux Device", "Unknown", Ecosystem.UNKNOWN),
    r"(?i)printer": ("Printer", "Unknown", Ecosystem.UNKNOWN),
    r"(?i)camera": ("Camera", "Unknown", Ecosystem.UNKNOWN),
    r"(?i)router": ("Router", "Unknown", Ecosystem.UNKNOWN),
    r"(?i)thermostat": ("Thermostat", "Unknown", Ecosystem.UNKNOWN),
}

# MAC OUI prefixes for vendor detection
OUI_PREFIXES = {
    # Apple
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:10:FA": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    # Google
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "94:EB:2C": "Google",
    "F4:F5:D8": "Google",
    "F4:F5:E8": "Google",
    # Samsung
    "00:00:F0": "Samsung",
    "00:02:78": "Samsung",
    "00:07:AB": "Samsung",
    "00:09:18": "Samsung",
    "00:0D:AE": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:15:B9": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:6C": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    # Amazon
    "00:FC:8B": "Amazon",
    "10:CE:A9": "Amazon",
    "18:74:2E": "Amazon",
    "34:D2:70": "Amazon",
    "38:F7:3D": "Amazon",
    "40:B4:CD": "Amazon",
    "44:65:0D": "Amazon",
    "50:DC:E7": "Amazon",
    "68:37:E9": "Amazon",
    "68:54:FD": "Amazon",
    # Microsoft
    "00:03:FF": "Microsoft",
    "00:0D:3A": "Microsoft",
    "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft",
    "00:17:FA": "Microsoft",
    "00:1D:D8": "Microsoft",
    "00:22:48": "Microsoft",
    "00:25:AE": "Microsoft",
    "00:50:F2": "Microsoft",
    "28:18:78": "Microsoft",
}


class IdentityEngine:
    """
    Transforms raw device fingerprints into human-readable identities.

    This engine:
    1. Watches for new devices (via ClickHouse or direct events)
    2. Pulls fingerprint data (DHCP, mDNS, hostname, OUI)
    3. Classifies device type and ecosystem
    4. Suggests human labels (which users can customize)
    5. Tracks device trust over time
    """

    def __init__(
        self,
        clickhouse_host: str = "localhost",
        clickhouse_port: int = 8123,
        clickhouse_db: str = "aiochi",
        clickhouse_user: str = "aiochi",
        clickhouse_password: str = "",
        use_fortress_fingerprint: bool = True,
    ):
        """
        Initialize the Identity Engine.

        Args:
            clickhouse_host: ClickHouse server hostname
            clickhouse_port: ClickHouse HTTP port
            clickhouse_db: Database name
            clickhouse_user: Username
            clickhouse_password: Password
            use_fortress_fingerprint: Use Fortress Unified Fingerprint Engine if available
        """
        self.clickhouse_host = clickhouse_host
        self.clickhouse_port = clickhouse_port
        self.clickhouse_db = clickhouse_db
        self.clickhouse_user = clickhouse_user
        self.clickhouse_password = clickhouse_password
        self.use_fortress_fingerprint = use_fortress_fingerprint

        # Local cache for fast lookups
        self._cache: Dict[str, DeviceIdentity] = {}
        self._cache_ttl = 300  # 5 minutes

        # Try to import Fortress fingerprint engine
        self._fortress_engine = None
        if use_fortress_fingerprint:
            try:
                from products.fortress.lib.unified_fingerprint_engine import (
                    UnifiedFingerprintEngine,
                )
                self._fortress_engine = UnifiedFingerprintEngine()
                logger.info("Using Fortress Unified Fingerprint Engine")
            except ImportError:
                logger.warning("Fortress fingerprint engine not available, using built-in")

    def enrich(
        self,
        mac: str,
        hostname: str = "",
        dhcp_options: Optional[List[int]] = None,
        mdns_services: Optional[List[str]] = None,
        ip_address: str = "",
        force_refresh: bool = False,
    ) -> DeviceIdentity:
        """
        Enrich a device with identity information.

        Args:
            mac: Device MAC address
            hostname: Device hostname (from DHCP or mDNS)
            dhcp_options: DHCP Option 55 values
            mdns_services: mDNS service types discovered
            ip_address: Device IP address
            force_refresh: Skip cache and re-fingerprint

        Returns:
            DeviceIdentity with human-readable information
        """
        mac = mac.upper().replace("-", ":")

        # Check cache
        if not force_refresh and mac in self._cache:
            cached = self._cache[mac]
            cached.last_seen = datetime.now()
            return cached

        # Start with basic identity
        identity = DeviceIdentity(
            mac=mac,
            hostname=hostname,
            ip_address=ip_address,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
        )

        # Use Fortress engine if available
        if self._fortress_engine:
            identity = self._enrich_via_fortress(identity, dhcp_options, mdns_services)
        else:
            identity = self._enrich_builtin(identity, dhcp_options, mdns_services)

        # Generate fingerprint hash
        identity.fingerprint_hash = self._generate_fingerprint_hash(identity)

        # Auto-generate human label if not set
        if not identity.human_label:
            identity.human_label = self._generate_human_label(identity)

        # Cache the result
        self._cache[mac] = identity

        # Persist to ClickHouse (async in production)
        self._persist_identity(identity)

        return identity

    def _enrich_via_fortress(
        self,
        identity: DeviceIdentity,
        dhcp_options: Optional[List[int]],
        mdns_services: Optional[List[str]],
    ) -> DeviceIdentity:
        """Use Fortress Unified Fingerprint Engine for enrichment."""
        try:
            result = self._fortress_engine.fingerprint(
                mac=identity.mac,
                hostname=identity.hostname,
                dhcp_options=dhcp_options or [],
                mdns_services=mdns_services or [],
            )

            identity.device_type = result.get("device_type", "")
            identity.vendor = result.get("vendor", "")
            identity.confidence = result.get("confidence", 0.0)

            # Map ecosystem
            ecosystem_str = result.get("ecosystem", "unknown").lower()
            identity.ecosystem = Ecosystem(ecosystem_str) if ecosystem_str in [e.value for e in Ecosystem] else Ecosystem.UNKNOWN

            # Map trust level
            trust = result.get("trust_level", 0)
            identity.trust_level = TrustLevel(min(trust, 4))

            # Get bubble ID from ecosystem bubble manager
            identity.bubble_id = result.get("bubble_id", "")

        except Exception as e:
            logger.warning(f"Fortress fingerprint failed: {e}, falling back to builtin")
            identity = self._enrich_builtin(identity, dhcp_options, mdns_services)

        return identity

    def _enrich_builtin(
        self,
        identity: DeviceIdentity,
        dhcp_options: Optional[List[int]],
        mdns_services: Optional[List[str]],
    ) -> DeviceIdentity:
        """Built-in fingerprinting when Fortress engine is not available."""

        # 1. OUI lookup (vendor from MAC prefix)
        oui = identity.mac[:8].upper()
        if oui in OUI_PREFIXES:
            identity.vendor = OUI_PREFIXES[oui]
            # Set ecosystem from vendor
            vendor_lower = identity.vendor.lower()
            if vendor_lower == "apple":
                identity.ecosystem = Ecosystem.APPLE
            elif vendor_lower == "google":
                identity.ecosystem = Ecosystem.GOOGLE
            elif vendor_lower == "amazon":
                identity.ecosystem = Ecosystem.AMAZON
            elif vendor_lower == "samsung":
                identity.ecosystem = Ecosystem.SAMSUNG
            elif vendor_lower == "microsoft":
                identity.ecosystem = Ecosystem.MICROSOFT

        # 2. Hostname pattern matching
        if identity.hostname:
            for pattern, (device_type, vendor, ecosystem) in DEVICE_PATTERNS.items():
                if re.search(pattern, identity.hostname):
                    identity.device_type = device_type
                    if not identity.vendor:
                        identity.vendor = vendor
                    if identity.ecosystem == Ecosystem.UNKNOWN:
                        identity.ecosystem = ecosystem
                    break

        # 3. mDNS service analysis
        if mdns_services:
            for service in mdns_services:
                service_lower = service.lower()
                if "_airplay" in service_lower or "_raop" in service_lower:
                    identity.ecosystem = Ecosystem.APPLE
                    if not identity.device_type:
                        identity.device_type = "Apple Device"
                elif "_googlecast" in service_lower:
                    identity.ecosystem = Ecosystem.GOOGLE
                    if not identity.device_type:
                        identity.device_type = "Google Cast Device"
                elif "_amzn" in service_lower:
                    identity.ecosystem = Ecosystem.AMAZON
                    if not identity.device_type:
                        identity.device_type = "Amazon Device"

        # 4. Calculate confidence
        signals = 0
        if identity.vendor:
            signals += 1
        if identity.device_type:
            signals += 1
        if identity.hostname:
            signals += 1
        if mdns_services:
            signals += 1
        if dhcp_options:
            signals += 1

        identity.confidence = min(signals / 5.0, 1.0)

        # 5. Set trust level based on confidence
        if identity.confidence >= 0.8:
            identity.trust_level = TrustLevel.L2_STANDARD
        elif identity.confidence >= 0.5:
            identity.trust_level = TrustLevel.L1_MINIMAL
        else:
            identity.trust_level = TrustLevel.L0_UNTRUSTED

        return identity

    def _generate_fingerprint_hash(self, identity: DeviceIdentity) -> str:
        """Generate a unique fingerprint hash for this device identity."""
        data = f"{identity.mac}:{identity.vendor}:{identity.device_type}:{identity.hostname}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _generate_human_label(self, identity: DeviceIdentity) -> str:
        """
        Generate a human-friendly label for the device.

        Examples:
            - "iPhone (Living Room)"
            - "MacBook Pro"
            - "Samsung TV"
            - "Unknown Device (AA:BB:CC)"
        """
        parts = []

        if identity.device_type:
            parts.append(identity.device_type)
        elif identity.vendor:
            parts.append(f"{identity.vendor} Device")
        elif identity.hostname:
            # Clean up hostname
            clean_hostname = identity.hostname.replace("-", " ").replace("_", " ")
            parts.append(clean_hostname)
        else:
            # Last resort: partial MAC
            parts.append(f"Device ({identity.mac[-8:]})")

        return " ".join(parts)

    def set_human_label(self, mac: str, label: str) -> bool:
        """
        Set a custom human label for a device.

        Args:
            mac: Device MAC address
            label: New human-friendly label (e.g., "Dad's iPhone")

        Returns:
            True if successful
        """
        mac = mac.upper().replace("-", ":")

        if mac in self._cache:
            self._cache[mac].human_label = label
            self._persist_identity(self._cache[mac])
            return True

        return False

    def get_identity(self, mac: str) -> Optional[DeviceIdentity]:
        """
        Get the identity for a MAC address.

        Args:
            mac: Device MAC address

        Returns:
            DeviceIdentity or None if not found
        """
        mac = mac.upper().replace("-", ":")
        return self._cache.get(mac)

    def get_all_devices(self) -> List[DeviceIdentity]:
        """Get all known device identities."""
        return list(self._cache.values())

    def get_devices_by_ecosystem(self, ecosystem: Ecosystem) -> List[DeviceIdentity]:
        """Get all devices belonging to an ecosystem."""
        return [d for d in self._cache.values() if d.ecosystem == ecosystem]

    def get_devices_by_bubble(self, bubble_id: str) -> List[DeviceIdentity]:
        """Get all devices in a bubble (user group)."""
        return [d for d in self._cache.values() if d.bubble_id == bubble_id]

    def _persist_identity(self, identity: DeviceIdentity) -> None:
        """Persist identity to ClickHouse."""
        # In production, this would be an async write to ClickHouse
        # For now, we just log it
        logger.debug(f"Persisting identity: {identity.human_label} ({identity.mac})")

    def load_from_clickhouse(self) -> int:
        """
        Load existing identities from ClickHouse.

        Returns:
            Number of identities loaded
        """
        # In production, this would query ClickHouse
        # For now, return 0
        logger.info("Loading identities from ClickHouse...")
        return 0


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    engine = IdentityEngine(use_fortress_fingerprint=False)

    # Enrich a device
    identity = engine.enrich(
        mac="00:1E:C2:12:34:56",
        hostname="iPhone-Dad",
        mdns_services=["_airplay._tcp.local"],
    )

    print(f"Human Label: {identity.human_label}")
    print(f"Device Type: {identity.device_type}")
    print(f"Vendor: {identity.vendor}")
    print(f"Ecosystem: {identity.ecosystem.value}")
    print(f"Confidence: {identity.confidence:.2f}")
    print(f"Trust Level: {identity.trust_level.name}")
