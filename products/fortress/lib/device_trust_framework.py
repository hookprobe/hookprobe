#!/usr/bin/env python3
"""
HookProbe Fortress Device Trust Framework

Implements CIA Triad for Device Identity:
- Confidentiality: Encrypted enrollment, secure key storage
- Integrity: Hardware fingerprinting, attestation verification
- Authentication: Challenge-response, device certificates

Trust Levels:
- L0 (UNTRUSTED):    Unknown device → Quarantine VLAN
- L1 (MINIMAL):      MAC only, unverified → Guest VLAN
- L2 (STANDARD):     MAC + OUI verified + behavioral baseline → Segment VLAN
- L3 (HIGH):         MAC + Attestation + Certificate → Full segment access
- L4 (ENTERPRISE):   MAC + TPM Attestation + Neuro resonance → Management access

Single SSID Architecture:
- All devices connect to same WiFi SSID (untagged)
- OVS dynamically assigns VLAN based on verified trust level
- Re-verification every 5 minutes for L2+, every 30s for L3+

Version: 5.5.0
License: AGPL-3.0
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import IntEnum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from threading import Lock
import ipaddress

logger = logging.getLogger(__name__)


# ============================================================
# TRUST LEVELS
# ============================================================

class TrustLevel(IntEnum):
    """Device trust levels with VLAN mapping."""
    UNTRUSTED = 0    # Unknown device → Quarantine (VLAN 99)
    MINIMAL = 1      # MAC only → Guest (VLAN 40)
    STANDARD = 2     # MAC + OUI + behavior → Segment VLAN
    HIGH = 3         # MAC + Attestation → Full segment
    ENTERPRISE = 4   # MAC + TPM + Neuro → Management access


# Trust level → Default VLAN mapping (overridden by segment)
TRUST_VLAN_MAP = {
    TrustLevel.UNTRUSTED: 99,   # Quarantine
    TrustLevel.MINIMAL: 40,     # Guest
    TrustLevel.STANDARD: 30,    # Clients (default segment)
    TrustLevel.HIGH: 30,        # Clients with full access
    TrustLevel.ENTERPRISE: 10,  # Management
}


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class DeviceFingerprint:
    """
    Hardware fingerprint for device identification.

    Combines multiple identifiers to create unique device ID
    that's resistant to MAC spoofing.
    """
    mac_address: str                    # Primary identifier
    oui: str                            # First 3 bytes (vendor)
    oui_vendor: Optional[str] = None    # Resolved vendor name

    # Network behavior fingerprint
    dhcp_hostname: Optional[str] = None
    dhcp_vendor_class: Optional[str] = None  # DHCP option 60
    dhcp_options: List[int] = field(default_factory=list)  # Requested options

    # Passive OS fingerprint (from TCP/IP stack)
    os_fingerprint: Optional[str] = None  # e.g., "Linux 5.x", "iOS 17"
    ttl_signature: Optional[int] = None   # Initial TTL (64=Linux, 128=Windows, 255=Cisco)
    window_size: Optional[int] = None     # TCP window size
    mss: Optional[int] = None             # TCP MSS

    # Active probing results
    mdns_name: Optional[str] = None       # mDNS/Bonjour discovery
    upnp_info: Optional[Dict] = None      # UPnP device description
    snmp_sysinfo: Optional[Dict] = None   # SNMP system info (if available)

    # Behavioral baseline
    first_seen: float = 0.0
    last_seen: float = 0.0
    connection_count: int = 0
    bytes_total: int = 0
    typical_ports: List[int] = field(default_factory=list)  # Commonly used ports

    def compute_fingerprint_hash(self) -> str:
        """Compute unique fingerprint hash."""
        components = [
            self.mac_address.upper(),
            self.dhcp_hostname or '',
            self.dhcp_vendor_class or '',
            str(sorted(self.dhcp_options)),
            self.os_fingerprint or '',
            str(self.ttl_signature or 0),
            str(self.window_size or 0),
            self.mdns_name or '',
        ]
        data = '|'.join(components)
        return hashlib.sha256(data.encode()).hexdigest()[:32]

    def matches_baseline(self, other: 'DeviceFingerprint', tolerance: float = 0.8) -> bool:
        """Check if fingerprint matches a baseline with tolerance."""
        score = 0.0
        checks = 0

        # MAC must match exactly
        if self.mac_address.upper() != other.mac_address.upper():
            return False

        # OUI should match
        if self.oui == other.oui:
            score += 1.0
        checks += 1

        # Hostname similarity
        if self.dhcp_hostname and other.dhcp_hostname:
            if self.dhcp_hostname.lower() == other.dhcp_hostname.lower():
                score += 1.0
            elif self.dhcp_hostname.lower() in other.dhcp_hostname.lower():
                score += 0.5
        checks += 1

        # DHCP vendor class
        if self.dhcp_vendor_class == other.dhcp_vendor_class:
            score += 1.0
        checks += 1

        # OS fingerprint
        if self.os_fingerprint and other.os_fingerprint:
            if self.os_fingerprint == other.os_fingerprint:
                score += 1.0
        checks += 1

        # TTL signature
        if self.ttl_signature == other.ttl_signature:
            score += 1.0
        checks += 1

        return (score / checks) >= tolerance


@dataclass
class DeviceCertificate:
    """
    Device certificate for authenticated devices.

    Signed by Fortress local CA after successful attestation.
    Enables challenge-response authentication.
    """
    cert_id: str                         # Unique certificate ID
    device_id: str                       # Device identifier
    mac_address: str                     # Bound MAC address
    public_key: bytes                    # Ed25519 public key (32 bytes)

    # Certificate metadata
    issued_at: float                     # Unix timestamp
    expires_at: float                    # Unix timestamp
    issuer: str = "Fortress-CA"          # Local CA identifier

    # Trust constraints
    trust_level: TrustLevel = TrustLevel.STANDARD
    allowed_vlans: List[int] = field(default_factory=list)
    allowed_segments: List[str] = field(default_factory=list)

    # Attestation binding
    attestation_hash: Optional[str] = None  # Hash of original attestation
    fingerprint_hash: Optional[str] = None  # Device fingerprint binding

    # Signature
    signature: bytes = b''               # CA signature over certificate

    def is_valid(self) -> bool:
        """Check if certificate is currently valid."""
        now = time.time()
        return self.issued_at <= now <= self.expires_at

    def to_bytes(self) -> bytes:
        """Serialize certificate for signing/verification."""
        data = bytearray()
        data.extend(self.cert_id.encode()[:32].ljust(32, b'\x00'))
        data.extend(self.device_id.encode()[:32].ljust(32, b'\x00'))
        data.extend(self.mac_address.upper().encode()[:17].ljust(17, b'\x00'))
        data.extend(self.public_key)
        data.extend(struct.pack('<d', self.issued_at))
        data.extend(struct.pack('<d', self.expires_at))
        data.extend(struct.pack('<B', self.trust_level))
        data.extend((self.attestation_hash or '').encode()[:32].ljust(32, b'\x00'))
        data.extend((self.fingerprint_hash or '').encode()[:32].ljust(32, b'\x00'))
        return bytes(data)


@dataclass
class TrustAssessment:
    """
    Result of device trust assessment.

    Contains trust level, evidence, and VLAN assignment.
    """
    device_id: str
    mac_address: str
    trust_level: TrustLevel
    assigned_vlan: int
    segment: Optional[str] = None

    # Assessment details
    assessed_at: float = field(default_factory=time.time)
    expires_at: float = 0.0              # When re-verification needed

    # Evidence
    oui_verified: bool = False           # OUI matches known vendor
    fingerprint_verified: bool = False   # Fingerprint matches baseline
    certificate_verified: bool = False   # Valid device certificate
    attestation_verified: bool = False   # TPM/Neuro attestation valid
    behavior_normal: bool = True         # No anomalous behavior

    # Confidence score (0.0 - 1.0)
    confidence: float = 0.0

    # Warnings/issues
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'device_id': self.device_id,
            'mac_address': self.mac_address,
            'trust_level': self.trust_level.name,
            'trust_level_value': int(self.trust_level),
            'assigned_vlan': self.assigned_vlan,
            'segment': self.segment,
            'assessed_at': self.assessed_at,
            'expires_at': self.expires_at,
            'oui_verified': self.oui_verified,
            'fingerprint_verified': self.fingerprint_verified,
            'certificate_verified': self.certificate_verified,
            'attestation_verified': self.attestation_verified,
            'behavior_normal': self.behavior_normal,
            'confidence': self.confidence,
            'warnings': self.warnings,
        }


# ============================================================
# OUI DATABASE WITH VENDOR VERIFICATION
# ============================================================

# Vendor OUI database with expected device characteristics
# Format: OUI prefix -> (vendor_name, expected_device_types, trust_floor)
OUI_TRUST_DATABASE: Dict[str, Tuple[str, List[str], TrustLevel]] = {
    # Enterprise/Professional equipment - Higher trust floor
    '00:0D:7C': ('Synology', ['nas', 'nvr'], TrustLevel.STANDARD),
    '00:0C:F6': ('Seco', ['industrial'], TrustLevel.STANDARD),
    '00:11:32': ('Synology', ['nas', 'nvr'], TrustLevel.STANDARD),
    'B8:27:EB': ('Raspberry Pi', ['sbc', 'iot'], TrustLevel.STANDARD),
    'DC:A6:32': ('Raspberry Pi', ['sbc', 'iot'], TrustLevel.STANDARD),
    'E4:5F:01': ('Raspberry Pi', ['sbc', 'iot'], TrustLevel.STANDARD),

    # POS Terminals - Need verification
    '58:E6:BA': ('Square', ['pos'], TrustLevel.MINIMAL),
    '00:0B:CD': ('Hewlett-Packard/Ingenico', ['pos'], TrustLevel.MINIMAL),
    'D4:B9:2F': ('Clover', ['pos'], TrustLevel.MINIMAL),
    '00:1E:52': ('Verifone', ['pos'], TrustLevel.MINIMAL),

    # IP Cameras - Isolated by default
    '28:57:BE': ('Hikvision', ['camera'], TrustLevel.MINIMAL),
    '3C:EF:8C': ('Dahua', ['camera'], TrustLevel.MINIMAL),
    'AC:CC:8E': ('Axis', ['camera'], TrustLevel.MINIMAL),
    'E0:50:8B': ('Reolink', ['camera'], TrustLevel.MINIMAL),

    # Consumer devices - Need behavioral verification
    '3C:06:30': ('Apple', ['laptop', 'phone', 'tablet'], TrustLevel.MINIMAL),
    'A4:5E:60': ('Apple', ['phone', 'watch'], TrustLevel.MINIMAL),
    'F0:18:98': ('Apple', ['laptop', 'desktop'], TrustLevel.MINIMAL),
    '00:00:F0': ('Samsung', ['phone', 'tablet', 'tv'], TrustLevel.MINIMAL),
    '8C:F5:A3': ('Samsung', ['phone'], TrustLevel.MINIMAL),
    'B4:F1:DA': ('LG', ['tv', 'appliance'], TrustLevel.MINIMAL),

    # IoT - Minimal trust
    '18:B4:30': ('Nest/Google', ['thermostat', 'camera'], TrustLevel.MINIMAL),
    'D4:F5:47': ('Google', ['speaker', 'hub'], TrustLevel.MINIMAL),
    '00:17:88': ('Philips Hue', ['lighting'], TrustLevel.MINIMAL),
    '68:A4:0E': ('Amazon', ['echo', 'fire'], TrustLevel.MINIMAL),

    # Network equipment - Depends on context
    '00:02:B3': ('Intel', ['laptop', 'nic'], TrustLevel.MINIMAL),
    '00:1A:A0': ('Dell', ['laptop', 'desktop'], TrustLevel.MINIMAL),
    '00:21:6A': ('Lenovo', ['laptop', 'desktop'], TrustLevel.MINIMAL),
    '98:90:96': ('Dell', ['laptop', 'desktop'], TrustLevel.MINIMAL),

    # Printers - Limited access
    '00:00:48': ('Seiko Epson', ['printer'], TrustLevel.MINIMAL),
    '00:00:85': ('Canon', ['printer'], TrustLevel.MINIMAL),
    '3C:2A:F4': ('Brother', ['printer'], TrustLevel.MINIMAL),
    '00:17:C8': ('HP', ['printer'], TrustLevel.MINIMAL),
}


# ============================================================
# DEVICE TRUST FRAMEWORK
# ============================================================

class DeviceTrustFramework:
    """
    Core Device Trust Framework for network admission control.

    Implements:
    - Device fingerprinting and baseline management
    - OUI verification with vendor database
    - Certificate-based authentication
    - Challenge-response verification
    - Trust level assessment with VLAN assignment
    - Behavioral anomaly detection
    - Integration with OVS for dynamic flow rules
    """

    # Re-verification intervals by trust level
    REVERIFY_INTERVALS = {
        TrustLevel.UNTRUSTED: 30,       # 30 seconds
        TrustLevel.MINIMAL: 300,        # 5 minutes
        TrustLevel.STANDARD: 300,       # 5 minutes
        TrustLevel.HIGH: 60,            # 1 minute
        TrustLevel.ENTERPRISE: 30,      # 30 seconds
    }

    def __init__(self, db_path: str = '/var/lib/fortress/trust.db',
                 ovs_bridge: str = 'fortress'):
        """
        Initialize Device Trust Framework.

        Args:
            db_path: Path to SQLite database
            ovs_bridge: OVS bridge name for flow rules
        """
        self.db_path = Path(db_path)
        self.ovs_bridge = ovs_bridge
        self._lock = Lock()

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_db()

        # Load CA key (or generate if first run)
        self._ca_private_key, self._ca_public_key = self._load_or_generate_ca()

        # Active challenge nonces (mac -> (nonce, expires))
        self._challenges: Dict[str, Tuple[bytes, float]] = {}

        logger.info(f"Device Trust Framework initialized (bridge: {ovs_bridge})")

    def _init_db(self):
        """Initialize SQLite database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                -- Device fingerprints (baselines)
                CREATE TABLE IF NOT EXISTS device_fingerprints (
                    mac_address TEXT PRIMARY KEY,
                    fingerprint_json TEXT NOT NULL,
                    fingerprint_hash TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    connection_count INTEGER DEFAULT 1
                );

                -- Device certificates
                CREATE TABLE IF NOT EXISTS device_certificates (
                    cert_id TEXT PRIMARY KEY,
                    mac_address TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    trust_level INTEGER NOT NULL,
                    attestation_hash TEXT,
                    fingerprint_hash TEXT,
                    signature BLOB NOT NULL,
                    revoked INTEGER DEFAULT 0,
                    UNIQUE(mac_address)
                );

                -- Trust assessments (cache)
                CREATE TABLE IF NOT EXISTS trust_assessments (
                    mac_address TEXT PRIMARY KEY,
                    assessment_json TEXT NOT NULL,
                    assessed_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );

                -- Behavioral events (for anomaly detection)
                CREATE TABLE IF NOT EXISTS behavioral_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_address TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_data TEXT,
                    timestamp REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_behavioral_mac
                    ON behavioral_events(mac_address, timestamp);

                -- Enrollment attempts
                CREATE TABLE IF NOT EXISTS enrollment_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_address TEXT NOT NULL,
                    attempt_type TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    details TEXT,
                    timestamp REAL NOT NULL
                );
            ''')
            conn.commit()

    def _load_or_generate_ca(self) -> Tuple[bytes, bytes]:
        """Load or generate CA key pair."""
        ca_key_path = self.db_path.parent / 'ca_key.pem'

        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            if ca_key_path.exists():
                # Load existing key
                key_data = ca_key_path.read_bytes()
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
            else:
                # Generate new key
                private_key = ed25519.Ed25519PrivateKey.generate()
                ca_key_path.write_bytes(private_key.private_bytes_raw())
                ca_key_path.chmod(0o600)
                logger.info("Generated new Fortress CA key")

            public_key = private_key.public_key()
            return private_key.private_bytes_raw(), public_key.public_bytes_raw()

        except ImportError:
            # Fallback: use HMAC-based signing
            if ca_key_path.exists():
                key = ca_key_path.read_bytes()
            else:
                key = secrets.token_bytes(32)
                ca_key_path.write_bytes(key)
                ca_key_path.chmod(0o600)
            return key, hashlib.sha256(key).digest()

    # ========================================
    # Device Fingerprinting
    # ========================================

    def create_fingerprint(self, mac_address: str,
                          dhcp_hostname: Optional[str] = None,
                          dhcp_vendor_class: Optional[str] = None,
                          dhcp_options: Optional[List[int]] = None,
                          **kwargs) -> DeviceFingerprint:
        """
        Create device fingerprint from available information.

        Args:
            mac_address: Device MAC address
            dhcp_hostname: DHCP hostname from lease
            dhcp_vendor_class: DHCP option 60
            dhcp_options: DHCP requested options
            **kwargs: Additional fingerprint fields

        Returns:
            DeviceFingerprint with computed hash
        """
        mac = mac_address.upper()
        oui = mac[:8]

        # Look up vendor
        oui_info = OUI_TRUST_DATABASE.get(oui.replace(':', '-'),
                                          OUI_TRUST_DATABASE.get(oui))
        vendor_name = oui_info[0] if oui_info else None

        fp = DeviceFingerprint(
            mac_address=mac,
            oui=oui,
            oui_vendor=vendor_name,
            dhcp_hostname=dhcp_hostname,
            dhcp_vendor_class=dhcp_vendor_class,
            dhcp_options=dhcp_options or [],
            first_seen=time.time(),
            last_seen=time.time(),
            **{k: v for k, v in kwargs.items() if hasattr(DeviceFingerprint, k)}
        )

        return fp

    def save_fingerprint(self, fp: DeviceFingerprint) -> bool:
        """Save or update device fingerprint baseline."""
        try:
            fp_hash = fp.compute_fingerprint_hash()
            fp_json = json.dumps(asdict(fp))

            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO device_fingerprints
                    (mac_address, fingerprint_json, fingerprint_hash, first_seen, last_seen, connection_count)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        fingerprint_json = ?,
                        fingerprint_hash = ?,
                        last_seen = ?,
                        connection_count = connection_count + 1
                ''', (fp.mac_address, fp_json, fp_hash, fp.first_seen, fp.last_seen,
                      fp_json, fp_hash, fp.last_seen))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save fingerprint: {e}")
            return False

    def get_fingerprint_baseline(self, mac_address: str) -> Optional[DeviceFingerprint]:
        """Get stored fingerprint baseline for device."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    'SELECT fingerprint_json FROM device_fingerprints WHERE mac_address = ?',
                    (mac_address.upper(),)
                ).fetchone()

                if row:
                    data = json.loads(row[0])
                    return DeviceFingerprint(**data)
        except Exception as e:
            logger.error(f"Failed to get fingerprint: {e}")
        return None

    # ========================================
    # OUI Verification
    # ========================================

    def verify_oui(self, mac_address: str) -> Tuple[bool, Optional[str], TrustLevel]:
        """
        Verify MAC address OUI against vendor database.

        Args:
            mac_address: Device MAC address

        Returns:
            (is_known, vendor_name, trust_floor)
        """
        mac = mac_address.upper()
        oui = mac[:8]

        # Check different OUI formats
        for oui_format in [oui, oui.replace(':', '-')]:
            if oui_format in OUI_TRUST_DATABASE:
                vendor, device_types, trust_floor = OUI_TRUST_DATABASE[oui_format]
                return True, vendor, trust_floor

        # Unknown OUI - could be spoofed
        return False, None, TrustLevel.UNTRUSTED

    # ========================================
    # Challenge-Response Authentication
    # ========================================

    def create_challenge(self, mac_address: str) -> bytes:
        """
        Create challenge nonce for device authentication.

        Args:
            mac_address: Device MAC address

        Returns:
            16-byte challenge nonce
        """
        mac = mac_address.upper()
        nonce = secrets.token_bytes(16)
        expires = time.time() + 60  # 60 second validity

        with self._lock:
            self._challenges[mac] = (nonce, expires)

        return nonce

    def verify_challenge_response(self, mac_address: str,
                                  response: bytes,
                                  public_key: bytes) -> bool:
        """
        Verify device's response to challenge.

        Args:
            mac_address: Device MAC address
            response: Signed challenge response (64 bytes for Ed25519)
            public_key: Device's public key (32 bytes)

        Returns:
            True if response is valid
        """
        mac = mac_address.upper()

        # Get and remove challenge
        with self._lock:
            challenge_data = self._challenges.pop(mac, None)

        if not challenge_data:
            logger.warning(f"No active challenge for {mac}")
            return False

        nonce, expires = challenge_data

        if time.time() > expires:
            logger.warning(f"Challenge expired for {mac}")
            return False

        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            # Reconstruct expected signed message: nonce || mac
            message = nonce + mac.encode()

            # Verify signature
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public_key_obj.verify(response, message)

            return True

        except Exception as e:
            logger.warning(f"Challenge verification failed for {mac}: {e}")
            return False

    # ========================================
    # Device Certificates
    # ========================================

    def issue_certificate(self, mac_address: str,
                         public_key: bytes,
                         trust_level: TrustLevel,
                         attestation_hash: Optional[str] = None,
                         validity_days: int = 30) -> Optional[DeviceCertificate]:
        """
        Issue device certificate after successful enrollment.

        Args:
            mac_address: Device MAC address
            public_key: Device's public key (32 bytes)
            trust_level: Assigned trust level
            attestation_hash: Hash of attestation (for HIGH/ENTERPRISE)
            validity_days: Certificate validity period

        Returns:
            Signed DeviceCertificate or None on failure
        """
        mac = mac_address.upper()
        now = time.time()

        # Get fingerprint for binding
        baseline = self.get_fingerprint_baseline(mac)
        fp_hash = baseline.compute_fingerprint_hash() if baseline else None

        # Create certificate
        cert = DeviceCertificate(
            cert_id=hashlib.sha256(f"{mac}-{now}".encode()).hexdigest()[:16],
            device_id=f"fortress-{mac.replace(':', '')}",
            mac_address=mac,
            public_key=public_key,
            issued_at=now,
            expires_at=now + (validity_days * 86400),
            trust_level=trust_level,
            attestation_hash=attestation_hash,
            fingerprint_hash=fp_hash,
        )

        # Set allowed VLANs based on trust level
        cert.allowed_vlans = self._get_allowed_vlans(trust_level)

        # Sign certificate
        cert.signature = self._sign_certificate(cert)

        # Store in database
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO device_certificates
                    (cert_id, mac_address, device_id, public_key, issued_at, expires_at,
                     trust_level, attestation_hash, fingerprint_hash, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (cert.cert_id, cert.mac_address, cert.device_id, cert.public_key,
                      cert.issued_at, cert.expires_at, cert.trust_level,
                      cert.attestation_hash, cert.fingerprint_hash, cert.signature))
                conn.commit()

            logger.info(f"Issued certificate {cert.cert_id} for {mac} (L{trust_level})")
            return cert

        except Exception as e:
            logger.error(f"Failed to store certificate: {e}")
            return None

    def _sign_certificate(self, cert: DeviceCertificate) -> bytes:
        """Sign certificate with CA key."""
        message = cert.to_bytes()

        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(self._ca_private_key)
            return private_key.sign(message)
        except ImportError:
            # HMAC fallback
            return hmac.new(self._ca_private_key, message, hashlib.sha256).digest()

    def verify_certificate(self, mac_address: str) -> Optional[DeviceCertificate]:
        """
        Verify device has valid certificate.

        Args:
            mac_address: Device MAC address

        Returns:
            Valid DeviceCertificate or None
        """
        mac = mac_address.upper()

        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute('''
                    SELECT cert_id, device_id, public_key, issued_at, expires_at,
                           trust_level, attestation_hash, fingerprint_hash, signature
                    FROM device_certificates
                    WHERE mac_address = ? AND revoked = 0
                ''', (mac,)).fetchone()

                if not row:
                    return None

                cert = DeviceCertificate(
                    cert_id=row[0],
                    device_id=row[1],
                    mac_address=mac,
                    public_key=row[2],
                    issued_at=row[3],
                    expires_at=row[4],
                    trust_level=TrustLevel(row[5]),
                    attestation_hash=row[6],
                    fingerprint_hash=row[7],
                    signature=row[8],
                )

                # Check validity
                if not cert.is_valid():
                    logger.debug(f"Certificate expired for {mac}")
                    return None

                # Verify signature
                message = cert.to_bytes()
                try:
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    public_key = ed25519.Ed25519PublicKey.from_public_bytes(self._ca_public_key)
                    public_key.verify(cert.signature, message)
                except ImportError:
                    # HMAC verification
                    expected = hmac.new(self._ca_private_key, message, hashlib.sha256).digest()
                    if not hmac.compare_digest(cert.signature, expected):
                        logger.warning(f"Certificate signature invalid for {mac}")
                        return None

                return cert

        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return None

    def revoke_certificate(self, mac_address: str, reason: str = "manual") -> bool:
        """Revoke device certificate."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE device_certificates SET revoked = 1 WHERE mac_address = ?',
                    (mac_address.upper(),)
                )
                conn.commit()
            logger.info(f"Revoked certificate for {mac_address}: {reason}")
            return True
        except Exception:
            return False

    def _get_allowed_vlans(self, trust_level: TrustLevel) -> List[int]:
        """Get allowed VLANs for trust level."""
        if trust_level == TrustLevel.ENTERPRISE:
            return [10, 20, 30, 40, 50, 60]  # All segments
        elif trust_level == TrustLevel.HIGH:
            return [20, 30, 50, 60]  # POS, Clients, Cameras, IIoT
        elif trust_level == TrustLevel.STANDARD:
            return [30, 40, 60]  # Clients, Guest, IIoT
        elif trust_level == TrustLevel.MINIMAL:
            return [40]  # Guest only
        else:
            return [99]  # Quarantine

    # ========================================
    # Trust Assessment
    # ========================================

    def assess_trust(self, mac_address: str,
                    current_fingerprint: Optional[DeviceFingerprint] = None,
                    segment_hint: Optional[str] = None) -> TrustAssessment:
        """
        Assess device trust level and determine VLAN assignment.

        This is the main entry point for network admission control.

        Args:
            mac_address: Device MAC address
            current_fingerprint: Current device fingerprint (from DHCP, etc.)
            segment_hint: Suggested segment from SDN Auto-Pilot

        Returns:
            TrustAssessment with VLAN assignment
        """
        mac = mac_address.upper()
        now = time.time()

        # Check cache first
        cached = self._get_cached_assessment(mac)
        if cached and cached.expires_at > now:
            return cached

        # Start with untrusted
        assessment = TrustAssessment(
            device_id=f"dev-{mac.replace(':', '')}",
            mac_address=mac,
            trust_level=TrustLevel.UNTRUSTED,
            assigned_vlan=99,
            confidence=0.0,
        )

        # Step 1: OUI verification
        oui_known, vendor, oui_trust_floor = self.verify_oui(mac)
        if oui_known:
            assessment.oui_verified = True
            assessment.trust_level = max(assessment.trust_level, TrustLevel.MINIMAL)
            assessment.confidence += 0.2
            logger.debug(f"{mac}: OUI verified as {vendor}")
        else:
            assessment.warnings.append("Unknown vendor OUI")

        # Step 2: Fingerprint verification (if baseline exists)
        baseline = self.get_fingerprint_baseline(mac)
        if baseline and current_fingerprint:
            if current_fingerprint.matches_baseline(baseline):
                assessment.fingerprint_verified = True
                assessment.trust_level = max(assessment.trust_level, TrustLevel.STANDARD)
                assessment.confidence += 0.3
                logger.debug(f"{mac}: Fingerprint matches baseline")
            else:
                assessment.warnings.append("Fingerprint deviation from baseline")
                assessment.behavior_normal = False
        elif current_fingerprint:
            # First time - save baseline
            self.save_fingerprint(current_fingerprint)
            assessment.warnings.append("New device - baseline created")

        # Step 3: Certificate verification
        cert = self.verify_certificate(mac)
        if cert:
            assessment.certificate_verified = True
            assessment.trust_level = max(assessment.trust_level, cert.trust_level)
            assessment.confidence += 0.4
            logger.debug(f"{mac}: Certificate verified (L{cert.trust_level})")

            # Verify fingerprint binding
            if cert.fingerprint_hash and current_fingerprint:
                current_hash = current_fingerprint.compute_fingerprint_hash()
                if current_hash != cert.fingerprint_hash:
                    assessment.warnings.append("Fingerprint changed since enrollment")
                    assessment.trust_level = min(assessment.trust_level, TrustLevel.MINIMAL)

        # Step 4: Determine VLAN based on trust level and segment
        assessment.segment = segment_hint
        assessment.assigned_vlan = self._determine_vlan(
            assessment.trust_level, segment_hint
        )

        # Set re-verification interval
        interval = self.REVERIFY_INTERVALS.get(assessment.trust_level, 300)
        assessment.expires_at = now + interval

        # Cache assessment
        self._cache_assessment(assessment)

        # Apply OVS flow rules
        self._apply_ovs_flow(mac, assessment.assigned_vlan, assessment.trust_level)

        logger.info(
            f"Trust assessment: {mac} -> L{assessment.trust_level.name} "
            f"(VLAN {assessment.assigned_vlan}, confidence {assessment.confidence:.2f})"
        )

        return assessment

    def _determine_vlan(self, trust_level: TrustLevel,
                       segment_hint: Optional[str] = None) -> int:
        """Determine VLAN based on trust level and segment."""
        # Segment VLAN mappings
        SEGMENT_VLANS = {
            'SECMON': 10,
            'POS': 20,
            'CLIENTS': 30,
            'GUEST': 40,
            'CAMERAS': 50,
            'IIOT': 60,
            'QUARANTINE': 99,
        }

        # Quarantine untrusted devices
        if trust_level == TrustLevel.UNTRUSTED:
            return 99

        # Minimal trust -> Guest only
        if trust_level == TrustLevel.MINIMAL:
            return 40

        # Standard+ trust -> Use segment VLAN
        if segment_hint and segment_hint.upper() in SEGMENT_VLANS:
            return SEGMENT_VLANS[segment_hint.upper()]

        # Default to clients
        return TRUST_VLAN_MAP.get(trust_level, 30)

    def _get_cached_assessment(self, mac_address: str) -> Optional[TrustAssessment]:
        """Get cached trust assessment."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    'SELECT assessment_json FROM trust_assessments WHERE mac_address = ?',
                    (mac_address,)
                ).fetchone()

                if row:
                    data = json.loads(row[0])
                    data['trust_level'] = TrustLevel(data['trust_level_value'])
                    return TrustAssessment(**{k: v for k, v in data.items()
                                              if k != 'trust_level_value'})
        except Exception:
            pass
        return None

    def _cache_assessment(self, assessment: TrustAssessment):
        """Cache trust assessment."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO trust_assessments
                    (mac_address, assessment_json, assessed_at, expires_at)
                    VALUES (?, ?, ?, ?)
                ''', (assessment.mac_address, json.dumps(assessment.to_dict()),
                      assessment.assessed_at, assessment.expires_at))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to cache assessment: {e}")

    # ========================================
    # OVS Integration
    # ========================================

    def _apply_ovs_flow(self, mac_address: str, vlan_id: int,
                       trust_level: TrustLevel):
        """
        Apply OVS flow rules for device.

        Rules:
        - Tag traffic from MAC with assigned VLAN
        - Apply rate limits based on trust level
        - Block if untrusted
        """
        mac = mac_address.upper()

        # Remove existing flows for this MAC
        self._run_cmd([
            'ovs-ofctl', 'del-flows', self.ovs_bridge,
            f'dl_src={mac}'
        ])

        if trust_level == TrustLevel.UNTRUSTED:
            # Drop all traffic from untrusted devices
            self._run_cmd([
                'ovs-ofctl', 'add-flow', self.ovs_bridge,
                f'priority=1000,dl_src={mac},actions=drop'
            ])
            logger.info(f"Blocked untrusted device: {mac}")
        else:
            # Tag with VLAN
            self._run_cmd([
                'ovs-ofctl', 'add-flow', self.ovs_bridge,
                f'priority=200,dl_src={mac},actions=mod_vlan_vid:{vlan_id},normal'
            ])

            # Add rate limit for minimal trust
            if trust_level == TrustLevel.MINIMAL:
                # 10 Mbps limit for minimal trust
                self._apply_rate_limit(mac, 10)

    def _apply_rate_limit(self, mac_address: str, mbps: int):
        """Apply bandwidth rate limit to device."""
        # This would use OVS meters or tc
        # Simplified implementation
        pass

    def _run_cmd(self, cmd: List[str]) -> bool:
        """Run shell command."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Command failed: {cmd}: {e}")
            return False

    # ========================================
    # Behavioral Monitoring
    # ========================================

    def record_event(self, mac_address: str, event_type: str,
                    event_data: Optional[Dict] = None):
        """
        Record behavioral event for anomaly detection.

        Args:
            mac_address: Device MAC
            event_type: Type of event (port_scan, dns_tunnel, etc.)
            event_data: Additional event details
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO behavioral_events
                    (mac_address, event_type, event_data, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (mac_address.upper(), event_type,
                      json.dumps(event_data) if event_data else None,
                      time.time()))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to record event: {e}")

    def check_anomalies(self, mac_address: str,
                       window_hours: int = 1) -> List[str]:
        """
        Check for behavioral anomalies.

        Args:
            mac_address: Device MAC
            window_hours: Time window to check

        Returns:
            List of detected anomalies
        """
        anomalies = []
        cutoff = time.time() - (window_hours * 3600)

        try:
            with sqlite3.connect(self.db_path) as conn:
                # Count events by type
                rows = conn.execute('''
                    SELECT event_type, COUNT(*)
                    FROM behavioral_events
                    WHERE mac_address = ? AND timestamp > ?
                    GROUP BY event_type
                ''', (mac_address.upper(), cutoff)).fetchall()

                for event_type, count in rows:
                    if event_type == 'port_scan' and count > 100:
                        anomalies.append(f"Port scanning detected ({count} attempts)")
                    elif event_type == 'dns_query' and count > 1000:
                        anomalies.append(f"Excessive DNS queries ({count})")
                    elif event_type == 'failed_auth' and count > 10:
                        anomalies.append(f"Multiple auth failures ({count})")

        except Exception as e:
            logger.error(f"Anomaly check failed: {e}")

        return anomalies

    # ========================================
    # Statistics & Reporting
    # ========================================

    def get_trust_statistics(self) -> Dict[str, Any]:
        """Get trust framework statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                stats = {
                    'total_devices': 0,
                    'by_trust_level': {},
                    'certificates_issued': 0,
                    'certificates_revoked': 0,
                    'recent_enrollments': 0,
                }

                # Count by trust level
                rows = conn.execute('''
                    SELECT json_extract(assessment_json, '$.trust_level_value'), COUNT(*)
                    FROM trust_assessments
                    GROUP BY json_extract(assessment_json, '$.trust_level_value')
                ''').fetchall()

                for level, count in rows:
                    level_name = TrustLevel(level).name if level else 'UNKNOWN'
                    stats['by_trust_level'][level_name] = count
                    stats['total_devices'] += count

                # Certificate counts
                row = conn.execute(
                    'SELECT COUNT(*) FROM device_certificates WHERE revoked = 0'
                ).fetchone()
                stats['certificates_issued'] = row[0] if row else 0

                row = conn.execute(
                    'SELECT COUNT(*) FROM device_certificates WHERE revoked = 1'
                ).fetchone()
                stats['certificates_revoked'] = row[0] if row else 0

                # Recent enrollments (24h)
                cutoff = time.time() - 86400
                row = conn.execute(
                    'SELECT COUNT(*) FROM enrollment_attempts WHERE timestamp > ? AND success = 1',
                    (cutoff,)
                ).fetchone()
                stats['recent_enrollments'] = row[0] if row else 0

                return stats

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}


# ============================================================
# SINGLETON ACCESS
# ============================================================

_trust_framework: Optional[DeviceTrustFramework] = None


def get_trust_framework() -> DeviceTrustFramework:
    """Get Device Trust Framework singleton."""
    global _trust_framework
    if _trust_framework is None:
        _trust_framework = DeviceTrustFramework()
    return _trust_framework


# ============================================================
# CLI INTERFACE
# ============================================================

if __name__ == '__main__':
    import sys

    logging.basicConfig(level=logging.DEBUG)

    print("=== Device Trust Framework Test ===\n")

    dtf = DeviceTrustFramework(db_path='/tmp/test_trust.db')

    # Test device
    test_mac = "3C:06:30:DE:AD:BE"

    print("1. Creating fingerprint...")
    fp = dtf.create_fingerprint(
        mac_address=test_mac,
        dhcp_hostname="MacBook-Pro",
        dhcp_vendor_class="MSFT 5.0",
        dhcp_options=[1, 3, 6, 15, 28, 51]
    )
    print(f"   MAC: {fp.mac_address}")
    print(f"   OUI: {fp.oui} ({fp.oui_vendor})")
    print(f"   Hash: {fp.compute_fingerprint_hash()[:16]}...")
    dtf.save_fingerprint(fp)

    print("\n2. Assessing trust (first time)...")
    assessment = dtf.assess_trust(test_mac, fp, segment_hint="CLIENTS")
    print(f"   Trust Level: {assessment.trust_level.name}")
    print(f"   VLAN: {assessment.assigned_vlan}")
    print(f"   Confidence: {assessment.confidence:.2f}")
    print(f"   Warnings: {assessment.warnings}")

    print("\n3. Issuing certificate...")
    # Simulate device key
    test_pubkey = secrets.token_bytes(32)
    cert = dtf.issue_certificate(
        mac_address=test_mac,
        public_key=test_pubkey,
        trust_level=TrustLevel.STANDARD
    )
    if cert:
        print(f"   Cert ID: {cert.cert_id}")
        print(f"   Valid until: {datetime.fromtimestamp(cert.expires_at)}")

    print("\n4. Re-assessing trust (with certificate)...")
    assessment2 = dtf.assess_trust(test_mac, fp, segment_hint="CLIENTS")
    print(f"   Trust Level: {assessment2.trust_level.name}")
    print(f"   VLAN: {assessment2.assigned_vlan}")
    print(f"   Certificate verified: {assessment2.certificate_verified}")

    print("\n5. Statistics...")
    stats = dtf.get_trust_statistics()
    print(f"   {stats}")

    print("\n=== Test Complete ===")
