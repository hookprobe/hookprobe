"""
MSSP Device Registry - Liberty Version

Central registry for all devices (edge nodes and validators) in HookProbe.
Tracks hardware fingerprints, locations, status, and relationships.

MSSP Cloud maintains this registry to:
- Verify device authenticity
- Track device locations (IP-based geolocation)
- Monitor validator health
- Enforce KYC/validation requirements
"""

import hashlib
import json
import sqlite3
from typing import Optional, List, Dict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum


class DeviceType(Enum):
    """Type of device in HookProbe network."""
    EDGE = "edge"
    VALIDATOR = "validator"
    CLOUD = "cloud"


class DeviceStatus(Enum):
    """Operational status of device."""
    PENDING = "pending"  # Registered, awaiting approval
    ACTIVE = "active"  # Fully operational
    SUSPENDED = "suspended"  # Temporarily disabled
    REVOKED = "revoked"  # Permanently blacklisted


@dataclass
class DeviceLocation:
    """Geographic location information."""
    ip_address: str
    country: str
    region: str
    city: str
    latitude: float
    longitude: float
    asn: int  # Autonomous System Number
    isp: str


@dataclass
class DeviceRecord:
    """Complete device record in MSSP registry."""
    device_id: str
    device_type: DeviceType
    hardware_fingerprint: str  # SHA256 of hardware IDs

    # Identity
    public_key_ed25519: str  # Device signing key
    certificate_hash: Optional[str]  # OEM certificate hash

    # Location tracking
    current_location: DeviceLocation
    location_history: List[DeviceLocation]

    # Status
    status: DeviceStatus
    kyc_verified: bool  # For validators

    # Metadata
    firmware_version: str
    first_seen: int  # Unix timestamp microseconds
    last_seen: int

    # Validator-specific
    validator_stake: Optional[int]
    validator_reputation: Optional[float]

    # Edge-specific
    managed_by_validator: Optional[str]  # Validator ID managing this edge


class MSBPDeviceRegistry:
    """
    MSSP Device Registry.

    Central database tracking all devices in HookProbe network.
    Enforces prerequisite checks (e.g., cloud must exist before validator).
    """

    def __init__(self, db_path: str = "/var/lib/hookprobe/mssp/device_registry.db"):
        """
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_type TEXT NOT NULL,
                hardware_fingerprint TEXT NOT NULL,
                public_key_ed25519 TEXT NOT NULL,
                certificate_hash TEXT,
                status TEXT NOT NULL,
                kyc_verified INTEGER DEFAULT 0,
                firmware_version TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                validator_stake INTEGER,
                validator_reputation REAL,
                managed_by_validator TEXT,
                UNIQUE(hardware_fingerprint)
            )
        ''')

        # Location tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                country TEXT,
                region TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                asn INTEGER,
                isp TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            )
        ''')

        # Create indices
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_type ON devices(device_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON devices(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_location_device ON device_locations(device_id)')

        conn.commit()
        conn.close()

    def register_device(
        self,
        device_id: str,
        device_type: DeviceType,
        hardware_fingerprint: str,
        public_key: str,
        firmware_version: str,
        location: DeviceLocation,
        certificate_hash: Optional[str] = None
    ) -> bool:
        """
        Register new device with MSSP.

        Args:
            device_id: Unique device identifier
            device_type: Type of device
            hardware_fingerprint: Hardware fingerprint hash
            public_key: Ed25519 public key
            firmware_version: Firmware version
            location: Current location
            certificate_hash: OEM certificate hash (if available)

        Returns:
            True if registration successful
        """
        # Prerequisite check: Validators require cloud to exist
        if device_type == DeviceType.VALIDATOR:
            if not self._check_cloud_exists():
                print(f"ERROR: Cannot register validator {device_id} - MSSP Cloud not deployed")
                return False

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            timestamp = int(datetime.now(timezone.utc).timestamp() * 1e6)

            # Insert device
            cursor.execute('''
                INSERT INTO devices (
                    device_id, device_type, hardware_fingerprint,
                    public_key_ed25519, certificate_hash, status,
                    kyc_verified, firmware_version, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                device_type.value,
                hardware_fingerprint,
                public_key,
                certificate_hash,
                DeviceStatus.PENDING.value,
                0,  # KYC not verified yet
                firmware_version,
                timestamp,
                timestamp
            ))

            # Record location
            self._record_location(cursor, device_id, location, timestamp)

            conn.commit()
            print(f"✓ Device {device_id} registered (status: PENDING)")
            return True

        except sqlite3.IntegrityError as e:
            print(f"✗ Registration failed: {e}")
            return False
        finally:
            conn.close()

    def update_location(self, device_id: str, location: DeviceLocation) -> bool:
        """
        Update device location (called on each check-in).

        Args:
            device_id: Device identifier
            location: New location

        Returns:
            True if updated
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            timestamp = int(datetime.now(timezone.utc).timestamp() * 1e6)

            # Update last seen
            cursor.execute('''
                UPDATE devices SET last_seen = ? WHERE device_id = ?
            ''', (timestamp, device_id))

            # Record new location
            self._record_location(cursor, device_id, location, timestamp)

            conn.commit()
            return True

        except Exception as e:
            print(f"Location update failed: {e}")
            return False
        finally:
            conn.close()

    def approve_device(self, device_id: str, kyc_verified: bool = False) -> bool:
        """
        Approve device after manual verification (for validators: KYC required).

        Args:
            device_id: Device to approve
            kyc_verified: Whether KYC was completed (validators only)

        Returns:
            True if approved
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                UPDATE devices
                SET status = ?, kyc_verified = ?
                WHERE device_id = ?
            ''', (DeviceStatus.ACTIVE.value, 1 if kyc_verified else 0, device_id))

            conn.commit()
            print(f"✓ Device {device_id} approved (KYC: {kyc_verified})")
            return True

        except Exception as e:
            print(f"Approval failed: {e}")
            return False
        finally:
            conn.close()

    def get_device(self, device_id: str) -> Optional[Dict]:
        """
        Get device record.

        Args:
            device_id: Device identifier

        Returns:
            Device record or None
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM devices WHERE device_id = ?
            ''', (device_id,))

            row = cursor.fetchone()
            if not row:
                return None

            device = dict(row)

            # Get location history
            cursor.execute('''
                SELECT * FROM device_locations
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT 10
            ''', (device_id,))

            locations = [dict(row) for row in cursor.fetchall()]
            device['location_history'] = locations

            return device

        finally:
            conn.close()

    def get_all_validators(self, active_only: bool = True) -> List[Dict]:
        """
        Get all validators in network.

        Args:
            active_only: Return only active validators

        Returns:
            List of validator records
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            query = '''
                SELECT * FROM devices
                WHERE device_type = ?
            '''
            params = [DeviceType.VALIDATOR.value]

            if active_only:
                query += ' AND status = ?'
                params.append(DeviceStatus.ACTIVE.value)

            cursor.execute(query, params)

            validators = [dict(row) for row in cursor.fetchall()]
            return validators

        finally:
            conn.close()

    def verify_hardware_fingerprint(self, device_id: str, current_fingerprint: str) -> bool:
        """
        Verify device hardware fingerprint matches registration.

        Args:
            device_id: Device identifier
            current_fingerprint: Current hardware fingerprint

        Returns:
            True if fingerprint matches
        """
        device = self.get_device(device_id)
        if not device:
            return False

        return device['hardware_fingerprint'] == current_fingerprint

    def _check_cloud_exists(self) -> bool:
        """Check if MSSP cloud component is deployed."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT COUNT(*) FROM devices
                WHERE device_type = ? AND status = ?
            ''', (DeviceType.CLOUD.value, DeviceStatus.ACTIVE.value))

            count = cursor.fetchone()[0]
            return count > 0

        finally:
            conn.close()

    def _record_location(
        self,
        cursor: sqlite3.Cursor,
        device_id: str,
        location: DeviceLocation,
        timestamp: int
    ):
        """Record device location in database."""
        cursor.execute('''
            INSERT INTO device_locations (
                device_id, timestamp, ip_address, country, region,
                city, latitude, longitude, asn, isp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            timestamp,
            location.ip_address,
            location.country,
            location.region,
            location.city,
            location.latitude,
            location.longitude,
            location.asn,
            location.isp
        ))

    def _geolocate_ip(self, ip_address: str) -> DeviceLocation:
        """
        Geolocate IP address.

        In production: Use MaxMind GeoIP2 or similar service.
        For now: Return mock data.

        Args:
            ip_address: IP address to geolocate

        Returns:
            Location information
        """
        # TODO: Integrate with GeoIP service
        # For now, return mock location based on IP

        return DeviceLocation(
            ip_address=ip_address,
            country="US",
            region="California",
            city="San Francisco",
            latitude=37.7749,
            longitude=-122.4194,
            asn=7922,
            isp="Comcast Cable"
        )


# Example usage
if __name__ == '__main__':
    print("=== MSSP Device Registry Test ===\n")

    registry = MSSPDeviceRegistry(db_path="/tmp/test_registry.db")

    # 1. Register cloud (prerequisite)
    print("1. Registering MSSP Cloud...")
    cloud_location = DeviceLocation(
        ip_address="203.0.113.10",
        country="US",
        region="Virginia",
        city="Ashburn",
        latitude=39.0438,
        longitude=-77.4874,
        asn=16509,
        isp="Amazon AWS"
    )

    registered = registry.register_device(
        device_id="cloud-001",
        device_type=DeviceType.CLOUD,
        hardware_fingerprint=hashlib.sha256(b"cloud-hw-12345").hexdigest(),
        public_key="cloud-pubkey-hex",
        firmware_version="1.0.0",
        location=cloud_location
    )

    if registered:
        registry.approve_device("cloud-001", kyc_verified=True)

    # 2. Try to register validator (should succeed now)
    print("\n2. Registering Validator...")
    validator_location = DeviceLocation(
        ip_address="198.51.100.20",
        country="DE",
        region="Hesse",
        city="Frankfurt",
        latitude=50.1109,
        longitude=8.6821,
        asn=3320,
        isp="Deutsche Telekom"
    )

    registered = registry.register_device(
        device_id="validator-001",
        device_type=DeviceType.VALIDATOR,
        hardware_fingerprint=hashlib.sha256(b"validator-hw-67890").hexdigest(),
        public_key="validator-pubkey-hex",
        firmware_version="1.0.0",
        location=validator_location
    )

    if registered:
        # Validators require KYC
        registry.approve_device("validator-001", kyc_verified=True)

    # 3. Register edge device
    print("\n3. Registering Edge Device...")
    edge_location = DeviceLocation(
        ip_address="192.0.2.30",
        country="US",
        region="California",
        city="Los Angeles",
        latitude=34.0522,
        longitude=-118.2437,
        asn=7922,
        isp="Comcast"
    )

    registered = registry.register_device(
        device_id="edge-001",
        device_type=DeviceType.EDGE,
        hardware_fingerprint=hashlib.sha256(b"edge-hw-abcdef").hexdigest(),
        public_key="edge-pubkey-hex",
        firmware_version="1.0.0",
        location=edge_location
    )

    if registered:
        registry.approve_device("edge-001", kyc_verified=False)

    # 4. Query validators
    print("\n4. Querying active validators...")
    validators = registry.get_all_validators(active_only=True)
    print(f"   Found {len(validators)} active validators:")
    for v in validators:
        print(f"     - {v['device_id']} (KYC: {bool(v['kyc_verified'])})")

    # 5. Update location
    print("\n5. Updating edge location (simulating movement)...")
    new_location = DeviceLocation(
        ip_address="192.0.2.31",  # New IP
        country="US",
        region="California",
        city="San Diego",
        latitude=32.7157,
        longitude=-117.1611,
        asn=7922,
        isp="Comcast"
    )
    registry.update_location("edge-001", new_location)

    # 6. Get device with location history
    print("\n6. Retrieving edge device with location history...")
    edge = registry.get_device("edge-001")
    if edge:
        print(f"   Device: {edge['device_id']}")
        print(f"   Status: {edge['status']}")
        print(f"   Location history: {len(edge['location_history'])} records")
        for loc in edge['location_history'][:3]:
            print(f"     - {loc['city']}, {loc['region']} ({loc['ip_address']})")

    print("\n✓ MSSP device registry test complete")
