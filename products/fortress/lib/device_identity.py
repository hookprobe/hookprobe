#!/usr/bin/env python3
"""
HookProbe Fortress - Device Identity Layer

Tracks device identity across MAC address randomization using persistent
identifiers like DHCP Option 55 fingerprint and mDNS device names.

The Problem:
  - Apple/Android devices randomize MAC every 30-60 minutes
  - Traditional tracking by MAC creates duplicate entries
  - "John's iPhone" becomes "John's iPhone 2", "John's iPhone 3", etc.

The Solution:
  - Track devices by persistent identifiers (DHCP Option 55, mDNS name)
  - Link multiple MACs to a single device identity
  - Maintain history of all MACs for audit trail

Usage:
    from device_identity import DeviceIdentityManager

    manager = DeviceIdentityManager()

    # When device is seen (DHCP or mDNS discovery)
    identity = manager.find_or_create_identity(
        mac="AA:BB:CC:DD:EE:FF",
        dhcp_option55="1,121,3,6,15,119,252",
        mdns_name="John's iPhone",
        hostname="Johns-iPhone"
    )

    # Get all MACs for a device
    macs = manager.get_device_macs(identity.identity_id)

    # Lookup identity by any MAC
    identity = manager.get_identity_by_mac("AA:BB:CC:DD:EE:FF")

Version: 1.0.0
License: Proprietary (HookProbe Commercial)
"""

import json
import logging
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Database path
DEFAULT_DB_PATH = "/var/lib/hookprobe/device_identity.db"


@dataclass
class DeviceIdentity:
    """Represents a persistent device identity across MAC changes."""

    identity_id: str
    canonical_name: str
    mdns_device_id: Optional[str] = None
    dhcp_option55: Optional[str] = None
    fingerbank_id: Optional[int] = None
    device_type: Optional[str] = None
    manufacturer: Optional[str] = None
    current_mac: Optional[str] = None
    all_macs: List[str] = field(default_factory=list)
    bubble_id: Optional[str] = None
    policy: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    @property
    def display_name(self) -> str:
        """
        Human-friendly display name for the device.

        Combines user-set friendly name with device model when both are available.
        Examples:
            - "hookprobe" (mDNS) + "iPhone 16 Pro" (type) = "hookprobe (iPhone 16 Pro)"
            - "hookprobe Pro" + "MacBook Pro" = "hookprobe Pro (MacBook Pro)"
            - "hooksound" + "HomePod mini" = "hooksound (HomePod mini)"
        """
        user_name = self.canonical_name or self.mdns_device_id

        # If we have both user name and device type, combine them
        if user_name and self.device_type:
            # Avoid duplication if user_name already contains device type
            device_lower = self.device_type.lower()
            user_lower = user_name.lower()

            # Check for common patterns to avoid "iPhone (iPhone)"
            if device_lower not in user_lower:
                return f"{user_name} ({self.device_type})"

        if user_name:
            return user_name
        if self.device_type and self.manufacturer:
            return f"{self.manufacturer} {self.device_type}"
        if self.current_mac:
            return f"Device-{self.current_mac[-8:].replace(':', '')}"
        return f"Unknown-{self.identity_id[:8]}"

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "identity_id": self.identity_id,
            "canonical_name": self.canonical_name,
            "display_name": self.display_name,
            "mdns_device_id": self.mdns_device_id,
            "dhcp_option55": self.dhcp_option55,
            "fingerbank_id": self.fingerbank_id,
            "device_type": self.device_type,
            "manufacturer": self.manufacturer,
            "current_mac": self.current_mac,
            "all_macs": self.all_macs,
            "bubble_id": self.bubble_id,
            "policy": self.policy,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class DeviceIdentityManager:
    """
    Manages device identities across MAC address randomization.

    Uses multiple signals to track device identity:
    1. mDNS device name (most reliable for Apple ecosystem)
    2. DHCP Option 55 fingerprint (stable across MAC changes)
    3. Hostname patterns
    4. Fingerbank device classification
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Create database and tables if they don't exist."""
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            Path(db_dir).mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            # Device identities table - persistent identity across MAC changes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_identities (
                    identity_id TEXT PRIMARY KEY,
                    canonical_name TEXT UNIQUE,
                    mdns_device_id TEXT,
                    dhcp_option55 TEXT,
                    fingerbank_id INTEGER,
                    device_type TEXT,
                    manufacturer TEXT,
                    current_mac TEXT,
                    all_macs TEXT,
                    bubble_id TEXT,
                    policy TEXT,
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)

            # Indexes for fast lookup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_identities_mdns
                ON device_identities(mdns_device_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_identities_dhcp
                ON device_identities(dhcp_option55)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_identities_mac
                ON device_identities(current_mac)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_identities_name
                ON device_identities(canonical_name)
            """)

            # MAC to Identity mapping table - links MACs to identities
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mac_to_identity (
                    mac TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL,
                    assigned_at TEXT,
                    dhcp_option55 TEXT,
                    hostname TEXT,
                    ip_address TEXT,
                    FOREIGN KEY (identity_id) REFERENCES device_identities(identity_id)
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_mac_identity
                ON mac_to_identity(identity_id)
            """)

            # MAC history table - tracks when MACs were seen
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mac_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    identity_id TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    times_seen INTEGER DEFAULT 1,
                    FOREIGN KEY (identity_id) REFERENCES device_identities(identity_id)
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_mac_history_mac
                ON mac_history(mac)
            """)

            conn.commit()
            logger.info(f"Device identity database initialized at {self.db_path}")

        finally:
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def find_or_create_identity(
        self,
        mac: str,
        dhcp_option55: Optional[str] = None,
        mdns_name: Optional[str] = None,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_type: Optional[str] = None,
        manufacturer: Optional[str] = None,
        fingerbank_id: Optional[int] = None,
    ) -> DeviceIdentity:
        """
        Find existing device identity or create new one.

        Links the MAC to the identity using persistent identifiers.
        This is the main entry point for device tracking.

        Priority order for identity matching:
        1. Existing MAC mapping (already linked)
        2. mDNS device name (most reliable for Apple)
        3. DHCP Option 55 + hostname pattern
        4. Create new identity

        Args:
            mac: MAC address of the device
            dhcp_option55: DHCP fingerprint (Option 55)
            mdns_name: mDNS/Bonjour device name (e.g., "John's iPhone")
            hostname: DHCP hostname
            ip_address: Current IP address
            device_type: Device classification (e.g., "iPhone", "MacBook")
            manufacturer: Device manufacturer (e.g., "Apple")
            fingerbank_id: Fingerbank device ID

        Returns:
            DeviceIdentity object (existing or newly created)
        """
        mac = self._normalize_mac(mac)
        now = datetime.now().isoformat()

        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # Step 1: Check if MAC is already linked to an identity
            cursor.execute(
                "SELECT identity_id FROM mac_to_identity WHERE mac = ?",
                (mac,)
            )
            row = cursor.fetchone()
            if row:
                identity = self._get_identity(cursor, row["identity_id"])
                if identity:
                    # Update last seen
                    self._update_last_seen(cursor, identity.identity_id, mac)
                    conn.commit()
                    logger.debug(f"MAC {mac} already linked to identity '{identity.canonical_name}'")
                    return identity

            # Step 2: Try to find identity by mDNS name (most reliable)
            if mdns_name:
                cursor.execute(
                    "SELECT * FROM device_identities WHERE canonical_name = ?",
                    (mdns_name,)
                )
                row = cursor.fetchone()
                if row:
                    identity = self._row_to_identity(row)
                    self._link_mac_to_identity(cursor, mac, identity.identity_id,
                                                dhcp_option55, hostname, ip_address)
                    self._update_last_seen(cursor, identity.identity_id, mac)
                    conn.commit()
                    logger.info(f"Linked new MAC {mac} to existing identity '{mdns_name}' (mDNS match)")
                    return identity

            # Step 3: Try to find identity by DHCP fingerprint + similar hostname
            if dhcp_option55 and hostname:
                cursor.execute(
                    """SELECT di.* FROM device_identities di
                       JOIN mac_to_identity mti ON di.identity_id = mti.identity_id
                       WHERE di.dhcp_option55 = ? AND mti.hostname LIKE ?
                       LIMIT 1""",
                    (dhcp_option55, self._hostname_pattern(hostname))
                )
                row = cursor.fetchone()
                if row:
                    identity = self._row_to_identity(row)
                    self._link_mac_to_identity(cursor, mac, identity.identity_id,
                                                dhcp_option55, hostname, ip_address)
                    self._update_last_seen(cursor, identity.identity_id, mac)
                    conn.commit()
                    logger.info(f"Linked new MAC {mac} to existing identity '{identity.canonical_name}' (DHCP+hostname match)")
                    return identity

            # Step 4: Try to find identity by DHCP fingerprint alone (less reliable)
            if dhcp_option55:
                cursor.execute(
                    "SELECT * FROM device_identities WHERE dhcp_option55 = ? LIMIT 1",
                    (dhcp_option55,)
                )
                row = cursor.fetchone()
                if row:
                    identity = self._row_to_identity(row)
                    # Only link if fingerprint is specific enough (not generic)
                    if self._is_specific_fingerprint(dhcp_option55):
                        self._link_mac_to_identity(cursor, mac, identity.identity_id,
                                                    dhcp_option55, hostname, ip_address)
                        self._update_last_seen(cursor, identity.identity_id, mac)
                        conn.commit()
                        logger.info(f"Linked new MAC {mac} to existing identity '{identity.canonical_name}' (DHCP fingerprint match)")
                        return identity

            # Step 5: Create new identity
            identity_id = str(uuid.uuid4())
            canonical_name = mdns_name or hostname or f"Device-{mac[-8:].replace(':', '')}"

            cursor.execute(
                """INSERT INTO device_identities
                   (identity_id, canonical_name, mdns_device_id, dhcp_option55,
                    fingerbank_id, device_type, manufacturer, current_mac, all_macs,
                    first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (identity_id, canonical_name, mdns_name, dhcp_option55,
                 fingerbank_id, device_type, manufacturer, mac, json.dumps([mac]),
                 now, now)
            )

            self._link_mac_to_identity(cursor, mac, identity_id,
                                        dhcp_option55, hostname, ip_address)

            conn.commit()

            identity = DeviceIdentity(
                identity_id=identity_id,
                canonical_name=canonical_name,
                mdns_device_id=mdns_name,
                dhcp_option55=dhcp_option55,
                fingerbank_id=fingerbank_id,
                device_type=device_type,
                manufacturer=manufacturer,
                current_mac=mac,
                all_macs=[mac],
                first_seen=datetime.fromisoformat(now),
                last_seen=datetime.fromisoformat(now),
            )

            logger.info(f"Created new device identity '{canonical_name}' for MAC {mac}")
            return identity

        finally:
            conn.close()

    def get_identity_by_mac(self, mac: str) -> Optional[DeviceIdentity]:
        """Get device identity by any of its MAC addresses."""
        mac = self._normalize_mac(mac)

        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT identity_id FROM mac_to_identity WHERE mac = ?",
                (mac,)
            )
            row = cursor.fetchone()
            if row:
                return self._get_identity(cursor, row["identity_id"])
            return None

        finally:
            conn.close()

    def get_device_macs(self, identity_id: str) -> List[str]:
        """Get all MAC addresses associated with a device identity."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT mac FROM mac_to_identity WHERE identity_id = ?",
                (identity_id,)
            )
            return [row["mac"] for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_all_identities(self) -> List[DeviceIdentity]:
        """Get all device identities."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM device_identities ORDER BY last_seen DESC")
            return [self._row_to_identity(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def update_identity(
        self,
        identity_id: str,
        bubble_id: Optional[str] = None,
        policy: Optional[str] = None,
        canonical_name: Optional[str] = None,
    ) -> bool:
        """Update device identity attributes."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            updates = []
            params = []

            if bubble_id is not None:
                updates.append("bubble_id = ?")
                params.append(bubble_id)

            if policy is not None:
                updates.append("policy = ?")
                params.append(policy)

            if canonical_name is not None:
                updates.append("canonical_name = ?")
                params.append(canonical_name)

            if not updates:
                return False

            updates.append("last_seen = ?")
            params.append(datetime.now().isoformat())
            params.append(identity_id)

            cursor.execute(
                f"UPDATE device_identities SET {', '.join(updates)} WHERE identity_id = ?",
                params
            )
            conn.commit()
            return cursor.rowcount > 0

        finally:
            conn.close()

    def merge_identities(self, keep_id: str, merge_id: str) -> bool:
        """
        Merge two device identities (when user corrects a false split).

        All MACs from merge_id are moved to keep_id.
        merge_id is then deleted.
        """
        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # Get both identities
            keep_identity = self._get_identity(cursor, keep_id)
            merge_identity = self._get_identity(cursor, merge_id)

            if not keep_identity or not merge_identity:
                return False

            # Move all MACs from merge to keep
            cursor.execute(
                "UPDATE mac_to_identity SET identity_id = ? WHERE identity_id = ?",
                (keep_id, merge_id)
            )

            # Update all_macs list
            all_macs = list(set(keep_identity.all_macs + merge_identity.all_macs))
            cursor.execute(
                "UPDATE device_identities SET all_macs = ?, last_seen = ? WHERE identity_id = ?",
                (json.dumps(all_macs), datetime.now().isoformat(), keep_id)
            )

            # Delete merged identity
            cursor.execute(
                "DELETE FROM device_identities WHERE identity_id = ?",
                (merge_id,)
            )

            conn.commit()
            logger.info(f"Merged identity '{merge_identity.canonical_name}' into '{keep_identity.canonical_name}'")
            return True

        finally:
            conn.close()

    def cleanup_stale_identities(self, days: int = 30) -> int:
        """Remove identities not seen for specified days."""
        from datetime import timedelta

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # Get stale identity IDs
            cursor.execute(
                "SELECT identity_id FROM device_identities WHERE last_seen < ?",
                (cutoff,)
            )
            stale_ids = [row["identity_id"] for row in cursor.fetchall()]

            if not stale_ids:
                return 0

            # Delete MAC mappings
            placeholders = ",".join("?" * len(stale_ids))
            cursor.execute(
                f"DELETE FROM mac_to_identity WHERE identity_id IN ({placeholders})",
                stale_ids
            )

            # Delete identities
            cursor.execute(
                f"DELETE FROM device_identities WHERE identity_id IN ({placeholders})",
                stale_ids
            )

            conn.commit()
            logger.info(f"Cleaned up {len(stale_ids)} stale device identities")
            return len(stale_ids)

        finally:
            conn.close()

    # ========== Private Methods ==========

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to uppercase with colons."""
        return mac.upper().replace("-", ":").strip()

    def _hostname_pattern(self, hostname: str) -> str:
        """
        Create SQL LIKE pattern for hostname matching.

        Strips common suffixes like numbers to match:
        "Johns-iPhone" with "Johns-iPhone-2"
        """
        # Remove trailing numbers and separators
        import re
        pattern = re.sub(r'[-_]?\d+$', '%', hostname)
        if not pattern.endswith('%'):
            pattern += '%'
        return pattern

    def _is_specific_fingerprint(self, dhcp_option55: str) -> bool:
        """
        Check if DHCP fingerprint is specific enough for matching.

        Generic fingerprints like "1,3,6" are too common.
        Specific fingerprints like "1,121,3,6,15,119,252" are reliable.
        """
        if not dhcp_option55:
            return False
        options = dhcp_option55.split(",")
        # Require at least 5 options for reliable matching
        return len(options) >= 5

    def _get_identity(self, cursor: sqlite3.Cursor, identity_id: str) -> Optional[DeviceIdentity]:
        """Get identity by ID."""
        cursor.execute(
            "SELECT * FROM device_identities WHERE identity_id = ?",
            (identity_id,)
        )
        row = cursor.fetchone()
        return self._row_to_identity(row) if row else None

    def _row_to_identity(self, row: sqlite3.Row) -> DeviceIdentity:
        """Convert database row to DeviceIdentity object."""
        all_macs = []
        if row["all_macs"]:
            try:
                all_macs = json.loads(row["all_macs"])
            except json.JSONDecodeError:
                all_macs = []

        first_seen = None
        if row["first_seen"]:
            try:
                first_seen = datetime.fromisoformat(row["first_seen"])
            except ValueError:
                pass

        last_seen = None
        if row["last_seen"]:
            try:
                last_seen = datetime.fromisoformat(row["last_seen"])
            except ValueError:
                pass

        return DeviceIdentity(
            identity_id=row["identity_id"],
            canonical_name=row["canonical_name"],
            mdns_device_id=row["mdns_device_id"],
            dhcp_option55=row["dhcp_option55"],
            fingerbank_id=row["fingerbank_id"],
            device_type=row["device_type"],
            manufacturer=row["manufacturer"],
            current_mac=row["current_mac"],
            all_macs=all_macs,
            bubble_id=row["bubble_id"],
            policy=row["policy"],
            first_seen=first_seen,
            last_seen=last_seen,
        )

    def _link_mac_to_identity(
        self,
        cursor: sqlite3.Cursor,
        mac: str,
        identity_id: str,
        dhcp_option55: Optional[str],
        hostname: Optional[str],
        ip_address: Optional[str],
    ) -> None:
        """Link a MAC address to a device identity."""
        now = datetime.now().isoformat()

        # Insert or replace MAC mapping
        cursor.execute(
            """INSERT OR REPLACE INTO mac_to_identity
               (mac, identity_id, assigned_at, dhcp_option55, hostname, ip_address)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (mac, identity_id, now, dhcp_option55, hostname, ip_address)
        )

        # Update identity's all_macs list
        cursor.execute(
            "SELECT all_macs FROM device_identities WHERE identity_id = ?",
            (identity_id,)
        )
        row = cursor.fetchone()
        if row:
            all_macs = []
            if row["all_macs"]:
                try:
                    all_macs = json.loads(row["all_macs"])
                except json.JSONDecodeError:
                    all_macs = []

            if mac not in all_macs:
                all_macs.append(mac)
                cursor.execute(
                    "UPDATE device_identities SET all_macs = ?, current_mac = ? WHERE identity_id = ?",
                    (json.dumps(all_macs), mac, identity_id)
                )

    def _update_last_seen(
        self,
        cursor: sqlite3.Cursor,
        identity_id: str,
        mac: str,
    ) -> None:
        """Update last_seen timestamp for identity."""
        now = datetime.now().isoformat()
        cursor.execute(
            "UPDATE device_identities SET last_seen = ?, current_mac = ? WHERE identity_id = ?",
            (now, mac, identity_id)
        )


# Singleton instance
_manager: Optional[DeviceIdentityManager] = None


def get_identity_manager(db_path: str = DEFAULT_DB_PATH) -> DeviceIdentityManager:
    """Get or create singleton DeviceIdentityManager instance."""
    global _manager
    if _manager is None:
        _manager = DeviceIdentityManager(db_path)
    return _manager


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Device Identity Manager")
    parser.add_argument("command", choices=["list", "lookup", "stats", "cleanup"])
    parser.add_argument("--mac", help="MAC address for lookup")
    parser.add_argument("--days", type=int, default=30, help="Days for cleanup")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Database path")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    manager = DeviceIdentityManager(args.db)

    if args.command == "list":
        identities = manager.get_all_identities()
        print(f"\n{'Name':<30} {'MAC Count':<10} {'Current MAC':<20} {'Last Seen':<20}")
        print("-" * 80)
        for identity in identities:
            print(f"{identity.canonical_name:<30} {len(identity.all_macs):<10} "
                  f"{identity.current_mac or 'N/A':<20} "
                  f"{identity.last_seen.strftime('%Y-%m-%d %H:%M') if identity.last_seen else 'N/A':<20}")

    elif args.command == "lookup":
        if not args.mac:
            print("Error: --mac required for lookup")
            exit(1)
        identity = manager.get_identity_by_mac(args.mac)
        if identity:
            print(json.dumps(identity.to_dict(), indent=2, default=str))
        else:
            print(f"No identity found for MAC {args.mac}")

    elif args.command == "stats":
        identities = manager.get_all_identities()
        total_macs = sum(len(i.all_macs) for i in identities)
        print(f"\nDevice Identity Statistics:")
        print(f"  Total identities: {len(identities)}")
        print(f"  Total MAC addresses: {total_macs}")
        print(f"  Avg MACs per device: {total_macs / len(identities):.1f}" if identities else "  No devices")

    elif args.command == "cleanup":
        removed = manager.cleanup_stale_identities(args.days)
        print(f"Removed {removed} stale identities (not seen in {args.days} days)")


# Alias for backward compatibility with DHCP hooks
# The DHCP event scripts use DeviceIdentityTracker name
DeviceIdentityTracker = DeviceIdentityManager
