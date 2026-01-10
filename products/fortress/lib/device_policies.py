#!/usr/bin/env python3
"""
Fortress Device Policy Manager - Hybrid SQLite/PostgreSQL device management

Network Policies:
- QUARANTINE: Unknown devices, no network access (default for unknowns)
- INTERNET_ONLY: Can access internet but not LAN devices
- LAN_ONLY: Can access LAN but not internet (IoT, printers)
- SMART_HOME: Curated IoT (HomePod, Echo, Matter/Thread bridges)
- FULL_ACCESS: Management devices with full network access

Storage:
- Policies: SQLite at /var/lib/hookprobe/devices.db
- Device Identity: PostgreSQL (when available) for real-time status

G.N.C. Phase 2: Integrated device identity correlation with DHCP lifecycle
"""

import sqlite3
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum
from contextlib import contextmanager

# Import security utilities for PII masking (CWE-532 mitigation)
from security_utils import mask_mac

logger = logging.getLogger(__name__)

# PostgreSQL connection settings (from environment or defaults)
PG_HOST = os.environ.get('DATABASE_HOST', '172.20.200.10')
PG_PORT = int(os.environ.get('DATABASE_PORT', '5432'))
PG_NAME = os.environ.get('DATABASE_NAME', 'fortress')
PG_USER = os.environ.get('DATABASE_USER', 'fortress')
PG_PASSWORD = os.environ.get('DATABASE_PASSWORD', 'fortress_db_secret')


class DeviceStatus(str, Enum):
    """Device connection status (from PostgreSQL device lifecycle)."""
    ONLINE = 'ONLINE'       # Active DHCP lease, recently seen
    STALE = 'STALE'         # No activity for >30 mins but lease valid
    OFFLINE = 'OFFLINE'     # Released lease or >24h inactive
    EXPIRED = 'EXPIRED'     # No activity for >30 days, candidate for removal


# Status display info for UI
STATUS_INFO = {
    DeviceStatus.ONLINE: {
        'name': 'Online',
        'icon': 'fa-circle',
        'color': 'success',
        'description': 'Device is active on the network',
    },
    DeviceStatus.STALE: {
        'name': 'Stale',
        'icon': 'fa-clock',
        'color': 'warning',
        'description': 'Device inactive for >30 minutes',
    },
    DeviceStatus.OFFLINE: {
        'name': 'Offline',
        'icon': 'fa-circle-xmark',
        'color': 'secondary',
        'description': 'Device disconnected or lease expired',
    },
    DeviceStatus.EXPIRED: {
        'name': 'Expired',
        'icon': 'fa-ghost',
        'color': 'dark',
        'description': 'Device not seen for >30 days',
    },
}


def _get_pg_connection():
    """Get PostgreSQL connection if available."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_NAME,
            user=PG_USER,
            password=PG_PASSWORD,
            connect_timeout=5,
        )
        return conn
    except Exception as e:
        logger.debug(f"PostgreSQL not available: {e}")
        return None


def _load_devices_from_postgres() -> Optional[List[Dict]]:
    """Load devices from PostgreSQL v_devices_with_identity view.

    Returns None if PostgreSQL is unavailable, otherwise a list of device dicts.
    """
    conn = _get_pg_connection()
    if not conn:
        return None

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    mac_address,
                    ip_address,
                    hostname,
                    manufacturer,
                    device_type,
                    status,
                    canonical_name,
                    identity_id,
                    first_seen,
                    last_seen,
                    stale_at,
                    offline_at,
                    dhcp_lease_expiry,
                    dhcp_option55,
                    dhcp_option61,
                    is_mac_randomized
                FROM v_devices_with_identity
                ORDER BY
                    CASE status
                        WHEN 'ONLINE' THEN 1
                        WHEN 'STALE' THEN 2
                        WHEN 'OFFLINE' THEN 3
                        ELSE 4
                    END,
                    last_seen DESC NULLS LAST
            """)

            columns = [desc[0] for desc in cur.description]
            devices = []
            for row in cur.fetchall():
                device = dict(zip(columns, row))
                # Convert datetime objects to ISO strings
                for key in ('first_seen', 'last_seen', 'stale_at', 'offline_at', 'dhcp_lease_expiry'):
                    if device.get(key) and hasattr(device[key], 'isoformat'):
                        device[key] = device[key].isoformat()
                # Convert inet to string
                if device.get('ip_address'):
                    device['ip_address'] = str(device['ip_address'])
                # Convert UUID to string
                if device.get('identity_id'):
                    device['identity_id'] = str(device['identity_id'])
                devices.append(device)

            return devices
    except Exception as e:
        logger.warning(f"Failed to load devices from PostgreSQL: {e}")
        return None
    finally:
        conn.close()


def _decode_dnsmasq_hostname(hostname: str) -> str:
    """Decode dnsmasq octal escapes (e.g., \\123 -> ASCII char)."""
    if not hostname or '\\' not in hostname:
        return hostname
    try:
        result = b''
        i = 0
        while i < len(hostname):
            # Bug fix: was i + 3 < len, should be <= to handle escapes at end of string
            if hostname[i] == '\\' and i + 3 <= len(hostname):
                octal_str = hostname[i+1:i+4]
                if all(c in '01234567' for c in octal_str):
                    result += bytes([int(octal_str, 8)])
                    i += 4
                    continue
            result += hostname[i].encode('utf-8', errors='replace')
            i += 1
        return result.decode('utf-8', errors='replace').strip()
    except Exception:
        return hostname


def _clean_device_name(hostname: str, manufacturer: str = None) -> Optional[str]:
    """Clean device hostname, returning None if unusable.

    Handles:
    - dnsmasq octal escapes (\\123)
    - Hex prefixes (F6574fcbe4474hookprobepro -> hookprobepro)
    - UUID-like strings (return None)
    - Trailing numbers with punctuation ( 652!, 9!)
    - Auto-incremented numbers from OS conflicts (Hookprobe 10, Hookprobe's iPad 119)
    """
    if not hostname:
        return None

    name = _decode_dnsmasq_hostname(hostname)
    if not name:
        return None

    # Remove .local suffix first
    if name.endswith('.local'):
        name = name[:-6]

    # Remove hex prefixes (e.g., "F6574fcbe4474hookprobepro" -> "hookprobepro")
    hex_prefix_match = re.match(r'^[0-9a-fA-F]{8,}[-_]?(.+)$', name)
    if hex_prefix_match:
        remaining = hex_prefix_match.group(1)
        # Only use if remaining part looks like a real name (has letters)
        if re.search(r'[a-zA-Z]{3,}', remaining):
            name = remaining

    # Remove hex/UUID suffixes (e.g., "device-abc123def456")
    name = re.sub(r'[-_][0-9a-fA-F]{6,}(?:[-_]\d+)?$', '', name)

    # Remove trailing numbers with punctuation (e.g., " 652!", " 9!")
    name = re.sub(r'\s+\d+[!@#$%^&*]+$', '', name)

    # Remove pure UUID-like strings - return None to use fallback
    if re.match(r'^[0-9a-fA-F]{8}[-_ ][0-9a-fA-F]{4}[-_ ][0-9a-fA-F]{4}', name):
        return None

    # Remove trailing punctuation artifacts
    name = re.sub(r'[!@#$%^&*]+$', '', name)

    # Clean up whitespace and special chars
    name = re.sub(r'[-_]+', ' ', name)
    name = re.sub(r'\s+', ' ', name).strip()

    # Remove OS auto-incremented numbers (e.g., "Hookprobe 10", "Hookprobe's iPad 119")
    # These are added when a device sees a name conflict on the network.
    # Pattern: name followed by space and number
    trailing_num_match = re.match(r'^(.+?)\s+(\d+)$', name)
    if trailing_num_match:
        base_name = trailing_num_match.group(1)
        num = int(trailing_num_match.group(2))

        # Keep legitimate product model numbers - these patterns are unlikely auto-increment
        # iPhone 15, Galaxy S24, Pixel 8, iPad Pro 12, Watch 9, etc.
        model_patterns = [
            r'(?i)\biphone\s*\d{1,2}$',        # iPhone 11, iPhone 15
            r'(?i)\bipad\s*(pro|air|mini)?\s*\d{1,2}$',  # iPad Pro 12
            r'(?i)\bgalaxy\s*[sazm]\d{1,2}$',  # Galaxy S24
            r'(?i)\bpixel\s*\d{1,2}$',         # Pixel 8
            r'(?i)\bwatch\s*(se|ultra)?\s*\d{1,2}$',  # Watch 9, Watch Ultra 2
            r'(?i)\bmacbook\s*(pro|air)?\s*\d{2,4}$', # MacBook Pro 2023
            r'(?i)\bsurface\s*(pro|go|laptop)?\s*\d{1,2}$',  # Surface Pro 9
            r'(?i)\bps\d$',                     # PS5
            r'(?i)\bxbox\s*(one|series)?\s*[sx]?$',  # Xbox Series X
            r'(?i)\becho\s*(dot|show)?\s*\d{1,2}$',  # Echo Dot 5
        ]

        is_model_number = any(re.search(p, name) for p in model_patterns)

        # Strip the number if:
        # 1. It's a high number (>20) - unlikely to be a real model number
        # 2. Name contains possessive ('s) - user's personal device with conflict number
        # 3. Base name ends with common device words but isn't a known model pattern
        is_possessive = "'s" in base_name.lower() or "'s" in base_name
        is_high_number = num > 20

        if not is_model_number and (is_high_number or is_possessive or num > 9):
            name = base_name

    # If name is mostly hex/numbers, return None for fallback
    if name and len(re.sub(r'[0-9a-fA-F\s-]', '', name)) < 3:
        return None

    if not name or len(name) < 2:
        return None

    return name


def _get_friendly_name(mac: str, hostname: str, manufacturer: str, device_type: str) -> str:
    """Generate a user-friendly device name.

    Priority:
    1. Cleaned hostname (if usable)
    2. Device type + last 4 MAC chars (e.g., "iPhone CE05")
    3. Manufacturer + last 4 MAC chars (e.g., "Apple CE05")
    4. Generic "Device CE05"
    """
    # Try cleaned hostname first
    cleaned = _clean_device_name(hostname, manufacturer)
    if cleaned:
        return cleaned

    # Get last 4 MAC chars for uniqueness
    mac_suffix = mac[-5:].replace(':', '') if mac else '????'

    # Try device type
    if device_type and device_type.lower() not in ('unknown', '', 'none'):
        # Make device type more readable
        dt = device_type.replace('_', ' ').title()
        return f"{dt} {mac_suffix}"

    # Try manufacturer
    if manufacturer and manufacturer.lower() not in ('unknown', 'private', '', 'none'):
        return f"{manufacturer} {mac_suffix}"

    # Fallback
    return f"Device {mac_suffix}"

# Database path
DB_PATH = Path('/var/lib/hookprobe/devices.db')
AGENT_DATA_FILE = Path('/opt/hookprobe/fortress/data/devices.json')


class NetworkPolicy(str, Enum):
    """Network access policies for devices."""
    QUARANTINE = 'quarantine'       # No network access - unknown devices
    INTERNET_ONLY = 'internet_only' # Internet access, no LAN
    LAN_ONLY = 'lan_only'           # LAN access, no internet
    SMART_HOME = 'smart_home'       # Curated IoT (bridges, smart home)
    FULL_ACCESS = 'full_access'     # Full access, can manage others


# Policy display info
POLICY_INFO = {
    NetworkPolicy.QUARANTINE: {
        'name': 'Quarantine',
        'icon': 'fa-ban',
        'color': 'danger',
        'description': 'No network access - unknown/suspicious device',
        'internet': False,
        'lan': False,
    },
    NetworkPolicy.INTERNET_ONLY: {
        'name': 'Internet Only',
        'icon': 'fa-globe',
        'color': 'info',
        'description': 'Can access internet but not local devices',
        'internet': True,
        'lan': False,
    },
    NetworkPolicy.LAN_ONLY: {
        'name': 'LAN Only',
        'icon': 'fa-network-wired',
        'color': 'warning',
        'description': 'Can access local network but not internet',
        'internet': False,
        'lan': True,
    },
    NetworkPolicy.SMART_HOME: {
        'name': 'Smart Home',
        'icon': 'fa-home',
        'color': 'success',
        'description': 'Smart home devices with curated access',
        'internet': True,
        'lan': True,
    },
    NetworkPolicy.FULL_ACCESS: {
        'name': 'Full Access',
        'icon': 'fa-shield-alt',
        'color': 'primary',
        'description': 'Management device with full network access',
        'internet': True,
        'lan': True,
    },
}


class DevicePolicyDB:
    """SQLite-based device policy storage."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._ensure_db()

    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    mac_address TEXT PRIMARY KEY,
                    hostname TEXT,
                    manufacturer TEXT,
                    device_type TEXT,
                    policy TEXT DEFAULT 'quarantine',
                    notes TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_devices_policy ON devices(policy)
            ''')
            conn.commit()

    @contextmanager
    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def get_device(self, mac: str) -> Optional[Dict]:
        """Get device by MAC address."""
        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT * FROM devices WHERE mac_address = ?',
                (mac.upper(),)
            ).fetchone()
            return dict(row) if row else None

    def set_policy(self, mac: str, policy: str, hostname: str = None,
                   manufacturer: str = None, device_type: str = None,
                   notes: str = None) -> Dict:
        """Set or update device policy.

        This method:
        1. Stores the policy in SQLite database
        2. Applies OpenFlow rules via device_data_manager for enforcement
        """
        mac = mac.upper()
        now = datetime.now().isoformat()

        # Validate policy
        try:
            policy_enum = NetworkPolicy(policy)
        except ValueError:
            raise ValueError(f"Invalid policy: {policy}")

        with self._get_conn() as conn:
            existing = self.get_device(mac)

            if existing:
                # Update existing
                conn.execute('''
                    UPDATE devices SET
                        policy = ?,
                        hostname = COALESCE(?, hostname),
                        manufacturer = COALESCE(?, manufacturer),
                        device_type = COALESCE(?, device_type),
                        notes = COALESCE(?, notes),
                        last_seen = ?,
                        updated_at = ?
                    WHERE mac_address = ?
                ''', (policy, hostname, manufacturer, device_type, notes, now, now, mac))
            else:
                # Insert new
                conn.execute('''
                    INSERT INTO devices (mac_address, policy, hostname, manufacturer,
                                        device_type, notes, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (mac, policy, hostname, manufacturer, device_type, notes, now, now))

            conn.commit()

        # Apply OpenFlow rules for actual network enforcement
        self._apply_openflow_rules(mac, policy)

        return self.get_device(mac)

    def _apply_openflow_rules(self, mac: str, policy: str):
        """Apply OpenFlow rules via device_data_manager for NAC enforcement.

        Policy name mapping for compatibility:
        - quarantine -> isolated (both mean block all)
        """
        # Map device_policies names to device_data_manager names
        policy_map = {
            'quarantine': 'isolated',
        }
        internal_policy = policy_map.get(policy, policy)

        try:
            # Try different import paths for flexibility
            ddm = None
            try:
                # When running from same directory or lib/ is in path
                from device_data_manager import get_device_data_manager
                ddm = get_device_data_manager()
            except ImportError:
                try:
                    # When running from web module
                    import sys
                    from pathlib import Path
                    lib_path = Path(__file__).parent
                    if str(lib_path) not in sys.path:
                        sys.path.insert(0, str(lib_path))
                    from device_data_manager import get_device_data_manager
                    ddm = get_device_data_manager()
                except ImportError:
                    pass

            if ddm:
                ddm._apply_policy_rules(mac, internal_policy)
                logger.debug(f"Applied OpenFlow rules for {mac} with policy {internal_policy}")
            else:
                logger.warning("device_data_manager not available - OpenFlow rules not applied")

        except Exception as e:
            logger.warning(f"Failed to apply OpenFlow rules for {mac}: {e}")

    def get_all_policies(self) -> Dict[str, str]:
        """Get all MAC -> policy mappings."""
        with self._get_conn() as conn:
            rows = conn.execute('SELECT mac_address, policy FROM devices').fetchall()
            return {row['mac_address']: row['policy'] for row in rows}

    def get_devices_by_policy(self, policy: str) -> List[Dict]:
        """Get all devices with a specific policy."""
        with self._get_conn() as conn:
            rows = conn.execute(
                'SELECT * FROM devices WHERE policy = ? ORDER BY last_seen DESC',
                (policy,)
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_device(self, mac: str) -> bool:
        """Delete a device from the database."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                'DELETE FROM devices WHERE mac_address = ?',
                (mac.upper(),)
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self) -> Dict:
        """Get device statistics by policy."""
        with self._get_conn() as conn:
            rows = conn.execute('''
                SELECT policy, COUNT(*) as count FROM devices GROUP BY policy
            ''').fetchall()
            stats = {p.value: 0 for p in NetworkPolicy}
            for row in rows:
                stats[row['policy']] = row['count']
            stats['total'] = sum(stats.values())
            return stats


# Global instance
_db: Optional[DevicePolicyDB] = None


def get_device_db() -> DevicePolicyDB:
    """Get the global device policy database instance."""
    global _db
    if _db is None:
        _db = DevicePolicyDB()
    return _db


def load_agent_devices() -> List[Dict]:
    """Load devices from qsecbit agent data file."""
    if not AGENT_DATA_FILE.exists():
        logger.debug(f"Agent data file not found: {AGENT_DATA_FILE}")
        return []

    try:
        data = json.loads(AGENT_DATA_FILE.read_text())
        devices = data.get('devices', []) if isinstance(data, dict) else data
        if isinstance(devices, list):
            return [d for d in devices if isinstance(d, dict)]
        return []
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load agent devices: {e}")
        return []


def should_quarantine(device: Dict) -> bool:
    """Determine if a device should be auto-quarantined."""
    # Quarantine if: no hostname AND unknown manufacturer AND unknown type
    hostname = device.get('hostname')
    manufacturer = device.get('manufacturer', 'Unknown')
    device_type = device.get('device_type', 'unknown')

    no_hostname = not hostname or hostname in ('', '*', 'unknown', None)
    unknown_vendor = manufacturer in ('Unknown', 'Private', '', None)
    unknown_type = device_type in ('unknown', '', None)

    return no_hostname and unknown_vendor and unknown_type


def get_recommended_policy(device: Dict) -> str:
    """Get recommended policy based on device characteristics."""
    device_type = device.get('device_type', 'unknown').lower()
    manufacturer = device.get('manufacturer', '').lower()

    # Smart home hubs/bridges get SMART_HOME (they need both internet and LAN)
    if device_type in ('homepod', 'echo', 'google_home', 'smart_hub', 'bridge'):
        return NetworkPolicy.SMART_HOME.value

    # IoT devices get LAN_ONLY
    if device_type in ('iot', 'camera', 'printer', 'smart_plug', 'sensor'):
        return NetworkPolicy.LAN_ONLY.value

    # Phones, tablets, laptops get INTERNET_ONLY by default
    if device_type in ('iphone', 'android', 'phone', 'tablet', 'laptop', 'macbook'):
        return NetworkPolicy.INTERNET_ONLY.value

    # Raspberry Pi on management interface gets FULL_ACCESS
    if device_type == 'raspberry_pi':
        return NetworkPolicy.FULL_ACCESS.value

    # Unknown devices get quarantined
    if should_quarantine(device):
        return NetworkPolicy.QUARANTINE.value

    return NetworkPolicy.INTERNET_ONLY.value


def get_all_devices(use_postgres: bool = True) -> List[Dict]:
    """Get all devices merged with their policies.

    Data sources (in priority order):
    1. PostgreSQL v_devices_with_identity (if available and use_postgres=True)
    2. QSecBit agent JSON file merged with SQLite policies

    Auto-assigns policies to new devices based on their characteristics.

    Args:
        use_postgres: Try PostgreSQL first (default True). Set False to force legacy mode.
    """
    db = get_device_db()
    stored_policies = db.get_all_policies()
    now = datetime.now().isoformat()

    # Try PostgreSQL first for real-time device status
    pg_devices = _load_devices_from_postgres() if use_postgres else None

    if pg_devices is not None:
        # PostgreSQL mode - real-time identity-based tracking
        logger.debug(f"Using PostgreSQL: {len(pg_devices)} devices with identity tracking")
        return _process_postgres_devices(pg_devices, db, stored_policies, now)

    # Fallback to legacy mode (agent JSON + SQLite)
    logger.debug("Using legacy mode: agent JSON + SQLite")
    agent_devices = load_agent_devices()
    return _process_legacy_devices(agent_devices, db, stored_policies, now)


def _process_postgres_devices(pg_devices: List[Dict], db: 'DevicePolicyDB',
                               stored_policies: Dict[str, str], now: str) -> List[Dict]:
    """Process devices from PostgreSQL with identity tracking."""
    devices = []

    for device in pg_devices:
        mac = device.get('mac_address', '').upper()
        if not mac:
            continue

        # Get stored policy or assign new one
        if mac in stored_policies:
            policy = stored_policies[mac]
        else:
            # New device - auto-assign policy
            policy = get_recommended_policy(device)
            db.set_policy(
                mac=mac,
                policy=policy,
                hostname=device.get('hostname'),
                manufacturer=device.get('manufacturer'),
                device_type=device.get('device_type'),
            )
            logger.info(f"New device {mask_mac(mac)}: auto-assigned policy '{policy}'")

        # Get policy info
        try:
            policy_enum = NetworkPolicy(policy)
            policy_info = POLICY_INFO.get(policy_enum, POLICY_INFO[NetworkPolicy.QUARANTINE])
        except ValueError:
            policy_info = POLICY_INFO[NetworkPolicy.QUARANTINE]

        # Get status info
        status_str = device.get('status', 'OFFLINE')
        try:
            status_enum = DeviceStatus(status_str)
            status_info = STATUS_INFO.get(status_enum, STATUS_INFO[DeviceStatus.OFFLINE])
        except ValueError:
            status_info = STATUS_INFO[DeviceStatus.OFFLINE]

        # Use canonical_name if available (identity-based), otherwise generate friendly name
        raw_hostname = device.get('hostname')
        canonical_name = device.get('canonical_name')
        manufacturer = device.get('manufacturer', 'Unknown') or 'Unknown'
        device_type = device.get('device_type', 'unknown') or 'unknown'

        # Prefer canonical name (stable across MAC changes), then cleaned hostname
        if canonical_name and canonical_name != raw_hostname:
            display_name = canonical_name
        else:
            display_name = _get_friendly_name(mac, raw_hostname, manufacturer, device_type)

        devices.append({
            'mac_address': mac,
            'ip_address': device.get('ip_address', ''),
            'hostname': display_name,
            'raw_hostname': raw_hostname,
            'canonical_name': canonical_name,
            'manufacturer': manufacturer,
            'device_type': device_type,
            'policy': policy,
            'policy_name': policy_info['name'],
            'policy_icon': policy_info['icon'],
            'policy_color': policy_info['color'],
            'internet_access': policy_info['internet'],
            'lan_access': policy_info['lan'],
            # Real-time status from PostgreSQL
            'status': status_str,
            'status_name': status_info['name'],
            'status_icon': status_info['icon'],
            'status_color': status_info['color'],
            'is_online': status_str == 'ONLINE',
            'is_stale': status_str == 'STALE',
            # Identity tracking
            'identity_id': device.get('identity_id'),
            'is_mac_randomized': device.get('is_mac_randomized', False),
            'dhcp_option55': device.get('dhcp_option55'),
            'dhcp_option61': device.get('dhcp_option61'),
            # Timestamps
            'first_seen': device.get('first_seen', now),
            'last_seen': device.get('last_seen', now),
            'dhcp_lease_expiry': device.get('dhcp_lease_expiry'),
            'stale_at': device.get('stale_at'),
            'offline_at': device.get('offline_at'),
            'interface': '',  # Not tracked in PostgreSQL yet
            'notes': '',
        })

    return devices


def _process_legacy_devices(agent_devices: List[Dict], db: 'DevicePolicyDB',
                            stored_policies: Dict[str, str], now: str) -> List[Dict]:
    """Process devices from legacy agent JSON + SQLite mode."""
    devices = []

    for device in agent_devices:
        if not isinstance(device, dict):
            continue

        mac = device.get('mac_address', '').upper()
        if not mac:
            continue

        # Get stored policy or assign new one
        if mac in stored_policies:
            policy = stored_policies[mac]
            stored = db.get_device(mac)
        else:
            # New device - auto-assign policy
            policy = get_recommended_policy(device)
            stored = db.set_policy(
                mac=mac,
                policy=policy,
                hostname=device.get('hostname'),
                manufacturer=device.get('manufacturer'),
                device_type=device.get('device_type'),
            )
            logger.info(f"New device {mask_mac(mac)}: auto-assigned policy '{policy}'")

        # Get policy info
        try:
            policy_enum = NetworkPolicy(policy)
            policy_info = POLICY_INFO.get(policy_enum, POLICY_INFO[NetworkPolicy.QUARANTINE])
        except ValueError:
            policy_info = POLICY_INFO[NetworkPolicy.QUARANTINE]

        # Merge device data
        raw_hostname = device.get('hostname') or (stored.get('hostname') if stored else None)
        manufacturer = device.get('manufacturer') or (stored.get('manufacturer') if stored else 'Unknown') or 'Unknown'
        device_type = device.get('device_type') or (stored.get('device_type') if stored else 'unknown') or 'unknown'

        # Infer status from agent state
        agent_state = device.get('state', '')
        if agent_state in ('REACHABLE', 'DELAY'):
            status = 'ONLINE'
        elif agent_state in ('STALE',):
            status = 'STALE'
        else:
            status = 'OFFLINE'

        try:
            status_enum = DeviceStatus(status)
            status_info = STATUS_INFO.get(status_enum, STATUS_INFO[DeviceStatus.OFFLINE])
        except ValueError:
            status_info = STATUS_INFO[DeviceStatus.OFFLINE]

        devices.append({
            'mac_address': mac,
            'ip_address': device.get('ip_address', ''),
            'hostname': _get_friendly_name(mac, raw_hostname, manufacturer, device_type),
            'raw_hostname': raw_hostname,
            'canonical_name': None,  # Not available in legacy mode
            'manufacturer': manufacturer,
            'device_type': device_type,
            'policy': policy,
            'policy_name': policy_info['name'],
            'policy_icon': policy_info['icon'],
            'policy_color': policy_info['color'],
            'internet_access': policy_info['internet'],
            'lan_access': policy_info['lan'],
            'status': status,
            'status_name': status_info['name'],
            'status_icon': status_info['icon'],
            'status_color': status_info['color'],
            'is_online': status == 'ONLINE',
            'is_stale': status == 'STALE',
            'identity_id': None,
            'is_mac_randomized': False,
            'dhcp_option55': None,
            'dhcp_option61': None,
            'first_seen': stored.get('first_seen', now) if stored else now,
            'last_seen': device.get('last_seen', now),
            'dhcp_lease_expiry': None,
            'stale_at': None,
            'offline_at': None,
            'interface': device.get('interface', ''),
            'notes': stored.get('notes', '') if stored else '',
        })

    return devices


def get_device_stats() -> Dict:
    """Get device statistics including status breakdown."""
    devices = get_all_devices()
    stats = {
        'total': len(devices),
        'online': len([d for d in devices if d.get('status') == 'ONLINE']),
        'stale': len([d for d in devices if d.get('status') == 'STALE']),
        'offline': len([d for d in devices if d.get('status') == 'OFFLINE']),
        'expired': len([d for d in devices if d.get('status') == 'EXPIRED']),
        'quarantined': len([d for d in devices if d['policy'] == 'quarantine']),
        'mac_randomized': len([d for d in devices if d.get('is_mac_randomized')]),
        'with_identity': len([d for d in devices if d.get('identity_id')]),
        'by_policy': {},
        'by_status': {},
    }
    for policy in NetworkPolicy:
        stats['by_policy'][policy.value] = len([d for d in devices if d['policy'] == policy.value])
    for status in DeviceStatus:
        stats['by_status'][status.value] = len([d for d in devices if d.get('status') == status.value])
    return stats


def get_status_info(status: str) -> Dict:
    """Get status display information."""
    try:
        status_enum = DeviceStatus(status)
        return STATUS_INFO.get(status_enum, STATUS_INFO[DeviceStatus.OFFLINE])
    except ValueError:
        return STATUS_INFO[DeviceStatus.OFFLINE]


def get_devices_by_status(status: str) -> List[Dict]:
    """Get all devices with a specific status."""
    devices = get_all_devices()
    return [d for d in devices if d.get('status') == status]


def get_devices_by_identity(identity_id: str) -> List[Dict]:
    """Get all devices (MACs) linked to a specific identity."""
    devices = get_all_devices()
    return [d for d in devices if d.get('identity_id') == identity_id]


def purge_expired_devices(dry_run: bool = True) -> List[Dict]:
    """Remove EXPIRED devices from the database.

    Args:
        dry_run: If True, only return devices that would be removed.

    Returns:
        List of devices that were (or would be) removed.
    """
    devices = get_all_devices()
    expired = [d for d in devices if d.get('status') == 'EXPIRED']

    if dry_run:
        return expired

    conn = _get_pg_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                for device in expired:
                    cur.execute(
                        "DELETE FROM devices WHERE mac_address = %s",
                        (device['mac_address'],)
                    )
            conn.commit()
            logger.info(f"Purged {len(expired)} expired devices from PostgreSQL")
        except Exception as e:
            logger.error(f"Failed to purge expired devices: {e}")
            conn.rollback()
        finally:
            conn.close()

    # Also clean SQLite policies
    db = get_device_db()
    for device in expired:
        db.delete_device(device['mac_address'])

    return expired


def set_device_policy(mac: str, policy: str) -> Dict:
    """Set device policy."""
    db = get_device_db()
    return db.set_policy(mac, policy)


def get_policy_info(policy: str) -> Dict:
    """Get policy display information."""
    try:
        policy_enum = NetworkPolicy(policy)
        return POLICY_INFO.get(policy_enum, POLICY_INFO[NetworkPolicy.QUARANTINE])
    except ValueError:
        return POLICY_INFO[NetworkPolicy.QUARANTINE]


def sync_all_policies() -> int:
    """
    Sync all stored policies to OpenFlow rules.

    Call this on startup to restore NAC enforcement after reboot.
    OpenFlow rules in OVS are volatile and lost on restart, but
    policies persist in SQLite database.

    Returns:
        Number of policies synced
    """
    db = get_device_db()
    policies = db.get_all_policies()

    synced = 0
    for mac, policy in policies.items():
        try:
            db._apply_openflow_rules(mac, policy)
            synced += 1
        except Exception as e:
            logger.warning(f"Failed to sync policy for {mac}: {e}")

    logger.info(f"Synced {synced}/{len(policies)} device policies to OpenFlow")
    return synced
