#!/usr/bin/env python3
"""
Fortress SDN Auto Pilot - Premium Heuristic Scoring Engine

Philosophy: "Guilty until proven Innocent"
Goal: 99% accuracy device classification using multiple identity signals.

Identity Stack (via Fingerbank module):
- DHCP Option 55 Fingerprint (50%): OS/Device "DNA" - hardest to spoof
- MAC OUI Vendor (20%): Manufacturer identification (30,000+ vendors)
- Hostname Analysis (20%): User-assigned name patterns
- Fuzzy Matching: Similar fingerprint detection
- Fingerbank API: Cloud lookup for unknown devices

Policies (matching device_policies.py):
- QUARANTINE: Unknown devices, no network access (default)
- INTERNET_ONLY: Can access internet but not LAN devices
- LAN_ONLY: Can access LAN but not internet (IoT, printers)
- SMART_HOME: Curated IoT (HomePod, Echo, Matter/Thread bridges)
- FULL_ACCESS: Management devices with full access

Storage: SQLite database at /var/lib/hookprobe/autopilot.db
"""

import sqlite3
import json
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager
from dataclasses import dataclass

# Import comprehensive Fingerbank module
try:
    from fingerbank import Fingerbank, get_fingerbank, DeviceInfo, CATEGORY_POLICIES
    HAS_FINGERBANK = True
except ImportError:
    HAS_FINGERBANK = False

# Import mDNS resolver for premium friendly names
try:
    from mdns_resolver import MDNSResolver, IdentityConsolidator, resolve_premium_name
    HAS_MDNS = True
except ImportError:
    HAS_MDNS = False

# Import hostname decoder for cleaning device names
try:
    from hostname_decoder import clean_device_name
    HAS_HOSTNAME_DECODER = True
except ImportError:
    HAS_HOSTNAME_DECODER = False
    def clean_device_name(name, max_length=32):
        """Fallback - just return the name."""
        return name

logger = logging.getLogger(__name__)

# Database paths
AUTOPILOT_DB = Path('/var/lib/hookprobe/autopilot.db')
FINGERPRINT_DB_FILE = Path('/opt/hookprobe/fortress/data/dhcp_fingerprints.json')

# Trigger files for host-side scripts (container can't run OVS commands)
NAC_POLICY_TRIGGER_FILE = Path('/opt/hookprobe/fortress/data/.nac_policy_sync')

# Network configuration
GATEWAY_IP = "10.200.0.1"
LAN_SUBNET = "10.200.0.0/23"

# Blocked MACs file - devices that have been manually disconnected/deleted
# These should not be auto-recreated by sync_device() or ensure_device_exists()
BLOCKED_MACS_FILE = Path('/var/lib/hookprobe/blocked_macs.json')


def _load_blocked_macs() -> set:
    """Load set of blocked MAC addresses.

    Blocked MACs are devices that have been manually disconnected/deleted.
    They should not be auto-recreated by device discovery.
    """
    try:
        if BLOCKED_MACS_FILE.exists():
            data = json.loads(BLOCKED_MACS_FILE.read_text())
            if isinstance(data, list):
                return {mac.upper() for mac in data if isinstance(mac, str)}
    except (json.JSONDecodeError, IOError) as e:
        logger.debug(f"Failed to load blocked MACs: {e}")
    return set()


def _is_mac_blocked(mac: str) -> bool:
    """Check if a MAC address is in the blocked list."""
    mac = mac.upper().replace('-', ':')
    return mac in _load_blocked_macs()


# =============================================================================
# DHCP Option 55 Fingerprint Database - The Device "DNA"
# =============================================================================

FINGERPRINT_DATABASE = {
    # Apple macOS (laptops/desktops) - various versions
    "1,3,6,15,119,252": {"os": "macOS", "category": "laptop", "confidence": 0.95},
    "1,121,3,6,15,119,252": {"os": "macOS Monterey+", "category": "laptop", "confidence": 0.98},
    "1,121,3,6,15,108,114,119,162,252,95,44,46": {"os": "macOS Sonoma/Sequoia", "category": "laptop", "confidence": 0.98},
    "1,121,3,6,15,119,252,95,44,46": {"os": "macOS Ventura", "category": "laptop", "confidence": 0.98},
    "1,3,6,15,119,95,252,44,46": {"os": "macOS Big Sur", "category": "laptop", "confidence": 0.96},

    # Apple iOS (iPhones/iPads) - comprehensive list for randomized MACs
    "1,121,3,6,15,119,252": {"os": "iOS 14+", "category": "phone", "confidence": 0.98},
    "1,3,6,15,119,252": {"os": "iOS/iPadOS", "category": "phone", "confidence": 0.95},
    "1,121,3,6,15,119,252,95": {"os": "iOS 16+", "category": "phone", "confidence": 0.98},
    "1,121,3,6,15,119,252,95,44,46": {"os": "iOS 17+", "category": "phone", "confidence": 0.99},
    "1,3,6,15,119,95,252,44,46": {"os": "iOS 15", "category": "phone", "confidence": 0.97},
    "1,121,3,6,15,108,114,119,252": {"os": "iPadOS 17+", "category": "tablet", "confidence": 0.98},
    "1,3,6,15,119,95,252": {"os": "iOS/iPadOS", "category": "phone", "confidence": 0.96},
    # iOS uses various Option 55 combinations - catch more patterns
    "1,3,6,15,119": {"os": "iOS (minimal)", "category": "phone", "confidence": 0.85},
    "1,121,3,6,15,119": {"os": "iOS 14+", "category": "phone", "confidence": 0.90},

    # Apple Smart Home / Apple TV / HomePod
    "1,3,6,15,119,95,252": {"os": "Apple HomePod/Apple TV", "category": "smart_hub", "confidence": 0.99},
    "1,3,6,15,119,252,95": {"os": "Apple TV", "category": "smart_hub", "confidence": 0.98},
    "1,121,3,6,15,119,95,252": {"os": "Apple HomePod mini", "category": "smart_hub", "confidence": 0.99},

    # Android/Linux
    "1,3,6,15,26,28,51,58,59": {"os": "Android/Linux", "category": "android", "confidence": 0.90},
    "1,3,6,28,33,121": {"os": "Android 10+", "category": "android", "confidence": 0.92},

    # Windows
    "1,3,6,15,31,33,43,44,46,47,121,249,252": {"os": "Windows 10/11", "category": "workstation", "confidence": 0.95},
    "1,15,3,6,44,46,47,31,33,121,249,252": {"os": "Windows Server", "category": "server", "confidence": 0.90},

    # Smart Home Devices
    "1,3,6,15,28,33": {"os": "Amazon Echo", "category": "smart_hub", "confidence": 0.97},
    "1,3,6,12,15,28,42": {"os": "Philips Hue Bridge", "category": "bridge", "confidence": 0.99},
    "1,3,6,15,28,42": {"os": "Google Home/Nest", "category": "smart_hub", "confidence": 0.96},
    "1,3,6,12,15,28,40,41,42": {"os": "Sonos Speaker", "category": "smart_hub", "confidence": 0.98},

    # IoT Devices
    "1,3,6,12,15,28": {"os": "Generic IoT", "category": "iot", "confidence": 0.75},
    "1,3,6": {"os": "Minimal DHCP", "category": "iot", "confidence": 0.60},
    "1,3,6,15": {"os": "Basic IoT", "category": "iot", "confidence": 0.70},

    # Printers
    "1,3,6,15,44,47": {"os": "HP Printer", "category": "printer", "confidence": 0.95},
    "1,3,6,15,12,44": {"os": "Brother Printer", "category": "printer", "confidence": 0.93},
    "1,3,6,15,12,44,47": {"os": "Canon/Epson Printer", "category": "printer", "confidence": 0.90},

    # Network Equipment
    "1,3,6,15,66,67": {"os": "Network Equipment (PXE)", "category": "network", "confidence": 0.85},
    "1,28,2,3,15,6,12": {"os": "Ubiquiti UniFi", "category": "network", "confidence": 0.95},

    # Security Cameras
    "1,3,6,15,28,33,42": {"os": "Hikvision/Dahua", "category": "camera", "confidence": 0.92},
    "1,3,6,28": {"os": "IP Camera", "category": "camera", "confidence": 0.80},

    # ESP/Tuya IoT
    "1,3,6,15,26,28,51,58,59,43": {"os": "ESP8266/ESP32", "category": "iot", "confidence": 0.88},
    "1,3,28,6": {"os": "Tuya/Smart Life", "category": "iot", "confidence": 0.85},

    # Gaming
    "1,3,6,15,28,33,44": {"os": "PlayStation", "category": "gaming", "confidence": 0.90},
    "1,3,6,15,31,33,43,44,46,47": {"os": "Xbox", "category": "gaming", "confidence": 0.88},
    "1,3,6,12,15,17,28,42": {"os": "Nintendo Switch", "category": "gaming", "confidence": 0.92},

    # Raspberry Pi / Linux SBC
    "1,3,6,12,15,28,42,121": {"os": "Raspberry Pi OS", "category": "sbc", "confidence": 0.90},
    "1,28,2,3,15,6,119,12,44,47,26,121,42": {"os": "Debian/Ubuntu", "category": "workstation", "confidence": 0.88},
}

# OUI Vendor Database (subset - expand as needed)
OUI_DATABASE = {
    # Apple
    "3C:06:30": "Apple", "40:ED:CF": "Apple", "78:31:C1": "Apple",
    "A8:66:7F": "Apple", "B8:17:C2": "Apple", "F0:B4:79": "Apple",
    # Amazon
    "0C:47:C9": "Amazon", "34:D2:70": "Amazon", "68:37:E9": "Amazon",
    "A0:02:DC": "Amazon", "FC:65:DE": "Amazon",
    # Google
    "48:D6:D5": "Google", "54:60:09": "Google", "F4:F5:D8": "Google",
    # Samsung
    "00:17:D5": "Samsung", "00:1D:F6": "Samsung", "00:21:19": "Samsung",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    # Intel
    "00:1F:3B": "Intel", "00:24:D7": "Intel", "3C:97:0E": "Intel",
    # Dell
    "00:14:22": "Dell", "00:21:9B": "Dell", "18:A9:9B": "Dell",
    # HP
    "00:1E:0B": "HP", "00:21:5A": "HP", "3C:D9:2B": "HP",
    # Philips (Hue)
    "00:17:88": "Philips",
    # Sonos
    "5C:AA:FD": "Sonos", "78:28:CA": "Sonos",
    # Hikvision
    "00:0C:B5": "Hikvision", "44:19:B6": "Hikvision",
    # Espressif (ESP32/ESP8266)
    "24:0A:C4": "Espressif", "5C:CF:7F": "Espressif", "84:CC:A8": "Espressif",
    "A4:CF:12": "Espressif", "C4:4F:33": "Espressif",
    # Tuya
    "10:D5:61": "Tuya", "D8:1F:12": "Tuya",
}


@dataclass
class IdentityScore:
    """Result of device identity scoring."""
    policy: str
    confidence: float
    vendor: str
    os_fingerprint: str
    category: str
    signals: Dict[str, float]
    reason: str
    device_name: str = ""  # Specific product name (HomePod, iPhone, Dell Latitude)


class SDNAutoPilot:
    """Premium SDN Auto Pilot with Heuristic Scoring Engine."""

    def __init__(self, db_path: Path = AUTOPILOT_DB):
        # Accept both str and Path for flexibility in testing
        self.db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self._ensure_db()
        self._ensure_columns_exist()  # Run migrations for missing columns
        self._load_custom_fingerprints()

    def _ensure_db(self):
        """Create database and tables.

        Handles read-only mounts gracefully (container scenario).
        If database is read-only, just verify it exists and is readable.
        """
        # Check if database already exists
        if self.db_path.exists():
            # Try to open for reading to verify access
            try:
                conn = sqlite3.connect(f'file:{self.db_path}?mode=ro', uri=True, timeout=10)
                conn.row_factory = sqlite3.Row
                # Verify table exists
                cursor = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='device_identity'"
                )
                if cursor.fetchone():
                    conn.close()
                    logger.debug("Database exists and is readable (read-only mode)")
                    return
                conn.close()
            except sqlite3.OperationalError as e:
                logger.warning(f"Cannot open database for reading: {e}")
                raise

        # Database doesn't exist or table missing - try to create (write mode)
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # Read-only filesystem
            logger.warning(f"Cannot create database directory (read-only?): {e}")
            raise

        with self._get_conn() as conn:
            try:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS device_identity (
                        mac TEXT PRIMARY KEY,
                        ip TEXT,
                        hostname TEXT,
                        friendly_name TEXT,
                        device_type TEXT,
                        vendor TEXT,
                        dhcp_fingerprint TEXT,
                        os_detected TEXT,
                        category TEXT,
                        policy TEXT DEFAULT 'quarantine',
                        confidence REAL DEFAULT 0.0,
                        signals TEXT,
                        manual_override INTEGER DEFAULT 0,
                        first_seen TEXT,
                        last_seen TEXT,
                        updated_at TEXT,
                        status TEXT DEFAULT 'offline',
                        last_packet_count INTEGER DEFAULT 0,
                        neighbor_state TEXT DEFAULT 'UNKNOWN',
                        -- WiFi signal data (updated by host collector)
                        wifi_rssi INTEGER DEFAULT NULL,
                        wifi_quality INTEGER DEFAULT NULL,
                        wifi_proximity TEXT DEFAULT NULL,
                        wifi_band TEXT DEFAULT NULL,
                        wifi_interface TEXT DEFAULT NULL,
                        -- Traffic counters (from OpenFlow/WiFi)
                        rx_bytes INTEGER DEFAULT 0,
                        tx_bytes INTEGER DEFAULT 0,
                        connected_time INTEGER DEFAULT 0,
                        -- User-defined tags (JSON array)
                        tags TEXT DEFAULT '[]',
                        -- Connection type
                        connection_type TEXT DEFAULT 'unknown'
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS device_metrics (
                        mac TEXT PRIMARY KEY,
                        avg_jitter_ms REAL DEFAULT 0,
                        peak_jitter_ms REAL DEFAULT 0,
                        anomaly_count INTEGER DEFAULT 0,
                        last_anomaly TEXT,
                        auto_quarantined INTEGER DEFAULT 0
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS fingerprint_learning (
                        fingerprint TEXT PRIMARY KEY,
                        device_count INTEGER DEFAULT 0,
                        common_vendor TEXT,
                        common_category TEXT,
                        last_seen TEXT
                    )
                ''')
                # Connection history table for timeline visualization
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS connection_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        details TEXT,
                        FOREIGN KEY (mac) REFERENCES device_identity(mac)
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_policy ON device_identity(policy)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_status ON device_identity(status)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_proximity ON device_identity(wifi_proximity)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_history_mac ON connection_history(mac)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_history_ts ON connection_history(timestamp)')

                # Migrate existing tables - add new columns if missing
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN status TEXT DEFAULT "offline"')
                except sqlite3.OperationalError:
                    pass  # Column already exists
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN last_packet_count INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN neighbor_state TEXT DEFAULT "UNKNOWN"')
                except sqlite3.OperationalError:
                    pass
                # New columns for WiFi signal
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN wifi_rssi INTEGER DEFAULT NULL')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN wifi_quality INTEGER DEFAULT NULL')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN wifi_proximity TEXT DEFAULT NULL')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN wifi_band TEXT DEFAULT NULL')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN wifi_interface TEXT DEFAULT NULL')
                except sqlite3.OperationalError:
                    pass
                # Traffic counters
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN rx_bytes INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN tx_bytes INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN connected_time INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass
                # Tags
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN tags TEXT DEFAULT "[]"')
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute('ALTER TABLE device_identity ADD COLUMN connection_type TEXT DEFAULT "unknown"')
                except sqlite3.OperationalError:
                    pass

                conn.commit()
                logger.debug("Database initialized (write mode)")
            except sqlite3.OperationalError as e:
                if 'readonly' in str(e).lower():
                    logger.warning(f"Database is read-only, skipping schema creation: {e}")
                else:
                    raise

    @contextmanager
    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _ensure_columns_exist(self):
        """Ensure all required columns and tables exist in the database.

        This runs migrations for any missing columns/tables. Called on startup
        to handle schema changes gracefully.
        """
        required_columns = {
            'status': "TEXT DEFAULT 'offline'",
            'last_packet_count': 'INTEGER DEFAULT 0',
            'neighbor_state': "TEXT DEFAULT 'UNKNOWN'",
            'wifi_rssi': 'INTEGER DEFAULT NULL',
            'wifi_quality': 'INTEGER DEFAULT NULL',
            'wifi_proximity': 'TEXT DEFAULT NULL',
            'wifi_band': 'TEXT DEFAULT NULL',
            'wifi_interface': 'TEXT DEFAULT NULL',
            'rx_bytes': 'INTEGER DEFAULT 0',
            'tx_bytes': 'INTEGER DEFAULT 0',
            'connected_time': 'INTEGER DEFAULT 0',
            'tags': "TEXT DEFAULT '[]'",
            'connection_type': "TEXT DEFAULT 'unknown'",
        }

        try:
            with self._get_conn() as conn:
                # Ensure connection_history table exists (might be missing in old databases)
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS connection_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        details TEXT
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_history_mac ON connection_history(mac)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_history_ts ON connection_history(timestamp)')

                # Get existing columns in device_identity
                cursor = conn.execute("PRAGMA table_info(device_identity)")
                existing_columns = {row['name'] for row in cursor.fetchall()}

                # Add missing columns
                for col_name, col_def in required_columns.items():
                    if col_name not in existing_columns:
                        try:
                            conn.execute(f'ALTER TABLE device_identity ADD COLUMN {col_name} {col_def}')
                            logger.info(f"Added missing column: {col_name}")
                        except sqlite3.OperationalError as e:
                            logger.debug(f"Could not add column {col_name}: {e}")

                conn.commit()
        except Exception as e:
            logger.warning(f"Schema migration failed: {e}")

    def _load_custom_fingerprints(self):
        """Load fingerprint databases."""
        # Use comprehensive Fingerbank module if available
        if HAS_FINGERBANK:
            self.fingerbank = get_fingerbank()
            stats = self.fingerbank.get_stats()
            logger.info(f"Fingerbank loaded: {stats['loaded_fingerprints']} fingerprints, "
                       f"{stats['oui_entries']} OUI entries")
        else:
            self.fingerbank = None
            logger.warning("Fingerbank module not available, using legacy database")

        # Legacy fallback
        self.fingerprints = FINGERPRINT_DATABASE.copy()
        if FINGERPRINT_DB_FILE.exists():
            try:
                custom = json.loads(FINGERPRINT_DB_FILE.read_text())
                self.fingerprints.update(custom)
                logger.info(f"Loaded {len(custom)} custom fingerprints")
            except (json.JSONDecodeError, IOError) as e:
                logger.debug(f"No custom fingerprints: {e}")

        self.oui_db = OUI_DATABASE.copy()

    # =========================================================================
    # IDENTITY SCORING ENGINE - The 99% Accuracy Brain
    # =========================================================================

    def calculate_identity(self, mac: str, hostname: Optional[str] = None,
                          dhcp_fingerprint: Optional[str] = None,
                          vendor_class: Optional[str] = None,
                          open_ports: Optional[List[int]] = None) -> IdentityScore:
        """
        Identify device using Fingerbank (if available) or legacy scoring.

        Returns IdentityScore with policy, confidence, and device details.
        """
        # Use Fingerbank for comprehensive identification
        if HAS_FINGERBANK and self.fingerbank:
            return self._identify_with_fingerbank(mac, hostname, dhcp_fingerprint, vendor_class, open_ports)

        # Legacy identification
        return self._identify_legacy(mac, hostname, dhcp_fingerprint, open_ports)

    def _identify_with_fingerbank(self, mac: str, hostname: Optional[str],
                                   dhcp_fingerprint: Optional[str],
                                   vendor_class: Optional[str],
                                   open_ports: Optional[List[int]]) -> IdentityScore:
        """Use Fingerbank module for device identification."""
        device = self.fingerbank.identify(
            mac=mac,
            dhcp_fingerprint=dhcp_fingerprint,
            hostname=hostname,
            vendor_class=vendor_class  # Pass DHCP Option 60
        )

        # Apply probing bonus if available
        confidence = device.confidence
        category = device.category

        if open_ports:
            if any(p in open_ports for p in [22, 3389, 5900]):
                confidence = min(1.0, confidence + 0.08)
                if category == "unknown":
                    category = "workstation"
            elif any(p in open_ports for p in [9100, 631, 515]):
                confidence = min(1.0, confidence + 0.10)
                if category == "unknown":
                    category = "printer"

        # Determine policy based on score thresholds
        policy, reason = self._determine_policy_from_fingerbank(
            confidence, category, device.vendor, hostname, device.name, device.os
        )

        return IdentityScore(
            policy=policy,
            confidence=confidence,
            vendor=device.vendor,
            os_fingerprint=device.os,
            category=category,
            signals={
                'fingerbank_confidence': device.confidence,
                'name': device.name,
                'hierarchy': device.hierarchy,
            },
            reason=reason,
            device_name=device.name  # Store specific product name (HomePod, iPhone, etc.)
        )

    def _determine_policy_from_fingerbank(self, score: float, category: str,
                                          vendor: str, hostname: Optional[str],
                                          device_name: str, os_fingerprint: str = '') -> Tuple[str, str]:
        """
        Determine policy from Fingerbank identification.

        Policy Hierarchy:
        1. Management Devices (MacBook, iPad, iMac) - full network control
        2. Apple Ecosystem (iPhone, Apple Watch, HomePod, Apple TV) - smart_home LAN
        3. Trusted Infrastructure (Raspberry Pi) - smart_home access
        4. Smart Home devices - smart_home
        5. Personal Devices (non-Apple) - internet_only
        6. IoT Devices - lan_only
        7. Unknown - quarantine
        """
        # =======================================================================
        # MANAGEMENT DEVICES - Full network control (can manage other devices)
        # =======================================================================

        # MacBook, iPad, iMac, Mac Mini, Mac Pro are management devices
        if vendor == "Apple" and score >= 0.80:
            if category in ('laptop', 'tablet', 'desktop'):
                return 'full_access', f"Management: {device_name} (Apple)"

        # =======================================================================
        # APPLE ECOSYSTEM - Smart Home LAN access for inter-device communication
        # =======================================================================

        # iPhone, Apple Watch, HomePod, Apple TV get smart_home policy
        # Enables Bonjour/mDNS, AirPlay, AirDrop, Handoff, HomeKit
        if vendor == "Apple" and score >= 0.75:
            return 'smart_home', f"Apple Ecosystem: {device_name}"

        # =======================================================================
        # TRUSTED INFRASTRUCTURE - Smart Home access (not management)
        # =======================================================================

        # Raspberry Pi: Trusted but not management
        if vendor == "Raspberry Pi" and score >= 0.80:
            return 'smart_home', f"Trusted SBC: {device_name}"

        # =======================================================================
        # HIGH CONFIDENCE DEVICES (score >= 0.80)
        # =======================================================================
        if score >= 0.80:
            # Smart home devices need LAN access for control
            if category in ('voice_assistant', 'smart_hub', 'bridge'):
                return 'smart_home', f"Verified {device_name} (score: {score:.2f})"
            # Personal devices - internet access only (non-Apple)
            elif category in ('phone', 'tablet', 'laptop', 'workstation', 'desktop', 'gaming', 'streaming', 'smart_tv', 'wearable'):
                return 'internet_only', f"Verified {device_name} (score: {score:.2f})"
            # IoT devices - LAN only (no internet)
            elif category in ('printer', 'camera', 'doorbell', 'thermostat', 'iot', 'appliance', 'sensor', 'smart_plug', 'smart_light'):
                return 'lan_only', f"Verified IoT: {device_name} (score: {score:.2f})"
            # SBCs get smart_home access
            elif category == 'sbc':
                return 'smart_home', f"SBC: {device_name}"
            # Servers get full access
            elif category == 'server':
                return 'full_access', f"Server: {device_name} (score: {score:.2f})"
            return 'internet_only', f"Verified: {device_name} (score: {score:.2f})"

        # =======================================================================
        # MEDIUM CONFIDENCE DEVICES (score >= 0.50)
        # =======================================================================
        elif score >= 0.50:
            if category in ('printer', 'camera', 'iot', 'thermostat', 'appliance'):
                return 'lan_only', f"Likely IoT: {device_name} (score: {score:.2f})"
            if category in ('voice_assistant', 'smart_hub', 'bridge'):
                return 'smart_home', f"Likely smart home: {device_name} (score: {score:.2f})"
            return 'internet_only', f"Generic device: {device_name} (score: {score:.2f})"

        # Known workstation vendors get internet access
        elif vendor in ('Intel', 'Dell', 'HP', 'Lenovo', 'ASUS', 'Acer'):
            return 'internet_only', f"Workstation vendor ({vendor})"

        # =======================================================================
        # RANDOMIZED MAC WITH IDENTIFIED OS - ALLOW INTERNET ACCESS
        # =======================================================================
        # Apple/Android/Windows devices with randomized MACs should get internet
        # even with lower scores - they're identified via fingerprint
        elif "randomized MAC" in vendor.lower():
            if 'apple' in vendor.lower() or 'ios' in os_fingerprint.lower() or 'macos' in os_fingerprint.lower():
                return 'internet_only', f"Apple device (randomized MAC, score: {score:.2f})"
            elif 'android' in vendor.lower() or 'android' in os_fingerprint.lower():
                return 'internet_only', f"Android device (randomized MAC, score: {score:.2f})"
            elif 'windows' in vendor.lower() or 'windows' in os_fingerprint.lower():
                return 'internet_only', f"Windows device (randomized MAC, score: {score:.2f})"

        # =======================================================================
        # LOW CONFIDENCE - QUARANTINE
        # =======================================================================
        no_hn = not hostname or hostname.lower() in ('', '*', 'unknown', 'null')
        if no_hn and vendor in ("Unknown", "Randomized MAC"):
            return 'quarantine', "Zero-knowledge - awaiting identification"
        elif score < 0.30:
            return 'quarantine', f"Low confidence (score: {score:.2f})"

        return 'internet_only', f"Default (score: {score:.2f})"

    def _identify_legacy(self, mac: str, hostname: Optional[str] = None,
                          dhcp_fingerprint: Optional[str] = None,
                          open_ports: Optional[List[int]] = None) -> IdentityScore:
        """
        Heuristic Scoring Engine for device identity.

        Weights:
        - DHCP Option 55 (50%): Device DNA
        - MAC OUI Vendor (20%): Manufacturer
        - Hostname (20%): Name patterns
        - Active Probing (10%): Port behavior
        """
        mac = mac.upper()
        hostname = hostname.strip() if hostname else None
        signals = {'dhcp': 0.0, 'oui': 0.0, 'hostname': 0.0, 'probe': 0.0}

        # Get vendor from OUI
        oui = mac[:8].replace('-', ':')
        vendor = self.oui_db.get(oui, "Unknown")
        os_fingerprint = "Unknown"
        category = "unknown"

        # 1. DHCP Fingerprint (50% weight)
        if dhcp_fingerprint:
            fp_info = self.fingerprints.get(dhcp_fingerprint)
            if fp_info:
                os_fingerprint = fp_info['os']
                category = fp_info['category']
                signals['dhcp'] = fp_info['confidence'] * 0.50
            else:
                self._learn_fingerprint(dhcp_fingerprint, vendor, category)
                signals['dhcp'] = 0.10

        # 2. OUI Vendor (20% weight)
        # Check for randomized/private MAC (locally-administered bit set)
        is_randomized_mac = (int(mac.split(':')[0], 16) & 0x02) != 0

        if vendor != "Unknown":
            signals['oui'] = 0.15
            # Bonus for vendor/fingerprint alignment
            if os_fingerprint != "Unknown" and vendor.lower() in os_fingerprint.lower():
                signals['oui'] = 0.20
        elif is_randomized_mac and os_fingerprint != "Unknown":
            # Randomized MAC but fingerprint identifies vendor - give partial OUI credit
            signals['oui'] = 0.12
            # Infer vendor from fingerprint for logging
            if 'macos' in os_fingerprint.lower() or 'ios' in os_fingerprint.lower():
                vendor = "Apple (randomized MAC)"
            elif 'android' in os_fingerprint.lower():
                vendor = "Android (randomized MAC)"
            elif 'windows' in os_fingerprint.lower():
                vendor = "Windows (randomized MAC)"

        # 3. Hostname (20% weight)
        if hostname:
            hn = hostname.lower()
            patterns = {
                'homepod': ('smart_hub', 0.20), 'echo': ('smart_hub', 0.20),
                'google-home': ('smart_hub', 0.20), 'iphone': ('phone', 0.18),
                'ipad': ('tablet', 0.18), 'macbook': ('laptop', 0.18),
                'android': ('phone', 0.15), 'galaxy': ('phone', 0.15),
                'printer': ('printer', 0.18), 'cam': ('camera', 0.15),
            }
            for pattern, (cat, score) in patterns.items():
                if pattern in hn:
                    signals['hostname'] = max(signals['hostname'], score)
                    if category == "unknown":
                        category = cat
                    break
            if hn in ('', '*', 'unknown', 'null'):
                signals['hostname'] = -0.05
        else:
            signals['hostname'] = -0.05

        # 4. Active Probing (10% weight)
        if open_ports:
            if any(p in open_ports for p in [22, 3389, 5900]):
                signals['probe'] = 0.08
                if category == "unknown":
                    category = "workstation"
            elif any(p in open_ports for p in [9100, 631, 515]):
                signals['probe'] = 0.10
                if category == "unknown":
                    category = "printer"

        # Calculate total and determine policy
        total = sum(max(0, s) for s in signals.values())
        policy, reason = self._determine_policy(total, category, vendor, hostname)

        # Determine device name from category/vendor/hostname
        device_name = self._infer_device_name(vendor, category, hostname, os_fingerprint)

        return IdentityScore(
            policy=policy,
            confidence=min(1.0, total),
            vendor=vendor,
            os_fingerprint=os_fingerprint,
            category=category,
            signals=signals,
            reason=reason,
            device_name=device_name
        )

    def _determine_policy(self, score: float, category: str, vendor: str,
                         hostname: Optional[str]) -> Tuple[str, str]:
        """Determine policy based on score and category (legacy method)."""
        # Management: MacBook, iPad, iMac get full_access
        if vendor == "Apple" and score >= 0.80:
            if category in ('laptop', 'tablet', 'desktop'):
                return 'full_access', f"Management (Apple {category})"

        # Apple Ecosystem: Other Apple devices get smart_home
        if vendor == "Apple" and score >= 0.75:
            return 'smart_home', f"Apple Ecosystem (score: {score:.2f})"

        # Raspberry Pi: Trusted but not management
        if vendor == "Raspberry Pi" and score >= 0.80:
            return 'smart_home', f"Trusted SBC (score: {score:.2f})"

        if score >= 0.80:
            if category in ('smart_hub', 'bridge', 'voice_assistant'):
                return 'smart_home', f"Verified {category} (score: {score:.2f})"
            elif category in ('phone', 'tablet', 'laptop', 'workstation', 'gaming'):
                return 'internet_only', f"Verified device (score: {score:.2f})"
            elif category in ('printer', 'camera', 'iot', 'sensor'):
                return 'lan_only', f"Verified IoT (score: {score:.2f})"
            elif category == 'sbc':
                return 'smart_home', f"SBC (score: {score:.2f})"
            return 'internet_only', f"Verified (score: {score:.2f})"
        elif score >= 0.50:
            if category in ('printer', 'camera', 'iot'):
                return 'lan_only', f"Likely IoT (score: {score:.2f})"
            return 'internet_only', f"Generic device (score: {score:.2f})"
        elif vendor in ('Intel', 'Dell', 'HP', 'Lenovo'):
            return 'internet_only', "Workstation vendor"

        # Zero-knowledge quarantine
        no_hn = not hostname or hostname.lower() in ('', '*', 'unknown', 'null')
        if no_hn and vendor == "Unknown":
            return 'quarantine', "Zero-knowledge - awaiting identification"
        elif score < 0.30:
            return 'quarantine', f"Low confidence (score: {score:.2f})"

        return 'internet_only', f"Default (score: {score:.2f})"

    def _infer_device_name(self, vendor: str, category: str, hostname: Optional[str],
                           os_fingerprint: str) -> str:
        """Infer device name from available signals (legacy fallback)."""
        # Try to extract from hostname patterns
        if hostname:
            hn_lower = hostname.lower()
            # Apple products
            if 'macbook' in hn_lower:
                return 'MacBook'
            if 'imac' in hn_lower:
                return 'iMac'
            if 'iphone' in hn_lower:
                return 'iPhone'
            if 'ipad' in hn_lower:
                return 'iPad'
            if 'apple-watch' in hn_lower or 'applewatch' in hn_lower:
                return 'Apple Watch'
            if 'homepod' in hn_lower:
                return 'HomePod'
            # Android devices
            if 'pixel' in hn_lower:
                return 'Google Pixel'
            if 'samsung' in hn_lower or 'galaxy' in hn_lower:
                return 'Samsung Galaxy'
            # Consoles
            if 'playstation' in hn_lower or 'ps5' in hn_lower or 'ps4' in hn_lower:
                return 'PlayStation'
            if 'xbox' in hn_lower:
                return 'Xbox'
            if 'switch' in hn_lower:
                return 'Nintendo Switch'

        # Fall back to OS fingerprint pattern
        if os_fingerprint:
            os_lower = os_fingerprint.lower()
            if 'macos' in os_lower:
                return 'Mac Computer'
            if 'ios' in os_lower or 'ipad' in os_lower:
                return 'iOS Device'
            if 'android' in os_lower:
                return 'Android Device'
            if 'windows' in os_lower:
                return 'Windows PC'
            if 'raspberry' in os_lower:
                return 'Raspberry Pi'

        # Fall back to vendor + category
        if vendor and vendor != "Unknown":
            category_map = {
                'laptop': 'Laptop',
                'workstation': 'Workstation',
                'desktop': 'Desktop',
                'phone': 'Phone',
                'tablet': 'Tablet',
                'smart_hub': 'Smart Hub',
                'printer': 'Printer',
                'camera': 'Camera',
                'gaming': 'Gaming Console',
                'sbc': 'SBC',
            }
            cat_name = category_map.get(category, 'Device')
            return f"{vendor} {cat_name}"

        return "Unknown Device"

    def _learn_fingerprint(self, fingerprint: str, vendor: str, category: str):
        """Learn unknown fingerprints."""
        with self._get_conn() as conn:
            conn.execute('''
                INSERT INTO fingerprint_learning (fingerprint, device_count, common_vendor, common_category, last_seen)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    device_count = device_count + 1,
                    last_seen = excluded.last_seen
            ''', (fingerprint, vendor, category, datetime.now().isoformat()))
            conn.commit()

    # =========================================================================
    # OPENFLOW POLICY GENERATOR
    # =========================================================================

    def generate_openflow_rules(self, mac: str, ip: str, policy: str) -> List[Dict]:
        """Generate OpenFlow rules for micro-segmentation on OVS bridge."""
        mac = mac.upper()
        rules = []

        # Default drop
        rules.append({
            'priority': 1, 'match': {'eth_src': mac},
            'actions': [], 'comment': f"Default deny {mac}"
        })

        if policy == 'quarantine':
            # Only DHCP/DNS to gateway
            rules.append({
                'priority': 100,
                'match': {'eth_src': mac, 'udp_dst': 67},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow DHCP"
            })
            rules.append({
                'priority': 100,
                'match': {'eth_src': mac, 'udp_dst': 53},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow DNS"
            })

        elif policy == 'internet_only':
            rules.append({
                'priority': 500,
                'match': {'eth_src': mac, 'ipv4_dst': GATEWAY_IP},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow gateway"
            })
            rules.append({
                'priority': 400,
                'match': {'eth_src': mac, 'ipv4_dst': LAN_SUBNET},
                'actions': [], 'comment': "Block LAN"
            })
            rules.append({
                'priority': 300,
                'match': {'eth_src': mac},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow external"
            })

        elif policy == 'lan_only':
            rules.append({
                'priority': 500,
                'match': {'eth_src': mac, 'ipv4_dst': LAN_SUBNET},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow LAN"
            })
            rules.append({
                'priority': 450,
                'match': {'eth_src': mac, 'ipv4_dst': GATEWAY_IP},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow gateway"
            })

        elif policy == 'smart_home':
            rules.append({
                'priority': 600,
                'match': {'eth_src': mac},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow all (Smart Home / curated IoT)"
            })

        elif policy == 'full_access':
            rules.append({
                'priority': 1000,
                'match': {'eth_src': mac},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Full access"
            })

        return rules

    def apply_policy(self, mac: str, ip: str, policy: str) -> bool:
        """Apply OpenFlow rules via trigger file for host-side execution.

        The container cannot run OVS commands directly since OVS runs on the host.
        Instead, we write a trigger file that the host's nac-policy-sync.sh script
        picks up and applies the OpenFlow rules.
        """
        logger.info(f"Requesting policy [{policy}] for {mac} ({ip})")

        # Write trigger file for host-side script to apply OpenFlow rules
        try:
            trigger_data = {
                'mac': mac.upper(),
                'ip': ip,
                'policy': policy,
                'timestamp': datetime.now().isoformat(),
            }
            NAC_POLICY_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
            NAC_POLICY_TRIGGER_FILE.write_text(json.dumps(trigger_data))
            logger.info(f"NAC policy trigger written for {mac} -> {policy}")
            return True
        except IOError as e:
            logger.error(f"Failed to write policy trigger: {e}")
            return False

    def set_policy(self, mac: str, policy: str) -> bool:
        """Set and persist network policy for a device.

        Args:
            mac: Device MAC address
            policy: Policy name (quarantine, internet_only, lan_only, smart_home, full_access)

        Returns:
            True if successful, False otherwise
        """
        mac = mac.upper()

        # Normalize policy names
        # 'isolated' and 'normal' are legacy aliases
        # NOTE: full_access is a DISTINCT policy (includes management network access)
        #       and should NOT be aliased to 'smart_home'
        policy_aliases = {
            'isolated': 'quarantine',
            'normal': 'smart_home',
        }
        policy = policy_aliases.get(policy, policy)

        valid_policies = ['quarantine', 'internet_only', 'lan_only', 'smart_home', 'full_access']
        if policy not in valid_policies:
            logger.warning(f"Invalid policy: {policy}")
            return False

        try:
            with self._get_conn() as conn:
                # Check if device exists and get current policy for event logging
                row = conn.execute(
                    'SELECT ip, policy, friendly_name, hostname FROM device_identity WHERE mac = ?', (mac,)
                ).fetchone()

                if not row:
                    logger.warning(f"Device {mac} not found in database")
                    return False

                old_policy = row['policy']
                device_name = row['friendly_name'] or row['hostname'] or mac

                # Update policy and set manual_override to prevent auto-classification
                conn.execute('''
                    UPDATE device_identity SET
                        policy = ?,
                        manual_override = 1,
                        updated_at = ?
                    WHERE mac = ?
                ''', (policy, datetime.now().isoformat(), mac))
                conn.commit()

                logger.info(f"Policy for {mac} set to {policy} (manual override enabled)")

                # Log policy change event for connection history
                if old_policy != policy:
                    self.log_connection_event(
                        mac, 'policy_changed',
                        f'Policy changed: {old_policy} → {policy} for {device_name}'
                    )

                # Apply OpenFlow rules if device has IP
                ip = row['ip'] if row else None
                if ip:
                    self.apply_policy(mac, ip, policy)

                return True
        except Exception as e:
            logger.error(f"Failed to set policy for {mac}: {e}")
            return False

    def update_friendly_name(self, mac: str, name: str) -> bool:
        """Update the friendly_name for a device.

        This is the display name shown in the SDN dashboard.
        """
        mac = mac.upper()
        try:
            with self._get_conn() as conn:
                now = datetime.now().isoformat()
                conn.execute('''
                    UPDATE device_identity
                    SET friendly_name = ?, updated_at = ?
                    WHERE mac = ?
                ''', (name, now, mac))
                conn.commit()
                logger.info(f"Updated friendly_name for {mac} to '{name}'")
                return True
        except Exception as e:
            logger.error(f"Failed to update friendly_name for {mac}: {e}")
            return False

    def _apply_ovs_flow(self, rule: Dict) -> bool:
        """Apply a flow rule to OVS."""
        try:
            match_parts = []
            for k, v in rule['match'].items():
                if k == 'eth_src':
                    match_parts.append(f"dl_src={v}")
                elif k == 'ipv4_dst':
                    match_parts.append(f"nw_dst={v}")
                elif k == 'udp_dst':
                    match_parts.append(f"tp_dst={v}")

            match_str = ','.join(match_parts)
            actions = "drop" if not rule['actions'] else "output:NORMAL"

            cmd = ['ovs-ofctl', 'add-flow', 'FTS',
                   f"priority={rule['priority']},{match_str},actions={actions}"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"OVS flow: {e}")
            return False

    # =========================================================================
    # JITTER-BASED KILL SWITCH
    # =========================================================================

    def check_anomaly(self, mac: str, jitter_ms: float, threshold: float = 3.0) -> bool:
        """
        Auto-quarantine if jitter exceeds threshold multiplier of average.
        Returns True if device was quarantined.
        """
        mac = mac.upper()

        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT avg_jitter_ms FROM device_metrics WHERE mac = ?', (mac,)
            ).fetchone()

            if row and row['avg_jitter_ms'] > 0:
                avg = row['avg_jitter_ms']
                if jitter_ms > avg * threshold:
                    # Auto-quarantine
                    conn.execute('''
                        UPDATE device_metrics SET
                            peak_jitter_ms = MAX(peak_jitter_ms, ?),
                            anomaly_count = anomaly_count + 1,
                            last_anomaly = ?,
                            auto_quarantined = 1
                        WHERE mac = ?
                    ''', (jitter_ms, datetime.now().isoformat(), mac))

                    conn.execute('''
                        UPDATE device_identity SET policy = 'quarantine', updated_at = ?
                        WHERE mac = ? AND manual_override = 0
                    ''', (datetime.now().isoformat(), mac))
                    conn.commit()

                    logger.warning(f"ANOMALY: {mac} jitter {jitter_ms}ms > {avg*threshold}ms - QUARANTINE")
                    return True

                # Update rolling average
                new_avg = avg * 0.9 + jitter_ms * 0.1
                conn.execute('UPDATE device_metrics SET avg_jitter_ms = ? WHERE mac = ?',
                           (new_avg, mac))
            else:
                conn.execute('''
                    INSERT OR REPLACE INTO device_metrics (mac, avg_jitter_ms, peak_jitter_ms)
                    VALUES (?, ?, ?)
                ''', (mac, jitter_ms, jitter_ms))
            conn.commit()

        return False

    # =========================================================================
    # DEVICE SYNC
    # =========================================================================

    def _clean_hostname_to_display(self, hostname: str) -> str:
        """
        Clean hostname to friendly display format.

        Converts: "Johns-Apple-Watch" → "John's Apple Watch"
        """
        if not hostname:
            return ""

        import re
        name = hostname

        # Apply possessive patterns
        name = re.sub(r"(\w+)s-", r"\1's ", name, flags=re.IGNORECASE)
        name = re.sub(r"(\w+)-s-", r"\1's ", name, flags=re.IGNORECASE)

        # Replace hyphens/underscores with spaces
        name = name.replace("-", " ").replace("_", " ")

        # Title case with Apple product awareness
        words = name.split()
        result = []
        for word in words:
            lower = word.lower()
            if lower.startswith('iphone'):
                result.append('iPhone' + word[6:])
            elif lower.startswith('ipad'):
                result.append('iPad' + word[4:])
            elif lower == 'macbook':
                result.append('MacBook')
            elif lower == 'macbookpro':
                result.append('MacBook Pro')
            elif lower == 'macbookair':
                result.append('MacBook Air')
            elif lower == 'appletv':
                result.append('Apple TV')
            elif lower == 'applewatch':
                result.append('Apple Watch')
            elif lower == 'homepod':
                result.append('HomePod')
            elif lower == 'airpods':
                result.append('AirPods')
            else:
                result.append(word.capitalize())

        return " ".join(result)

    def sync_device(self, mac: str, ip: str, hostname: Optional[str] = None,
                   dhcp_fingerprint: Optional[str] = None,
                   vendor_class: Optional[str] = None,
                   apply_rules: bool = True) -> IdentityScore:
        """Sync device through auto-pilot pipeline."""
        mac = mac.upper()

        # CRITICAL: Do not recreate blocked/disconnected devices
        if _is_mac_blocked(mac):
            logger.debug(f"Skipping sync for blocked MAC: {mac[:8]}:XX:XX:XX")
            return IdentityScore(
                policy='quarantine',
                confidence=0.0,
                vendor='',
                os_fingerprint='',
                category='blocked',
                signals={},
                reason='Device was manually disconnected',
                device_name='Blocked Device'
            )

        identity = self.calculate_identity(mac, hostname, dhcp_fingerprint, vendor_class)

        # Premium: Resolve friendly name via mDNS/Bonjour
        friendly_name = None
        if HAS_MDNS and ip:
            try:
                friendly_name = resolve_premium_name(ip, mac, hostname)
                if friendly_name and friendly_name != "Unknown Device":
                    logger.debug(f"{mac}: mDNS resolved '{friendly_name}'")
            except Exception as e:
                logger.debug(f"mDNS resolution failed: {e}")

        # Fallback to cleaned hostname if no mDNS name
        if not friendly_name and hostname:
            friendly_name = self._clean_hostname_to_display(hostname)

        # Policy hierarchy: lower number = more permissive
        # Auto-classification should NEVER downgrade a device to less permissive policy
        # This prevents WAN failover from resetting trusted devices to internet_only
        POLICY_RANK = {
            'full_access': 1,
            'smart_home': 2,
            'lan_only': 3,
            'internet_only': 4,
            'quarantine': 5,
        }

        with self._get_conn() as conn:
            # Check existing device state for connection event logging
            existing = conn.execute(
                'SELECT policy, manual_override, status FROM device_identity WHERE mac = ?', (mac,)
            ).fetchone()

            # Track if this is a new device or reconnection for event logging
            is_new_device = existing is None
            was_offline = existing and existing['status'] == 'offline'

            if existing and existing['manual_override']:
                identity = IdentityScore(
                    policy=existing['policy'],
                    confidence=identity.confidence,
                    vendor=identity.vendor,
                    os_fingerprint=identity.os_fingerprint,
                    category=identity.category,
                    signals=identity.signals,
                    reason="Manual override",
                    device_name=identity.device_name
                )
            elif existing:
                # CRITICAL: Preserve policy if existing is MORE permissive than new classification
                # This prevents WAN failover from resetting full_access devices to internet_only
                existing_rank = POLICY_RANK.get(existing['policy'], 4)
                new_rank = POLICY_RANK.get(identity.policy, 4)
                if existing_rank < new_rank:
                    # Existing policy is more permissive - keep it
                    logger.info(f"{mac}: Preserving {existing['policy']} (more permissive than {identity.policy})")
                    identity = IdentityScore(
                        policy=existing['policy'],
                        confidence=identity.confidence,
                        vendor=identity.vendor,
                        os_fingerprint=identity.os_fingerprint,
                        category=identity.category,
                        signals=identity.signals,
                        reason=f"Preserved (was {existing['policy']})",
                        device_name=identity.device_name
                    )

            now = datetime.now().isoformat()
            conn.execute('''
                INSERT INTO device_identity
                    (mac, ip, hostname, friendly_name, device_type, vendor, dhcp_fingerprint, os_detected,
                     category, policy, confidence, signals, first_seen, last_seen, updated_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = COALESCE(excluded.hostname, hostname),
                    friendly_name = COALESCE(excluded.friendly_name, friendly_name),
                    device_type = COALESCE(excluded.device_type, device_type),
                    vendor = excluded.vendor,
                    dhcp_fingerprint = COALESCE(excluded.dhcp_fingerprint, dhcp_fingerprint),
                    os_detected = excluded.os_detected,
                    category = excluded.category,
                    policy = CASE WHEN manual_override = 1 THEN policy ELSE excluded.policy END,
                    confidence = excluded.confidence,
                    signals = excluded.signals,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at,
                    status = 'online'
            ''', (mac, ip, hostname, friendly_name, identity.device_name, identity.vendor, dhcp_fingerprint,
                  identity.os_fingerprint, identity.category, identity.policy,
                  identity.confidence, json.dumps(identity.signals), now, now, now))
            conn.commit()

        # Log connection event for history tracking
        display = friendly_name or hostname or mac
        if is_new_device:
            self.log_connection_event(mac, 'connected', f'New device: {display} ({identity.vendor or "Unknown vendor"})')
        elif was_offline:
            self.log_connection_event(mac, 'reconnected', f'Device reconnected: {display}')

        if apply_rules:
            self.apply_policy(mac, ip, identity.policy)

        # Log with friendly name if available
        logger.info(f"{display}: {identity.policy} ({identity.confidence:.2f}) - {identity.reason}")
        return identity

    def sync_all(self, devices: List[Dict], apply_rules: bool = True) -> Dict:
        """Sync all devices."""
        results = {'total': 0, 'quarantine': 0, 'internet_only': 0,
                   'lan_only': 0, 'smart_home': 0, 'full_access': 0}

        for d in devices:
            if not d.get('mac'):
                continue
            identity = self.sync_device(
                mac=d['mac'], ip=d.get('ip', ''),
                hostname=d.get('hostname'),
                dhcp_fingerprint=d.get('dhcp_sig') or d.get('dhcp_fingerprint'),
                apply_rules=apply_rules
            )
            results['total'] += 1
            results[identity.policy] = results.get(identity.policy, 0) + 1

        return results

    def get_device(self, mac: str) -> Optional[Dict]:
        """Get device from database."""
        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT * FROM device_identity WHERE mac = ?', (mac.upper(),)
            ).fetchone()
            if row:
                d = dict(row)
                d['signals'] = json.loads(d['signals']) if d['signals'] else {}
                return d
        return None

    def get_all_devices(self) -> List[Dict]:
        """Get all devices."""
        with self._get_conn() as conn:
            rows = conn.execute(
                'SELECT * FROM device_identity ORDER BY last_seen DESC'
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_device(self, mac: str) -> bool:
        """Delete a device from the database.

        This removes the device from device_identity table and any associated
        tags and connection history. Used for removing manually added test
        devices or cleaning up stale entries.

        Args:
            mac: Device MAC address

        Returns:
            True if device was deleted, False if not found
        """
        mac = mac.upper()
        try:
            with self._get_conn() as conn:
                # Check if device exists
                existing = conn.execute(
                    'SELECT mac FROM device_identity WHERE mac = ?', (mac,)
                ).fetchone()

                if not existing:
                    return False

                # Delete from device_identity (main table)
                conn.execute('DELETE FROM device_identity WHERE mac = ?', (mac,))

                # Delete associated tags
                conn.execute('DELETE FROM device_tags WHERE mac = ?', (mac,))

                # Delete connection history
                conn.execute('DELETE FROM connection_history WHERE mac = ?', (mac,))

                conn.commit()
                logger.info(f"Deleted device {mac} from database")
                return True
        except Exception as e:
            logger.error(f"Failed to delete device {mac}: {e}")
            return False

    def ensure_device_exists(self, mac: str, ip: str = None, hostname: str = None,
                              dhcp_fingerprint: str = None, vendor_class: str = None) -> Dict:
        """Ensure a device exists in the database, creating it if necessary.

        This method uses the full Fingerbank identification pipeline to properly
        classify devices. It's called before operations that require the device
        to exist (like adding tags, setting policies, etc.).

        Identity Stack (via Fingerbank module):
        - DHCP Option 55 Fingerprint (50%): OS/Device "DNA" - hardest to spoof
        - MAC OUI Vendor (20%): Manufacturer identification (30,000+ vendors)
        - Hostname Analysis (20%): User-assigned name patterns
        - Fuzzy Matching: Similar fingerprint detection
        - Fingerbank API: Cloud lookup for unknown devices

        Args:
            mac: Device MAC address (required)
            ip: IP address (optional, for discovery)
            hostname: Hostname (optional)
            dhcp_fingerprint: DHCP Option 55 fingerprint (optional but valuable)
            vendor_class: DHCP Option 60 vendor class (optional, high value)

        Returns:
            Device dict (existing or newly created), or None if MAC is blocked
        """
        mac = mac.upper()

        # CRITICAL: Do not recreate blocked/disconnected devices
        if _is_mac_blocked(mac):
            logger.debug(f"Skipping ensure_device_exists for blocked MAC: {mac[:8]}:XX:XX:XX")
            return None

        now = datetime.now().isoformat()

        # Check if device already exists with good confidence
        existing = self.get_device(mac)
        if existing:
            confidence = existing.get('confidence', 0)

            # If we have new identification data, re-run classification
            if dhcp_fingerprint and confidence < 0.8:
                # Re-classify with new fingerprint data
                logger.debug(f"Re-classifying {mac} with new fingerprint data")
                self.sync_device(
                    mac=mac,
                    ip=ip or existing.get('ip', ''),
                    hostname=hostname or existing.get('hostname'),
                    dhcp_fingerprint=dhcp_fingerprint,
                    vendor_class=vendor_class,
                    apply_rules=False  # Don't reapply if manual override
                )
                return self.get_device(mac)

            # Update last_seen, IP, and set status to online (device is active if we're seeing it)
            with self._get_conn() as conn:
                if ip:
                    conn.execute('''
                        UPDATE device_identity SET ip = ?, last_seen = ?, updated_at = ?, status = 'online'
                        WHERE mac = ?
                    ''', (ip, now, now, mac))
                else:
                    conn.execute('''
                        UPDATE device_identity SET last_seen = ?, updated_at = ?, status = 'online'
                        WHERE mac = ?
                    ''', (now, now, mac))
                conn.commit()
            return self.get_device(mac)

        # Device doesn't exist - run through full Fingerbank pipeline
        # This will:
        # 1. Use Fingerbank for comprehensive identification
        # 2. Resolve friendly name via mDNS/Bonjour
        # 3. Calculate proper confidence scores
        # 4. Assign appropriate policy based on device category
        try:
            self.sync_device(
                mac=mac,
                ip=ip or '',
                hostname=hostname,
                dhcp_fingerprint=dhcp_fingerprint,
                vendor_class=vendor_class,
                apply_rules=False  # Don't apply rules - web container can't access OVS
            )
        except Exception as e:
            # Log but don't fail - device creation is more important than rule application
            logger.warning(f"sync_device failed for {mac}: {e}")
            # Try a simple insert as fallback
            try:
                with self._get_conn() as conn:
                    now = datetime.now().isoformat()
                    # Get vendor from OUI for basic identification
                    oui = mac[:8]
                    vendor = self._get_vendor_from_oui(oui)
                    # Set status to 'online' since we're creating this in response to activity
                    conn.execute('''
                        INSERT OR IGNORE INTO device_identity
                            (mac, ip, hostname, vendor, category, policy, confidence,
                             signals, first_seen, last_seen, updated_at, tags, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')
                    ''', (mac, ip or '', hostname or '', vendor, 'unknown', 'quarantine',
                          0.5, '{}', now, now, now, '[]'))
                    conn.commit()
                logger.info(f"Fallback device creation for {mac}")
            except Exception as e2:
                logger.error(f"Fallback device creation also failed for {mac}: {e2}")

        logger.info(f"Created device via Fingerbank pipeline: {mac} (IP: {ip}, Hostname: {hostname})")
        return self.get_device(mac)

    def _get_vendor_from_oui(self, oui: str) -> str:
        """Get vendor name from OUI prefix."""
        # Common OUI prefixes for quick lookup
        oui_vendors = {
            '00:1A:11': 'Google',
            '3C:5A:B4': 'Google',
            'F4:F5:D8': 'Google',
            'A4:77:33': 'Google',
            '94:EB:2C': 'Google',
            '00:17:C4': 'Quanta',
            '00:1B:63': 'Apple',
            '00:1E:C2': 'Apple',
            '00:21:E9': 'Apple',
            '00:22:41': 'Apple',
            '00:23:12': 'Apple',
            '00:23:32': 'Apple',
            '00:23:6C': 'Apple',
            '00:23:DF': 'Apple',
            '00:25:00': 'Apple',
            '00:25:4B': 'Apple',
            '00:25:BC': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4A': 'Apple',
            '00:26:B0': 'Apple',
            '00:26:BB': 'Apple',
            '00:50:E4': 'Apple',
            '04:0C:CE': 'Apple',
            '04:15:52': 'Apple',
            '04:1E:64': 'Apple',
            '04:26:65': 'Apple',
            '04:48:9A': 'Apple',
            '04:52:F3': 'Apple',
            '04:54:53': 'Apple',
            '04:69:F8': 'Apple',
            '04:D3:CF': 'Apple',
            '04:DB:56': 'Apple',
            '04:E5:36': 'Apple',
            '04:F1:3E': 'Apple',
            '04:F7:E4': 'Apple',
            '08:00:27': 'VirtualBox',
            '08:66:98': 'Apple',
            '08:6D:41': 'Apple',
            '10:40:F3': 'Apple',
            '10:93:E9': 'Apple',
            '10:94:BB': 'Apple',
            '10:9A:DD': 'Apple',
            '10:DD:B1': 'Apple',
            '14:10:9F': 'Apple',
            '14:5A:05': 'Apple',
            '14:8F:C6': 'Apple',
            '14:99:E2': 'Apple',
            '18:20:32': 'Apple',
            '18:34:51': 'Apple',
            '18:65:90': 'Apple',
            '18:81:0E': 'Apple',
            '18:9E:FC': 'Apple',
            '18:AF:61': 'Apple',
            '18:AF:8F': 'Apple',
            '18:E7:F4': 'Apple',
            '18:EE:69': 'Apple',
            '18:F6:43': 'Apple',
            '1C:1A:C0': 'Apple',
            '1C:36:BB': 'Apple',
            '1C:5C:F2': 'Apple',
            '1C:91:48': 'Apple',
            '1C:9E:46': 'Apple',
            '1C:AB:A7': 'Apple',
            '1C:E6:2B': 'Apple',
            '20:3C:AE': 'Apple',
            '20:78:F0': 'Apple',
            '20:7D:74': 'Apple',
            '20:9B:CD': 'Apple',
            '20:A2:E4': 'Apple',
            '20:AB:37': 'Apple',
            '20:C9:D0': 'Apple',
            '24:1E:EB': 'Apple',
            '24:24:0E': 'Apple',
            '24:5B:A7': 'Apple',
            '24:AB:81': 'Apple',
            '24:E3:14': 'Apple',
            '24:F0:94': 'Apple',
            '24:F6:77': 'Apple',
            '28:0B:5C': 'Apple',
            '28:37:37': 'Apple',
            '28:5A:EB': 'Apple',
            '28:6A:B8': 'Apple',
            '28:6A:BA': 'Apple',
            '28:A0:2B': 'Apple',
            '28:CF:DA': 'Apple',
            '28:CF:E9': 'Apple',
            '28:E0:2C': 'Apple',
            '28:E1:4C': 'Apple',
            '28:E7:CF': 'Apple',
            '28:ED:6A': 'Apple',
            '28:F0:76': 'Apple',
            '2C:1F:23': 'Apple',
            '2C:20:0B': 'Apple',
            '2C:33:61': 'Apple',
            '2C:54:CF': 'Apple',
            '2C:B4:3A': 'Apple',
            '2C:BE:08': 'Apple',
            '2C:F0:A2': 'Apple',
            '2C:F0:EE': 'Apple',
            '30:35:AD': 'Apple',
            '30:63:6B': 'Apple',
            '30:90:AB': 'Apple',
            '30:F7:C5': 'Apple',
            '34:08:BC': 'Apple',
            '34:12:98': 'Apple',
            '34:15:9E': 'Apple',
            '34:36:3B': 'Apple',
            '34:51:C9': 'Apple',
            '34:A3:95': 'Apple',
            '34:AB:37': 'Apple',
            '34:C0:59': 'Apple',
            '34:E2:FD': 'Apple',
            '38:0F:4A': 'Apple',
            '38:48:4C': 'Apple',
            '38:4F:F0': 'Apple',
            '38:53:9C': 'Apple',
            '38:66:F0': 'Apple',
            '38:71:DE': 'Apple',
            '38:B5:4D': 'Apple',
            '38:C9:86': 'Apple',
            '38:CA:DA': 'Apple',
            '3C:06:30': 'Apple',
            '3C:07:71': 'Apple',
            '3C:15:C2': 'Apple',
            '3C:2E:F9': 'Apple',
            '80:8A:BD': 'Samsung',
            '00:12:FB': 'Samsung',
            '00:13:77': 'Samsung',
            '00:15:B9': 'Samsung',
            '00:16:32': 'Samsung',
            '00:16:6B': 'Samsung',
            '00:16:6C': 'Samsung',
            '00:17:C9': 'Samsung',
            '00:17:D5': 'Samsung',
            '00:18:AF': 'Samsung',
            '00:1A:8A': 'Samsung',
            '00:1B:98': 'Samsung',
            '00:1C:43': 'Samsung',
            '00:1D:25': 'Samsung',
            '00:1D:F6': 'Samsung',
            '00:1E:7D': 'Samsung',
            '00:1E:E1': 'Samsung',
            '00:1E:E2': 'Samsung',
            '00:1F:CC': 'Samsung',
            '00:1F:CD': 'Samsung',
            '00:21:19': 'Samsung',
            '00:21:4C': 'Samsung',
            '00:21:D1': 'Samsung',
            '00:21:D2': 'Samsung',
            '00:23:39': 'Samsung',
            '00:23:3A': 'Samsung',
            '00:23:99': 'Samsung',
            '00:23:D6': 'Samsung',
            '00:23:D7': 'Samsung',
            '00:24:54': 'Samsung',
            '00:24:90': 'Samsung',
            '00:24:91': 'Samsung',
            '00:25:66': 'Samsung',
            '00:25:67': 'Samsung',
            '00:26:37': 'Samsung',
            '00:26:5D': 'Samsung',
            '00:26:5F': 'Samsung',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:05:69': 'VMware',
        }
        oui_upper = oui.upper()
        return oui_vendors.get(oui_upper, 'Unknown')

    def sync_from_device_list(self, devices: List[Dict]) -> int:
        """Sync devices from a list (e.g., from device_status.json or DHCP leases).

        Uses the full Fingerbank identification pipeline to properly classify
        devices. Creates database entries for new devices and updates existing
        ones if new identification data is available.

        Identity Stack (via Fingerbank module):
        - DHCP Option 55 Fingerprint (50%): OS/Device "DNA" - hardest to spoof
        - MAC OUI Vendor (20%): Manufacturer identification (30,000+ vendors)
        - Hostname Analysis (20%): User-assigned name patterns
        - Fuzzy Matching: Similar fingerprint detection
        - Fingerbank API: Cloud lookup for unknown devices

        Args:
            devices: List of dicts with keys:
                - mac: MAC address (required)
                - ip: IP address (optional)
                - hostname: Device hostname (optional)
                - dhcp_fingerprint: DHCP Option 55 (optional but valuable)
                - dhcp_sig: Alias for dhcp_fingerprint (optional)
                - vendor_class: DHCP Option 60 (optional, high value)

        Returns:
            Number of devices synced (new + updated)
        """
        synced = 0
        for device in devices:
            mac = device.get('mac', '').upper()
            if not mac or len(mac) < 17:  # Skip invalid MACs
                continue

            # Extract DHCP fingerprint from various possible keys
            dhcp_fingerprint = (
                device.get('dhcp_fingerprint') or
                device.get('dhcp_sig') or
                device.get('fingerprint')
            )
            vendor_class = device.get('vendor_class')

            # Check existing device
            existing = self.get_device(mac)

            # Sync if: device doesn't exist, or we have new fingerprint data
            should_sync = (
                not existing or
                (dhcp_fingerprint and existing.get('confidence', 0) < 0.8)
            )

            if should_sync:
                self.ensure_device_exists(
                    mac=mac,
                    ip=device.get('ip'),
                    hostname=device.get('hostname') or device.get('name'),
                    dhcp_fingerprint=dhcp_fingerprint,
                    vendor_class=vendor_class
                )
                synced += 1

        if synced > 0:
            logger.info(f"Synced {synced} devices via Fingerbank pipeline")
        return synced

    def set_manual_policy(self, mac: str, policy: str) -> bool:
        """Set manual policy override and apply OpenFlow rules.

        This method:
        1. Updates the policy in the database with manual_override flag
        2. Applies OpenFlow rules via OVS for immediate enforcement
        """
        mac = mac.upper()
        ip = None

        with self._get_conn() as conn:
            # Get device's IP for OpenFlow rules
            row = conn.execute(
                'SELECT ip FROM device_identity WHERE mac = ?', (mac,)
            ).fetchone()
            if row:
                ip = row['ip']

            # Update database
            conn.execute('''
                UPDATE device_identity SET policy = ?, manual_override = 1, updated_at = ?
                WHERE mac = ?
            ''', (policy, datetime.now().isoformat(), mac))
            conn.commit()
            updated = conn.total_changes > 0

        # Apply OpenFlow rules for immediate enforcement
        if updated and ip:
            try:
                self.apply_policy(mac, ip, policy)
                logger.info(f"Policy changed: {mac} -> {policy} (OpenFlow applied)")
            except Exception as e:
                logger.warning(f"Policy updated but OpenFlow failed for {mac}: {e}")
        elif updated:
            logger.warning(f"Policy updated for {mac} but no IP - OpenFlow not applied")

        return updated

    def clear_manual_override(self, mac: str) -> bool:
        """Clear manual override."""
        with self._get_conn() as conn:
            conn.execute('''
                UPDATE device_identity SET manual_override = 0, updated_at = ?
                WHERE mac = ?
            ''', (datetime.now().isoformat(), mac.upper()))
            conn.commit()
            return conn.total_changes > 0

    def get_stats(self) -> Dict:
        """Get statistics."""
        with self._get_conn() as conn:
            rows = conn.execute(
                'SELECT policy, COUNT(*) as count FROM device_identity GROUP BY policy'
            ).fetchall()
            by_policy = {r['policy']: r['count'] for r in rows}

            row = conn.execute('''
                SELECT COUNT(*) as total, AVG(confidence) as avg_conf,
                       SUM(manual_override) as manual
                FROM device_identity
            ''').fetchone()

            return {
                'total': row['total'] if row else 0,
                'avg_confidence': round(row['avg_conf'] or 0, 2),
                'manual_overrides': row['manual'] if row else 0,
                'by_policy': by_policy,
            }

    # =========================================================================
    # PREMIUM STATUS TRACKING - OpenFlow + Kernel Neighbor State
    # =========================================================================

    def get_neighbor_states(self) -> Dict[str, Dict]:
        """Get kernel neighbor (ARP) states for all devices.

        Returns dict mapping IP -> {mac, state, ip}
        States: REACHABLE, STALE, DELAY, PROBE, FAILED, INCOMPLETE

        First tries to read from ARP status JSON file (generated by host-side timer).
        Falls back to `ip neigh show` if file not available.
        """
        neighbors = {}

        # Try reading from ARP status JSON file (works in containers)
        arp_file = Path('/var/lib/hookprobe/arp-status.json')
        try:
            if arp_file.exists():
                with open(arp_file, 'r') as f:
                    arp_data = json.load(f)
                    for mac, info in arp_data.items():
                        mac_upper = mac.upper()
                        ip = info.get('ip', '')
                        state = info.get('state', 'UNKNOWN')
                        # Map online boolean to ARP-like states if state not provided
                        if state == 'UNKNOWN' and info.get('online'):
                            state = 'REACHABLE'
                        if ip:
                            neighbors[ip] = {'mac': mac_upper, 'state': state, 'ip': ip}
                    if neighbors:
                        logger.debug(f"Loaded {len(neighbors)} neighbors from ARP status file")
                        return neighbors
        except Exception as e:
            logger.debug(f"Failed to read ARP status file: {e}")

        # Fallback: try `ip neigh show` (works on host, not in container)
        try:
            result = subprocess.run(
                ['ip', 'neigh', 'show'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = None
                        state = 'UNKNOWN'
                        for i, part in enumerate(parts):
                            if ':' in part and len(part) == 17:  # MAC format
                                mac = part.upper()
                            if part in ('REACHABLE', 'STALE', 'DELAY', 'PROBE', 'FAILED', 'INCOMPLETE', 'PERMANENT'):
                                state = part
                        if mac:
                            neighbors[ip] = {'mac': mac, 'state': state, 'ip': ip}
        except Exception as e:
            logger.debug(f"Failed to get neighbor states: {e}")
        return neighbors

    def get_flow_counters(self, mac: str = None) -> Dict[str, int]:
        """Get OpenFlow packet counters for devices.

        Returns dict mapping MAC -> packet_count
        Uses OVS-OFCTL to query flow statistics.
        """
        counters = {}
        try:
            # Get flow stats from OVS bridge
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', 'FTS', '-O', 'OpenFlow13'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                import re
                for line in result.stdout.strip().split('\n'):
                    # Parse dl_src (source MAC) and n_packets
                    mac_match = re.search(r'dl_src=([0-9a-fA-F:]+)', line)
                    pkt_match = re.search(r'n_packets=(\d+)', line)
                    if mac_match and pkt_match:
                        flow_mac = mac_match.group(1).upper()
                        packets = int(pkt_match.group(1))
                        # Sum packets for same MAC (multiple flows)
                        counters[flow_mac] = counters.get(flow_mac, 0) + packets
        except Exception as e:
            logger.debug(f"Failed to get flow counters: {e}")
        return counters

    def update_online_status(self) -> Dict[str, str]:
        """Update online status for all devices using premium detection.

        Uses three-tier status:
        - ONLINE: Active traffic in last 60s OR neighbor REACHABLE
        - IDLE: No recent traffic but neighbor STALE/DELAY (sleeping device)
        - OFFLINE: No traffic and no ARP response for > 5 minutes

        Returns dict mapping MAC -> new_status
        """
        import math

        # Decay constant for probability calculation (λ)
        # Higher = faster decay to offline
        DECAY_LAMBDA = 0.005  # ~5 min half-life

        # Thresholds
        ONLINE_THRESHOLD = 60      # seconds - active traffic
        IDLE_THRESHOLD = 300       # 5 minutes - still in ARP table
        OFFLINE_THRESHOLD = 600    # 10 minutes - definitely gone

        results = {}
        now = datetime.now()

        # Get kernel neighbor states and flow counters
        neighbors = self.get_neighbor_states()
        flow_counters = self.get_flow_counters()

        # Build IP -> MAC mapping from neighbors
        ip_to_mac = {v['ip']: v['mac'] for v in neighbors.values()}
        mac_to_neighbor = {v['mac']: v for v in neighbors.values()}

        with self._get_conn() as conn:
            devices = conn.execute('SELECT * FROM device_identity').fetchall()

            # Track status transitions for connection history logging
            status_transitions = []

            for row in devices:
                mac = row['mac']
                ip = row['ip']
                last_seen_str = row['last_seen']
                prev_packet_count = row['last_packet_count'] or 0
                prev_status = row['status'] or 'offline'
                device_name = row.get('friendly_name') or row.get('hostname') or mac

                # Calculate time since last seen
                elapsed = OFFLINE_THRESHOLD + 1  # Default to offline
                if last_seen_str:
                    try:
                        last_seen = datetime.fromisoformat(last_seen_str)
                        elapsed = (now - last_seen).total_seconds()
                    except ValueError:
                        pass

                # Get current flow counter
                current_packets = flow_counters.get(mac, 0)
                has_new_traffic = current_packets > prev_packet_count

                # Get neighbor state
                neighbor_info = mac_to_neighbor.get(mac, {})
                neighbor_state = neighbor_info.get('state', 'UNKNOWN')

                # Determine status using priority logic
                new_status = 'offline'

                # 1. Check for active traffic (highest priority)
                if has_new_traffic:
                    new_status = 'online'
                    elapsed = 0  # Reset timer

                # 2. Check neighbor state
                elif neighbor_state in ('REACHABLE',):
                    new_status = 'online'
                elif neighbor_state in ('STALE', 'DELAY', 'PROBE'):
                    # Device is in ARP cache but not actively communicating
                    if elapsed < IDLE_THRESHOLD:
                        new_status = 'idle'
                    else:
                        new_status = 'offline'
                elif neighbor_state in ('FAILED', 'INCOMPLETE'):
                    new_status = 'offline'

                # 3. Fallback to time-based with probability decay
                else:
                    # Calculate probability of presence: P = e^(-λt)
                    prob_present = math.exp(-DECAY_LAMBDA * elapsed)

                    if elapsed < ONLINE_THRESHOLD and prob_present > 0.8:
                        new_status = 'online'
                    elif elapsed < IDLE_THRESHOLD and prob_present > 0.3:
                        new_status = 'idle'
                    else:
                        new_status = 'offline'

                # Update database
                update_time = now.isoformat() if has_new_traffic else last_seen_str
                conn.execute('''
                    UPDATE device_identity
                    SET status = ?, last_packet_count = ?, neighbor_state = ?,
                        last_seen = COALESCE(?, last_seen)
                    WHERE mac = ?
                ''', (new_status, current_packets, neighbor_state, update_time, mac))

                results[mac] = new_status

                # Track significant status transitions for event logging
                if prev_status != new_status:
                    if new_status == 'offline' and prev_status in ('online', 'idle'):
                        status_transitions.append((mac, 'disconnected', f'Device went offline: {device_name}'))
                    elif new_status == 'online' and prev_status == 'offline':
                        status_transitions.append((mac, 'reconnected', f'Device came online: {device_name}'))

            conn.commit()

        # Log status transition events (outside transaction for safety)
        for mac, event_type, details in status_transitions:
            try:
                self.log_connection_event(mac, event_type, details)
            except Exception as e:
                logger.debug(f"Failed to log status transition for {mac}: {e}")

        logger.info(f"Status update: {sum(1 for s in results.values() if s == 'online')} online, "
                   f"{sum(1 for s in results.values() if s == 'idle')} idle, "
                   f"{sum(1 for s in results.values() if s == 'offline')} offline")

        return results

    def get_status_stats(self) -> Dict:
        """Get device status statistics."""
        with self._get_conn() as conn:
            rows = conn.execute('''
                SELECT status, COUNT(*) as count
                FROM device_identity
                GROUP BY status
            ''').fetchall()
            return {r['status'] or 'unknown': r['count'] for r in rows}

    # =========================================================================
    # WIFI SIGNAL & PROXIMITY MANAGEMENT
    # =========================================================================

    def update_wifi_signals(self, signals_data: List[Dict]) -> int:
        """Update WiFi signal data for devices from host collector.

        Args:
            signals_data: List of dicts with mac, rssi, quality, proximity, band, etc.

        Returns:
            Number of devices updated
        """
        updated = 0
        with self._get_conn() as conn:
            for signal in signals_data:
                mac = signal.get('mac', '').upper()
                if not mac:
                    continue

                # Check if device exists
                exists = conn.execute(
                    'SELECT 1 FROM device_identity WHERE mac = ?', (mac,)
                ).fetchone()

                now = datetime.now().isoformat()

                if exists:
                    conn.execute('''
                        UPDATE device_identity SET
                            wifi_rssi = ?,
                            wifi_quality = ?,
                            wifi_proximity = ?,
                            wifi_band = ?,
                            wifi_interface = ?,
                            rx_bytes = COALESCE(?, rx_bytes),
                            tx_bytes = COALESCE(?, tx_bytes),
                            connected_time = COALESCE(?, connected_time),
                            connection_type = 'wifi',
                            status = 'online',
                            last_seen = ?,
                            updated_at = ?
                        WHERE mac = ?
                    ''', (
                        signal.get('rssi'),
                        signal.get('quality'),
                        signal.get('proximity'),
                        signal.get('band'),
                        signal.get('interface'),
                        signal.get('rx_bytes'),
                        signal.get('tx_bytes'),
                        signal.get('connected_time'),
                        now,
                        now,
                        mac
                    ))
                    updated += 1
                else:
                    # WiFi device not in database - create it with basic info
                    # Will be fully identified later via DHCP event or Fingerbank
                    oui = mac[:8]
                    vendor = self._get_vendor_from_oui(oui)
                    conn.execute('''
                        INSERT INTO device_identity (
                            mac, vendor, connection_type, wifi_rssi, wifi_quality,
                            wifi_proximity, wifi_band, wifi_interface, rx_bytes, tx_bytes,
                            connected_time, status, policy, confidence, first_seen, last_seen, updated_at
                        ) VALUES (?, ?, 'wifi', ?, ?, ?, ?, ?, ?, ?, ?, 'online', 'quarantine', 0.3, ?, ?, ?)
                    ''', (
                        mac, vendor,
                        signal.get('rssi'),
                        signal.get('quality'),
                        signal.get('proximity'),
                        signal.get('band'),
                        signal.get('interface'),
                        signal.get('rx_bytes', 0),
                        signal.get('tx_bytes', 0),
                        signal.get('connected_time', 0),
                        now, now, now
                    ))
                    updated += 1
                    logger.info(f"Auto-registered WiFi device: {mac} ({vendor})")

            conn.commit()

        logger.info(f"Updated WiFi signals for {updated} devices")
        return updated

    def get_device_detail(self, mac: str) -> Optional[Dict]:
        """Get comprehensive device detail for modal view.

        Includes: identity, policy, WiFi signal, traffic, tags, history.
        Handles missing tables gracefully for older database versions.
        """
        mac = mac.upper()
        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT * FROM device_identity WHERE mac = ?', (mac,)
            ).fetchone()

            if not row:
                return None

            device = dict(row)

            # Clean device names (remove hex suffixes, UUID patterns, etc.)
            if device.get('hostname'):
                device['hostname'] = clean_device_name(device['hostname'])
            if device.get('friendly_name'):
                device['friendly_name'] = clean_device_name(device['friendly_name'])

            # Parse tags JSON
            try:
                device['tags'] = json.loads(device.get('tags') or '[]')
            except (json.JSONDecodeError, TypeError):
                device['tags'] = []

            # Parse signals JSON
            try:
                device['signals'] = json.loads(device.get('signals') or '{}')
            except (json.JSONDecodeError, TypeError):
                device['signals'] = {}

            # Get metrics (table might not exist in older databases)
            try:
                metrics = conn.execute(
                    'SELECT * FROM device_metrics WHERE mac = ?', (mac,)
                ).fetchone()
                device['metrics'] = dict(metrics) if metrics else {}
            except sqlite3.OperationalError:
                # Table doesn't exist
                device['metrics'] = {}

            # Get connection history (table might not exist in older databases)
            try:
                # Use strftime to compare timestamps properly (ISO format with T separator)
                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                history = conn.execute('''
                    SELECT event_type, timestamp, details
                    FROM connection_history
                    WHERE mac = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                ''', (mac, cutoff)).fetchall()
                device['history'] = [dict(h) for h in history]
            except sqlite3.OperationalError:
                # Table doesn't exist
                device['history'] = []

            # Format traffic for display
            # Note: rx/tx from WiFi driver is from AP perspective:
            #   rx_bytes = bytes AP received FROM device = device's UPLOAD
            #   tx_bytes = bytes AP sent TO device = device's DOWNLOAD
            # We swap here to show from device's perspective in the UI
            ap_rx_bytes = device.get('rx_bytes') or 0  # device upload
            ap_tx_bytes = device.get('tx_bytes') or 0  # device download
            device['traffic'] = {
                'rx_bytes': ap_tx_bytes,  # Device download (shown as "Download" in UI)
                'tx_bytes': ap_rx_bytes,  # Device upload (shown as "Upload" in UI)
                'rx_formatted': self._format_bytes(ap_tx_bytes),  # Device download
                'tx_formatted': self._format_bytes(ap_rx_bytes),  # Device upload
                'total_formatted': self._format_bytes(ap_rx_bytes + ap_tx_bytes)
            }

            return device

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} PB"

    # =========================================================================
    # TAG MANAGEMENT
    # =========================================================================

    def add_tag(self, mac: str, tag: str) -> bool:
        """Add a tag to a device."""
        mac = mac.upper()
        tag = tag.strip()
        if not tag:
            return False

        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT tags FROM device_identity WHERE mac = ?', (mac,)
            ).fetchone()

            if not row:
                return False

            try:
                tags = json.loads(row['tags'] or '[]')
            except json.JSONDecodeError:
                tags = []

            if tag not in tags:
                tags.append(tag)
                conn.execute(
                    'UPDATE device_identity SET tags = ?, updated_at = ? WHERE mac = ?',
                    (json.dumps(tags), datetime.now().isoformat(), mac)
                )
                conn.commit()

            return True

    def remove_tag(self, mac: str, tag: str) -> bool:
        """Remove a tag from a device."""
        mac = mac.upper()

        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT tags FROM device_identity WHERE mac = ?', (mac,)
            ).fetchone()

            if not row:
                return False

            try:
                tags = json.loads(row['tags'] or '[]')
            except json.JSONDecodeError:
                tags = []

            if tag in tags:
                tags.remove(tag)
                conn.execute(
                    'UPDATE device_identity SET tags = ?, updated_at = ? WHERE mac = ?',
                    (json.dumps(tags), datetime.now().isoformat(), mac)
                )
                conn.commit()

            return True

    def get_all_tags(self) -> List[str]:
        """Get all unique tags across all devices."""
        tags = set()
        with self._get_conn() as conn:
            rows = conn.execute('SELECT tags FROM device_identity').fetchall()
            for row in rows:
                try:
                    device_tags = json.loads(row['tags'] or '[]')
                    tags.update(device_tags)
                except json.JSONDecodeError:
                    pass
        return sorted(tags)

    # =========================================================================
    # CONNECTION HISTORY
    # =========================================================================

    def log_connection_event(self, mac: str, event_type: str, details: str = None):
        """Log a connection event for history tracking.

        Event types: connected, disconnected, policy_changed, signal_weak, etc.
        """
        mac = mac.upper()
        with self._get_conn() as conn:
            conn.execute('''
                INSERT INTO connection_history (mac, event_type, timestamp, details)
                VALUES (?, ?, ?, ?)
            ''', (mac, event_type, datetime.now().isoformat(), details))
            conn.commit()

    def get_connection_timeline(self, mac: str, hours: int = 24) -> List[Dict]:
        """Get connection timeline for visualization."""
        mac = mac.upper()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._get_conn() as conn:
            rows = conn.execute('''
                SELECT event_type, timestamp, details
                FROM connection_history
                WHERE mac = ? AND timestamp > ?
                ORDER BY timestamp ASC
            ''', (mac, cutoff)).fetchall()
            return [dict(r) for r in rows]

    # =========================================================================
    # PROXIMITY-BASED SECURITY POLICY
    # =========================================================================

    # Proximity thresholds (dBm)
    PROXIMITY_IMMEDIATE = -45   # Very close, high trust
    PROXIMITY_NEAR = -65        # Same room, trusted
    PROXIMITY_FAR = -75         # Adjacent room, reduced trust
    # Below -75 = "distant" - potential security concern

    def enforce_proximity_policies(self) -> Dict[str, str]:
        """Enforce proximity-based security policies.

        Devices with full_access policy that move to 'distant' proximity
        are automatically downgraded to 'internet_only' for security.

        Returns dict of MAC -> action taken
        """
        actions = {}
        now = datetime.now().isoformat()

        with self._get_conn() as conn:
            # Find full_access devices with distant proximity
            risky_devices = conn.execute('''
                SELECT mac, wifi_rssi, wifi_proximity, policy, friendly_name
                FROM device_identity
                WHERE policy = 'full_access'
                  AND wifi_proximity = 'distant'
                  AND manual_override = 0
            ''').fetchall()

            for device in risky_devices:
                mac = device['mac']
                name = device['friendly_name'] or mac

                # Downgrade policy
                conn.execute('''
                    UPDATE device_identity
                    SET policy = 'internet_only', updated_at = ?
                    WHERE mac = ?
                ''', (now, mac))

                # Log the event
                self.log_connection_event(
                    mac,
                    'proximity_downgrade',
                    f'Auto-downgraded from full_access to internet_only (signal: {device["wifi_rssi"]} dBm)'
                )

                actions[mac] = 'downgraded'
                logger.warning(f"Proximity security: {name} downgraded to internet_only (signal too weak)")

            # Find devices that returned to near proximity - restore policy
            restored_devices = conn.execute('''
                SELECT mac, wifi_rssi, wifi_proximity, friendly_name
                FROM device_identity
                WHERE policy = 'internet_only'
                  AND wifi_proximity IN ('immediate', 'near')
                  AND manual_override = 0
            ''').fetchall()

            # Note: We don't auto-restore to full_access for security
            # Admin must manually re-enable if needed

            conn.commit()

        if actions:
            logger.info(f"Proximity enforcement: {len(actions)} devices affected")

        return actions

    def get_proximity_report(self) -> Dict:
        """Get proximity security report."""
        with self._get_conn() as conn:
            # Count by proximity
            proximity_counts = conn.execute('''
                SELECT wifi_proximity, COUNT(*) as count
                FROM device_identity
                WHERE wifi_proximity IS NOT NULL
                GROUP BY wifi_proximity
            ''').fetchall()

            # Find devices at risk (full_access + far/distant)
            at_risk = conn.execute('''
                SELECT mac, friendly_name, wifi_rssi, wifi_proximity, policy
                FROM device_identity
                WHERE policy IN ('full_access', 'lan_only')
                  AND wifi_proximity IN ('far', 'distant')
            ''').fetchall()

            return {
                'proximity_distribution': {r['wifi_proximity']: r['count'] for r in proximity_counts},
                'devices_at_risk': [dict(d) for d in at_risk],
                'risk_count': len(at_risk)
            }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

_autopilot: Optional[SDNAutoPilot] = None


def get_autopilot() -> SDNAutoPilot:
    """Get global Auto Pilot instance."""
    global _autopilot
    if _autopilot is None:
        _autopilot = SDNAutoPilot()
    return _autopilot


def identify_device(mac: str, hostname: str = None,
                   dhcp_fingerprint: str = None) -> IdentityScore:
    """Quick device identification."""
    return get_autopilot().calculate_identity(mac, hostname, dhcp_fingerprint)


def sync_device(mac: str, ip: str, hostname: str = None,
               dhcp_fingerprint: str = None) -> IdentityScore:
    """Sync device through auto-pilot."""
    return get_autopilot().sync_device(mac, ip, hostname, dhcp_fingerprint)


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    if len(sys.argv) < 2:
        print("Usage: sdn_autopilot.py <command> [args]")
        print("\nCommands:")
        print("  identify <mac> [hostname] [dhcp_sig]")
        print("  sync <mac> <ip> [hostname] [dhcp_sig]")
        print("  stats")
        print("  list")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    pilot = get_autopilot()

    if cmd == "identify" and len(sys.argv) >= 3:
        mac = sys.argv[2]
        hostname = sys.argv[3] if len(sys.argv) > 3 else None
        dhcp_sig = sys.argv[4] if len(sys.argv) > 4 else None

        result = pilot.calculate_identity(mac, hostname, dhcp_sig)
        print(f"\nDevice: {mac}")
        print(f"  Policy:     {result.policy}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Vendor:     {result.vendor}")
        print(f"  OS:         {result.os_fingerprint}")
        print(f"  Category:   {result.category}")
        print(f"  Reason:     {result.reason}")
        print(f"  Signals:    {result.signals}")

    elif cmd == "sync" and len(sys.argv) >= 4:
        mac, ip = sys.argv[2], sys.argv[3]
        hostname = sys.argv[4] if len(sys.argv) > 4 else None
        dhcp_sig = sys.argv[5] if len(sys.argv) > 5 else None

        result = pilot.sync_device(mac, ip, hostname, dhcp_sig)
        print(f"\nSynced: {mac} -> {result.policy} ({result.confidence:.2f})")

    elif cmd == "stats":
        stats = pilot.get_stats()
        print(f"\nSDN Auto-Pilot Stats")
        print(f"  Total: {stats['total']}")
        print(f"  Avg Confidence: {stats['avg_confidence']}")
        print(f"  By Policy: {stats['by_policy']}")

    elif cmd == "list":
        devices = pilot.get_all_devices()
        print(f"\nDevices ({len(devices)}):")
        for d in devices:
            print(f"  {d['mac']}: {d['policy']} ({d.get('confidence', 0):.2f})")
