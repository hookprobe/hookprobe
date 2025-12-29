#!/usr/bin/env python3
"""
Fortress SDN Auto Pilot - Premium Heuristic Scoring Engine

Philosophy: "Guilty until proven Innocent"
Goal: 99% accuracy device classification using multiple identity signals.

Identity Stack (Weighted Scoring):
- DHCP Option 55 Fingerprint (50%): OS/Device "DNA" - hardest to spoof
- MAC OUI Vendor (20%): Manufacturer identification
- Hostname Analysis (20%): User-assigned name patterns
- Active Probing (10%): Open ports/services behavior

Policies (matching device_policies.py):
- QUARANTINE: Unknown devices, no network access (default)
- INTERNET_ONLY: Can access internet but not LAN devices
- LAN_ONLY: Can access LAN but not internet (IoT, printers)
- NORMAL: Curated IoT (HomePod, Echo, Matter/Thread bridges)
- FULL_ACCESS: Management devices with full access

Storage: SQLite database at /var/lib/hookprobe/autopilot.db
"""

import sqlite3
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Database paths
AUTOPILOT_DB = Path('/var/lib/hookprobe/autopilot.db')
FINGERPRINT_DB_FILE = Path('/opt/hookprobe/fortress/data/dhcp_fingerprints.json')

# Network configuration
GATEWAY_IP = "10.200.0.1"
LAN_SUBNET = "10.200.0.0/23"


# =============================================================================
# DHCP Option 55 Fingerprint Database - The Device "DNA"
# =============================================================================

FINGERPRINT_DATABASE = {
    # Apple Devices
    "1,3,6,15,119,252": {"os": "Apple iOS/macOS", "category": "apple", "confidence": 0.95},
    "1,121,3,6,15,119,252": {"os": "Apple iOS 14+", "category": "apple", "confidence": 0.98},
    "1,3,6,15,119,95,252": {"os": "Apple HomePod/Apple TV", "category": "smart_hub", "confidence": 0.99},

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


class SDNAutoPilot:
    """Premium SDN Auto Pilot with Heuristic Scoring Engine."""

    def __init__(self, db_path: Path = AUTOPILOT_DB):
        self.db_path = db_path
        self._ensure_db()
        self._load_custom_fingerprints()

    def _ensure_db(self):
        """Create database and tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS device_identity (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
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
                    updated_at TEXT
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
            conn.execute('CREATE INDEX IF NOT EXISTS idx_policy ON device_identity(policy)')
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

    def _load_custom_fingerprints(self):
        """Load custom fingerprint database if available."""
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
        if vendor != "Unknown":
            signals['oui'] = 0.15
            # Bonus for vendor/fingerprint alignment
            if os_fingerprint != "Unknown" and vendor.lower() in os_fingerprint.lower():
                signals['oui'] = 0.20

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

        return IdentityScore(
            policy=policy,
            confidence=min(1.0, total),
            vendor=vendor,
            os_fingerprint=os_fingerprint,
            category=category,
            signals=signals,
            reason=reason
        )

    def _determine_policy(self, score: float, category: str, vendor: str,
                         hostname: Optional[str]) -> Tuple[str, str]:
        """Determine policy based on score and category."""
        if score >= 0.80:
            if category in ('smart_hub', 'bridge'):
                return 'normal', f"Verified {category} (score: {score:.2f})"
            elif category in ('phone', 'tablet', 'laptop', 'workstation', 'gaming'):
                return 'internet_only', f"Verified device (score: {score:.2f})"
            elif category in ('printer', 'camera', 'iot', 'sensor'):
                return 'lan_only', f"Verified IoT (score: {score:.2f})"
            elif category == 'sbc' and 'raspberry' in vendor.lower():
                return 'full_access', f"Management device (score: {score:.2f})"
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
        """Generate OpenFlow rules for micro-segmentation on VLAN 100."""
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

        elif policy == 'normal':
            rules.append({
                'priority': 600,
                'match': {'eth_src': mac},
                'actions': [{'type': 'OUTPUT', 'port': 'NORMAL'}],
                'comment': "Allow all (curated IoT)"
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
        """Apply OpenFlow rules via OVS."""
        rules = self.generate_openflow_rules(mac, ip, policy)
        logger.info(f"Applying [{policy}] to {mac} ({ip})")

        for rule in rules:
            self._apply_ovs_flow(rule)
        return True

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

    def sync_device(self, mac: str, ip: str, hostname: Optional[str] = None,
                   dhcp_fingerprint: Optional[str] = None,
                   apply_rules: bool = True) -> IdentityScore:
        """Sync device through auto-pilot pipeline."""
        mac = mac.upper()
        identity = self.calculate_identity(mac, hostname, dhcp_fingerprint)

        with self._get_conn() as conn:
            # Check manual override
            existing = conn.execute(
                'SELECT policy, manual_override FROM device_identity WHERE mac = ?', (mac,)
            ).fetchone()

            if existing and existing['manual_override']:
                identity = IdentityScore(
                    policy=existing['policy'],
                    confidence=identity.confidence,
                    vendor=identity.vendor,
                    os_fingerprint=identity.os_fingerprint,
                    category=identity.category,
                    signals=identity.signals,
                    reason="Manual override"
                )

            now = datetime.now().isoformat()
            conn.execute('''
                INSERT INTO device_identity
                    (mac, ip, hostname, vendor, dhcp_fingerprint, os_detected,
                     category, policy, confidence, signals, first_seen, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = COALESCE(excluded.hostname, hostname),
                    vendor = excluded.vendor,
                    dhcp_fingerprint = COALESCE(excluded.dhcp_fingerprint, dhcp_fingerprint),
                    os_detected = excluded.os_detected,
                    category = excluded.category,
                    policy = CASE WHEN manual_override = 1 THEN policy ELSE excluded.policy END,
                    confidence = excluded.confidence,
                    signals = excluded.signals,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at
            ''', (mac, ip, hostname, identity.vendor, dhcp_fingerprint,
                  identity.os_fingerprint, identity.category, identity.policy,
                  identity.confidence, json.dumps(identity.signals), now, now, now))
            conn.commit()

        if apply_rules:
            self.apply_policy(mac, ip, identity.policy)

        logger.info(f"{mac}: {identity.policy} ({identity.confidence:.2f}) - {identity.reason}")
        return identity

    def sync_all(self, devices: List[Dict], apply_rules: bool = True) -> Dict:
        """Sync all devices."""
        results = {'total': 0, 'quarantine': 0, 'internet_only': 0,
                   'lan_only': 0, 'normal': 0, 'full_access': 0}

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

    def set_manual_policy(self, mac: str, policy: str) -> bool:
        """Set manual policy override."""
        with self._get_conn() as conn:
            conn.execute('''
                UPDATE device_identity SET policy = ?, manual_override = 1, updated_at = ?
                WHERE mac = ?
            ''', (policy, datetime.now().isoformat(), mac.upper()))
            conn.commit()
            return conn.total_changes > 0

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
