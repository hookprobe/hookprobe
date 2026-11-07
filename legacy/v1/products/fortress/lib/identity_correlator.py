#!/usr/bin/env python3
"""
HookProbe Fortress - Identity Correlator

Bridges the device_identity.db (persistent identities) with
autopilot.db (SDN policy engine) to handle MAC randomization.

When a DHCP event arrives with a new/randomized MAC:
1. Queries device_identity.db for an existing identity match
2. If found: links the new MAC in autopilot.db to that identity
3. If not found: creates new identity in both databases
4. Writes dnsmasq host reservation for stable IP assignment

Signal hierarchy for cross-MAC identity correlation:
  Priority 1: Existing MAC mapping                 (confidence: 0.95)
  Priority 2: mDNS device name (unique per LAN)    (confidence: 0.90)
  Priority 3: Unique hostname + Option 55 match     (confidence: 0.80)
  Priority 4: Option 55 alone (>= 5 options, IoT)   (confidence: 0.30)

IMPORTANT (per Gemini 3 Flash validation, 2026-03-21):
  - Option 61 (Client ID) is NOT stable across MAC rotations on modern
    iOS/Android/Windows. It derives from the randomized MAC itself.
  - Option 55 identifies device TYPE not INSTANCE. Two iPhone 16s on
    the same network share the same Option 55 fingerprint.
  - mDNS names are the strongest cross-MAC signal for Apple devices.
  - Generic hostnames (iPhone, android-*, localhost, DESKTOP-*) must
    NEVER trigger auto-merge.

Thread-safety: Uses file-based advisory lock (flock) since multiple
dnsmasq events can fire concurrently.

Version: 1.0.0
License: Proprietary (HookProbe Commercial)
"""

import fcntl
import logging
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Paths
LOCK_FILE = Path("/run/hookprobe/identity_correlator.lock")
AUTOPILOT_DB = Path("/var/lib/hookprobe/autopilot.db")
IDENTITY_DB = Path("/var/lib/hookprobe/device_identity.db")
HOSTS_DIR = Path("/etc/dnsmasq.d/hosts.d")

# Thresholds
AUTO_MERGE_THRESHOLD = 0.75

# Generic hostnames that must NEVER trigger auto-merge.
# These are shared by many devices of the same type.
GENERIC_HOSTNAMES = frozenset({
    'iphone', 'ipad', 'macbook', 'macbook-pro', 'macbook-air',
    'android', 'galaxy', 'pixel', 'samsung',
    'desktop', 'laptop', 'windows', 'surface',
    'localhost', 'unknown', 'device', '*',
})

# Patterns for hostnames that are auto-generated and not unique
GENERIC_HOSTNAME_PATTERNS = [
    re.compile(r'^android-[a-f0-9]+$', re.IGNORECASE),       # android-abc123
    re.compile(r'^DESKTOP-[A-Z0-9]+$', re.IGNORECASE),       # DESKTOP-A1B2C3D
    re.compile(r'^LAPTOP-[A-Z0-9]+$', re.IGNORECASE),        # LAPTOP-X1Y2Z3
    re.compile(r'^[A-F0-9]{8,}$', re.IGNORECASE),            # Pure hex (serial numbers)
    re.compile(r'^localhost$', re.IGNORECASE),                 # iOS 17+ privacy
]


@dataclass
class CorrelationResult:
    """Result of identity correlation."""
    identity_id: str
    confidence: float
    match_method: str  # "mac", "mdns", "hostname_fp", "new"
    is_new: bool
    display_name: str
    previous_ip: Optional[str] = None  # For IP stability


@contextmanager
def _identity_lock(timeout: float = 2.0):
    """
    File-based lock to prevent race conditions between concurrent
    DHCP events modifying identity mappings.

    Timeout is short (2s) to not block dnsmasq DHCP responses.
    On timeout, proceeds without lock (better to risk a dup than delay DHCP).
    """
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
                return
            except OSError:
                if time.monotonic() >= deadline:
                    logger.warning("identity_lock timeout after %.1fs, proceeding unlocked", timeout)
                    yield
                    return
                time.sleep(0.05)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def is_generic_hostname(hostname: Optional[str]) -> bool:
    """Check if hostname is generic/auto-generated (unsafe for auto-merge)."""
    if not hostname:
        return True
    h = hostname.lower().strip()
    if h in GENERIC_HOSTNAMES:
        return True
    return any(p.match(h) for p in GENERIC_HOSTNAME_PATTERNS)


def normalize_hostname_base(hostname: Optional[str]) -> Optional[str]:
    """
    Extract the stable base from a hostname for pattern matching.

    "Johns-iPhone"    -> "johns-iphone"
    "Johns-iPhone-2"  -> "johns-iphone"
    "hookprobe's iPad" -> "hookprobe's ipad"
    """
    if not hostname:
        return None
    h = hostname.lower().strip()
    # Strip trailing numbers and separators
    h = re.sub(r'[-_]?\d+$', '', h)
    return h if h and len(h) >= 3 else None


def is_randomized_mac(mac: str) -> bool:
    """Check if MAC is locally administered (randomized/privacy mode)."""
    try:
        first_byte = int(mac.split(':')[0], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def correlate_device(
    mac: str,
    ip: str,
    hostname: Optional[str] = None,
    dhcp_option55: Optional[str] = None,
    dhcp_option61: Optional[str] = None,
    vendor_class: Optional[str] = None,
    mdns_name: Optional[str] = None,
) -> Optional[CorrelationResult]:
    """
    Main entry point: correlate a DHCP event to an existing device identity
    or create a new one.

    Called from dhcp-event.sh Python block and sdn_autopilot.sync_device().

    Returns CorrelationResult or None if identity DB is unavailable.
    """
    mac = mac.upper().replace('-', ':')

    with _identity_lock():
        try:
            return _correlate_locked(
                mac, ip, hostname, dhcp_option55,
                dhcp_option61, vendor_class, mdns_name,
            )
        except Exception as e:
            logger.error("Identity correlation failed for %s: %s", mac[:8], e)
            return None


def _correlate_locked(
    mac: str,
    ip: str,
    hostname: Optional[str],
    dhcp_option55: Optional[str],
    dhcp_option61: Optional[str],
    vendor_class: Optional[str],
    mdns_name: Optional[str],
) -> Optional[CorrelationResult]:
    """Core correlation logic, called under lock."""

    if not IDENTITY_DB.exists():
        logger.debug("Identity DB not found at %s", IDENTITY_DB)
        return None

    conn = sqlite3.connect(str(IDENTITY_DB), timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        # PRIORITY 1: Existing MAC mapping (same MAC reconnecting)
        cursor.execute(
            "SELECT m.identity_id, m.ip_address, d.canonical_name "
            "FROM mac_to_identity m "
            "JOIN device_identities d ON m.identity_id = d.identity_id "
            "WHERE m.mac = ?",
            (mac,)
        )
        row = cursor.fetchone()
        if row:
            _update_last_seen(cursor, row['identity_id'], mac, ip)
            conn.commit()
            return CorrelationResult(
                identity_id=row['identity_id'],
                confidence=0.95,
                match_method='mac',
                is_new=False,
                display_name=row['canonical_name'],
                previous_ip=row['ip_address'],
            )

        # PRIORITY 2: mDNS device name (strongest cross-MAC signal)
        if mdns_name and not is_generic_hostname(mdns_name):
            cursor.execute(
                "SELECT identity_id, canonical_name, current_mac "
                "FROM device_identities WHERE canonical_name = ? OR mdns_device_id = ?",
                (mdns_name, mdns_name)
            )
            row = cursor.fetchone()
            if row:
                # Get previous IP for this identity
                prev_ip = _get_identity_ip(cursor, row['identity_id'])
                _link_mac(cursor, mac, row['identity_id'], dhcp_option55, hostname, ip)
                _update_last_seen(cursor, row['identity_id'], mac, ip)
                conn.commit()
                logger.info("Linked MAC %s to '%s' via mDNS match", mac[:8], row['canonical_name'])
                return CorrelationResult(
                    identity_id=row['identity_id'],
                    confidence=0.90,
                    match_method='mdns',
                    is_new=False,
                    display_name=row['canonical_name'],
                    previous_ip=prev_ip,
                )

        # PRIORITY 3: Option 55 + unique hostname base
        hostname_base = normalize_hostname_base(hostname)
        if dhcp_option55 and hostname_base and not is_generic_hostname(hostname):
            cursor.execute(
                "SELECT d.identity_id, d.canonical_name "
                "FROM device_identities d "
                "JOIN mac_to_identity m ON d.identity_id = m.identity_id "
                "WHERE d.dhcp_option55 = ? AND LOWER(m.hostname) LIKE ? "
                "LIMIT 1",
                (dhcp_option55, hostname_base + '%')
            )
            row = cursor.fetchone()
            if row:
                prev_ip = _get_identity_ip(cursor, row['identity_id'])
                _link_mac(cursor, mac, row['identity_id'], dhcp_option55, hostname, ip)
                _update_last_seen(cursor, row['identity_id'], mac, ip)
                conn.commit()
                logger.info("Linked MAC %s to '%s' via hostname+fp match", mac[:8], row['canonical_name'])
                return CorrelationResult(
                    identity_id=row['identity_id'],
                    confidence=0.80,
                    match_method='hostname_fp',
                    is_new=False,
                    display_name=row['canonical_name'],
                    previous_ip=prev_ip,
                )

        # PRIORITY 4: Option 55 alone — ONLY for IoT/specific devices
        # (never auto-merge consumer devices like phones/laptops on fp alone)
        if dhcp_option55 and _is_specific_fingerprint(dhcp_option55):
            # Check if this fingerprint belongs to a non-consumer device
            # Consumer categories should NOT auto-merge on fingerprint alone
            cursor.execute(
                "SELECT identity_id, canonical_name, device_type "
                "FROM device_identities WHERE dhcp_option55 = ? LIMIT 1",
                (dhcp_option55,)
            )
            row = cursor.fetchone()
            if row:
                device_type = (row['device_type'] or '').lower()
                # Only auto-merge for IoT-like devices where there's usually one per network
                iot_types = {'printer', 'camera', 'thermostat', 'bridge', 'hub',
                             'smart_plug', 'smart_light', 'scale', 'sensor',
                             'doorbell', 'appliance'}
                if device_type in iot_types:
                    prev_ip = _get_identity_ip(cursor, row['identity_id'])
                    _link_mac(cursor, mac, row['identity_id'], dhcp_option55, hostname, ip)
                    _update_last_seen(cursor, row['identity_id'], mac, ip)
                    conn.commit()
                    logger.info("Linked MAC %s to '%s' via IoT fp match", mac[:8], row['canonical_name'])
                    return CorrelationResult(
                        identity_id=row['identity_id'],
                        confidence=0.60,
                        match_method='iot_fp',
                        is_new=False,
                        display_name=row['canonical_name'],
                        previous_ip=prev_ip,
                    )

        # NO MATCH: Create new identity
        # Use the existing DeviceIdentityManager for creation
        try:
            from device_identity import get_identity_manager
            mgr = get_identity_manager(str(IDENTITY_DB))
            identity = mgr.find_or_create_identity(
                mac=mac,
                dhcp_option55=dhcp_option55,
                mdns_name=mdns_name,
                hostname=hostname,
                ip_address=ip,
            )
            return CorrelationResult(
                identity_id=identity.identity_id,
                confidence=0.50 if dhcp_option55 else 0.20,
                match_method='new',
                is_new=True,
                display_name=identity.display_name,
            )
        except Exception as e:
            logger.error("Failed to create identity via manager: %s", e)
            return None

    finally:
        conn.close()


def _is_specific_fingerprint(dhcp_option55: str) -> bool:
    """Check if fingerprint has enough options to be meaningful."""
    if not dhcp_option55:
        return False
    return len(dhcp_option55.split(',')) >= 5


def _get_identity_ip(cursor: sqlite3.Cursor, identity_id: str) -> Optional[str]:
    """Get the most recent IP for this identity (for IP stability)."""
    cursor.execute(
        "SELECT ip_address FROM mac_to_identity "
        "WHERE identity_id = ? AND ip_address IS NOT NULL "
        "ORDER BY assigned_at DESC LIMIT 1",
        (identity_id,)
    )
    row = cursor.fetchone()
    return row['ip_address'] if row else None


def _link_mac(
    cursor: sqlite3.Cursor,
    mac: str,
    identity_id: str,
    dhcp_option55: Optional[str],
    hostname: Optional[str],
    ip_address: Optional[str],
) -> None:
    """Link a MAC address to an identity in mac_to_identity table."""
    import json
    from datetime import datetime
    now = datetime.now().isoformat()

    cursor.execute(
        "INSERT OR REPLACE INTO mac_to_identity "
        "(mac, identity_id, assigned_at, dhcp_option55, hostname, ip_address) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (mac, identity_id, now, dhcp_option55, hostname, ip_address)
    )

    # Update identity's all_macs and current_mac
    cursor.execute(
        "SELECT all_macs FROM device_identities WHERE identity_id = ?",
        (identity_id,)
    )
    row = cursor.fetchone()
    if row:
        all_macs = []
        if row['all_macs']:
            try:
                all_macs = json.loads(row['all_macs'])
            except (json.JSONDecodeError, TypeError):
                all_macs = []
        if mac not in all_macs:
            all_macs.append(mac)
        cursor.execute(
            "UPDATE device_identities SET all_macs = ?, current_mac = ? WHERE identity_id = ?",
            (json.dumps(all_macs), mac, identity_id)
        )


def _update_last_seen(
    cursor: sqlite3.Cursor,
    identity_id: str,
    mac: str,
    ip: Optional[str] = None,
) -> None:
    """Update last_seen and current_mac on the identity."""
    from datetime import datetime
    now = datetime.now().isoformat()
    cursor.execute(
        "UPDATE device_identities SET last_seen = ?, current_mac = ? WHERE identity_id = ?",
        (now, mac, identity_id)
    )
    # Also update IP in mac_to_identity
    if ip:
        cursor.execute(
            "UPDATE mac_to_identity SET ip_address = ?, assigned_at = ? WHERE mac = ?",
            (ip, now, mac)
        )


def link_mac_in_autopilot(
    mac: str,
    identity_id: str,
    db_path: Optional[str] = None,
) -> None:
    """
    Update autopilot.db to link this MAC to an identity_id.
    Marks previous MACs for this identity as non-current.

    Called after successful correlation to keep autopilot in sync.
    """
    ap_db = Path(db_path) if db_path else AUTOPILOT_DB
    if not ap_db.exists():
        return

    conn = sqlite3.connect(str(ap_db), timeout=5)
    try:
        # Check if identity_id column exists (migration may not have run)
        cursor = conn.execute("PRAGMA table_info(device_identity)")
        columns = {row[1] for row in cursor.fetchall()}
        if 'identity_id' not in columns:
            logger.debug("autopilot.db missing identity_id column, skipping link")
            return

        # Mark all previous MACs for this identity as non-current
        conn.execute(
            "UPDATE device_identity SET is_current_mac = 0 WHERE identity_id = ? AND mac != ?",
            (identity_id, mac)
        )
        # Set identity_id on the current MAC
        conn.execute(
            "UPDATE device_identity SET identity_id = ?, is_current_mac = 1 WHERE mac = ?",
            (identity_id, mac)
        )
        conn.commit()
    except sqlite3.OperationalError as e:
        logger.debug("Could not update autopilot.db: %s", e)
    finally:
        conn.close()


def write_dnsmasq_host_reservation(
    mac: str,
    ip: str,
    identity_id: str,
    display_name: str,
) -> bool:
    """
    Write a dnsmasq host file for stable IP assignment.

    When a device reconnects with a new MAC but is correlated to an
    existing identity, we write a host reservation so dnsmasq assigns
    the same IP on next DHCP cycle.

    File: /etc/dnsmasq.d/hosts.d/identity-<id>.conf
    Format: <mac>,<ip>,<hostname>,<lease_time>

    Returns True if file was written and SIGHUP sent.
    """
    if not ip or not mac:
        return False

    HOSTS_DIR.mkdir(parents=True, exist_ok=True)

    # Sanitize display name for dnsmasq hostname (alphanumeric + hyphens only)
    safe_name = re.sub(r'[^a-zA-Z0-9-]', '-', display_name or 'device')[:63]
    safe_name = re.sub(r'-+', '-', safe_name).strip('-').lower()

    # Determine lease time: shorter for randomized MACs
    lease_time = '2h' if is_randomized_mac(mac) else '12h'

    host_file = HOSTS_DIR / f"identity-{identity_id[:12]}.conf"
    content = (
        f"# Auto-generated by HookProbe identity correlator\n"
        f"# Identity: {display_name} ({identity_id[:8]})\n"
        f"# MAC: {mac}\n"
        f"{mac},{ip},{safe_name},{lease_time}\n"
    )

    try:
        host_file.write_text(content)
        # SIGHUP dnsmasq to reload host files
        _sighup_dnsmasq()
        logger.info("Wrote host reservation: %s -> %s (%s)", mac[:8], ip, safe_name)
        return True
    except OSError as e:
        logger.warning("Failed to write host reservation: %s", e)
        return False


def _sighup_dnsmasq() -> None:
    """Send SIGHUP to dnsmasq to reload host files."""
    import signal
    pid_files = [
        Path('/run/dnsmasq/dnsmasq.pid'),
        Path('/var/run/dnsmasq/dnsmasq.pid'),
        Path('/run/dnsmasq.pid'),
    ]
    for pid_file in pid_files:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, signal.SIGHUP)
                return
            except (ValueError, ProcessLookupError, OSError):
                continue
    # Fallback: try pkill
    os.system('pkill -HUP dnsmasq 2>/dev/null')
