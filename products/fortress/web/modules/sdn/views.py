"""
Fortress SDN Views - Unified Device and Network Policy Management

Network Policies:
- QUARANTINE: Unknown devices, no network access (default for unknowns)
- INTERNET_ONLY: Can access internet but not LAN devices
- LAN_ONLY: Can access LAN but not internet (IoT, printers)
- NORMAL: Curated IoT (HomePod, Echo, Matter/Thread bridges)
- FULL_ACCESS: Management devices with full network access
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from collections import defaultdict
from datetime import datetime
from functools import wraps
from threading import Lock
from typing import Dict, List, Optional
import hashlib
import json
import logging
import os
import re
import subprocess
import time


# Simple in-memory rate limiter for security-sensitive endpoints
class RateLimiter:
    """Thread-safe rate limiter to prevent DoS attacks on sensitive endpoints."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.lock = Lock()

    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed for given key (IP or user)."""
        now = time.time()
        with self.lock:
            # Clean old entries
            self.requests[key] = [
                ts for ts in self.requests[key]
                if now - ts < self.window_seconds
            ]
            # Check rate
            if len(self.requests[key]) >= self.max_requests:
                return False
            # Record request
            self.requests[key].append(now)
            return True

    def get_retry_after(self, key: str) -> int:
        """Get seconds until next request is allowed."""
        now = time.time()
        with self.lock:
            if not self.requests[key]:
                return 0
            oldest = min(self.requests[key])
            return max(0, int(self.window_seconds - (now - oldest)))


# Rate limiter for disconnect endpoint: 10 requests per minute per user
disconnect_rate_limiter = RateLimiter(max_requests=10, window_seconds=60)


def rate_limit(limiter: RateLimiter):
    """Decorator to apply rate limiting to an endpoint."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use username if logged in, otherwise IP
            if hasattr(current_user, 'username') and current_user.is_authenticated:
                key = f"user:{current_user.username}"
            else:
                key = f"ip:{request.remote_addr}"

            if not limiter.is_allowed(key):
                retry_after = limiter.get_retry_after(key)
                return jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded. Too many requests.',
                    'retry_after': retry_after
                }), 429

            return f(*args, **kwargs)
        return decorated_function
    return decorator

from . import sdn_bp
from ..auth.decorators import operator_required
from ...security_utils import mask_mac, safe_error_message

# Setup logging
logger = logging.getLogger(__name__)

# Add lib path
import sys
from pathlib import Path
lib_path = Path(__file__).parent.parent.parent.parent / 'lib'
if lib_path.exists() and str(lib_path) not in sys.path:
    sys.path.insert(0, str(lib_path))

# Import device policies module (simple SQLite-based)
DEVICE_POLICIES_AVAILABLE = False
try:
    from device_policies import (
        get_all_devices,
        get_device_stats,
        set_device_policy,
        get_device_db,
        get_policy_info,
        get_recommended_policy,
        NetworkPolicy,
        POLICY_INFO,
    )
    DEVICE_POLICIES_AVAILABLE = True
    logger.info("Device policies module loaded successfully")
except ImportError as e:
    logger.warning(f"Device policies module not available: {e}")

# Import device and VLAN management modules
DEVICE_MANAGERS_AVAILABLE = False
try:
    from device_manager import get_device_manager
    from vlan_manager import get_vlan_manager
    from device_data_manager import get_device_data_manager
    from database import get_db
    DEVICE_MANAGERS_AVAILABLE = True
    logger.info("Device/VLAN managers loaded successfully")
except ImportError as e:
    logger.debug(f"Device managers not available: {e}")

    # Stub functions to prevent NameError
    def get_device_manager():
        return None

    def get_vlan_manager():
        return None

    def get_device_data_manager():
        return None

    def get_db():
        return None

# Import SDN Auto Pilot module (premium heuristic scoring engine)
SDN_AUTOPILOT_AVAILABLE = False
try:
    from sdn_autopilot import (
        get_autopilot as get_sdn_autopilot,
        SDNAutoPilot,
        IdentityScore,
    )
    SDN_AUTOPILOT_AVAILABLE = True
    logger.info("SDN Auto Pilot module loaded successfully")
except ImportError as e:
    logger.warning(f"SDN Auto Pilot module not available: {e}")

    # Stub function to prevent NameError
    def get_sdn_autopilot():
        return None

# Import host agent client for WiFi device control (G.N.C. Architecture)
HOST_AGENT_AVAILABLE = False
try:
    from host_agent_client import (
        get_host_agent_client,
        deauthenticate_device,
        disconnect_device as host_agent_disconnect,  # Renamed to avoid collision with Flask route
        block_device,
        unblock_device,
        is_host_agent_available,
        revoke_lease,
        timed_block_device,  # Enterprise-style disconnect with auto-unblock
    )
    HOST_AGENT_AVAILABLE = True
    logger.info("Host agent client loaded successfully")
except ImportError as e:
    logger.warning(f"Host agent client not available: {e}")

    # Fallback stubs
    def get_host_agent_client():
        return None

    def deauthenticate_device(mac, interfaces=None):
        return {'success': False, 'error': 'Host agent client not available'}

    def host_agent_disconnect(mac, interfaces=None):
        return {'success': False, 'error': 'Host agent client not available'}

    def block_device(mac, interfaces=None):
        return {'success': False, 'error': 'Host agent client not available'}

    def unblock_device(mac, interfaces=None):
        return {'success': False, 'error': 'Host agent client not available'}

    def revoke_lease(mac):
        return {'success': False, 'error': 'Host agent client not available'}

    def timed_block_device(mac, block_duration_seconds=60, interfaces=None):
        return {'success': False, 'error': 'Host agent client not available'}

# Import device names from bubbles module
DEVICE_NAMES_AVAILABLE = False
try:
    from ..bubbles.views import (
        get_all_device_names,
        get_device_custom_name,
        get_db_connection as get_bubbles_db,
    )
    DEVICE_NAMES_AVAILABLE = True
    logger.info("Device names module loaded successfully")
except ImportError as e:
    logger.debug(f"Device names module not available: {e}")

    # Fallback stubs
    def get_all_device_names():
        return {}

    def get_device_custom_name(mac):
        return None

    def is_host_agent_available():
        return False


# Shared ARP status file (updated every 5s by fts-arp-export.timer)
ARP_STATUS_FILE = Path('/var/lib/hookprobe/arp-status.json')


def get_arp_online_status():
    """
    Get real-time online status from ARP table.

    Reads from /var/lib/hookprobe/arp-status.json which is updated
    every 5 seconds by the fts-arp-export.timer systemd service.

    Returns:
        Dict mapping MAC address (uppercase) to online status dict:
        {'online': bool, 'state': str, 'ip': str}
    """
    arp_status = {}
    try:
        if ARP_STATUS_FILE.exists():
            import time as time_module
            # Check file age - if older than 30 seconds, data may be stale
            file_age = time_module.time() - ARP_STATUS_FILE.stat().st_mtime
            if file_age > 30:
                logger.warning(f"ARP status file is {file_age:.0f}s old, data may be stale")

            with open(ARP_STATUS_FILE, 'r') as f:
                arp_status = json.load(f)

            logger.debug(f"ARP status: {len(arp_status)} devices loaded")
        else:
            logger.debug(f"ARP status file not found: {ARP_STATUS_FILE}")

    except Exception as e:
        logger.warning(f"Failed to read ARP status: {e}")

    return arp_status


# Import hostname decoder for dnsmasq octal escapes
try:
    from hostname_decoder import decode_dnsmasq_hostname, clean_device_name, is_randomized_mac
except ImportError:
    # Fallback implementations if module not found
    def decode_dnsmasq_hostname(hostname):
        """Decode dnsmasq octal escapes (fallback implementation)."""
        if not hostname or '\\' not in hostname:
            return hostname
        try:
            result = b''
            i = 0
            while i < len(hostname):
                if hostname[i] == '\\' and i + 3 < len(hostname):
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

    def clean_device_name(hostname, max_length=32):
        """Clean device name (fallback implementation)."""
        if not hostname:
            return None
        name = decode_dnsmasq_hostname(hostname)
        if not name:
            return None
        import re

        # Remove .local suffix first
        if name.endswith('.local'):
            name = name[:-6]

        # Remove hex prefixes (e.g., "F6574fcbe4474hookprobepro" -> "hookprobepro")
        # Match hex chars at start followed by recognizable word
        hex_prefix_match = re.match(r'^[0-9a-fA-F]{8,}[-_]?(.+)$', name)
        if hex_prefix_match:
            remaining = hex_prefix_match.group(1)
            # Only use if remaining part looks like a real name (has letters)
            if re.search(r'[a-zA-Z]{3,}', remaining):
                name = remaining

        # Remove hex/UUID suffixes (e.g., "device-abc123def456", "Hooksound 40edcf82626b")
        # IMPORTANT: Include space (\s) to catch space+hex patterns
        name = re.sub(r'[\s_-][0-9a-fA-F]{6,}(?:[-_]\d+)?$', '', name)

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
        trailing_num_match = re.match(r'^(.+?)\s+(\d+)$', name)
        if trailing_num_match:
            base_name = trailing_num_match.group(1)
            num = int(trailing_num_match.group(2))

            # Keep legitimate product model numbers
            model_patterns = [
                r'(?i)\biphone\s*\d{1,2}$',
                r'(?i)\bipad\s*(pro|air|mini)?\s*\d{1,2}$',
                r'(?i)\bgalaxy\s*[sazm]\d{1,2}$',
                r'(?i)\bpixel\s*\d{1,2}$',
                r'(?i)\bwatch\s*(se|ultra)?\s*\d{1,2}$',
                r'(?i)\bmacbook\s*(pro|air)?\s*\d{2,4}$',
                r'(?i)\bsurface\s*(pro|go|laptop)?\s*\d{1,2}$',
                r'(?i)\bps\d$',
                r'(?i)\becho\s*(dot|show)?\s*\d{1,2}$',
            ]
            is_model = any(re.search(p, name) for p in model_patterns)
            is_possessive = "'s" in base_name.lower() or "'s" in base_name
            is_high_number = num > 20

            if not is_model and (is_high_number or is_possessive or num > 9):
                name = base_name

        # If name is mostly hex/numbers, return None for fallback
        if name and len(re.sub(r'[0-9a-fA-F\s-]', '', name)) < 3:
            return None

        if not name or len(name) < 2:
            return None

        return name[:max_length-3] + '...' if len(name) > max_length else name

    def is_randomized_mac(mac):
        """Check if MAC is locally administered/randomized (fallback)."""
        if not mac:
            return False
        mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').upper()
        if len(mac_clean) != 12:
            return False
        try:
            first_octet = int(mac_clean[:2], 16)
            return bool(first_octet & 0x02)
        except ValueError:
            return False


def get_friendly_name(mac: str, hostname: str, manufacturer: str, device_type: str) -> str:
    """Generate a user-friendly device name with smart fallbacks.

    Priority:
    1. Cleaned hostname (if usable)
    2. Device type + last 4 MAC chars (e.g., "iPhone CE05")
    3. Manufacturer + last 4 MAC chars (e.g., "Withings 5A0A")
    4. For randomized MACs: "Private Device XXXX"
    5. Generic "Device CE05"
    """
    # Try cleaned hostname first
    cleaned = clean_device_name(hostname)
    if cleaned and cleaned != "Unknown Device":
        return cleaned

    # Get last 4 MAC chars for uniqueness
    mac_suffix = mac[-5:].replace(':', '') if mac else '????'

    # Check if this is a randomized/private MAC address
    is_private_mac = is_randomized_mac(mac)

    # Try device type (skip generic types)
    if device_type and device_type.lower() not in ('unknown', '', 'none', 'other'):
        dt = device_type.replace('_', ' ').title()
        return f"{dt} {mac_suffix}"

    # Try manufacturer (this is key for devices like Withings)
    # Skip "Unknown" and empty manufacturers
    if manufacturer and manufacturer.lower() not in ('unknown', 'private', '', 'none'):
        return f"{manufacturer} {mac_suffix}"

    # For randomized MACs (no OUI possible), indicate it's a private address
    if is_private_mac:
        return f"Private Device {mac_suffix}"

    # Fallback
    return f"Device {mac_suffix}"


def classify_device(mac_address: str) -> dict:
    """Simple device classification based on MAC address.

    Returns basic classification info. For full OUI lookup, the device_policies
    module handles this during device discovery.
    """
    mac = mac_address.upper() if mac_address else ''
    oui = mac[:8] if len(mac) >= 8 else mac

    # Basic classification - actual device info comes from device_policies module
    return {
        'mac_address': mac,
        'oui': oui,
        'category': 'unknown',
        'recommended_policy': 'quarantine',
        'manufacturer': 'Unknown'
    }


# Device status cache file (updated by host-based script)
DEVICE_STATUS_CACHE = Path('/opt/hookprobe/fortress/data/device_status.json')

# DHCP devices file (updated by dhcp-event.sh with DHCP fingerprints)
DHCP_DEVICES_FILE = Path('/opt/hookprobe/fortress/data/devices.json')

# WiFi signals file (updated by wifi-signal-collector.sh)
WIFI_SIGNALS_FILE = Path('/opt/hookprobe/fortress/data/wifi_signals.json')

# Blocked MACs file - devices that should not be auto-created
BLOCKED_MACS_FILE = Path('/var/lib/hookprobe/blocked_macs.json')

# MAC validation regex (strict format)
_MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def _hash_mac(mac: str) -> str:
    """Hash a MAC address for secure storage (CWE-312 mitigation).

    Uses SHA-256 with a fixed salt to create a one-way hash.
    This allows checking if a MAC is blocked without storing the raw MAC.
    """
    # Fixed salt - consistent for comparison purposes
    salt = b'hookprobe_blocked_mac_v1'
    mac_normalized = mac.upper().replace('-', ':').encode('utf-8')
    return hashlib.sha256(salt + mac_normalized).hexdigest()[:32]


def _load_blocked_macs() -> set:
    """Load set of blocked MAC hashes.

    Blocked MACs are devices that were manually disconnected and should
    not be auto-created by device discovery. Stored as hashes for security.
    """
    try:
        if BLOCKED_MACS_FILE.exists():
            data = json.loads(BLOCKED_MACS_FILE.read_text())
            if isinstance(data, list):
                return set(data)  # Already hashes
    except (json.JSONDecodeError, IOError) as e:
        logger.debug(f"Failed to load blocked MACs: {e}")
    return set()


def _add_blocked_mac(mac: str) -> bool:
    """Add a MAC address to the blocked list (stored as hash).

    Uses atomic write (temp file + rename) for safety.
    CWE-312 mitigation: Stores hash instead of plain MAC.
    """
    mac = mac.upper().replace('-', ':')
    if not _MAC_REGEX.match(mac):
        logger.warning(f"Invalid MAC format for blocking: {mask_mac(mac)}")
        return False

    try:
        blocked = _load_blocked_macs()
        mac_hash = _hash_mac(mac)
        blocked.add(mac_hash)

        # Atomic write: write to temp file then rename (hashes only)
        temp_file = BLOCKED_MACS_FILE.with_suffix('.tmp')
        temp_file.write_text(json.dumps(sorted(list(blocked)), indent=2))
        temp_file.rename(BLOCKED_MACS_FILE)

        logger.info(f"Added {mask_mac(mac)} to blocked MACs list")
        return True
    except Exception as e:
        logger.error(f"Failed to add blocked MAC: {e}")
        return False


def _remove_blocked_mac(mac: str) -> bool:
    """Remove a MAC address from the blocked list."""
    mac = mac.upper().replace('-', ':')

    try:
        blocked = _load_blocked_macs()
        mac_hash = _hash_mac(mac)
        if mac_hash in blocked:
            blocked.discard(mac_hash)

            # Atomic write (hashes only)
            temp_file = BLOCKED_MACS_FILE.with_suffix('.tmp')
            temp_file.write_text(json.dumps(sorted(list(blocked)), indent=2))
            temp_file.rename(BLOCKED_MACS_FILE)

            logger.info(f"Removed {mask_mac(mac)} from blocked MACs list")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to remove blocked MAC: {e}")
        return False


def _is_mac_blocked(mac: str) -> bool:
    """Check if a MAC address is in the blocked list."""
    mac = mac.upper().replace('-', ':')
    return _hash_mac(mac) in _load_blocked_macs()


def _load_wifi_signals() -> Dict[str, Dict]:
    """Load WiFi signal data from host-generated file.

    Returns dict mapping MAC -> {wifi_rssi, wifi_quality, wifi_proximity, interface}
    """
    signals = {}
    try:
        if WIFI_SIGNALS_FILE.exists():
            data = json.loads(WIFI_SIGNALS_FILE.read_text())
            for station in data.get('stations', []):
                mac = station.get('mac', '').upper()
                if mac:
                    signals[mac] = {
                        'wifi_rssi': station.get('rssi'),
                        'wifi_quality': station.get('quality'),
                        'wifi_proximity': station.get('proximity'),
                        'wifi_interface': station.get('interface'),
                        'wifi_band': station.get('band'),
                    }
    except (json.JSONDecodeError, IOError) as e:
        logger.debug(f"Failed to load WiFi signals: {e}")
    return signals


def _load_device_status_cache() -> Dict[str, Dict]:
    """Load device status and DHCP fingerprints from host-generated files.

    Sources:
    1. device_status.json - Generated by device-status-updater.sh (ip neigh, ovs-ofctl)
    2. devices.json - Generated by dhcp-event.sh (DHCP fingerprints, vendor class)

    The DHCP fingerprint data is critical for accurate device identification via
    the Fingerbank module (99% accuracy with DHCP Option 55 fingerprints).

    Returns dict mapping MAC -> {status, ip, hostname, dhcp_fingerprint, vendor_class, ...}
    """
    cache = {}

    # First, load DHCP devices (has fingerprints but may not have current status)
    try:
        if DHCP_DEVICES_FILE.exists():
            dhcp_data = json.loads(DHCP_DEVICES_FILE.read_text())
            # Validate JSON is a dict
            if not isinstance(dhcp_data, dict):
                logger.warning(f"DHCP devices file has unexpected format: {type(dhcp_data)}")
            else:
                for mac, device in dhcp_data.items():
                    # Skip entries that aren't dicts (corrupt data)
                    if not isinstance(device, dict):
                        # CWE-532: Pre-compute masked MAC to break taint chain
                        mac_safe = mask_mac(mac)
                        logger.debug(f"Skipping non-dict entry for {mac_safe}: {type(device)}")
                        continue
                    mac_upper = mac.upper()
                    cache[mac_upper] = {
                        'status': 'online' if device.get('is_active', False) else 'offline',
                        'neighbor_state': 'REACHABLE' if device.get('is_active', False) else 'STALE',
                        'last_packet_count': 0,
                        'ip': device.get('ip_address', ''),
                        'hostname': clean_device_name(device.get('hostname', '')),
                        'vendor': '',  # Will be detected by Fingerbank from OUI
                        # CRITICAL: DHCP fingerprint data for Fingerbank identification
                        'dhcp_fingerprint': device.get('dhcp_fingerprint', ''),
                        'vendor_class': device.get('vendor_class', ''),
                        'first_seen': device.get('first_seen', ''),
                        'last_seen': device.get('last_seen', ''),
                    }
                logger.debug(f"Loaded DHCP devices: {len(cache)} devices with fingerprints")
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse DHCP devices JSON (corrupt file?): {e}")
        # Try to remove corrupt file
        try:
            DHCP_DEVICES_FILE.unlink()
            logger.info("Removed corrupt DHCP devices file")
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"Failed to load DHCP devices: {e}")

    # Then, merge with status cache (has current status from ip neigh/ovs)
    try:
        if DEVICE_STATUS_CACHE.exists():
            data = json.loads(DEVICE_STATUS_CACHE.read_text())
            for device in data.get('devices', []):
                mac = device.get('mac', '').upper()
                if mac:
                    if mac in cache:
                        # Merge: update status but keep fingerprint data
                        cache[mac].update({
                            'status': device.get('status', cache[mac].get('status', 'offline')),
                            'neighbor_state': device.get('neighbor_state', cache[mac].get('neighbor_state', 'UNKNOWN')),
                            'last_packet_count': device.get('last_packet_count', 0),
                            'ip': device.get('ip', '') or cache[mac].get('ip', ''),
                            'hostname': clean_device_name(device.get('hostname', '') or device.get('name', '') or cache[mac].get('hostname', '')),
                            'vendor': device.get('vendor', '') or cache[mac].get('vendor', ''),
                        })
                    else:
                        # New device from status cache (no DHCP fingerprint yet)
                        cache[mac] = {
                            'status': device.get('status', 'offline'),
                            'neighbor_state': device.get('neighbor_state', 'UNKNOWN'),
                            'last_packet_count': device.get('last_packet_count', 0),
                            'ip': device.get('ip', ''),
                            'hostname': clean_device_name(device.get('hostname', '') or device.get('name', '')),
                            'vendor': device.get('vendor', ''),
                            'dhcp_fingerprint': '',  # Not yet available
                            'vendor_class': '',
                        }
            logger.debug(f"Merged status cache: {len(cache)} total devices")
    except Exception as e:
        logger.warning(f"Failed to load status cache: {e}")

    # Finally, merge with ARP status file (source of truth for online/offline)
    # This file is updated every 5 seconds by the host ARP export timer
    try:
        arp_status = get_arp_online_status()
        if arp_status:
            for mac, arp_info in arp_status.items():
                mac_upper = mac.upper()
                state = arp_info.get('state', 'UNKNOWN')
                ip = arp_info.get('ip', '')

                # Map ARP state to status more accurately:
                # REACHABLE = actively communicating = online
                # STALE/DELAY/PROBE = was seen recently but idle = idle
                # FAILED/INCOMPLETE = unreachable = offline
                if state == 'REACHABLE':
                    status = 'online'
                elif state in ('STALE', 'DELAY', 'PROBE'):
                    status = 'idle'
                else:
                    status = 'offline'

                if mac_upper in cache:
                    # Update status based on ARP state
                    cache[mac_upper]['status'] = status
                    cache[mac_upper]['neighbor_state'] = state
                    if ip and not cache[mac_upper].get('ip'):
                        cache[mac_upper]['ip'] = ip
                else:
                    # New device from ARP (not in DHCP or status cache)
                    cache[mac_upper] = {
                        'status': status,
                        'neighbor_state': state,
                        'last_packet_count': 0,
                        'ip': ip,
                        'hostname': '',
                        'vendor': '',
                        'dhcp_fingerprint': '',
                        'vendor_class': '',
                    }
            logger.debug(f"Merged ARP status: {len([m for m, d in cache.items() if d.get('status') == 'online'])} online, "
                        f"{len([m for m, d in cache.items() if d.get('status') == 'idle'])} idle")
    except Exception as e:
        logger.warning(f"Failed to merge ARP status: {e}")

    # Filter out blocked MACs - these devices were manually disconnected
    # and should not be auto-created by device discovery
    blocked_macs = _load_blocked_macs()
    if blocked_macs:
        before_count = len(cache)
        cache = {mac: info for mac, info in cache.items() if mac not in blocked_macs}
        filtered_count = before_count - len(cache)
        if filtered_count > 0:
            logger.debug(f"Filtered {filtered_count} blocked MACs from device cache")

    return cache


# Note: NetworkSegment enum removed - using NetworkPolicy from device_policies module


# DFS Intelligence for WiFi channel data
DFS_AVAILABLE = False
try:
    dfs_path = Path(__file__).parent.parent.parent.parent.parent.parent / 'shared' / 'wireless'
    if dfs_path.exists() and str(dfs_path) not in sys.path:
        sys.path.insert(0, str(dfs_path))
    from dfs_intelligence import DFSDatabase, ChannelScorer
    DFS_AVAILABLE = True
except ImportError:
    pass

# Legacy flags - set to False to use new simple device_policies module
# These were previously used for PostgreSQL database and complex policy managers
DB_AVAILABLE = False
POLICY_MANAGER_AVAILABLE = False
DEVICE_DATA_MANAGER_AVAILABLE = False

import sqlite3


# ============================================================
# DATA FILE PATHS (written by qsecbit agent running with host network)
# ============================================================
DATA_DIR = Path('/opt/hookprobe/fortress/data')


def _read_agent_data(filename: str, max_age_seconds: int = 60) -> dict:
    """Read data from qsecbit agent data file.

    Returns data if file exists. If data has a timestamp, checks freshness
    but still returns stale data (marked with _stale=True) rather than None.
    This ensures we always have data to display when the agent is running.
    """
    # Check if data directory exists
    if not DATA_DIR.exists():
        logger.debug(f"Data directory not found: {DATA_DIR} - ensure qsecbit agent is running")
        return None

    data_file = DATA_DIR / filename
    if not data_file.exists():
        # List available files for debugging
        available = list(DATA_DIR.glob('*.json')) if DATA_DIR.exists() else []
        logger.debug(f"Agent data file not found: {data_file}. Available: {[f.name for f in available]}")
        return None
    try:
        data = json.loads(data_file.read_text())
        # Check if data is recent (but return stale data anyway)
        if 'timestamp' in data:
            from datetime import datetime
            file_ts = data['timestamp']
            if isinstance(file_ts, str):
                try:
                    # Parse ISO format timestamp
                    file_time = datetime.fromisoformat(file_ts.replace('Z', '+00:00'))
                    if file_time.tzinfo:
                        file_time = file_time.replace(tzinfo=None)
                    age = (datetime.now() - file_time).total_seconds()
                    if age >= max_age_seconds:
                        # Data is stale but still usable - log warning and mark as stale
                        logger.debug(f"Agent data {filename} is stale ({age:.0f}s old)")
                        data['_stale'] = True
                        data['_age_seconds'] = age
                except ValueError as e:
                    logger.debug(f"Could not parse timestamp in {filename}: {e}")
        # Always return data if we got this far
        return data
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON in agent data {filename}: {e}")
    except Exception as e:
        logger.debug(f"Failed to read agent data from {filename}: {e}")
    return None


# NOTE: The old get_real_devices() function has been removed.
# Device management now uses the simple device_policies module with SQLite storage.
# See device_policies.py in lib/ for the new implementation.


def get_dfs_intelligence():
    """
    Get real DFS/WiFi intelligence data from multiple sources.

    Priority:
    1. DFS container API (fts-dfs on port 8050)
    2. DFS database file
    3. WiFi status data file (from qsecbit agent)
    4. Direct hostapd_cli query
    5. Calculate ML score from channel characteristics

    Returns dict with:
    - ml_channel_score: Current ML-based channel safety score (0-100)
    - radar_events: Count of radar events in last 30 days
    - channel_switches: Count of channel switches in last 30 days
    - current_channel: Current WiFi channel
    - next_optimization: Next scheduled optimization time
    - last_optimization: Last optimization timestamp
    """
    import urllib.request

    data = {
        'ml_channel_score': None,
        'radar_events': 0,
        'channel_switches': 0,
        'current_channel': None,
        'next_optimization': None,
        'last_optimization': None,
        'scan_mode': 'basic',
    }

    # Priority 1: Try DFS container API
    try:
        dfs_api_url = os.environ.get('DFS_API_URL', 'http://fts-dfs:8050')
        req = urllib.request.Request(f'{dfs_api_url}/api/status', timeout=3)
        with urllib.request.urlopen(req, timeout=3) as response:
            api_data = json.loads(response.read().decode())
            if api_data.get('success'):
                status = api_data.get('status', {})
                data['current_channel'] = status.get('current_channel')
                data['ml_channel_score'] = status.get('channel_score')
                data['radar_events'] = status.get('radar_events_30d', 0)
                data['channel_switches'] = status.get('channel_switches_30d', 0)
                data['last_optimization'] = status.get('last_scan')
                data['scan_mode'] = 'dfs_intelligence'
                if data['ml_channel_score'] is not None:
                    logger.debug(f"DFS API: channel={data['current_channel']} score={data['ml_channel_score']}")
                    return data
    except Exception as e:
        logger.debug(f"DFS API not available: {e}")

    # Priority 2: Try to get data from DFS database
    db_path = '/var/lib/hookprobe/dfs_intelligence.db'
    try:
        if Path(db_path).exists():
            conn = sqlite3.connect(db_path, timeout=5)
            cursor = conn.cursor()

            # Get radar events count (last 30 days)
            cursor.execute("""
                SELECT COUNT(*) FROM radar_events
                WHERE timestamp > datetime('now', '-30 days')
            """)
            row = cursor.fetchone()
            if row:
                data['radar_events'] = row[0]

            # Get channel switches count (last 30 days)
            cursor.execute("""
                SELECT COUNT(*) FROM channel_switches
                WHERE timestamp > datetime('now', '-30 days')
            """)
            row = cursor.fetchone()
            if row:
                data['channel_switches'] = row[0]

            # Get last channel switch for current channel
            cursor.execute("""
                SELECT to_channel, timestamp FROM channel_switches
                ORDER BY timestamp DESC LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                data['current_channel'] = row[0]
                data['last_optimization'] = row[1]

            conn.close()
            data['scan_mode'] = 'dfs_database'
    except Exception as e:
        logger.debug(f"Failed to read DFS database: {e}")

    # Priority 3: Get WiFi info from qsecbit agent data file
    wifi_file = DATA_DIR / 'wifi_status.json'
    if wifi_file.exists() and data['current_channel'] is None:
        try:
            wifi_data = json.loads(wifi_file.read_text())
            if wifi_data.get('primary_channel'):
                data['current_channel'] = wifi_data['primary_channel']
                logger.debug(f"Got channel from wifi_status.json: {data['current_channel']}")
        except Exception as e:
            logger.debug(f"Failed to read wifi_status.json: {e}")

    # Priority 4: Get current channel from hostapd (fallback)
    if data['current_channel'] is None:
        try:
            result = subprocess.run(
                ['hostapd_cli', '-i', 'wlan0', 'status'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('channel='):
                        data['current_channel'] = int(line.split('=')[1])
                        break
        except Exception as e:
            logger.debug(f"Failed to get hostapd status: {e}")

    # Priority 5: Calculate ML channel score
    if data['ml_channel_score'] is None and data['current_channel']:
        # Try DFS module scorer first
        if DFS_AVAILABLE:
            try:
                db = DFSDatabase(db_path)
                scorer = ChannelScorer(db)
                score = scorer.score_channel(data['current_channel'])
                if score:
                    data['ml_channel_score'] = round(score.total_score * 100)
                    data['scan_mode'] = 'dfs_intelligence'
            except Exception as e:
                logger.debug(f"DFS scorer failed: {e}")

        # Fallback: Calculate score from channel characteristics
        if data['ml_channel_score'] is None:
            channel = data['current_channel']
            score = calculate_channel_score(channel, data['radar_events'])
            data['ml_channel_score'] = score
            data['scan_mode'] = 'channel_analysis'

    # Get next optimization time from systemd timer
    try:
        result = subprocess.run(
            ['systemctl', 'show', 'fts-channel-optimize.timer', '--property=NextElapseUSecRealtime'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and '=' in result.stdout:
            timestamp = result.stdout.strip().split('=')[1]
            if timestamp and timestamp != 'n/a':
                data['next_optimization'] = timestamp
    except Exception as e:
        logger.debug(f"Failed to get optimization timer: {e}")

    return data


def calculate_channel_score(channel: int, radar_events: int = 0) -> int:
    """
    Calculate ML-style channel score based on channel characteristics.

    Factors:
    - DFS status (UNII bands)
    - Channel width capability
    - Regulatory restrictions
    - Radar event history
    - Congestion (estimated from band)

    Returns score 0-100 (higher = better)
    """
    if not channel:
        return None

    score = 100

    # 5GHz DFS channels (UNII-2A: 52-64, UNII-2C: 100-144)
    dfs_channels = list(range(52, 65)) + list(range(100, 145))
    unii1_channels = list(range(36, 49))  # Non-DFS, always safe
    unii3_channels = list(range(149, 166))  # Non-DFS, high power

    # 2.4GHz channels
    if channel <= 14:
        # 2.4GHz is typically more congested
        score = 60
        # Channels 1, 6, 11 are non-overlapping (better)
        if channel in [1, 6, 11]:
            score = 70
        return score

    # 5GHz scoring
    if channel in unii1_channels:
        # UNII-1: No DFS, indoor, typically cleaner
        score = 85
    elif channel in unii3_channels:
        # UNII-3: No DFS, high power, outdoor friendly
        score = 80
    elif channel in dfs_channels:
        # DFS channels: Good spectrum but radar risk
        score = 75

        # UNII-2C (100-144) has weather radar - higher risk
        if channel >= 100 and channel <= 144:
            score = 70

        # Penalize for radar events
        if radar_events > 0:
            score -= min(20, radar_events * 5)

    # Channel width bonus (80MHz capable channels)
    # Primary 80MHz channels: 36, 52, 100, 116, 132, 149
    primary_80mhz = [36, 52, 100, 116, 132, 149]
    if channel in primary_80mhz:
        score += 5

    # Clamp to 0-100
    return max(0, min(100, score))


# ============================================================
# DEMO DATA (fallback only - kept for VLANs and policies)
# ============================================================


def get_demo_policies():
    """Return demo network policies."""
    return [
        {
            'name': 'full_access',
            'display_name': 'Full Access',
            'description': 'Full internet and LAN access',
            'internet_access': True,
            'lan_access': True,
            'icon': 'fa-globe',
            'color': 'success',
        },
        {
            'name': 'lan_only',
            'display_name': 'LAN Only',
            'description': 'Local network only - no internet',
            'internet_access': False,
            'lan_access': True,
            'icon': 'fa-network-wired',
            'color': 'info',
        },
        {
            'name': 'internet_only',
            'display_name': 'Internet Only',
            'description': 'Internet access only - no LAN',
            'internet_access': True,
            'lan_access': False,
            'icon': 'fa-cloud',
            'color': 'primary',
        },
        {
            'name': 'isolated',
            'display_name': 'Isolated',
            'description': 'Completely isolated - no network access',
            'internet_access': False,
            'lan_access': False,
            'icon': 'fa-ban',
            'color': 'danger',
        },
        {
            'name': 'default',
            'display_name': 'Default',
            'description': 'Default policy for unclassified devices',
            'internet_access': True,
            'lan_access': True,
            'icon': 'fa-question-circle',
            'color': 'secondary',
        },
    ]


def get_demo_vlans():
    """Return demo VLANs."""
    return [
        {'vlan_id': 10, 'name': 'Management', 'subnet': '10.250.10.0/24', 'device_count': 2},
        {'vlan_id': 20, 'name': 'POS', 'subnet': '10.250.20.0/24', 'device_count': 1},
        {'vlan_id': 30, 'name': 'Staff', 'subnet': '10.250.30.0/24', 'device_count': 1},
        {'vlan_id': 40, 'name': 'Guest', 'subnet': '10.250.40.0/24', 'device_count': 1},
        {'vlan_id': 99, 'name': 'IoT', 'subnet': '10.250.99.0/24', 'device_count': 3},
    ]


def format_device_for_template(device):
    """Format device data for template consumption."""
    policy = device.get('network_policy', 'default')
    is_blocked = device.get('is_blocked', False)
    is_online = device.get('is_online', False)

    # Determine status
    if is_blocked:
        status = 'blocked'
    elif is_online:
        status = 'online'
    else:
        status = 'offline'

    # Determine access rights based on policy
    access_rights = {
        'full_access': {'lan': True, 'internet': True, 'gateway': True, 'dns': True},
        'lan_only': {'lan': True, 'internet': False, 'gateway': True, 'dns': True},
        'internet_only': {'lan': False, 'internet': True, 'gateway': True, 'dns': True},
        'isolated': {'lan': False, 'internet': False, 'gateway': True, 'dns': True},
        'default': {'lan': True, 'internet': True, 'gateway': True, 'dns': True},
    }
    rights = access_rights.get(policy, access_rights['default'])

    # Icon mapping
    icon_map = {
        'iot': 'fa-microchip',
        'camera': 'fa-video',
        'pos': 'fa-cash-register',
        'voice_assistant': 'fa-microphone',
        'workstation': 'fa-desktop',
        'printer': 'fa-print',
        'phone': 'fa-mobile-alt',
        'tablet': 'fa-tablet-alt',
        'router': 'fa-router',
        'unknown': 'fa-question-circle',
    }
    # Prefer device_type (Fingerbank name like "iPhone", "HomePod")
    # Fall back to oui_category or category
    category = device.get('device_type') or device.get('oui_category') or device.get('category', 'unknown')

    # Format bytes for display
    def format_bytes(b):
        if not b:
            return '0 B'
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f'{b:.1f} {unit}'
            b /= 1024
        return f'{b:.1f} PB'

    mac = device.get('mac_address', '')
    vendor = device.get('manufacturer', 'Unknown')
    hostname = get_friendly_name(mac, device.get('hostname', ''), vendor, category)

    return {
        'mac': mac,
        'ip': device.get('ip_address', ''),
        'hostname': hostname,
        'vendor': vendor,
        'category': category,
        'policy': policy,
        'status': status,
        'is_online': is_online,
        'is_blocked': is_blocked,
        'can_access_lan': rights['lan'] and not is_blocked,
        'can_access_internet': rights['internet'] and not is_blocked,
        'can_access_gateway': rights['gateway'] and not is_blocked,
        'can_access_dns': rights['dns'] and not is_blocked,
        'icon': icon_map.get(category, 'fa-laptop'),
        'first_seen': device.get('first_seen', ''),
        'last_seen': device.get('last_seen', ''),
        'recommended_policy': device.get('auto_policy', 'default'),
        'bytes_sent': format_bytes(device.get('bytes_sent', 0)),
        'bytes_received': format_bytes(device.get('bytes_received', 0)),
        'vlan_id': device.get('vlan_id'),
        'recent_events': device.get('recent_events', []),
    }


# ============================================================
# MAIN DASHBOARD VIEW
# ============================================================

@sdn_bp.route('/')
@login_required
def index():
    """SDN Management Dashboard - unified device and policy view.

    Uses new simple device_policies module with SQLite storage.
    Network Policies:
    - QUARANTINE: Unknown devices, no network access
    - INTERNET_ONLY: Internet access but not LAN
    - LAN_ONLY: LAN access but not internet (IoT, printers)
    - NORMAL: Curated IoT (HomePod, Echo, Matter/Thread bridges)
    - FULL_ACCESS: Management devices with full network access
    """
    devices = []
    policies = []
    stats = {}
    dfs_data = {}
    network_mode = 'vlan'  # Always VLAN mode
    using_real_data = False

    # Primary: Use SDN Auto Pilot (autopilot.db) for device data
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            if autopilot:
                # Load device status from host-generated cache file
                # (web container can't run ip neigh/ovs-ofctl directly)
                status_cache = _load_device_status_cache()

                # Load WiFi signal data from host-generated file
                wifi_signals = _load_wifi_signals()

                # Sync devices from status cache to database
                # This ensures any devices discovered by the host are persisted
                # and properly classified via Fingerbank using DHCP fingerprints
                if status_cache:
                    devices_to_sync = [
                        {
                            'mac': mac,
                            'ip': info.get('ip', ''),
                            'hostname': clean_device_name(info.get('hostname', '')),
                            # CRITICAL: Pass DHCP fingerprint for Fingerbank identification
                            # Identity Stack: DHCP Option 55 (50%) + OUI (20%) + Hostname (20%)
                            'dhcp_fingerprint': info.get('dhcp_fingerprint', ''),
                            'vendor_class': info.get('vendor_class', ''),
                        }
                        for mac, info in status_cache.items()
                    ]
                    autopilot.sync_from_device_list(devices_to_sync)

                db_devices = autopilot.get_all_devices()
                # Convert autopilot format to template format
                for d in db_devices:
                    policy = d.get('policy', 'quarantine')
                    mac = d.get('mac', '').upper()

                    # Get policy info for display (safely handle unknown policies)
                    policy_info = {}
                    if DEVICE_POLICIES_AVAILABLE:
                        try:
                            policy_info = POLICY_INFO.get(NetworkPolicy(policy), {})
                        except ValueError:
                            # CWE-532: Pre-compute masked MAC to break taint chain
                            mac_safe = mask_mac(mac)
                            logger.warning(f"Unknown policy '{policy}' for device {mac_safe}")

                    # Get status from cache, fall back to DB status or 'offline'
                    cached = status_cache.get(mac, {})
                    status = cached.get('status') or d.get('status', 'offline')
                    neighbor_state = cached.get('neighbor_state') or d.get('neighbor_state', 'UNKNOWN')

                    # Map status to display values (online/idle/offline)
                    is_online = status == 'online'
                    is_idle = status == 'idle'
                    is_offline = status == 'offline'

                    # Get WiFi signal data if available
                    wifi_data = wifi_signals.get(mac, {})

                    # Get friendly name with smart fallback
                    raw_name = d.get('friendly_name') or d.get('hostname', '')
                    vendor = d.get('vendor', 'Unknown')
                    # device_type contains Fingerbank-identified name (e.g., "iPhone", "HomePod")
                    # category is just the category (e.g., "phone", "smart_tv")
                    # Use device_type for display, fallback to category
                    device_type = d.get('device_type') or d.get('category', 'unknown')
                    friendly = get_friendly_name(mac, raw_name, vendor, device_type)

                    device = {
                        'mac_address': mac,
                        'ip_address': d.get('ip', ''),
                        'hostname': friendly,
                        'friendly_name': clean_device_name(d.get('friendly_name', '')),
                        'manufacturer': vendor,
                        'device_type': device_type,
                        'policy': policy,
                        'policy_name': policy_info.get('name', policy.replace('_', ' ').title()),
                        'policy_color': policy_info.get('color', 'secondary'),
                        'policy_icon': policy_info.get('icon', 'fa-question'),
                        'confidence': d.get('confidence', 0.0),
                        'status': status,
                        'is_online': is_online,
                        'is_idle': is_idle,
                        'is_offline': is_offline,
                        'neighbor_state': neighbor_state,
                        'is_blocked': policy == 'quarantine',
                        'internet_access': policy in ('internet_only', 'full_access', 'smart_home'),
                        'lan_access': policy in ('lan_only', 'full_access', 'smart_home'),
                        'first_seen': d.get('first_seen', ''),
                        'last_seen': d.get('last_seen', ''),
                        # WiFi signal data (from host wifi-signal-collector.sh)
                        'wifi_rssi': wifi_data.get('wifi_rssi'),
                        'wifi_quality': wifi_data.get('wifi_quality'),
                        'wifi_proximity': wifi_data.get('wifi_proximity'),
                        'wifi_interface': wifi_data.get('wifi_interface'),
                        'wifi_band': wifi_data.get('wifi_band'),
                    }
                    devices.append(device)

                # Calculate stats from devices
                stats = {
                    'total': len(devices),
                    'online': len([d for d in devices if d['is_online']]),
                    'idle': len([d for d in devices if d.get('is_idle')]),
                    'offline': len([d for d in devices if d.get('is_offline')]),
                    'quarantined': len([d for d in devices if d['policy'] == 'quarantine']),
                    'policy_counts': {}
                }
                for d in devices:
                    policy = d['policy']
                    stats['policy_counts'][policy] = stats['policy_counts'].get(policy, 0) + 1

                using_real_data = len(devices) > 0
                logger.info(f"Loaded {len(devices)} devices from autopilot.db")
        except Exception as e:
            logger.error(f"Failed to load from autopilot.db: {e}")

    # Fallback: Use device_policies module if no autopilot data
    if not devices and DEVICE_POLICIES_AVAILABLE:
        try:
            devices = get_all_devices()
            stats = get_device_stats()
            # Ensure policy_counts is set (get_device_stats returns 'by_policy')
            if 'policy_counts' not in stats:
                stats['policy_counts'] = stats.get('by_policy', {})
            using_real_data = len(devices) > 0
            logger.info(f"Loaded {len(devices)} devices from device_policies module")
        except Exception as e:
            logger.error(f"Failed to get device data: {e}")

    # Build policies list from POLICY_INFO
    if DEVICE_POLICIES_AVAILABLE:
        policies = []
        for policy_enum, info in POLICY_INFO.items():
            policies.append({
                'name': policy_enum.value,
                'display_name': info['name'],
                'description': info['description'],
                'internet_access': info['internet'],
                'lan_access': info['lan'],
                'icon': info['icon'],
                'color': info['color'],
            })
    else:
        policies = get_demo_policies()

    # Set default stats if still empty
    if not stats:
        stats = {'total': 0, 'online': 0, 'offline': 0, 'quarantined': 0, 'policy_counts': {}}

    # Ensure policy_counts always exists (template requires it)
    if 'policy_counts' not in stats:
        stats['policy_counts'] = stats.get('by_policy', {})

    # Get real DFS/WiFi intelligence data
    try:
        dfs_data = get_dfs_intelligence()
    except Exception as e:
        logger.debug(f"Failed to get DFS data: {e}")
        dfs_data = {
            'ml_channel_score': None,
            'radar_events': 0,
            'channel_switches': 0,
            'current_channel': None,
            'next_optimization': None,
            'last_optimization': None,
            'scan_mode': 'basic',
        }

    # Load network mode from state file
    try:
        state_file = Path('/etc/hookprobe/fortress-state.json')
        if state_file.exists():
            state = json.loads(state_file.read_text())
            network_mode = state.get('network_mode', 'vlan')
    except Exception:
        pass

    logger.info(f"Rendering SDN index with {len(devices)} devices, using_real_data={using_real_data}")
    if devices:
        # CWE-532: Pre-compute masked values to break taint chain
        # codeql[py/clear-text-logging-sensitive-data] - sample_mac is sanitized, hostname is truncated
        sample_mac = mask_mac(devices[0].get('mac_address') or '')
        sample_host = (devices[0].get('hostname') or '')[:20]  # Truncate hostname, don't log full names
        logger.info(f"First device sample: mac={sample_mac}, hostname_prefix={sample_host}")

    return render_template(
        'sdn/index.html',
        devices=devices,
        policies=policies,
        vlans=[],  # VLANs managed separately
        stats=stats,
        dfs_data=dfs_data,
        network_mode=network_mode,
        db_available=DEVICE_POLICIES_AVAILABLE,
        policy_manager_available=DEVICE_POLICIES_AVAILABLE,
        using_real_data=using_real_data
    )


# ============================================================
# DEVICE DETAIL
# ============================================================

@sdn_bp.route('/device/<mac_address>')
@login_required
def device_detail(mac_address):
    """Device detail view with full SDN info."""
    device = None
    policies = get_demo_policies()
    vlans = get_demo_vlans()

    if DB_AVAILABLE:
        try:
            device_mgr = get_device_manager()
            raw_device = device_mgr.get_device(mac_address)
            if raw_device:
                classification = classify_device(mac_address)
                raw_device['oui_category'] = classification.get('category', 'unknown')
                raw_device['auto_policy'] = classification.get('recommended_policy', 'default')
                raw_device['manufacturer'] = raw_device.get('manufacturer') or classification.get('manufacturer', 'Unknown')
                device = format_device_for_template(raw_device)

            vlan_mgr = get_vlan_manager()
            vlans = vlan_mgr.get_vlans()
        except Exception as e:
            flash(f'Error loading device: {e}', 'warning')

    # No demo fallback - only show real devices
    if not device:
        flash('Device not found', 'warning')
        return redirect(url_for('sdn.index'))

    return render_template(
        'sdn/device_detail.html',
        device=device,
        policies=policies,
        vlans=vlans,
        db_available=DB_AVAILABLE
    )


# ============================================================
# POLICY OPERATIONS
# ============================================================

@sdn_bp.route('/set-policy', methods=['POST'])
@login_required
@operator_required
def set_policy():
    """Set network policy for a device (MAC from form data).

    Uses new simple device_policies module with SQLite storage.
    Valid policies: quarantine, internet_only, lan_only, smart_home, full_access
    """
    mac_address = request.form.get('mac')
    policy = request.form.get('policy')

    if not mac_address or not policy:
        return jsonify({'success': False, 'error': 'MAC address and policy required'}), 400

    # Valid policies from new system
    valid_policies = ['quarantine', 'internet_only', 'lan_only', 'smart_home', 'full_access']
    if policy not in valid_policies:
        return jsonify({'success': False, 'error': f'Invalid policy: {policy}. Valid: {valid_policies}'}), 400

    try:
        if not DEVICE_POLICIES_AVAILABLE:
            return jsonify({'success': False, 'error': 'Device policies module not available'}), 500

        # Use new simple device_policies module
        result = set_device_policy(mac_address, policy)
        # CWE-532: Pre-compute masked MAC to break taint chain for static analysis
        mac_safe = mask_mac(mac_address)
        logger.info(f"Policy for {mac_safe} set to {policy} by user {current_user.id}")

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'message': f'Policy set to {policy}',
                'device': result
            })

        flash(f'Policy for {mac_safe} set to {policy}', 'success')
        return redirect(url_for('sdn.index'))

    except ValueError as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': safe_error_message(e)}), 400
        flash(f'Invalid policy: {e}', 'danger')
        return redirect(url_for('sdn.index'))

    except Exception as e:
        logger.error(f"Error setting policy: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
        flash(f'Error setting policy: {e}', 'danger')
        return redirect(url_for('sdn.index'))


@sdn_bp.route('/auto-classify', methods=['POST'])
@login_required
@operator_required
def auto_classify():
    """Auto-classify device based on OUI (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        classification = classify_device(mac_address)
        recommended = classification.get('recommended_policy', 'default')

        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.update(mac_address, policy=recommended, category=classification.get('category', 'unknown'))

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(recommended), assigned_by='oui')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET network_policy = %s, device_type = %s WHERE mac_address = %s",
                (recommended, classification.get('category'), mac_address.upper())
            )

        return jsonify({
            'success': True,
            'category': classification.get('category'),
            'policy': recommended,
            'policy_applied': recommended,
            'classification': classification
        })

    except Exception as e:
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@sdn_bp.route('/disconnect-device', methods=['POST'])
@login_required
@operator_required
def disconnect_device():
    """Disconnect a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.set_policy(mac_address, 'isolated')

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy.ISOLATED, assigned_by=f'disconnect:{current_user.id}')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.audit_log(
                current_user.id,
                'disconnect',
                'device',
                mac_address,
                {'action': 'disconnect'},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': 'Device disconnected'})

    except Exception as e:
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@sdn_bp.route('/block-device', methods=['POST'])
@login_required
@operator_required
def block_device():
    """Block a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    reason = request.form.get('reason', 'manual_block')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.block(mac_address, reason)

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy.ISOLATED, assigned_by=f'block:{current_user.id}')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET is_blocked = TRUE, network_policy = 'isolated' WHERE mac_address = %s",
                (mac_address.upper(),)
            )
            db.audit_log(
                current_user.id,
                'block',
                'device',
                mac_address,
                {'reason': reason},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': 'Device blocked'})

    except Exception as e:
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@sdn_bp.route('/unblock-device', methods=['POST'])
@login_required
@operator_required
def unblock_device():
    """Unblock a device (MAC from form data)."""
    mac_address = request.form.get('mac')
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    try:
        classification = classify_device(mac_address)
        recommended = classification.get('recommended_policy', 'default')

        # Use device data manager for persistent CRUD (primary)
        if DEVICE_DATA_MANAGER_AVAILABLE:
            ddm = get_device_data_manager()
            ddm.unblock(mac_address)

        # Legacy: policy manager for nftables
        if POLICY_MANAGER_AVAILABLE:
            from network_policy_manager import NetworkPolicyManager, NetworkPolicy
            manager = NetworkPolicyManager(use_nftables=True)
            manager.set_policy(mac_address, NetworkPolicy(recommended), assigned_by='unblock')

        # Legacy: database for additional tracking
        if DB_AVAILABLE:
            db = get_db()
            db.execute(
                "UPDATE devices SET is_blocked = FALSE, network_policy = %s WHERE mac_address = %s",
                (recommended, mac_address.upper())
            )
            db.audit_log(
                current_user.id,
                'unblock',
                'device',
                mac_address,
                {'policy_restored': recommended},
                request.remote_addr
            )

        return jsonify({'success': True, 'message': f'Device unblocked, policy: {recommended}'})

    except Exception as e:
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500




# ============================================================
# BULK OPERATIONS
# ============================================================

@sdn_bp.route('/bulk/set-policy', methods=['POST'])
@login_required
@operator_required
def bulk_set_policy():
    """Set policy for multiple devices."""
    data = request.get_json()
    mac_addresses = data.get('mac_addresses', [])
    policy = data.get('policy')

    if not mac_addresses or not policy:
        return jsonify({'success': False, 'error': 'MAC addresses and policy required'}), 400

    results = {'success': [], 'failed': []}

    for mac in mac_addresses:
        try:
            if POLICY_MANAGER_AVAILABLE:
                from network_policy_manager import NetworkPolicyManager, NetworkPolicy
                manager = NetworkPolicyManager(use_nftables=True)
                manager.set_policy(mac, NetworkPolicy(policy), assigned_by=f'bulk:{current_user.id}')

            if DB_AVAILABLE:
                db = get_db()
                db.execute(
                    "UPDATE devices SET network_policy = %s WHERE mac_address = %s",
                    (policy, mac.upper())
                )

            results['success'].append(mac)
        except Exception as e:
            results['failed'].append({'mac': mac, 'error': safe_error_message(e)})

    return jsonify({
        'success': len(results['failed']) == 0,
        'results': results,
        'message': f'{len(results["success"])} devices updated'
    })


@sdn_bp.route('/bulk/auto-classify', methods=['POST'])
@login_required
@operator_required
def bulk_auto_classify():
    """Auto-classify multiple devices based on OUI."""
    data = request.get_json()
    mac_addresses = data.get('mac_addresses', [])

    if not mac_addresses:
        return jsonify({'success': False, 'error': 'MAC addresses required'}), 400

    results = {'success': [], 'failed': []}

    for mac in mac_addresses:
        try:
            classification = classify_device(mac)
            recommended = classification.get('recommended_policy', 'default')

            if POLICY_MANAGER_AVAILABLE:
                from network_policy_manager import NetworkPolicyManager, NetworkPolicy
                manager = NetworkPolicyManager(use_nftables=True)
                manager.set_policy(mac, NetworkPolicy(recommended), assigned_by='bulk_oui')

            if DB_AVAILABLE:
                db = get_db()
                db.execute(
                    "UPDATE devices SET network_policy = %s, device_type = %s WHERE mac_address = %s",
                    (recommended, classification.get('category'), mac.upper())
                )

            results['success'].append({
                'mac': mac,
                'category': classification.get('category'),
                'policy': recommended
            })
        except Exception as e:
            results['failed'].append({'mac': mac, 'error': safe_error_message(e)})

    return jsonify({
        'success': len(results['failed']) == 0,
        'results': results,
        'message': f'{len(results["success"])} devices classified'
    })


# ============================================================
# DISCOVERY
# ============================================================

@sdn_bp.route('/discover', methods=['POST'])
@login_required
@operator_required
def discover_devices():
    """Load devices from autopilot.db.

    Returns devices already classified by SDN Auto Pilot from
    /var/lib/hookprobe/autopilot.db. No network rescan needed.
    """
    if not SDN_AUTOPILOT_AVAILABLE:
        return jsonify({'success': False, 'error': 'SDN Auto Pilot not available'}), 503

    try:
        autopilot = get_sdn_autopilot()
        if not autopilot:
            return jsonify({'success': False, 'error': 'Auto Pilot not initialized'}), 503

        # Get all devices from autopilot.db (already classified)
        db_devices = autopilot.get_all_devices()

        # Convert to frontend format
        devices = []
        for d in db_devices:
            device = {
                'mac_address': d.get('mac', ''),
                'ip_address': d.get('ip', ''),
                'hostname': clean_device_name(d.get('hostname', '')),
                'friendly_name': clean_device_name(d.get('friendly_name', '')) or d.get('device_type', ''),
                'manufacturer': d.get('vendor', 'Unknown'),
                'device_type': d.get('device_type') or d.get('category', 'unknown'),
                'policy': d.get('policy', 'quarantine'),
                'confidence': d.get('confidence', 0.0),
                'category': d.get('category', 'unknown'),
                'is_online': True,  # Assume online if in DB
                'first_seen': d.get('first_seen', ''),
                'last_seen': d.get('last_seen', ''),
            }
            devices.append(device)

        logger.info(f"Loaded {len(devices)} devices from autopilot.db")

        return jsonify({
            'success': True,
            'total': len(devices),
            'new': 0,  # Not doing new discovery, just loading
            'devices': devices
        })

    except Exception as e:
        logger.error(f"Device discovery failed: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


def _get_dhcp_hostnames() -> Dict[str, str]:
    """Get hostname mapping from DHCP leases file.

    Reads /var/lib/misc/dnsmasq.leases which has format:
    <expiry_timestamp> <mac> <ip> <hostname> <client_id>

    Returns:
        Dict mapping uppercase MAC address to hostname
    """
    hostnames = {}
    dhcp_leases_path = Path('/var/lib/misc/dnsmasq.leases')

    try:
        if dhcp_leases_path.exists():
            with open(dhcp_leases_path, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        mac = parts[1].upper()
                        hostname = parts[3] if parts[3] != '*' else None
                        if hostname:
                            hostnames[mac] = hostname
    except Exception as e:
        logger.debug(f"Failed to read DHCP leases: {e}")

    return hostnames


def _scan_network_devices() -> List[Dict]:
    """Scan network for devices using ARP table and DHCP leases.

    Reads from shared ARP status file updated by fts-arp-export.timer.
    Enriches with hostname from DHCP leases for accurate device names.
    Returns list of discovered devices with basic info.
    """
    devices = []

    try:
        # Get ARP status from shared file (updated every 5s by host-side timer)
        arp_status = get_arp_online_status()

        if not arp_status:
            logger.warning("No ARP status available")
            return devices

        # Get hostnames from DHCP leases (much more reliable than reverse DNS)
        dhcp_hostnames = _get_dhcp_hostnames()

        # Get custom device names (user-defined aliases)
        custom_names = get_all_device_names()

        for mac_address, arp_info in arp_status.items():
            ip_address = arp_info.get('ip', '')
            state = arp_info.get('state', 'UNKNOWN')
            is_online = arp_info.get('online', False)

            # Skip localhost/gateway MACs
            if mac_address.startswith('00:00:00') or mac_address == 'FF:FF:FF:FF:FF:FF':
                continue

            # Get manufacturer from OUI
            manufacturer = _lookup_oui(mac_address)

            # Get hostname from DHCP leases (primary) or reverse DNS (fallback)
            hostname = dhcp_hostnames.get(mac_address) or _resolve_hostname(ip_address)

            # Detect device type
            device_type = _detect_device_type(mac_address, hostname, manufacturer)

            # Get custom name if available (takes priority for display)
            custom_name = custom_names.get(mac_address)

            # Build display name: custom > hostname > manufacturer > MAC prefix
            display_name = custom_name or hostname or manufacturer
            if display_name == 'Unknown':
                display_name = mac_address[:8]

            devices.append({
                'mac_address': mac_address,
                'ip_address': ip_address,
                'hostname': hostname,
                'custom_name': custom_name,  # User-defined alias
                'display_name': display_name,
                'manufacturer': manufacturer,
                'device_type': device_type,
                'state': state,
                'is_online': is_online,
            })

    except Exception as e:
        logger.error(f"Network scan error: {e}")

    return devices


def _lookup_oui(mac_address: str) -> str:
    """Lookup manufacturer from MAC OUI prefix."""
    oui = mac_address[:8].upper()

    # Common manufacturer OUIs
    OUI_MAP = {
        # Apple
        'A4:5E:60': 'Apple', 'AC:BC:32': 'Apple', 'B0:34:95': 'Apple',
        'B8:09:8A': 'Apple', 'BC:52:B7': 'Apple', 'C0:84:7A': 'Apple',
        'D4:9A:20': 'Apple', 'DC:2B:2A': 'Apple', 'E0:B9:BA': 'Apple',
        'F0:B4:79': 'Apple', 'F4:5C:89': 'Apple', '00:1C:B3': 'Apple',
        '14:7D:DA': 'Apple', '28:6A:BA': 'Apple', '3C:06:30': 'Apple',
        # Samsung
        '00:00:F0': 'Samsung', '8C:71:F8': 'Samsung', 'AC:5F:3E': 'Samsung',
        'E4:7C:F9': 'Samsung', 'F0:25:B7': 'Samsung', '94:35:0A': 'Samsung',
        # Google/Nest
        '3C:5A:B4': 'Google', '94:EB:2C': 'Google', 'F4:F5:D8': 'Google',
        '54:60:09': 'Google', 'F8:8F:CA': 'Google', '18:D6:C7': 'Google',
        # Amazon
        '00:FC:8B': 'Amazon', '0C:47:C9': 'Amazon', '34:D2:70': 'Amazon',
        '40:B4:CD': 'Amazon', '44:65:0D': 'Amazon', '68:54:FD': 'Amazon',
        # Intel
        '00:02:B3': 'Intel', '00:03:47': 'Intel', '3C:A9:F4': 'Intel',
        '8C:EC:4B': 'Intel', 'A4:C4:94': 'Intel', 'B4:96:91': 'Intel',
        # Raspberry Pi
        'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
        'E4:5F:01': 'Raspberry Pi', '28:CD:C1': 'Raspberry Pi',
        # TP-Link
        '00:27:19': 'TP-Link', '14:CC:20': 'TP-Link', '30:B5:C2': 'TP-Link',
        '50:C7:BF': 'TP-Link', '54:C8:0F': 'TP-Link', '60:E3:27': 'TP-Link',
        # Hikvision (cameras)
        '44:19:B6': 'Hikvision', 'C0:56:E3': 'Hikvision', 'BC:AD:28': 'Hikvision',
        # Ubiquiti
        '04:18:D6': 'Ubiquiti', '24:A4:3C': 'Ubiquiti', 'F0:9F:C2': 'Ubiquiti',
        # HP
        '00:01:E6': 'HP', '00:02:A5': 'HP', '3C:D9:2B': 'HP',
    }

    return OUI_MAP.get(oui, 'Unknown')


def _resolve_hostname(ip_address: str) -> str:
    """Resolve hostname via reverse DNS."""
    try:
        import socket
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname if hostname != ip_address else None
    except Exception:
        return None


def _detect_device_type(mac: str, hostname: str, manufacturer: str) -> str:
    """Detect device type from available information."""
    hostname_lower = (hostname or '').lower()
    manufacturer_lower = (manufacturer or '').lower()

    # Hostname-based detection
    if 'iphone' in hostname_lower:
        return 'iphone'
    if 'ipad' in hostname_lower:
        return 'tablet'
    if 'macbook' in hostname_lower:
        return 'macbook'
    if 'imac' in hostname_lower:
        return 'desktop'
    if 'android' in hostname_lower:
        return 'android'
    if 'printer' in hostname_lower or 'hp-' in hostname_lower:
        return 'printer'
    if 'camera' in hostname_lower or 'cam' in hostname_lower:
        return 'camera'
    if 'echo' in hostname_lower or 'alexa' in hostname_lower:
        return 'voice_assistant'
    if 'google-home' in hostname_lower or 'nest' in hostname_lower:
        return 'voice_assistant'

    # Manufacturer-based detection
    if manufacturer_lower == 'apple':
        return 'apple_device'
    if manufacturer_lower == 'raspberry pi':
        return 'raspberry_pi'
    if manufacturer_lower in ['samsung', 'google']:
        return 'mobile'
    if manufacturer_lower in ['amazon']:
        return 'voice_assistant'
    if manufacturer_lower in ['hikvision']:
        return 'camera'
    if manufacturer_lower in ['hp']:
        return 'workstation'

    return 'unknown'


def _write_devices_json(devices: List[Dict]):
    """Write discovered devices to JSON file for agent compatibility."""
    try:
        data_dir = Path('/opt/hookprobe/fortress/data')
        data_dir.mkdir(parents=True, exist_ok=True)

        devices_file = data_dir / 'devices.json'

        # Read existing data
        existing_data = {}
        if devices_file.exists():
            try:
                existing_data = json.loads(devices_file.read_text())
                if not isinstance(existing_data, dict):
                    existing_data = {'devices': existing_data if isinstance(existing_data, list) else []}
            except Exception:
                existing_data = {'devices': []}

        # Merge with discovered devices
        existing_macs = {d.get('mac_address', '').upper() for d in existing_data.get('devices', [])}
        merged_devices = list(existing_data.get('devices', []))

        for device in devices:
            mac = device.get('mac_address', '').upper()
            if mac not in existing_macs:
                merged_devices.append(device)
                existing_macs.add(mac)
            else:
                # Update existing device
                for i, d in enumerate(merged_devices):
                    if d.get('mac_address', '').upper() == mac:
                        merged_devices[i].update(device)
                        break

        # Write updated data
        output = {
            'devices': merged_devices,
            'timestamp': datetime.now().isoformat(),
            'source': 'web_discovery'
        }
        devices_file.write_text(json.dumps(output, indent=2))
        logger.info(f"Updated devices.json with {len(merged_devices)} devices")

    except Exception as e:
        logger.warning(f"Failed to write devices.json: {e}")


# ============================================================
# API ENDPOINTS
# ============================================================

@sdn_bp.route('/api/devices')
@login_required
def api_devices():
    """Get all devices with SDN info (JSON).

    Uses new simple device_policies module with SQLite storage.
    """
    devices = []
    using_real_data = False

    # Use new simple device_policies module
    if DEVICE_POLICIES_AVAILABLE:
        try:
            devices = get_all_devices()
            using_real_data = len(devices) > 0
        except Exception as e:
            logger.error(f"Failed to get devices: {e}")
            devices = []

    # Load WiFi signals and merge into device data
    wifi_signals = _load_wifi_signals()
    for device in devices:
        mac = device.get('mac_address', '').upper()
        wifi_data = wifi_signals.get(mac, {})
        device['wifi_rssi'] = wifi_data.get('wifi_rssi')
        device['wifi_quality'] = wifi_data.get('wifi_quality')
        device['wifi_proximity'] = wifi_data.get('wifi_proximity')
        device['wifi_interface'] = wifi_data.get('wifi_interface')
        device['wifi_band'] = wifi_data.get('wifi_band')

    # Apply filters
    policy_filter = request.args.get('policy')
    online_filter = request.args.get('online')

    if policy_filter:
        devices = [d for d in devices if d.get('policy') == policy_filter]
    if online_filter:
        is_online = online_filter.lower() == 'true'
        devices = [d for d in devices if d.get('is_online') == is_online]

    return jsonify({
        'success': True,
        'count': len(devices),
        'devices': devices,
        'using_real_data': using_real_data
    })


@sdn_bp.route('/api/debug/devices')
@login_required
def api_debug_devices():
    """Debug endpoint to view device data from agent file and policy database."""
    data_file = DATA_DIR / 'devices.json'
    result = {
        'file_path': str(data_file),
        'file_exists': data_file.exists(),
        'raw_data': None,
        'device_policies_available': DEVICE_POLICIES_AVAILABLE,
        'devices_from_module': None,
        'errors': []
    }

    # Check raw agent file
    if data_file.exists():
        try:
            result['raw_data'] = json.loads(data_file.read_text())
            if isinstance(result['raw_data'], dict):
                result['device_count_in_file'] = len(result['raw_data'].get('devices', []))
        except Exception as e:
            result['errors'].append(f"Failed to read raw file: {e}")

    # Check device_policies module
    if DEVICE_POLICIES_AVAILABLE:
        try:
            devices = get_all_devices()
            result['devices_from_module'] = {
                'success': True,
                'count': len(devices),
                'devices': devices[:5] if devices else []  # First 5 only
            }
        except Exception as e:
            result['errors'].append(f"get_all_devices() error: {e}")
    else:
        result['errors'].append("device_policies module not available")

    return jsonify(result)


@sdn_bp.route('/api/stats')
@login_required
def api_stats():
    """Get SDN statistics.

    Uses autopilot.db for device data (consistent with index view).
    """
    stats = {'total': 0, 'online': 0, 'idle': 0, 'offline': 0, 'quarantined': 0, 'policy_counts': {}}
    using_real_data = False

    # Use SDN Auto Pilot (autopilot.db) - same source as index view
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            if autopilot:
                # Update online status from ARP data (logs connection events)
                try:
                    autopilot.update_online_status()
                except Exception as e:
                    logger.debug(f"Failed to update online status: {e}")

                # Load status from cache
                status_cache = _load_device_status_cache()
                devices = autopilot.get_all_devices()

                # Calculate stats
                online = 0
                idle = 0
                offline = 0
                policy_counts = {}

                for d in devices:
                    mac = d.get('mac', '').upper()
                    policy = d.get('policy', 'quarantine')

                    # Get status from cache
                    cached = status_cache.get(mac, {})
                    status = cached.get('status') or d.get('status', 'offline')

                    if status == 'online':
                        online += 1
                    elif status == 'idle':
                        idle += 1
                    else:
                        offline += 1

                    policy_counts[policy] = policy_counts.get(policy, 0) + 1

                stats = {
                    'total': len(devices),
                    'online': online,
                    'idle': idle,
                    'offline': offline,
                    'quarantined': policy_counts.get('quarantine', 0),
                    'policy_counts': policy_counts,
                }
                using_real_data = len(devices) > 0
        except Exception as e:
            logger.error(f"Failed to get stats from autopilot: {e}")

    # Add DFS intelligence data
    try:
        dfs_data = get_dfs_intelligence()
        stats['dfs'] = dfs_data
    except Exception:
        stats['dfs'] = {}

    return jsonify({'success': True, 'stats': stats, 'using_real_data': using_real_data})


@sdn_bp.route('/api/classify/<mac_address>')
@login_required
def api_classify(mac_address):
    """Get OUI classification for a MAC address."""
    classification = classify_device(mac_address)
    return jsonify({
        'success': True,
        'classification': classification
    })


@sdn_bp.route('/api/policies')
@login_required
def api_policies():
    """Get available network policies.

    Returns policies from device_policies module if available.
    """
    policies = []

    if DEVICE_POLICIES_AVAILABLE:
        # Build policies list from POLICY_INFO
        for policy_enum, info in POLICY_INFO.items():
            policies.append({
                'name': policy_enum.value,
                'display_name': info['name'],
                'description': info['description'],
                'internet_access': info['internet'],
                'lan_access': info['lan'],
                'icon': info['icon'],
                'color': info['color'],
            })
    else:
        policies = get_demo_policies()

    return jsonify({
        'success': True,
        'policies': policies
    })


@sdn_bp.route('/api/wifi-intelligence')
@login_required
def api_wifi_intelligence():
    """Get WiFi channel optimization and DFS intelligence data."""
    import os
    from datetime import timedelta

    # Start with data from get_dfs_intelligence()
    dfs_data = get_dfs_intelligence()

    data = {
        'current_channel': dfs_data.get('current_channel'),
        'band': '5GHz' if dfs_data.get('current_channel') and dfs_data.get('current_channel') > 14 else '2.4GHz',
        'hw_mode': 'a' if dfs_data.get('current_channel') and dfs_data.get('current_channel') > 14 else 'g',
        'last_optimization': dfs_data.get('last_optimization'),
        'previous_channel': None,
        'next_optimization': dfs_data.get('next_optimization'),
        'time_to_next': None,
        'ml_score': dfs_data.get('ml_channel_score'),
        'radar_events': [],
        'radar_count_30d': dfs_data.get('radar_events', 0),
        'channel_switches_30d': dfs_data.get('channel_switches', 0),
        'dfs_available': DFS_AVAILABLE or Path('/usr/local/bin/dfs-channel-selector').exists(),
        'optimization_method': dfs_data.get('scan_mode', 'basic_scan'),
        'wifi_interface': None,
        'ssid': None,
        # Dual-band support
        'ssid_24ghz': None,
        'ssid_5ghz': None,
        'channel_24ghz': None,
        'channel_5ghz': None,
    }

    # Priority 1: Read from wifi_status.json written by qsecbit agent
    wifi_data = _read_agent_data('wifi_status.json', max_age_seconds=120)
    if wifi_data:
        # Support dual-band from agent data
        if wifi_data.get('ssid_24ghz') or wifi_data.get('ssid_5ghz'):
            data['ssid_24ghz'] = wifi_data.get('ssid_24ghz')
            data['ssid_5ghz'] = wifi_data.get('ssid_5ghz')
            data['channel_24ghz'] = wifi_data.get('channel_24ghz')
            data['channel_5ghz'] = wifi_data.get('channel_5ghz')
            # Use 5GHz as primary if available
            data['ssid'] = data['ssid_5ghz'] or data['ssid_24ghz']
            data['current_channel'] = data['channel_5ghz'] or data['channel_24ghz']
            data['band'] = '5GHz' if data['channel_5ghz'] else '2.4GHz'
        elif wifi_data.get('primary_ssid'):
            data['ssid'] = wifi_data.get('primary_ssid')
            data['current_channel'] = wifi_data.get('primary_channel')
            data['band'] = wifi_data.get('primary_band', '5GHz')
            data['hw_mode'] = 'a' if data['band'] == '5GHz' else 'g'

        # Process interfaces for dual-band info
        if wifi_data.get('interfaces'):
            for iface_info in wifi_data['interfaces']:
                channel = iface_info.get('channel')
                ssid = iface_info.get('ssid')
                if channel and channel <= 14:
                    data['channel_24ghz'] = channel
                    data['ssid_24ghz'] = ssid or data['ssid']
                elif channel and channel > 14:
                    data['channel_5ghz'] = channel
                    data['ssid_5ghz'] = ssid or data['ssid']
                if not data['wifi_interface']:
                    data['wifi_interface'] = iface_info.get('interface')

        logger.debug(f"Loaded WiFi status from agent data: SSID={data['ssid']} ch_24={data['channel_24ghz']} ch_5={data['channel_5ghz']}")
    else:
        # Priority 2: Fallback - Read hostapd config files directly
        # Check for dual-band configs
        hostapd_configs = [
            ('/etc/hostapd/fortress-5ghz.conf', '5GHz'),
            ('/etc/hostapd/fortress-24ghz.conf', '2.4GHz'),
            ('/etc/hostapd/fortress.conf', None),  # Single config fallback
        ]

        for conf_path, band_hint in hostapd_configs:
            if os.path.exists(conf_path):
                try:
                    conf_data = {}
                    with open(conf_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('channel='):
                                conf_data['channel'] = int(line.split('=')[1])
                            elif line.startswith('hw_mode='):
                                conf_data['hw_mode'] = line.split('=')[1]
                            elif line.startswith('interface='):
                                conf_data['interface'] = line.split('=')[1]
                            elif line.startswith('ssid='):
                                conf_data['ssid'] = line.split('=')[1]

                    # Determine band
                    ch = conf_data.get('channel')
                    is_5ghz = (band_hint == '5GHz' or
                               conf_data.get('hw_mode') == 'a' or
                               (ch and ch > 14))

                    if is_5ghz:
                        data['channel_5ghz'] = ch
                        data['ssid_5ghz'] = conf_data.get('ssid')
                    else:
                        data['channel_24ghz'] = ch
                        data['ssid_24ghz'] = conf_data.get('ssid')

                    # Set primary values
                    if not data['current_channel']:
                        data['current_channel'] = ch
                        data['hw_mode'] = conf_data.get('hw_mode', 'a' if is_5ghz else 'g')
                        data['wifi_interface'] = conf_data.get('interface')
                        data['ssid'] = conf_data.get('ssid')
                        data['band'] = '5GHz' if is_5ghz else '2.4GHz'
                except Exception:
                    pass

    # Read channel state file for optimization history
    state_file = '/var/lib/fortress/channel_state.json'
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                data['last_optimization'] = state.get('last_scan')
                data['previous_channel'] = state.get('previous_channel')
                data['optimization_method'] = state.get('method', 'interference_score')
                if state.get('score'):
                    data['ml_score'] = state.get('score')
        except Exception:
            pass

    # Calculate next optimization time (4:00 AM)
    now = datetime.now()
    next_4am = now.replace(hour=4, minute=0, second=0, microsecond=0)
    if now.hour >= 4:
        next_4am += timedelta(days=1)
    data['next_optimization'] = next_4am.isoformat()
    time_diff = next_4am - now
    hours, remainder = divmod(int(time_diff.total_seconds()), 3600)
    minutes = remainder // 60
    data['time_to_next'] = f'{hours}h {minutes}m'
    data['time_to_next_seconds'] = int(time_diff.total_seconds())

    # Check if DFS intelligence is available
    dfs_selector = '/usr/local/bin/dfs-channel-selector'
    if os.path.exists(dfs_selector) and os.access(dfs_selector, os.X_OK):
        data['dfs_available'] = True

        # Try to get DFS status
        try:
            result = subprocess.run(
                [dfs_selector, 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse status output
                for line in result.stdout.strip().split('\n'):
                    if 'radar events' in line.lower():
                        try:
                            data['radar_count_30d'] = int(line.split(':')[1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
        except Exception:
            pass

        # Try to get current channel score
        if data['current_channel'] and data['band'] == '5GHz':
            try:
                result = subprocess.run(
                    [dfs_selector, 'score', str(data['current_channel'])],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    try:
                        data['ml_score'] = float(result.stdout.strip())
                    except ValueError:
                        pass
            except Exception:
                pass

    # Read radar events from DFS log
    radar_log = '/var/lib/fortress/dfs/radar_events.jsonl'
    if os.path.exists(radar_log):
        try:
            events = []
            with open(radar_log, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        events.append(event)
                    except json.JSONDecodeError:
                        pass
            # Return last 10 events
            data['radar_events'] = events[-10:]
            # Count events in last 30 days
            cutoff = (datetime.now() - timedelta(days=30)).isoformat()
            data['radar_count_30d'] = len([e for e in events if e.get('timestamp', '') > cutoff])
        except Exception:
            pass

    # Read channel switch count from optimization log
    opt_log = '/var/log/hookprobe/channel-optimization.log'
    if os.path.exists(opt_log):
        try:
            with open(opt_log, 'r') as f:
                content = f.read()
                # Count "Updating hostapd config to channel" lines
                data['channel_switches_30d'] = content.count('Updating hostapd config to channel')
        except Exception:
            pass

    return jsonify({
        'success': True,
        'wifi_intelligence': data
    })


# ============================================================
# EXPORT
# ============================================================

@sdn_bp.route('/export')
@login_required
def export_devices():
    """Export device inventory with SDN info.

    Uses new simple device_policies module.
    """
    format_type = request.args.get('format', 'json')
    devices = []

    # Use new simple device_policies module
    if DEVICE_POLICIES_AVAILABLE:
        try:
            devices = get_all_devices()
        except Exception as e:
            logger.error(f"Failed to get devices for export: {e}")

    if format_type == 'csv':
        import csv
        import io

        output = io.StringIO()
        if devices:
            writer = csv.DictWriter(output, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)

        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=sdn_devices.csv'
        }
    else:
        return jsonify({
            'exported_at': datetime.now().isoformat(),
            'count': len(devices),
            'devices': devices
        }), 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename=sdn_devices.json'
        }


# ============================================================
# SEGMENT DASHBOARD - Per-Category Traffic Visualization
# ============================================================

def get_demo_segment_data():
    """Return demo segment data for development."""
    import random
    import time

    base_time = time.time()
    segments = {
        'SECMON': {
            'vlan_id': 10,
            'name': 'Security Monitoring',
            'icon': 'fa-shield-alt',
            'color': '#17a2b8',
            'device_count': 3,
            'active_count': 2,
            'bytes_in': 524288000,
            'bytes_out': 1048576000,
            'bandwidth_mbps': 12.5,
            'top_devices': [
                {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology NVR', 'bytes': 800000000},
                {'mac': '00:0C:F6:AA:BB:CC', 'hostname': 'Axis Camera Hub', 'bytes': 200000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(50000, 150000), 'out': random.randint(100000, 300000)}
                for i in range(60, 0, -1)
            ]
        },
        'CLIENTS': {
            'vlan_id': 30,
            'name': 'Staff Devices',
            'icon': 'fa-laptop',
            'color': '#28a745',
            'device_count': 8,
            'active_count': 5,
            'bytes_in': 2147483648,
            'bytes_out': 536870912,
            'bandwidth_mbps': 45.2,
            'top_devices': [
                {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook Sarah', 'bytes': 500000000},
                {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone Mike', 'bytes': 300000000},
                {'mac': '00:21:6A:44:55:66', 'hostname': 'Lenovo ThinkPad', 'bytes': 250000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(200000, 600000), 'out': random.randint(50000, 150000)}
                for i in range(60, 0, -1)
            ]
        },
        'POS': {
            'vlan_id': 20,
            'name': 'Point of Sale',
            'icon': 'fa-credit-card',
            'color': '#ffc107',
            'device_count': 2,
            'active_count': 2,
            'bytes_in': 104857600,
            'bytes_out': 52428800,
            'bandwidth_mbps': 2.1,
            'top_devices': [
                {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square POS-1', 'bytes': 80000000},
                {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico Terminal', 'bytes': 30000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(5000, 20000), 'out': random.randint(2000, 10000)}
                for i in range(60, 0, -1)
            ]
        },
        'CAMERAS': {
            'vlan_id': 50,
            'name': 'Security Cameras',
            'icon': 'fa-video',
            'color': '#6f42c1',
            'device_count': 6,
            'active_count': 6,
            'bytes_in': 10737418240,
            'bytes_out': 53687091,
            'bandwidth_mbps': 85.3,
            'top_devices': [
                {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision Front', 'bytes': 3000000000},
                {'mac': '28:57:BE:44:55:66', 'hostname': 'Hikvision Back', 'bytes': 2500000000},
                {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua Parking', 'bytes': 2000000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(800000, 1200000), 'out': random.randint(5000, 15000)}
                for i in range(60, 0, -1)
            ]
        },
        'IIOT': {
            'vlan_id': 60,
            'name': 'IoT / Smart Devices',
            'icon': 'fa-thermometer-half',
            'color': '#fd7e14',
            'device_count': 12,
            'active_count': 10,
            'bytes_in': 52428800,
            'bytes_out': 26214400,
            'bandwidth_mbps': 0.8,
            'top_devices': [
                {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest Thermostat', 'bytes': 15000000},
                {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips Hue Bridge', 'bytes': 10000000},
                {'mac': 'D4:F5:47:11:22:33', 'hostname': 'Google Nest Hub', 'bytes': 8000000},
            ],
            'traffic_history': [
                {'ts': base_time - i*10, 'in': random.randint(2000, 8000), 'out': random.randint(1000, 4000)}
                for i in range(60, 0, -1)
            ]
        },
    }
    return segments


@sdn_bp.route('/segments')
@login_required
def segments():
    """Network Segments Dashboard - Per-category traffic visualization."""
    segment_data = {}

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            segment_data = autopilot.get_segment_summary()
        except Exception as e:
            flash(f'Error loading segments: {e}', 'warning')
            segment_data = get_demo_segment_data()
    else:
        segment_data = get_demo_segment_data()

    return render_template(
        'sdn/segments.html',
        segments=segment_data,
        autopilot_available=SDN_AUTOPILOT_AVAILABLE
    )


@sdn_bp.route('/api/segments')
@login_required
def api_segments():
    """Get all segment statistics (JSON) - returns demo data."""
    # Segment APIs return demo data since segment feature is not fully implemented
    return jsonify({
        'success': True,
        'segments': get_demo_segment_data()
    })


@sdn_bp.route('/api/segments/<segment_name>')
@login_required
def api_segment_detail(segment_name):
    """Get detailed statistics for a specific segment."""
    segment_name = segment_name.upper()
    demo = get_demo_segment_data()
    if segment_name in demo:
        return jsonify({
            'success': True,
            'segment': demo[segment_name]
        })
    return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/api/segments/<segment_name>/devices')
@login_required
def api_segment_devices(segment_name):
    """Get devices in a specific segment."""
    segment_name = segment_name.upper()
    demo = get_demo_segment_data()
    if segment_name in demo:
        return jsonify({
            'success': True,
            'segment': segment_name,
            'count': len(demo[segment_name].get('top_devices', [])),
            'devices': demo[segment_name].get('top_devices', [])
        })
    return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


@sdn_bp.route('/api/segments/<segment_name>/traffic')
@login_required
def api_segment_traffic(segment_name):
    """Get traffic history for a segment (for live chart updates)."""
    segment_name = segment_name.upper()
    demo = get_demo_segment_data()
    if segment_name in demo:
        return jsonify({
            'success': True,
            'segment': segment_name,
            'traffic_history': demo[segment_name].get('traffic_history', [])
        })
    return jsonify({'success': False, 'error': f'Unknown segment: {segment_name}'}), 404


# ============================================================
# DEVICE TRUST FRAMEWORK - CIA Triad Authentication
# ============================================================

# Import Trust Framework
TRUST_FRAMEWORK_AVAILABLE = False
try:
    from device_trust_framework import (
        get_trust_framework,
        TrustLevel,
        DeviceTrustFramework,
    )
    TRUST_FRAMEWORK_AVAILABLE = True
except ImportError:
    pass


def get_demo_trust_data():
    """Return demo trust data for development."""
    return {
        'total_devices': 15,
        'trust_framework_enabled': True,
        # Dashboard expects lowercase keys for trust_distribution
        'trust_distribution': {
            'untrusted': 2,
            'minimal': 5,
            'standard': 4,
            'high': 3,
            'enterprise': 1,
        },
        # Keep uppercase version for backwards compatibility
        'by_trust_level': {
            'UNTRUSTED': 2,
            'MINIMAL': 5,
            'STANDARD': 4,
            'HIGH': 3,
            'ENTERPRISE': 1,
        },
        'verified_count': 8,
        'verified_percent': 53.3,
        'certificate_count': 4,
        'certificate_percent': 26.7,
        'attestation_count': 1,
        'attestation_percent': 6.7,
    }


def get_demo_trust_devices():
    """Return demo devices with trust information."""
    import random
    devices = [
        {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook-Sarah', 'vendor': 'Apple', 'segment': 'CLIENTS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone-Mike', 'vendor': 'Apple', 'segment': 'CLIENTS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '00:21:6A:44:55:66', 'hostname': 'ThinkPad-T14', 'vendor': 'Lenovo', 'segment': 'CLIENTS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square-POS-1', 'vendor': 'Square', 'segment': 'POS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico-Term', 'vendor': 'Ingenico', 'segment': 'POS', 'trust': 3, 'verified': True, 'cert': True},
        {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision-Front', 'vendor': 'Hikvision', 'segment': 'CAMERAS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua-Parking', 'vendor': 'Dahua', 'segment': 'CAMERAS', 'trust': 2, 'verified': True, 'cert': False},
        {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology-NVR', 'vendor': 'Synology', 'segment': 'SECMON', 'trust': 4, 'verified': True, 'cert': True},
        {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest-Thermostat', 'vendor': 'Google Nest', 'segment': 'IIOT', 'trust': 1, 'verified': False, 'cert': False},
        {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips-Hue', 'vendor': 'Philips', 'segment': 'IIOT', 'trust': 1, 'verified': False, 'cert': False},
        {'mac': 'AA:BB:CC:DD:EE:FF', 'hostname': 'Unknown-Device', 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'verified': False, 'cert': False},
        {'mac': '11:22:33:44:55:66', 'hostname': None, 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'verified': False, 'cert': False},
    ]

    trust_names = {0: 'UNTRUSTED', 1: 'MINIMAL', 2: 'STANDARD', 3: 'HIGH', 4: 'ENTERPRISE'}

    return [
        {
            'mac_address': d['mac'],
            'hostname': d['hostname'],
            'ip_address': f"10.200.0.{100 + i}",
            'vendor': d['vendor'],
            'segment_name': d['segment'],
            'trust_level': d['trust'],
            'trust_level_name': trust_names.get(d['trust'], 'UNKNOWN'),
            'trust_verified': d['verified'],
            'certificate_issued': d['cert'],
        }
        for i, d in enumerate(devices)
    ]


@sdn_bp.route('/trust')
@login_required
def trust_dashboard():
    """Device Trust Framework dashboard - CIA Triad authentication."""
    trust_summary = {}
    devices = []
    segment_colors = {
        'SECMON': '#17a2b8',
        'CLIENTS': '#28a745',
        'POS': '#ffc107',
        'CAMERAS': '#6f42c1',
        'IIOT': '#fd7e14',
        'GUEST': '#20c997',
        'QUARANTINE': '#dc3545',
    }

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            trust_summary = autopilot.get_trust_summary()
            devices = autopilot.get_all_devices()
        except Exception as e:
            flash(f'Error loading trust data: {e}', 'warning')
            trust_summary = get_demo_trust_data()
            devices = get_demo_trust_devices()
    else:
        trust_summary = get_demo_trust_data()
        devices = get_demo_trust_devices()

    return render_template(
        'sdn/trust.html',
        trust_summary=trust_summary,
        devices=devices,
        segment_colors=segment_colors,
        trust_available=TRUST_FRAMEWORK_AVAILABLE
    )


@sdn_bp.route('/api/trust')
@login_required
def api_trust_summary():
    """Get trust framework summary (JSON)."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            return jsonify({
                'success': True,
                'trust_summary': autopilot.get_trust_summary(),
                'trust_framework_available': TRUST_FRAMEWORK_AVAILABLE
            })
        except Exception as e:
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'trust_summary': get_demo_trust_data(),
            'trust_framework_available': False
        })


@sdn_bp.route('/api/trust/enroll', methods=['POST'])
@login_required
@operator_required
def api_enroll_device():
    """Enroll a device for certificate-based authentication."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if TRUST_FRAMEWORK_AVAILABLE:
        try:
            import secrets
            trust_framework = get_trust_framework()

            # Generate device key (in production, device would provide this)
            device_pubkey = secrets.token_bytes(32)

            # Issue certificate
            cert = trust_framework.issue_certificate(
                mac_address=mac_address,
                public_key=device_pubkey,
                trust_level=TrustLevel.STANDARD,
                validity_days=30
            )

            if cert:
                return jsonify({
                    'success': True,
                    'message': f'Device {mask_mac(mac_address)} enrolled successfully',
                    'cert_id': cert.cert_id,
                    'expires': cert.expires_at
                })
            else:
                return jsonify({'success': False, 'error': 'Certificate issuance failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mask_mac(mac_address)} enrolled (demo mode)'
        })


@sdn_bp.route('/api/trust/revoke', methods=['POST'])
@login_required
@operator_required
def api_revoke_device():
    """Revoke a device certificate."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if TRUST_FRAMEWORK_AVAILABLE:
        try:
            trust_framework = get_trust_framework()
            success = trust_framework.revoke_certificate(mac_address, reason="admin_revoke")

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Certificate revoked for {mask_mac(mac_address)}'
                })
            else:
                return jsonify({'success': False, 'error': 'Revocation failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Certificate revoked for {mac_address} (demo mode)'
        })


@sdn_bp.route('/api/trust/quarantine', methods=['POST'])
@login_required
@operator_required
def api_quarantine_device():
    """Move a device to quarantine."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            success = autopilot.set_manual_policy(mac_address, 'quarantine')

            if success:
                # Also revoke certificate if trust framework available
                if TRUST_FRAMEWORK_AVAILABLE:
                    trust_framework = get_trust_framework()
                    trust_framework.revoke_certificate(mac_address, reason="quarantine")

                return jsonify({
                    'success': True,
                    'message': f'Device {mask_mac(mac_address)} moved to quarantine'
                })
            else:
                return jsonify({'success': False, 'error': 'Quarantine failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mask_mac(mac_address)} quarantined (demo mode)'
        })


# ============================================================
# UNIFIED SDN MANAGEMENT DASHBOARD
# ============================================================

def get_demo_wifi_data():
    """Return demo WiFi intelligence data."""
    from datetime import datetime, timedelta
    import random

    now = datetime.now()
    events = [
        {'timestamp': (now - timedelta(hours=2)).isoformat(), 'type': 'switch', 'message': 'Channel switched 36 → 149 (congestion)'},
        {'timestamp': (now - timedelta(hours=4)).isoformat(), 'type': 'radar', 'message': 'Radar detected on CH 52 (weather)'},
        {'timestamp': (now - timedelta(hours=8)).isoformat(), 'type': 'cac', 'message': 'CAC completed on CH 149'},
        {'timestamp': (now - timedelta(hours=12)).isoformat(), 'type': 'switch', 'message': 'Channel switched 44 → 36 (DFS)'},
        {'timestamp': (now - timedelta(hours=18)).isoformat(), 'type': 'radar', 'message': 'Radar detected on CH 100'},
    ]

    return {
        'channel': 149,
        'width': 80,
        'power': 23,
        'band': '5GHz',
        'dfs_status': 'clear',
        'channel_score': random.randint(75, 95),
        'radar_events_24h': 2,
        'channel_switches_24h': 5,
        'events': events,
        'ssid': 'HookProbe-Fortress',
        'clients_24': random.randint(3, 8),
        'clients_5': random.randint(10, 20),
    }


def get_demo_sdn_devices():
    """Return demo devices for SDN Management dashboard."""
    import random

    segments = ['STAFF', 'GUEST', 'POS', 'CAMERAS', 'IIOT', 'QUARANTINE', 'SECMON']
    segment_vlans = {'SECMON': 10, 'POS': 20, 'STAFF': 30, 'GUEST': 40, 'CAMERAS': 50, 'IIOT': 60, 'QUARANTINE': 99}

    devices = [
        {'mac': '3C:06:30:DE:AD:BE', 'hostname': 'MacBook-Sarah', 'vendor': 'Apple', 'segment': 'STAFF', 'trust': 3, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': 'A4:5E:60:11:22:33', 'hostname': 'iPhone-Mike', 'vendor': 'Apple', 'segment': 'STAFF', 'trust': 2, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': '00:21:6A:44:55:66', 'hostname': 'ThinkPad-T14', 'vendor': 'Lenovo', 'segment': 'STAFF', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '58:E6:BA:11:22:33', 'hostname': 'Square-POS-1', 'vendor': 'Square', 'segment': 'POS', 'trust': 3, 'conn': 'lan', 'band': None},
        {'mac': '00:0B:CD:AA:BB:CC', 'hostname': 'Ingenico-Term', 'vendor': 'Ingenico', 'segment': 'POS', 'trust': 3, 'conn': 'lan', 'band': None},
        {'mac': '28:57:BE:11:22:33', 'hostname': 'Hikvision-Front', 'vendor': 'Hikvision', 'segment': 'CAMERAS', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '3C:EF:8C:77:88:99', 'hostname': 'Dahua-Parking', 'vendor': 'Dahua', 'segment': 'CAMERAS', 'trust': 2, 'conn': 'lan', 'band': None},
        {'mac': '00:0D:7C:12:34:56', 'hostname': 'Synology-NVR', 'vendor': 'Synology', 'segment': 'SECMON', 'trust': 4, 'conn': 'lan', 'band': None},
        {'mac': '18:B4:30:AA:BB:CC', 'hostname': 'Nest-Thermostat', 'vendor': 'Google Nest', 'segment': 'IIOT', 'trust': 1, 'conn': 'wifi', 'band': '2.4GHz'},
        {'mac': '00:17:88:DD:EE:FF', 'hostname': 'Philips-Hue', 'vendor': 'Philips', 'segment': 'IIOT', 'trust': 1, 'conn': 'lan', 'band': None},
        {'mac': 'CC:50:E3:12:34:56', 'hostname': 'Samsung-Tab', 'vendor': 'Samsung', 'segment': 'GUEST', 'trust': 1, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': '48:E1:E9:AA:BB:CC', 'hostname': 'Pixel-Guest', 'vendor': 'Google', 'segment': 'GUEST', 'trust': 1, 'conn': 'wifi', 'band': '5GHz'},
        {'mac': 'AA:BB:CC:DD:EE:FF', 'hostname': 'Unknown-Device', 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'conn': 'wifi', 'band': '2.4GHz'},
        {'mac': '11:22:33:44:55:66', 'hostname': None, 'vendor': 'Unknown', 'segment': 'QUARANTINE', 'trust': 0, 'conn': 'lan', 'band': None},
    ]

    return [
        {
            'mac': d['mac'],
            'hostname': d['hostname'] or 'Unknown',
            'ip_address': f"10.200.0.{100 + i}",
            'vendor': d['vendor'],
            'segment': d['segment'],
            'vlan_id': segment_vlans.get(d['segment'], 40),
            'trust_level': d['trust'],
            'connection_type': d['conn'],
            'band': d['band'],
            'online': random.choice([True, True, True, False]),
        }
        for i, d in enumerate(devices)
    ]


@sdn_bp.route('/management')
@login_required
def management_dashboard():
    """Unified SDN Management Dashboard - Consolidates clients/networks/WiFi."""
    return render_template('sdn/management.html')


@sdn_bp.route('/api/sdn/devices')
@login_required
def api_sdn_devices():
    """Get all network devices for SDN Management dashboard."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            devices = autopilot.get_all_devices()

            # Transform to SDN format
            # Map policy to segment and trust level
            policy_to_segment = {
                'full_access': ('TRUSTED', 4),
                'lan_only': ('LAN', 3),
                'internet_only': ('GUEST', 2),
                'quarantine': ('QUARANTINE', 0),
                'isolated': ('QUARANTINE', 0),
            }

            sdn_devices = []
            for device in devices:
                policy = device.get('policy', 'quarantine')
                segment, trust = policy_to_segment.get(policy, ('GUEST', 1))
                mac = device.get('mac', '')
                vendor = device.get('vendor', 'Unknown')
                # Prefer device_type (Fingerbank name) over category
                category = device.get('device_type') or device.get('category', 'unknown')
                raw_hostname = device.get('hostname') or device.get('friendly_name', '')

                sdn_devices.append({
                    'mac': mac,
                    'hostname': get_friendly_name(mac, raw_hostname, vendor, category),
                    'ip_address': device.get('ip', '--'),
                    'vendor': vendor,
                    'segment': segment,
                    'vlan_id': device.get('vlan_id', 40),
                    'trust_level': trust,
                    'connection_type': device.get('connection_type', 'unknown'),
                    'band': device.get('wifi_band'),
                    'online': device.get('status') == 'online',
                    # WiFi signal data
                    'wifi_rssi': device.get('wifi_rssi'),
                    'wifi_quality': device.get('wifi_quality'),
                    'wifi_proximity': device.get('wifi_proximity'),
                })

            return jsonify({'success': True, 'devices': sdn_devices})

        except Exception as e:
            return jsonify({'success': False, 'error': safe_error_message(e), 'devices': []}), 500
    else:
        # Demo mode
        return jsonify({'success': True, 'devices': get_demo_sdn_devices()})


@sdn_bp.route('/api/sdn/segments')
@login_required
def api_sdn_segments():
    """Get segment distribution statistics."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            devices = autopilot.get_all_devices()

            # Count devices per segment
            segments = {}
            for device in devices:
                seg = device.get('segment_name', 'GUEST')
                segments[seg] = segments.get(seg, 0) + 1

            return jsonify({'success': True, 'segments': segments})

        except Exception as e:
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        # Demo data
        demo_devices = get_demo_sdn_devices()
        segments = {}
        for d in demo_devices:
            seg = d['segment']
            segments[seg] = segments.get(seg, 0) + 1

        return jsonify({'success': True, 'segments': segments})


@sdn_bp.route('/api/sdn/wifi')
@login_required
def api_sdn_wifi_status():
    """Get WiFi intelligence data including DFS/channel info."""
    import subprocess
    import os

    # Try to get real data from hostapd/iw
    wifi_data = None

    try:
        # Check if DFS Intelligence is available
        dfs_available = False
        try:
            from shared.wireless import ChannelScorer, DFSDatabase
            dfs_available = True
        except ImportError:
            pass

        # Try to get real WiFi status
        result = subprocess.run(
            ['iw', 'dev'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout:
            # Parse iw output for channel info
            wifi_data = parse_iw_output(result.stdout)

        # Try to get DFS intelligence data
        if dfs_available and wifi_data:
            try:
                scorer = ChannelScorer()
                channel = wifi_data.get('channel', 149)
                score = scorer.score_channel(channel)
                wifi_data['channel_score'] = int(score.total_score * 100)
            except Exception:
                pass

    except Exception as e:
        # Fall back to demo data
        pass

    if not wifi_data:
        wifi_data = get_demo_wifi_data()

    return jsonify(wifi_data)


def parse_iw_output(output):
    """Parse iw dev output to extract WiFi info."""
    import re

    data = {
        'channel': None,
        'width': None,
        'power': None,
        'band': '5GHz',
        'dfs_status': 'clear',
        'channel_score': 85,
        'radar_events_24h': 0,
        'channel_switches_24h': 0,
        'events': [],
    }

    # Look for channel info
    channel_match = re.search(r'channel (\d+)', output)
    if channel_match:
        data['channel'] = int(channel_match.group(1))
        # Determine band from channel
        if data['channel'] <= 14:
            data['band'] = '2.4GHz'

    # Look for width
    width_match = re.search(r'width: (\d+)', output)
    if width_match:
        data['width'] = int(width_match.group(1))

    # Look for txpower
    power_match = re.search(r'txpower (\d+\.\d+)', output)
    if power_match:
        data['power'] = int(float(power_match.group(1)))

    return data


@sdn_bp.route('/api/sdn/move', methods=['POST'])
@login_required
@operator_required
def api_move_device():
    """Move a device to a different segment/policy."""
    data = request.get_json() or {}
    mac_address = data.get('mac_address')
    segment = data.get('segment', '').upper()

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    if not segment:
        return jsonify({'success': False, 'error': 'Segment required'}), 400

    # Map segment names to policy names
    segment_to_policy = {
        'SECMON': 'full_access',
        'POS': 'lan_only',
        'STAFF': 'full_access',
        'CLIENTS': 'full_access',
        'GUEST': 'internet_only',
        'CAMERAS': 'lan_only',
        'IIOT': 'lan_only',
        'QUARANTINE': 'quarantine',
    }

    policy = segment_to_policy.get(segment)
    if not policy:
        return jsonify({'success': False, 'error': f'Invalid segment: {segment}'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            success = autopilot.set_manual_policy(mac_address, policy)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device {mask_mac(mac_address)} moved to {segment}'
                })
            else:
                return jsonify({'success': False, 'error': 'Move failed'}), 500

        except Exception as e:
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac_address} moved to {segment} (demo mode)'
        })


# ============================================================
# DEVICE DATA CRUD API - Persistent device management
# ============================================================

@sdn_bp.route('/api/device/register', methods=['POST'])
@login_required
@operator_required
def api_device_register():
    """
    Create/register a device with policy assignment.

    POST data:
        mac_address: Device MAC address (required)
        name: Friendly name
        policy: Network policy (full_access, lan_only, internet_only, isolated, default)
        notes: Optional notes
        is_trusted: Whether device is trusted
    """
    data = request.get_json() or {}
    mac_address = data.get('mac_address', '').upper().strip()

    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address required'}), 400

    # Validate MAC format
    import re
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac_address.replace('-', ':')):
        return jsonify({'success': False, 'error': 'Invalid MAC address format'}), 400

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            entry = manager.create(
                mac_address=mac_address,
                name=data.get('name', ''),
                policy=data.get('policy', 'default'),
                notes=data.get('notes', ''),
                is_trusted=data.get('is_trusted', False),
            )

            return jsonify({
                'success': True,
                'device': {
                    'mac_address': entry.mac_address,
                    'name': entry.name,
                    'policy': entry.policy,
                    'category': entry.category,
                    'manufacturer': entry.manufacturer,
                    'is_trusted': entry.is_trusted,
                    'created_at': entry.created_at,
                }
            })
        except Exception as e:
            logger.error(f"Failed to register device: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'device': {
                'mac_address': mac_address,
                'name': data.get('name', ''),
                'policy': data.get('policy', 'default'),
            },
            'note': 'Demo mode - device not persisted'
        })


@sdn_bp.route('/api/device/<mac_address>')
@login_required
def api_device_get(mac_address):
    """Get device details by MAC address."""
    mac = mac_address.upper().replace('-', ':')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            device = manager.read(mac)

            if device:
                # Merge real-time status from status_cache (ip neigh)
                status_cache = _load_device_status_cache()
                live_status = status_cache.get(mac, {})
                if live_status:
                    device['status'] = live_status.get('status', device.get('status', 'offline'))
                    device['neighbor_state'] = live_status.get('neighbor_state', '')
                return jsonify({'success': True, 'device': device})
            else:
                return jsonify({'success': False, 'error': 'Device not found'}), 404
        except Exception as e:
            logger.error(f"Failed to get device: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        # Return demo data
        return jsonify({
            'success': True,
            'device': {
                'mac_address': mac,
                'ip_address': '',
                'name': '',
                'policy': 'default',
                'category': 'unknown',
                'manufacturer': 'Unknown',
            }
        })


@sdn_bp.route('/api/device/<mac_address>', methods=['PUT', 'PATCH'])
@login_required
@operator_required
def api_device_update(mac_address):
    """
    Update a device entry.

    PUT/PATCH data:
        name: Friendly name
        policy: Network policy
        notes: Notes
        is_trusted: Trusted flag
        is_blocked: Blocked flag
        category: Device category
    """
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()

            # Filter allowed fields
            allowed = {'name', 'policy', 'notes', 'is_trusted', 'is_blocked', 'category'}
            updates = {k: v for k, v in data.items() if k in allowed}

            entry = manager.update(mac, **updates)

            if entry:
                return jsonify({
                    'success': True,
                    'device': {
                        'mac_address': entry.mac_address,
                        'name': entry.name,
                        'policy': entry.policy,
                        'category': entry.category,
                        'is_blocked': entry.is_blocked,
                        'is_trusted': entry.is_trusted,
                        'updated_at': entry.updated_at,
                    }
                })
            else:
                return jsonify({'success': False, 'error': 'Update failed'}), 500
        except Exception as e:
            logger.error(f"Failed to update device: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'device': {'mac_address': mac, **data},
            'note': 'Demo mode - changes not persisted'
        })


@sdn_bp.route('/api/device/<mac_address>', methods=['DELETE'])
@login_required
@operator_required
def api_device_delete(mac_address):
    """
    Delete a device from ALL data stores (SQLite, PostgreSQL, JSON files).

    This properly removes devices even if they're offline and haven't
    connected in days. The device will be re-created automatically
    when it reconnects via DHCP.
    """
    mac = mac_address.upper().replace('-', ':')
    mac_masked = mask_mac(mac)
    deleted_from = []

    # 1. Delete from device_registry.json (DeviceDataManager)
    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            if manager.delete(mac):
                deleted_from.append('device_registry')
        except Exception as e:
            logger.debug(f"device_registry delete: {e}")

    # 2. Delete from SQLite device_identity table (autopilot.db)
    # This is the main data source for the UI
    try:
        import sqlite3
        db_path = '/var/lib/hookprobe/autopilot.db'
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("DELETE FROM device_identity WHERE mac = ?", (mac,))
            if cur.rowcount > 0:
                deleted_from.append('device_identity')
            conn.commit()
            conn.close()
    except Exception as e:
        logger.debug(f"SQLite device_identity delete: {e}")

    # 3. Delete from PostgreSQL devices table
    try:
        import psycopg2
        # CWE-532 SECURITY FIX: Get credentials from environment, no hardcoded defaults with secrets
        db_host = os.environ.get('DATABASE_HOST', '172.20.200.10')
        db_port = os.environ.get('DATABASE_PORT', '5432')
        db_name = os.environ.get('DATABASE_NAME', 'fortress')
        db_user = os.environ.get('DATABASE_USER', 'fortress')
        db_pass = os.environ.get('DATABASE_PASSWORD', '')  # No default password
        if db_pass:
            pg_conn = psycopg2.connect(
                host=db_host,
                port=db_port,
                dbname=db_name,
                user=db_user,
                password=db_pass
            )
            pg_cur = pg_conn.cursor()
            pg_cur.execute("DELETE FROM devices WHERE mac_address = %s", (mac,))
            if pg_cur.rowcount > 0:
                deleted_from.append('devices_pg')
            pg_conn.commit()
            pg_cur.close()
            pg_conn.close()
    except Exception as e:
        # CWE-532 SECURITY FIX: Log only exception type, not full message which may contain credentials
        logger.debug(f"PostgreSQL devices delete: {type(e).__name__}")

    # 4. Delete from devices.json
    try:
        devices_file = Path('/opt/hookprobe/fortress/data/devices.json')
        if devices_file.exists():
            import json as json_module
            with open(devices_file, 'r') as f:
                data = json_module.load(f)
            # devices.json can have two formats: dict by MAC or list with 'devices' key
            if isinstance(data, dict):
                if 'devices' in data and isinstance(data['devices'], list):
                    # Format: {"timestamp": "...", "devices": [...], "count": N}
                    original_len = len(data['devices'])
                    data['devices'] = [d for d in data['devices']
                                       if d.get('mac', '').upper() != mac]
                    if len(data['devices']) < original_len:
                        data['count'] = len(data['devices'])
                        deleted_from.append('devices_json')
                elif mac in data:
                    # Format: {"MAC": {...}, "MAC2": {...}}
                    del data[mac]
                    deleted_from.append('devices_json')
            if 'devices_json' in deleted_from:
                with open(devices_file, 'w') as f:
                    json_module.dump(data, f, indent=2)
    except Exception as e:
        logger.debug(f"devices.json delete: {e}")

    # 5. Also clean up from blocked_macs.json if present
    # CWE-312 FIX: Use hash-based lookup (blocked_macs.json stores hashes)
    try:
        if _remove_blocked_mac(mac):
            deleted_from.append('blocked_macs')
    except Exception as e:
        # CWE-532 SECURITY FIX: Log only exception type, not full message
        logger.debug(f"blocked_macs.json cleanup: {type(e).__name__}")

    # 6. Also try autopilot.delete_device() for any other cleanup
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            autopilot.delete_device(mac)
        except Exception:
            pass  # Already handled

    if deleted_from:
        logger.info(f"Deleted device {mac_masked} from: {', '.join(deleted_from)}")
        return jsonify({
            'success': True,
            'message': f'Device {mac_masked} deleted',
            'deleted_from': deleted_from
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Device not found in any data store'
        }), 404


@sdn_bp.route('/api/device/<mac_address>/name', methods=['GET'])
@login_required
def api_device_get_name(mac_address):
    """Get custom name for a device."""
    mac = mac_address.upper().replace('-', ':')

    # Validate MAC format
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    custom_name = get_device_custom_name(mac)
    return jsonify({
        'success': True,
        'mac': mac,
        'custom_name': custom_name
    })


@sdn_bp.route('/api/device/<mac_address>/name', methods=['PUT', 'POST'])
@login_required
@operator_required
def api_device_set_name(mac_address):
    """
    Set custom name for a device.

    Body: {"name": "Living Room Light", "original_hostname": "013_aio-nap"}

    This name will be used as the display label throughout the dashboard.
    The MAC address and hostname remain the primary identifiers.
    """
    mac = mac_address.upper().replace('-', ':')

    # Validate MAC format
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    if not DEVICE_NAMES_AVAILABLE:
        return jsonify({'success': False, 'error': 'Device naming not available'}), 503

    data = request.get_json() or {}
    custom_name = data.get('name', '').strip()

    if not custom_name:
        return jsonify({'success': False, 'error': 'Name is required'}), 400

    if len(custom_name) > 64:
        return jsonify({'success': False, 'error': 'Name too long (max 64 chars)'}), 400

    # Sanitize name - only allow safe characters
    if not re.match(r'^[\w\s\-\'\.]+$', custom_name):
        return jsonify({
            'success': False,
            'error': 'Name contains invalid characters (only letters, numbers, spaces, hyphens, apostrophes, periods allowed)'
        }), 400

    try:
        with get_bubbles_db() as conn:
            original_hostname = data.get('original_hostname', '')
            conn.execute('''
                INSERT OR REPLACE INTO device_names
                (mac, custom_name, original_hostname, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                mac,
                custom_name,
                original_hostname,
                current_user.username if hasattr(current_user, 'username') else 'system',
                datetime.now().isoformat()
            ))
            conn.commit()

        # Also update the SDN autopilot database for immediate display
        if SDN_AUTOPILOT_AVAILABLE:
            try:
                autopilot = get_sdn_autopilot()
                if autopilot:
                    autopilot.update_friendly_name(mac, custom_name)
            except Exception as e:
                logger.debug(f"Failed to update autopilot friendly_name: {e}")

        logger.info(f"Device {mask_mac(mac)} renamed to '{custom_name}'")
        return jsonify({
            'success': True,
            'message': f'Device renamed to {custom_name}',
            'mac': mac,
            'custom_name': custom_name
        })
    except Exception as e:
        logger.error(f"Failed to set device name: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@sdn_bp.route('/api/device/<mac_address>/name', methods=['DELETE'])
@login_required
@operator_required
def api_device_delete_name(mac_address):
    """Remove custom name for a device (revert to hostname)."""
    mac = mac_address.upper().replace('-', ':')

    # Validate MAC format
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    if not DEVICE_NAMES_AVAILABLE:
        return jsonify({'success': False, 'error': 'Device naming not available'}), 503

    try:
        with get_bubbles_db() as conn:
            conn.execute('DELETE FROM device_names WHERE mac = ?', (mac,))
            conn.commit()

        logger.info(f"Device {mask_mac(mac)} name reset to default")
        return jsonify({'success': True, 'message': 'Device name reset to default'})
    except Exception as e:
        logger.error(f"Failed to delete device name: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@sdn_bp.route('/api/device/<mac_address>/policy', methods=['POST'])
@login_required
@operator_required
def api_device_set_policy(mac_address):
    """
    Set network policy for a device.

    POST data:
        policy: Network policy

    Accepted policies (with aliases for compatibility):
        - quarantine / isolated: No network access (DHCP/DNS only)
        - internet_only: Internet access, no LAN
        - lan_only: LAN access, no internet
        - normal / full_access: Full network access
        - default: Use OUI-based default
    """
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}
    policy = data.get('policy', 'default')

    # Policy name normalization (device_policies uses quarantine/smart_home,
    # device_data_manager uses isolated/smart_home)
    policy_aliases = {
        'quarantine': 'isolated',    # Both mean "block all"
        'normal': 'smart_home',      # Legacy alias
    }
    policy = policy_aliases.get(policy, policy)

    valid_policies = ['full_access', 'lan_only', 'internet_only', 'isolated', 'quarantine', 'smart_home', 'default']
    if policy not in valid_policies:
        return jsonify({
            'success': False,
            'error': f'Invalid policy. Must be one of: quarantine, internet_only, lan_only, smart_home, full_access, default'
        }), 400

    # Try SDN Autopilot first (primary method)
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()

            # Auto-create device if it doesn't exist (but not if blocked)
            device = autopilot.get_device(mac)
            if not device:
                # Check if MAC is blocked - don't auto-create blocked devices
                if _is_mac_blocked(mac):
                    return jsonify({
                        'success': False,
                        'error': 'Device is blocked and cannot be modified'
                    }), 403

                # Try to get additional info from device status cache
                status_cache = _load_device_status_cache()
                device_info = status_cache.get(mac, {})

                # Create device via Fingerbank pipeline with DHCP fingerprint
                device = autopilot.ensure_device_exists(
                    mac=mac,
                    ip=device_info.get('ip', ''),
                    hostname=device_info.get('hostname', ''),
                    dhcp_fingerprint=device_info.get('dhcp_fingerprint', ''),
                    vendor_class=device_info.get('vendor_class', '')
                )
                # CWE-532: Pre-compute masked MAC to break taint chain
                mac_safe = mask_mac(mac)
                logger.info(f"Auto-created device {mac_safe} via Fingerbank pipeline")

            success = autopilot.set_policy(mac, policy)
            # CWE-532: Pre-compute masked MAC for response message
            mac_display = mask_mac(mac)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Policy set to {policy} for {mac_display}'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to set policy'}), 500
        except Exception as e:
            logger.error(f"Failed to set device policy via autopilot: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500

    # Fallback to DeviceDataManager if available
    elif DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            success = manager.set_policy(mac, policy)

            if success:
                # Apply OpenFlow rules for immediate enforcement
                manager._apply_policy_rules(mac, policy)

                return jsonify({
                    'success': True,
                    'message': f'Policy set to {policy} for {mask_mac(mac)}'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to set policy'}), 500
        except Exception as e:
            logger.error(f"Failed to set device policy: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': False,
            'error': 'Policy management not available - SDN Autopilot database not initialized'
        }), 503


@sdn_bp.route('/api/device/<mac_address>/block', methods=['POST'])
@login_required
@operator_required
def api_device_block(mac_address):
    """Block a device."""
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}
    reason = data.get('reason', '')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            success = manager.block(mac, reason)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device {mask_mac(mac)} blocked'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to block device'}), 500
        except Exception as e:
            logger.error(f"Failed to block device: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac} blocked (demo mode)'
        })


@sdn_bp.route('/api/device/<mac_address>/unblock', methods=['POST'])
@login_required
@operator_required
def api_device_unblock(mac_address):
    """Unblock a device."""
    mac = mac_address.upper().replace('-', ':')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            success = manager.unblock(mac)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Device {mask_mac(mac)} unblocked'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to unblock device'}), 500
        except Exception as e:
            logger.error(f"Failed to unblock device: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': f'Device {mac} unblocked (demo mode)'
        })


@sdn_bp.route('/api/device/list')
@login_required
def api_device_list():
    """
    List all devices with optional filters.

    Query params:
        policy: Filter by policy
        category: Filter by category
        online: Filter online/offline (true/false)
    """
    policy = request.args.get('policy')
    category = request.args.get('category')
    online = request.args.get('online')

    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()

            if policy:
                devices = manager.list_by_policy(policy)
            elif category:
                devices = manager.list_by_category(category)
            else:
                devices = manager.list_all()

            # Filter by online status
            if online is not None:
                online_bool = online.lower() in ('true', '1', 'yes')
                devices = [
                    d for d in devices
                    if (d.get('state') in ('REACHABLE', 'DELAY')) == online_bool
                ]

            return jsonify({
                'success': True,
                'devices': devices,
                'count': len(devices),
            })
        except Exception as e:
            logger.error(f"Failed to list devices: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        # Return demo data
        return jsonify({
            'success': True,
            'devices': [],
            'count': 0,
            'note': 'Device data manager not available'
        })


@sdn_bp.route('/api/device/stats')
@login_required
def api_device_stats():
    """Get device statistics."""
    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            stats = manager.get_stats()
            return jsonify({'success': True, 'stats': stats})
        except Exception as e:
            logger.error(f"Failed to get device stats: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'stats': {
                'total': 0,
                'online': 0,
                'offline': 0,
                'blocked': 0,
                'registered': 0,
                'by_policy': {},
                'by_category': {},
            }
        })


@sdn_bp.route('/api/device/sync-policies', methods=['POST'])
@login_required
@operator_required
def api_device_sync_policies():
    """Sync all device policies to OpenFlow rules."""
    if DEVICE_DATA_MANAGER_AVAILABLE:
        try:
            manager = get_device_data_manager()
            manager.sync_policies()
            return jsonify({
                'success': True,
                'message': 'All policies synced to network'
            })
        except Exception as e:
            logger.error(f"Failed to sync policies: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'message': 'Policies synced (demo mode)'
        })


@sdn_bp.route('/api/policies/available')
@login_required
def api_policies_available():
    """Get available network policies with descriptions."""
    policies = [
        {
            'id': 'full_access',
            'name': 'Full Access',
            'description': 'Full internet and LAN access (staff, trusted devices)',
            'icon': 'fas fa-globe',
            'color': 'success',
        },
        {
            'id': 'lan_only',
            'name': 'LAN Only',
            'description': 'LAN access only, no internet (cameras, printers, IoT)',
            'icon': 'fas fa-network-wired',
            'color': 'info',
        },
        {
            'id': 'internet_only',
            'name': 'Internet Only',
            'description': 'Internet only, no LAN access (guests, POS, voice assistants)',
            'icon': 'fas fa-cloud',
            'color': 'primary',
        },
        {
            'id': 'isolated',
            'name': 'Isolated',
            'description': 'Completely isolated, no network access (quarantined)',
            'icon': 'fas fa-ban',
            'color': 'danger',
        },
        {
            'id': 'default',
            'name': 'Default (Auto)',
            'description': 'Auto-classified based on device type',
            'icon': 'fas fa-magic',
            'color': 'secondary',
        },
    ]

    categories = [
        {'id': 'workstation', 'name': 'Workstation', 'icon': 'fas fa-desktop'},
        {'id': 'mobile', 'name': 'Mobile', 'icon': 'fas fa-mobile-alt'},
        {'id': 'iot', 'name': 'IoT', 'icon': 'fas fa-microchip'},
        {'id': 'camera', 'name': 'Camera', 'icon': 'fas fa-video'},
        {'id': 'printer', 'name': 'Printer', 'icon': 'fas fa-print'},
        {'id': 'pos', 'name': 'POS Terminal', 'icon': 'fas fa-cash-register'},
        {'id': 'voice_assistant', 'name': 'Voice Assistant', 'icon': 'fas fa-microphone'},
        {'id': 'network', 'name': 'Network Equipment', 'icon': 'fas fa-network-wired'},
        {'id': 'unknown', 'name': 'Unknown', 'icon': 'fas fa-question'},
    ]

    return jsonify({
        'success': True,
        'policies': policies,
        'categories': categories,
    })


# ============================================================
# DEVICE TAGGING API - Manual device classification
# ============================================================

DEVICE_TAGS_FILE = DATA_DIR / 'device_tags.json'


def load_device_tags():
    """Load manually assigned device tags."""
    if DEVICE_TAGS_FILE.exists():
        try:
            return json.loads(DEVICE_TAGS_FILE.read_text())
        except Exception:
            pass
    return {}


def save_device_tags(tags):
    """Save device tags to file."""
    try:
        DEVICE_TAGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEVICE_TAGS_FILE.write_text(json.dumps(tags, indent=2))
        return True
    except Exception as e:
        # CWE-532 SECURITY FIX: Log only exception type, not full message
        logger.error(f"Failed to save device tags: {type(e).__name__}")
        return False


@sdn_bp.route('/api/device/<mac_address>/tag', methods=['POST'])
@login_required
@operator_required
def api_device_tag(mac_address):
    """
    Manually tag a device with a device type and optional label.

    POST data:
        device_type: Device type (e.g., 'iphone', 'apple_watch', 'homepod', 'smart_tv')
        label: Optional friendly label for the device
    """
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}

    device_type = data.get('device_type')
    label = data.get('label')

    if not device_type:
        return jsonify({'success': False, 'error': 'device_type is required'}), 400

    # Load existing tags
    tags = load_device_tags()

    # Update or create tag
    tags[mac] = {
        'device_type': device_type,
        'label': label,
        'tagged_at': datetime.now().isoformat(),
        'tagged_by': current_user.username if hasattr(current_user, 'username') else 'admin'
    }

    if save_device_tags(tags):
        return jsonify({
            'success': True,
            'message': f'Device {mask_mac(mac)} tagged as {device_type}',
            'tag': tags[mac]
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to save tag'}), 500


@sdn_bp.route('/api/device/<mac_address>/tag', methods=['DELETE'])
@login_required
@operator_required
def api_device_untag(mac_address):
    """Remove manual tag from a device (revert to auto-detection)."""
    mac = mac_address.upper().replace('-', ':')

    tags = load_device_tags()
    if mac in tags:
        del tags[mac]
        if save_device_tags(tags):
            return jsonify({
                'success': True,
                'message': f'Tag removed from {mask_mac(mac)} - device will use auto-detection'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save'}), 500
    else:
        return jsonify({'success': False, 'error': 'Device has no manual tag'}), 404


@sdn_bp.route('/api/device/tags')
@login_required
def api_device_tags_list():
    """List all manually tagged devices."""
    tags = load_device_tags()
    return jsonify({
        'success': True,
        'count': len(tags),
        'tags': tags
    })


@sdn_bp.route('/api/device/types')
@login_required
def api_device_types():
    """Get available device types for manual tagging."""
    device_types = [
        # Apple devices
        {'id': 'iphone', 'name': 'iPhone', 'icon': 'fa-mobile-alt', 'category': 'phone'},
        {'id': 'ipad', 'name': 'iPad', 'icon': 'fa-tablet-alt', 'category': 'tablet'},
        {'id': 'macbook', 'name': 'MacBook', 'icon': 'fa-laptop', 'category': 'laptop'},
        {'id': 'imac', 'name': 'iMac', 'icon': 'fa-desktop', 'category': 'desktop'},
        {'id': 'mac_mini', 'name': 'Mac mini', 'icon': 'fa-server', 'category': 'desktop'},
        {'id': 'apple_watch', 'name': 'Apple Watch', 'icon': 'fa-clock', 'category': 'wearable'},
        {'id': 'homepod', 'name': 'HomePod', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'apple_tv', 'name': 'Apple TV', 'icon': 'fa-tv', 'category': 'streaming'},
        {'id': 'airpods', 'name': 'AirPods', 'icon': 'fa-headphones', 'category': 'audio'},

        # Android devices
        {'id': 'android_phone', 'name': 'Android Phone', 'icon': 'fa-mobile-alt', 'category': 'phone'},
        {'id': 'android_tablet', 'name': 'Android Tablet', 'icon': 'fa-tablet-alt', 'category': 'tablet'},

        # Computers
        {'id': 'windows_pc', 'name': 'Windows PC', 'icon': 'fa-desktop', 'category': 'computer'},
        {'id': 'linux_pc', 'name': 'Linux PC', 'icon': 'fa-linux', 'category': 'computer'},
        {'id': 'laptop', 'name': 'Laptop', 'icon': 'fa-laptop', 'category': 'computer'},

        # Smart speakers
        {'id': 'amazon_echo', 'name': 'Amazon Echo', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'sonos_speaker', 'name': 'Sonos Speaker', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'google_home', 'name': 'Google Home', 'icon': 'fa-volume-up', 'category': 'speaker'},
        {'id': 'nest_hub', 'name': 'Nest Hub', 'icon': 'fa-tv', 'category': 'smart_display'},

        # Streaming devices
        {'id': 'smart_tv', 'name': 'Smart TV', 'icon': 'fa-tv', 'category': 'tv'},
        {'id': 'roku', 'name': 'Roku', 'icon': 'fa-tv', 'category': 'streaming'},
        {'id': 'chromecast', 'name': 'Chromecast', 'icon': 'fa-tv', 'category': 'streaming'},
        {'id': 'fire_tv', 'name': 'Fire TV', 'icon': 'fa-tv', 'category': 'streaming'},

        # IoT
        {'id': 'ip_camera', 'name': 'IP Camera', 'icon': 'fa-video', 'category': 'camera'},
        {'id': 'ring_camera', 'name': 'Ring Camera', 'icon': 'fa-video', 'category': 'camera'},
        {'id': 'smart_thermostat', 'name': 'Smart Thermostat', 'icon': 'fa-thermometer-half', 'category': 'iot'},
        {'id': 'smart_doorbell', 'name': 'Smart Doorbell', 'icon': 'fa-bell', 'category': 'iot'},
        {'id': 'smart_light', 'name': 'Smart Light', 'icon': 'fa-lightbulb', 'category': 'lighting'},
        {'id': 'raspberry_pi', 'name': 'Raspberry Pi', 'icon': 'fa-microchip', 'category': 'iot'},

        # Network devices
        {'id': 'router', 'name': 'Router', 'icon': 'fa-network-wired', 'category': 'network'},
        {'id': 'network_switch', 'name': 'Network Switch', 'icon': 'fa-network-wired', 'category': 'network'},
        {'id': 'access_point', 'name': 'Access Point', 'icon': 'fa-wifi', 'category': 'network'},

        # Printers
        {'id': 'printer', 'name': 'Printer', 'icon': 'fa-print', 'category': 'printer'},

        # Gaming
        {'id': 'playstation', 'name': 'PlayStation', 'icon': 'fa-gamepad', 'category': 'gaming'},
        {'id': 'xbox', 'name': 'Xbox', 'icon': 'fa-gamepad', 'category': 'gaming'},
        {'id': 'nintendo_switch', 'name': 'Nintendo Switch', 'icon': 'fa-gamepad', 'category': 'gaming'},

        # Generic
        {'id': 'unknown', 'name': 'Unknown Device', 'icon': 'fa-question-circle', 'category': 'unknown'},
    ]

    return jsonify({
        'success': True,
        'device_types': device_types
    })


# =============================================================================
# DEVICE DETAIL MODAL API - Premium SDN Features
# =============================================================================

def _sync_wifi_signals_to_db():
    """Sync WiFi signal data from host collector JSON to database."""
    import os
    signals_file = '/opt/hookprobe/fortress/data/wifi_signals.json'

    if not os.path.exists(signals_file):
        return 0

    try:
        with open(signals_file, 'r') as f:
            data = json.load(f)

        stations = data.get('stations', [])
        if not stations:
            return 0

        autopilot = get_sdn_autopilot()
        return autopilot.update_wifi_signals(stations)
    except Exception as e:
        logger.warning(f"Failed to sync WiFi signals: {e}")
        return 0


@sdn_bp.route('/api/device/<mac_address>/detail')
@login_required
def api_device_detail(mac_address):
    """Get comprehensive device detail for modal view.

    Returns: identity, policy, WiFi signal, traffic, tags, connection history.
    """
    mac = mac_address.upper().replace('-', ':')

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()

            # Sync WiFi signals from host collector before getting device detail
            _sync_wifi_signals_to_db()

            device = autopilot.get_device_detail(mac)

            # Auto-create device if it doesn't exist (from device status cache)
            # But skip if MAC is blocked (manually disconnected)
            if not device:
                # Check if MAC is blocked - return 404 for blocked devices
                if _is_mac_blocked(mac):
                    return jsonify({'success': False, 'error': 'Device has been disconnected'}), 404

                # Try to get info from device status cache
                status_cache = _load_device_status_cache()
                device_info = status_cache.get(mac, {})

                # Only create if we have info from cache (device is actually present)
                if device_info:
                    # Create device via Fingerbank pipeline with DHCP fingerprint
                    autopilot.ensure_device_exists(
                        mac=mac,
                        ip=device_info.get('ip', ''),
                        hostname=device_info.get('hostname', ''),
                        dhcp_fingerprint=device_info.get('dhcp_fingerprint', ''),
                        vendor_class=device_info.get('vendor_class', '')
                    )
                    # CWE-532: Pre-compute masked MAC to break taint chain
                    mac_safe = mask_mac(mac)
                    logger.info(f"Auto-created device {mac_safe} via Fingerbank pipeline")

                    # Get the newly created device
                    device = autopilot.get_device_detail(mac)

            if not device:
                return jsonify({'success': False, 'error': 'Device not found'}), 404

            # Merge real-time status from status_cache (ip neigh) into device data
            # The database status may be stale - status_cache has live data
            status_cache = _load_device_status_cache()
            live_status = status_cache.get(mac, {})
            if live_status:
                device['status'] = live_status.get('status', device.get('status', 'offline'))
                device['neighbor_state'] = live_status.get('neighbor_state', '')
                # Update IP if we have a more recent one from ARP
                if live_status.get('ip') and not device.get('ip'):
                    device['ip'] = live_status['ip']

            return jsonify({
                'success': True,
                'device': device
            })
        except Exception as e:
            logger.error(f"Failed to get device detail: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': False,
            'error': 'SDN Auto Pilot not available'
        }), 503


@sdn_bp.route('/api/device/<mac_address>/tags', methods=['POST'])
@login_required
@operator_required
def api_device_add_tag(mac_address):
    """Add a user tag to a device."""
    mac = mac_address.upper().replace('-', ':')
    data = request.get_json() or {}
    tag = data.get('tag', '').strip()

    if not tag:
        return jsonify({'success': False, 'error': 'Tag required'}), 400

    if len(tag) > 32:
        return jsonify({'success': False, 'error': 'Tag too long (max 32 chars)'}), 400

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()

            # Auto-create device if it doesn't exist (get IP from status cache if available)
            # Skip if MAC is blocked (manually disconnected)
            device = autopilot.get_device(mac)
            if not device:
                # Check if MAC is blocked
                if _is_mac_blocked(mac):
                    return jsonify({
                        'success': False,
                        'error': 'Device has been disconnected'
                    }), 404

                # Try to get additional info from device status cache
                status_cache = _load_device_status_cache()
                device_info = status_cache.get(mac, {})

                if device_info:
                    # Create device via Fingerbank pipeline with DHCP fingerprint
                    device = autopilot.ensure_device_exists(
                        mac=mac,
                        ip=device_info.get('ip', ''),
                        hostname=device_info.get('hostname', ''),
                        dhcp_fingerprint=device_info.get('dhcp_fingerprint', ''),
                        vendor_class=device_info.get('vendor_class', '')
                    )
                    # CWE-532: Pre-compute masked MAC to break taint chain
                    mac_safe = mask_mac(mac)
                    logger.info(f"Auto-created device {mac_safe} via Fingerbank pipeline")

            success = autopilot.add_tag(mac, tag)

            if success:
                # Log the event
                autopilot.log_connection_event(mac, 'tag_added', f'Tag "{tag}" added')
                return jsonify({
                    'success': True,
                    'message': f'Tag "{tag}" added to device'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to add tag to database'}), 500
        except Exception as e:
            logger.error(f"Failed to add tag: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({'success': False, 'error': 'SDN Auto Pilot not available'}), 503


@sdn_bp.route('/api/device/<mac_address>/tags/<tag>', methods=['DELETE'])
@login_required
@operator_required
def api_device_remove_tag(mac_address, tag):
    """Remove a user tag from a device."""
    mac = mac_address.upper().replace('-', ':')

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()

            # Check if device exists first
            device = autopilot.get_device(mac)
            if not device:
                return jsonify({
                    'success': False,
                    'error': f'Device {mask_mac(mac)} not found in database'
                }), 404

            success = autopilot.remove_tag(mac, tag)

            if success:
                # Log the event
                autopilot.log_connection_event(mac, 'tag_removed', f'Tag "{tag}" removed')
                return jsonify({
                    'success': True,
                    'message': f'Tag "{tag}" removed from device'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to remove tag from database'}), 500
        except Exception as e:
            logger.error(f"Failed to remove tag: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({'success': False, 'error': 'SDN Auto Pilot not available'}), 503


@sdn_bp.route('/api/device/<mac_address>/disconnect', methods=['POST'])
@login_required
@operator_required
@rate_limit(disconnect_rate_limiter)  # Security: Prevent DoS via rapid disconnect requests
def api_device_disconnect(mac_address):
    """Disconnect a device from WiFi by deauthenticating it.

    This sends a deauth frame via the FTS Host Agent (G.N.C. Architecture).
    The host agent communicates with hostapd via Unix Domain Socket to force
    the client to disconnect. The client will typically reconnect automatically
    unless also blocked.

    Rate limited: 10 requests per minute per user to prevent abuse.

    Options (JSON body):
    - block: bool - Also quarantine the device
    - delete: bool - Remove device from database (for manual/test devices)
    """
    import re

    # Validate and normalize MAC address (security: prevent injection)
    mac = mac_address.upper().replace('-', ':')
    mac_regex = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')
    if not mac_regex.match(mac):
        return jsonify({
            'success': False,
            'error': 'Invalid MAC address format'
        }), 400

    # Pre-compute masked MAC for secure logging (CWE-532 mitigation)
    # This breaks the taint chain for static analysis tools like CodeQL
    mac_masked = mask_mac(mac)

    data = request.get_json() or {}
    also_block = data.get('block', False)
    also_delete = data.get('delete', False)

    results = {
        'deauth_sent': False,
        'interfaces_tried': [],
        'blocked': False,  # WiFi MAC block
        'deleted': False,
        'lease_revoked': False,
        'host_agent_used': False,
        'unblock_scheduled': False,  # Auto-unblock timer started
        'block_duration_seconds': 60,  # How long device is blocked
    }

    # ==========================================================================
    # CISCO/ARUBA-STYLE DISCONNECT FLOW (with timed block)
    # ==========================================================================
    # Uses timed_block which:
    # 1. Blocks MAC for 60s (prevents immediate reconnection)
    # 2. Deauthenticates (kicks from WiFi)
    # 3. Revokes DHCP lease and clears ARP
    # 4. Automatically unblocks after 60s (device can manually reconnect)
    #
    # This stops the auto-reconnect loop while still allowing the device
    # to reconnect later when the user manually triggers it.
    # ==========================================================================

    # Get block duration from request (default 60s)
    block_duration = data.get('block_duration_seconds', 60)

    # Use timed_block for enterprise-style disconnect
    if HOST_AGENT_AVAILABLE:
        try:
            disconnect_result = timed_block_device(mac, block_duration_seconds=block_duration)
            results['host_agent_used'] = True

            if disconnect_result.get('success'):
                results['blocked'] = disconnect_result.get('blocked', False)
                results['deauth_sent'] = disconnect_result.get('deauth_sent', False)
                results['lease_revoked'] = disconnect_result.get('lease_revoked', False)
                results['ip_released'] = disconnect_result.get('ip_released')
                results['unblock_scheduled'] = disconnect_result.get('unblock_scheduled', False)
                results['block_duration_seconds'] = disconnect_result.get('block_duration_seconds', block_duration)
                results['interfaces_tried'] = disconnect_result.get('interfaces_blocked', [])
                logger.info(f"Timed block for {mac_masked}: blocked={results['blocked']}, "
                           f"deauth={results['deauth_sent']}, unblock_in={block_duration}s")
            elif disconnect_result.get('socket_missing'):
                logger.warning("Host agent socket not available, trying direct hostapd_cli")
                results['host_agent_used'] = False
            else:
                logger.warning(f"Host agent timed_block failed: {disconnect_result.get('error')}")
        except Exception as e:
            logger.error(f"Host agent error: {e}")
            results['host_agent_used'] = False

    # Fallback: Try direct hostapd_cli (works when not in container)
    # Note: Direct fallback only deauths - no timed block available
    if not results['host_agent_used'] or not results['deauth_sent']:
        import subprocess
        wifi_interfaces = ['wlan_24ghz', 'wlan_5ghz', 'wlan0', 'wlan1']

        for iface in wifi_interfaces:
            try:
                result = subprocess.run(
                    ['hostapd_cli', '-i', iface, 'deauthenticate', mac],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if iface not in results['interfaces_tried']:
                    results['interfaces_tried'].append(iface)

                if result.returncode == 0 and 'OK' in result.stdout:
                    results['deauth_sent'] = True
                    logger.info(f"Deauthenticated {mac_masked} from {iface} (direct fallback)")
            except FileNotFoundError:
                logger.debug(f"hostapd_cli not found for {iface}")
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout deauthenticating from {iface}")
            except Exception as e:
                logger.debug(f"Could not deauth from {iface}: {e}")

    # Update device status to offline after successful disconnect
    if results['deauth_sent']:
        try:
            import sqlite3
            db_path = '/var/lib/hookprobe/autopilot.db'
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            new_status = 'blocked' if results.get('blocked') else 'offline'
            cur.execute(
                "UPDATE device_identity SET status = ?, neighbor_state = 'DISCONNECTED' WHERE mac = ?",
                (new_status, mac)
            )
            conn.commit()
            conn.close()
            logger.debug(f"Updated device {mac_masked} status to {new_status}")
        except Exception as e:
            logger.warning(f"Failed to update device status: {e}")

    # Note: Lease revocation is handled by timed_block, but do it here for fallback
    if results['deauth_sent'] and not results.get('lease_revoked'):
        try:
            lease_result = revoke_lease(mac)
            if lease_result.get('success'):
                results['lease_revoked'] = True
                results['ip_released'] = lease_result.get('ip_address')
                logger.info(f"Revoked DHCP lease for {mac_masked}, IP: {lease_result.get('ip_address')}")
            else:
                results['lease_revoked'] = False
                logger.debug(f"Could not revoke lease for {mac_masked}: {lease_result.get('error')}")
        except Exception as e:
            logger.warning(f"Failed to revoke lease for {mac_masked}: {e}")
            results['lease_revoked'] = False

    # Also set policy to quarantine if requested (legacy option)
    if also_block and SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            autopilot.set_manual_policy(mac, 'quarantine')
            logger.info(f"Quarantined device {mac_masked}")
        except Exception as e:
            logger.warning(f"Failed to block device: {e}")

    # STEP 3: Delete device from database
    # When timed_block succeeds (device is blocked for 60s), always delete from DB.
    # This cleans up randomized MACs and stale entries.
    # Device will be re-created automatically by dhcp-event.sh when it reconnects.
    should_delete = also_delete or results.get('blocked', False)
    if should_delete:
        # Add to blocked MACs list to prevent auto-recreation during the block period
        # This ensures _load_device_status_cache() filters out the device
        if _add_blocked_mac(mac):
            results['blocked_mac_added'] = True
            logger.info(f"Added {mac_masked} to blocked MACs (prevents auto-recreation)")
        try:
            # Delete from device_identity table (SQLite - autopilot)
            import sqlite3
            db_path = '/var/lib/hookprobe/autopilot.db'
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("DELETE FROM device_identity WHERE mac = ?", (mac,))
            deleted_count = cur.rowcount
            conn.commit()
            conn.close()
            if deleted_count > 0:
                results['deleted'] = True
                logger.info(f"Deleted device {mac_masked} from SQLite autopilot.db")
        except Exception as e:
            logger.warning(f"Failed to delete device from SQLite: {e}")

        # Delete from PostgreSQL devices table (primary device lifecycle)
        try:
            import psycopg2
            pg_conn = psycopg2.connect(
                host=os.environ.get('DATABASE_HOST', '172.20.200.10'),
                port=os.environ.get('DATABASE_PORT', '5432'),
                dbname=os.environ.get('DATABASE_NAME', 'fortress'),
                user=os.environ.get('DATABASE_USER', 'fortress'),
                password=os.environ.get('DATABASE_PASSWORD', 'fortress_db_secret')
            )
            pg_cur = pg_conn.cursor()
            pg_cur.execute("DELETE FROM devices WHERE mac_address = %s", (mac,))
            pg_deleted = pg_cur.rowcount
            pg_conn.commit()
            pg_cur.close()
            pg_conn.close()
            if pg_deleted > 0:
                results['deleted'] = True
                logger.info(f"Deleted device {mac_masked} from PostgreSQL devices table")
        except Exception as e:
            logger.debug(f"PostgreSQL delete (optional): {e}")

        # Delete from local devices.json (updated by dhcp-event.sh)
        try:
            devices_file = Path('/opt/hookprobe/fortress/data/devices.json')
            if devices_file.exists():
                import json as json_module
                with open(devices_file, 'r') as f:
                    devices = json_module.load(f)
                if mac in devices:
                    del devices[mac]
                    with open(devices_file, 'w') as f:
                        json_module.dump(devices, f, indent=2)
                    results['deleted'] = True
                    logger.info(f"Deleted device {mac_masked} from devices.json")
        except Exception as e:
            logger.debug(f"devices.json delete (optional): {e}")

        # Also try autopilot delete for any other cleanup
        if SDN_AUTOPILOT_AVAILABLE:
            try:
                autopilot = get_sdn_autopilot()
                autopilot.delete_device(mac)
            except Exception:
                pass  # Already deleted via direct SQL

    # Build response message
    msg_parts = []
    if results['deauth_sent']:
        msg_parts.append('kicked from WiFi')
    if results.get('blocked'):
        block_time = results.get('block_duration_seconds', 60)
        msg_parts.append(f'blocked for {block_time}s')
    if results.get('lease_revoked'):
        msg_parts.append('lease revoked')
    if results['deleted']:
        msg_parts.append('removed from DB (will re-appear on reconnect)')

    if msg_parts:
        msg = 'Device ' + ' and '.join(msg_parts)
        return jsonify({'success': True, 'message': msg, 'details': results})
    elif also_delete and results.get('deleted'):
        return jsonify({
            'success': True,
            'message': 'Device removed from database',
            'details': results
        })
    elif not results['interfaces_tried'] and not results['host_agent_used']:
        # Neither host agent nor direct hostapd_cli available
        if results.get('deleted'):
            return jsonify({
                'success': True,
                'message': 'Device removed from database',
                'details': results
            })
        return jsonify({
            'success': False,
            'error': 'WiFi control unavailable - host agent not running and hostapd_cli not accessible',
            'details': results
        }), 503
    elif not results['deauth_sent']:
        return jsonify({
            'success': False,
            'error': 'Could not disconnect device - may not be connected via WiFi',
            'details': results
        }), 400
    else:
        return jsonify({'success': True, 'message': 'Device disconnected', 'details': results})


@sdn_bp.route('/api/device/<mac_address>/timeline')
@login_required
def api_device_timeline(mac_address):
    """Get connection timeline for a device (last 24 hours)."""
    mac = mac_address.upper().replace('-', ':')
    hours = request.args.get('hours', 24, type=int)

    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            timeline = autopilot.get_connection_timeline(mac, hours)

            return jsonify({
                'success': True,
                'timeline': timeline,
                'hours': hours
            })
        except Exception as e:
            logger.error(f"Failed to get timeline: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({'success': False, 'error': 'SDN Auto Pilot not available'}), 503


@sdn_bp.route('/api/tags')
@login_required
def api_all_tags():
    """Get all unique tags across all devices."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            tags = autopilot.get_all_tags()

            return jsonify({
                'success': True,
                'tags': tags,
                'count': len(tags)
            })
        except Exception as e:
            logger.error(f"Failed to get tags: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({'success': True, 'tags': [], 'count': 0})


@sdn_bp.route('/api/proximity/report')
@login_required
def api_proximity_report():
    """Get proximity security report."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            report = autopilot.get_proximity_report()

            return jsonify({
                'success': True,
                **report
            })
        except Exception as e:
            logger.error(f"Failed to get proximity report: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'proximity_distribution': {},
            'devices_at_risk': [],
            'risk_count': 0
        })


@sdn_bp.route('/api/proximity/enforce', methods=['POST'])
@login_required
@operator_required
def api_proximity_enforce():
    """Manually trigger proximity-based policy enforcement."""
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            actions = autopilot.enforce_proximity_policies()

            return jsonify({
                'success': True,
                'actions': actions,
                'affected_count': len(actions)
            })
        except Exception as e:
            logger.error(f"Failed to enforce proximity policies: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({'success': False, 'error': 'SDN Auto Pilot not available'}), 503


@sdn_bp.route('/api/wifi/signals')
@login_required
def api_wifi_signals():
    """Get current WiFi signal data from host collector cache."""
    import os

    signals_file = '/opt/hookprobe/fortress/data/wifi_signals.json'

    if os.path.exists(signals_file):
        try:
            with open(signals_file, 'r') as f:
                data = json.load(f)
            return jsonify({
                'success': True,
                **data
            })
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to read WiFi signals: {e}")
            return jsonify({'success': False, 'error': safe_error_message(e)}), 500
    else:
        return jsonify({
            'success': True,
            'timestamp': None,
            'stations': [],
            'station_count': 0,
            'note': 'WiFi signal collector not running'
        })
