#!/usr/bin/env python3
"""
QSecBit Fortress Agent - Full Implementation
Version: 5.2.0
License: AGPL-3.0

Fortress-enhanced QSecBit with:
- L2-L7 Layer Threat Detection (Suricata/Zeek integration)
- Extended telemetry from monitoring stack
- XDP/eBPF DDoS protection integration
- nftables policy scoring
- MACsec status monitoring
- OpenFlow flow analysis
- HTTP API for healthcheck and status
"""

import json
import time
import os
import sys
import signal
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from threading import Thread, Event
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request

# Import L2-L7 Layer Detectors from core
try:
    from core.qsecbit.detectors import (
        L2DataLinkDetector,
        L3NetworkDetector,
        L4TransportDetector,
        L5SessionDetector,
        L7ApplicationDetector,
    )
    from core.qsecbit.threat_types import ThreatEvent, ThreatSeverity
    LAYER_DETECTORS_AVAILABLE = True
except ImportError:
    LAYER_DETECTORS_AVAILABLE = False

# Logging setup
LOG_DIR = Path(os.environ.get('QSECBIT_LOG_DIR', '/var/log/hookprobe'))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'qsecbit-fortress.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('qsecbit-fortress')

# Paths
DATA_DIR = Path(os.environ.get('QSECBIT_DATA_DIR', '/opt/hookprobe/fortress/data'))
STATS_FILE = DATA_DIR / "qsecbit_stats.json"
CONFIG_DIR = Path("/etc/hookprobe")

# OVS Bridge name (FTS = abbreviation for fortress)
OVS_BRIDGE = os.environ.get('OVS_BRIDGE', 'FTS')

# OUI Database for manufacturer lookup (common vendors)
OUI_DATABASE = {
    'Apple': [
        '00:1C:B3', '00:03:93', '00:0A:27', '00:0A:95', '00:10:FA', '00:11:24',
        '00:14:51', '00:16:CB', '00:17:F2', '00:19:E3', '00:1B:63', '00:1D:4F',
        '00:1E:52', '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9', '00:22:41',
        '00:23:12', '00:23:32', '00:23:6C', '00:23:DF', '00:24:36', '00:25:00',
        'A4:5E:60', 'AC:BC:32', 'B0:34:95', 'B8:09:8A', 'BC:52:B7', 'C0:84:7A',
        'D4:9A:20', 'DC:2B:2A', 'E0:B9:BA', 'F0:B4:79', 'F4:5C:89', '3C:06:30',
        '8C:85:90', 'A8:66:7F', 'AC:DE:48', 'B4:F0:AB', 'C8:69:CD', 'D0:C5:D3',
    ],
    'Samsung': [
        '00:00:F0', '00:07:AB', '00:09:18', '00:12:47', '00:12:FB', '00:13:77',
        '00:15:99', '00:15:B9', '00:16:32', '00:16:6B', '00:16:6C', '00:17:C9',
        '08:D4:2B', '10:D5:42', '14:89:FD', '18:3A:2D', '1C:62:B8', '20:D3:90',
    ],
    'Google': [
        '3C:5A:B4', '94:EB:2C', 'F4:F5:D8', '54:60:09', 'F8:8F:CA', '94:94:26',
        '00:1A:11', '1C:F2:9A', '30:FD:38', '44:07:0B',
    ],
    'Intel': [
        '00:02:B3', '00:03:47', '00:04:23', '00:07:E9', '00:0C:F1', '00:0E:0C',
        '00:0E:35', '00:11:11', '00:12:F0', '00:13:02', '00:13:20', '00:13:CE',
        '00:15:00', '00:16:6F', '00:16:76', '00:16:EA', '00:16:EB', '00:18:DE',
    ],
    'Realtek': ['00:E0:4C', '52:54:00', '00:20:18', '00:0A:CD', '00:40:F4'],
    'Dell': [
        '00:06:5B', '00:08:74', '00:0B:DB', '00:0D:56', '00:0F:1F', '00:11:43',
        '00:12:3F', '00:13:72', '00:14:22', '00:15:C5', '00:18:8B', '00:19:B9',
    ],
    'HP': [
        '00:01:E6', '00:02:A5', '00:04:EA', '00:08:02', '00:0A:57', '00:0B:CD',
        '00:0D:9D', '00:0E:7F', '00:0F:20', '00:0F:61', '00:10:83', '00:11:0A',
    ],
    'Cisco': [
        '00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64', '00:01:96',
        '00:01:97', '00:01:C7', '00:01:C9', '00:02:3D', '00:02:4A', '00:02:4B',
    ],
    'TP-Link': [
        '00:27:19', '14:CC:20', '30:B5:C2', '50:C7:BF', '54:C8:0F', '60:E3:27',
        '64:66:B3', '6C:5A:B5', '70:4F:57', '74:DA:88', '78:44:76', '80:89:17',
    ],
    'Xiaomi': [
        '00:9E:C8', '0C:1D:AF', '10:2A:B3', '14:F6:5A', '18:59:36', '1C:5F:2B',
        '20:47:DA', '28:6C:07', '2C:56:DC', '34:80:B3', '38:A4:ED', '3C:BD:D8',
    ],
    'Huawei': [
        '00:1E:10', '00:25:9E', '00:25:68', '00:34:FE', '00:46:4B', '00:5A:13',
        '00:66:4B', '00:9A:CD', '00:E0:FC', '04:02:1F', '04:25:C5', '04:33:89',
    ],
    'Raspberry Pi': ['B8:27:EB', 'DC:A6:32', 'E4:5F:01', '28:CD:C1', 'D8:3A:DD'],
    'Amazon': [
        '00:FC:8B', '0C:47:C9', '10:CE:A9', '18:74:2E', '34:D2:70', '38:F7:3D',
        '40:A2:DB', '44:65:0D', '4C:EF:C0', '50:DC:E7', '68:37:E9', '68:54:FD',
    ],
    'Microsoft': [
        '00:0D:3A', '00:12:5A', '00:15:5D', '00:17:FA', '00:1D:D8', '00:22:48',
        '00:25:AE', '28:18:78', '30:59:B7', '48:50:73', '50:1A:C5', '58:82:A8',
    ],
    'Espressif': ['24:0A:C4', '24:62:AB', '30:AE:A4', '3C:61:05', '4C:11:AE', '5C:CF:7F'],
    'Sonos': ['00:0E:58', '34:7E:5C', '54:2A:1B', '78:28:CA', '94:9F:3E'],
    'Ring': ['0C:8C:DC', '20:72:64', '34:71:7A', '50:4E:DC', '7C:50:79'],
    'Nest': ['18:B4:30', '64:16:66', 'F8:8F:CA'],
    'Philips': ['00:09:97', '00:17:88', '00:1F:E4'],
}


# IEEE OUI file path (installed by ieee-data package or hwdata)
OUI_FILE = Path('/usr/share/misc/oui.txt')
OUI_FILE_ALT = Path('/usr/share/hwdata/oui.txt')
_oui_cache: Dict[str, str] = {}
_oui_loaded = False


def is_locally_administered_mac(mac_address: str) -> bool:
    """Check if MAC address is locally administered (randomized).

    The second nibble of a MAC address indicates if it's locally administered:
    - If the second least significant bit is 1, it's locally administered
    - This means second nibble is 2, 3, 6, 7, A, B, E, or F

    iOS 14+, Android 10+, Windows 10+ use MAC randomization by default.
    """
    if not mac_address or len(mac_address) < 2:
        return False

    # Get second character (second nibble)
    mac_clean = mac_address.replace(':', '').replace('-', '').upper()
    if len(mac_clean) < 2:
        return False

    second_nibble = mac_clean[1]
    # Locally administered if second nibble is 2, 3, 6, 7, A, B, E, or F
    return second_nibble in '2367ABEF'


def _load_oui_database():
    """Load IEEE OUI database from system file."""
    global _oui_cache, _oui_loaded

    if _oui_loaded:
        return

    _oui_loaded = True

    # Try to load from IEEE OUI file
    oui_file = None
    for path in [OUI_FILE, OUI_FILE_ALT]:
        if path.exists():
            oui_file = path
            break

    if oui_file:
        try:
            with open(oui_file, 'r', errors='ignore') as f:
                for line in f:
                    if '(hex)' in line:
                        parts = line.split('(hex)')
                        if len(parts) >= 2:
                            # Format: "00-00-00   (hex)		Xerox Corporation"
                            prefix = parts[0].strip().replace('-', '').upper()
                            vendor = parts[1].strip()
                            if prefix and vendor:
                                _oui_cache[prefix] = vendor
            logger.info(f"Loaded {len(_oui_cache)} OUI entries from {oui_file}")
        except Exception as e:
            logger.warning(f"Failed to load OUI file: {e}")


def lookup_manufacturer(mac_address: str) -> str:
    """Lookup manufacturer from MAC OUI prefix.

    Uses IEEE OUI database file if available, falls back to built-in database.
    Returns 'Private' for locally administered (randomized) MAC addresses.
    """
    if not mac_address:
        return 'Unknown'

    # Check if MAC is locally administered (randomized)
    if is_locally_administered_mac(mac_address):
        return 'Private'

    # Get OUI prefix (first 6 hex chars without separators)
    mac_clean = mac_address.replace(':', '').replace('-', '').upper()
    oui_prefix = mac_clean[:6]
    mac_prefix = mac_address[:8].upper()

    # Try IEEE OUI database first
    _load_oui_database()
    if oui_prefix in _oui_cache:
        return _oui_cache[oui_prefix]

    # Fall back to built-in database
    for manufacturer, ouis in OUI_DATABASE.items():
        if mac_prefix in ouis:
            return manufacturer

    return 'Unknown'


# Device manual tags file path
DEVICE_TAGS_FILE = DATA_DIR / 'device_tags.json'


def load_device_tags() -> Dict[str, Dict]:
    """Load manually assigned device tags."""
    if DEVICE_TAGS_FILE.exists():
        try:
            return json.loads(DEVICE_TAGS_FILE.read_text())
        except Exception:
            pass
    return {}


def save_device_tag(mac: str, device_type: str, label: str = None):
    """Save a manual device tag for a MAC address."""
    tags = load_device_tags()
    tags[mac.upper()] = {
        'device_type': device_type,
        'label': label,
        'tagged_at': datetime.now().isoformat()
    }
    try:
        DEVICE_TAGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEVICE_TAGS_FILE.write_text(json.dumps(tags, indent=2))
    except Exception as e:
        logger.warning(f"Failed to save device tag: {e}")


def detect_device_type(mac: str, hostname: str, manufacturer: str) -> str:
    """Detect device type from available information with ML-enhanced classification.

    Priority:
    1. Manual tags (user-assigned)
    2. Hostname patterns (most reliable)
    3. mDNS service patterns
    4. Manufacturer + MAC OUI patterns
    5. Generic manufacturer classification
    """
    hostname_lower = (hostname or '').lower()
    manufacturer_lower = (manufacturer or '').lower()
    mac_upper = (mac or '').upper()

    # Priority 1: Check for manual device tags
    tags = load_device_tags()
    if mac_upper in tags:
        return tags[mac_upper].get('device_type', 'unknown')

    # Priority 2: Hostname-based detection (most specific)
    # Apple devices - specific models
    if 'iphone' in hostname_lower:
        return 'iphone'
    if 'ipad' in hostname_lower:
        return 'ipad'
    if 'macbook' in hostname_lower:
        return 'macbook'
    if 'imac' in hostname_lower:
        return 'imac'
    if 'mac-mini' in hostname_lower or 'macmini' in hostname_lower:
        return 'mac_mini'
    if 'mac-pro' in hostname_lower or 'macpro' in hostname_lower:
        return 'mac_pro'
    if 'mac-studio' in hostname_lower:
        return 'mac_studio'
    if 'apple-watch' in hostname_lower or 'applewatch' in hostname_lower:
        return 'apple_watch'
    if 'homepod' in hostname_lower:
        return 'homepod'
    if 'apple-tv' in hostname_lower or 'appletv' in hostname_lower:
        return 'apple_tv'
    if 'airpods' in hostname_lower:
        return 'airpods'
    if 'airplay' in hostname_lower:
        return 'airplay_speaker'

    # Other phones/tablets
    if 'android' in hostname_lower:
        return 'android_phone'
    if 'pixel' in hostname_lower:
        return 'pixel_phone'
    if 'galaxy' in hostname_lower and 'tab' in hostname_lower:
        return 'android_tablet'
    if 'galaxy' in hostname_lower or 'samsung' in hostname_lower:
        return 'android_phone'
    if 'surface' in hostname_lower:
        return 'tablet'

    # Computers
    if 'windows' in hostname_lower or '-pc' in hostname_lower:
        return 'windows_pc'
    if 'linux' in hostname_lower or 'ubuntu' in hostname_lower:
        return 'linux_pc'

    # Printers
    if 'printer' in hostname_lower or 'hp-' in hostname_lower.split('-')[0]:
        return 'printer'
    if 'epson' in hostname_lower or 'canon' in hostname_lower or 'brother' in hostname_lower:
        return 'printer'

    # Cameras
    if 'camera' in hostname_lower or 'cam-' in hostname_lower:
        return 'ip_camera'
    if 'hikvision' in hostname_lower or 'dahua' in hostname_lower or 'reolink' in hostname_lower:
        return 'ip_camera'
    if 'ring' in hostname_lower and ('cam' in hostname_lower or 'doorbell' in hostname_lower):
        return 'ring_camera'

    # Smart TVs
    if 'tv' in hostname_lower or 'samsung-tv' in hostname_lower:
        return 'smart_tv'
    if 'roku' in hostname_lower:
        return 'roku'
    if 'chromecast' in hostname_lower:
        return 'chromecast'
    if 'firetv' in hostname_lower or 'fire-tv' in hostname_lower:
        return 'fire_tv'

    # Smart speakers and assistants
    if 'echo' in hostname_lower or 'alexa' in hostname_lower:
        return 'amazon_echo'
    if 'sonos' in hostname_lower:
        return 'sonos_speaker'
    if 'google-home' in hostname_lower or 'googlehome' in hostname_lower:
        return 'google_home'
    if 'nest-hub' in hostname_lower or 'nesthub' in hostname_lower:
        return 'nest_hub'
    if 'nest-mini' in hostname_lower or 'nestmini' in hostname_lower:
        return 'nest_mini'

    # IoT devices
    if 'nest' in hostname_lower or 'thermostat' in hostname_lower:
        return 'smart_thermostat'
    if 'ring' in hostname_lower or 'doorbell' in hostname_lower:
        return 'smart_doorbell'
    if 'hue' in hostname_lower:
        return 'hue_light'
    if 'wemo' in hostname_lower:
        return 'wemo_switch'
    if 'lifx' in hostname_lower:
        return 'smart_light'
    if 'smartthings' in hostname_lower:
        return 'smartthings_hub'

    # Network devices
    if 'router' in hostname_lower or 'gateway' in hostname_lower:
        return 'router'
    if 'switch' in hostname_lower or 'unifi' in hostname_lower:
        return 'network_switch'
    if 'ap-' in hostname_lower or 'access-point' in hostname_lower:
        return 'access_point'

    # Game consoles
    if 'playstation' in hostname_lower or 'ps4' in hostname_lower or 'ps5' in hostname_lower:
        return 'playstation'
    if 'xbox' in hostname_lower:
        return 'xbox'
    if 'nintendo' in hostname_lower or 'switch' in hostname_lower:
        return 'nintendo_switch'

    # Priority 3: Manufacturer + MAC OUI specific patterns
    if manufacturer_lower == 'apple':
        # Apple MAC ranges can help identify device types
        mac_prefix = mac_upper[:8] if len(mac_upper) >= 8 else ''
        # Apple Watch tends to have specific MAC ranges
        watch_prefixes = ['F0:C7:7F', '70:3E:AC', '60:F8:1D', '5C:F9:38']
        homepod_prefixes = ['70:56:81', 'E8:B2:AC', '60:AB:D2']
        if any(mac_upper.startswith(p) for p in watch_prefixes):
            return 'apple_watch'
        if any(mac_upper.startswith(p) for p in homepod_prefixes):
            return 'homepod'
        return 'apple_device'

    if manufacturer_lower in ['samsung', 'xiaomi', 'huawei', 'oppo', 'oneplus', 'vivo']:
        return 'android_phone'
    if manufacturer_lower == 'raspberry pi':
        return 'raspberry_pi'
    if manufacturer_lower == 'amazon':
        return 'amazon_device'
    if manufacturer_lower == 'google':
        return 'google_device'
    if manufacturer_lower in ['intel', 'realtek', 'dell', 'hp', 'lenovo', 'asus', 'acer']:
        return 'computer'
    if manufacturer_lower == 'microsoft':
        return 'windows_device'
    if manufacturer_lower in ['cisco', 'tp-link', 'netgear', 'ubiquiti', 'aruba']:
        return 'network_device'
    if manufacturer_lower == 'espressif':
        return 'esp_iot'
    if manufacturer_lower in ['sonos']:
        return 'sonos_speaker'
    if manufacturer_lower in ['philips']:
        return 'philips_device'
    if manufacturer_lower in ['hikvision', 'dahua']:
        return 'ip_camera'

    # Priority 5: For randomized MACs, classify as mobile/laptop
    # iOS 14+, Android 10+, Windows 10+ use MAC randomization by default
    # These are typically phones, tablets, or modern laptops
    if manufacturer_lower == 'private':
        return 'mobile_device'

    return 'unknown'


def get_device_display_info(device_type: str) -> Dict[str, str]:
    """Get display name and icon for a device type."""
    DEVICE_DISPLAY = {
        # Apple devices
        'iphone': {'name': 'iPhone', 'icon': 'fa-mobile-alt', 'category': 'phone'},
        'ipad': {'name': 'iPad', 'icon': 'fa-tablet-alt', 'category': 'tablet'},
        'macbook': {'name': 'MacBook', 'icon': 'fa-laptop', 'category': 'laptop'},
        'imac': {'name': 'iMac', 'icon': 'fa-desktop', 'category': 'desktop'},
        'mac_mini': {'name': 'Mac mini', 'icon': 'fa-server', 'category': 'desktop'},
        'mac_pro': {'name': 'Mac Pro', 'icon': 'fa-server', 'category': 'desktop'},
        'mac_studio': {'name': 'Mac Studio', 'icon': 'fa-server', 'category': 'desktop'},
        'apple_watch': {'name': 'Apple Watch', 'icon': 'fa-clock', 'category': 'wearable'},
        'homepod': {'name': 'HomePod', 'icon': 'fa-volume-up', 'category': 'speaker'},
        'apple_tv': {'name': 'Apple TV', 'icon': 'fa-tv', 'category': 'streaming'},
        'airpods': {'name': 'AirPods', 'icon': 'fa-headphones', 'category': 'audio'},
        'apple_device': {'name': 'Apple Device', 'icon': 'fa-apple', 'category': 'unknown'},

        # Android devices
        'android_phone': {'name': 'Android Phone', 'icon': 'fa-mobile-alt', 'category': 'phone'},
        'pixel_phone': {'name': 'Pixel Phone', 'icon': 'fa-mobile-alt', 'category': 'phone'},
        'android_tablet': {'name': 'Android Tablet', 'icon': 'fa-tablet-alt', 'category': 'tablet'},

        # Computers
        'windows_pc': {'name': 'Windows PC', 'icon': 'fa-desktop', 'category': 'computer'},
        'linux_pc': {'name': 'Linux PC', 'icon': 'fa-linux', 'category': 'computer'},
        'computer': {'name': 'Computer', 'icon': 'fa-desktop', 'category': 'computer'},
        'laptop': {'name': 'Laptop', 'icon': 'fa-laptop', 'category': 'computer'},
        'desktop': {'name': 'Desktop', 'icon': 'fa-desktop', 'category': 'computer'},
        'tablet': {'name': 'Tablet', 'icon': 'fa-tablet-alt', 'category': 'tablet'},

        # Smart speakers
        'amazon_echo': {'name': 'Amazon Echo', 'icon': 'fa-volume-up', 'category': 'speaker'},
        'sonos_speaker': {'name': 'Sonos Speaker', 'icon': 'fa-volume-up', 'category': 'speaker'},
        'google_home': {'name': 'Google Home', 'icon': 'fa-volume-up', 'category': 'speaker'},
        'nest_hub': {'name': 'Nest Hub', 'icon': 'fa-tv', 'category': 'smart_display'},
        'nest_mini': {'name': 'Nest Mini', 'icon': 'fa-volume-down', 'category': 'speaker'},
        'airplay_speaker': {'name': 'AirPlay Speaker', 'icon': 'fa-volume-up', 'category': 'speaker'},

        # Streaming devices
        'roku': {'name': 'Roku', 'icon': 'fa-tv', 'category': 'streaming'},
        'chromecast': {'name': 'Chromecast', 'icon': 'fa-tv', 'category': 'streaming'},
        'fire_tv': {'name': 'Fire TV', 'icon': 'fa-tv', 'category': 'streaming'},
        'smart_tv': {'name': 'Smart TV', 'icon': 'fa-tv', 'category': 'tv'},

        # IoT
        'smart_thermostat': {'name': 'Smart Thermostat', 'icon': 'fa-thermometer-half', 'category': 'iot'},
        'smart_doorbell': {'name': 'Smart Doorbell', 'icon': 'fa-bell', 'category': 'iot'},
        'ring_camera': {'name': 'Ring Camera', 'icon': 'fa-video', 'category': 'camera'},
        'ip_camera': {'name': 'IP Camera', 'icon': 'fa-video', 'category': 'camera'},
        'hue_light': {'name': 'Philips Hue', 'icon': 'fa-lightbulb', 'category': 'lighting'},
        'smart_light': {'name': 'Smart Light', 'icon': 'fa-lightbulb', 'category': 'lighting'},
        'wemo_switch': {'name': 'WeMo Switch', 'icon': 'fa-plug', 'category': 'switch'},
        'smartthings_hub': {'name': 'SmartThings Hub', 'icon': 'fa-home', 'category': 'hub'},
        'raspberry_pi': {'name': 'Raspberry Pi', 'icon': 'fa-microchip', 'category': 'iot'},
        'esp_iot': {'name': 'ESP IoT Device', 'icon': 'fa-microchip', 'category': 'iot'},

        # Network devices
        'router': {'name': 'Router', 'icon': 'fa-network-wired', 'category': 'network'},
        'network_switch': {'name': 'Network Switch', 'icon': 'fa-network-wired', 'category': 'network'},
        'access_point': {'name': 'Access Point', 'icon': 'fa-wifi', 'category': 'network'},
        'network_device': {'name': 'Network Device', 'icon': 'fa-network-wired', 'category': 'network'},

        # Printers
        'printer': {'name': 'Printer', 'icon': 'fa-print', 'category': 'printer'},

        # Gaming
        'playstation': {'name': 'PlayStation', 'icon': 'fa-gamepad', 'category': 'gaming'},
        'xbox': {'name': 'Xbox', 'icon': 'fa-gamepad', 'category': 'gaming'},
        'nintendo_switch': {'name': 'Nintendo Switch', 'icon': 'fa-gamepad', 'category': 'gaming'},

        # Generic
        'amazon_device': {'name': 'Amazon Device', 'icon': 'fa-amazon', 'category': 'smart_home'},
        'google_device': {'name': 'Google Device', 'icon': 'fa-google', 'category': 'smart_home'},
        'windows_device': {'name': 'Windows Device', 'icon': 'fa-windows', 'category': 'computer'},
        'philips_device': {'name': 'Philips Device', 'icon': 'fa-lightbulb', 'category': 'smart_home'},
        'mobile_device': {'name': 'Mobile Device', 'icon': 'fa-mobile-alt', 'category': 'mobile'},
        'unknown': {'name': 'Unknown Device', 'icon': 'fa-question-circle', 'category': 'unknown'},
    }
    return DEVICE_DISPLAY.get(device_type, DEVICE_DISPLAY['unknown'])


def get_dhcp_hostnames() -> Dict[str, str]:
    """Get hostnames from dnsmasq DHCP leases file.

    This is the most reliable source as it contains what devices
    told the DHCP server during lease acquisition.
    """
    hostnames = {}  # MAC -> hostname

    # Common dnsmasq lease file locations
    lease_files = [
        '/var/lib/misc/dnsmasq.leases',
        '/var/lib/dnsmasq/dnsmasq.leases',
        '/tmp/dhcp.leases',
        '/var/run/dnsmasq/leases',
    ]

    for lease_file in lease_files:
        if Path(lease_file).exists():
            try:
                with open(lease_file) as f:
                    for line in f:
                        parts = line.strip().split()
                        # Format: timestamp MAC IP hostname client-id
                        if len(parts) >= 4:
                            mac = parts[1].upper()
                            hostname = parts[3]
                            # Skip placeholder hostnames
                            if hostname != '*' and hostname != '':
                                hostnames[mac] = hostname
            except Exception:
                pass
            break  # Use first found lease file

    return hostnames


def get_mdns_hostnames() -> Dict[str, str]:
    """Get hostnames from mDNS/Avahi discovery.

    Uses avahi-browse to discover devices advertising via mDNS.
    Returns IP -> hostname mapping.
    """
    hostnames = {}  # IP -> hostname

    try:
        # Run avahi-browse to discover all services (timeout after 3 seconds)
        result = subprocess.run(
            ['avahi-browse', '-atrp'],  # all, terminate, resolve, parseable
            capture_output=True, text=True, timeout=5
        )

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                # Parseable format: +;interface;protocol;name;type;domain;hostname;address;port;txt
                # We want the resolved entries (=)
                if line.startswith('='):
                    parts = line.split(';')
                    if len(parts) >= 8:
                        hostname = parts[6]  # hostname field
                        ip_addr = parts[7]   # address field
                        if ip_addr and hostname and not hostname.endswith('.local'):
                            # Remove .local suffix if present
                            hostname = hostname.replace('.local', '')
                            hostnames[ip_addr] = hostname
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # avahi-browse not installed
        pass
    except Exception:
        pass

    return hostnames


def get_netbios_hostnames() -> Dict[str, str]:
    """Get hostnames from NetBIOS (Windows devices).

    Uses nbtscan to discover Windows device names.
    Returns IP -> hostname mapping.
    """
    hostnames = {}  # IP -> hostname

    try:
        # Scan local network for NetBIOS names
        result = subprocess.run(
            ['nbtscan', '-q', '-s', '\t', '10.200.0.0/23'],  # Fortress default subnet
            capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    ip_addr = parts[0].strip()
                    hostname = parts[1].strip()
                    if ip_addr and hostname:
                        hostnames[ip_addr] = hostname
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # nbtscan not installed
        pass
    except Exception:
        pass

    return hostnames


# Cache for hostname lookups (refreshed every 30 seconds with device collection)
_hostname_cache = {
    'dhcp': {},      # MAC -> hostname
    'mdns': {},      # IP -> hostname
    'netbios': {},   # IP -> hostname
    'last_refresh': 0
}


def refresh_hostname_cache():
    """Refresh all hostname caches from various sources."""
    global _hostname_cache

    _hostname_cache['dhcp'] = get_dhcp_hostnames()
    _hostname_cache['mdns'] = get_mdns_hostnames()
    _hostname_cache['netbios'] = get_netbios_hostnames()
    _hostname_cache['last_refresh'] = time.time()

    total = len(_hostname_cache['dhcp']) + len(_hostname_cache['mdns']) + len(_hostname_cache['netbios'])
    logger.debug(f"Hostname cache refreshed: {len(_hostname_cache['dhcp'])} DHCP, "
                 f"{len(_hostname_cache['mdns'])} mDNS, {len(_hostname_cache['netbios'])} NetBIOS")


def resolve_hostname(ip_address: str, mac_address: str = None) -> str:
    """Resolve hostname using multiple sources (most reliable first).

    Priority:
    1. DHCP leases (device-provided hostname, most reliable)
    2. mDNS/Avahi (Apple devices, Linux, printers)
    3. NetBIOS (Windows devices)
    4. Reverse DNS (fallback, often unreliable)
    """
    import socket

    # Refresh cache if stale (older than 60 seconds)
    if time.time() - _hostname_cache['last_refresh'] > 60:
        refresh_hostname_cache()

    # 1. Check DHCP hostname (by MAC address)
    if mac_address:
        mac_upper = mac_address.upper()
        if mac_upper in _hostname_cache['dhcp']:
            return _hostname_cache['dhcp'][mac_upper]

    # 2. Check mDNS hostname
    if ip_address in _hostname_cache['mdns']:
        return _hostname_cache['mdns'][ip_address]

    # 3. Check NetBIOS hostname
    if ip_address in _hostname_cache['netbios']:
        return _hostname_cache['netbios'][ip_address]

    # 4. Fallback to reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        if hostname != ip_address and not hostname.startswith(ip_address.replace('.', '-')):
            return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        pass

    return None


@dataclass
class QSecBitConfig:
    """QSecBit configuration for Fortress"""
    # Main component weights (must sum to 1.0)
    alpha: float = 0.15   # System drift weight
    beta: float = 0.10    # Network health weight
    gamma: float = 0.35   # L2-L7 threat detection weight (primary)
    delta: float = 0.10   # Energy efficiency weight
    epsilon: float = 0.10 # Infrastructure health weight

    # Thresholds (higher = healthier, we want high scores)
    amber_threshold: float = 0.45
    red_threshold: float = 0.30

    # Fortress-specific weights
    nftables_weight: float = 0.05
    macsec_weight: float = 0.05
    openflow_weight: float = 0.05
    xdp_weight: float = 0.05

    # Layer detection weights (within gamma)
    l2_weight: float = 0.25  # Data Link (ARP, MAC, Evil Twin)
    l3_weight: float = 0.15  # Network (IP spoofing, ICMP)
    l4_weight: float = 0.20  # Transport (SYN flood, port scan)
    l5_weight: float = 0.20  # Session (SSL strip, TLS downgrade)
    l7_weight: float = 0.20  # Application (SQLi, XSS, C2)


@dataclass
class QSecBitSample:
    """Single QSecBit measurement"""
    timestamp: str
    score: float
    rag_status: str
    components: Dict[str, float]
    threats_detected: int
    suricata_alerts: int
    policy_violations: int
    macsec_status: str
    openflow_flows: int
    # Layer threat scores (0.0-1.0, higher = more threats)
    layer_scores: Dict[str, float] = None
    # Recent threat events
    recent_threats: List[Dict] = None
    # XDP stats
    xdp_stats: Dict[str, int] = None

    def __post_init__(self):
        if self.layer_scores is None:
            self.layer_scores = {}
        if self.recent_threats is None:
            self.recent_threats = []
        if self.xdp_stats is None:
            self.xdp_stats = {}


# Global reference to agent for HTTP handler
_agent_instance: Optional['QSecBitFortressAgent'] = None


class QSecBitAPIHandler(BaseHTTPRequestHandler):
    """HTTP API handler for QSecBit status and health"""

    def log_message(self, format, *args):
        """Suppress default logging, use our logger instead"""
        logger.debug(f"HTTP: {args[0]}")

    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response"""
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Handle GET requests"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == '/health':
            self._handle_health()
        elif path == '/status':
            self._handle_status()
        elif path == '/score':
            self._handle_score()
        elif path == '/history':
            self._handle_history()
        else:
            self._send_json({'error': 'not found', 'path': path}, 404)

    def _handle_health(self):
        """Health check endpoint"""
        if _agent_instance and _agent_instance.running.is_set():
            self._send_json({
                'status': 'healthy',
                'service': 'qsecbit-fortress',
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': int(time.time() - _agent_instance.start_time)
            })
        else:
            self._send_json({'status': 'unhealthy', 'reason': 'agent not running'}, 503)

    def _handle_status(self):
        """Full status endpoint with L2-L7 layer detection data"""
        if not _agent_instance:
            self._send_json({'error': 'agent not initialized'}, 503)
            return

        sample = _agent_instance.last_sample
        if sample:
            self._send_json({
                'status': 'operational',
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'threats_detected': sample.threats_detected,
                'suricata_alerts': sample.suricata_alerts,
                'policy_violations': sample.policy_violations,
                'macsec_status': sample.macsec_status,
                'openflow_flows': sample.openflow_flows,
                'layer_scores': sample.layer_scores,
                'recent_threats': sample.recent_threats,
                'xdp_stats': sample.xdp_stats,
                'uptime_seconds': int(time.time() - _agent_instance.start_time)
            })
        else:
            self._send_json({
                'status': 'initializing',
                'uptime_seconds': int(time.time() - _agent_instance.start_time)
            })

    def _handle_score(self):
        """Current score endpoint"""
        if not _agent_instance or not _agent_instance.last_sample:
            self._send_json({'error': 'no data available'}, 503)
            return

        sample = _agent_instance.last_sample
        self._send_json({
            'score': sample.score,
            'rag_status': sample.rag_status,
            'timestamp': sample.timestamp
        })

    def _handle_history(self):
        """Recent history endpoint"""
        if not _agent_instance:
            self._send_json({'error': 'agent not initialized'}, 503)
            return

        # Return last 10 samples
        history = _agent_instance.history[-10:]
        self._send_json({
            'count': len(history),
            'samples': [asdict(s) for s in history]
        })


class QSecBitFortressAgent:
    """Full QSecBit agent for Fortress deployments with L2-L7 threat detection"""

    def __init__(self, config: QSecBitConfig = None):
        self.config = config or QSecBitConfig()
        self.running = Event()
        self.start_time = time.time()
        self.last_sample: Optional[QSecBitSample] = None
        self.history: List[QSecBitSample] = []
        self.all_threats: List[Any] = []  # Accumulated threats

        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Initialize L2-L7 Layer Detectors
        self.layer_detectors = {}
        if LAYER_DETECTORS_AVAILABLE:
            data_dir = str(DATA_DIR / "layer_detectors")
            try:
                self.layer_detectors = {
                    'L2': L2DataLinkDetector(data_dir=data_dir),
                    'L3': L3NetworkDetector(data_dir=data_dir),
                    'L4': L4TransportDetector(data_dir=data_dir),
                    'L5': L5SessionDetector(data_dir=data_dir),
                    'L7': L7ApplicationDetector(data_dir=data_dir),
                }
                logger.info(f"Initialized {len(self.layer_detectors)} L2-L7 layer detectors")
            except Exception as e:
                logger.warning(f"Failed to initialize layer detectors: {e}")
        else:
            logger.warning("Layer detectors not available - running in basic mode")

        # XDP API endpoint
        self.xdp_api_url = os.environ.get('XDP_API_URL', 'http://localhost:9091')

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("QSecBit Fortress Agent v5.2.0 initialized")

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running.clear()

    def get_policy_violations(self) -> int:
        """Check for nftables policy violations (dropped packets)"""
        try:
            # Check nftables counters for dropped packets
            result = subprocess.run(
                ['nft', 'list', 'chain', 'inet', 'fortress', 'forward'],
                capture_output=True, text=True, timeout=5
            )
            # Count dropped packets (policy violations)
            violations = 0
            for line in result.stdout.split('\n'):
                if 'drop' in line and 'packets' in line:
                    # Parse "packets X bytes Y" format
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'packets' and i + 1 < len(parts):
                            violations += int(parts[i + 1])
                            break
            return violations
        except Exception:
            return 0

    def get_macsec_status(self) -> str:
        """Check MACsec status"""
        try:
            result = subprocess.run(
                ['ip', 'macsec', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if 'macsec' in result.stdout:
                return 'active'
            return 'inactive'
        except Exception:
            return 'unknown'

    def get_openflow_stats(self) -> int:
        """Get OpenFlow flow count"""
        try:
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', OVS_BRIDGE],
                capture_output=True, text=True, timeout=5
            )
            return len([l for l in result.stdout.split('\n') if l.strip()])
        except Exception:
            return 0

    def get_suricata_alerts(self) -> int:
        """Get recent Suricata alert count"""
        try:
            alert_file = Path("/var/log/suricata/fast.log")
            if alert_file.exists():
                # Count alerts in last 5 minutes
                count = 0
                with open(alert_file, 'r') as f:
                    for line in f:
                        count += 1
                return min(count, 100)  # Cap at 100
            return 0
        except Exception:
            return 0

    def get_xdp_stats(self) -> Dict[str, int]:
        """Get XDP/eBPF stats from the XDP container"""
        try:
            req = urllib.request.Request(f"{self.xdp_api_url}/stats", method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                return json.loads(response.read().decode())
        except Exception:
            return {}

    def run_layer_detection(self) -> tuple:
        """
        Run all L2-L7 layer detectors and return scores.

        Returns:
            (layer_scores dict, new_threats list, total_threat_count)
        """
        layer_scores = {
            'L2': 0.0,
            'L3': 0.0,
            'L4': 0.0,
            'L5': 0.0,
            'L7': 0.0,
        }
        new_threats = []
        total_count = 0

        if not self.layer_detectors:
            return layer_scores, new_threats, total_count

        for layer_name, detector in self.layer_detectors.items():
            try:
                # Run detection
                threats = detector.detect()

                # Get layer score (0.0-1.0, higher = more threats)
                layer_scores[layer_name] = detector.get_layer_score()

                # Collect new threats
                for threat in threats:
                    total_count += 1
                    new_threats.append({
                        'id': threat.id,
                        'timestamp': threat.timestamp.isoformat(),
                        'attack_type': threat.attack_type.name,
                        'layer': threat.layer.name,
                        'severity': threat.severity.name,
                        'source_ip': threat.source_ip,
                        'description': threat.description,
                        'confidence': threat.confidence,
                        'blocked': threat.blocked,
                    })
                    self.all_threats.append(threat)

            except Exception as e:
                logger.warning(f"Error in {layer_name} detector: {e}")

        # Keep threat history bounded
        if len(self.all_threats) > 1000:
            self.all_threats = self.all_threats[-500:]

        return layer_scores, new_threats, total_count

    def block_ip_via_xdp(self, ip: str) -> bool:
        """Block an IP address via XDP at kernel level"""
        try:
            data = json.dumps({'ip': ip}).encode()
            req = urllib.request.Request(
                f"{self.xdp_api_url}/block",
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode())
                return result.get('status') == 'blocked'
        except Exception as e:
            logger.warning(f"Failed to block IP {ip} via XDP: {e}")
            return False

    def calculate_score(self, layer_scores: Dict[str, float] = None, xdp_stats: Dict = None) -> tuple:
        """Calculate QSecBit score with Fortress enhancements and L2-L7 layer detection"""
        components = {
            'drift': 0.0,
            'network': 0.0,
            'threats': 0.0,  # Now includes L2-L7 layer scores
            'energy': 0.0,
            'infrastructure': 0.0,
            'nftables': 0.0,
            'macsec': 0.0,
            'openflow': 0.0,
            'xdp': 0.0,
        }

        # System drift (CPU, memory usage)
        try:
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
            components['drift'] = max(0, 1.0 - (load / os.cpu_count()))
        except Exception:
            components['drift'] = 0.5

        # Network health
        try:
            result = subprocess.run(['ip', 'link', 'show', 'up'],
                                  capture_output=True, text=True, timeout=5)
            up_interfaces = len([l for l in result.stdout.split('\n') if 'state UP' in l])
            components['network'] = min(1.0, up_interfaces / 4)
        except Exception:
            components['network'] = 0.5

        # L2-L7 Threat detection (primary threat scoring)
        if layer_scores:
            # Calculate weighted layer score (invert: higher threat = lower health)
            layer_threat_score = (
                self.config.l2_weight * layer_scores.get('L2', 0.0) +
                self.config.l3_weight * layer_scores.get('L3', 0.0) +
                self.config.l4_weight * layer_scores.get('L4', 0.0) +
                self.config.l5_weight * layer_scores.get('L5', 0.0) +
                self.config.l7_weight * layer_scores.get('L7', 0.0)
            )
            # Invert: 0.0 threats = 1.0 health
            components['threats'] = max(0, 1.0 - layer_threat_score)
        else:
            # Fallback to Suricata alerts only
            alerts = self.get_suricata_alerts()
            components['threats'] = max(0, 1.0 - (alerts / 50))

        # Energy efficiency (simplified)
        components['energy'] = 0.8

        # Infrastructure health
        try:
            result = subprocess.run(['podman', 'ps', '-q'],
                                  capture_output=True, text=True, timeout=5)
            containers = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            components['infrastructure'] = min(1.0, containers / 5)
        except Exception:
            components['infrastructure'] = 0.5

        # nftables policy enforcement
        violations = self.get_policy_violations()
        components['nftables'] = max(0, 1.0 - (violations / 100))

        # MACsec status
        macsec = self.get_macsec_status()
        components['macsec'] = 1.0 if macsec == 'active' else 0.5 if macsec == 'inactive' else 0.3

        # OpenFlow health
        flows = self.get_openflow_stats()
        components['openflow'] = min(1.0, flows / 20) if flows > 0 else 0.5

        # XDP protection health (based on drop rate)
        if xdp_stats:
            total = xdp_stats.get('total_packets', 0)
            passed = xdp_stats.get('passed', 0)
            if total > 0:
                # Good if most packets pass (low attack rate)
                components['xdp'] = min(1.0, passed / total)
            else:
                components['xdp'] = 1.0  # No traffic = healthy
        else:
            components['xdp'] = 0.5  # Unknown

        # Calculate weighted score
        score = (
            self.config.alpha * components['drift'] +
            self.config.beta * components['network'] +
            self.config.gamma * components['threats'] +
            self.config.delta * components['energy'] +
            self.config.epsilon * components['infrastructure'] +
            self.config.nftables_weight * components['nftables'] +
            self.config.macsec_weight * components['macsec'] +
            self.config.openflow_weight * components['openflow'] +
            self.config.xdp_weight * components['xdp']
        )

        # Determine RAG status
        if score >= self.config.amber_threshold:
            rag_status = "GREEN"
        elif score >= self.config.red_threshold:
            rag_status = "AMBER"
        else:
            rag_status = "RED"

        return score, rag_status, components

    def collect_sample(self) -> QSecBitSample:
        """Collect a complete QSecBit sample with L2-L7 layer detection"""
        # Run L2-L7 layer detection
        layer_scores, new_threats, threat_count = self.run_layer_detection()

        # Get XDP stats
        xdp_stats = self.get_xdp_stats()

        # Calculate score with layer data
        score, rag_status, components = self.calculate_score(layer_scores, xdp_stats)

        sample = QSecBitSample(
            timestamp=datetime.now().isoformat(),
            score=score,
            rag_status=rag_status,
            components=components,
            threats_detected=threat_count,
            suricata_alerts=self.get_suricata_alerts(),
            policy_violations=self.get_policy_violations(),
            macsec_status=self.get_macsec_status(),
            openflow_flows=self.get_openflow_stats(),
            layer_scores=layer_scores,
            recent_threats=new_threats[-10:],  # Keep last 10
            xdp_stats=xdp_stats,
        )

        self.last_sample = sample
        self.history.append(sample)
        if len(self.history) > 1000:
            self.history = self.history[-500:]

        return sample

    def save_stats(self, sample: QSecBitSample):
        """Save stats to file"""
        try:
            stats = {
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'threats_detected': sample.threats_detected,
                'suricata_alerts': sample.suricata_alerts,
                'policy_violations': sample.policy_violations,
                'macsec_status': sample.macsec_status,
                'openflow_flows': sample.openflow_flows,
                'layer_scores': sample.layer_scores,
                'recent_threats': sample.recent_threats,
                'xdp_stats': sample.xdp_stats,
                'uptime_seconds': int(time.time() - self.start_time)
            }
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def _get_lte_signal(self, iface_name: str) -> Optional[float]:
        """Get LTE signal strength in dBm using mmcli or other methods."""
        signal_dbm = None

        # Try mmcli first (ModemManager)
        try:
            # List modems
            result = subprocess.run(
                ['mmcli', '-L'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and '/Modem/' in result.stdout:
                # Extract modem number
                import re
                match = re.search(r'/Modem/(\d+)', result.stdout)
                if match:
                    modem_num = match.group(1)
                    # Get signal quality
                    result = subprocess.run(
                        ['mmcli', '-m', modem_num, '--signal-get'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        # Parse RSSI from output
                        for line in result.stdout.split('\n'):
                            if 'rssi' in line.lower():
                                match = re.search(r'(-?\d+\.?\d*)\s*dBm', line)
                                if match:
                                    signal_dbm = float(match.group(1))
                                    break
        except Exception:
            pass

        # Fallback: try qmicli for Qualcomm modems
        if signal_dbm is None:
            try:
                result = subprocess.run(
                    ['qmicli', '-d', f'/dev/cdc-{iface_name}', '--nas-get-signal-strength'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    import re
                    match = re.search(r'Network.*:\s*\'(-?\d+)\s*dBm\'', result.stdout)
                    if match:
                        signal_dbm = float(match.group(1))
            except Exception:
                pass

        return signal_dbm

    def collect_wan_health(self) -> Dict:
        """Collect WAN health data for SLAAI dashboard.

        This runs with host network access, so we can ping through real interfaces.
        Data is written to wan_health.json for the web container to read.
        """
        import re

        def test_connectivity(interface: str, source_ip: str = None, target: str = '1.1.1.1') -> Dict:
            """Test connectivity through a specific interface.

            Uses multiple methods in order of reliability:
            1. Socket-based TCP connect (most reliable, works with policy routing)
            2. ICMP ping via subprocess
            3. HTTP-based fallback for LTE interfaces

            For LTE/wwan interfaces, uses SO_BINDTODEVICE to force traffic through the interface.
            """
            import socket

            result = {
                'rtt_ms': None,
                'jitter_ms': None,
                'packet_loss': 100.0,
                'is_connected': False,
            }

            is_lte = interface.startswith(('wwan', 'usb', 'wwp'))
            src_ip = source_ip.split('/')[0] if source_ip and source_ip != 'dynamic' else None

            # Get source IP from interface if not provided
            if not src_ip:
                try:
                    result_cmd = subprocess.run(
                        ['ip', '-j', 'addr', 'show', interface],
                        capture_output=True, text=True, timeout=5
                    )
                    if result_cmd.returncode == 0:
                        iface_data = json.loads(result_cmd.stdout)
                        if iface_data:
                            for addr in iface_data[0].get('addr_info', []):
                                if addr.get('family') == 'inet':
                                    src_ip = addr.get('local')
                                    logger.debug(f"Got source IP {src_ip} from interface {interface}")
                                    break
                except Exception as e:
                    logger.debug(f"Could not get IP from interface {interface}: {e}")

            # Method 1: Socket-based TCP connect test (most reliable)
            # This works even with policy routing because we bind to the device
            tcp_targets = [
                ('1.1.1.1', 80),      # Cloudflare HTTP
                ('1.1.1.1', 443),     # Cloudflare HTTPS
                ('8.8.8.8', 53),      # Google DNS
            ]

            for target_ip, target_port in tcp_targets:
                rtt_samples = []
                success_count = 0
                attempts = 3

                for _ in range(attempts):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3.0)

                        # Bind to interface using SO_BINDTODEVICE (requires CAP_NET_RAW)
                        try:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
                        except (OSError, PermissionError) as e:
                            # Fallback: bind to source IP if SO_BINDTODEVICE fails
                            if src_ip:
                                sock.bind((src_ip, 0))
                            else:
                                logger.debug(f"SO_BINDTODEVICE failed and no source IP: {e}")
                                sock.close()
                                continue

                        start = time.time()
                        sock.connect((target_ip, target_port))
                        elapsed = (time.time() - start) * 1000  # ms
                        sock.close()

                        rtt_samples.append(elapsed)
                        success_count += 1

                    except socket.timeout:
                        logger.debug(f"TCP connect timeout to {target_ip}:{target_port} via {interface}")
                    except OSError as e:
                        logger.debug(f"TCP connect error to {target_ip}:{target_port} via {interface}: {e}")
                    except Exception as e:
                        logger.debug(f"TCP test exception: {e}")

                if success_count > 0:
                    result['is_connected'] = True
                    result['rtt_ms'] = sum(rtt_samples) / len(rtt_samples)
                    # Calculate jitter as standard deviation
                    if len(rtt_samples) > 1:
                        mean = result['rtt_ms']
                        variance = sum((x - mean) ** 2 for x in rtt_samples) / len(rtt_samples)
                        result['jitter_ms'] = variance ** 0.5
                    else:
                        result['jitter_ms'] = 0.0
                    result['packet_loss'] = ((attempts - success_count) / attempts) * 100
                    logger.info(f"TCP connectivity OK for {interface}: RTT={result['rtt_ms']:.1f}ms, loss={result['packet_loss']:.0f}%")
                    return result

            # Method 2: ICMP ping with subprocess
            ping_commands = []

            if src_ip:
                # Try source IP first (works with policy routing)
                ping_commands.append(['ping', '-c', '3', '-W', '2', '-I', src_ip, '1.1.1.1'])
            # Also try interface name
            ping_commands.append(['ping', '-c', '3', '-W', '2', '-I', interface, '1.1.1.1'])

            proc = None
            for ping_cmd in ping_commands:
                try:
                    logger.debug(f"Testing connectivity: {' '.join(ping_cmd)}")
                    proc = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=12)

                    if proc.returncode != 0:
                        logger.debug(f"Ping failed on {interface}: rc={proc.returncode}, stderr={proc.stderr.strip()}")
                        continue

                    # Parse RTT
                    rtt_match = re.search(
                        r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
                        proc.stdout
                    )
                    if rtt_match:
                        result['rtt_ms'] = float(rtt_match.group(2))
                        result['jitter_ms'] = float(rtt_match.group(4))
                        result['is_connected'] = True

                    # Parse packet loss
                    loss_match = re.search(r'(\d+)% packet loss', proc.stdout)
                    if loss_match:
                        result['packet_loss'] = float(loss_match.group(1))

                    if result['is_connected']:
                        logger.info(f"Ping connectivity OK for {interface}: RTT={result['rtt_ms']:.1f}ms")
                        return result

                except subprocess.TimeoutExpired:
                    logger.debug(f"Ping timeout on {interface}")
                except Exception as e:
                    logger.debug(f"Ping error on {interface}: {e}")

            # Method 3: HTTP-based test for LTE (fallback)
            if not result['is_connected']:
                try:
                    logger.debug(f"Trying HTTP test for {interface}")
                    start = time.time()
                    http_result = subprocess.run(
                        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                         '--interface', interface, '--connect-timeout', '5',
                         '--max-time', '8', 'http://1.1.1.1'],
                        capture_output=True, text=True, timeout=12
                    )
                    elapsed = (time.time() - start) * 1000

                    if http_result.returncode == 0 and http_result.stdout.strip() in ['200', '301', '302']:
                        logger.info(f"HTTP fallback succeeded for {interface} in {elapsed:.0f}ms")
                        result['is_connected'] = True
                        result['rtt_ms'] = elapsed
                        result['jitter_ms'] = 0
                        result['packet_loss'] = 0
                except Exception as e:
                    logger.debug(f"HTTP fallback failed for {interface}: {e}")

            return result

        def calculate_health_score(conn: Dict, signal_dbm: int = None) -> float:
            """Calculate health score 0-1 based on connectivity metrics."""
            if not conn['is_connected']:
                return 0.0
            score = 1.0
            if conn['rtt_ms']:
                if conn['rtt_ms'] > 200:
                    score -= 0.3
                elif conn['rtt_ms'] > 100:
                    score -= 0.2
                elif conn['rtt_ms'] > 50:
                    score -= 0.1
            if conn['jitter_ms']:
                if conn['jitter_ms'] > 50:
                    score -= 0.2
                elif conn['jitter_ms'] > 20:
                    score -= 0.1
            if conn['packet_loss'] > 0:
                score -= min(0.4, conn['packet_loss'] / 100 * 0.4)
            if signal_dbm is not None:
                if signal_dbm < -100:
                    score -= 0.2
                elif signal_dbm < -85:
                    score -= 0.1
            return max(0.0, min(1.0, score))

        health = {
            'primary': None,
            'backup': None,
            'active': None,
            'active_is_primary': False,
            'uptime_pct': 99.9,
            'state': 'disconnected',
            'timestamp': datetime.now().isoformat(),
        }

        # Get interfaces
        try:
            proc = subprocess.run(
                ['ip', '-j', 'addr', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if proc.returncode == 0:
                interfaces = json.loads(proc.stdout)
            else:
                interfaces = []
        except Exception:
            interfaces = []

        primary_iface = None
        backup_iface = None

        # Collect all potential WAN interfaces
        wan_candidates = []
        lte_candidates = []

        # Interfaces to exclude (bridges, containers, internal)
        exclude_prefixes = ('lo', 'docker', 'podman', 'veth', 'br-', 'virbr', 'FTS', 'vlan')
        exclude_names = {'lo', 'FTS', 'br0', 'br-lan'}

        # Get interfaces that are part of OVS bridge (these are LAN ports, not WAN)
        ovs_bridge_ports = set()
        try:
            result = subprocess.run(
                ['ovs-vsctl', 'list-ports', 'FTS'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ovs_bridge_ports = set(p.strip() for p in result.stdout.strip().split('\n') if p.strip())
                logger.debug(f"OVS bridge ports (LAN): {ovs_bridge_ports}")
        except Exception:
            pass

        # Get interface with default route (this is the real WAN)
        # Parse multiple route formats:
        # - "default via 192.168.1.1 dev eth0"
        # - "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        # - "default dev wwan0 proto static" (point-to-point, no gateway)
        # - "default dev wwan0 scope link" (direct link)
        wan_interface_from_route = None
        default_routes = []  # Track all default routes with metrics
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    # Extract device name - handles both "via X dev Y" and "dev Y" formats
                    dev_match = re.search(r'\bdev\s+(\S+)', line)
                    if dev_match:
                        dev_name = dev_match.group(1)
                        # Extract metric if present (lower = preferred)
                        metric_match = re.search(r'\bmetric\s+(\d+)', line)
                        metric = int(metric_match.group(1)) if metric_match else 0
                        default_routes.append((metric, dev_name, line))
                        logger.debug(f"Found default route: dev={dev_name} metric={metric}")

                # Sort by metric (lowest first) and take primary WAN
                if default_routes:
                    default_routes.sort(key=lambda x: x[0])
                    wan_interface_from_route = default_routes[0][1]
                    logger.info(f"WAN interface from default route: {wan_interface_from_route} (metric={default_routes[0][0]})")
        except Exception as e:
            logger.debug(f"Failed to get default route: {e}")

        for iface in interfaces:
            name = iface.get('ifname', '')
            state = iface.get('operstate', 'UNKNOWN')

            # Check if this is an LTE interface (check early for special handling)
            is_lte = name.startswith(('wwan', 'usb', 'wwp'))

            # Skip down interfaces, but be lenient with LTE (may show as UNKNOWN)
            if state not in ['UP', 'UNKNOWN'] and not is_lte:
                continue

            # For LTE, also check if interface exists in /sys/class/net (means it's active)
            if is_lte and state not in ['UP', 'UNKNOWN']:
                if not Path(f'/sys/class/net/{name}').exists():
                    continue

            # Skip excluded interfaces
            if name in exclude_names:
                continue
            if any(name.startswith(prefix) for prefix in exclude_prefixes):
                continue

            # Get IP address
            ip_addr = None
            for addr_info in iface.get('addr_info', []):
                if addr_info.get('family') == 'inet':
                    ip_addr = f"{addr_info.get('local')}/{addr_info.get('prefixlen')}"
                    break

            # For LTE interfaces, try to get IP from nmcli if not in addr_info
            if is_lte and not ip_addr:
                try:
                    # Try nmcli to get connection info
                    result = subprocess.run(
                        ['nmcli', '-g', 'IP4.ADDRESS', 'device', 'show', name],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        ip_addr = result.stdout.strip().split()[0]
                except Exception:
                    pass

                # Also try ip route to find if interface has routes
                if not ip_addr:
                    try:
                        result = subprocess.run(
                            ['ip', 'route', 'show', 'dev', name],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            # Interface has routes, mark as having dynamic IP
                            ip_addr = 'dynamic'
                    except Exception:
                        pass

            # Skip ethernet interfaces without IP, but allow LTE interfaces
            # (LTE may have dynamic IP or be a point-to-point link)
            if not ip_addr and not is_lte:
                continue

            # For LTE, check if it actually exists and has carrier
            if is_lte:
                carrier_file = Path(f'/sys/class/net/{name}/carrier')
                if carrier_file.exists():
                    try:
                        carrier = carrier_file.read_text().strip()
                        if carrier != '1':
                            logger.debug(f"LTE interface {name} has no carrier, skipping")
                            continue
                    except Exception:
                        pass  # Some interfaces don't support carrier check

            # Categorize interface
            iface_info = {'name': name, 'ip': ip_addr or 'dynamic', 'state': state}

            if is_lte:
                # LTE/cellular interfaces
                lte_candidates.append(iface_info)
                logger.debug(f"Found LTE candidate: {name} ip={ip_addr} state={state}")
            elif name.startswith('eth') or name.startswith('en') or name.startswith('eno'):
                # Ethernet interface - check if it's WAN or LAN
                # Skip if it's part of OVS bridge (LAN port)
                if name in ovs_bridge_ports:
                    logger.debug(f"Skipping {name} - is OVS bridge port (LAN)")
                    continue

                # Only add as WAN candidate if:
                # 1. It has the default route, OR
                # 2. No default route detected yet (fallback)
                if wan_interface_from_route:
                    if name == wan_interface_from_route:
                        wan_candidates.append(iface_info)
                        logger.debug(f"Found WAN candidate (default route): {name}")
                else:
                    # No default route detected, use first non-bridge ethernet
                    wan_candidates.append(iface_info)
                    logger.debug(f"Found WAN candidate (fallback): {name}")

        # Sort WAN candidates by name for consistent ordering (eth0 before eth1)
        wan_candidates.sort(key=lambda x: x['name'])

        # Log detected interfaces for debugging
        logger.info(f"WAN candidates: {[c['name'] for c in wan_candidates]}, LTE candidates: {[c['name'] for c in lte_candidates]}")

        # Assign primary and backup
        # Priority for primary: First ethernet with IP
        # Priority for backup: LTE preferred (for failover), then second ethernet
        if len(wan_candidates) >= 1:
            primary_iface = wan_candidates[0]

        # Prefer LTE as backup (typical failover scenario: ethernet primary, LTE backup)
        if lte_candidates:
            backup_iface = lte_candidates[0]
            logger.info(f"Using LTE as backup: {backup_iface['name']}")
        elif len(wan_candidates) >= 2:
            # Fall back to second ethernet if no LTE
            backup_iface = wan_candidates[1]
            logger.info(f"Using second ethernet as backup: {backup_iface['name']}")

        # Log final selection
        logger.info(f"WAN selection: primary={primary_iface['name'] if primary_iface else None}, backup={backup_iface['name'] if backup_iface else None}")

        # Test primary WAN
        if primary_iface:
            conn = test_connectivity(primary_iface['name'], primary_iface['ip'])
            health['primary'] = {
                'interface': primary_iface['name'],
                'ip': primary_iface['ip'],
                'state': 'UP',
                'rtt_ms': conn['rtt_ms'],
                'jitter_ms': conn['jitter_ms'],
                'packet_loss': conn['packet_loss'],
                'is_connected': conn['is_connected'],
                'health_score': calculate_health_score(conn),
                'status': 'ACTIVE' if conn['is_connected'] else 'FAILED',
            }
            if conn['is_connected']:
                health['active'] = primary_iface['name']
                health['active_is_primary'] = True
                health['state'] = 'primary_active'

        # Test backup WAN (could be second ethernet or LTE)
        if backup_iface:
            conn = test_connectivity(backup_iface['name'], backup_iface['ip'])

            # Detect if this is an LTE interface
            is_lte = backup_iface['name'].startswith(('wwan', 'usb', 'wwp'))

            # Try to get LTE signal strength
            signal_dbm = None
            if is_lte:
                signal_dbm = self._get_lte_signal(backup_iface['name'])

            health['backup'] = {
                'interface': backup_iface['name'],
                'ip': backup_iface['ip'],
                'state': 'UP',
                'rtt_ms': conn['rtt_ms'],
                'jitter_ms': conn['jitter_ms'],
                'packet_loss': conn['packet_loss'],
                'is_connected': conn['is_connected'],
                'health_score': calculate_health_score(conn, signal_dbm),
                'signal_dbm': signal_dbm,
                'is_lte': is_lte,
                'status': 'STANDBY' if health['active'] else ('ACTIVE' if conn['is_connected'] else 'FAILED'),
            }
            if not health['active'] and conn['is_connected']:
                health['active'] = backup_iface['name']
                health['active_is_primary'] = False
                health['state'] = 'backup_active'
                health['backup']['status'] = 'ACTIVE'

        return health

    def save_wan_health(self):
        """Collect and save WAN health data for SLAAI dashboard.

        Merges data from:
        1. Live ping connectivity tests (collect_wan_health)
        2. PBR failover state file (/run/fortress/wan-failover.state)
        3. PBR JSON state file (/var/lib/fortress/wan-failover-state.json)
        """
        try:
            health = self.collect_wan_health()

            # Try to read PBR state for additional info (route switching status)
            pbr_state = self._read_pbr_state()
            if pbr_state:
                # Merge PBR status info
                health['pbr'] = pbr_state

                # Override active WAN if PBR has definitive info
                if pbr_state.get('active_wan'):
                    if pbr_state['active_wan'] != health.get('active'):
                        logger.debug(f"PBR override: active WAN {pbr_state['active_wan']} vs ping {health.get('active')}")
                        health['active'] = pbr_state['active_wan']
                        health['active_is_primary'] = pbr_state.get('primary_status') == 'ACTIVE'

                # Use PBR status if our ping tests failed but PBR says link is up
                if health.get('primary') and not health['primary'].get('is_connected'):
                    if pbr_state.get('primary_status') == 'ACTIVE':
                        health['primary']['status'] = 'ACTIVE'
                        health['primary']['health_score'] = max(0.5, health['primary'].get('health_score', 0))

                if health.get('backup') and not health['backup'].get('is_connected'):
                    if pbr_state.get('backup_status') == 'ACTIVE':
                        health['backup']['status'] = 'ACTIVE'
                        health['backup']['health_score'] = max(0.5, health['backup'].get('health_score', 0))

            wan_file = DATA_DIR / "wan_health.json"
            with open(wan_file, 'w') as f:
                json.dump(health, f, indent=2)
            logger.debug(f"WAN health saved: state={health['state']}, active={health.get('active')}")
        except Exception as e:
            logger.warning(f"Failed to save WAN health: {e}")

    def _read_pbr_state(self) -> Dict:
        """Read PBR (Policy-Based Routing) failover state.

        Returns info about which WAN is currently active according to PBR.
        """
        state = {}

        # Try shell format state file first (more frequently updated)
        shell_state_file = Path('/run/fortress/wan-failover.state')
        if shell_state_file.exists():
            try:
                content = shell_state_file.read_text()
                for line in content.strip().split('\n'):
                    if '=' in line:
                        key, _, value = line.partition('=')
                        key = key.strip().lower()
                        value = value.strip().strip('"\'')
                        if key == 'primary_status':
                            state['primary_status'] = value
                        elif key == 'backup_status':
                            state['backup_status'] = value
                        elif key == 'active_wan':
                            state['active_wan'] = value
                        elif key == 'primary_interface':
                            state['primary_interface'] = value
                        elif key == 'backup_interface':
                            state['backup_interface'] = value
                        elif key == 'failover_count':
                            state['failover_count'] = int(value) if value.isdigit() else 0
                state['source'] = 'shell'
                return state
            except Exception as e:
                logger.debug(f"Failed to read PBR shell state: {e}")

        # Try JSON format state file
        json_state_file = Path('/var/lib/fortress/wan-failover-state.json')
        if json_state_file.exists():
            try:
                data = json.loads(json_state_file.read_text())
                state = {
                    'primary_status': data.get('primary', {}).get('status', 'UNKNOWN'),
                    'backup_status': data.get('backup', {}).get('status', 'UNKNOWN'),
                    'active_wan': data.get('active_interface'),
                    'primary_interface': data.get('primary', {}).get('interface'),
                    'backup_interface': data.get('backup', {}).get('interface'),
                    'failover_count': data.get('failover_count', 0),
                    'source': 'json',
                }
                return state
            except Exception as e:
                logger.debug(f"Failed to read PBR JSON state: {e}")

        return {}

    def collect_interface_traffic(self) -> List[Dict]:
        """Collect interface traffic statistics for all relevant interfaces.

        This runs with host network access, so we can read /sys/class/net stats.
        Data is written to interface_traffic.json for the web container to read.
        """
        import re

        # Get interfaces
        try:
            proc = subprocess.run(
                ['ip', '-j', 'addr', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if proc.returncode == 0:
                interfaces = json.loads(proc.stdout)
            else:
                interfaces = []
        except Exception:
            interfaces = []

        # Get OVS bridge ports (these are LAN, not WAN)
        ovs_bridge_ports = set()
        try:
            result = subprocess.run(
                ['ovs-vsctl', 'list-ports', 'FTS'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ovs_bridge_ports = set(p.strip() for p in result.stdout.strip().split('\n') if p.strip())
        except Exception:
            pass

        # Get interface with default route (this is the WAN)
        # Parse multiple route formats:
        # - "default via 192.168.1.1 dev eth0"
        # - "default dev wwan0" (point-to-point, no gateway)
        wan_interface = None
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                # Find all default routes with metrics
                default_routes = []
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    dev_match = re.search(r'\bdev\s+(\S+)', line)
                    if dev_match:
                        metric_match = re.search(r'\bmetric\s+(\d+)', line)
                        metric = int(metric_match.group(1)) if metric_match else 0
                        default_routes.append((metric, dev_match.group(1)))
                # Sort by metric and take lowest
                if default_routes:
                    default_routes.sort(key=lambda x: x[0])
                    wan_interface = default_routes[0][1]
                    logger.debug(f"WAN interface from default route: {wan_interface}")
        except Exception as e:
            logger.debug(f"Failed to get default route for traffic: {e}")

        traffic = []
        now = time.time()

        # Only include relevant interface types
        for iface in interfaces:
            name = iface.get('ifname', '')
            state = iface.get('operstate', 'UNKNOWN')

            # Skip interfaces without IP (except WiFi which might be AP mode)
            has_ip = False
            for addr_info in iface.get('addr_info', []):
                if addr_info.get('family') == 'inet':
                    has_ip = True
                    break

            # Determine interface type
            iface_type = None
            if name.startswith('eth') or name.startswith('en') or name.startswith('eno'):
                # Check if it's actually WAN or LAN
                if name in ovs_bridge_ports:
                    iface_type = 'lan'  # Part of OVS bridge = LAN
                elif wan_interface and name == wan_interface:
                    iface_type = 'wan'  # Has default route = WAN
                elif not wan_interface and name not in ovs_bridge_ports and has_ip:
                    iface_type = 'wan'  # Fallback: non-bridge with IP = WAN
                else:
                    continue  # Skip unknown ethernet without IP
            elif name.startswith('wwan') or name.startswith('usb') or name.startswith('wwp'):
                iface_type = 'lte'
            elif name in ['FTS', 'br0', 'br-lan']:
                iface_type = 'bridge'
            elif name.startswith('wlan') or name.startswith('wl'):
                iface_type = 'wifi'
            elif name.startswith('vlan'):
                iface_type = 'vlan'

            if not iface_type:
                continue

            # Filter: only show interfaces that are UP and have IP (except LTE/WiFi)
            if state not in ['UP', 'UNKNOWN']:
                continue
            if not has_ip and iface_type not in ['lte', 'wifi']:
                continue

            # Read stats from /sys/class/net
            stats_path = Path(f'/sys/class/net/{name}/statistics')
            if not stats_path.exists():
                continue

            try:
                rx_bytes = int((stats_path / 'rx_bytes').read_text().strip())
                tx_bytes = int((stats_path / 'tx_bytes').read_text().strip())
            except Exception:
                continue

            # Calculate rate using stored previous values
            cache_key = f'traffic_{name}'
            prev = getattr(self, '_traffic_cache', {}).get(cache_key)
            rx_bps = 0
            tx_bps = 0

            if prev:
                prev_rx, prev_tx, prev_time = prev
                elapsed = now - prev_time
                if elapsed > 0:
                    rx_bps = max(0, int((rx_bytes - prev_rx) / elapsed))
                    tx_bps = max(0, int((tx_bytes - prev_tx) / elapsed))

            # Store current values for next calculation
            if not hasattr(self, '_traffic_cache'):
                self._traffic_cache = {}
            self._traffic_cache[cache_key] = (rx_bytes, tx_bytes, now)

            traffic.append({
                'interface': name,
                'type': iface_type,
                'state': state,
                'rx_bytes': rx_bytes,
                'tx_bytes': tx_bytes,
                'rx_bps': rx_bps,
                'tx_bps': tx_bps,
                'rx_mbps': round(rx_bps * 8 / 1_000_000, 2),
                'tx_mbps': round(tx_bps * 8 / 1_000_000, 2),
                'total_mbps': round((rx_bps + tx_bps) * 8 / 1_000_000, 2),
            })

        return traffic

    def save_interface_traffic(self):
        """Collect and save interface traffic data for SLAAI dashboard."""
        try:
            traffic = self.collect_interface_traffic()
            traffic_file = DATA_DIR / "interface_traffic.json"
            with open(traffic_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'interfaces': traffic
                }, f, indent=2)
            logger.debug(f"Interface traffic saved: {len(traffic)} interfaces")
        except Exception as e:
            logger.warning(f"Failed to save interface traffic: {e}")

    def collect_devices(self) -> List[Dict]:
        """Collect connected devices from ARP neighbor table with enrichment.

        Enriches each device with:
        - Manufacturer from OUI database
        - Hostname from reverse DNS lookup
        - Device type based on manufacturer and hostname

        Filters out:
        - Internal container network devices (podman, docker, veth)
        - OVS internal interfaces (FTS, FTS-mirror)
        - IPv6 link-local addresses (fe80::)
        """
        devices = []

        # Interfaces to exclude (internal/container networks)
        exclude_interface_prefixes = (
            'podman', 'docker', 'veth', 'cni', 'br-',  # Container networks
            'FTS',  # OVS bridge and mirrors
            'lo',   # Loopback
        )

        # IP prefixes to exclude (container networks, link-local)
        exclude_ip_prefixes = (
            '172.20.200.',  # Container network (fts-internal)
            '172.17.',      # Docker default
            '172.18.',      # Docker networks
            '172.19.',      # Docker networks
            'fe80:',        # IPv6 link-local
            '::1',          # IPv6 loopback
        )

        try:
            proc = subprocess.run(
                ['ip', '-j', 'neigh', 'show'],
                capture_output=True, text=True, timeout=10
            )
            if proc.returncode == 0 and proc.stdout.strip():
                neighbors = json.loads(proc.stdout)
                for n in neighbors:
                    state = n.get('state', ['UNKNOWN'])
                    if isinstance(state, list):
                        state = state[0] if state else 'UNKNOWN'
                    if state in ['FAILED', 'INCOMPLETE']:
                        continue

                    ip_addr = n.get('dst', '')
                    mac = n.get('lladdr', '')
                    interface = n.get('dev', '')

                    if not mac:
                        continue

                    # Filter out internal interfaces
                    if any(interface.startswith(prefix) for prefix in exclude_interface_prefixes):
                        logger.debug(f"Skipping device on internal interface: {interface}")
                        continue

                    # Filter out internal IP ranges
                    if any(ip_addr.startswith(prefix) for prefix in exclude_ip_prefixes):
                        logger.debug(f"Skipping device with internal IP: {ip_addr}")
                        continue

                    mac = mac.upper()

                    # Enrich device data
                    manufacturer = lookup_manufacturer(mac)
                    hostname = resolve_hostname(ip_addr, mac)  # Pass MAC for DHCP lookup
                    device_type = detect_device_type(mac, hostname, manufacturer)

                    devices.append({
                        'ip_address': ip_addr,
                        'mac_address': mac,
                        'state': state,
                        'device_type': device_type,
                        'hostname': hostname,
                        'manufacturer': manufacturer,
                        'interface': interface,
                        'last_seen': datetime.now().isoformat(),
                    })
        except Exception as e:
            logger.debug(f"Failed to collect devices: {e}")

        logger.debug(f"Collected {len(devices)} devices with enrichment")
        return devices

    def collect_wifi_status(self) -> Dict:
        """Collect WiFi status from hostapd config and runtime status.

        This runs with host network access, so we can read hostapd configs
        and run hostapd_cli to get live data.
        Data is written to wifi_status.json for the web container to read.
        """
        import re

        status = {
            'timestamp': datetime.now().isoformat(),
            'interfaces': [],
            'primary_ssid': None,
            'primary_channel': None,
            'primary_band': None,
        }

        # Try multiple hostapd config locations
        hostapd_configs = [
            '/etc/hostapd/fortress.conf',
            '/etc/hostapd/hostapd.conf',
            '/etc/hostapd/fts-24ghz.conf',
            '/etc/hostapd/fts-5ghz.conf',
            '/etc/hostapd/fortress-5ghz.conf',
        ]

        # Also check if there's a directory with multiple configs
        hostapd_dir = Path('/etc/hostapd')
        if hostapd_dir.exists():
            for conf in hostapd_dir.glob('*.conf'):
                if str(conf) not in hostapd_configs:
                    hostapd_configs.append(str(conf))

        for config_path in hostapd_configs:
            if not Path(config_path).exists():
                continue

            try:
                iface_info = {
                    'config_file': config_path,
                    'interface': None,
                    'ssid': None,
                    'channel': None,
                    'hw_mode': None,
                    'band': None,
                    'clients': 0,
                    'state': 'unknown',
                }

                with open(config_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('#') or '=' not in line:
                            continue
                        key, _, value = line.partition('=')
                        key = key.strip()
                        value = value.strip()

                        if key == 'interface':
                            iface_info['interface'] = value
                        elif key == 'ssid':
                            iface_info['ssid'] = value
                        elif key == 'channel':
                            try:
                                iface_info['channel'] = int(value)
                            except ValueError:
                                pass
                        elif key == 'hw_mode':
                            iface_info['hw_mode'] = value

                # Determine band from hw_mode or channel
                if iface_info['hw_mode'] == 'a':
                    iface_info['band'] = '5GHz'
                elif iface_info['hw_mode'] in ['g', 'b']:
                    iface_info['band'] = '2.4GHz'
                elif iface_info['channel']:
                    iface_info['band'] = '5GHz' if iface_info['channel'] > 14 else '2.4GHz'

                # Try to get live status from hostapd_cli
                if iface_info['interface']:
                    try:
                        result = subprocess.run(
                            ['hostapd_cli', '-i', iface_info['interface'], 'status'],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            iface_info['state'] = 'running'
                            for line in result.stdout.split('\n'):
                                if line.startswith('channel='):
                                    try:
                                        iface_info['channel'] = int(line.split('=')[1])
                                    except ValueError:
                                        pass
                                elif line.startswith('ssid='):
                                    iface_info['ssid'] = line.split('=')[1]
                        else:
                            iface_info['state'] = 'stopped'
                    except Exception:
                        pass

                    # Count connected clients
                    try:
                        result = subprocess.run(
                            ['hostapd_cli', '-i', iface_info['interface'], 'all_sta'],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            # Count MAC addresses (lines matching MAC pattern)
                            mac_count = 0
                            for line in result.stdout.split('\n'):
                                if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', line.strip()):
                                    mac_count += 1
                            iface_info['clients'] = mac_count
                    except Exception:
                        pass

                # Only add if we got meaningful data
                if iface_info['ssid'] or iface_info['interface']:
                    status['interfaces'].append(iface_info)

                    # Set primary (5GHz preferred, or first found)
                    if status['primary_ssid'] is None or iface_info['band'] == '5GHz':
                        status['primary_ssid'] = iface_info['ssid']
                        status['primary_channel'] = iface_info['channel']
                        status['primary_band'] = iface_info['band']

            except Exception as e:
                logger.debug(f"Failed to read hostapd config {config_path}: {e}")

        return status

    def save_wifi_status(self):
        """Collect and save WiFi status for SDN dashboard."""
        try:
            wifi_status = self.collect_wifi_status()
            wifi_file = DATA_DIR / "wifi_status.json"
            with open(wifi_file, 'w') as f:
                json.dump(wifi_status, f, indent=2)
            if wifi_status['primary_ssid']:
                logger.debug(f"WiFi status saved: SSID={wifi_status['primary_ssid']} channel={wifi_status['primary_channel']}")
            else:
                logger.debug("WiFi status saved: no hostapd configs found")
        except Exception as e:
            logger.warning(f"Failed to save WiFi status: {e}")

    def save_devices(self):
        """Collect and save device list for clients page."""
        try:
            devices = self.collect_devices()
            devices_file = DATA_DIR / "devices.json"
            # Wrap in dict with timestamp for age validation
            data = {
                'timestamp': datetime.now().isoformat(),
                'devices': devices,
                'count': len(devices),
            }
            with open(devices_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Devices saved: {len(devices)} devices")
        except Exception as e:
            logger.warning(f"Failed to save devices: {e}")

    def run_monitoring_loop(self):
        """Main monitoring loop with L2-L7 threat detection"""
        logger.info("Starting QSecBit monitoring loop with L2-L7 detection...")
        interval = 10
        wan_health_counter = 0
        traffic_counter = 0
        device_counter = 0
        wifi_counter = 0

        while self.running.is_set():
            try:
                sample = self.collect_sample()
                self.save_stats(sample)

                # Collect WAN health every 3 cycles (30 seconds)
                wan_health_counter += 1
                if wan_health_counter >= 3:
                    self.save_wan_health()
                    wan_health_counter = 0

                # Collect interface traffic every cycle (for real-time charts)
                traffic_counter += 1
                if traffic_counter >= 1:  # Every 10 seconds
                    self.save_interface_traffic()
                    traffic_counter = 0

                # Collect devices every 3 cycles (30 seconds)
                device_counter += 1
                if device_counter >= 3:
                    self.save_devices()
                    device_counter = 0

                # Collect WiFi status every 3 cycles (30 seconds)
                wifi_counter += 1
                if wifi_counter >= 3:
                    self.save_wifi_status()
                    wifi_counter = 0

                # Log detailed status
                layer_summary = ' '.join([f"{k}={v:.2f}" for k, v in sample.layer_scores.items()])
                logger.info(
                    f"QSecBit: {sample.rag_status} score={sample.score:.3f} "
                    f"threats={sample.threats_detected} layers=[{layer_summary}] "
                    f"macsec={sample.macsec_status}"
                )

                # Auto-block high-severity threats via XDP
                for threat in sample.recent_threats:
                    if threat.get('severity') in ('CRITICAL', 'HIGH') and threat.get('source_ip'):
                        if not threat.get('blocked'):
                            if self.block_ip_via_xdp(threat['source_ip']):
                                logger.info(f"Auto-blocked {threat['source_ip']} via XDP")

                time.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(interval)

    def run_api_server(self, port: int = 9090):
        """Run HTTP API server"""
        try:
            server = HTTPServer(('0.0.0.0', port), QSecBitAPIHandler)
            logger.info(f"QSecBit API server listening on port {port}")
            while self.running.is_set():
                server.handle_request()
        except Exception as e:
            logger.error(f"API server error: {e}")

    def start(self):
        """Start the agent"""
        global _agent_instance
        _agent_instance = self

        logger.info("Starting QSecBit Fortress Agent v5.2.0...")
        self.running.set()

        # Start monitoring loop
        monitor_thread = Thread(target=self.run_monitoring_loop, daemon=True)
        monitor_thread.start()

        # Start HTTP API server
        api_port = int(os.environ.get('QSECBIT_API_PORT', '9090'))
        api_thread = Thread(target=self.run_api_server, args=(api_port,), daemon=True)
        api_thread.start()

        # Wait for shutdown signal (block while running is set)
        while self.running.is_set():
            time.sleep(1)

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping QSecBit Fortress Agent...")
        self.running.clear()


def main():
    agent = QSecBitFortressAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
