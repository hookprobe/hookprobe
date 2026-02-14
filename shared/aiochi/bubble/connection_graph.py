#!/usr/bin/env python3
"""
Connection Graph Analyzer - Device-to-Device Communication Detection

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

╔═══════════════════════════════════════════════════════════════════════════════╗
║                        D2D BUBBLES vs DEVICE GROUPS                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  This module is part of the D2D BUBBLE COLORING system, which is INDEPENDENT  ║
║  of Device Groups:                                                             ║
║                                                                                 ║
║  • D2D Bubbles (this module): Automatic background algorithm that detects     ║
║    device relationships through network traffic patterns (NAPSE events).      ║
║    Devices that communicate frequently are colored similarly in the UI.       ║
║    This is PASSIVE and AUTOMATIC - users don't manage these.                  ║
║                                                                                 ║
║  • Device Groups (web UI): Manual CRUD feature for users to organize devices  ║
║    into named groups (Dad's Devices, Kids' Devices, Work, etc.) with          ║
║    OpenFlow network policies. Users CREATE, EDIT, DELETE groups manually.     ║
║                                                                                 ║
║  The two systems are INDEPENDENT:                                             ║
║    - D2D coloring happens in background based on network traffic              ║
║    - Device Groups are user-managed organizational containers                  ║
║    - A device can be in a "Work" group but colored same as "Dad's iPhone"    ║
║      if they communicate frequently via D2D                                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝

This module analyzes NAPSE connection events to detect device-to-device
communication patterns, enabling cross-ecosystem bubble detection.

The Innovation:
When Mom's iPhone shares photos with her Huawei Watch via WiFi Direct,
or when Kids' Samsung phone syncs with their Xiaomi band, these
communication patterns reveal same-user ownership REGARDLESS of ecosystem.

Detection Methods:
1. NAPSE ConnectionRecord events - TCP/UDP connections between LAN devices
2. Local service traffic - mDNS, AirPlay, Spotify Connect, casting
3. High-frequency short connections - File transfers, screen mirrors
4. Bidirectional traffic patterns - Not just client→server

Data Flow:
┌─────────────────────────────────────────────────────────────────┐
│  NAPSE IDS Engine (core/napse/)                                  │
│       │                                                          │
│       ▼                                                          │
│  NapseEventBus → BubbleFeed                                      │
│       │                                                          │
│       ▼                                                          │
│  ConnectionGraphAnalyzer.process_napse_connection()               │
│       │                                                          │
│       ├──▶ Filter LAN-only traffic (exclude internet)            │
│       ├──▶ Build device relationship graph                       │
│       ├──▶ Calculate D2D affinity scores                         │
│       └──▶ Return clusters for D2D bubble coloring               │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

Integration:
This module feeds into BehavioralClusteringEngine to add D2D features
that enable cross-ecosystem bubble detection. D2D bubble coloring is
displayed in the UI as visual indicators separate from Device Groups.
"""

import json
import logging
import re
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import ipaddress

logger = logging.getLogger(__name__)


# =============================================================================
# DEVICE TYPE CLASSIFICATION (IoT vs Personal)
# =============================================================================

class DeviceType(Enum):
    """Device type classification for bubble coloring."""
    PERSONAL = "personal"      # Laptops, phones, tablets, watches, headphones
    IOT = "iot"                # Smart home devices, sensors, hubs
    INFRASTRUCTURE = "infra"   # Routers, switches, servers
    UNKNOWN = "unknown"

    @property
    def color(self) -> str:
        """Get bubble visualization color for device type."""
        return DEVICE_TYPE_COLORS.get(self, "#808080")


class DeviceRole(Enum):
    """
    Device role for ecosystem mismatch penalty calculation.

    TRIO+ Recommendation (2026-01-14):
    Primary devices (phones, laptops, tablets) from different ecosystems
    should have a MUCH higher penalty than secondary devices (IoT, TVs).
    """
    PRIMARY = "primary"    # Phones, laptops, tablets - user's main devices
    SECONDARY = "secondary"  # Smart TVs, speakers, IoT - shared/utility devices
    UNKNOWN = "unknown"


def get_device_role(device_type: DeviceType, services: Optional[Set[str]] = None) -> DeviceRole:
    """
    Determine device role (PRIMARY vs SECONDARY) for ecosystem penalty calculation.

    TRIO+ Recommendation: Apply stronger penalty for PRIMARY-PRIMARY cross-ecosystem pairs.

    Args:
        device_type: DeviceType classification
        services: Optional mDNS services for additional classification

    Returns:
        DeviceRole enum value
    """
    # Personal devices are PRIMARY
    if device_type == DeviceType.PERSONAL:
        return DeviceRole.PRIMARY

    # IoT devices are SECONDARY
    if device_type == DeviceType.IOT:
        return DeviceRole.SECONDARY

    # Infrastructure is SECONDARY
    if device_type == DeviceType.INFRASTRUCTURE:
        return DeviceRole.SECONDARY

    # Check services for additional classification
    if services:
        services_lower = {s.lower() for s in services}
        # TV/media services -> SECONDARY
        if any(s in services_lower for s in ['_googlecast._tcp', '_airplay._tcp', '_raop._tcp']):
            return DeviceRole.SECONDARY
        # Companion/sync services -> PRIMARY (indicates phone/laptop)
        if any(s in services_lower for s in ['_companion-link._tcp', '_rdlink._tcp']):
            return DeviceRole.PRIMARY

    return DeviceRole.UNKNOWN


# Bubble visualization colors (for UI)
DEVICE_TYPE_COLORS = {
    DeviceType.PERSONAL: "#4CAF50",      # Green - personal devices
    DeviceType.IOT: "#FF9800",           # Orange - IoT devices
    DeviceType.INFRASTRUCTURE: "#2196F3", # Blue - infrastructure
    DeviceType.UNKNOWN: "#9E9E9E",       # Gray - unknown
}

# User bubble colors (rotating palette for different users)
USER_BUBBLE_COLORS = [
    "#E91E63",  # Pink - User 1 (e.g., Mom)
    "#3F51B5",  # Indigo - User 2 (e.g., Dad)
    "#009688",  # Teal - User 3 (e.g., Kids)
    "#FF5722",  # Deep Orange - User 4 (e.g., Guest)
    "#673AB7",  # Deep Purple - User 5
    "#00BCD4",  # Cyan - User 6
    "#795548",  # Brown - User 7
    "#607D8B",  # Blue Gray - User 8
]

# Known IoT vendor OUIs (first 3 bytes of MAC address)
IOT_VENDOR_OUIS = {
    # Smart home hubs
    "B0:FC:36": "tp-link",      # TP-Link smart devices
    "50:C7:BF": "tp-link",
    "60:A4:23": "tp-link",
    "70:4F:57": "tp-link",
    "98:DA:C4": "tp-link",
    "C0:06:C3": "tp-link",
    "60:32:B1": "wemo",         # Belkin WeMo
    "B4:79:A7": "wemo",
    "94:10:3E": "belkin",
    "C4:41:1E": "belkin",
    "00:17:88": "philips-hue",  # Philips Hue
    "EC:B5:FA": "philips-hue",
    "00:1E:06": "wemo",
    "7C:B2:7D": "orbi",         # Netgear Orbi
    "A4:2B:8C": "amazon-echo",  # Amazon devices
    "FC:65:DE": "amazon",
    "44:65:0D": "amazon",
    "68:54:FD": "amazon",
    "84:D6:D0": "amazon",
    "F0:F0:A4": "amazon",
    "18:B4:30": "nest",         # Google/Nest
    "64:16:66": "nest",
    "D8:EB:46": "google-home",
    "30:FD:38": "google",
    "F4:F5:D8": "google",
    "54:60:09": "google",
    "F8:0F:F9": "google",
    "34:36:3B": "apple-home",   # Apple HomePod
    "70:56:81": "apple-home",
    "58:D3:49": "apple-home",
    "1C:36:BB": "xiaomi",       # Xiaomi IoT
    "28:6C:07": "xiaomi",
    "64:09:80": "xiaomi",
    "78:02:F8": "xiaomi",
    "7C:49:EB": "xiaomi",
    "9C:9D:7E": "xiaomi",
    "B0:E2:35": "xiaomi",
    "00:9E:C8": "xiaomi",
    "04:CF:8C": "xiaomi",
    "0C:1D:AF": "xiaomi",
    "10:2A:B3": "xiaomi",
    "34:CE:00": "xiaomi",
    "3C:BD:D8": "xiaomi",
    "5C:E5:0C": "xiaomi",
    "74:23:44": "xiaomi",
    "7C:1C:4E": "xiaomi",
    "E4:AA:EC": "tuya",         # Tuya IoT platform
    "D8:1F:12": "tuya",
    "10:D5:61": "tuya",
    "24:62:AB": "tuya",
    "44:59:E3": "tuya",
    "50:02:91": "tuya",
    "58:8E:81": "tuya",
    "68:57:2D": "tuya",
    "7C:F6:66": "tuya",
    "84:0D:8E": "tuya",
    "90:8D:78": "espressif",    # ESP32/ESP8266 (IoT maker)
    "30:AE:A4": "espressif",
    "84:CC:A8": "espressif",
    "24:B2:DE": "espressif",
    "5C:CF:7F": "espressif",
    "A4:CF:12": "espressif",
    "BC:DD:C2": "espressif",
    "60:01:94": "espressif",
    "AC:D0:74": "espressif",
    "C4:4F:33": "espressif",
    "3C:71:BF": "espressif",
    "B4:E6:2D": "espressif",
    "CC:50:E3": "espressif",
    "8C:AA:B5": "espressif",
    "50:8C:B1": "sonoff",       # Sonoff/ITEAD
    "D8:BF:C0": "sonoff",
    "5C:CF:7F": "sonoff",
    "2C:F4:32": "sonoff",
    "08:3A:F2": "wyze",         # Wyze devices
    "2C:AA:8E": "wyze",
    "D0:3F:27": "wyze",
    "78:8C:B5": "ring",         # Ring devices
    "B0:09:DA": "ring",
    "EC:FA:5C": "ring",
    "00:62:6E": "ecobee",       # Ecobee thermostat
    "44:61:32": "ecobee",
    # Smart scales, fitness
    "88:C6:26": "withings",     # Withings scales
    "00:24:E4": "withings",
}

# Known personal device vendor OUIs
PERSONAL_VENDOR_OUIS = {
    # Apple devices (typically personal)
    "00:03:93": "apple",
    "00:05:02": "apple",
    "00:0A:27": "apple",
    "00:0A:95": "apple",
    "00:0D:93": "apple",
    "00:10:FA": "apple",
    "00:11:24": "apple",
    "00:14:51": "apple",
    "00:16:CB": "apple",
    "00:17:F2": "apple",
    "00:19:E3": "apple",
    "00:1B:63": "apple",
    "00:1C:B3": "apple",
    "00:1D:4F": "apple",
    "00:1E:52": "apple",
    "00:1E:C2": "apple",
    "00:1F:5B": "apple",
    "00:1F:F3": "apple",
    "00:21:E9": "apple",
    "00:22:41": "apple",
    "00:23:12": "apple",
    "00:23:32": "apple",
    "00:23:6C": "apple",
    "00:23:DF": "apple",
    "00:24:36": "apple",
    "00:25:00": "apple",
    "00:25:4B": "apple",
    "00:25:BC": "apple",
    "00:26:08": "apple",
    "00:26:4A": "apple",
    "00:26:B0": "apple",
    "00:26:BB": "apple",
    "00:C6:10": "apple",
    "04:0C:CE": "apple",
    "04:15:52": "apple",
    "04:1E:64": "apple",
    "04:26:65": "apple",
    "04:48:9A": "apple",
    "04:4B:ED": "apple",
    "04:52:F3": "apple",
    "04:54:53": "apple",
    "04:69:F8": "apple",
    "04:D3:CF": "apple",
    "04:DB:56": "apple",
    "04:E5:36": "apple",
    "04:F1:3E": "apple",
    "04:F7:E4": "apple",
    # Samsung phones/tablets
    "00:07:AB": "samsung",
    "00:09:18": "samsung",
    "00:0D:AE": "samsung",
    "00:12:47": "samsung",
    "00:12:FB": "samsung",
    "00:13:77": "samsung",
    "00:15:99": "samsung",
    "00:15:B9": "samsung",
    "00:16:32": "samsung",
    "00:16:6B": "samsung",
    "00:16:6C": "samsung",
    "00:16:DB": "samsung",
    "00:17:C9": "samsung",
    "00:17:D5": "samsung",
    "00:18:AF": "samsung",
    "00:1A:8A": "samsung",
    "00:1B:98": "samsung",
    "00:1C:43": "samsung",
    "00:1D:25": "samsung",
    "00:1D:F6": "samsung",
    "00:1E:7D": "samsung",
    "00:1F:CC": "samsung",
    "00:1F:CD": "samsung",
    "00:21:19": "samsung",
    "00:21:4C": "samsung",
    "00:21:D1": "samsung",
    "00:21:D2": "samsung",
    # Google Pixel
    "3C:28:6D": "google-pixel",
    "F4:F5:E8": "google-pixel",
    "94:EB:2C": "google-pixel",
}


def get_oui(mac: str) -> str:
    """Extract OUI (first 3 bytes) from MAC address."""
    mac = mac.upper().replace('-', ':')
    parts = mac.split(':')
    if len(parts) >= 3:
        return ':'.join(parts[:3])
    return ""


def detect_ecosystem(mac: str, services: Optional[Set[str]] = None) -> str:
    """
    Detect device ecosystem from MAC OUI and mDNS services.

    TRIO+ Addition (2026-01-14):
    Ecosystem detection is critical for preventing false bubble groupings.
    Devices from different ecosystems (Apple + Android) should NOT be
    grouped together unless they have very strong affinity scores.

    Args:
        mac: Device MAC address
        services: Set of mDNS service types observed

    Returns:
        Ecosystem string: 'apple', 'android', 'google', 'samsung', 'amazon', 'windows', 'unknown'
    """
    oui = get_oui(mac)

    # Check OUI for known ecosystems
    if oui in PERSONAL_VENDOR_OUIS:
        vendor = PERSONAL_VENDOR_OUIS[oui].lower()
        if 'apple' in vendor:
            return 'apple'
        elif 'samsung' in vendor:
            return 'samsung'
        elif 'google' in vendor or 'pixel' in vendor:
            return 'google'
        elif 'xiaomi' in vendor or 'huawei' in vendor or 'oppo' in vendor or 'vivo' in vendor:
            return 'android'

    if oui in IOT_VENDOR_OUIS:
        vendor = IOT_VENDOR_OUIS[oui].lower()
        if 'amazon' in vendor or 'echo' in vendor or 'alexa' in vendor:
            return 'amazon'
        elif 'google' in vendor or 'nest' in vendor:
            return 'google'
        elif 'apple' in vendor:
            return 'apple'

    # Check services for ecosystem hints
    if services:
        services_lower = {s.lower() for s in services}
        # Apple services
        if any(s in services_lower for s in ['_airplay._tcp', '_raop._tcp', '_companion-link._tcp', '_homekit._tcp']):
            return 'apple'
        # Google services
        if any(s in services_lower for s in ['_googlecast._tcp', '_googlezone._tcp']):
            return 'google'
        # Amazon services
        if any(s in services_lower for s in ['_amzn-wplay._tcp', '_alexa._tcp']):
            return 'amazon'
        # Samsung services
        if any(s in services_lower for s in ['_smartthings._tcp', '_samsungtv._tcp']):
            return 'samsung'

    # Check MAC for randomized Android patterns
    # Android 10+ uses randomized MACs - often starting with locally administered bit
    mac_upper = mac.upper()
    if len(mac_upper) >= 2:
        first_byte = int(mac_upper[:2], 16) if mac_upper[:2].replace(':', '').isalnum() else 0
        # Locally administered bit (bit 1 of first byte) - common in Android random MACs
        if first_byte & 0x02:
            # This is a randomized MAC - could be Android or iOS
            # Without more context, we can't determine ecosystem
            pass

    return 'unknown'


def classify_device_type(
    mac: str,
    cloud_traffic_ratio: float = 0.0,
    d2d_connection_weight: float = 0.0,
    services: Optional[Set[str]] = None
) -> Tuple[DeviceType, float]:
    """
    Classify device as Personal vs IoT based on multiple heuristics.

    Algorithm (from Trio+ consultation):
    1. OUI lookup - Known IoT/Personal vendors
    2. Cloud traffic ratio - IoT devices talk mostly to cloud
    3. D2D weight - Personal devices have high D2D communication
    4. Service analysis - mDNS services reveal device type

    Args:
        mac: Device MAC address
        cloud_traffic_ratio: Ratio of cloud vs local traffic (0-1)
        d2d_connection_weight: Total D2D affinity weight
        services: Set of mDNS service types observed

    Returns:
        Tuple of (DeviceType, confidence 0-1)
    """
    oui = get_oui(mac)
    score_personal = 0.0
    score_iot = 0.0
    confidence_factors = 0

    # 1. OUI lookup (weight: 0.35)
    if oui in IOT_VENDOR_OUIS:
        score_iot += 0.35
        confidence_factors += 1
        logger.debug(f"OUI {oui} matches IoT vendor: {IOT_VENDOR_OUIS[oui]}")
    elif oui in PERSONAL_VENDOR_OUIS:
        score_personal += 0.35
        confidence_factors += 1
        logger.debug(f"OUI {oui} matches Personal vendor: {PERSONAL_VENDOR_OUIS[oui]}")

    # 2. Cloud traffic ratio (weight: 0.25)
    # IoT devices typically have 70%+ cloud traffic
    if cloud_traffic_ratio > 0:
        confidence_factors += 1
        if cloud_traffic_ratio > 0.7:
            score_iot += 0.25 * cloud_traffic_ratio
        elif cloud_traffic_ratio < 0.3:
            score_personal += 0.25 * (1 - cloud_traffic_ratio)
        else:
            # Ambiguous - slight lean to personal
            score_personal += 0.1

    # 3. D2D connection weight (weight: 0.25)
    # Personal devices communicate with each other (AirDrop, Handoff)
    # IoT devices talk to hub/cloud, not to user devices
    if d2d_connection_weight > 0:
        confidence_factors += 1
        if d2d_connection_weight > 0.5:
            score_personal += 0.25 * min(d2d_connection_weight, 1.0)
        elif d2d_connection_weight < 0.1:
            score_iot += 0.20

    # 4. Service analysis (weight: 0.15)
    if services:
        confidence_factors += 1
        personal_services = {
            '_airplay', '_airdrop', '_spotify-connect', '_companion-link',
            '_presence', '_ssh', '_sftp-ssh', '_smb', '_afpovertcp',
            '_raop', '_touch-able', '_homekit', '_sleep-proxy'
        }
        iot_services = {
            '_hap', '_hue', '_matter', '_matterc', '_coap', '_mqtt',
            '_zigbee', '_zwave', '_tuya', '_miio', '_smartthings'
        }

        personal_match = len(services & personal_services)
        iot_match = len(services & iot_services)

        if personal_match > iot_match:
            score_personal += 0.15 * min(personal_match / 3, 1.0)
        elif iot_match > personal_match:
            score_iot += 0.15 * min(iot_match / 2, 1.0)

    # Calculate confidence based on evidence
    confidence = min(0.95, 0.5 + (confidence_factors * 0.15))

    # Determine type
    if score_personal > score_iot and score_personal > 0.2:
        return DeviceType.PERSONAL, confidence
    elif score_iot > score_personal and score_iot > 0.2:
        return DeviceType.IOT, confidence
    else:
        return DeviceType.UNKNOWN, max(0.3, confidence - 0.2)


def get_user_bubble_color(bubble_index: int) -> str:
    """Get a unique color for a user bubble."""
    return USER_BUBBLE_COLORS[bubble_index % len(USER_BUBBLE_COLORS)]

# Optional ClickHouse integration
try:
    from .clickhouse_graph import get_clickhouse_store, ClickHouseGraphStore
    HAS_CLICKHOUSE = True
except ImportError:
    HAS_CLICKHOUSE = False
    ClickHouseGraphStore = None

# dnsmasq leases file for IP→MAC mapping (container-friendly)
DNSMASQ_LEASES = Path('/var/lib/misc/dnsmasq.leases')

# Database for D2D relationship storage
D2D_DB = Path('/var/lib/hookprobe/d2d_graph.db')

# LAN network ranges (RFC 1918)
LAN_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
]

# Local service ports that indicate D2D communication
D2D_SERVICE_PORTS = {
    # Apple ecosystem
    5353: 'mdns',                    # mDNS/Bonjour
    7000: 'airplay',                 # AirPlay
    7100: 'airplay_mirror',          # AirPlay Mirroring
    3689: 'daap',                    # iTunes sharing
    62078: 'iphone_sync',            # iPhone USB sync

    # Google ecosystem
    8008: 'chromecast',              # Chromecast
    8009: 'chromecast_ssl',          # Chromecast (SSL)
    8443: 'google_home',             # Google Home

    # Samsung ecosystem
    8001: 'samsung_smartthings',     # SmartThings
    8002: 'samsung_tv',              # Samsung TV
    55000: 'samsung_allshare',       # AllShare/DLNA

    # Xiaomi ecosystem
    54321: 'xiaomi_miio',            # Xiaomi Mi Home
    54322: 'xiaomi_gateway',         # Xiaomi Gateway

    # Generic smart home
    1900: 'upnp_ssdp',               # UPnP/SSDP
    5000: 'upnp_av',                 # UPnP AV
    10001: 'ubiquiti',               # Ubiquiti discovery

    # Media streaming
    57621: 'spotify_connect',        # Spotify Connect
    8200: 'trivial_ftp',             # GoTV/media
    1883: 'mqtt',                    # IoT MQTT
    8883: 'mqtt_ssl',                # IoT MQTT (SSL)

    # File sharing
    445: 'smb',                      # SMB/CIFS
    139: 'netbios',                  # NetBIOS
    548: 'afp',                      # Apple Filing Protocol
    2049: 'nfs',                     # NFS

    # Remote access (indicates same-user devices)
    22: 'ssh',                       # SSH
    5900: 'vnc',                     # VNC
    3389: 'rdp',                     # RDP
}

# High-affinity ports (strong indicator of same-user)
HIGH_AFFINITY_PORTS = {
    7000, 7100,  # AirPlay (almost always same user)
    62078,       # iPhone sync
    548,         # AFP (Apple file sharing)
    57621,       # Spotify Connect
    5900,        # VNC
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class D2DConnection:
    """A device-to-device connection record."""
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_mac: str
    port: int
    protocol: str
    service: str
    bytes_sent: int
    bytes_recv: int
    packets: int
    duration: float
    timestamp: datetime

    @property
    def is_bidirectional(self) -> bool:
        """Check if traffic flows both ways (strong D2D indicator)."""
        return self.bytes_sent > 0 and self.bytes_recv > 0

    @property
    def is_high_affinity(self) -> bool:
        """Check if this is a high-affinity service."""
        return self.port in HIGH_AFFINITY_PORTS


@dataclass
class D2DMetrics:
    """
    Normalized D2D metrics for enhanced affinity scoring.

    Used by the Trio+ recommended formula (2026-01-14 update):
    w_uv = α·freq + β·bytes + γ·recency + δ·symmetry + ε·overlap + ζ·discovery + η·temporal + θ·activity_hour

    All values normalized to 0-1 range.
    """
    frequency: float = 0.0      # Normalized connection frequency (f̂)
    bytes_exchanged: float = 0.0  # Normalized bytes (b̂)
    recency: float = 0.0        # Recency score (r̂), 1.0 = just now
    symmetry: float = 0.0       # Bidirectional traffic ratio
    service_overlap: float = 0.0  # Service diversity score

    # Additional metrics for bubble suggestion
    discovery_score: float = 0.0   # mDNS discovery correlation
    temporal_score: float = 0.0    # Wake/sleep pattern correlation

    # Trio+ 2026-01-14: Activity hour similarity (Jaccard index of active hours)
    activity_hour_similarity: float = 0.0  # 0-1 similarity of daily activity patterns

    def to_dict(self) -> Dict:
        return {
            'frequency': round(self.frequency, 3),
            'bytes': round(self.bytes_exchanged, 3),
            'recency': round(self.recency, 3),
            'symmetry': round(self.symmetry, 3),
            'overlap': round(self.service_overlap, 3),
            'discovery': round(self.discovery_score, 3),
            'temporal': round(self.temporal_score, 3),
            'activity_hour_similarity': round(self.activity_hour_similarity, 3),
        }


@dataclass
class DeviceRelationship:
    """Relationship between two devices based on communication."""
    mac_a: str
    mac_b: str

    # Connection statistics
    connection_count: int = 0
    total_bytes: int = 0
    total_duration: float = 0.0

    # Service breakdown
    services_used: Dict[str, int] = field(default_factory=dict)

    # Affinity scoring
    bidirectional_count: int = 0
    high_affinity_count: int = 0

    # Timestamps
    first_seen: datetime = None
    last_seen: datetime = None

    # Affinity Score components (can be updated by mDNS analysis)
    discovery_hits: int = 0       # mDNS query/response pairs
    temporal_sync_score: float = 0.0  # Join/leave timing correlation

    # Device classification cache
    device_type_a: Optional[str] = None
    device_type_b: Optional[str] = None

    # Ecosystem classification (Trio+ recommendation for cross-ecosystem penalty)
    ecosystem_a: Optional[str] = None  # 'apple', 'android', 'windows', 'unknown'
    ecosystem_b: Optional[str] = None

    # Device role classification (Trio+ 2026-01-14: PRIMARY/SECONDARY for penalty tiers)
    device_role_a: Optional[str] = None  # 'primary', 'secondary', 'unknown'
    device_role_b: Optional[str] = None

    # Activity hour tracking (Trio+ 2026-01-14: Activity hour similarity signal)
    # Tracks which hours of the day devices are active (0-23)
    activity_hours_a: Set[int] = field(default_factory=set)
    activity_hours_b: Set[int] = field(default_factory=set)

    # Session tracking for sustained traffic detection (Trio+ recommendation)
    distinct_sessions: int = 0  # Number of distinct communication sessions
    session_timestamps: List[datetime] = field(default_factory=list)

    # Daily decay tracking (Trio+ 2026-01-14: 0.97 daily decay factor)
    last_decay_date: Optional[datetime] = None
    days_since_interaction: int = 0

    # Assigned bubble color (for visualization)
    bubble_color: Optional[str] = None

    def get_normalized_metrics(self) -> D2DMetrics:
        """
        Calculate normalized D2D metrics for affinity scoring.

        Returns metrics normalized to 0-1 scale for the Trio+ formula.
        """
        # Frequency normalization (log scale, max ~1000 connections/day = 1.0)
        freq_norm = min(1.0, self.connection_count / 100) if self.connection_count > 0 else 0.0

        # Bytes normalization (log scale, 100MB = 1.0)
        bytes_norm = 0.0
        if self.total_bytes > 0:
            import math
            # Log scale: 1KB = 0.1, 1MB = 0.5, 100MB = 1.0
            bytes_norm = min(1.0, math.log10(self.total_bytes + 1) / 8)

        # Recency calculation (exponential decay)
        # Trio+ Recommendation: Reduced half-life from 12h to 6h for faster decay
        # Old data should lose influence faster to prevent stale associations
        recency = 0.0
        if self.last_seen:
            age_hours = (datetime.now() - self.last_seen).total_seconds() / 3600
            # Exponential decay: half-life of 6 hours (was 12 - too slow)
            recency = min(1.0, 2 ** (-age_hours / 6))

        # Symmetry (bidirectional ratio)
        symmetry = 0.0
        if self.connection_count > 0:
            symmetry = self.bidirectional_count / self.connection_count

        # Service overlap (diversity score)
        overlap = 0.0
        if self.services_used:
            # High-affinity services boost the score
            ha_count = self.high_affinity_count
            total_services = len(self.services_used)
            # Normalize: 5+ services with some high-affinity = 1.0
            overlap = min(1.0, (total_services * 0.15) + (ha_count * 0.25))

        # Discovery score (mDNS)
        discovery = min(1.0, self.discovery_hits * 0.1) if self.discovery_hits > 0 else 0.0

        # Activity hour similarity (Trio+ 2026-01-14)
        # Jaccard index of active hours: |A ∩ B| / |A ∪ B|
        activity_similarity = 0.0
        if self.activity_hours_a and self.activity_hours_b:
            intersection = len(self.activity_hours_a & self.activity_hours_b)
            union = len(self.activity_hours_a | self.activity_hours_b)
            if union > 0:
                activity_similarity = intersection / union

        return D2DMetrics(
            frequency=freq_norm,
            bytes_exchanged=bytes_norm,
            recency=recency,
            symmetry=symmetry,
            service_overlap=overlap,
            discovery_score=discovery,
            temporal_score=self.temporal_sync_score,
            activity_hour_similarity=activity_similarity,
        )

    def calculate_affinity_score(self) -> float:
        """
        Calculate D2D affinity score using Trio+ recommended weighted algorithm.

        TRIO+ UPDATE 2026-01-14 (Gemini 2.5 Flash + Nemotron analysis):
        - New weights optimized for owner detection
        - Added activity_hour_similarity signal (0.13)
        - Tiered ecosystem penalties: -0.45 for PRIMARY-PRIMARY, -0.15 for mixed
        - Daily decay factor: 0.97 (3% daily reduction)
        - Reduced bytes weight to 0.02 (too easily skewed by streaming)

        Formula:
        w_uv = α·freq + β·bytes + γ·recency + δ·symmetry + ε·overlap
               + ζ·discovery + η·temporal + θ·activity_hour

        Weights (sum = 1.0):
        - α = 0.05 (frequency - reduced, less critical for owner than presence)
        - β = 0.02 (bytes - significantly reduced, too easily skewed)
        - γ = 0.20 (recency - high, essential for current relevance)
        - δ = 0.05 (symmetry - reduced, common for P2P but less owner-specific)
        - ε = 0.15 (overlap - maintained, shared services are good)
        - ζ = 0.20 (discovery - increased, strong owner signal via mDNS)
        - η = 0.20 (temporal - increased, strongest owner signal)
        - θ = 0.13 (activity_hour_similarity - NEW, strong owner pattern)

        Returns:
            Normalized affinity score (0.0 - 1.0)
        """
        # TRIO+ FIX: Sustained traffic requirement
        # Prevent transient/one-time connections from inflating scores
        MIN_SUSTAINED_CONNECTIONS = 10  # Minimum connections for sustained traffic
        MIN_SUSTAINED_SESSIONS = 3       # Minimum distinct sessions

        if self.connection_count < MIN_SUSTAINED_CONNECTIONS:
            # Not enough data for reliable affinity - return low score
            # This prevents one-time streaming/sharing from creating false bubbles
            return 0.0

        if self.distinct_sessions < MIN_SUSTAINED_SESSIONS:
            # Single burst of traffic (e.g., one AirPlay session) - cap score
            # Real same-user devices communicate across multiple sessions
            return min(0.3, self.connection_count / 100)

        metrics = self.get_normalized_metrics()

        # TRIO+ 2026-01-14: Optimized weights for owner detection
        # Sum = 1.0 (0.05 + 0.02 + 0.20 + 0.05 + 0.15 + 0.20 + 0.20 + 0.13)
        WEIGHT_FREQUENCY = 0.05    # Reduced - less critical for owner detection
        WEIGHT_BYTES = 0.02        # Significantly reduced - streaming skews this
        WEIGHT_RECENCY = 0.20      # High - essential for current relevance
        WEIGHT_SYMMETRY = 0.05     # Reduced - common for P2P but less owner-specific
        WEIGHT_OVERLAP = 0.15      # Maintained - shared services indicate ownership
        WEIGHT_DISCOVERY = 0.20    # Increased - mDNS discovery is strong owner signal
        WEIGHT_TEMPORAL = 0.20     # Increased - wake/sleep together is strongest signal
        WEIGHT_ACTIVITY_HOUR = 0.13  # NEW - activity hour similarity (Jaccard)

        # Calculate weighted sum
        score = (
            WEIGHT_FREQUENCY * metrics.frequency +
            WEIGHT_BYTES * metrics.bytes_exchanged +
            WEIGHT_RECENCY * metrics.recency +
            WEIGHT_SYMMETRY * metrics.symmetry +
            WEIGHT_OVERLAP * metrics.service_overlap +
            WEIGHT_DISCOVERY * metrics.discovery_score +
            WEIGHT_TEMPORAL * metrics.temporal_score +
            WEIGHT_ACTIVITY_HOUR * metrics.activity_hour_similarity
        )

        # TRIO+ 2026-01-14: Apply daily decay factor (0.97 per day)
        # Relationships need "maintenance" - if no communication, score decays
        DAILY_DECAY_FACTOR = 0.97  # 3% daily reduction
        if self.days_since_interaction > 0:
            decay_multiplier = DAILY_DECAY_FACTOR ** self.days_since_interaction
            score *= decay_multiplier
            if self.days_since_interaction > 5:
                logger.debug(
                    f"Daily decay applied: {self.mac_a} <-> {self.mac_b}, "
                    f"days={self.days_since_interaction}, multiplier={decay_multiplier:.3f}"
                )

        # High-affinity service bonus (AirPlay, AirDrop, etc.)
        # These are strong indicators of same-user ownership
        if self.high_affinity_count >= 3:
            score = min(1.0, score + 0.15)
        elif self.high_affinity_count >= 1:
            score = min(1.0, score + 0.08)

        # Personal device bonus (from device type classification)
        # Two personal devices communicating = likely same user
        if self.device_type_a == 'personal' and self.device_type_b == 'personal':
            score = min(1.0, score + 0.10)

        # TRIO+ 2026-01-14: Tiered ecosystem mismatch penalties
        # Primary-Primary cross-ecosystem pairs get MUCH higher penalty
        # This prevents false groupings like Android work phone + Apple family devices
        ECOSYSTEM_MISMATCH_PENALTY_PRIMARY = 0.45  # Was 0.25 - increased for primary pairs
        ECOSYSTEM_MISMATCH_PENALTY_MIXED = 0.15    # Lower for IoT/mixed pairs

        if self.ecosystem_a and self.ecosystem_b:
            # Both ecosystems are known
            if self.ecosystem_a != self.ecosystem_b:
                # Different ecosystems - apply tiered penalty based on device roles
                role_a = self.device_role_a or 'unknown'
                role_b = self.device_role_b or 'unknown'

                # Determine penalty tier
                if role_a == 'primary' and role_b == 'primary':
                    # PRIMARY-PRIMARY: Strongest penalty (e.g., Android phone + iPhone)
                    penalty = ECOSYSTEM_MISMATCH_PENALTY_PRIMARY
                    logger.debug(
                        f"PRIMARY ecosystem mismatch: {self.mac_a} ({self.ecosystem_a}/{role_a}) "
                        f"<-> {self.mac_b} ({self.ecosystem_b}/{role_b}), penalty={penalty}"
                    )
                else:
                    # Mixed pair (IoT, secondary) - lower penalty
                    penalty = ECOSYSTEM_MISMATCH_PENALTY_MIXED
                    logger.debug(
                        f"MIXED ecosystem mismatch: {self.mac_a} ({self.ecosystem_a}/{role_a}) "
                        f"<-> {self.mac_b} ({self.ecosystem_b}/{role_b}), penalty={penalty}"
                    )

                score = max(0.0, score - penalty)
            else:
                # Same ecosystem - small bonus
                score = min(1.0, score + 0.05)

        return min(1.0, max(0.0, score))

    def get_bubble_suggestion(self) -> Dict:
        """
        Get bubble suggestion for UI display.

        Returns dict with:
        - should_suggest: bool - whether to suggest same bubble
        - confidence: float - confidence level (0-1)
        - reason: str - human-readable reason
        - color: str - suggested bubble color
        """
        affinity = self.calculate_affinity_score()
        metrics = self.get_normalized_metrics()

        # Determine suggestion
        # TRIO+ FIX: Increased threshold from 0.4 to 0.55 to prevent false groupings
        should_suggest = affinity >= 0.55  # 55% threshold for suggestion (was 0.4)
        confidence = affinity

        # Build reason
        reasons = []
        if metrics.frequency > 0.3:
            reasons.append("communicate frequently")
        if metrics.symmetry > 0.5:
            reasons.append("bidirectional traffic")
        if metrics.discovery_score > 0.3:
            reasons.append("discover each other via mDNS")
        if metrics.temporal_score > 0.4:
            reasons.append("wake/sleep together")
        if self.high_affinity_count > 0:
            reasons.append("share files/media")

        reason = "Devices " + ", ".join(reasons) if reasons else "Low affinity detected"

        return {
            'should_suggest': should_suggest,
            'confidence': round(confidence, 2),
            'reason': reason,
            'color': self.bubble_color or get_user_bubble_color(0),
            'metrics': metrics.to_dict(),
        }


@dataclass
class D2DCluster:
    """A cluster of devices based on D2D communication."""
    devices: Set[str]  # MAC addresses
    affinity_matrix: Dict[Tuple[str, str], float]
    avg_affinity: float
    primary_services: List[str]

    def to_dict(self) -> Dict:
        return {
            'devices': list(self.devices),
            'device_count': len(self.devices),
            'avg_affinity': self.avg_affinity,
            'primary_services': self.primary_services,
        }


@dataclass
class TemporalPattern:
    """
    Temporal pattern for a device - tracks wake/sleep cycles.

    Used to correlate devices that follow the same schedule:
    - Mom's phone and laptop wake at 7am together
    - Kids' devices go dormant at 9pm bedtime
    - Work devices active 9-5, home devices 6pm-10pm
    """
    mac: str
    # Active hours (0-23)
    active_hours: Set[int] = field(default_factory=set)
    # Wake/sleep events (hour, weekday)
    wake_events: List[Tuple[int, int]] = field(default_factory=list)  # (hour, weekday)
    sleep_events: List[Tuple[int, int]] = field(default_factory=list)  # (hour, weekday)
    # Typical activity pattern
    avg_session_duration: float = 0.0  # minutes
    avg_idle_duration: float = 0.0     # minutes between sessions

    def similarity(self, other: 'TemporalPattern') -> float:
        """
        Calculate similarity with another device's temporal pattern.

        Returns 0.0 - 1.0:
        - 1.0 = identical schedule (same user, different devices)
        - 0.5 = similar schedule (work colleagues, family members)
        - 0.0 = completely different schedules
        """
        if not self.active_hours or not other.active_hours:
            return 0.0

        # Jaccard similarity for active hours
        intersection = len(self.active_hours & other.active_hours)
        union = len(self.active_hours | other.active_hours)
        hour_similarity = intersection / union if union > 0 else 0.0

        # Wake/sleep event correlation
        wake_corr = self._event_correlation(self.wake_events, other.wake_events)
        sleep_corr = self._event_correlation(self.sleep_events, other.sleep_events)

        # Weighted average
        return (hour_similarity * 0.4) + (wake_corr * 0.3) + (sleep_corr * 0.3)

    @staticmethod
    def _event_correlation(events_a: List[Tuple[int, int]],
                          events_b: List[Tuple[int, int]]) -> float:
        """Calculate correlation between two event lists."""
        if not events_a or not events_b:
            return 0.0

        # Count events within same hour (any weekday)
        hours_a = set(e[0] for e in events_a)
        hours_b = set(e[0] for e in events_b)

        intersection = len(hours_a & hours_b)
        union = len(hours_a | hours_b)

        return intersection / union if union > 0 else 0.0


# =============================================================================
# CONNECTION GRAPH ANALYZER
# =============================================================================

class ConnectionGraphAnalyzer:
    """
    Analyzes NAPSE connection events to build device relationship graph.

    Device-to-device communication patterns reveal same-user ownership:
    - AirDrop/WiFi Direct between iPhone ↔ Samsung (sharing photos)
    - mDNS queries from Phone → Smart Band (fitness sync)
    - Local API calls between app ↔ wearable
    - File sharing between laptop ↔ phone
    """

    # Analysis parameters
    LOOKBACK_HOURS = 24           # Analyze last 24 hours of logs
    MIN_CONNECTIONS = 3           # Minimum connections to consider relationship
    # TRIO+ FIX: Increased from 0.3 to 0.55 to prevent false D2D cluster coloring
    # This was causing devices with brief interactions to get the same color
    AFFINITY_THRESHOLD = 0.55     # Minimum affinity for clustering (was 0.3)

    def __init__(self, db_path: Path = D2D_DB, enable_clickhouse: bool = True):
        self.db_path = db_path
        self.relationships: Dict[Tuple[str, str], DeviceRelationship] = {}
        self.ip_to_mac: Dict[str, str] = {}
        self._lock = __import__('threading').Lock()

        # Temporal pattern tracking for enhanced affinity scoring
        self._temporal_patterns: Dict[str, TemporalPattern] = {}
        self._device_last_seen: Dict[str, datetime] = {}
        self._device_state: Dict[str, str] = {}  # 'active' or 'dormant'

        # Event batching for temporal analysis
        self._temporal_event_buffer: List[Dict] = []
        self._temporal_buffer_size = 100

        # ClickHouse integration for AI learning
        self._clickhouse_store: Optional[ClickHouseGraphStore] = None
        if enable_clickhouse and HAS_CLICKHOUSE:
            try:
                self._clickhouse_store = get_clickhouse_store()
                logger.info("ClickHouse graph storage enabled")
            except Exception as e:
                logger.debug(f"ClickHouse not available: {e}")

        self._ensure_db()
        self._load_ip_mac_mapping()

    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS d2d_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_mac TEXT NOT NULL,
                    dst_mac TEXT NOT NULL,
                    port INTEGER,
                    service TEXT,
                    bytes_total INTEGER,
                    is_bidirectional INTEGER,
                    timestamp TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS device_relationships (
                    mac_a TEXT NOT NULL,
                    mac_b TEXT NOT NULL,
                    connection_count INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    bidirectional_count INTEGER DEFAULT 0,
                    high_affinity_count INTEGER DEFAULT 0,
                    services_json TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    affinity_score REAL DEFAULT 0.0,
                    PRIMARY KEY (mac_a, mac_b)
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_d2d_timestamp
                ON d2d_connections(timestamp)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_rel_affinity
                ON device_relationships(affinity_score DESC)
            ''')
            # Temporal patterns table for wake/sleep analysis
            conn.execute('''
                CREATE TABLE IF NOT EXISTS temporal_patterns (
                    mac TEXT PRIMARY KEY,
                    active_hours_json TEXT,
                    wake_events_json TEXT,
                    sleep_events_json TEXT,
                    avg_session_duration REAL DEFAULT 0.0,
                    avg_idle_duration REAL DEFAULT 0.0,
                    last_updated TEXT
                )
            ''')
            # Temporal correlation between device pairs
            conn.execute('''
                CREATE TABLE IF NOT EXISTS temporal_correlations (
                    mac_a TEXT NOT NULL,
                    mac_b TEXT NOT NULL,
                    pattern_similarity REAL DEFAULT 0.0,
                    coincident_wake_count INTEGER DEFAULT 0,
                    coincident_sleep_count INTEGER DEFAULT 0,
                    last_calculated TEXT,
                    PRIMARY KEY (mac_a, mac_b)
                )
            ''')

            # TRIO+ 2026-01-14: Color persistence for D2D bubbles
            # Ensures consistent bubble colors across restarts
            conn.execute('''
                CREATE TABLE IF NOT EXISTS bubble_color_persistence (
                    cluster_id TEXT PRIMARY KEY,
                    color TEXT NOT NULL,
                    device_macs_json TEXT,
                    created_at TEXT,
                    last_updated TEXT
                )
            ''')
            conn.commit()

    def _load_ip_mac_mapping(self):
        """
        Load IP to MAC mapping from multiple sources.

        Priority order:
        1. dnsmasq leases file (works in containers, authoritative for DHCP)
        2. ARP table (fallback, requires host network access)
        """
        # First try dnsmasq leases (container-friendly, authoritative)
        self._load_from_dnsmasq_leases()

        # Fallback to ARP table if no mappings found
        if not self.ip_to_mac:
            self._load_from_arp_table()

        logger.debug(f"Loaded {len(self.ip_to_mac)} IP→MAC mappings")

    def _load_from_dnsmasq_leases(self):
        """
        Load IP→MAC mappings from dnsmasq leases file.

        Format: timestamp mac_address ip_address hostname client_id
        Example: 1768320904 40:ed:cf:82:62:6b 10.200.0.13 hooksound 01:40:ed:cf:82:62:6b
        """
        try:
            if not DNSMASQ_LEASES.exists():
                logger.debug(f"dnsmasq leases file not found: {DNSMASQ_LEASES}")
                return

            with open(DNSMASQ_LEASES, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        # Format: timestamp mac ip [hostname] [client_id]
                        mac = parts[1].upper()
                        ip = parts[2]

                        # Validate IP is in LAN range
                        if self._is_lan_ip(ip):
                            self.ip_to_mac[ip] = mac

            logger.debug(f"Loaded {len(self.ip_to_mac)} IP→MAC from dnsmasq leases")

        except Exception as e:
            logger.debug(f"Could not load from dnsmasq leases: {e}")

    def _load_from_arp_table(self):
        """Load IP→MAC mappings from ARP table (fallback)."""
        try:
            result = subprocess.run(
                ['ip', 'neigh', 'show'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                # Format: 10.200.0.5 dev FTS lladdr aa:bb:cc:dd:ee:ff REACHABLE
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    mac_idx = parts.index('lladdr') + 1
                    if mac_idx < len(parts):
                        mac = parts[mac_idx].upper()
                        self.ip_to_mac[ip] = mac

            logger.debug(f"Loaded {len(self.ip_to_mac)} IP→MAC from ARP table")
        except Exception as e:
            logger.debug(f"Could not load from ARP table: {e}")

    def _is_lan_ip(self, ip: str) -> bool:
        """Check if IP is in LAN range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in LAN_NETWORKS)
        except ValueError:
            return False

    def _normalize_mac_pair(self, mac_a: str, mac_b: str) -> Tuple[str, str]:
        """Normalize MAC pair for consistent key ordering."""
        return tuple(sorted([mac_a.upper(), mac_b.upper()]))

    def process_napse_connection(self, record) -> Optional[D2DConnection]:
        """
        Process a NAPSE ConnectionRecord into a D2DConnection.

        This replaces the old file-based log parsing
        with direct event-bus consumption from NAPSE.

        Args:
            record: ConnectionRecord from NAPSE event bus

        Returns:
            D2DConnection if LAN-to-LAN traffic, None otherwise
        """
        src_ip = getattr(record, 'id_orig_h', '')
        dst_ip = getattr(record, 'id_resp_h', '')

        # Only keep LAN-to-LAN traffic
        if not (self._is_lan_ip(src_ip) and self._is_lan_ip(dst_ip)):
            return None

        # Skip traffic to/from gateway (typically .1)
        if src_ip.endswith('.1') or dst_ip.endswith('.1'):
            return None

        # Get MACs
        src_mac = self.ip_to_mac.get(src_ip, '').upper()
        dst_mac = self.ip_to_mac.get(dst_ip, '').upper()

        if not src_mac or not dst_mac:
            return None

        # Skip if same device
        if src_mac == dst_mac:
            return None

        # Parse port and service
        dst_port = getattr(record, 'id_resp_p', 0) or 0
        service = getattr(record, 'service', '') or ''

        # Check if this is a D2D service port
        service_name = D2D_SERVICE_PORTS.get(dst_port, service)
        if not service_name and dst_port > 1024:
            service_name = 'ephemeral'

        # Traffic stats
        duration = getattr(record, 'duration', 0.0) or 0.0
        bytes_sent = getattr(record, 'orig_bytes', 0) or 0
        bytes_recv = getattr(record, 'resp_bytes', 0) or 0
        packets = (getattr(record, 'orig_pkts', 0) or 0) + (getattr(record, 'resp_pkts', 0) or 0) or 1

        # Parse timestamp
        ts = getattr(record, 'ts', 0)
        try:
            timestamp = datetime.fromtimestamp(ts) if ts else datetime.now()
        except (ValueError, OSError):
            timestamp = datetime.now()

        conn = D2DConnection(
            src_ip=src_ip,
            src_mac=src_mac,
            dst_ip=dst_ip,
            dst_mac=dst_mac,
            port=dst_port,
            protocol=getattr(record, 'proto', 'tcp') or 'tcp',
            service=service_name,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            packets=packets,
            duration=duration,
            timestamp=timestamp,
        )

        logger.debug(f"D2D connection: {src_mac} -> {dst_mac} ({service_name})")
        return conn

    def update_relationships(self, connections: List[D2DConnection] = None):
        """
        Update device relationships from connection data.

        This method:
        1. Accepts D2DConnection list (from NAPSE event bus via process_napse_connection)
        2. Updates relationship statistics
        3. Calculates affinity scores
        4. Persists to database
        """
        if connections is None:
            connections = []

        if not connections:
            logger.debug("No D2D connections to process")
            return

        with self._lock:
            # Process each connection
            for conn in connections:
                key = self._normalize_mac_pair(conn.src_mac, conn.dst_mac)

                if key not in self.relationships:
                    self.relationships[key] = DeviceRelationship(
                        mac_a=key[0],
                        mac_b=key[1],
                        first_seen=conn.timestamp,
                        # TRIO+ FIX: Detect ecosystems at relationship creation
                        ecosystem_a=detect_ecosystem(key[0]),
                        ecosystem_b=detect_ecosystem(key[1]),
                    )

                rel = self.relationships[key]
                rel.connection_count += 1
                rel.total_bytes += conn.bytes_sent + conn.bytes_recv
                rel.total_duration += conn.duration
                rel.last_seen = conn.timestamp

                # TRIO+ FIX: Track distinct sessions for sustained traffic detection
                # A session is a connection with a gap of >30 minutes from previous
                if rel.session_timestamps:
                    last_session = rel.session_timestamps[-1]
                    gap = (conn.timestamp - last_session).total_seconds() / 60
                    if gap > 30:  # New session if >30 min gap
                        rel.distinct_sessions += 1
                        rel.session_timestamps.append(conn.timestamp)
                else:
                    rel.distinct_sessions = 1
                    rel.session_timestamps = [conn.timestamp]

                # Track services
                if conn.service:
                    rel.services_used[conn.service] = \
                        rel.services_used.get(conn.service, 0) + 1
                    # TRIO+ FIX: Update ecosystems based on observed services
                    services_set = set(rel.services_used.keys())
                    if not rel.ecosystem_a or rel.ecosystem_a == 'unknown':
                        rel.ecosystem_a = detect_ecosystem(key[0], services_set)
                    if not rel.ecosystem_b or rel.ecosystem_b == 'unknown':
                        rel.ecosystem_b = detect_ecosystem(key[1], services_set)

                # Track bidirectional and high-affinity
                if conn.is_bidirectional:
                    rel.bidirectional_count += 1
                if conn.is_high_affinity:
                    rel.high_affinity_count += 1

            # Persist to database
            self._persist_relationships()

        logger.info(f"Updated {len(self.relationships)} device relationships")

    def analyze_mdns_browsing(self):
        """
        Analyze mDNS browsing patterns to detect discovery hits.

        mDNS "browsing" is a strong indicator of same-user devices:
        - When Dad opens Remote app, iPhone queries _touch-remote._tcp
        - Apple TV responds, revealing same-ecosystem relationship

        Uses tshark for lightweight capture (NAPSE event bus handles this
        in the container via bubble_feed.py).
        """
        self._capture_mdns_traffic()

    def _capture_mdns_traffic(self, duration: int = 10):
        """
        Quick tshark capture for mDNS traffic.

        TRIO+ FIX (2026-01-14):
        The old algorithm created false relationships when two devices
        simply queried the same service. Now we properly capture both
        queries and responses, and only create discovery hits for
        actual query→response pairs.
        """
        try:
            # TRIO+ FIX: Capture both queries AND responses separately
            result = subprocess.run(
                ['tshark', '-i', 'FTS', '-Y', 'mdns',
                 '-T', 'fields',
                 '-e', 'eth.src',           # Source MAC
                 '-e', 'mdns.qry.name',     # Query name (when querying)
                 '-e', 'mdns.resp.name',    # Response name (when advertising)
                 '-a', f'duration:{duration}'],
                capture_output=True, text=True, timeout=duration + 5
            )

            if result.returncode != 0:
                logger.debug(f"tshark capture failed: {result.stderr}")
                return

            # TRIO+ FIX: Track queries and responses SEPARATELY
            queries: Dict[str, Set[str]] = defaultdict(set)    # service → {querier_macs}
            responses: Dict[str, Set[str]] = defaultdict(set)  # service → {responder_macs}

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) < 3:
                    continue

                mac = parts[0].upper().replace(':', ':')
                query_name = parts[1] if len(parts) > 1 else ''
                response_name = parts[2] if len(parts) > 2 else ''

                # Track queries (device searching for service)
                if query_name and '.local' in query_name:
                    queries[query_name].add(mac)

                # Track responses (device advertising service)
                if response_name and '.local' in response_name:
                    responses[response_name].add(mac)

            # TRIO+ FIX: Only create discovery hits for query→response pairs
            discovery_pairs = 0
            for service, querier_macs in queries.items():
                responder_macs = responses.get(service, set())
                if not responder_macs:
                    continue

                for querier in querier_macs:
                    for responder in responder_macs:
                        # Skip self-discovery
                        if querier == responder:
                            continue

                        key = self._normalize_mac_pair(querier, responder)
                        if key not in self.relationships:
                            self.relationships[key] = DeviceRelationship(
                                mac_a=key[0],
                                mac_b=key[1],
                                first_seen=datetime.now(),
                                last_seen=datetime.now(),
                                ecosystem_a=detect_ecosystem(key[0]),
                                ecosystem_b=detect_ecosystem(key[1]),
                            )
                        self.relationships[key].discovery_hits += 1
                        discovery_pairs += 1

            logger.debug(f"Captured mDNS for {duration}s: {discovery_pairs} valid discovery pairs")

        except subprocess.TimeoutExpired:
            logger.debug("tshark capture timed out")
        except FileNotFoundError:
            logger.debug("tshark not available")
        except Exception as e:
            logger.warning(f"mDNS capture failed: {e}")

    def update_temporal_sync(self, presence_events: List[Dict]):
        """
        Update temporal sync scores from presence sensor events.

        Enhanced algorithm:
        1. Track wake/sleep patterns per device
        2. Detect coincident events (same time window)
        3. Calculate pattern similarity between devices
        4. Update temporal_sync_score with weighted combination

        Args:
            presence_events: List of {mac, event_type, timestamp, access_point}
        """
        if len(presence_events) < 2:
            return

        # Buffer events for batch processing
        self._temporal_event_buffer.extend(presence_events)

        # Process when buffer is full
        if len(self._temporal_event_buffer) >= self._temporal_buffer_size:
            self._process_temporal_buffer()
            self._temporal_event_buffer = []
        else:
            # Still process immediate coincidence detection
            self._detect_coincident_events(presence_events)

        logger.debug(f"Updated temporal sync from {len(presence_events)} events")

    def _detect_coincident_events(self, events: List[Dict]):
        """Detect and score coincident wake/sleep events."""
        # Group events by time window (60 seconds)
        windows: Dict[int, List[Dict]] = defaultdict(list)

        for event in events:
            try:
                ts = datetime.fromisoformat(event['timestamp'])
                window_key = int(ts.timestamp() // 60)  # 1-minute windows
                windows[window_key].append(event)

                # Track device state and pattern
                mac = event.get('mac', '').upper()
                event_type = event.get('event_type', '')

                if mac and event_type in ('join', 'leave'):
                    self._update_device_pattern(mac, event_type, ts)

            except (KeyError, ValueError):
                continue

        # Find correlated events (same time window, same event type)
        for window_key, window_events in windows.items():
            by_type: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)

            for e in window_events:
                event_type = e.get('event_type', '')
                mac = e.get('mac', '').upper()
                try:
                    ts = datetime.fromisoformat(e['timestamp'])
                except (KeyError, ValueError):
                    ts = datetime.now()

                if event_type in ('join', 'leave') and mac:
                    by_type[event_type].append((mac, ts))

            # Score coincident events
            for event_type, mac_times in by_type.items():
                macs = [m for m, t in mac_times]

                if len(macs) >= 2:
                    # Calculate time closeness for bonus scoring
                    for i in range(len(mac_times)):
                        for j in range(i + 1, len(mac_times)):
                            mac_a, time_a = mac_times[i]
                            mac_b, time_b = mac_times[j]

                            # Time difference bonus (closer = higher score)
                            time_diff = abs((time_a - time_b).total_seconds())
                            closeness_bonus = max(0, 1.0 - (time_diff / 60))  # 0-1 based on 60s window

                            key = self._normalize_mac_pair(mac_a, mac_b)
                            if key not in self.relationships:
                                self.relationships[key] = DeviceRelationship(
                                    mac_a=key[0],
                                    mac_b=key[1],
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                )

                            rel = self.relationships[key]

                            # Enhanced scoring:
                            # - Base: 0.05 per coincident event
                            # - Bonus: up to 0.05 more for very close events
                            # - Wake events worth more (user starting day)
                            base_score = 0.05
                            if event_type == 'join':
                                base_score = 0.08  # Wake events more significant

                            score_increment = base_score + (closeness_bonus * 0.05)
                            rel.temporal_sync_score = min(1.0, rel.temporal_sync_score + score_increment)

    def _update_device_pattern(self, mac: str, event_type: str, timestamp: datetime):
        """Update temporal pattern for a device."""
        mac = mac.upper()

        if mac not in self._temporal_patterns:
            self._temporal_patterns[mac] = TemporalPattern(mac=mac)

        pattern = self._temporal_patterns[mac]
        hour = timestamp.hour
        weekday = timestamp.weekday()

        # Track active hours
        pattern.active_hours.add(hour)

        # Track wake/sleep events
        if event_type == 'join':
            # Check if this is a "wake" event (device was dormant)
            if self._device_state.get(mac) == 'dormant':
                pattern.wake_events.append((hour, weekday))
                # Keep only recent events (last 7 days worth)
                if len(pattern.wake_events) > 50:
                    pattern.wake_events = pattern.wake_events[-50:]

            self._device_state[mac] = 'active'

        elif event_type == 'leave':
            pattern.sleep_events.append((hour, weekday))
            if len(pattern.sleep_events) > 50:
                pattern.sleep_events = pattern.sleep_events[-50:]

            self._device_state[mac] = 'dormant'

        # Track last seen for session duration calculation
        if mac in self._device_last_seen and self._device_state.get(mac) == 'active':
            session_duration = (timestamp - self._device_last_seen[mac]).total_seconds() / 60
            if pattern.avg_session_duration == 0:
                pattern.avg_session_duration = session_duration
            else:
                # Exponential moving average
                pattern.avg_session_duration = (pattern.avg_session_duration * 0.9) + (session_duration * 0.1)

        self._device_last_seen[mac] = timestamp

    def _process_temporal_buffer(self):
        """Process buffered events for pattern similarity calculation."""
        with self._lock:
            # Get unique MACs from buffer
            macs = set()
            for event in self._temporal_event_buffer:
                mac = event.get('mac', '').upper()
                if mac:
                    macs.add(mac)

            # Calculate pattern similarity between all pairs
            macs_list = list(macs)
            for i in range(len(macs_list)):
                for j in range(i + 1, len(macs_list)):
                    mac_a = macs_list[i]
                    mac_b = macs_list[j]

                    pattern_a = self._temporal_patterns.get(mac_a)
                    pattern_b = self._temporal_patterns.get(mac_b)

                    if pattern_a and pattern_b:
                        similarity = pattern_a.similarity(pattern_b)

                        if similarity > 0.3:  # Only update if significant
                            key = self._normalize_mac_pair(mac_a, mac_b)

                            if key not in self.relationships:
                                self.relationships[key] = DeviceRelationship(
                                    mac_a=key[0],
                                    mac_b=key[1],
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                )

                            # Blend pattern similarity into temporal sync score
                            rel = self.relationships[key]
                            # Pattern similarity has weight of 0.3 in overall temporal score
                            current_event_score = rel.temporal_sync_score
                            blended = (current_event_score * 0.7) + (similarity * 0.3)
                            rel.temporal_sync_score = min(1.0, blended)

            # Persist patterns
            self._persist_temporal_patterns()

    def _persist_temporal_patterns(self):
        """Persist temporal patterns to SQLite and ClickHouse."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                for mac, pattern in self._temporal_patterns.items():
                    # SQLite persistence
                    conn.execute('''
                        INSERT OR REPLACE INTO temporal_patterns
                        (mac, active_hours_json, wake_events_json, sleep_events_json,
                         avg_session_duration, avg_idle_duration, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        mac,
                        json.dumps(list(pattern.active_hours)),
                        json.dumps(pattern.wake_events),
                        json.dumps(pattern.sleep_events),
                        pattern.avg_session_duration,
                        pattern.avg_idle_duration,
                        datetime.now().isoformat(),
                    ))

                    # ClickHouse persistence for AI learning
                    if self._clickhouse_store and len(pattern.active_hours) > 0:
                        wake_hours = list(set(h for h, w in pattern.wake_events))
                        sleep_hours = list(set(h for h, w in pattern.sleep_events))

                        self._clickhouse_store.record_temporal_pattern(
                            mac=mac,
                            active_hours=list(pattern.active_hours),
                            wake_hours=wake_hours,
                            sleep_hours=sleep_hours,
                            avg_session_duration=pattern.avg_session_duration,
                            avg_idle_duration=pattern.avg_idle_duration,
                        )

                conn.commit()

            # Flush ClickHouse buffer
            if self._clickhouse_store:
                self._clickhouse_store.flush()

        except Exception as e:
            logger.debug(f"Could not persist temporal patterns: {e}")

    def load_temporal_patterns(self):
        """Load temporal patterns from database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                rows = conn.execute('SELECT * FROM temporal_patterns').fetchall()

                for row in rows:
                    mac = row[0]
                    self._temporal_patterns[mac] = TemporalPattern(
                        mac=mac,
                        active_hours=set(json.loads(row[1] or '[]')),
                        wake_events=json.loads(row[2] or '[]'),
                        sleep_events=json.loads(row[3] or '[]'),
                        avg_session_duration=row[4] or 0.0,
                        avg_idle_duration=row[5] or 0.0,
                    )

                logger.debug(f"Loaded {len(rows)} temporal patterns from DB")
        except Exception as e:
            logger.debug(f"Could not load temporal patterns: {e}")

    def get_temporal_similarity(self, mac_a: str, mac_b: str) -> float:
        """
        Get temporal pattern similarity between two devices.

        Returns:
            Similarity score 0.0 - 1.0
        """
        pattern_a = self._temporal_patterns.get(mac_a.upper())
        pattern_b = self._temporal_patterns.get(mac_b.upper())

        if pattern_a and pattern_b:
            return pattern_a.similarity(pattern_b)
        return 0.0

    def _persist_relationships(self):
        """Persist relationships to SQLite and ClickHouse."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Ensure schema has new columns
                try:
                    conn.execute('ALTER TABLE device_relationships ADD COLUMN discovery_hits INTEGER DEFAULT 0')
                except sqlite3.OperationalError:
                    pass  # Column already exists
                try:
                    conn.execute('ALTER TABLE device_relationships ADD COLUMN temporal_sync REAL DEFAULT 0.0')
                except sqlite3.OperationalError:
                    pass  # Column already exists

                for key, rel in self.relationships.items():
                    affinity = rel.calculate_affinity_score()

                    # Persist to SQLite
                    conn.execute('''
                        INSERT OR REPLACE INTO device_relationships
                        (mac_a, mac_b, connection_count, total_bytes,
                         bidirectional_count, high_affinity_count,
                         services_json, first_seen, last_seen, affinity_score,
                         discovery_hits, temporal_sync)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rel.mac_a, rel.mac_b,
                        rel.connection_count, rel.total_bytes,
                        rel.bidirectional_count, rel.high_affinity_count,
                        json.dumps(rel.services_used),
                        rel.first_seen.isoformat() if rel.first_seen else None,
                        rel.last_seen.isoformat() if rel.last_seen else None,
                        affinity,
                        rel.discovery_hits,
                        rel.temporal_sync_score,
                    ))

                    # Also persist to ClickHouse for AI learning
                    if self._clickhouse_store:
                        self._clickhouse_store.record_relationship(
                            mac_a=rel.mac_a,
                            mac_b=rel.mac_b,
                            connection_count=rel.connection_count,
                            total_bytes=rel.total_bytes,
                            bidirectional_count=rel.bidirectional_count,
                            high_affinity_count=rel.high_affinity_count,
                            services=rel.services_used,
                            discovery_hits=rel.discovery_hits,
                            temporal_sync_score=rel.temporal_sync_score,
                            affinity_score=affinity,
                        )

                        # Also record affinity history for trend analysis
                        if affinity > 0.1:  # Only meaningful affinities
                            self._clickhouse_store.record_affinity_history(
                                mac_a=rel.mac_a,
                                mac_b=rel.mac_b,
                                affinity_score=affinity,
                                discovery_hits=rel.discovery_hits,
                                temporal_sync_score=rel.temporal_sync_score,
                                connection_count=rel.connection_count,
                            )

                conn.commit()

            # Flush ClickHouse buffer
            if self._clickhouse_store:
                self._clickhouse_store.flush()

        except Exception as e:
            logger.error(f"Failed to persist relationships: {e}")

    def load_relationships(self):
        """Load relationships from database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute('''
                    SELECT * FROM device_relationships
                    WHERE affinity_score > 0
                    ORDER BY affinity_score DESC
                ''').fetchall()

                for row in rows:
                    key = (row['mac_a'], row['mac_b'])
                    # Handle new columns that may not exist in old DB
                    discovery_hits = row['discovery_hits'] if 'discovery_hits' in row.keys() else 0
                    temporal_sync = row['temporal_sync'] if 'temporal_sync' in row.keys() else 0.0

                    self.relationships[key] = DeviceRelationship(
                        mac_a=row['mac_a'],
                        mac_b=row['mac_b'],
                        connection_count=row['connection_count'],
                        total_bytes=row['total_bytes'],
                        bidirectional_count=row['bidirectional_count'],
                        high_affinity_count=row['high_affinity_count'],
                        services_used=json.loads(row['services_json'] or '{}'),
                        first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
                        last_seen=datetime.fromisoformat(row['last_seen']) if row['last_seen'] else None,
                        discovery_hits=discovery_hits,
                        temporal_sync_score=temporal_sync,
                    )

                logger.debug(f"Loaded {len(self.relationships)} relationships from DB")
        except Exception as e:
            logger.warning(f"Failed to load relationships: {e}")

    def get_d2d_affinity_score(self, mac_a: str, mac_b: str) -> float:
        """
        Get D2D affinity score between two devices.

        This is the primary interface for the BehavioralClusteringEngine
        to incorporate D2D communication into clustering.

        Args:
            mac_a: First device MAC
            mac_b: Second device MAC

        Returns:
            Affinity score (0.0 - 1.0)
        """
        key = self._normalize_mac_pair(mac_a, mac_b)

        if key in self.relationships:
            return self.relationships[key].calculate_affinity_score()

        return 0.0

    def get_device_peers(self, mac: str) -> List[Tuple[str, float]]:
        """
        Get all devices that communicate with the given device.

        Args:
            mac: Device MAC address

        Returns:
            List of (peer_mac, affinity_score) tuples, sorted by affinity
        """
        mac = mac.upper()
        peers = []

        for key, rel in self.relationships.items():
            if mac in key:
                peer = key[1] if key[0] == mac else key[0]
                affinity = rel.calculate_affinity_score()
                if affinity >= self.AFFINITY_THRESHOLD:
                    peers.append((peer, affinity))

        return sorted(peers, key=lambda x: x[1], reverse=True)

    def find_d2d_clusters(self) -> List[D2DCluster]:
        """
        Find clusters of devices based on D2D communication.

        Uses a simple graph clustering approach:
        1. Build adjacency graph from relationships above threshold
        2. Find connected components
        3. Return clusters with affinity metrics

        Returns:
            List of D2DCluster objects
        """
        # Build adjacency list
        graph: Dict[str, Set[str]] = defaultdict(set)

        for key, rel in self.relationships.items():
            affinity = rel.calculate_affinity_score()
            if affinity >= self.AFFINITY_THRESHOLD:
                graph[key[0]].add(key[1])
                graph[key[1]].add(key[0])

        # Find connected components (BFS)
        visited = set()
        clusters = []

        for node in graph:
            if node in visited:
                continue

            # BFS to find component
            component = set()
            queue = [node]

            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)

                for neighbor in graph[current]:
                    if neighbor not in visited:
                        queue.append(neighbor)

            if len(component) >= 2:
                # Build affinity matrix for cluster
                affinity_matrix = {}
                total_affinity = 0
                count = 0
                services = defaultdict(int)

                for mac_a in component:
                    for mac_b in component:
                        if mac_a >= mac_b:
                            continue
                        key = self._normalize_mac_pair(mac_a, mac_b)
                        if key in self.relationships:
                            rel = self.relationships[key]
                            aff = rel.calculate_affinity_score()
                            affinity_matrix[(mac_a, mac_b)] = aff
                            total_affinity += aff
                            count += 1
                            for svc, cnt in rel.services_used.items():
                                services[svc] += cnt

                avg_affinity = total_affinity / count if count > 0 else 0
                primary_services = sorted(
                    services.keys(),
                    key=lambda x: services[x],
                    reverse=True
                )[:5]

                clusters.append(D2DCluster(
                    devices=component,
                    affinity_matrix=affinity_matrix,
                    avg_affinity=avg_affinity,
                    primary_services=primary_services,
                ))

        logger.info(f"Found {len(clusters)} D2D clusters")
        return clusters

    def classify_device(self, mac: str) -> Tuple[DeviceType, float]:
        """
        Classify a device as Personal/IoT/Infrastructure.

        Uses D2D communication patterns and OUI lookup.

        Args:
            mac: Device MAC address

        Returns:
            Tuple of (DeviceType, confidence)
        """
        mac = mac.upper()

        # Calculate D2D weight for this device
        d2d_weight = 0.0
        services = set()

        for key, rel in self.relationships.items():
            if mac in key:
                d2d_weight += rel.calculate_affinity_score()
                services.update(rel.services_used.keys())

        # Use the classification function
        return classify_device_type(
            mac=mac,
            d2d_connection_weight=d2d_weight,
            services=services
        )

    def get_bubble_suggestions(self, min_affinity: float = 0.4) -> List[Dict]:
        """
        Get bubble suggestions for the dashboard UI.

        Returns list of device pairs that should be in the same bubble,
        sorted by confidence.

        Args:
            min_affinity: Minimum affinity threshold for suggestions

        Returns:
            List of suggestion dicts with device pairs and reasons
        """
        suggestions = []

        for key, rel in self.relationships.items():
            suggestion = rel.get_bubble_suggestion()

            if suggestion['confidence'] >= min_affinity:
                # Add device info
                suggestion['mac_a'] = rel.mac_a
                suggestion['mac_b'] = rel.mac_b

                # Classify devices
                type_a, conf_a = self.classify_device(rel.mac_a)
                type_b, conf_b = self.classify_device(rel.mac_b)

                suggestion['device_type_a'] = type_a.value
                suggestion['device_type_b'] = type_b.value
                suggestion['type_confidence_a'] = round(conf_a, 2)
                suggestion['type_confidence_b'] = round(conf_b, 2)

                # Only suggest same bubble for personal devices
                if type_a == DeviceType.PERSONAL and type_b == DeviceType.PERSONAL:
                    suggestion['bubble_type'] = 'user'
                    suggestion['should_suggest'] = True
                elif type_a == DeviceType.IOT or type_b == DeviceType.IOT:
                    suggestion['bubble_type'] = 'iot'
                    # IoT devices go to IoT bubble, not user bubble
                    suggestion['should_suggest'] = False
                    suggestion['reason'] = "IoT device detected - suggest IoT bubble instead"
                else:
                    suggestion['bubble_type'] = 'unknown'

                suggestions.append(suggestion)

        # Sort by confidence (highest first)
        suggestions.sort(key=lambda x: x['confidence'], reverse=True)

        return suggestions

    def get_device_colors(self) -> Dict[str, str]:
        """
        Get color assignments for all devices based on type.

        Returns dict mapping MAC address to hex color.
        """
        colors = {}

        # Get all unique MACs
        all_macs = set()
        for key in self.relationships.keys():
            all_macs.add(key[0])
            all_macs.add(key[1])

        for mac in all_macs:
            device_type, _ = self.classify_device(mac)
            colors[mac] = device_type.color

        return colors

    def assign_bubble_colors(self) -> Dict[int, str]:
        """
        Assign colors to D2D clusters/bubbles with persistence.

        TRIO+ 2026-01-14: Colors are now persisted to SQLite to ensure
        consistency across restarts. Uses stable cluster ID based on
        sorted MAC addresses of core members.

        Returns dict mapping cluster index to hex color.
        """
        clusters = self.find_d2d_clusters()
        bubble_colors = {}

        # Load existing color assignments from database
        persisted_colors = self._load_persisted_colors()
        used_colors = set(persisted_colors.values())

        for i, cluster in enumerate(clusters):
            # Generate stable cluster ID from sorted MAC addresses
            cluster_id = self._generate_cluster_id(cluster.devices)

            # Check if this cluster already has a persisted color
            if cluster_id in persisted_colors:
                color = persisted_colors[cluster_id]
            else:
                # Find next available color not already in use
                for j in range(len(USER_BUBBLE_COLORS)):
                    candidate = get_user_bubble_color(j)
                    if candidate not in used_colors:
                        color = candidate
                        break
                else:
                    # All colors in use - use rotating index
                    color = get_user_bubble_color(i)

                # Persist the new color assignment
                self._persist_color(cluster_id, color, cluster.devices)

            used_colors.add(color)
            bubble_colors[i] = color

            # Update relationships with assigned color
            for mac_a in cluster.devices:
                for mac_b in cluster.devices:
                    if mac_a < mac_b:
                        key = self._normalize_mac_pair(mac_a, mac_b)
                        if key in self.relationships:
                            self.relationships[key].bubble_color = color

        return bubble_colors

    def _generate_cluster_id(self, devices: Set[str]) -> str:
        """
        Generate stable cluster ID from device MACs.

        Uses hash of sorted MACs to create a consistent identifier
        that survives restarts and device reordering.
        """
        import hashlib
        sorted_macs = sorted(devices)
        mac_string = ','.join(sorted_macs)
        return hashlib.sha256(mac_string.encode()).hexdigest()[:16]

    def _load_persisted_colors(self) -> Dict[str, str]:
        """Load persisted cluster colors from database."""
        colors = {}
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute(
                    'SELECT cluster_id, color FROM bubble_color_persistence'
                )
                for row in cursor:
                    colors[row[0]] = row[1]
        except Exception as e:
            logger.warning(f"Failed to load persisted colors: {e}")
        return colors

    def _persist_color(self, cluster_id: str, color: str, devices: Set[str]):
        """Persist cluster color assignment to database."""
        import json
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                now = datetime.now().isoformat()
                conn.execute('''
                    INSERT OR REPLACE INTO bubble_color_persistence
                    (cluster_id, color, device_macs_json, created_at, last_updated)
                    VALUES (?, ?, ?, COALESCE(
                        (SELECT created_at FROM bubble_color_persistence WHERE cluster_id = ?),
                        ?
                    ), ?)
                ''', (cluster_id, color, json.dumps(sorted(devices)),
                      cluster_id, now, now))
                conn.commit()
                logger.debug(f"Persisted color {color} for cluster {cluster_id[:8]}...")
        except Exception as e:
            logger.warning(f"Failed to persist color: {e}")

    def get_stats(self) -> Dict:
        """Get D2D graph statistics."""
        total_connections = sum(r.connection_count for r in self.relationships.values())
        high_affinity = sum(
            1 for r in self.relationships.values()
            if r.calculate_affinity_score() >= 0.5
        )

        # Temporal affinity stats
        temporal_pairs = sum(
            1 for r in self.relationships.values()
            if r.temporal_sync_score > 0.3
        )

        # Device type breakdown
        device_types = {'personal': 0, 'iot': 0, 'unknown': 0}
        all_macs = set()
        for key in self.relationships.keys():
            all_macs.add(key[0])
            all_macs.add(key[1])

        for mac in all_macs:
            dtype, _ = self.classify_device(mac)
            if dtype == DeviceType.PERSONAL:
                device_types['personal'] += 1
            elif dtype == DeviceType.IOT:
                device_types['iot'] += 1
            else:
                device_types['unknown'] += 1

        # Bubble suggestions count
        suggestions = self.get_bubble_suggestions(min_affinity=0.4)
        personal_suggestions = [s for s in suggestions if s.get('bubble_type') == 'user']

        return {
            'total_relationships': len(self.relationships),
            'total_connections': total_connections,
            'high_affinity_pairs': high_affinity,
            'unique_devices': len(all_macs),
            # Temporal stats
            'temporal_patterns_tracked': len(self._temporal_patterns),
            'temporal_high_affinity_pairs': temporal_pairs,
            'buffered_events': len(self._temporal_event_buffer),
            # Device classification
            'device_types': device_types,
            # Bubble suggestions
            'bubble_suggestions': len(personal_suggestions),
            'total_suggestions': len(suggestions),
        }


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_analyzer: Optional[ConnectionGraphAnalyzer] = None
_analyzer_lock = __import__('threading').Lock()


def get_connection_analyzer() -> ConnectionGraphAnalyzer:
    """Get the global ConnectionGraphAnalyzer instance."""
    global _analyzer

    with _analyzer_lock:
        if _analyzer is None:
            _analyzer = ConnectionGraphAnalyzer()
            _analyzer.load_relationships()
            _analyzer.load_temporal_patterns()
        return _analyzer


def analyze_d2d_connections():
    """
    Convenience function to run D2D analysis.

    Call periodically (e.g., every 5 minutes) to update relationships.
    """
    analyzer = get_connection_analyzer()
    analyzer.update_relationships()
    return analyzer.get_stats()


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='D2D Connection Graph Analyzer')
    parser.add_argument('command', choices=['analyze', 'clusters', 'stats', 'peers'])
    parser.add_argument('--mac', help='MAC address for peers command')
    args = parser.parse_args()

    analyzer = get_connection_analyzer()

    if args.command == 'analyze':
        analyzer.update_relationships()
        print(f"Analysis complete: {analyzer.get_stats()}")

    elif args.command == 'clusters':
        clusters = analyzer.find_d2d_clusters()
        for i, cluster in enumerate(clusters):
            print(f"\nCluster {i+1}:")
            print(f"  Devices: {cluster.devices}")
            print(f"  Avg Affinity: {cluster.avg_affinity:.2f}")
            print(f"  Services: {cluster.primary_services}")

    elif args.command == 'stats':
        stats = analyzer.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.command == 'peers':
        if not args.mac:
            print("Error: --mac required for peers command")
        else:
            peers = analyzer.get_device_peers(args.mac)
            print(f"Peers for {args.mac}:")
            for peer, affinity in peers:
                print(f"  {peer}: {affinity:.2f}")
