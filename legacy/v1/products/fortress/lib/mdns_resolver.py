#!/usr/bin/env python3
"""
mDNS/Bonjour Resolver for Premium Device Identification

This module resolves "friendly names" like "John's Apple Watch" from
network devices using mDNS (Multicast DNS) / Bonjour protocols.

Apple devices broadcast their user-set names via mDNS, which gives us
the premium touch for our SDN Auto Pilot - showing "Sarah's iPhone"
instead of just "iPhone" or "Apple Device".

Techniques Used:
1. Reverse mDNS Lookup (avahi-resolve -a IP)
2. mDNS Service Browser (_apple-mobdev2._tcp, _airplay._tcp, etc.)
3. Name cleaning and normalization

Requirements:
- avahi-utils package (apt install avahi-utils)
- avahi-daemon running on host
- Network access to mDNS multicast (224.0.0.251:5353)

Author: HookProbe Team
License: AGPL v3.0
"""

import subprocess
import re
import logging
import sqlite3
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
import threading
import time

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class MDNSIdentity:
    """Result from mDNS identity resolution."""
    friendly_name: Optional[str]  # "John's Apple Watch"
    mdns_hostname: Optional[str]  # "Johns-Apple-Watch.local"
    services: List[str]           # ["_airplay._tcp", "_apple-mobdev2._tcp"]
    confidence: float             # 0.0 - 1.0
    source: str                   # "avahi-resolve", "service-browser", "cache"
    timestamp: datetime


@dataclass
class ConsolidatedIdentity:
    """Final identity after consolidating all sources."""
    display_name: str             # "John's Apple Watch" (premium name)
    technical_name: str           # "Apple Watch Series 9"
    vendor: str                   # "Apple"
    device_type: str              # "wearable"
    confidence: float             # 0.0 - 1.0
    sources: Dict[str, float]     # {"mdns": 0.60, "dhcp": 0.30, "oui": 0.10}


# =============================================================================
# APPLE SERVICE TYPES (for mDNS browsing)
# =============================================================================

APPLE_MDNS_SERVICES = {
    # Core Apple services
    "_apple-mobdev2._tcp": {"type": "apple_device", "weight": 0.95},
    "_airplay._tcp": {"type": "streaming", "weight": 0.90},
    "_raop._tcp": {"type": "audio", "weight": 0.85},  # Remote Audio Output
    "_homekit._tcp": {"type": "smart_home", "weight": 0.90},
    "_hap._tcp": {"type": "homekit", "weight": 0.90},  # HomeKit Accessory
    "_companion-link._tcp": {"type": "apple_watch", "weight": 0.95},
    "_sleep-proxy._udp": {"type": "apple_tv", "weight": 0.85},

    # Printer services
    "_ipp._tcp": {"type": "printer", "weight": 0.80},
    "_ipps._tcp": {"type": "printer", "weight": 0.80},
    "_pdl-datastream._tcp": {"type": "printer", "weight": 0.75},

    # Smart speaker services
    "_googlecast._tcp": {"type": "google_home", "weight": 0.90},
    "_spotify-connect._tcp": {"type": "speaker", "weight": 0.70},
    "_sonos._tcp": {"type": "sonos", "weight": 0.95},

    # General services
    "_http._tcp": {"type": "web", "weight": 0.30},
    "_ssh._tcp": {"type": "server", "weight": 0.50},
    "_smb._tcp": {"type": "file_share", "weight": 0.40},
    "_afpovertcp._tcp": {"type": "mac_file_share", "weight": 0.70},
}


# =============================================================================
# NAME CLEANING PATTERNS
# =============================================================================

# Patterns to detect possessive forms
POSSESSIVE_PATTERNS = [
    (r"(\w+)s-", r"\1's "),           # "Johns-" → "John's "
    (r"(\w+)-s-", r"\1's "),          # "John-s-" → "John's "
    (r"(\w+)'s-", r"\1's "),          # "John's-" → "John's "
]

# Device type suffixes to preserve
DEVICE_SUFFIXES = [
    "iPhone", "iPad", "MacBook", "MacBook-Pro", "MacBook-Air",
    "iMac", "Mac-Mini", "Mac-Pro", "Apple-Watch", "Apple-TV",
    "HomePod", "AirPods", "AirPods-Pro", "AirPods-Max",
]


# =============================================================================
# MDNS RESOLVER CLASS
# =============================================================================

class MDNSResolver:
    """
    Premium mDNS resolver for friendly device names.

    Uses avahi-utils to resolve human-readable names from devices
    on the local network via mDNS/Bonjour.
    """

    def __init__(self, cache_db: Optional[str] = None, cache_ttl: int = 3600):
        """
        Initialize mDNS resolver.

        Args:
            cache_db: Path to SQLite cache database
            cache_ttl: Cache TTL in seconds (default: 1 hour)
        """
        self.cache_ttl = cache_ttl
        self.cache_db = cache_db or "/var/lib/hookprobe/mdns_cache.db"
        self._init_cache()
        self._lock = threading.Lock()

    def _init_cache(self):
        """Initialize the mDNS cache database."""
        try:
            Path(self.cache_db).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.cache_db) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS mdns_cache (
                        ip TEXT PRIMARY KEY,
                        mac TEXT,
                        friendly_name TEXT,
                        mdns_hostname TEXT,
                        services TEXT,
                        confidence REAL,
                        source TEXT,
                        updated_at TEXT
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_mac ON mdns_cache(mac)
                """)
        except Exception as e:
            logger.warning(f"Failed to init mDNS cache: {e}")

    # =========================================================================
    # CORE RESOLUTION METHODS
    # =========================================================================

    def resolve(self, ip: str, mac: Optional[str] = None,
                timeout: float = 2.0) -> MDNSIdentity:
        """
        Resolve friendly name for an IP address via mDNS.

        Args:
            ip: IP address to resolve
            mac: Optional MAC address for cache lookup
            timeout: Timeout in seconds

        Returns:
            MDNSIdentity with resolution result
        """
        # 1. Check cache first
        cached = self._get_cached(ip, mac)
        if cached:
            return cached

        # 2. Try avahi-resolve (reverse DNS lookup)
        hostname = self._avahi_resolve(ip, timeout)

        # 3. Try service browsing for more info
        services = self._browse_services(ip, timeout)

        # 4. Build result
        friendly_name = None
        confidence = 0.0
        source = "none"

        if hostname:
            friendly_name = self._clean_hostname(hostname)
            confidence = 0.85 if "'" in friendly_name else 0.70
            source = "avahi-resolve"
        elif services:
            # Extract name from service if possible
            for svc in services:
                if svc.get('name'):
                    friendly_name = self._clean_hostname(svc['name'])
                    confidence = 0.75
                    source = "service-browser"
                    break

        result = MDNSIdentity(
            friendly_name=friendly_name,
            mdns_hostname=hostname,
            services=[s.get('type', '') for s in services],
            confidence=confidence,
            source=source,
            timestamp=datetime.now()
        )

        # 5. Cache result
        if friendly_name or services:
            self._cache_result(ip, mac, result)

        return result

    def _avahi_resolve(self, ip: str, timeout: float = 2.0) -> Optional[str]:
        """
        Resolve IP to hostname using avahi-resolve.

        Returns: Hostname like "Johns-Apple-Watch.local" or None
        """
        try:
            result = subprocess.run(
                ["avahi-resolve", "-a", ip],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0 and result.stdout.strip():
                # Output: "10.200.0.4\tJohns-Apple-Watch.local"
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[-1]
                    # Remove .local suffix
                    if hostname.endswith('.local'):
                        hostname = hostname[:-6]
                    return hostname

        except subprocess.TimeoutExpired:
            logger.debug(f"mDNS resolve timeout for {ip}")
        except FileNotFoundError:
            logger.warning("avahi-resolve not found. Install avahi-utils.")
        except Exception as e:
            logger.debug(f"mDNS resolve error for {ip}: {e}")

        return None

    def _browse_services(self, ip: str, timeout: float = 2.0) -> List[Dict]:
        """
        Browse mDNS services advertised by an IP.

        Returns: List of service dicts with name, type, port
        """
        services = []

        try:
            # Use avahi-browse to find services
            result = subprocess.run(
                ["avahi-browse", "-a", "-r", "-t", "-p"],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith('=') and ip in line:
                        # Parse avahi-browse output
                        # Format: =;interface;protocol;name;type;domain;host;ip;port;txt
                        parts = line.split(';')
                        if len(parts) >= 8:
                            services.append({
                                'name': parts[3],
                                'type': parts[4],
                                'host': parts[6],
                                'port': parts[8] if len(parts) > 8 else None
                            })

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            logger.debug("avahi-browse not found")
        except Exception as e:
            logger.debug(f"Service browse error: {e}")

        return services

    # =========================================================================
    # NAME CLEANING
    # =========================================================================

    def _clean_hostname(self, hostname: str) -> str:
        """
        Clean mDNS hostname to friendly display name.

        Converts: "Johns-Apple-Watch" → "John's Apple Watch"
        """
        if not hostname:
            return ""

        name = hostname

        # Apply possessive patterns
        for pattern, replacement in POSSESSIVE_PATTERNS:
            name = re.sub(pattern, replacement, name, flags=re.IGNORECASE)

        # Replace remaining hyphens with spaces (except in device names)
        # First, protect device suffixes
        protected = {}
        for suffix in DEVICE_SUFFIXES:
            if suffix in name:
                placeholder = f"__DEVICE_{len(protected)}__"
                protected[placeholder] = suffix.replace("-", " ")
                name = name.replace(suffix, placeholder)

        # Replace hyphens with spaces
        name = name.replace("-", " ")

        # Restore protected device names
        for placeholder, original in protected.items():
            name = name.replace(placeholder, original)

        # Title case, but preserve Apple product names
        words = name.split()
        result = []
        for word in words:
            if word.lower() in ['iphone', 'ipad', 'imac', 'ipod', 'ios']:
                result.append('i' + word[1:].capitalize())
            elif word.lower() == 'macbook':
                result.append('MacBook')
            elif word.lower() == 'airpods':
                result.append('AirPods')
            elif word.lower() == 'homepod':
                result.append('HomePod')
            elif word.lower() == 'appletv':
                result.append('Apple TV')
            elif word.lower() == 'applewatch':
                result.append('Apple Watch')
            else:
                result.append(word.capitalize())

        return " ".join(result)

    # =========================================================================
    # CACHE OPERATIONS
    # =========================================================================

    def _get_cached(self, ip: str, mac: Optional[str]) -> Optional[MDNSIdentity]:
        """Get cached mDNS result if still valid."""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                cursor = conn.execute("""
                    SELECT friendly_name, mdns_hostname, services, confidence,
                           source, updated_at
                    FROM mdns_cache
                    WHERE ip = ? OR mac = ?
                    ORDER BY updated_at DESC
                    LIMIT 1
                """, (ip, mac or ""))

                row = cursor.fetchone()
                if row:
                    updated = datetime.fromisoformat(row[5])
                    if datetime.now() - updated < timedelta(seconds=self.cache_ttl):
                        return MDNSIdentity(
                            friendly_name=row[0],
                            mdns_hostname=row[1],
                            services=row[2].split(',') if row[2] else [],
                            confidence=row[3],
                            source="cache",
                            timestamp=updated
                        )
        except Exception as e:
            logger.debug(f"Cache lookup error: {e}")

        return None

    def _cache_result(self, ip: str, mac: Optional[str], result: MDNSIdentity):
        """Cache mDNS resolution result."""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO mdns_cache
                    (ip, mac, friendly_name, mdns_hostname, services,
                     confidence, source, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    mac or "",
                    result.friendly_name,
                    result.mdns_hostname,
                    ','.join(result.services),
                    result.confidence,
                    result.source,
                    result.timestamp.isoformat()
                ))
        except Exception as e:
            logger.debug(f"Cache write error: {e}")


# =============================================================================
# IDENTITY CONSOLIDATOR
# =============================================================================

class IdentityConsolidator:
    """
    Consolidates identity from multiple sources with weighted scoring.

    Sources and their weights:
    - mDNS/Bonjour:     60% (most reliable for friendly names)
    - DHCP Hostname:    25% (often generic or missing)
    - DHCP Fingerprint: 10% (device type identification)
    - MAC OUI:           5% (vendor only)
    """

    # Default weights for identity sources
    WEIGHTS = {
        'mdns': 0.60,        # mDNS friendly name (highest value)
        'dhcp_hostname': 0.25,  # DHCP hostname
        'fingerprint': 0.10,    # DHCP fingerprint device type
        'oui': 0.05,            # MAC OUI vendor
    }

    def __init__(self, mdns_resolver: Optional[MDNSResolver] = None):
        self.mdns = mdns_resolver or MDNSResolver()

    def consolidate(self, ip: str, mac: str,
                    dhcp_hostname: Optional[str] = None,
                    device_type: Optional[str] = None,
                    vendor: Optional[str] = None,
                    fingerbank_confidence: float = 0.0) -> ConsolidatedIdentity:
        """
        Consolidate identity from all available sources.

        Args:
            ip: Device IP address
            mac: Device MAC address
            dhcp_hostname: Hostname from DHCP (Option 12)
            device_type: Device type from fingerprinting
            vendor: Vendor from OUI lookup
            fingerbank_confidence: Confidence from Fingerbank

        Returns:
            ConsolidatedIdentity with best available name
        """
        sources = {}
        candidates = []

        # 1. Try mDNS resolution (highest weight)
        mdns_result = self.mdns.resolve(ip, mac)
        if mdns_result.friendly_name:
            weight = self.WEIGHTS['mdns'] * mdns_result.confidence
            sources['mdns'] = weight
            candidates.append((mdns_result.friendly_name, weight, 'mdns'))

        # 2. Use DHCP hostname
        if dhcp_hostname and dhcp_hostname.lower() not in ('', '*', 'localhost', 'unknown', 'none'):
            cleaned = self._clean_dhcp_hostname(dhcp_hostname)
            weight = self.WEIGHTS['dhcp_hostname']
            # Boost if hostname looks personalized
            if any(c in cleaned for c in ["'s", "s "]):
                weight *= 1.2
            sources['dhcp_hostname'] = weight
            candidates.append((cleaned, weight, 'dhcp'))

        # 3. Use fingerprint device type
        if device_type and device_type != 'unknown':
            weight = self.WEIGHTS['fingerprint'] * fingerbank_confidence
            sources['fingerprint'] = weight
            candidates.append((device_type, weight, 'fingerprint'))

        # 4. Use OUI vendor as fallback
        if vendor and vendor not in ('Unknown', 'Randomized MAC'):
            weight = self.WEIGHTS['oui']
            sources['oui'] = weight
            candidates.append((f"{vendor} Device", weight, 'oui'))

        # Select best candidate
        if candidates:
            candidates.sort(key=lambda x: x[1], reverse=True)
            display_name = candidates[0][0]
            total_confidence = sum(sources.values())
        else:
            display_name = "Unknown Device"
            total_confidence = 0.0

        # Determine technical name
        technical_name = device_type or "Unknown"
        if vendor and vendor not in ('Unknown', 'Randomized MAC'):
            technical_name = f"{vendor} {device_type or 'Device'}"

        return ConsolidatedIdentity(
            display_name=display_name,
            technical_name=technical_name,
            vendor=vendor or "Unknown",
            device_type=device_type or "unknown",
            confidence=min(1.0, total_confidence),
            sources=sources
        )

    def _clean_dhcp_hostname(self, hostname: str) -> str:
        """Clean DHCP hostname to friendly format."""
        if not hostname:
            return ""

        name = hostname

        # Apply possessive patterns
        for pattern, replacement in POSSESSIVE_PATTERNS:
            name = re.sub(pattern, replacement, name, flags=re.IGNORECASE)

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
            else:
                result.append(word.capitalize())

        return " ".join(result)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def resolve_premium_name(ip: str, mac: str,
                         dhcp_hostname: Optional[str] = None) -> str:
    """
    Resolve the best available name for a device.

    This is the main entry point for premium name resolution.

    Args:
        ip: Device IP address
        mac: Device MAC address
        dhcp_hostname: Optional DHCP hostname

    Returns:
        Best available friendly name (e.g., "John's Apple Watch")
    """
    resolver = MDNSResolver()

    # 1. Try mDNS first
    mdns = resolver.resolve(ip, mac)
    if mdns.friendly_name:
        return mdns.friendly_name

    # 2. Clean DHCP hostname
    if dhcp_hostname and dhcp_hostname.lower() not in ('', '*', 'none', 'unknown'):
        consolidator = IdentityConsolidator(resolver)
        cleaned = consolidator._clean_dhcp_hostname(dhcp_hostname)
        return cleaned

    # 3. Fallback
    return "Unknown Device"


def get_friendly_name(ip: str) -> Optional[str]:
    """
    Quick mDNS lookup for friendly name.

    Compatible with the simple API pattern in SDN Auto Pilot.

    Args:
        ip: IP address to resolve

    Returns:
        Friendly name or None
    """
    try:
        resolver = MDNSResolver()
        result = resolver.resolve(ip)
        return result.friendly_name
    except Exception as e:
        logger.debug(f"Friendly name lookup failed: {e}")
        return None


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python mdns_resolver.py <ip_address> [mac_address]")
        print("\nExample:")
        print("  python mdns_resolver.py 10.200.0.4")
        print("  python mdns_resolver.py 10.200.0.4 40:ED:CF:82:62:6B")
        sys.exit(1)

    ip = sys.argv[1]
    mac = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"\n{'='*60}")
    print(f"mDNS Resolution for {ip}")
    print(f"{'='*60}\n")

    resolver = MDNSResolver()
    result = resolver.resolve(ip, mac)

    print(f"Friendly Name: {result.friendly_name or '(none)'}")
    print(f"mDNS Hostname: {result.mdns_hostname or '(none)'}")
    print(f"Services:      {', '.join(result.services) or '(none)'}")
    print(f"Confidence:    {result.confidence:.2f}")
    print(f"Source:        {result.source}")

    # If we have a DHCP hostname to consolidate
    if len(sys.argv) > 3:
        dhcp_hostname = sys.argv[3]
        print(f"\n{'='*60}")
        print(f"Identity Consolidation")
        print(f"{'='*60}\n")

        consolidator = IdentityConsolidator(resolver)
        identity = consolidator.consolidate(
            ip=ip,
            mac=mac or "00:00:00:00:00:00",
            dhcp_hostname=dhcp_hostname,
            device_type="phone",
            vendor="Apple"
        )

        print(f"Display Name:   {identity.display_name}")
        print(f"Technical Name: {identity.technical_name}")
        print(f"Vendor:         {identity.vendor}")
        print(f"Device Type:    {identity.device_type}")
        print(f"Confidence:     {identity.confidence:.2f}")
        print(f"Sources:        {identity.sources}")
