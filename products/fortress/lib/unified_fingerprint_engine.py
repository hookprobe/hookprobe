#!/usr/bin/env python3
"""
Unified Fingerprint Engine - SDN Autopilot Core

Combines all fingerprinting signals into a unified device identification system.
Target: 99% accuracy for device type, vendor, and category classification.

Signal Sources:
1. DHCP Option 55 Fingerprint (40%) - Device "DNA", hardest to spoof
2. MAC OUI Vendor (15%) - Manufacturer identification
3. Hostname Analysis (15%) - User-assigned name patterns
4. mDNS/Bonjour (10%) - Apple ecosystem, printers, IoT
5. JA3/TLS Fingerprint (10%) - TLS client characteristics
6. TCP/IP Stack (5%) - p0f-style OS detection
7. Fingerbank API (5%) - Cloud enrichment for unknowns

Architecture:
┌─────────────────────────────────────────────────────────────────┐
│                  UNIFIED FINGERPRINT ENGINE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │   DHCP   │  │   MAC    │  │ Hostname │  │   mDNS   │        │
│  │ Option55 │  │   OUI    │  │ Analysis │  │ Bonjour  │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│       └─────────────┴─────────────┴─────────────┘               │
│                           │                                      │
│                    ┌──────┴──────┐                              │
│                    │  Signal     │                              │
│                    │  Aggregator │                              │
│                    └──────┬──────┘                              │
│                           │                                      │
│              ┌────────────┴────────────┐                        │
│              ▼                         ▼                        │
│       ┌────────────┐            ┌────────────┐                  │
│       │ Rule-Based │            │ ML Classifier │               │
│       │ Classifier │            │  (XGBoost)    │               │
│       └──────┬─────┘            └──────┬───────┘                │
│              │                         │                        │
│              └───────────┬─────────────┘                        │
│                          ▼                                      │
│                   ┌────────────┐                                │
│                   │  Ensemble  │                                │
│                   │   Voter    │                                │
│                   └──────┬─────┘                                │
│                          │                                      │
│           ┌──────────────┼──────────────┐                       │
│           ▼              ▼              ▼                       │
│      High Conf     Low Conf      Unknown                        │
│       (>0.8)       (0.5-0.8)      (<0.5)                        │
│         │              │              │                         │
│         │              │              ▼                         │
│         │              │       ┌────────────┐                   │
│         │              │       │ Fingerbank │                   │
│         │              │       │    API     │                   │
│         │              │       └──────┬─────┘                   │
│         │              │              │                         │
│         └──────────────┴──────────────┘                         │
│                          │                                      │
│                    ┌─────┴─────┐                                │
│                    │  Policy   │                                │
│                    │ Assignment│                                │
│                    └───────────┘                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# Configuration
CONFIG_DIR = Path('/etc/hookprobe')
FINGERBANK_CONFIG = CONFIG_DIR / 'fingerbank.json'
DATA_DIR = Path('/var/lib/hookprobe')
ENGINE_DB = DATA_DIR / 'unified_fingerprint.db'

# Optional imports
try:
    from fingerbank import Fingerbank, get_fingerbank, DeviceInfo
    HAS_FINGERBANK = True
except ImportError:
    HAS_FINGERBANK = False

try:
    from ml_fingerprint_classifier import (
        MLFingerprintClassifier, get_ml_classifier,
        DeviceSignals, ClassificationResult
    )
    HAS_ML = True
except ImportError:
    HAS_ML = False

try:
    from ja3_fingerprint import JA3Fingerprinter, get_ja3_fingerprinter, JA3Result
    HAS_JA3 = True
except ImportError:
    HAS_JA3 = False

try:
    from mdns_resolver import MDNSResolver, resolve_premium_name
    HAS_MDNS = True
except ImportError:
    HAS_MDNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DeviceIdentity:
    """Complete device identity from all signals."""
    mac: str
    device_type: str = 'unknown'
    vendor: str = 'Unknown'
    category: str = 'unknown'
    os: str = 'Unknown'
    model: Optional[str] = None
    friendly_name: Optional[str] = None
    confidence: float = 0.0
    policy: str = 'quarantine'
    signals: Dict[str, Any] = field(default_factory=dict)
    classification_method: str = 'unknown'
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SignalData:
    """Collected signals for a device."""
    mac: str
    ip: Optional[str] = None
    dhcp_fingerprint: Optional[str] = None
    dhcp_vendor_class: Optional[str] = None
    hostname: Optional[str] = None
    mdns_services: List[str] = field(default_factory=list)
    mdns_model: Optional[str] = None
    ja3_hashes: List[str] = field(default_factory=list)
    user_agent: Optional[str] = None
    tcp_ttl: Optional[int] = None
    tcp_window_size: Optional[int] = None

    def to_dict(self) -> Dict:
        return asdict(self)


# =============================================================================
# FINGERBANK API CLIENT
# =============================================================================

class FingerbankAPIClient:
    """Client for Fingerbank API with rate limiting and caching."""

    API_URL = "https://api.fingerbank.org/api/v2"

    def __init__(self):
        self.api_key: Optional[str] = None
        self.enabled = False
        self.requests_today = 0
        self.daily_limit = 20  # Free tier ~600/month
        self._load_config()
        self._lock = threading.Lock()

    def _load_config(self):
        """Load API configuration."""
        if FINGERBANK_CONFIG.exists():
            try:
                with open(FINGERBANK_CONFIG) as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key')
                    self.enabled = config.get('enabled', False)
                    self.requests_today = config.get('requests_today', 0)

                    # Reset daily counter if new day
                    last_reset = config.get('last_reset', '')
                    today = datetime.now().strftime('%Y-%m-%d')
                    if last_reset != today:
                        self.requests_today = 0
                        self._save_config()
            except Exception as e:
                logger.debug(f"Could not load Fingerbank config: {e}")

    def _save_config(self):
        """Save API configuration."""
        try:
            config = {
                'api_key': self.api_key,
                'enabled': self.enabled,
                'requests_today': self.requests_today,
                'last_reset': datetime.now().strftime('%Y-%m-%d')
            }
            FINGERBANK_CONFIG.parent.mkdir(parents=True, exist_ok=True)
            with open(FINGERBANK_CONFIG, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.debug(f"Could not save Fingerbank config: {e}")

    def is_available(self) -> bool:
        """Check if API is available for queries."""
        return (
            self.enabled and
            self.api_key and
            HAS_REQUESTS and
            self.requests_today < self.daily_limit
        )

    def query(self, dhcp_fingerprint: str, mac: str,
              hostname: Optional[str] = None,
              vendor_class: Optional[str] = None) -> Optional[Dict]:
        """Query Fingerbank API for device identification."""
        if not self.is_available():
            return None

        with self._lock:
            try:
                url = f"{self.API_URL}/combinations/interrogate"
                params = {'key': self.api_key}
                data = {
                    'dhcp_fingerprint': dhcp_fingerprint,
                    'mac': mac[:8] if len(mac) >= 8 else mac,  # OUI only
                }
                if hostname:
                    data['hostname'] = hostname
                if vendor_class:
                    data['dhcp_vendor'] = vendor_class

                response = requests.post(url, params=params, json=data, timeout=5)
                self.requests_today += 1
                self._save_config()

                if response.status_code == 200:
                    result = response.json()
                    device = result.get('device', {})
                    score = result.get('score', 0)

                    if device:
                        return {
                            'name': device.get('name', 'Unknown'),
                            'parents': device.get('parents', []),
                            'score': score,
                            'confidence': min(0.95, score / 100),
                            'source': 'fingerbank_api'
                        }

                elif response.status_code == 429:
                    logger.warning("Fingerbank API rate limited")
                    self.requests_today = self.daily_limit  # Prevent further requests today

            except Exception as e:
                logger.debug(f"Fingerbank API error: {e}")

        return None


# =============================================================================
# UNIFIED FINGERPRINT ENGINE
# =============================================================================

class UnifiedFingerprintEngine:
    """
    Main engine for device fingerprinting and classification.

    Combines multiple signals and classifiers to achieve 99% accuracy.
    """

    # Signal weights for confidence calculation
    SIGNAL_WEIGHTS = {
        'dhcp_fingerprint': 0.40,
        'mac_oui': 0.15,
        'hostname': 0.15,
        'mdns': 0.10,
        'ja3': 0.10,
        'tcp_stack': 0.05,
        'fingerbank_api': 0.05,
    }

    # Policy assignment based on category and vendor
    CATEGORY_POLICIES = {
        'phone': 'normal',
        'tablet': 'normal',
        'laptop': 'full_access',
        'desktop': 'full_access',
        'smart_tv': 'internet_only',
        'streaming': 'internet_only',
        'gaming': 'internet_only',
        'voice_assistant': 'normal',
        'smart_hub': 'normal',
        'camera': 'lan_only',
        'printer': 'lan_only',
        'thermostat': 'lan_only',
        'iot': 'lan_only',
        'network': 'full_access',
        'server': 'full_access',
        'wearable': 'normal',
        'unknown': 'quarantine',
    }

    # Vendor trust levels (Apple and Raspberry Pi get elevated trust)
    TRUSTED_VENDORS = {
        'Apple': {'policy_boost': 'full_access', 'confidence_boost': 0.10},
        'Raspberry Pi': {'policy_boost': 'normal', 'confidence_boost': 0.05},
    }

    def __init__(self):
        # Initialize components
        self.fingerbank_api = FingerbankAPIClient()

        # Optional components
        self.fingerbank = get_fingerbank() if HAS_FINGERBANK else None
        self.ml_classifier = get_ml_classifier() if HAS_ML else None
        self.ja3_fingerprinter = get_ja3_fingerprinter() if HAS_JA3 else None

        # Cache
        self._cache: Dict[str, DeviceIdentity] = {}
        self._lock = threading.Lock()

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize unified fingerprint database."""
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(str(ENGINE_DB)) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS device_identifications (
                        mac TEXT PRIMARY KEY,
                        device_type TEXT,
                        vendor TEXT,
                        category TEXT,
                        os TEXT,
                        model TEXT,
                        friendly_name TEXT,
                        confidence REAL,
                        policy TEXT,
                        signals_json TEXT,
                        classification_method TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        identification_count INTEGER DEFAULT 1
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS identification_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT NOT NULL,
                        signals_json TEXT,
                        result_json TEXT,
                        timestamp TEXT
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_ident_mac ON device_identifications(mac)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_hist_mac ON identification_history(mac)')
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize engine database: {e}")

    def identify(self, signals: SignalData) -> DeviceIdentity:
        """
        Main entry point: Identify a device from collected signals.

        Returns DeviceIdentity with device type, vendor, category, and policy.
        """
        mac = signals.mac.upper()

        # Check cache first
        with self._lock:
            if mac in self._cache:
                cached = self._cache[mac]
                # Update if we have new signals
                if signals.dhcp_fingerprint and signals.dhcp_fingerprint != cached.signals.get('dhcp_fingerprint'):
                    pass  # Proceed with new identification
                else:
                    return cached

        # Collect all classification results
        results = []

        # 1. Rule-based Fingerbank classification (local)
        if self.fingerbank and signals.dhcp_fingerprint:
            fb_result = self._classify_fingerbank(signals)
            if fb_result:
                results.append(('fingerbank_local', fb_result))

        # 2. ML classification
        if self.ml_classifier:
            ml_result = self._classify_ml(signals)
            if ml_result:
                results.append(('ml_classifier', ml_result))

        # 3. Hostname pattern matching
        if signals.hostname:
            hostname_result = self._classify_hostname(signals)
            if hostname_result:
                results.append(('hostname', hostname_result))

        # 4. mDNS/Bonjour
        if signals.mdns_services or signals.mdns_model:
            mdns_result = self._classify_mdns(signals)
            if mdns_result:
                results.append(('mdns', mdns_result))

        # 5. JA3 TLS fingerprint
        if signals.ja3_hashes:
            ja3_result = self._classify_ja3(signals)
            if ja3_result:
                results.append(('ja3', ja3_result))

        # 6. Ensemble voting
        identity = self._ensemble_vote(mac, results, signals)

        # 7. If still low confidence, try Fingerbank API
        if identity.confidence < 0.5 and self.fingerbank_api.is_available():
            api_result = self._query_fingerbank_api(signals)
            if api_result:
                # Merge API result
                identity = self._merge_api_result(identity, api_result)

        # 8. Assign policy
        identity.policy = self._determine_policy(identity)

        # 9. Store result
        self._store_identification(identity, signals)

        # 10. Cache
        with self._lock:
            self._cache[mac] = identity

        return identity

    def _classify_fingerbank(self, signals: SignalData) -> Optional[Dict]:
        """Classify using local Fingerbank database."""
        if not self.fingerbank or not signals.dhcp_fingerprint:
            return None

        try:
            result = self.fingerbank.identify(
                signals.dhcp_fingerprint,
                signals.mac,
                signals.hostname,
                signals.dhcp_vendor_class
            )

            if result:
                return {
                    'device_type': result.get('name', 'Unknown'),
                    'vendor': result.get('vendor', 'Unknown'),
                    'category': result.get('category', 'unknown'),
                    'os': result.get('os', 'Unknown'),
                    'confidence': result.get('confidence', 0.5),
                }
        except Exception as e:
            logger.debug(f"Fingerbank classification error: {e}")

        return None

    def _classify_ml(self, signals: SignalData) -> Optional[Dict]:
        """Classify using ML model."""
        if not self.ml_classifier:
            return None

        try:
            # Convert to ML signals format
            ml_signals = DeviceSignals(
                mac=signals.mac,
                dhcp_fingerprint=signals.dhcp_fingerprint,
                dhcp_vendor_class=signals.dhcp_vendor_class,
                hostname=signals.hostname,
                mdns_services=signals.mdns_services,
                mdns_model=signals.mdns_model,
                ja3_hashes=signals.ja3_hashes,
                tcp_window_size=signals.tcp_window_size,
                tcp_ttl=signals.tcp_ttl,
            )

            result = self.ml_classifier.classify(ml_signals)

            return {
                'device_type': result.device_type,
                'vendor': result.vendor,
                'category': result.category,
                'os': result.os,
                'confidence': result.confidence,
            }
        except Exception as e:
            logger.debug(f"ML classification error: {e}")

        return None

    def _classify_hostname(self, signals: SignalData) -> Optional[Dict]:
        """Classify based on hostname patterns."""
        if not signals.hostname:
            return None

        hn = signals.hostname.lower()

        # Apple devices
        if 'iphone' in hn:
            return {'device_type': 'iPhone', 'vendor': 'Apple', 'category': 'phone', 'os': 'iOS', 'confidence': 0.85}
        if 'ipad' in hn:
            return {'device_type': 'iPad', 'vendor': 'Apple', 'category': 'tablet', 'os': 'iPadOS', 'confidence': 0.85}
        if 'macbook' in hn or 'mbp' in hn or 'mba' in hn:
            return {'device_type': 'MacBook', 'vendor': 'Apple', 'category': 'laptop', 'os': 'macOS', 'confidence': 0.85}
        if 'imac' in hn or 'mac-pro' in hn or 'mac-mini' in hn:
            return {'device_type': 'Mac', 'vendor': 'Apple', 'category': 'desktop', 'os': 'macOS', 'confidence': 0.85}
        if 'homepod' in hn:
            return {'device_type': 'HomePod', 'vendor': 'Apple', 'category': 'voice_assistant', 'os': 'audioOS', 'confidence': 0.90}
        if 'apple-tv' in hn or 'appletv' in hn:
            return {'device_type': 'Apple TV', 'vendor': 'Apple', 'category': 'streaming', 'os': 'tvOS', 'confidence': 0.90}

        # Samsung
        if 'galaxy' in hn:
            return {'device_type': 'Galaxy', 'vendor': 'Samsung', 'category': 'phone', 'os': 'Android', 'confidence': 0.80}
        if 'samsung' in hn:
            return {'device_type': 'Samsung Device', 'vendor': 'Samsung', 'category': 'unknown', 'os': 'Unknown', 'confidence': 0.70}

        # Google
        if 'pixel' in hn:
            return {'device_type': 'Pixel', 'vendor': 'Google', 'category': 'phone', 'os': 'Android', 'confidence': 0.85}
        if 'chromecast' in hn:
            return {'device_type': 'Chromecast', 'vendor': 'Google', 'category': 'streaming', 'os': 'Cast OS', 'confidence': 0.90}
        if 'google-home' in hn or 'nest' in hn:
            return {'device_type': 'Google Home', 'vendor': 'Google', 'category': 'voice_assistant', 'os': 'Cast OS', 'confidence': 0.85}

        # Amazon
        if 'echo' in hn or 'alexa' in hn:
            return {'device_type': 'Echo', 'vendor': 'Amazon', 'category': 'voice_assistant', 'os': 'Fire OS', 'confidence': 0.85}
        if 'fire-tv' in hn or 'firetv' in hn:
            return {'device_type': 'Fire TV', 'vendor': 'Amazon', 'category': 'streaming', 'os': 'Fire OS', 'confidence': 0.85}

        # Raspberry Pi
        if 'raspberry' in hn or 'raspberrypi' in hn:
            return {'device_type': 'Raspberry Pi', 'vendor': 'Raspberry Pi', 'category': 'server', 'os': 'Linux', 'confidence': 0.85}

        # Printers
        if 'printer' in hn or 'laserjet' in hn or 'officejet' in hn:
            return {'device_type': 'Printer', 'vendor': 'Unknown', 'category': 'printer', 'os': 'Embedded', 'confidence': 0.75}

        return None

    def _classify_mdns(self, signals: SignalData) -> Optional[Dict]:
        """Classify based on mDNS/Bonjour services."""
        if not signals.mdns_services:
            return None

        services_str = ' '.join(signals.mdns_services).lower()

        # Apple ecosystem
        if '_airplay' in services_str or '_raop' in services_str:
            return {'device_type': 'Apple Device', 'vendor': 'Apple', 'category': 'unknown', 'os': 'Apple OS', 'confidence': 0.75}
        if '_homekit' in services_str:
            return {'device_type': 'HomeKit Device', 'vendor': 'Apple', 'category': 'smart_hub', 'os': 'Unknown', 'confidence': 0.80}
        if '_companion-link' in services_str:
            return {'device_type': 'Apple Device', 'vendor': 'Apple', 'category': 'unknown', 'os': 'Apple OS', 'confidence': 0.75}

        # Google
        if '_googlecast' in services_str:
            return {'device_type': 'Google Cast', 'vendor': 'Google', 'category': 'streaming', 'os': 'Cast OS', 'confidence': 0.80}

        # Printers
        if '_printer' in services_str or '_ipp' in services_str:
            return {'device_type': 'Printer', 'vendor': 'Unknown', 'category': 'printer', 'os': 'Embedded', 'confidence': 0.80}

        # Use model if available
        if signals.mdns_model:
            model = signals.mdns_model.lower()
            if 'iphone' in model:
                return {'device_type': signals.mdns_model, 'vendor': 'Apple', 'category': 'phone', 'os': 'iOS', 'confidence': 0.95}
            if 'ipad' in model:
                return {'device_type': signals.mdns_model, 'vendor': 'Apple', 'category': 'tablet', 'os': 'iPadOS', 'confidence': 0.95}
            if 'macbook' in model:
                return {'device_type': signals.mdns_model, 'vendor': 'Apple', 'category': 'laptop', 'os': 'macOS', 'confidence': 0.95}

        return None

    def _classify_ja3(self, signals: SignalData) -> Optional[Dict]:
        """Classify based on JA3 TLS fingerprints."""
        if not self.ja3_fingerprinter or not signals.ja3_hashes:
            return None

        for ja3_hash in signals.ja3_hashes:
            info = self.ja3_fingerprinter.lookup_ja3(ja3_hash)
            if info:
                return {
                    'device_type': info.get('app', 'Unknown'),
                    'vendor': 'Unknown',
                    'category': 'unknown',
                    'os': info.get('os', 'Unknown'),
                    'confidence': info.get('confidence', 0.5),
                }

        return None

    def _ensemble_vote(self, mac: str, results: List[Tuple[str, Dict]],
                       signals: SignalData) -> DeviceIdentity:
        """Combine multiple classification results using weighted voting."""
        if not results:
            return DeviceIdentity(
                mac=mac,
                confidence=0.1,
                classification_method='none',
                signals=signals.to_dict()
            )

        # Vote by category
        category_votes: Dict[str, float] = {}
        vendor_votes: Dict[str, float] = {}
        os_votes: Dict[str, float] = {}
        device_type_votes: Dict[str, float] = {}

        best_result = None
        best_confidence = 0.0

        for method, result in results:
            weight = self.SIGNAL_WEIGHTS.get(method.split('_')[0], 0.1)
            confidence = result.get('confidence', 0.5)
            weighted_score = weight * confidence

            # Accumulate votes
            cat = result.get('category', 'unknown')
            if cat != 'unknown':
                category_votes[cat] = category_votes.get(cat, 0) + weighted_score

            vendor = result.get('vendor', 'Unknown')
            if vendor != 'Unknown':
                vendor_votes[vendor] = vendor_votes.get(vendor, 0) + weighted_score

            os_val = result.get('os', 'Unknown')
            if os_val != 'Unknown':
                os_votes[os_val] = os_votes.get(os_val, 0) + weighted_score

            device = result.get('device_type', 'unknown')
            if device != 'unknown':
                device_type_votes[device] = device_type_votes.get(device, 0) + weighted_score

            # Track best result
            if confidence > best_confidence:
                best_confidence = confidence
                best_result = result

        # Determine winners
        def get_winner(votes: Dict[str, float]) -> Tuple[str, float]:
            if not votes:
                return 'unknown', 0.0
            winner = max(votes, key=votes.get)
            return winner, votes[winner]

        final_category, cat_score = get_winner(category_votes)
        final_vendor, vendor_score = get_winner(vendor_votes)
        final_os, os_score = get_winner(os_votes)
        final_device_type, device_score = get_winner(device_type_votes)

        # Calculate overall confidence
        total_score = cat_score + vendor_score + os_score + device_score
        overall_confidence = min(0.95, total_score / 2)  # Normalize

        # Use best result for device type if no clear winner
        if final_device_type == 'unknown' and best_result:
            final_device_type = best_result.get('device_type', 'unknown')

        return DeviceIdentity(
            mac=mac,
            device_type=final_device_type if final_device_type != 'unknown' else 'Unknown Device',
            vendor=final_vendor if final_vendor != 'unknown' else 'Unknown',
            category=final_category,
            os=final_os if final_os != 'unknown' else 'Unknown',
            confidence=overall_confidence,
            classification_method='ensemble',
            signals=signals.to_dict()
        )

    def _query_fingerbank_api(self, signals: SignalData) -> Optional[Dict]:
        """Query Fingerbank API for unknown devices."""
        if not signals.dhcp_fingerprint:
            return None

        return self.fingerbank_api.query(
            signals.dhcp_fingerprint,
            signals.mac,
            signals.hostname,
            signals.dhcp_vendor_class
        )

    def _merge_api_result(self, identity: DeviceIdentity, api_result: Dict) -> DeviceIdentity:
        """Merge Fingerbank API result with existing identity."""
        if not api_result:
            return identity

        # Update if API result has higher confidence
        api_confidence = api_result.get('confidence', 0)
        if api_confidence > identity.confidence:
            parents = api_result.get('parents', [])
            name = api_result.get('name', 'Unknown')

            identity.device_type = name
            identity.vendor = parents[0] if parents else identity.vendor
            identity.confidence = api_confidence
            identity.classification_method = 'fingerbank_api'

            # Infer category from name/parents
            identity.category = self._infer_category(name, parents)

        return identity

    def _infer_category(self, name: str, parents: List[str]) -> str:
        """Infer device category from name and parents."""
        combined = f"{name} {' '.join(parents)}".lower()

        categories = {
            'phone': ['phone', 'iphone', 'android', 'galaxy', 'pixel', 'smartphone'],
            'tablet': ['tablet', 'ipad', 'tab'],
            'laptop': ['laptop', 'macbook', 'notebook', 'thinkpad', 'chromebook'],
            'desktop': ['desktop', 'imac', 'mac pro', 'workstation', 'pc'],
            'smart_tv': ['tv', 'television', 'tizen', 'webos', 'roku tv'],
            'streaming': ['roku', 'chromecast', 'fire tv', 'apple tv', 'shield'],
            'gaming': ['playstation', 'xbox', 'nintendo', 'switch', 'ps4', 'ps5'],
            'voice_assistant': ['echo', 'alexa', 'google home', 'homepod', 'sonos'],
            'printer': ['printer', 'laserjet', 'officejet'],
            'camera': ['camera', 'ring', 'nest cam', 'arlo', 'wyze'],
            'smart_hub': ['hub', 'bridge', 'smartthings', 'hue bridge'],
            'thermostat': ['thermostat', 'nest', 'ecobee'],
            'iot': ['iot', 'sensor', 'plug', 'switch', 'light'],
            'network': ['router', 'access point', 'switch', 'unifi'],
            'server': ['server', 'nas', 'synology', 'qnap'],
            'wearable': ['watch', 'fitbit', 'band'],
        }

        for category, keywords in categories.items():
            if any(kw in combined for kw in keywords):
                return category

        return 'unknown'

    def _determine_policy(self, identity: DeviceIdentity) -> str:
        """Determine network policy based on identity."""
        # Check vendor trust first
        if identity.vendor in self.TRUSTED_VENDORS:
            trust_info = self.TRUSTED_VENDORS[identity.vendor]
            if identity.confidence >= 0.75:
                # Apple management devices (MacBook, iPad) get full access
                if identity.vendor == 'Apple' and identity.category in ('laptop', 'tablet', 'desktop'):
                    return 'full_access'
                # Other Apple devices get normal
                if identity.vendor == 'Apple':
                    return 'normal'
                return trust_info['policy_boost']

        # Category-based policy
        policy = self.CATEGORY_POLICIES.get(identity.category, 'quarantine')

        # Require minimum confidence for elevated access
        if identity.confidence < 0.5:
            return 'quarantine'
        elif identity.confidence < 0.7 and policy == 'full_access':
            return 'normal'

        return policy

    def _store_identification(self, identity: DeviceIdentity, signals: SignalData):
        """Store identification result in database."""
        try:
            with sqlite3.connect(str(ENGINE_DB)) as conn:
                now = datetime.now().isoformat()

                # Upsert main record
                conn.execute('''
                    INSERT INTO device_identifications
                    (mac, device_type, vendor, category, os, model, friendly_name,
                     confidence, policy, signals_json, classification_method,
                     first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        device_type = excluded.device_type,
                        vendor = excluded.vendor,
                        category = excluded.category,
                        os = excluded.os,
                        confidence = MAX(confidence, excluded.confidence),
                        policy = excluded.policy,
                        signals_json = excluded.signals_json,
                        classification_method = excluded.classification_method,
                        last_seen = excluded.last_seen,
                        identification_count = identification_count + 1
                ''', (
                    identity.mac,
                    identity.device_type,
                    identity.vendor,
                    identity.category,
                    identity.os,
                    identity.model,
                    identity.friendly_name,
                    identity.confidence,
                    identity.policy,
                    json.dumps(identity.signals),
                    identity.classification_method,
                    now,
                    now
                ))

                # Store history
                conn.execute('''
                    INSERT INTO identification_history
                    (mac, signals_json, result_json, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (
                    identity.mac,
                    json.dumps(signals.to_dict()),
                    json.dumps(identity.to_dict()),
                    now
                ))

                conn.commit()
        except Exception as e:
            logger.error(f"Could not store identification: {e}")

    def get_stats(self) -> Dict:
        """Get engine statistics."""
        stats = {
            'fingerbank_local': HAS_FINGERBANK,
            'ml_classifier': HAS_ML,
            'ja3_fingerprinter': HAS_JA3,
            'mdns_resolver': HAS_MDNS,
            'fingerbank_api_enabled': self.fingerbank_api.enabled,
            'fingerbank_api_requests_today': self.fingerbank_api.requests_today,
            'cached_devices': len(self._cache),
            'total_identifications': 0,
        }

        try:
            with sqlite3.connect(str(ENGINE_DB)) as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM device_identifications')
                stats['total_identifications'] = cursor.fetchone()[0]
        except Exception:
            pass

        return stats


# =============================================================================
# SINGLETON
# =============================================================================

_engine_instance: Optional[UnifiedFingerprintEngine] = None
_engine_lock = threading.Lock()


def get_fingerprint_engine() -> UnifiedFingerprintEngine:
    """Get singleton fingerprint engine instance."""
    global _engine_instance

    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = UnifiedFingerprintEngine()
        return _engine_instance


# =============================================================================
# DAEMON MODE - Continuous Device Monitoring
# =============================================================================

class FingerprintDaemon:
    """
    Daemon that monitors for new devices and applies fingerprinting.

    Watches:
    - DHCP lease file for new/changed leases
    - OVS bridge for new MAC addresses
    - Runs periodic scans for device updates
    """

    def __init__(self, engine: UnifiedFingerprintEngine):
        self.engine = engine
        self.running = False
        self.lease_file = Path('/var/lib/misc/dnsmasq.leases')
        self.lease_mtime = 0
        self.known_macs: set = set()
        self._stop_event = threading.Event()

    def start(self):
        """Start the daemon main loop."""
        import signal
        import time

        self.running = True
        logger.info("Fingerprint daemon starting...")

        # Handle signals for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Initial scan
        self._scan_dhcp_leases()
        self._scan_ovs_macs()

        logger.info("Fingerprint daemon started - monitoring for new devices")

        while self.running and not self._stop_event.is_set():
            try:
                # Check for DHCP lease changes
                if self.lease_file.exists():
                    current_mtime = self.lease_file.stat().st_mtime
                    if current_mtime > self.lease_mtime:
                        self.lease_mtime = current_mtime
                        self._scan_dhcp_leases()

                # Periodic OVS MAC scan (every 30 seconds)
                self._scan_ovs_macs()

                # Wait before next iteration
                self._stop_event.wait(timeout=30)

            except Exception as e:
                logger.error(f"Daemon loop error: {e}")
                time.sleep(5)

        logger.info("Fingerprint daemon stopped")

    def stop(self):
        """Stop the daemon."""
        self.running = False
        self._stop_event.set()

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def _scan_dhcp_leases(self):
        """Parse dnsmasq lease file for device info."""
        if not self.lease_file.exists():
            return

        try:
            with open(self.lease_file, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        # Format: timestamp mac ip hostname [client-id]
                        mac = parts[1].upper()
                        hostname = parts[3] if parts[3] != '*' else None

                        if mac not in self.known_macs:
                            self.known_macs.add(mac)
                            self._fingerprint_device(mac, hostname=hostname)

        except Exception as e:
            logger.error(f"Failed to parse DHCP leases: {e}")

    def _scan_ovs_macs(self):
        """Scan OVS bridge for MAC addresses."""
        import subprocess

        try:
            # Get MAC addresses from OVS FDB
            result = subprocess.run(
                ['ovs-appctl', 'fdb/show', 'FTS'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = parts[1].upper()
                        # Skip broadcast, multicast, and local MACs
                        if mac.startswith('FF:') or mac.startswith('01:'):
                            continue
                        if mac not in self.known_macs:
                            self.known_macs.add(mac)
                            self._fingerprint_device(mac)
        except subprocess.TimeoutExpired:
            logger.warning("OVS FDB query timed out")
        except FileNotFoundError:
            pass  # ovs-appctl not available
        except Exception as e:
            logger.debug(f"OVS scan error: {e}")

    def _fingerprint_device(self, mac: str, hostname: str = None):
        """Fingerprint a newly discovered device."""
        try:
            signals = SignalData(mac=mac, hostname=hostname)
            identity = self.engine.identify(signals)

            logger.info(
                f"Device identified: {mac} → {identity.device_type} "
                f"({identity.vendor}) [{identity.confidence:.0%}] "
                f"→ policy: {identity.policy}"
            )

        except Exception as e:
            logger.error(f"Failed to fingerprint {mac}: {e}")


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse
    import signal
    import time

    parser = argparse.ArgumentParser(description='Unified Fingerprint Engine')
    parser.add_argument('--daemon', action='store_true',
                        help='Run as daemon (monitoring mode)')
    subparsers = parser.add_subparsers(dest='command')

    # Identify
    identify_parser = subparsers.add_parser('identify', help='Identify a device')
    identify_parser.add_argument('--mac', required=True, help='MAC address')
    identify_parser.add_argument('--dhcp', help='DHCP Option 55 fingerprint')
    identify_parser.add_argument('--hostname', help='Hostname')
    identify_parser.add_argument('--vendor-class', help='DHCP vendor class')

    # Stats
    subparsers.add_parser('stats', help='Show engine statistics')

    args = parser.parse_args()

    # Handle daemon mode - run as a service that keeps the engine ready
    if args.daemon:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        engine = get_fingerprint_engine()
        logging.info("Unified Fingerprint Engine started in daemon mode")
        logging.info(f"Engine ready - ML model: {'loaded' if engine.ml_model else 'not available'}")
        logging.info(f"Fingerbank API: {'configured' if engine.fingerbank_api_key else 'not configured'}")

        # Signal handler for graceful shutdown
        running = True
        def handle_signal(signum, frame):
            nonlocal running
            logging.info(f"Received signal {signum}, shutting down...")
            running = False

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

        # Main daemon loop - keep engine warm and log periodic stats
        stats_interval = 300  # Log stats every 5 minutes
        last_stats = time.time()

        while running:
            try:
                time.sleep(10)

                # Periodic stats logging
                if time.time() - last_stats >= stats_interval:
                    stats = engine.get_stats()
                    logging.info(f"Stats: {stats.get('total_identifications', 0)} identifications, "
                                f"cache hit rate: {stats.get('cache_hit_rate', 0):.1%}")
                    last_stats = time.time()

            except Exception as e:
                logging.error(f"Error in daemon loop: {e}")
                time.sleep(30)

        logging.info("Unified Fingerprint Engine stopped")
        return

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    try:
        engine = get_fingerprint_engine()
    except Exception as e:
        logging.error(f"Failed to initialize fingerprint engine: {e}")
        import traceback
        traceback.print_exc()
        return 1

    if args.daemon:
        # Run as daemon
        try:
            logging.info("Unified Fingerprint Engine started in daemon mode")
            logging.info(f"  ML classifier: {'loaded' if engine.ml_classifier else 'not available'}")
            logging.info(f"  Fingerbank API: {'configured' if engine.fingerbank_api else 'not configured'}")
            logging.info(f"  OUI database: {len(engine.oui_db)} entries")
            daemon = FingerprintDaemon(engine)
            daemon.start()
        except Exception as e:
            logging.error(f"Daemon failed: {e}")
            import traceback
            traceback.print_exc()
            return 1

    elif args.command == 'identify':
        signals = SignalData(
            mac=args.mac,
            dhcp_fingerprint=args.dhcp,
            hostname=args.hostname,
            dhcp_vendor_class=args.vendor_class
        )

        identity = engine.identify(signals)

        print("\nDevice Identification Result:")
        print(f"  MAC:         {identity.mac}")
        print(f"  Device Type: {identity.device_type}")
        print(f"  Vendor:      {identity.vendor}")
        print(f"  Category:    {identity.category}")
        print(f"  OS:          {identity.os}")
        print(f"  Confidence:  {identity.confidence:.1%}")
        print(f"  Policy:      {identity.policy}")
        print(f"  Method:      {identity.classification_method}")

    elif args.command == 'stats':
        stats = engine.get_stats()
        print("\nUnified Fingerprint Engine Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    else:
        parser.print_help()
        return 0

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
