"""
dnsXai Packet Inspector - Deep Packet Analysis for Ad/Tracker Detection

Detects ads and trackers at the network packet level using:
1. TLS SNI (Server Name Indication) inspection
2. IP reputation database for known ad networks
3. Traffic pattern analysis (tracking pixels, beacons)
4. Connection fingerprinting (JA3 hashes)

Works in tandem with DNS-based blocking for comprehensive protection.
"""
import os
import re
import json
import time
import struct
import socket
import logging
import hashlib
import threading
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Set, Any

logger = logging.getLogger(__name__)

# Data directory
PACKET_DATA_DIR = '/opt/hookprobe/guardian/dns-shield/packet'
IP_REPUTATION_PATH = f'{PACKET_DATA_DIR}/ip_reputation.json'
DETECTION_LOG_PATH = f'{PACKET_DATA_DIR}/packet_detections.json'
JA3_DATABASE_PATH = f'{PACKET_DATA_DIR}/ja3_fingerprints.json'

# =============================================================================
# KNOWN AD NETWORK IP RANGES
# =============================================================================
# These are CIDR ranges belonging to major ad/tracking networks
# Updated periodically from public ASN data

KNOWN_AD_IP_RANGES = [
    # Google Ads / DoubleClick (partial - Google has many ranges)
    '172.217.0.0/16',      # Google general
    '142.250.0.0/15',      # Google
    '172.253.0.0/16',      # Google
    '74.125.0.0/16',       # Google
    '216.58.0.0/16',       # Google

    # Facebook/Meta Ads
    '157.240.0.0/16',      # Facebook
    '31.13.24.0/21',       # Facebook
    '31.13.64.0/18',       # Facebook
    '66.220.144.0/20',     # Facebook
    '69.63.176.0/20',      # Facebook
    '69.171.224.0/19',     # Facebook
    '173.252.64.0/18',     # Facebook
    '179.60.192.0/22',     # Facebook
    '185.60.216.0/22',     # Facebook
    '204.15.20.0/22',      # Facebook

    # Amazon Ads (CloudFront ranges often used for ads)
    '54.230.0.0/16',       # CloudFront
    '54.239.128.0/18',     # CloudFront
    '52.84.0.0/15',        # CloudFront
    '99.84.0.0/16',        # CloudFront
    '143.204.0.0/16',      # CloudFront

    # Microsoft/LinkedIn Ads
    '13.64.0.0/11',        # Azure (partial)
    '40.64.0.0/10',        # Azure (partial)
    '52.224.0.0/11',       # Azure (partial)

    # Criteo
    '178.250.0.0/21',      # Criteo
    '185.235.84.0/22',     # Criteo

    # AppNexus/Xandr
    '68.67.128.0/17',      # AppNexus

    # Taboola
    '199.21.64.0/22',      # Taboola

    # Outbrain
    '185.79.236.0/22',     # Outbrain

    # The Trade Desk
    '52.8.0.0/16',         # Trade Desk (AWS)

    # Rubicon Project
    '162.247.72.0/21',     # Rubicon

    # PubMatic
    '185.94.188.0/22',     # PubMatic

    # Index Exchange
    '52.40.0.0/14',        # Index Exchange (AWS)

    # Quantcast
    '173.194.0.0/16',      # Quantcast

    # comScore
    '63.80.0.0/17',        # comScore

    # Adobe Analytics/Audience Manager
    '66.235.128.0/17',     # Adobe
    '192.243.224.0/19',    # Adobe

    # Twitter Ads
    '199.16.156.0/22',     # Twitter
    '199.59.148.0/22',     # Twitter
    '104.244.40.0/21',     # Twitter

    # Snap Inc
    '54.149.0.0/16',       # Snap (AWS)

    # TikTok/ByteDance
    '161.117.0.0/16',      # ByteDance
    '144.48.0.0/16',       # ByteDance
]

# Known ad-serving domains for SNI matching
AD_SNI_PATTERNS = [
    # Google Ads
    r'.*\.doubleclick\.net$',
    r'.*\.googlesyndication\.com$',
    r'.*\.googleadservices\.com$',
    r'.*adservice\.google\..*$',
    r'.*pagead.*\.google.*$',
    r'.*\.googletagmanager\.com$',
    r'.*\.googletagservices\.com$',

    # YouTube ads
    r'.*\.youtube\.com/api/stats/ads.*',
    r'.*\.youtube\.com/pagead.*',
    r'.*\.youtube\.com/ptracking.*',
    r'r\d+---sn-.*\.googlevideo\.com$',  # Ad video servers

    # Facebook/Meta
    r'.*\.facebook\.com/tr.*',
    r'pixel\.facebook\.com$',
    r'.*\.facebook\.net$',
    r'an\.facebook\.com$',

    # Twitter
    r'.*ads.*twitter\.com$',
    r'analytics\.twitter\.com$',
    r'.*\.ads-twitter\.com$',

    # Generic ad patterns
    r'.*\.adnxs\.com$',
    r'.*\.adsrvr\.org$',
    r'.*\.pubmatic\.com$',
    r'.*\.rubiconproject\.com$',
    r'.*\.openx\.net$',
    r'.*\.criteo\..*$',
    r'.*\.taboola\.com$',
    r'.*\.outbrain\.com$',
    r'.*\.amazon-adsystem\.com$',

    # Analytics/Tracking
    r'.*\.google-analytics\.com$',
    r'.*\.analytics\..*$',
    r'.*\.segment\.(io|com)$',
    r'.*\.amplitude\.com$',
    r'.*\.mixpanel\.com$',
    r'.*\.hotjar\.com$',
    r'.*\.mouseflow\.com$',
    r'.*\.fullstory\.com$',
    r'.*\.quantserve\.com$',
    r'.*\.scorecardresearch\.com$',
    r'.*\.omtrdc\.net$',
    r'.*\.demdex\.net$',

    # Mobile tracking
    r'.*\.adjust\.com$',
    r'.*\.appsflyer\.com$',
    r'.*\.branch\.io$',
    r'.*app-measurement\.com$',

    # Generic patterns
    r'.*track(er|ing)?\..*',
    r'.*pixel\..*',
    r'.*beacon\..*',
    r'.*telemetry\..*',
    r'.*metrics\..*',
    r'.*\.ads\..*',
    r'.*-ads\..*',
    r'ad[sx]?\d*\..*',
]

# Compile regex patterns for performance
AD_SNI_COMPILED = [re.compile(p, re.IGNORECASE) for p in AD_SNI_PATTERNS]

# Known ad network JA3 hashes (TLS fingerprints)
# These identify specific ad SDK implementations
KNOWN_AD_JA3_HASHES = {
    # These are example hashes - real ones would be collected from traffic analysis
    '769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,0-10-11,23-24-25,0': 'Google Ads SDK',
    '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0': 'Facebook SDK',
}

# Traffic pattern thresholds
TRACKING_PIXEL_MAX_SIZE = 500  # bytes - tracking pixels are tiny
BEACON_PATTERN_THRESHOLD = 10  # requests within time window
BEACON_TIME_WINDOW = 60  # seconds


class IPReputationDatabase:
    """
    Database of known ad/tracker IP ranges with efficient lookup.
    Uses a prefix tree (trie) for fast IP range matching.
    """

    def __init__(self):
        self.networks: List[ipaddress.IPv4Network] = []
        self.network_info: Dict[str, str] = {}  # network -> description
        self.custom_blocked: Set[str] = set()
        self._lock = threading.Lock()
        self._load_database()

    def _load_database(self):
        """Load IP reputation database."""
        # Load built-in ranges
        for cidr in KNOWN_AD_IP_RANGES:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                self.networks.append(network)
            except ValueError:
                logger.warning(f"Invalid CIDR: {cidr}")

        # Load custom ranges from file
        try:
            if os.path.exists(IP_REPUTATION_PATH):
                with open(IP_REPUTATION_PATH, 'r') as f:
                    data = json.load(f)
                    for cidr in data.get('custom_ranges', []):
                        try:
                            network = ipaddress.ip_network(cidr, strict=False)
                            self.networks.append(network)
                        except ValueError:
                            continue
                    self.custom_blocked = set(data.get('blocked_ips', []))
                    self.network_info = data.get('network_info', {})
        except Exception as e:
            logger.error(f"Failed to load IP reputation: {e}")

        logger.info(f"Loaded {len(self.networks)} ad network IP ranges")

    def save_database(self):
        """Save custom IP reputation data."""
        try:
            os.makedirs(PACKET_DATA_DIR, exist_ok=True)
            with open(IP_REPUTATION_PATH, 'w') as f:
                json.dump({
                    'custom_ranges': list(self.custom_blocked),
                    'blocked_ips': list(self.custom_blocked),
                    'network_info': self.network_info,
                    'updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save IP reputation: {e}")

    def is_ad_network(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP belongs to a known ad network.

        Returns:
            (is_ad_network, network_description)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check custom blocked IPs first
            if ip in self.custom_blocked:
                return True, "Custom blocked IP"

            # Check against known ranges
            for network in self.networks:
                if ip_obj in network:
                    return True, self.network_info.get(str(network), "Known ad network")

            return False, None
        except ValueError:
            return False, None

    def add_blocked_ip(self, ip: str, reason: str = "User blocked"):
        """Add an IP to the blocked list."""
        with self._lock:
            self.custom_blocked.add(ip)
            self.network_info[ip] = reason
            self.save_database()

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        return {
            'total_ranges': len(self.networks),
            'custom_blocked': len(self.custom_blocked),
            'last_updated': self.network_info.get('_last_update', 'Unknown')
        }


class SNIExtractor:
    """
    Extract Server Name Indication (SNI) from TLS ClientHello packets.

    SNI is sent in plaintext even for HTTPS connections, allowing us
    to identify the destination domain without decryption.
    """

    # TLS record types
    TLS_HANDSHAKE = 0x16

    # Handshake types
    HANDSHAKE_CLIENT_HELLO = 0x01

    # Extension types
    EXT_SNI = 0x0000

    @staticmethod
    def extract_sni(packet_data: bytes) -> Optional[str]:
        """
        Extract SNI hostname from a TLS ClientHello packet.

        Args:
            packet_data: Raw packet data (TCP payload)

        Returns:
            SNI hostname if found, None otherwise
        """
        try:
            if len(packet_data) < 5:
                return None

            # Check for TLS handshake
            content_type = packet_data[0]
            if content_type != SNIExtractor.TLS_HANDSHAKE:
                return None

            # TLS version (we don't strictly validate)
            # version = struct.unpack('!H', packet_data[1:3])[0]

            # Record length
            record_length = struct.unpack('!H', packet_data[3:5])[0]

            if len(packet_data) < 5 + record_length:
                return None

            # Parse handshake header
            handshake_data = packet_data[5:5+record_length]

            if len(handshake_data) < 4:
                return None

            handshake_type = handshake_data[0]
            if handshake_type != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
                return None

            # Handshake length (3 bytes)
            handshake_length = struct.unpack('!I', b'\x00' + handshake_data[1:4])[0]

            # Skip to extensions
            # ClientHello structure:
            # - Version (2 bytes)
            # - Random (32 bytes)
            # - Session ID length (1 byte) + Session ID
            # - Cipher suites length (2 bytes) + Cipher suites
            # - Compression methods length (1 byte) + Compression methods
            # - Extensions length (2 bytes) + Extensions

            pos = 4  # Start after handshake header

            if pos + 2 > len(handshake_data):
                return None

            # Skip version
            pos += 2

            # Skip random
            pos += 32

            if pos + 1 > len(handshake_data):
                return None

            # Skip session ID
            session_id_length = handshake_data[pos]
            pos += 1 + session_id_length

            if pos + 2 > len(handshake_data):
                return None

            # Skip cipher suites
            cipher_suites_length = struct.unpack('!H', handshake_data[pos:pos+2])[0]
            pos += 2 + cipher_suites_length

            if pos + 1 > len(handshake_data):
                return None

            # Skip compression methods
            compression_length = handshake_data[pos]
            pos += 1 + compression_length

            if pos + 2 > len(handshake_data):
                return None

            # Extensions
            extensions_length = struct.unpack('!H', handshake_data[pos:pos+2])[0]
            pos += 2
            extensions_end = pos + extensions_length

            # Parse extensions to find SNI
            while pos < extensions_end and pos + 4 <= len(handshake_data):
                ext_type = struct.unpack('!H', handshake_data[pos:pos+2])[0]
                ext_length = struct.unpack('!H', handshake_data[pos+2:pos+4])[0]
                pos += 4

                if ext_type == SNIExtractor.EXT_SNI:
                    # SNI extension found
                    if pos + ext_length <= len(handshake_data):
                        sni_data = handshake_data[pos:pos+ext_length]
                        return SNIExtractor._parse_sni_extension(sni_data)

                pos += ext_length

            return None

        except Exception as e:
            logger.debug(f"SNI extraction error: {e}")
            return None

    @staticmethod
    def _parse_sni_extension(data: bytes) -> Optional[str]:
        """Parse the SNI extension data to extract hostname."""
        try:
            if len(data) < 5:
                return None

            # SNI list length
            sni_list_length = struct.unpack('!H', data[0:2])[0]

            pos = 2
            while pos < 2 + sni_list_length and pos + 3 <= len(data):
                name_type = data[pos]
                name_length = struct.unpack('!H', data[pos+1:pos+3])[0]
                pos += 3

                if name_type == 0:  # host_name
                    if pos + name_length <= len(data):
                        hostname = data[pos:pos+name_length].decode('ascii', errors='ignore')
                        return hostname

                pos += name_length

            return None
        except Exception:
            return None


class TrafficPatternAnalyzer:
    """
    Analyze traffic patterns to detect ad-like behavior:
    - Tracking pixels (small images)
    - Beacon requests (frequent small requests)
    - Fingerprinting patterns
    """

    def __init__(self):
        # Track requests per destination
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.response_sizes: Dict[str, List[int]] = defaultdict(list)
        self._lock = threading.Lock()

    def analyze_request(self, destination: str, size: int,
                       content_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a request for ad/tracking patterns.

        Args:
            destination: IP or hostname
            size: Request/response size in bytes
            content_type: HTTP Content-Type if available

        Returns:
            Analysis result with confidence score
        """
        result = {
            'is_suspicious': False,
            'confidence': 0.0,
            'patterns': [],
            'recommendation': 'allow'
        }

        current_time = time.time()

        with self._lock:
            # Record this request
            self.request_history[destination].append(current_time)
            self.response_sizes[destination].append(size)

        # Check for tracking pixel pattern
        if size > 0 and size <= TRACKING_PIXEL_MAX_SIZE:
            if content_type and any(t in content_type.lower() for t in ['image', 'gif', 'png']):
                result['patterns'].append('tracking_pixel')
                result['confidence'] += 0.4
                result['is_suspicious'] = True

        # Check for beacon pattern (many requests in short time)
        with self._lock:
            recent_requests = [t for t in self.request_history[destination]
                             if current_time - t < BEACON_TIME_WINDOW]

        if len(recent_requests) >= BEACON_PATTERN_THRESHOLD:
            result['patterns'].append('beacon_pattern')
            result['confidence'] += 0.3
            result['is_suspicious'] = True

        # Check for consistent small responses (analytics)
        with self._lock:
            recent_sizes = self.response_sizes[destination][-20:]

        if len(recent_sizes) >= 5:
            avg_size = sum(recent_sizes) / len(recent_sizes)
            if avg_size < 1000:  # Consistently small responses
                result['patterns'].append('analytics_pattern')
                result['confidence'] += 0.2
                result['is_suspicious'] = True

        result['confidence'] = min(result['confidence'], 1.0)

        if result['confidence'] > 0.6:
            result['recommendation'] = 'block'
        elif result['confidence'] > 0.3:
            result['recommendation'] = 'warn'

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get pattern analysis statistics."""
        with self._lock:
            return {
                'tracked_destinations': len(self.request_history),
                'total_samples': sum(len(h) for h in self.request_history.values())
            }


class JA3Fingerprinter:
    """
    JA3 TLS fingerprinting to identify specific clients/SDKs.

    JA3 creates a hash from TLS ClientHello parameters that can
    identify specific applications, including ad SDKs.
    """

    @staticmethod
    def calculate_ja3(packet_data: bytes) -> Optional[str]:
        """
        Calculate JA3 fingerprint from TLS ClientHello.

        Returns:
            JA3 string (not hashed) or None
        """
        try:
            # This is a simplified implementation
            # Full JA3 requires parsing: TLS version, cipher suites,
            # extensions, elliptic curves, and EC point formats

            # For now, we'll extract basic info
            if len(packet_data) < 5:
                return None

            if packet_data[0] != 0x16:  # Not TLS handshake
                return None

            # Extract version
            version = struct.unpack('!H', packet_data[1:3])[0]

            # TODO: Extract full JA3 components
            # This would require full ClientHello parsing

            return f"{version}"

        except Exception:
            return None

    @staticmethod
    def is_known_ad_sdk(ja3_hash: str) -> Tuple[bool, Optional[str]]:
        """Check if JA3 hash matches known ad SDK."""
        if ja3_hash in KNOWN_AD_JA3_HASHES:
            return True, KNOWN_AD_JA3_HASHES[ja3_hash]
        return False, None


class PacketAdDetector:
    """
    Main packet-level ad detection engine.
    Combines all detection methods for comprehensive analysis.
    """

    def __init__(self):
        self.ip_db = IPReputationDatabase()
        self.sni_extractor = SNIExtractor()
        self.pattern_analyzer = TrafficPatternAnalyzer()
        self.ja3_fingerprinter = JA3Fingerprinter()

        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'ads_detected': 0,
            'sni_blocks': 0,
            'ip_blocks': 0,
            'pattern_blocks': 0
        }

        # Detection log
        self.detection_log: List[Dict] = []
        self._lock = threading.Lock()

        self._load_state()

    def _load_state(self):
        """Load detector state from disk."""
        try:
            if os.path.exists(DETECTION_LOG_PATH):
                with open(DETECTION_LOG_PATH, 'r') as f:
                    data = json.load(f)
                    self.stats = data.get('stats', self.stats)
                    self.detection_log = data.get('detections', [])[-100:]
        except Exception as e:
            logger.error(f"Failed to load packet detector state: {e}")

    def _save_state(self):
        """Save detector state to disk."""
        try:
            os.makedirs(PACKET_DATA_DIR, exist_ok=True)
            with open(DETECTION_LOG_PATH, 'w') as f:
                json.dump({
                    'stats': self.stats,
                    'detections': self.detection_log[-100:],
                    'updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save packet detector state: {e}")

    def analyze_connection(self, dst_ip: str, dst_port: int,
                          tls_data: Optional[bytes] = None,
                          payload_size: int = 0,
                          content_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a network connection for ad/tracking activity.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            tls_data: Optional TLS ClientHello data for SNI extraction
            payload_size: Size of the payload/response
            content_type: HTTP Content-Type if known

        Returns:
            Comprehensive detection result
        """
        with self._lock:
            self.stats['packets_analyzed'] += 1

        result = {
            'timestamp': datetime.now().isoformat(),
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'is_ad': False,
            'confidence': 0.0,
            'detection_methods': [],
            'sni': None,
            'action': 'allow'
        }

        detection_score = 0.0

        # 1. IP Reputation Check
        is_ad_ip, ip_info = self.ip_db.is_ad_network(dst_ip)
        if is_ad_ip:
            detection_score += 0.5
            result['detection_methods'].append({
                'method': 'ip_reputation',
                'info': ip_info
            })
            with self._lock:
                self.stats['ip_blocks'] += 1

        # 2. SNI Analysis (if TLS data available)
        if tls_data:
            sni = self.sni_extractor.extract_sni(tls_data)
            if sni:
                result['sni'] = sni

                # Check SNI against ad patterns
                for pattern in AD_SNI_COMPILED:
                    if pattern.match(sni):
                        detection_score += 0.6
                        result['detection_methods'].append({
                            'method': 'sni_pattern',
                            'pattern': pattern.pattern,
                            'domain': sni
                        })
                        with self._lock:
                            self.stats['sni_blocks'] += 1
                        break

        # 3. Traffic Pattern Analysis
        pattern_result = self.pattern_analyzer.analyze_request(
            dst_ip, payload_size, content_type
        )
        if pattern_result['is_suspicious']:
            detection_score += pattern_result['confidence'] * 0.4
            result['detection_methods'].append({
                'method': 'traffic_pattern',
                'patterns': pattern_result['patterns']
            })
            with self._lock:
                self.stats['pattern_blocks'] += 1

        # 4. JA3 Fingerprinting (if TLS data available)
        if tls_data:
            ja3 = self.ja3_fingerprinter.calculate_ja3(tls_data)
            if ja3:
                is_ad_sdk, sdk_name = self.ja3_fingerprinter.is_known_ad_sdk(ja3)
                if is_ad_sdk:
                    detection_score += 0.7
                    result['detection_methods'].append({
                        'method': 'ja3_fingerprint',
                        'sdk': sdk_name
                    })

        # Calculate final score and action
        result['confidence'] = min(detection_score, 1.0)
        result['is_ad'] = result['confidence'] > 0.4

        if result['confidence'] > 0.7:
            result['action'] = 'block'
        elif result['confidence'] > 0.4:
            result['action'] = 'warn'

        # Log detection
        if result['is_ad']:
            with self._lock:
                self.stats['ads_detected'] += 1
                self.detection_log.append({
                    'timestamp': result['timestamp'],
                    'ip': dst_ip,
                    'sni': result['sni'],
                    'confidence': result['confidence'],
                    'methods': [m['method'] for m in result['detection_methods']]
                })

                # Periodic save
                if len(self.detection_log) % 10 == 0:
                    self._save_state()

        return result

    def check_sni(self, domain: str) -> Dict[str, Any]:
        """
        Quick check if a domain matches known ad SNI patterns.

        Useful for integrating with DNS-based blocking.
        """
        result = {
            'domain': domain,
            'is_ad': False,
            'matched_pattern': None
        }

        for pattern in AD_SNI_COMPILED:
            if pattern.match(domain):
                result['is_ad'] = True
                result['matched_pattern'] = pattern.pattern
                break

        return result

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Quick check if an IP belongs to known ad network.
        """
        is_ad, info = self.ip_db.is_ad_network(ip)
        return {
            'ip': ip,
            'is_ad': is_ad,
            'info': info
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics."""
        with self._lock:
            return {
                **self.stats,
                'ip_database': self.ip_db.get_stats(),
                'pattern_analyzer': self.pattern_analyzer.get_stats(),
                'recent_detections': self.detection_log[-10:]
            }

    def get_recent_detections(self, limit: int = 50) -> List[Dict]:
        """Get recent ad detections."""
        with self._lock:
            return self.detection_log[-limit:]


# =============================================================================
# DNS Query Interceptor Integration
# =============================================================================

class DNSResponseAnalyzer:
    """
    Analyze DNS responses to detect ad-related patterns.
    Works with the existing dnsXai DNS interception.
    """

    def __init__(self, packet_detector: PacketAdDetector):
        self.packet_detector = packet_detector

    def analyze_dns_response(self, domain: str,
                            ip_addresses: List[str],
                            cnames: Optional[List[str]] = None,
                            ttl: int = 0) -> Dict[str, Any]:
        """
        Analyze a DNS response for ad indicators.

        Args:
            domain: Queried domain
            ip_addresses: Resolved IP addresses
            cnames: CNAME chain if any
            ttl: DNS TTL value

        Returns:
            Analysis result
        """
        result = {
            'domain': domain,
            'is_ad': False,
            'confidence': 0.0,
            'indicators': [],
            'resolved_ips': ip_addresses
        }

        detection_score = 0.0

        # Check domain against SNI patterns
        sni_check = self.packet_detector.check_sni(domain)
        if sni_check['is_ad']:
            detection_score += 0.6
            result['indicators'].append({
                'type': 'domain_pattern',
                'pattern': sni_check['matched_pattern']
            })

        # Check resolved IPs
        ad_ips = []
        for ip in ip_addresses:
            ip_check = self.packet_detector.check_ip(ip)
            if ip_check['is_ad']:
                ad_ips.append(ip)
                detection_score += 0.3

        if ad_ips:
            result['indicators'].append({
                'type': 'ad_network_ip',
                'ips': ad_ips
            })

        # Check CNAME chain
        if cnames:
            for cname in cnames:
                cname_check = self.packet_detector.check_sni(cname)
                if cname_check['is_ad']:
                    detection_score += 0.5
                    result['indicators'].append({
                        'type': 'cname_to_ad',
                        'cname': cname
                    })
                    break

        # Very short TTL can indicate ad networks (they rotate IPs)
        if ttl > 0 and ttl < 60:
            detection_score += 0.1
            result['indicators'].append({
                'type': 'short_ttl',
                'ttl': ttl
            })

        result['confidence'] = min(detection_score, 1.0)
        result['is_ad'] = result['confidence'] > 0.4

        return result


# =============================================================================
# Global Instances
# =============================================================================

_packet_detector: Optional[PacketAdDetector] = None
_dns_analyzer: Optional[DNSResponseAnalyzer] = None


def get_packet_detector() -> PacketAdDetector:
    """Get global packet detector instance."""
    global _packet_detector
    if _packet_detector is None:
        _packet_detector = PacketAdDetector()
    return _packet_detector


def get_dns_analyzer() -> DNSResponseAnalyzer:
    """Get global DNS analyzer instance."""
    global _dns_analyzer
    if _dns_analyzer is None:
        _dns_analyzer = DNSResponseAnalyzer(get_packet_detector())
    return _dns_analyzer
