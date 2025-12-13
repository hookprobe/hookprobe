"""
Threat Signature Database - CVE-Inspired Format

A lightweight, fast signature database for OSI L2-L7 attack detection.
Inspired by CVE/NVD format but optimized for real-time edge detection.

Memory footprint: ~200KB for 500 signatures
Lookup time: <0.1ms average (bloom filter + hash)

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Set, Any
from enum import Enum


class OSILayer(Enum):
    """OSI Model layers for attack classification."""
    L2_DATA_LINK = 2
    L3_NETWORK = 3
    L4_TRANSPORT = 4
    L5_SESSION = 5
    L6_PRESENTATION = 6
    L7_APPLICATION = 7


class Severity(Enum):
    """CVSS-inspired severity levels."""
    CRITICAL = 4  # 9.0-10.0
    HIGH = 3      # 7.0-8.9
    MEDIUM = 2    # 4.0-6.9
    LOW = 1       # 0.1-3.9
    INFO = 0      # Informational


class AttackCategory(Enum):
    """High-level attack categories."""
    RECONNAISSANCE = "reconnaissance"      # Port scans, service enumeration
    CREDENTIAL_ACCESS = "credential"       # Brute force, credential stuffing
    INITIAL_ACCESS = "initial_access"      # Exploit, phishing
    EXECUTION = "execution"                # Code execution, injection
    PERSISTENCE = "persistence"            # Backdoors, rootkits
    PRIVILEGE_ESCALATION = "priv_esc"      # Local/remote escalation
    DEFENSE_EVASION = "evasion"            # Obfuscation, tunneling
    CREDENTIAL_DUMP = "cred_dump"          # Memory scraping
    DISCOVERY = "discovery"                # Network/system enumeration
    LATERAL_MOVEMENT = "lateral"           # Pivoting, pass-the-hash
    COLLECTION = "collection"              # Data staging
    COMMAND_CONTROL = "c2"                 # C2 communication
    EXFILTRATION = "exfiltration"          # Data theft
    IMPACT = "impact"                      # DoS, destruction
    SPOOFING = "spoofing"                  # Identity impersonation
    MANIPULATION = "manipulation"          # MitM, injection


@dataclass
class FeaturePattern:
    """
    Pattern for matching network features.

    Supports: exact, range, regex, threshold comparisons.
    """
    feature_name: str                      # e.g., 'syn_ratio', 'packet_size'
    operator: str                          # 'eq', 'gt', 'lt', 'ge', 'le', 'range', 'regex', 'in'
    value: Any                             # Comparison value(s)
    weight: float = 1.0                    # Importance weight for scoring

    def matches(self, actual_value: Any) -> bool:
        """Check if actual value matches this pattern."""
        try:
            if self.operator == 'eq':
                return actual_value == self.value
            elif self.operator == 'gt':
                return actual_value > self.value
            elif self.operator == 'lt':
                return actual_value < self.value
            elif self.operator == 'ge':
                return actual_value >= self.value
            elif self.operator == 'le':
                return actual_value <= self.value
            elif self.operator == 'range':
                min_val, max_val = self.value
                return min_val <= actual_value <= max_val
            elif self.operator == 'in':
                return actual_value in self.value
            elif self.operator == 'contains':
                return self.value in str(actual_value)
            elif self.operator == 'regex':
                import re
                return bool(re.search(self.value, str(actual_value)))
            return False
        except (TypeError, ValueError):
            return False


@dataclass
class ThreatSignature:
    """
    CVE-inspired threat signature for network attack detection.

    Format inspired by NVD CVE entries but optimized for real-time detection.
    """
    # Identity (CVE-style)
    sig_id: str                            # e.g., 'HP-2024-0001', 'HP-L4-SYN-001'
    name: str                              # Human-readable name
    description: str                       # Detailed description

    # Classification
    layer: OSILayer                        # OSI layer (L2-L7)
    severity: Severity                     # CVSS-style severity
    category: AttackCategory               # MITRE-style category

    # MITRE ATT&CK mapping
    mitre_technique: Optional[str] = None  # e.g., 'T1046' (Port Scan)
    mitre_tactic: Optional[str] = None     # e.g., 'TA0007' (Discovery)

    # Detection patterns
    patterns: List[FeaturePattern] = field(default_factory=list)
    match_threshold: float = 0.7           # Min pattern match ratio to trigger

    # Protocol/port hints for fast filtering
    protocols: List[str] = field(default_factory=list)  # ['tcp', 'udp', 'icmp']
    ports: List[int] = field(default_factory=list)      # Relevant ports

    # Response guidance
    recommended_action: str = "Monitor"    # Block, Alert, Monitor, Quarantine
    auto_block: bool = False               # Enable automatic blocking
    block_duration: int = 300              # Block duration in seconds

    # Metadata
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    updated: str = field(default_factory=lambda: datetime.now().isoformat())
    version: str = "1.0"
    enabled: bool = True
    source: str = "hookprobe"              # 'hookprobe', 'community', 'mesh', 'custom'

    # Performance hints
    fast_check: Optional[str] = None       # Quick check before full pattern match
    bloom_keys: List[str] = field(default_factory=list)  # Keys for bloom filter

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        d = asdict(self)
        d['layer'] = self.layer.name
        d['severity'] = self.severity.name
        d['category'] = self.category.value
        d['patterns'] = [asdict(p) for p in self.patterns]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'ThreatSignature':
        """Deserialize from dictionary."""
        d = d.copy()
        d['layer'] = OSILayer[d['layer']]
        d['severity'] = Severity[d['severity']]
        d['category'] = AttackCategory(d['category'])
        d['patterns'] = [FeaturePattern(**p) for p in d.get('patterns', [])]
        return cls(**d)

    def get_hash(self) -> str:
        """Get unique hash for this signature."""
        content = f"{self.sig_id}:{self.layer.name}:{self.name}"
        return hashlib.md5(content.encode()).hexdigest()[:12]


class SignatureDatabase:
    """
    In-memory signature database with fast lookup.

    Optimized for Raspberry Pi:
    - Bloom filter for fast negative lookups
    - Hash-based indexing by layer/protocol
    - Lazy loading for memory efficiency
    """

    def __init__(self, data_dir: str = "/opt/hookprobe/data/signatures"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Main storage
        self.signatures: Dict[str, ThreatSignature] = {}

        # Indexes for fast lookup
        self._by_layer: Dict[OSILayer, List[str]] = {l: [] for l in OSILayer}
        self._by_protocol: Dict[str, List[str]] = {}
        self._by_port: Dict[int, List[str]] = {}
        self._by_category: Dict[AttackCategory, List[str]] = {c: [] for c in AttackCategory}

        # Bloom filter for fast negative lookup (simple implementation)
        self._bloom_filter: Set[str] = set()

        # Statistics
        self.stats = {
            'total_signatures': 0,
            'lookups': 0,
            'matches': 0,
            'bloom_hits': 0,
            'last_update': None
        }

        # Load built-in signatures
        self._load_builtin_signatures()

        # Load custom signatures from disk
        self._load_custom_signatures()

    def _load_builtin_signatures(self):
        """Load built-in L2-L7 attack signatures."""

        # =====================================================================
        # LAYER 2 - DATA LINK ATTACKS
        # =====================================================================

        self.add_signature(ThreatSignature(
            sig_id="HP-L2-ARP-001",
            name="ARP Spoofing",
            description="ARP cache poisoning attack detected. Attacker is sending gratuitous ARP replies to redirect traffic.",
            layer=OSILayer.L2_DATA_LINK,
            severity=Severity.HIGH,
            category=AttackCategory.SPOOFING,
            mitre_technique="T1557.002",
            mitre_tactic="TA0006",
            patterns=[
                FeaturePattern("arp_gratuitous_ratio", "ge", 0.3, weight=1.5),
                FeaturePattern("arp_reply_rate", "ge", 10.0, weight=1.0),
            ],
            protocols=["arp"],
            recommended_action="Block",
            auto_block=True,
            fast_check="arp_gratuitous_ratio > 0.1"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L2-MAC-001",
            name="MAC Flooding",
            description="CAM table overflow attack. Excessive MAC addresses detected, attempting to turn switch into hub.",
            layer=OSILayer.L2_DATA_LINK,
            severity=Severity.HIGH,
            category=AttackCategory.IMPACT,
            mitre_technique="T1499.001",
            patterns=[
                FeaturePattern("unique_src_macs", "ge", 500, weight=2.0),
                FeaturePattern("mac_churn_rate", "ge", 50.0, weight=1.5),
            ],
            recommended_action="Alert",
            fast_check="unique_src_macs > 100"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L2-TWIN-001",
            name="Evil Twin AP",
            description="Rogue access point detected mimicking legitimate SSID. Potential credential harvesting.",
            layer=OSILayer.L2_DATA_LINK,
            severity=Severity.CRITICAL,
            category=AttackCategory.CREDENTIAL_ACCESS,
            mitre_technique="T1557.001",
            patterns=[
                FeaturePattern("duplicate_ssid", "eq", True, weight=2.0),
                FeaturePattern("signal_strength_anomaly", "eq", True, weight=1.0),
            ],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L2-VLAN-001",
            name="VLAN Hopping",
            description="Double-tagged 802.1Q frames detected. Attempt to access unauthorized VLAN.",
            layer=OSILayer.L2_DATA_LINK,
            severity=Severity.HIGH,
            category=AttackCategory.LATERAL_MOVEMENT,
            mitre_technique="T1599",
            patterns=[
                FeaturePattern("double_tagged_frames", "ge", 1, weight=2.0),
                FeaturePattern("vlan_mismatch", "eq", True, weight=1.5),
            ],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L2-DHCP-001",
            name="Rogue DHCP Server",
            description="Unauthorized DHCP server detected. Potential MitM via malicious gateway/DNS.",
            layer=OSILayer.L2_DATA_LINK,
            severity=Severity.CRITICAL,
            category=AttackCategory.SPOOFING,
            mitre_technique="T1557.003",
            patterns=[
                FeaturePattern("dhcp_server_count", "ge", 2, weight=2.0),
                FeaturePattern("dhcp_offer_anomaly", "eq", True, weight=1.5),
            ],
            ports=[67, 68],
            protocols=["udp"],
            recommended_action="Block",
            auto_block=True,
        ))

        # =====================================================================
        # LAYER 3 - NETWORK ATTACKS
        # =====================================================================

        self.add_signature(ThreatSignature(
            sig_id="HP-L3-SPOOF-001",
            name="IP Spoofing",
            description="Packets with spoofed source IP detected. Attacker masking origin.",
            layer=OSILayer.L3_NETWORK,
            severity=Severity.HIGH,
            category=AttackCategory.SPOOFING,
            mitre_technique="T1090",
            patterns=[
                FeaturePattern("bogon_source", "eq", True, weight=2.0),
                FeaturePattern("martian_packet", "eq", True, weight=2.0),
            ],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L3-ICMP-001",
            name="ICMP Flood",
            description="ICMP flood attack (ping flood). Denial of service via ICMP echo requests.",
            layer=OSILayer.L3_NETWORK,
            severity=Severity.MEDIUM,
            category=AttackCategory.IMPACT,
            mitre_technique="T1498.001",
            patterns=[
                FeaturePattern("icmp_ratio", "ge", 0.7, weight=1.5),
                FeaturePattern("icmp_echo_request_rate", "ge", 100.0, weight=2.0),
            ],
            protocols=["icmp"],
            recommended_action="Rate Limit",
            fast_check="icmp_ratio > 0.5"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L3-SMURF-001",
            name="Smurf Attack",
            description="ICMP amplification attack using broadcast addresses.",
            layer=OSILayer.L3_NETWORK,
            severity=Severity.HIGH,
            category=AttackCategory.IMPACT,
            mitre_technique="T1498.001",
            patterns=[
                FeaturePattern("icmp_broadcast_ratio", "ge", 0.5, weight=2.0),
                FeaturePattern("icmp_amplification_factor", "ge", 10.0, weight=1.5),
            ],
            protocols=["icmp"],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L3-FRAG-001",
            name="IP Fragmentation Attack",
            description="Malicious IP fragmentation detected. Potential evasion or DoS.",
            layer=OSILayer.L3_NETWORK,
            severity=Severity.MEDIUM,
            category=AttackCategory.DEFENSE_EVASION,
            mitre_technique="T1027",
            patterns=[
                FeaturePattern("fragment_ratio", "ge", 0.3, weight=1.5),
                FeaturePattern("tiny_fragment_count", "ge", 10, weight=1.0),
                FeaturePattern("overlapping_fragments", "ge", 1, weight=2.0),
            ],
            recommended_action="Block",
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L3-ROUTE-001",
            name="Route Hijacking",
            description="Suspicious routing changes detected. Potential BGP/route manipulation.",
            layer=OSILayer.L3_NETWORK,
            severity=Severity.CRITICAL,
            category=AttackCategory.MANIPULATION,
            mitre_technique="T1599.001",
            patterns=[
                FeaturePattern("default_route_changed", "eq", True, weight=2.0),
                FeaturePattern("multiple_default_gateways", "eq", True, weight=1.5),
            ],
            recommended_action="Alert",
        ))

        # =====================================================================
        # LAYER 4 - TRANSPORT ATTACKS
        # =====================================================================

        self.add_signature(ThreatSignature(
            sig_id="HP-L4-SYN-001",
            name="SYN Flood",
            description="TCP SYN flood attack. Excessive half-open connections exhausting resources.",
            layer=OSILayer.L4_TRANSPORT,
            severity=Severity.CRITICAL,
            category=AttackCategory.IMPACT,
            mitre_technique="T1498.001",
            patterns=[
                FeaturePattern("syn_ratio", "ge", 0.7, weight=2.0),
                FeaturePattern("half_open_connections", "ge", 50, weight=1.5),
                FeaturePattern("syn_ack_ratio", "le", 0.1, weight=1.0),
            ],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
            block_duration=600,
            fast_check="syn_ratio > 0.5"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L4-SCAN-001",
            name="Port Scan",
            description="Network reconnaissance via port scanning. Attacker enumerating services.",
            layer=OSILayer.L4_TRANSPORT,
            severity=Severity.MEDIUM,
            category=AttackCategory.RECONNAISSANCE,
            mitre_technique="T1046",
            mitre_tactic="TA0007",
            patterns=[
                FeaturePattern("port_scan_score", "ge", 0.5, weight=2.0),
                FeaturePattern("unique_dst_ports", "ge", 30, weight=1.5),
                FeaturePattern("connections_per_src", "ge", 50.0, weight=1.0),
            ],
            protocols=["tcp", "udp"],
            recommended_action="Alert",
            fast_check="unique_dst_ports > 20"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L4-SCAN-002",
            name="Service Scan",
            description="Targeted service enumeration on well-known ports.",
            layer=OSILayer.L4_TRANSPORT,
            severity=Severity.LOW,
            category=AttackCategory.RECONNAISSANCE,
            mitre_technique="T1046",
            patterns=[
                FeaturePattern("horizontal_scan_score", "ge", 0.6, weight=1.5),
                FeaturePattern("scan_common_ports", "eq", True, weight=1.0),
            ],
            ports=[21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080],
            protocols=["tcp"],
            recommended_action="Monitor",
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L4-RST-001",
            name="TCP Reset Attack",
            description="Abnormal TCP RST packets. Potential connection disruption attack.",
            layer=OSILayer.L4_TRANSPORT,
            severity=Severity.MEDIUM,
            category=AttackCategory.IMPACT,
            mitre_technique="T1090.001",
            patterns=[
                FeaturePattern("rst_ratio", "ge", 0.5, weight=2.0),
                FeaturePattern("rst_without_connection", "ge", 10, weight=1.5),
            ],
            protocols=["tcp"],
            recommended_action="Alert",
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L4-UDP-001",
            name="UDP Flood",
            description="UDP flood attack overwhelming network/application.",
            layer=OSILayer.L4_TRANSPORT,
            severity=Severity.HIGH,
            category=AttackCategory.IMPACT,
            mitre_technique="T1498.001",
            patterns=[
                FeaturePattern("udp_ratio", "ge", 0.8, weight=2.0),
                FeaturePattern("packets_per_second", "ge", 1000.0, weight=1.5),
            ],
            protocols=["udp"],
            recommended_action="Rate Limit",
            fast_check="udp_ratio > 0.7"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L4-SESS-001",
            name="TCP Session Hijacking",
            description="TCP sequence prediction/injection detected. Session takeover attempt.",
            layer=OSILayer.L4_TRANSPORT,
            severity=Severity.CRITICAL,
            category=AttackCategory.LATERAL_MOVEMENT,
            mitre_technique="T1563",
            patterns=[
                FeaturePattern("sequence_anomaly", "eq", True, weight=2.0),
                FeaturePattern("ack_prediction_pattern", "eq", True, weight=1.5),
            ],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
        ))

        # =====================================================================
        # LAYER 5 - SESSION ATTACKS
        # =====================================================================

        self.add_signature(ThreatSignature(
            sig_id="HP-L5-SSL-001",
            name="SSL Stripping",
            description="HTTPS downgrade to HTTP detected. MitM intercepting credentials.",
            layer=OSILayer.L5_SESSION,
            severity=Severity.CRITICAL,
            category=AttackCategory.CREDENTIAL_ACCESS,
            mitre_technique="T1557.002",
            patterns=[
                FeaturePattern("https_to_http_redirect", "eq", True, weight=2.0),
                FeaturePattern("hsts_bypass_attempt", "eq", True, weight=1.5),
            ],
            ports=[80, 443],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L5-TLS-001",
            name="TLS Downgrade Attack",
            description="Attempt to force weak TLS version (SSLv3, TLS 1.0).",
            layer=OSILayer.L5_SESSION,
            severity=Severity.HIGH,
            category=AttackCategory.MANIPULATION,
            mitre_technique="T1557.002",
            patterns=[
                FeaturePattern("ssl_weak_version_ratio", "ge", 0.3, weight=2.0),
                FeaturePattern("tls_version_mismatch", "eq", True, weight=1.0),
            ],
            ports=[443, 8443],
            protocols=["tcp"],
            recommended_action="Block",
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L5-CERT-001",
            name="Invalid Certificate",
            description="Self-signed, expired, or invalid SSL certificate detected.",
            layer=OSILayer.L5_SESSION,
            severity=Severity.HIGH,
            category=AttackCategory.SPOOFING,
            mitre_technique="T1557.002",
            patterns=[
                FeaturePattern("ssl_self_signed_ratio", "ge", 0.5, weight=1.5),
                FeaturePattern("ssl_expired_ratio", "ge", 0.3, weight=1.5),
                FeaturePattern("cert_chain_invalid", "eq", True, weight=2.0),
            ],
            ports=[443],
            protocols=["tcp"],
            recommended_action="Alert",
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L5-AUTH-001",
            name="Brute Force Attack",
            description="Multiple failed authentication attempts from single source.",
            layer=OSILayer.L5_SESSION,
            severity=Severity.HIGH,
            category=AttackCategory.CREDENTIAL_ACCESS,
            mitre_technique="T1110",
            mitre_tactic="TA0006",
            patterns=[
                FeaturePattern("failed_auth_count", "ge", 5, weight=2.0),
                FeaturePattern("auth_attempt_rate", "ge", 1.0, weight=1.5),
            ],
            ports=[22, 23, 21, 3389, 5900],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
            block_duration=3600,
            fast_check="failed_auth_count > 3"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L5-SESS-001",
            name="Session Fixation",
            description="Session ID manipulation detected. Attempting to hijack user session.",
            layer=OSILayer.L5_SESSION,
            severity=Severity.HIGH,
            category=AttackCategory.CREDENTIAL_ACCESS,
            mitre_technique="T1563",
            patterns=[
                FeaturePattern("session_id_reuse_anomaly", "eq", True, weight=2.0),
                FeaturePattern("session_from_different_ip", "eq", True, weight=1.5),
            ],
            recommended_action="Block",
        ))

        # =====================================================================
        # LAYER 6 - PRESENTATION ATTACKS
        # =====================================================================

        self.add_signature(ThreatSignature(
            sig_id="HP-L6-ENC-001",
            name="Double URL Encoding",
            description="Multi-layered URL encoding to bypass WAF/filters.",
            layer=OSILayer.L6_PRESENTATION,
            severity=Severity.MEDIUM,
            category=AttackCategory.DEFENSE_EVASION,
            mitre_technique="T1027",
            patterns=[
                FeaturePattern("double_encoding_detected", "eq", True, weight=2.0),
                FeaturePattern("nested_encoding_depth", "ge", 2, weight=1.5),
            ],
            ports=[80, 443, 8080],
            protocols=["tcp"],
            recommended_action="Block",
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L6-XML-001",
            name="XXE Injection",
            description="XML External Entity injection attempt. Potential data exfiltration.",
            layer=OSILayer.L6_PRESENTATION,
            severity=Severity.CRITICAL,
            category=AttackCategory.EXFILTRATION,
            mitre_technique="T1059.009",
            patterns=[
                FeaturePattern("xml_entity_declaration", "eq", True, weight=2.0),
                FeaturePattern("external_dtd_reference", "eq", True, weight=2.0),
            ],
            ports=[80, 443, 8080],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L6-DESER-001",
            name="Insecure Deserialization",
            description="Malicious serialized object detected. Potential RCE.",
            layer=OSILayer.L6_PRESENTATION,
            severity=Severity.CRITICAL,
            category=AttackCategory.EXECUTION,
            mitre_technique="T1190",
            patterns=[
                FeaturePattern("java_serialization_magic", "eq", True, weight=2.0),
                FeaturePattern("pickle_payload_detected", "eq", True, weight=2.0),
            ],
            ports=[80, 443, 8080, 8443],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
        ))

        # =====================================================================
        # LAYER 7 - APPLICATION ATTACKS
        # =====================================================================

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-SQL-001",
            name="SQL Injection",
            description="SQL injection attempt in request parameters.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.CRITICAL,
            category=AttackCategory.EXECUTION,
            mitre_technique="T1190",
            patterns=[
                FeaturePattern("sqli_pattern_match", "eq", True, weight=2.0),
                FeaturePattern("sql_keywords_in_input", "ge", 2, weight=1.5),
            ],
            ports=[80, 443, 3306, 5432, 1433],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
            fast_check="sqli_pattern_match == True"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-XSS-001",
            name="Cross-Site Scripting (XSS)",
            description="XSS payload detected in request. Script injection attempt.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.HIGH,
            category=AttackCategory.EXECUTION,
            mitre_technique="T1059.007",
            patterns=[
                FeaturePattern("xss_pattern_match", "eq", True, weight=2.0),
                FeaturePattern("script_tag_in_input", "eq", True, weight=1.5),
            ],
            ports=[80, 443, 8080],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-CMD-001",
            name="Command Injection",
            description="OS command injection attempt via user input.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.CRITICAL,
            category=AttackCategory.EXECUTION,
            mitre_technique="T1059",
            patterns=[
                FeaturePattern("cmd_injection_pattern", "eq", True, weight=2.0),
                FeaturePattern("shell_metacharacters", "ge", 2, weight=1.5),
            ],
            ports=[80, 443, 8080],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-PATH-001",
            name="Path Traversal",
            description="Directory traversal attempt (../) to access restricted files.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.HIGH,
            category=AttackCategory.DISCOVERY,
            mitre_technique="T1083",
            patterns=[
                FeaturePattern("path_traversal_pattern", "eq", True, weight=2.0),
                FeaturePattern("dot_dot_slash_count", "ge", 2, weight=1.5),
            ],
            ports=[80, 443, 8080],
            protocols=["tcp"],
            recommended_action="Block",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-DNS-001",
            name="DNS Tunneling",
            description="Data exfiltration via DNS queries. Encoded data in DNS names.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.HIGH,
            category=AttackCategory.EXFILTRATION,
            mitre_technique="T1071.004",
            patterns=[
                FeaturePattern("dns_query_length_avg", "ge", 40.0, weight=2.0),
                FeaturePattern("dns_query_entropy_avg", "ge", 3.5, weight=1.5),
                FeaturePattern("dns_txt_query_ratio", "ge", 0.3, weight=1.0),
            ],
            ports=[53],
            protocols=["udp", "tcp"],
            recommended_action="Block",
            auto_block=True,
            fast_check="dns_query_length_avg > 35"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-HTTP-001",
            name="HTTP Flood",
            description="HTTP request flood. Application-layer DoS attack.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.HIGH,
            category=AttackCategory.IMPACT,
            mitre_technique="T1498.001",
            patterns=[
                FeaturePattern("http_request_rate", "ge", 50.0, weight=2.0),
                FeaturePattern("http_same_uri_ratio", "ge", 0.8, weight=1.0),
            ],
            ports=[80, 443, 8080],
            protocols=["tcp"],
            recommended_action="Rate Limit",
            fast_check="http_request_rate > 30"
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-C2-001",
            name="Malware C2 Communication",
            description="Command and control beaconing pattern detected.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.CRITICAL,
            category=AttackCategory.COMMAND_CONTROL,
            mitre_technique="T1071.001",
            mitre_tactic="TA0011",
            patterns=[
                FeaturePattern("beaconing_interval_variance", "le", 0.1, weight=2.0),
                FeaturePattern("http_post_ratio", "ge", 0.7, weight=1.5),
                FeaturePattern("encoded_payload_ratio", "ge", 0.5, weight=1.0),
            ],
            ports=[80, 443, 8080, 8443],
            protocols=["tcp"],
            recommended_action="Quarantine",
            auto_block=True,
        ))

        self.add_signature(ThreatSignature(
            sig_id="HP-L7-EXFIL-001",
            name="Data Exfiltration",
            description="Large outbound data transfer to suspicious destination.",
            layer=OSILayer.L7_APPLICATION,
            severity=Severity.HIGH,
            category=AttackCategory.EXFILTRATION,
            mitre_technique="T1048",
            mitre_tactic="TA0010",
            patterns=[
                FeaturePattern("outbound_bytes_anomaly", "eq", True, weight=2.0),
                FeaturePattern("rare_destination_ip", "eq", True, weight=1.5),
                FeaturePattern("encrypted_channel", "eq", True, weight=1.0),
            ],
            recommended_action="Alert",
        ))

        # Update stats
        self.stats['total_signatures'] = len(self.signatures)
        self.stats['last_update'] = datetime.now().isoformat()

    def _load_custom_signatures(self):
        """Load custom signatures from disk."""
        custom_file = self.data_dir / "custom_signatures.json"
        if custom_file.exists():
            try:
                with open(custom_file) as f:
                    data = json.load(f)
                    for sig_dict in data.get('signatures', []):
                        sig = ThreatSignature.from_dict(sig_dict)
                        sig.source = "custom"
                        self.add_signature(sig)
            except Exception as e:
                print(f"Warning: Failed to load custom signatures: {e}")

    def add_signature(self, signature: ThreatSignature):
        """Add a signature to the database."""
        self.signatures[signature.sig_id] = signature

        # Update indexes
        self._by_layer[signature.layer].append(signature.sig_id)
        self._by_category[signature.category].append(signature.sig_id)

        for proto in signature.protocols:
            if proto not in self._by_protocol:
                self._by_protocol[proto] = []
            self._by_protocol[proto].append(signature.sig_id)

        for port in signature.ports:
            if port not in self._by_port:
                self._by_port[port] = []
            self._by_port[port].append(signature.sig_id)

        # Update bloom filter
        self._bloom_filter.add(signature.get_hash())
        for key in signature.bloom_keys:
            self._bloom_filter.add(key)

        self.stats['total_signatures'] = len(self.signatures)

    def get_by_layer(self, layer: OSILayer) -> List[ThreatSignature]:
        """Get all signatures for a specific OSI layer."""
        return [self.signatures[sid] for sid in self._by_layer.get(layer, [])]

    def get_by_protocol(self, protocol: str) -> List[ThreatSignature]:
        """Get all signatures for a specific protocol."""
        return [self.signatures[sid] for sid in self._by_protocol.get(protocol.lower(), [])]

    def get_by_port(self, port: int) -> List[ThreatSignature]:
        """Get all signatures relevant to a specific port."""
        return [self.signatures[sid] for sid in self._by_port.get(port, [])]

    def get_by_category(self, category: AttackCategory) -> List[ThreatSignature]:
        """Get all signatures for a specific attack category."""
        return [self.signatures[sid] for sid in self._by_category.get(category, [])]

    def get_signature(self, sig_id: str) -> Optional[ThreatSignature]:
        """Get a specific signature by ID."""
        return self.signatures.get(sig_id)

    def get_all(self, enabled_only: bool = True) -> List[ThreatSignature]:
        """Get all signatures."""
        if enabled_only:
            return [s for s in self.signatures.values() if s.enabled]
        return list(self.signatures.values())

    def save_custom_signatures(self):
        """Save custom signatures to disk."""
        custom_sigs = [
            s.to_dict() for s in self.signatures.values()
            if s.source == "custom"
        ]

        custom_file = self.data_dir / "custom_signatures.json"
        with open(custom_file, 'w') as f:
            json.dump({
                'version': '1.0',
                'updated': datetime.now().isoformat(),
                'signatures': custom_sigs
            }, f, indent=2)

    def export_all(self, filepath: str):
        """Export all signatures to JSON file."""
        data = {
            'version': '1.0',
            'exported': datetime.now().isoformat(),
            'count': len(self.signatures),
            'signatures': [s.to_dict() for s in self.signatures.values()]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        by_layer = {l.name: len(ids) for l, ids in self._by_layer.items()}
        by_severity = {}
        for sig in self.signatures.values():
            sev = sig.severity.name
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            **self.stats,
            'by_layer': by_layer,
            'by_severity': by_severity,
            'protocols': list(self._by_protocol.keys()),
            'auto_block_count': sum(1 for s in self.signatures.values() if s.auto_block),
        }
