"""
Qsecbit Unified - Unified Threat Types and Data Model

Defines all attack types, severities, and the canonical ThreatEvent
data structure used throughout the unified threat detection engine.

Author: HookProbe Team
License: Proprietary - see LICENSE in this directory
Version: 5.0.0
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List


class OSILayer(Enum):
    """OSI Model Layers for threat classification"""
    L2_DATA_LINK = 2
    L3_NETWORK = 3
    L4_TRANSPORT = 4
    L5_SESSION = 5
    L6_PRESENTATION = 6
    L7_APPLICATION = 7


class AttackType(Enum):
    """
    Comprehensive attack type enumeration covering all 17 target attacks.
    Each attack type maps to an OSI layer and MITRE ATT&CK technique.
    """
    # Layer 2 - Data Link
    ARP_SPOOFING = auto()
    MAC_FLOODING = auto()
    VLAN_HOPPING = auto()
    EVIL_TWIN = auto()
    ROGUE_DHCP = auto()

    # Layer 3 - Network
    IP_SPOOFING = auto()
    ICMP_FLOOD = auto()
    SMURF_ATTACK = auto()
    ROUTING_ATTACK = auto()
    FRAGMENTATION_ATTACK = auto()

    # Layer 4 - Transport
    SYN_FLOOD = auto()
    PORT_SCAN = auto()
    TCP_RESET_ATTACK = auto()
    SESSION_HIJACK = auto()
    UDP_FLOOD = auto()

    # Layer 5 - Session
    SSL_STRIP = auto()
    TLS_DOWNGRADE = auto()
    CERT_PINNING_BYPASS = auto()
    AUTH_BYPASS = auto()

    # Layer 7 - Application
    SQL_INJECTION = auto()
    XSS = auto()
    DNS_TUNNELING = auto()
    HTTP_FLOOD = auto()
    MALWARE_C2 = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()

    # Meta/Composite
    UNKNOWN = auto()


class ThreatSeverity(Enum):
    """Threat severity levels aligned with CVSS scoring"""
    CRITICAL = 4  # CVSS 9.0-10.0
    HIGH = 3      # CVSS 7.0-8.9
    MEDIUM = 2    # CVSS 4.0-6.9
    LOW = 1       # CVSS 0.1-3.9
    INFO = 0      # Informational


class ResponseAction(Enum):
    """Available automated response actions"""
    MONITOR = auto()        # Just log and observe
    ALERT = auto()          # Send alert notification
    RATE_LIMIT = auto()     # Apply rate limiting
    BLOCK_IP = auto()       # Block source IP (XDP/firewall)
    BLOCK_MAC = auto()      # Block MAC address
    TERMINATE_SESSION = auto()  # Kill active session
    QUARANTINE = auto()     # Isolate device
    CAPTIVE_PORTAL = auto() # Redirect to captive portal
    KILL_PROCESS = auto()   # Kill malicious process (eBPF healing)
    QUARANTINE_PROCESS = auto()  # Isolate process via cgroup
    REFLEX_JITTER = auto()       # Stochastic delay injection (Reflex L1)
    REFLEX_SHADOW = auto()       # Redirect to Mirage honeypot (Reflex L2)
    REFLEX_DISCONNECT = auto()   # Surgical SIGKILL + TCP_RST (Reflex L3)


# Attack type to OSI layer mapping
ATTACK_LAYER_MAP: Dict[AttackType, OSILayer] = {
    # L2
    AttackType.ARP_SPOOFING: OSILayer.L2_DATA_LINK,
    AttackType.MAC_FLOODING: OSILayer.L2_DATA_LINK,
    AttackType.VLAN_HOPPING: OSILayer.L2_DATA_LINK,
    AttackType.EVIL_TWIN: OSILayer.L2_DATA_LINK,
    AttackType.ROGUE_DHCP: OSILayer.L2_DATA_LINK,
    # L3
    AttackType.IP_SPOOFING: OSILayer.L3_NETWORK,
    AttackType.ICMP_FLOOD: OSILayer.L3_NETWORK,
    AttackType.SMURF_ATTACK: OSILayer.L3_NETWORK,
    AttackType.ROUTING_ATTACK: OSILayer.L3_NETWORK,
    AttackType.FRAGMENTATION_ATTACK: OSILayer.L3_NETWORK,
    # L4
    AttackType.SYN_FLOOD: OSILayer.L4_TRANSPORT,
    AttackType.PORT_SCAN: OSILayer.L4_TRANSPORT,
    AttackType.TCP_RESET_ATTACK: OSILayer.L4_TRANSPORT,
    AttackType.SESSION_HIJACK: OSILayer.L4_TRANSPORT,
    AttackType.UDP_FLOOD: OSILayer.L4_TRANSPORT,
    # L5
    AttackType.SSL_STRIP: OSILayer.L5_SESSION,
    AttackType.TLS_DOWNGRADE: OSILayer.L5_SESSION,
    AttackType.CERT_PINNING_BYPASS: OSILayer.L5_SESSION,
    AttackType.AUTH_BYPASS: OSILayer.L5_SESSION,
    # L7
    AttackType.SQL_INJECTION: OSILayer.L7_APPLICATION,
    AttackType.XSS: OSILayer.L7_APPLICATION,
    AttackType.DNS_TUNNELING: OSILayer.L7_APPLICATION,
    AttackType.HTTP_FLOOD: OSILayer.L7_APPLICATION,
    AttackType.MALWARE_C2: OSILayer.L7_APPLICATION,
    AttackType.COMMAND_INJECTION: OSILayer.L7_APPLICATION,
    AttackType.PATH_TRAVERSAL: OSILayer.L7_APPLICATION,
    # Meta
    AttackType.UNKNOWN: OSILayer.L7_APPLICATION,
}


# MITRE ATT&CK technique mapping
MITRE_ATTACK_MAP: Dict[AttackType, str] = {
    AttackType.ARP_SPOOFING: "T1557.002",
    AttackType.MAC_FLOODING: "T1499.001",
    AttackType.VLAN_HOPPING: "T1599",
    AttackType.EVIL_TWIN: "T1557.001",
    AttackType.ROGUE_DHCP: "T1557.003",
    AttackType.IP_SPOOFING: "T1090",
    AttackType.ICMP_FLOOD: "T1498.001",
    AttackType.SMURF_ATTACK: "T1498.001",
    AttackType.ROUTING_ATTACK: "T1599.001",
    AttackType.FRAGMENTATION_ATTACK: "T1499.001",
    AttackType.SYN_FLOOD: "T1498.001",
    AttackType.PORT_SCAN: "T1046",
    AttackType.TCP_RESET_ATTACK: "T1090.001",
    AttackType.SESSION_HIJACK: "T1563",
    AttackType.UDP_FLOOD: "T1498.001",
    AttackType.SSL_STRIP: "T1557.002",
    AttackType.TLS_DOWNGRADE: "T1557.002",
    AttackType.CERT_PINNING_BYPASS: "T1553.004",
    AttackType.AUTH_BYPASS: "T1110",
    AttackType.SQL_INJECTION: "T1190",
    AttackType.XSS: "T1059.007",
    AttackType.DNS_TUNNELING: "T1071.004",
    AttackType.HTTP_FLOOD: "T1498.001",
    AttackType.MALWARE_C2: "T1071.001",
    AttackType.COMMAND_INJECTION: "T1059",
    AttackType.PATH_TRAVERSAL: "T1083",
    AttackType.UNKNOWN: "T1000",
}

# Alias for backward compatibility
MITRE_ATTACK_MAPPING = MITRE_ATTACK_MAP


# Attack type to OSI layer mapping
ATTACK_TO_LAYER: Dict[AttackType, OSILayer] = {
    # Layer 2 - Data Link
    AttackType.ARP_SPOOFING: OSILayer.L2_DATA_LINK,
    AttackType.MAC_FLOODING: OSILayer.L2_DATA_LINK,
    AttackType.VLAN_HOPPING: OSILayer.L2_DATA_LINK,
    AttackType.EVIL_TWIN: OSILayer.L2_DATA_LINK,
    AttackType.ROGUE_DHCP: OSILayer.L2_DATA_LINK,
    # Layer 3 - Network
    AttackType.IP_SPOOFING: OSILayer.L3_NETWORK,
    AttackType.ICMP_FLOOD: OSILayer.L3_NETWORK,
    AttackType.SMURF_ATTACK: OSILayer.L3_NETWORK,
    AttackType.ROUTING_ATTACK: OSILayer.L3_NETWORK,
    AttackType.FRAGMENTATION_ATTACK: OSILayer.L3_NETWORK,
    # Layer 4 - Transport
    AttackType.SYN_FLOOD: OSILayer.L4_TRANSPORT,
    AttackType.PORT_SCAN: OSILayer.L4_TRANSPORT,
    AttackType.TCP_RESET_ATTACK: OSILayer.L4_TRANSPORT,
    AttackType.SESSION_HIJACK: OSILayer.L4_TRANSPORT,
    AttackType.UDP_FLOOD: OSILayer.L4_TRANSPORT,
    # Layer 5 - Session
    AttackType.SSL_STRIP: OSILayer.L5_SESSION,
    AttackType.TLS_DOWNGRADE: OSILayer.L5_SESSION,
    AttackType.CERT_PINNING_BYPASS: OSILayer.L5_SESSION,
    AttackType.AUTH_BYPASS: OSILayer.L5_SESSION,
    # Layer 7 - Application
    AttackType.SQL_INJECTION: OSILayer.L7_APPLICATION,
    AttackType.XSS: OSILayer.L7_APPLICATION,
    AttackType.DNS_TUNNELING: OSILayer.L7_APPLICATION,
    AttackType.HTTP_FLOOD: OSILayer.L7_APPLICATION,
    AttackType.MALWARE_C2: OSILayer.L7_APPLICATION,
    AttackType.COMMAND_INJECTION: OSILayer.L7_APPLICATION,
    AttackType.PATH_TRAVERSAL: OSILayer.L7_APPLICATION,
    AttackType.UNKNOWN: OSILayer.L7_APPLICATION,
}


# Default severity mapping (can be overridden by detection confidence)
DEFAULT_SEVERITY_MAP: Dict[AttackType, ThreatSeverity] = {
    AttackType.ARP_SPOOFING: ThreatSeverity.HIGH,
    AttackType.MAC_FLOODING: ThreatSeverity.HIGH,
    AttackType.VLAN_HOPPING: ThreatSeverity.HIGH,
    AttackType.EVIL_TWIN: ThreatSeverity.CRITICAL,
    AttackType.ROGUE_DHCP: ThreatSeverity.CRITICAL,
    AttackType.IP_SPOOFING: ThreatSeverity.HIGH,
    AttackType.ICMP_FLOOD: ThreatSeverity.MEDIUM,
    AttackType.SMURF_ATTACK: ThreatSeverity.HIGH,
    AttackType.ROUTING_ATTACK: ThreatSeverity.CRITICAL,
    AttackType.FRAGMENTATION_ATTACK: ThreatSeverity.MEDIUM,
    AttackType.SYN_FLOOD: ThreatSeverity.CRITICAL,
    AttackType.PORT_SCAN: ThreatSeverity.MEDIUM,
    AttackType.TCP_RESET_ATTACK: ThreatSeverity.MEDIUM,
    AttackType.SESSION_HIJACK: ThreatSeverity.CRITICAL,
    AttackType.UDP_FLOOD: ThreatSeverity.MEDIUM,
    AttackType.SSL_STRIP: ThreatSeverity.CRITICAL,
    AttackType.TLS_DOWNGRADE: ThreatSeverity.HIGH,
    AttackType.CERT_PINNING_BYPASS: ThreatSeverity.CRITICAL,
    AttackType.AUTH_BYPASS: ThreatSeverity.HIGH,
    AttackType.SQL_INJECTION: ThreatSeverity.CRITICAL,
    AttackType.XSS: ThreatSeverity.HIGH,
    AttackType.DNS_TUNNELING: ThreatSeverity.HIGH,
    AttackType.HTTP_FLOOD: ThreatSeverity.HIGH,
    AttackType.MALWARE_C2: ThreatSeverity.CRITICAL,
    AttackType.COMMAND_INJECTION: ThreatSeverity.CRITICAL,
    AttackType.PATH_TRAVERSAL: ThreatSeverity.HIGH,
    AttackType.UNKNOWN: ThreatSeverity.LOW,
}


# Default response actions per attack type
DEFAULT_RESPONSE_MAP: Dict[AttackType, List[ResponseAction]] = {
    AttackType.ARP_SPOOFING: [ResponseAction.ALERT, ResponseAction.BLOCK_MAC],
    AttackType.MAC_FLOODING: [ResponseAction.ALERT, ResponseAction.RATE_LIMIT],
    AttackType.VLAN_HOPPING: [ResponseAction.ALERT, ResponseAction.BLOCK_IP],
    AttackType.EVIL_TWIN: [ResponseAction.ALERT, ResponseAction.CAPTIVE_PORTAL],
    AttackType.ROGUE_DHCP: [ResponseAction.ALERT, ResponseAction.BLOCK_IP],
    AttackType.IP_SPOOFING: [ResponseAction.BLOCK_IP],
    AttackType.ICMP_FLOOD: [ResponseAction.RATE_LIMIT],
    AttackType.SMURF_ATTACK: [ResponseAction.BLOCK_IP, ResponseAction.RATE_LIMIT],
    AttackType.ROUTING_ATTACK: [ResponseAction.ALERT],
    AttackType.FRAGMENTATION_ATTACK: [ResponseAction.BLOCK_IP],
    AttackType.SYN_FLOOD: [ResponseAction.RATE_LIMIT, ResponseAction.BLOCK_IP],
    AttackType.PORT_SCAN: [ResponseAction.RATE_LIMIT, ResponseAction.ALERT],
    AttackType.TCP_RESET_ATTACK: [ResponseAction.ALERT],
    AttackType.SESSION_HIJACK: [ResponseAction.REFLEX_JITTER, ResponseAction.TERMINATE_SESSION, ResponseAction.BLOCK_IP],
    AttackType.UDP_FLOOD: [ResponseAction.RATE_LIMIT],
    AttackType.SSL_STRIP: [ResponseAction.ALERT, ResponseAction.TERMINATE_SESSION],
    AttackType.TLS_DOWNGRADE: [ResponseAction.ALERT],
    AttackType.CERT_PINNING_BYPASS: [ResponseAction.ALERT, ResponseAction.TERMINATE_SESSION],
    AttackType.AUTH_BYPASS: [ResponseAction.BLOCK_IP, ResponseAction.ALERT],
    AttackType.SQL_INJECTION: [ResponseAction.BLOCK_IP, ResponseAction.ALERT],
    AttackType.XSS: [ResponseAction.BLOCK_IP, ResponseAction.ALERT],
    AttackType.DNS_TUNNELING: [ResponseAction.REFLEX_SHADOW, ResponseAction.BLOCK_IP, ResponseAction.ALERT],
    AttackType.HTTP_FLOOD: [ResponseAction.RATE_LIMIT, ResponseAction.BLOCK_IP],
    AttackType.MALWARE_C2: [ResponseAction.REFLEX_SHADOW, ResponseAction.QUARANTINE, ResponseAction.BLOCK_IP],
    AttackType.COMMAND_INJECTION: [ResponseAction.BLOCK_IP, ResponseAction.ALERT],
    AttackType.PATH_TRAVERSAL: [ResponseAction.BLOCK_IP],
    AttackType.UNKNOWN: [ResponseAction.MONITOR],
}


@dataclass
class ThreatEvent:
    """
    Canonical threat event structure - the single source of truth for all detections.

    This unified data model is used by all detectors, classifiers, and response systems.
    """
    # Core identification
    id: str                         # Unique event ID (UUID)
    timestamp: datetime             # Detection timestamp
    attack_type: AttackType         # Classified attack type
    layer: OSILayer                 # OSI layer
    severity: ThreatSeverity        # Threat severity

    # Source information
    source_ip: Optional[str] = None
    source_mac: Optional[str] = None
    source_port: Optional[int] = None

    # Destination information
    dest_ip: Optional[str] = None
    dest_mac: Optional[str] = None
    dest_port: Optional[int] = None

    # Detection details
    description: str = ""           # Human-readable description
    confidence: float = 0.0         # Detection confidence (0.0-1.0)
    detector: str = ""              # Which detector found this
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Classification
    mitre_attack_id: str = ""       # MITRE ATT&CK technique ID
    kill_chain_phase: str = ""      # Cyber kill chain phase

    # Response tracking
    blocked: bool = False           # Was this attack blocked?
    response_actions: List[ResponseAction] = field(default_factory=list)
    response_timestamp: Optional[datetime] = None

    # Correlation
    chain_id: Optional[str] = None  # Attack chain correlation ID
    related_events: List[str] = field(default_factory=list)

    # Qsecbit integration
    qsecbit_contribution: float = 0.0  # How much this affects Qsecbit score

    def __post_init__(self):
        """Auto-fill derived fields"""
        if not self.layer:
            self.layer = ATTACK_LAYER_MAP.get(self.attack_type, OSILayer.L7_APPLICATION)
        if not self.severity:
            self.severity = DEFAULT_SEVERITY_MAP.get(self.attack_type, ThreatSeverity.MEDIUM)
        if not self.mitre_attack_id:
            self.mitre_attack_id = MITRE_ATTACK_MAP.get(self.attack_type, "")
        if not self.response_actions:
            self.response_actions = DEFAULT_RESPONSE_MAP.get(self.attack_type, [ResponseAction.MONITOR])

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON/database storage"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'attack_type': self.attack_type.name,
            'layer': self.layer.name,
            'layer_num': self.layer.value,
            'severity': self.severity.name,
            'severity_num': self.severity.value,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'source_port': self.source_port,
            'dest_ip': self.dest_ip,
            'dest_mac': self.dest_mac,
            'dest_port': self.dest_port,
            'description': self.description,
            'confidence': self.confidence,
            'detector': self.detector,
            'evidence': self.evidence,
            'mitre_attack_id': self.mitre_attack_id,
            'kill_chain_phase': self.kill_chain_phase,
            'blocked': self.blocked,
            'response_actions': [a.name for a in self.response_actions],
            'response_timestamp': self.response_timestamp.isoformat() if self.response_timestamp else None,
            'chain_id': self.chain_id,
            'related_events': self.related_events,
            'qsecbit_contribution': self.qsecbit_contribution,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatEvent':
        """Deserialize from dictionary"""
        return cls(
            id=data['id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            attack_type=AttackType[data['attack_type']],
            layer=OSILayer[data['layer']],
            severity=ThreatSeverity[data['severity']],
            source_ip=data.get('source_ip'),
            source_mac=data.get('source_mac'),
            source_port=data.get('source_port'),
            dest_ip=data.get('dest_ip'),
            dest_mac=data.get('dest_mac'),
            dest_port=data.get('dest_port'),
            description=data.get('description', ''),
            confidence=data.get('confidence', 0.0),
            detector=data.get('detector', ''),
            evidence=data.get('evidence', {}),
            mitre_attack_id=data.get('mitre_attack_id', ''),
            kill_chain_phase=data.get('kill_chain_phase', ''),
            blocked=data.get('blocked', False),
            response_actions=[ResponseAction[a] for a in data.get('response_actions', [])],
            response_timestamp=datetime.fromisoformat(data['response_timestamp']) if data.get('response_timestamp') else None,
            chain_id=data.get('chain_id'),
            related_events=data.get('related_events', []),
            qsecbit_contribution=data.get('qsecbit_contribution', 0.0),
        )


@dataclass
class LayerScore:
    """Per-layer threat score for Qsecbit calculation"""
    layer: OSILayer
    score: float = 0.0              # Normalized score (0.0-1.0)
    threat_count: int = 0           # Number of threats at this layer
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    top_threats: List[AttackType] = field(default_factory=list)

    def calculate_score(self) -> float:
        """
        Calculate normalized layer score based on threat counts.

        Formula: score = min(1.0, (critical×1.0 + high×0.6 + medium×0.3 + low×0.1) / 5)
        """
        weighted = (
            self.critical_count * 1.0 +
            self.high_count * 0.6 +
            self.medium_count * 0.3 +
            self.low_count * 0.1
        )
        self.score = min(1.0, weighted / 5.0)
        return self.score


@dataclass
class QsecbitUnifiedScore:
    """
    Unified Qsecbit score - the single source of truth for system security posture.
    """
    timestamp: datetime
    score: float                    # Final Qsecbit score (0.0-1.0)
    rag_status: str                 # RED, AMBER, GREEN

    # Layer breakdown
    layer_scores: Dict[OSILayer, LayerScore] = field(default_factory=dict)

    # Component scores
    l2_score: float = 0.0
    l3_score: float = 0.0
    l4_score: float = 0.0
    l5_score: float = 0.0
    l7_score: float = 0.0
    energy_score: float = 0.0
    behavioral_score: float = 0.0
    correlation_score: float = 0.0

    # Weights used
    weights: Dict[str, float] = field(default_factory=dict)

    # Active threats
    active_threats: int = 0
    critical_threats: int = 0
    blocked_threats: int = 0

    # Trend analysis
    trend: str = "STABLE"           # IMPROVING, STABLE, DEGRADING
    convergence_rate: Optional[float] = None

    # Metadata
    deployment_type: str = "guardian"
    hostname: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'score': self.score,
            'rag_status': self.rag_status,
            'layer_scores': {
                layer.name: {
                    'score': ls.score,
                    'threat_count': ls.threat_count,
                    'critical': ls.critical_count,
                    'high': ls.high_count,
                    'medium': ls.medium_count,
                    'low': ls.low_count,
                }
                for layer, ls in self.layer_scores.items()
            },
            'components': {
                'l2': self.l2_score,
                'l3': self.l3_score,
                'l4': self.l4_score,
                'l5': self.l5_score,
                'l7': self.l7_score,
                'energy': self.energy_score,
                'behavioral': self.behavioral_score,
                'correlation': self.correlation_score,
            },
            'weights': self.weights,
            'active_threats': self.active_threats,
            'critical_threats': self.critical_threats,
            'blocked_threats': self.blocked_threats,
            'trend': self.trend,
            'convergence_rate': self.convergence_rate,
            'deployment_type': self.deployment_type,
            'hostname': self.hostname,
        }
