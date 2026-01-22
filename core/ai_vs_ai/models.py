"""
AI vs AI Data Models

Defines core data structures for IoC generation, threat prediction,
defense strategies, and compute routing between Fortress and Nexus.

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import json
import hashlib
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class IoCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    PORT_PATTERN = "port_pattern"
    ATTACK_SIGNATURE = "attack_signature"
    BEHAVIOR_PATTERN = "behavior_pattern"
    NETWORK_FLOW = "network_flow"
    TLS_FINGERPRINT = "tls_fingerprint"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComputeTier(Enum):
    """Compute tier for task routing"""
    FORTRESS_LITE = "fortress_lite"      # 4GB RAM, basic analysis
    FORTRESS_STANDARD = "fortress_std"   # 4GB RAM, standard analysis
    NEXUS_STANDARD = "nexus_std"         # 16GB RAM, advanced analysis
    NEXUS_ADVANCED = "nexus_adv"         # 16GB+ RAM, deep learning
    MESH_CLOUD = "mesh_cloud"            # Cloud, unlimited resources


class DefenseAction(Enum):
    """Actions that can be taken in defense"""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    HONEYPOT_REDIRECT = "honeypot_redirect"
    DECEPTION = "deception"
    ISOLATE = "isolate"
    TERMINATE_SESSION = "terminate_session"
    UPDATE_RULES = "update_rules"
    RETRAIN_MODEL = "retrain_model"
    ESCALATE = "escalate"


@dataclass
class IoC:
    """
    Indicator of Compromise

    Generated from LSTM predictions and Suricata/Zeek analysis.
    Contains structured attack information for defense AI consultation.
    """
    ioc_id: str                          # Unique identifier
    ioc_type: IoCType                    # Type of indicator
    value: str                           # The actual indicator value
    confidence: float                    # 0.0 - 1.0
    severity: ThreatSeverity             # Severity level

    # Attack context
    attack_category: str                 # LSTM category (e.g., "port_scan")
    attack_description: str              # Human-readable description
    attack_sequence: List[str]           # Sequence of attack types leading here

    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Temporal data
    first_seen: str = ""
    last_seen: str = ""
    occurrence_count: int = 1

    # Source data
    source_system: str = "lstm"          # lstm, suricata, zeek, dnsxai
    source_node: str = ""                # Node that detected this

    # Metadata
    tags: List[str] = field(default_factory=list)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.ioc_id:
            self.ioc_id = self._generate_id()
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()

    def _generate_id(self) -> str:
        """Generate unique IoC ID"""
        data = f"{self.ioc_type.value}:{self.value}:{self.attack_category}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_prompt(self) -> str:
        """Generate AI consultation prompt from this IoC"""
        sequence_str = " → ".join(self.attack_sequence[-5:]) if self.attack_sequence else "N/A"
        mitre_str = ", ".join(self.mitre_techniques[:3]) if self.mitre_techniques else "Unknown"

        return f"""
THREAT INDICATOR ANALYSIS REQUEST
=================================
Type: {self.ioc_type.value.upper()}
Value: {self.value}
Severity: {self.severity.value.upper()}
Confidence: {self.confidence:.1%}

ATTACK CONTEXT:
- Category: {self.attack_category}
- Description: {self.attack_description}
- Attack Sequence: {sequence_str}
- MITRE Techniques: {mitre_str}

TEMPORAL DATA:
- First Seen: {self.first_seen}
- Last Seen: {self.last_seen}
- Occurrences: {self.occurrence_count}

Please analyze this threat indicator and recommend:
1. Is this a true positive or false positive?
2. What is the likely intent of the attacker?
3. What defense actions should be taken?
4. What patterns should we look for next?
5. Should we update our detection models?
"""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['ioc_type'] = self.ioc_type.value
        d['severity'] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IoC':
        """Create from dictionary"""
        data['ioc_type'] = IoCType(data['ioc_type'])
        data['severity'] = ThreatSeverity(data['severity'])
        return cls(**data)


@dataclass
class ThreatPrediction:
    """
    LSTM-based threat prediction

    Contains the predicted next attack type and temporal patterns.
    """
    prediction_id: str = ""
    timestamp: str = ""

    # Prediction output
    predicted_attack: str = "unknown"    # Next predicted attack type
    confidence: float = 0.0              # Prediction confidence

    # Probability distribution over all attack types
    attack_probabilities: Dict[str, float] = field(default_factory=dict)

    # Sequence analysis
    input_sequence: List[str] = field(default_factory=list)
    sequence_length: int = 0

    # Temporal patterns
    time_to_next_attack: Optional[float] = None  # Estimated seconds
    attack_intensity: float = 0.0                # Events per minute
    trend: str = "stable"                        # increasing/stable/decreasing

    # Anomaly detection
    anomaly_score: float = 0.0           # Higher = more anomalous
    is_anomalous: bool = False

    # Model info
    model_version: str = "1.0"
    model_accuracy: float = 0.0

    def __post_init__(self):
        if not self.prediction_id:
            self.prediction_id = hashlib.md5(
                f"{self.timestamp}:{self.predicted_attack}".encode(),
                usedforsecurity=False
            ).hexdigest()[:12]
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def get_top_predictions(self, n: int = 3) -> List[tuple]:
        """Get top N predicted attack types"""
        sorted_probs = sorted(
            self.attack_probabilities.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_probs[:n]


@dataclass
class DefenseStrategy:
    """
    AI-recommended defense strategy

    Generated by consulting AI models about detected threats.
    """
    strategy_id: str = ""
    timestamp: str = ""

    # Related IoC
    ioc_id: str = ""

    # Recommended actions
    primary_action: DefenseAction = DefenseAction.ALERT
    secondary_actions: List[DefenseAction] = field(default_factory=list)

    # Action parameters
    action_params: Dict[str, Any] = field(default_factory=dict)

    # AI reasoning
    reasoning: str = ""
    confidence: float = 0.0
    risk_assessment: str = ""

    # Expected outcomes
    expected_effectiveness: float = 0.0  # 0-1
    estimated_false_positive_rate: float = 0.0

    # Resource requirements
    compute_tier_required: ComputeTier = ComputeTier.FORTRESS_LITE
    estimated_latency_ms: int = 0

    # Follow-up
    monitoring_recommendations: List[str] = field(default_factory=list)
    model_update_suggestions: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.strategy_id:
            self.strategy_id = hashlib.md5(
                f"{self.ioc_id}:{self.timestamp}".encode(),
                usedforsecurity=False
            ).hexdigest()[:12]
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['primary_action'] = self.primary_action.value
        d['secondary_actions'] = [a.value for a in self.secondary_actions]
        d['compute_tier_required'] = self.compute_tier_required.value
        return d


@dataclass
class ComputeTask:
    """
    Task for compute routing between Fortress and Nexus
    """
    task_id: str = ""
    task_type: str = ""                  # prediction, analysis, training

    # Resource requirements (estimated)
    estimated_memory_mb: int = 256
    estimated_cpu_cores: float = 0.5
    estimated_gpu_required: bool = False
    estimated_duration_sec: int = 5

    # Priority
    priority: int = 5                    # 1-10, higher = more urgent
    deadline_sec: Optional[int] = None   # Max time to complete

    # Data
    input_data: Dict[str, Any] = field(default_factory=dict)

    # Routing result
    assigned_tier: Optional[ComputeTier] = None
    routed_to_node: str = ""

    def __post_init__(self):
        if not self.task_id:
            self.task_id = hashlib.md5(
                f"{self.task_type}:{datetime.now().isoformat()}".encode(),
                usedforsecurity=False
            ).hexdigest()[:12]

    def can_run_on_fortress(self) -> bool:
        """Check if task can run on Fortress (lite)"""
        return (
            self.estimated_memory_mb <= 2048 and
            self.estimated_cpu_cores <= 2.0 and
            not self.estimated_gpu_required and
            self.estimated_duration_sec <= 60
        )

    def requires_nexus(self) -> bool:
        """Check if task requires Nexus resources"""
        return (
            self.estimated_memory_mb > 2048 or
            self.estimated_gpu_required or
            self.estimated_duration_sec > 60
        )


@dataclass
class AIConsultationRequest:
    """
    Request to consult AI for defense strategy
    """
    request_id: str = ""
    timestamp: str = ""

    # Input
    ioc: Optional[IoC] = None
    prediction: Optional[ThreatPrediction] = None
    context: Dict[str, Any] = field(default_factory=dict)

    # Request configuration
    prompt: str = ""
    max_tokens: int = 1000
    temperature: float = 0.3

    # Routing
    preferred_model: str = "local"       # local, openai, anthropic, ollama
    fallback_models: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.request_id:
            self.request_id = hashlib.md5(
                f"{datetime.now().isoformat()}".encode(),
                usedforsecurity=False
            ).hexdigest()[:12]
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.ioc and not self.prompt:
            self.prompt = self.ioc.to_prompt()


@dataclass
class AIConsultationResponse:
    """
    Response from AI consultation
    """
    response_id: str = ""
    request_id: str = ""
    timestamp: str = ""

    # Response data
    model_used: str = ""
    raw_response: str = ""

    # Parsed strategy
    defense_strategy: Optional[DefenseStrategy] = None

    # Metadata
    tokens_used: int = 0
    latency_ms: int = 0
    success: bool = True
    error_message: str = ""

    def __post_init__(self):
        if not self.response_id:
            self.response_id = hashlib.md5(
                f"{self.request_id}:{datetime.now().isoformat()}".encode(),
                usedforsecurity=False
            ).hexdigest()[:12]
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# MITRE ATT&CK mapping for common attack categories
ATTACK_TO_MITRE = {
    "port_scan": {
        "tactics": ["Reconnaissance", "Discovery"],
        "techniques": ["T1046", "T1595"]
    },
    "address_scan": {
        "tactics": ["Reconnaissance"],
        "techniques": ["T1595.001"]
    },
    "syn_flood": {
        "tactics": ["Impact"],
        "techniques": ["T1499.001"]
    },
    "udp_flood": {
        "tactics": ["Impact"],
        "techniques": ["T1499.001"]
    },
    "icmp_flood": {
        "tactics": ["Impact"],
        "techniques": ["T1499.001"]
    },
    "brute_force": {
        "tactics": ["Credential Access"],
        "techniques": ["T1110"]
    },
    "sql_injection": {
        "tactics": ["Initial Access", "Execution"],
        "techniques": ["T1190", "T1059.001"]
    },
    "xss": {
        "tactics": ["Initial Access", "Execution"],
        "techniques": ["T1189"]
    },
    "dns_tunneling": {
        "tactics": ["Command and Control", "Exfiltration"],
        "techniques": ["T1071.004", "T1048"]
    },
    "malware_c2": {
        "tactics": ["Command and Control"],
        "techniques": ["T1071", "T1095"]
    },
    "data_exfiltration": {
        "tactics": ["Exfiltration"],
        "techniques": ["T1041", "T1048"]
    },
    "privilege_escalation": {
        "tactics": ["Privilege Escalation"],
        "techniques": ["T1068", "T1055"]
    },
    "lateral_movement": {
        "tactics": ["Lateral Movement"],
        "techniques": ["T1021", "T1570"]
    },
    "dos_attack": {
        "tactics": ["Impact"],
        "techniques": ["T1499"]
    },
    "reconnaissance": {
        "tactics": ["Reconnaissance"],
        "techniques": ["T1592", "T1590"]
    }
}


def get_mitre_mapping(attack_category: str) -> Dict[str, List[str]]:
    """Get MITRE ATT&CK mapping for an attack category"""
    return ATTACK_TO_MITRE.get(
        attack_category.lower(),
        {"tactics": ["Unknown"], "techniques": ["Unknown"]}
    )
