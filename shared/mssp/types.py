"""
MSSP Intelligence Types

Shared data models for the HookProbe Collective Intelligence Loop.
Used by all tiers for MSSP communication and mesh propagation.

Data Flow:
    ThreatFinding:     Edge → MSSP (detection report)
    RecommendedAction: MSSP/Nexus → Edge (action to take)
    ExecutionFeedback: Edge → MSSP (outcome report)
    DeviceMetrics:     Edge → MSSP (heartbeat telemetry)
"""

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingStatus(str, Enum):
    """Status of a threat finding in the intelligence pipeline."""
    SUBMITTED = "submitted"
    PENDING_ANALYSIS = "pending_analysis"
    ANALYZING = "analyzing"
    RECOMMENDATION_READY = "recommendation_ready"
    ACKNOWLEDGED = "acknowledged"
    EXPIRED = "expired"


class ActionType(str, Enum):
    """Types of recommended actions."""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_MAC = "block_mac"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    DNS_SINKHOLE = "dns_sinkhole"
    MONITOR = "monitor"
    ALERT = "alert"
    TERMINATE_SESSION = "terminate_session"
    UPDATE_POLICY = "update_policy"


class ActionPriority(int, Enum):
    """Priority levels for recommended actions.

    Lower number = higher priority. Controls gossip TTL and consensus requirements.
    """
    CRITICAL = 1   # 10 hops, BFT consensus required
    HIGH = 2       # 8 hops, single Nexus signature
    MEDIUM = 3     # 5 hops, single Nexus signature
    LOW = 4        # 3 hops, no consensus
    INFO = 5       # 2 hops, lazy gossip


class SourceTier(str, Enum):
    """Product tier that generated the finding."""
    SENTINEL = "sentinel"
    GUARDIAN = "guardian"
    FORTRESS = "fortress"
    NEXUS = "nexus"


# ---------------------------------------------------------------------------
# Core Intelligence Types
# ---------------------------------------------------------------------------

@dataclass
class ThreatFinding:
    """A threat finding reported by any edge node to MSSP.

    This is the primary unit of intelligence flowing FROM edge nodes TO MSSP.
    MSSP routes HIGH+ severity or needs_deep_analysis findings to Nexus.
    """
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_tier: str = "fortress"
    source_node_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    threat_type: str = ""          # MITRE ATT&CK technique ID or descriptive type
    severity: str = "LOW"          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float = 0.0        # 0.0 - 1.0
    ioc_type: str = ""             # ip, domain, hash, mac, pattern
    ioc_value: str = ""            # The actual indicator of compromise
    local_action_taken: str = ""   # What the node already did (e.g., "blocked_ip")
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    needs_deep_analysis: bool = False
    description: str = ""

    # Populated by MSSP after submission
    status: str = FindingStatus.SUBMITTED.value

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatFinding':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid_fields})

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ThreatFinding':
        return cls.from_dict(json.loads(data.decode('utf-8')))

    @property
    def content_hash(self) -> str:
        """Deterministic hash for deduplication."""
        key = f"{self.source_node_id}:{self.threat_type}:{self.ioc_value}:{self.severity}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class RecommendedAction:
    """An action recommended by Nexus AI, delivered via MSSP.

    This is the primary unit of intelligence flowing FROM MSSP/Nexus TO edge nodes.
    Can be propagated across the mesh via DSM gossip.
    """
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""           # Links to original ThreatFinding
    action_type: str = ActionType.ALERT.value
    target: str = ""               # IP, domain, MAC, etc.
    confidence: float = 0.0        # 0.0 - 1.0
    reasoning: str = ""            # Plain-English explanation from Nexus AI
    ttl_seconds: int = 3600        # How long action should persist (default 1h)
    priority: int = ActionPriority.LOW.value
    mesh_propagate: bool = False   # Should this be gossiped to mesh?
    nexus_analysis: Dict[str, Any] = field(default_factory=dict)
    mitre_attack_id: str = ""      # MITRE ATT&CK technique ID
    signature: str = ""            # Ed25519 signature from MSSP
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RecommendedAction':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid_fields})

    @classmethod
    def from_bytes(cls, data: bytes) -> 'RecommendedAction':
        return cls.from_dict(json.loads(data.decode('utf-8')))

    @property
    def gossip_ttl_hops(self) -> int:
        """Gossip TTL based on priority."""
        return {1: 10, 2: 8, 3: 5, 4: 3, 5: 2}.get(self.priority, 3)

    @property
    def requires_consensus(self) -> bool:
        """Whether BFT consensus is required before mesh propagation."""
        return self.priority <= ActionPriority.CRITICAL.value


@dataclass
class ExecutionFeedback:
    """Feedback from a node after executing a recommended action.

    Flows FROM edge nodes TO MSSP for continuous learning.
    Nexus uses this to improve future recommendations via meta-regressive learning.
    """
    feedback_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str = ""            # Which recommendation was executed
    node_id: str = ""              # Which node executed it
    executed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    success: bool = True           # Did the action execute successfully?
    effect_observed: str = ""      # What happened after execution
    false_positive: bool = False   # User marked as false positive
    metrics_before: Dict[str, Any] = field(default_factory=dict)  # QSecBit score before
    metrics_after: Dict[str, Any] = field(default_factory=dict)   # QSecBit score after

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceMetrics:
    """Device telemetry metrics for heartbeat.

    Sent periodically from all tiers to MSSP for monitoring.
    """
    status: str = 'online'
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    disk_usage: float = 0.0
    uptime_seconds: int = 0
    qsecbit_score: Optional[float] = None
    threat_events_count: int = 0
    network_rx_rate: float = 0.0
    network_tx_rate: float = 0.0
    aegis_tier: str = ""           # pico/lite/full/deep
    napse_active: bool = False     # Whether local NAPSE is running
    mesh_peers: int = 0            # Number of connected mesh peers

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class IntelligenceReport:
    """Full intelligence report from Nexus deep analysis.

    Contains the complete analysis of a threat finding, including
    correlation across devices, simulation results, and recommendations.
    """
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    analyzed_by: str = ""          # Nexus node ID
    analysis_duration_ms: int = 0
    threat_assessment: str = ""    # confirmed/likely/possible/false_positive
    cross_device_hits: int = 0     # Same IOC seen on other nodes
    related_findings: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    simulation_result: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[RecommendedAction] = field(default_factory=list)
    summary: str = ""              # Plain-English summary

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['recommendations'] = [r.to_dict() for r in self.recommendations]
        return data
