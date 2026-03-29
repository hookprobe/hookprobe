"""
CNO Type Definitions

Shared data types for the Cognitive Network Organism.
All types are plain dataclasses — no external dependencies.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional


# ------------------------------------------------------------------
# Biological Layer Mapping
# ------------------------------------------------------------------

class BrainLayer(str, Enum):
    """Which biological layer an event originates from or targets."""
    BRAINSTEM = "brainstem"      # <1ms, XDP/BPF autonomic
    CEREBELLUM = "cerebellum"    # 1-100ms, coordination/state
    CEREBRUM = "cerebrum"        # 100ms-30s, cognition/LLM


class StressState(str, Enum):
    """Organism-wide stress level (hypothalamus output)."""
    CALM = "calm"            # Normal operations, no threats
    ALERT = "alert"          # Elevated awareness, monitor closely
    FIGHT = "fight"          # Active threat engagement
    RECOVERY = "recovery"    # Post-incident stabilization


class EmotionState(str, Enum):
    """Network emotional state (amygdala output).

    Based on Russell's circumplex model mapped to defensive posture.
    Each state drives different adaptive camouflage behaviors.
    """
    SERENE = "serene"        # Low arousal, positive valence — no camo
    VIGILANT = "vigilant"    # Medium arousal — passive monitoring enhanced
    ANXIOUS = "anxious"      # High arousal, negative valence — TTL jitter, window randomization
    FEARFUL = "fearful"      # Very high arousal — full camo + honeypot deployment
    ANGRY = "angry"          # High arousal, negative valence — active counter-intel


class SynapticRoute(str, Enum):
    """Where the Synaptic Controller routes an event."""
    # Cerebrum destinations
    COGNITIVE_DEFENSE = "cognitive_defense"   # Frontal lobe — Reflex/Reason/Learn
    MULTI_RAG = "multi_rag"                  # Multi-RAG consensus engine
    SESSION_ANALYSIS = "session_analysis"     # Wernicke's area — dialogue analysis
    TEMPORAL_MEMORY = "temporal_memory"       # Temporal lobe — drift/patterns
    ENTITY_GRAPH = "entity_graph"            # Parietal lobe — kill chain attribution

    # Brainstem feedback (downward)
    XDP_BLOCKLIST = "xdp_blocklist"          # Push IP to XDP block map
    XDP_ALLOWLIST = "xdp_allowlist"          # Push IP to XDP allow map
    XDP_CAMOUFLAGE = "xdp_camouflage"        # Update camo BPF config
    XDP_FLOW_CTRL = "xdp_flow_ctrl"          # Update flow control stress level

    # Cerebellum feedback
    BASELINE_UPDATE = "baseline_update"       # Update Welford profile
    SIEM_INGEST = "siem_ingest"              # Ingest into Packet SIEM

    # Content pipeline
    SCRIBE = "scribe"                        # AEGIS SCRIBE agent for blog generation


# ------------------------------------------------------------------
# Synaptic Event — The universal message type
# ------------------------------------------------------------------

@dataclass
class SynapticEvent:
    """A single event flowing through the CNO nervous system.

    Every event has a source layer, a route (destination), priority,
    and a payload. The Synaptic Controller reads these to dispatch.
    """
    source_layer: BrainLayer
    route: SynapticRoute
    priority: int = 5                  # 1=critical, 10=informational
    timestamp: float = field(default_factory=time.time)

    # Event identity
    event_type: str = ""               # e.g., "velocity_spike", "novel_pattern"
    source_ip: str = ""                # Source IP if applicable
    dest_ip: str = ""                  # Destination IP if applicable

    # Payload
    payload: Dict[str, Any] = field(default_factory=dict)

    # Processing metadata
    processed: bool = False
    processed_by: str = ""
    processing_time_us: int = 0        # Microseconds to process

    def __repr__(self) -> str:
        return (f"SynapticEvent({self.source_layer.value}→{self.route.value}, "
                f"pri={self.priority}, type={self.event_type!r})")


# ------------------------------------------------------------------
# Stress Signal — Input to the Stress Gauge
# ------------------------------------------------------------------

@dataclass
class StressSignal:
    """A single stress metric from any subsystem."""
    source: str                        # e.g., "xdp_stats", "aegis_cognition"
    metric: str                        # e.g., "drop_rate", "active_incidents"
    value: float                       # Normalized 0.0 - 1.0
    timestamp: float = field(default_factory=time.time)


# ------------------------------------------------------------------
# Packet Snapshot — Lightweight packet record for SIEM working memory
# ------------------------------------------------------------------

@dataclass
class PacketSnapshot:
    """Lightweight record of a packet traversal for the 60s SIEM window.

    NOT a full packet capture — just enough for spatial awareness.
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    proto: int = 6                     # IP protocol (6=TCP, 17=UDP, 1=ICMP)
    bytes_len: int = 0
    action: str = "pass"               # pass, drop, alert
    intent_class: str = "benign"       # benign, scan, bruteforce, etc.
    community_id: str = ""


# ------------------------------------------------------------------
# Spatial State — Cerebellum's view of current network posture
# ------------------------------------------------------------------

@dataclass
class SpatialState:
    """The organism's proprioceptive awareness — where packets are moving.

    Computed from the 60s sliding window. Provides a snapshot for the
    Cerebrum to reason about without querying databases.
    """
    timestamp: float = field(default_factory=time.time)
    window_seconds: float = 60.0

    # Volume metrics
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0

    # Unique entities
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_flows: int = 0

    # Threat metrics
    drops: int = 0
    alerts: int = 0
    threat_ratio: float = 0.0         # (drops + alerts) / total_packets

    # Top talkers (src_ip → packet count)
    top_sources: Dict[str, int] = field(default_factory=dict)
    # Top targets (dst_ip → packet count)
    top_destinations: Dict[str, int] = field(default_factory=dict)
    # Protocol distribution
    protocol_dist: Dict[int, int] = field(default_factory=dict)
    # Intent distribution
    intent_dist: Dict[str, int] = field(default_factory=dict)

    # Anomaly flags
    is_under_attack: bool = False
    dominant_threat: str = ""


# ------------------------------------------------------------------
# BPF Map Write Request — Brainstem feedback
# ------------------------------------------------------------------

@dataclass
class BPFMapWrite:
    """Request to write a value to a BPF map (brainstem feedback).

    The Synaptic Controller batches these and executes via bpf_map_ops.
    """
    map_name: str                      # "blocklist", "allowlist", "stress_level", "camo_config"
    key: bytes = b""                   # Packed key
    value: bytes = b""                 # Packed value
    operation: str = "update"          # "update", "delete"
    ttl_seconds: int = 0              # 0 = permanent
    reason: str = ""                   # Audit trail
