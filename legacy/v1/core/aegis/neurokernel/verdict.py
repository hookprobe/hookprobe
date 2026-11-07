"""
Verdict Types — Shared decision types for Hybrid Inference.

Defines the verdicts that both the fast path (local QSecBit/0.5B model)
and slow path (Nexus 8B LLM) produce.

Verdicts flow:
    QSecBit fast path → Verdict (confidence > 0.90 → done)
    Nexus slow path  → Verdict (1-5 seconds, higher quality)

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------

class VerdictAction(str, Enum):
    """The action to take based on inference."""
    ALLOW = "allow"               # Traffic is safe
    DROP = "drop"                 # Block the traffic
    RATE_LIMIT = "rate_limit"     # Throttle the source
    INVESTIGATE = "investigate"   # Needs deeper analysis
    QUARANTINE = "quarantine"     # Isolate the source
    PENDING = "pending"           # Awaiting Nexus response


class VerdictSource(str, Enum):
    """Where the verdict came from."""
    QSECBIT = "qsecbit"           # QSecBit signature match (< 1ms)
    LOCAL_MODEL = "local_model"   # Local 0.5B model (~ 100ms)
    NEXUS = "nexus"               # Nexus 8B LLM (1-5s)
    TEMPLATE = "template"         # Template match (instant)
    FALLBACK = "fallback"         # Timeout/error fallback
    SHADOW = "shadow"             # Shadow pentester finding


class ConfidenceLevel(str, Enum):
    """Bucketed confidence for routing decisions."""
    HIGH = "high"          # >= 0.90 — fast path sufficient
    MEDIUM = "medium"      # 0.70-0.90 — local model
    LOW = "low"            # 0.50-0.70 — offload to Nexus
    UNKNOWN = "unknown"    # < 0.50 — must offload


# ------------------------------------------------------------------
# Data Types
# ------------------------------------------------------------------

@dataclass
class VerdictResult:
    """The output of an inference decision."""
    action: VerdictAction
    confidence: float                    # 0.0 - 1.0
    source: VerdictSource
    reasoning: str = ""                  # LLM reasoning (if from model)
    source_ip: str = ""                  # Source IP being judged
    threat_type: str = ""                # Detected threat category
    severity: str = ""                   # CRITICAL/HIGH/MEDIUM/LOW
    suggested_ebpf: str = ""             # Suggested eBPF template name
    latency_ms: float = 0.0             # Time to produce verdict
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Bucket confidence into a level."""
        if self.confidence >= 0.90:
            return ConfidenceLevel.HIGH
        if self.confidence >= 0.70:
            return ConfidenceLevel.MEDIUM
        if self.confidence >= 0.50:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.UNKNOWN

    @property
    def is_blocking(self) -> bool:
        """Whether this verdict blocks traffic."""
        return self.action in (VerdictAction.DROP, VerdictAction.QUARANTINE)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "source": self.source.value,
            "reasoning": self.reasoning,
            "source_ip": self.source_ip,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "suggested_ebpf": self.suggested_ebpf,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp,
            "is_blocking": self.is_blocking,
            "metadata": self.metadata,
        }


@dataclass
class ThreatContext:
    """Context for a threat event being analyzed."""
    event_type: str
    source_ip: str = ""
    dest_ip: str = ""
    severity: str = "MEDIUM"
    qsecbit_score: float = 0.5          # Current QSecBit resilience score
    qsecbit_confidence: float = 0.5     # QSecBit's confidence in classification
    rag_context: str = ""               # Streaming RAG context
    signal_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_prompt(self) -> str:
        """Format as an LLM prompt context string."""
        parts = [
            f"Event: {self.event_type} from {self.source_ip}",
            f"Severity: {self.severity}",
            f"QSecBit Score: {self.qsecbit_score:.2f} (confidence: {self.qsecbit_confidence:.2f})",
        ]
        if self.dest_ip:
            parts.append(f"Destination: {self.dest_ip}")
        if self.rag_context:
            parts.append(f"\nRecent Activity:\n{self.rag_context}")
        return "\n".join(parts)


# ------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------

def make_allow(
    source: VerdictSource = VerdictSource.QSECBIT,
    confidence: float = 0.95,
    **kwargs,
) -> VerdictResult:
    """Create an ALLOW verdict."""
    return VerdictResult(
        action=VerdictAction.ALLOW,
        confidence=confidence,
        source=source,
        **kwargs,
    )


def make_drop(
    source: VerdictSource = VerdictSource.QSECBIT,
    confidence: float = 0.95,
    **kwargs,
) -> VerdictResult:
    """Create a DROP verdict."""
    return VerdictResult(
        action=VerdictAction.DROP,
        confidence=confidence,
        source=source,
        **kwargs,
    )


def make_investigate(
    source: VerdictSource = VerdictSource.QSECBIT,
    confidence: float = 0.5,
    **kwargs,
) -> VerdictResult:
    """Create an INVESTIGATE verdict (needs Nexus analysis)."""
    return VerdictResult(
        action=VerdictAction.INVESTIGATE,
        confidence=confidence,
        source=source,
        **kwargs,
    )


def make_pending(source_ip: str = "", **kwargs) -> VerdictResult:
    """Create a PENDING verdict (awaiting Nexus response)."""
    return VerdictResult(
        action=VerdictAction.PENDING,
        confidence=0.0,
        source=VerdictSource.FALLBACK,
        source_ip=source_ip,
        **kwargs,
    )
