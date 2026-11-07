"""
MSSP Intelligence Types — Minimal clean-slate models.

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies

Data Flow:
    Finding:        Edge → MSSP (threat detection report, piggybacked on heartbeat)
    Recommendation: MSSP → Edge (signed action, delivered in heartbeat response)
    Feedback:       Edge → MSSP (execution outcome, piggybacked on next heartbeat)
"""

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict


@dataclass
class Finding:
    """A threat finding reported by an edge node to MSSP via heartbeat."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: str = ""          # ddos, brute_force, port_scan, malware, etc.
    severity: int = 4              # 1=critical, 2=high, 3=medium, 4=low, 5=info
    confidence: float = 0.0        # 0.0–1.0
    ioc_type: str = ""             # ip, domain, hash, mac, pattern
    ioc_value: str = ""            # The actual indicator of compromise
    evidence: Dict[str, Any] = field(default_factory=dict)
    local_action: str = ""         # What the node already did (e.g. "blocked_ip")
    description: str = ""          # Human-readable summary

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}

    @classmethod
    def from_dict(cls, data: dict) -> 'Finding':
        fields = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in fields})


@dataclass
class Recommendation:
    """A signed action recommended by MSSP, delivered in heartbeat response."""
    id: str = ""
    finding_id: str = ""           # Links back to source Finding
    action: str = ""               # BLOCK_IP, BLOCK_DOMAIN, DNS_SINKHOLE, etc.
    target: str = ""               # What to act on
    confidence: float = 0.0        # 0.0–1.0
    ttl: int = 3600                # Seconds until expiry
    priority: int = 4              # 1=critical through 5=info
    reasoning: str = ""            # Why this action
    sig: str = ""                  # HMAC-SHA256 signature

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'Recommendation':
        fields = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in fields})


@dataclass
class Feedback:
    """Feedback from a node after executing a recommendation."""
    action_id: str = ""            # Which recommendation was executed
    success: bool = True           # Did it work?
    effect: str = ""               # What happened after execution
    false_positive: bool = False   # Was the finding wrong?

    def to_dict(self) -> dict:
        return asdict(self)
