"""
Base NSE Adapter - Abstract interface for product-tier NSE integration

HTP-DSM-NEURO-QSECBIT-NSE: The Core Security Stack
==================================================

This base class defines the contract that all product-tier NSE adapters
must implement. The stack provides:

- HTP: Secure, keyless transport with post-quantum cryptography
- DSM: Byzantine fault-tolerant consensus for threat validation
- NEURO: Neural resonance authentication (nobody knows the key)
- QSECBIT: Real-time threat scoring with RAG status
- NSE: Neural Synaptic Encryption - keys emerge from neural state

"One node's detection → Everyone's protection"
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import hashlib
import struct
import time


class ProductTier(Enum):
    """HookProbe product tier identifiers"""
    SENTINEL = "sentinel"   # 256MB - IoT Validator
    GUARDIAN = "guardian"   # 1.5GB - Travel Companion
    FORTRESS = "fortress"   # 4GB - Edge Router
    NEXUS = "nexus"         # 16GB+ - ML/AI Compute
    MSSP = "mssp"           # Cloud - Federation Platform


@dataclass
class NSECapabilities:
    """Capabilities available at each product tier"""
    tier: ProductTier
    max_memory_mb: int
    can_generate_keys: bool
    can_validate_ter: bool
    can_train_weights: bool
    can_relay_nse: bool
    can_run_adversarial: bool
    can_aggregate_threat_intel: bool
    max_concurrent_sessions: int
    supports_offline_mode: bool


# Define capabilities per tier
TIER_CAPABILITIES = {
    ProductTier.SENTINEL: NSECapabilities(
        tier=ProductTier.SENTINEL,
        max_memory_mb=256,
        can_generate_keys=False,  # Too memory constrained
        can_validate_ter=True,    # Lightweight validation
        can_train_weights=False,
        can_relay_nse=False,
        can_run_adversarial=False,
        can_aggregate_threat_intel=False,
        max_concurrent_sessions=5,
        supports_offline_mode=True,
    ),
    ProductTier.GUARDIAN: NSECapabilities(
        tier=ProductTier.GUARDIAN,
        max_memory_mb=1536,
        can_generate_keys=True,   # Full NSE client
        can_validate_ter=True,
        can_train_weights=False,  # Not enough for training
        can_relay_nse=False,
        can_run_adversarial=False,
        can_aggregate_threat_intel=True,
        max_concurrent_sessions=50,
        supports_offline_mode=True,
    ),
    ProductTier.FORTRESS: NSECapabilities(
        tier=ProductTier.FORTRESS,
        max_memory_mb=4096,
        can_generate_keys=True,
        can_validate_ter=True,
        can_train_weights=False,
        can_relay_nse=True,       # Can relay for other nodes
        can_run_adversarial=False,
        can_aggregate_threat_intel=True,
        max_concurrent_sessions=200,
        supports_offline_mode=True,
    ),
    ProductTier.NEXUS: NSECapabilities(
        tier=ProductTier.NEXUS,
        max_memory_mb=16384,
        can_generate_keys=True,
        can_validate_ter=True,
        can_train_weights=True,   # ML training capability
        can_relay_nse=True,
        can_run_adversarial=True,  # Can run red team tests
        can_aggregate_threat_intel=True,
        max_concurrent_sessions=1000,
        supports_offline_mode=True,
    ),
    ProductTier.MSSP: NSECapabilities(
        tier=ProductTier.MSSP,
        max_memory_mb=-1,  # Auto-scale
        can_generate_keys=True,
        can_validate_ter=True,
        can_train_weights=True,
        can_relay_nse=True,
        can_run_adversarial=True,  # Full adversarial framework
        can_aggregate_threat_intel=True,
        max_concurrent_sessions=-1,  # Unlimited
        supports_offline_mode=False,  # Cloud-native
    ),
}


@dataclass
class NSESessionState:
    """State of an NSE session"""
    session_id: str
    peer_id: str
    tier: ProductTier
    created_at: datetime
    last_activity: datetime
    neural_fingerprint: bytes
    current_qsecbit: float
    rag_status: str
    resonance_state: str  # UNALIGNED, SEEKING, ALIGNED, DRIFTING, LOST
    keys_derived: int
    ter_validated: int
    threats_detected: int
    threats_propagated: int


@dataclass
class ThreatIntel:
    """Threat intelligence record for mesh propagation"""
    intel_id: str
    source_node: str
    source_tier: ProductTier
    timestamp: datetime
    threat_type: str
    severity: str
    ioc_type: str
    ioc_value: str
    confidence: float
    hop_count: int
    seen_by: List[str] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Serialize for mesh transmission"""
        data = {
            'id': self.intel_id,
            'src': self.source_node,
            'tier': self.source_tier.value,
            'ts': self.timestamp.isoformat(),
            'type': self.threat_type,
            'sev': self.severity,
            'ioc_t': self.ioc_type,
            'ioc_v': self.ioc_value,
            'conf': self.confidence,
            'hops': self.hop_count,
        }
        import json
        return json.dumps(data).encode('utf-8')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ThreatIntel':
        """Deserialize from mesh transmission"""
        import json
        d = json.loads(data.decode('utf-8'))
        return cls(
            intel_id=d['id'],
            source_node=d['src'],
            source_tier=ProductTier(d['tier']),
            timestamp=datetime.fromisoformat(d['ts']),
            threat_type=d['type'],
            severity=d['sev'],
            ioc_type=d['ioc_t'],
            ioc_value=d['ioc_v'],
            confidence=d['conf'],
            hop_count=d['hops'],
        )


class BaseNSEAdapter(ABC):
    """
    Abstract base class for product-tier NSE adapters.

    The HTP-DSM-NEURO-QSECBIT-NSE stack provides:

    1. HTP (HookProbe Transport Protocol):
       - Post-quantum Kyber KEM for key exchange
       - ChaCha20-Poly1305 for symmetric encryption
       - Keyless authentication via entropy echo

    2. DSM (Decentralized Security Mesh):
       - Byzantine fault-tolerant consensus
       - Microblock chain for threat validation
       - 2/3 quorum for checkpoint finalization

    3. NEURO (Neural Resonance Protocol):
       - TER (Telemetry Event Records) for device identity
       - PoSF (Proof of Sensor Fusion) for authentication
       - Weight evolution creates unique device fingerprint

    4. QSECBIT (Quantified Security Metric):
       - Real-time threat scoring (0.0-1.0)
       - RAG status (GREEN < 0.45 < AMBER < 0.70 < RED)
       - Multi-layer detection (L2-L7)

    5. NSE (Neural Synaptic Encryption):
       - Keys emerge from neural state
       - Nobody knows the password - only the AI knows
       - Collective entropy from mesh consciousness
    """

    def __init__(self, node_id: str, tier: ProductTier):
        self.node_id = node_id
        self.tier = tier
        self.capabilities = TIER_CAPABILITIES[tier]
        self.sessions: Dict[str, NSESessionState] = {}
        self.threat_cache: Dict[str, ThreatIntel] = {}
        self._initialized = False
        self._start_time = datetime.now()

    @property
    def uptime_seconds(self) -> float:
        """Get adapter uptime in seconds"""
        return (datetime.now() - self._start_time).total_seconds()

    # =========================================================================
    # ABSTRACT METHODS - Must be implemented by each tier
    # =========================================================================

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the NSE adapter for this tier"""
        pass

    @abstractmethod
    def derive_session_key(
        self,
        peer_id: str,
        rdv: bytes,
        qsecbit: float,
    ) -> Optional[bytes]:
        """
        Derive an encryption key using NSE.

        The key is derived from:
        - Neural weight state
        - Resonance Drift Vector (RDV)
        - Current Qsecbit score
        - Peer identity

        Returns None if tier cannot generate keys.
        """
        pass

    @abstractmethod
    def validate_ter(
        self,
        ter_bytes: bytes,
        expected_source: str,
    ) -> Tuple[bool, str]:
        """
        Validate a Telemetry Event Record.

        Returns:
            (is_valid, reason)
        """
        pass

    @abstractmethod
    def report_threat(self, threat: ThreatIntel) -> bool:
        """
        Report a detected threat to the mesh.

        The threat will be:
        1. Validated locally
        2. Added to threat cache
        3. Propagated to connected peers
        4. Submitted to DSM for consensus
        """
        pass

    @abstractmethod
    def get_mesh_status(self) -> Dict[str, Any]:
        """Get current mesh connectivity and health status"""
        pass

    # =========================================================================
    # COMMON METHODS - Shared across all tiers
    # =========================================================================

    def create_session(
        self,
        peer_id: str,
        initial_fingerprint: bytes,
    ) -> NSESessionState:
        """Create a new NSE session with a peer"""
        session_id = self._generate_session_id(peer_id)
        now = datetime.now()

        session = NSESessionState(
            session_id=session_id,
            peer_id=peer_id,
            tier=self.tier,
            created_at=now,
            last_activity=now,
            neural_fingerprint=initial_fingerprint,
            current_qsecbit=0.0,
            rag_status="GREEN",
            resonance_state="UNALIGNED",
            keys_derived=0,
            ter_validated=0,
            threats_detected=0,
            threats_propagated=0,
        )

        self.sessions[session_id] = session
        return session

    def update_session_qsecbit(
        self,
        session_id: str,
        qsecbit: float,
        rag_status: str,
    ) -> None:
        """Update session Qsecbit score"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.current_qsecbit = qsecbit
            session.rag_status = rag_status
            session.last_activity = datetime.now()

    def get_session(self, session_id: str) -> Optional[NSESessionState]:
        """Get session by ID"""
        return self.sessions.get(session_id)

    def cleanup_stale_sessions(self, max_age_seconds: int = 3600) -> int:
        """Remove sessions that have been inactive"""
        now = datetime.now()
        stale = [
            sid for sid, session in self.sessions.items()
            if (now - session.last_activity).total_seconds() > max_age_seconds
        ]
        for sid in stale:
            del self.sessions[sid]
        return len(stale)

    def cache_threat(self, threat: ThreatIntel) -> None:
        """Add threat to local cache"""
        self.threat_cache[threat.intel_id] = threat

        # Enforce cache size limit based on tier
        max_cache = {
            ProductTier.SENTINEL: 100,
            ProductTier.GUARDIAN: 1000,
            ProductTier.FORTRESS: 5000,
            ProductTier.NEXUS: 50000,
            ProductTier.MSSP: 500000,
        }.get(self.tier, 1000)

        if len(self.threat_cache) > max_cache:
            # Remove oldest entries
            sorted_threats = sorted(
                self.threat_cache.items(),
                key=lambda x: x[1].timestamp
            )
            for tid, _ in sorted_threats[:len(sorted_threats) - max_cache]:
                del self.threat_cache[tid]

    def is_threat_known(self, intel_id: str) -> bool:
        """Check if threat is already in cache (deduplication)"""
        return intel_id in self.threat_cache

    def get_stats(self) -> Dict[str, Any]:
        """Get adapter statistics"""
        return {
            'node_id': self.node_id,
            'tier': self.tier.value,
            'capabilities': {
                'can_generate_keys': self.capabilities.can_generate_keys,
                'can_validate_ter': self.capabilities.can_validate_ter,
                'can_train_weights': self.capabilities.can_train_weights,
                'can_relay_nse': self.capabilities.can_relay_nse,
                'can_run_adversarial': self.capabilities.can_run_adversarial,
            },
            'sessions': {
                'active': len(self.sessions),
                'max': self.capabilities.max_concurrent_sessions,
            },
            'threat_cache': {
                'size': len(self.threat_cache),
            },
            'uptime_seconds': self.uptime_seconds,
            'initialized': self._initialized,
        }

    def _generate_session_id(self, peer_id: str) -> str:
        """Generate unique session ID"""
        data = f"{self.node_id}:{peer_id}:{time.time_ns()}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]

    def _generate_threat_id(self) -> str:
        """Generate unique threat ID"""
        data = f"{self.node_id}:{time.time_ns()}"
        return hashlib.sha256(data.encode()).hexdigest()[:24]
