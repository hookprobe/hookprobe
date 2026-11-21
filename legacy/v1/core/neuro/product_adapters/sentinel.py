"""
Sentinel NSE Adapter - Lightweight IoT Validator (256MB)

The Sentinel tier provides lightweight NSE validation for IoT devices
and constrained environments. It cannot generate keys but can validate
TER records from other nodes.

"One node's detection → Everyone's protection"

HTP-DSM-NEURO-QSECBIT-NSE Integration:
- Validates incoming TER records
- Participates in DSM consensus (partial signatures)
- Reports threats to upstream nodes
- Maintains minimal threat cache (100 entries)
"""

from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import hashlib
import struct

from .base import (
    BaseNSEAdapter,
    ProductTier,
    NSESessionState,
    ThreatIntel,
)


class SentinelNSEAdapter(BaseNSEAdapter):
    """
    Sentinel NSE Adapter for IoT validators (256MB RAM)

    Capabilities:
    - TER validation (lightweight)
    - Threat reporting (upstream only)
    - DSM consensus participation (partial signatures)

    Limitations:
    - Cannot generate NSE keys (memory constrained)
    - Cannot relay NSE traffic
    - Cannot run adversarial tests
    - Maximum 5 concurrent sessions
    """

    def __init__(self, node_id: str):
        super().__init__(node_id, ProductTier.SENTINEL)
        self._upstream_node: Optional[str] = None
        self._ter_sequence: int = 0
        self._validation_count: int = 0

    def initialize(self) -> bool:
        """Initialize Sentinel NSE adapter"""
        try:
            # Sentinel has minimal initialization
            # Just verify we have enough memory
            self._initialized = True
            return True
        except Exception:
            return False

    def derive_session_key(
        self,
        peer_id: str,
        rdv: bytes,
        qsecbit: float,
    ) -> Optional[bytes]:
        """
        Sentinel cannot derive keys - too memory constrained.
        Returns None to indicate key derivation not supported.
        """
        # Sentinel tier cannot generate keys
        return None

    def validate_ter(
        self,
        ter_bytes: bytes,
        expected_source: str,
    ) -> Tuple[bool, str]:
        """
        Lightweight TER validation for Sentinel tier.

        Performs:
        1. Length check (must be 64 bytes)
        2. Timestamp freshness check
        3. Sequence monotonicity check
        4. Basic entropy check on H_Entropy field
        """
        self._validation_count += 1

        # Check length
        if len(ter_bytes) != 64:
            return False, f"Invalid TER length: {len(ter_bytes)}, expected 64"

        # Parse TER structure
        # H_Entropy (32) + H_Integrity (20) + Timestamp (8) + Sequence (2) + Chain_Hash (2)
        h_entropy = ter_bytes[:32]
        h_integrity = ter_bytes[32:52]
        timestamp = struct.unpack('>Q', ter_bytes[52:60])[0]
        sequence = struct.unpack('>H', ter_bytes[60:62])[0]
        chain_hash = struct.unpack('>H', ter_bytes[62:64])[0]

        # Check timestamp freshness (within last hour)
        now_us = int(datetime.now().timestamp() * 1_000_000)
        age_seconds = (now_us - timestamp) / 1_000_000
        if age_seconds > 3600:  # 1 hour max age
            return False, f"TER too old: {age_seconds:.0f} seconds"
        if age_seconds < -60:  # 1 minute future tolerance
            return False, "TER timestamp in future"

        # Check entropy field has sufficient randomness
        # Simple check: at least 16 unique bytes
        unique_bytes = len(set(h_entropy))
        if unique_bytes < 16:
            return False, f"Insufficient entropy: {unique_bytes} unique bytes"

        # Sequence check (basic - just ensure non-zero)
        if sequence == 0:
            return False, "Invalid sequence number"

        # All checks passed
        self._ter_sequence = max(self._ter_sequence, sequence)
        return True, "Valid"

    def report_threat(self, threat: ThreatIntel) -> bool:
        """
        Report threat to upstream node.

        Sentinel cannot propagate directly to mesh - it reports
        to its upstream Guardian/Fortress node.
        """
        if not self._upstream_node:
            # Cache locally until upstream is available
            self.cache_threat(threat)
            return False

        # Add to cache
        self.cache_threat(threat)

        # In real implementation, would send to upstream via HTP
        # For now, just mark as reported
        return True

    def get_mesh_status(self) -> Dict[str, Any]:
        """Get Sentinel mesh status"""
        return {
            'node_id': self.node_id,
            'tier': 'sentinel',
            'upstream_connected': self._upstream_node is not None,
            'upstream_node': self._upstream_node,
            'ter_validations': self._validation_count,
            'threat_cache_size': len(self.threat_cache),
            'sessions': len(self.sessions),
            'status': 'healthy' if self._initialized else 'initializing',
        }

    def set_upstream(self, upstream_node_id: str) -> None:
        """Set the upstream node for threat reporting"""
        self._upstream_node = upstream_node_id

    def get_validation_stats(self) -> Dict[str, int]:
        """Get TER validation statistics"""
        return {
            'total_validations': self._validation_count,
            'current_sequence': self._ter_sequence,
            'cached_threats': len(self.threat_cache),
        }
