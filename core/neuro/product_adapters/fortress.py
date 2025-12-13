"""
Fortress NSE Adapter - Edge Router with Relay (4GB)

The Fortress tier provides edge routing and NSE relay capabilities
for business networks. It can relay NSE traffic for constrained
nodes and coordinate regional threat intelligence.

"One node's detection → Everyone's protection"

HTP-DSM-NEURO-QSECBIT-NSE Integration:
- Full NSE key derivation
- NSE relay for Sentinel nodes
- Regional threat aggregation
- VLAN-aware security segmentation
- DSM checkpoint coordination
"""

from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List, Set
import hashlib
import struct
import time

from .base import (
    BaseNSEAdapter,
    ProductTier,
    NSESessionState,
    ThreatIntel,
)


class FortressNSEAdapter(BaseNSEAdapter):
    """
    Fortress NSE Adapter for edge routers (4GB RAM)

    Capabilities:
    - Full NSE key derivation
    - Complete TER validation
    - NSE relay for constrained nodes
    - Regional threat aggregation
    - VLAN-aware security policies
    - Up to 200 concurrent sessions

    The Fortress acts as a regional coordinator, relaying NSE
    traffic for Sentinel nodes and aggregating threats from
    multiple sources.
    """

    def __init__(self, node_id: str):
        super().__init__(node_id, ProductTier.FORTRESS)
        self._neural_weights: Optional[bytes] = None
        self._collective_entropy: bytes = b'\x00' * 32
        self._relay_sessions: Dict[str, Set[str]] = {}  # node_id -> set of relayed peers
        self._downstream_nodes: Dict[str, ProductTier] = {}  # nodes we relay for
        self._regional_threats: Dict[str, ThreatIntel] = {}
        self._vlan_policies: Dict[int, Dict[str, Any]] = {}
        self._keys_derived: int = 0
        self._relays_processed: int = 0

    def initialize(self) -> bool:
        """Initialize Fortress NSE adapter"""
        try:
            self._neural_weights = self._initialize_weights()
            self._collective_entropy = self._gather_local_entropy()
            self._initialized = True
            return True
        except Exception:
            return False

    def _initialize_weights(self) -> bytes:
        """Initialize neural weights"""
        seed = hashlib.sha512(self.node_id.encode()).digest()
        return seed[:64]

    def _gather_local_entropy(self) -> bytes:
        """Gather entropy from local sources"""
        sources = [
            struct.pack('>Q', time.time_ns()),
            self.node_id.encode(),
        ]
        import os
        sources.append(struct.pack('>I', os.getpid()))
        return hashlib.sha256(b''.join(sources)).digest()

    def derive_session_key(
        self,
        peer_id: str,
        rdv: bytes,
        qsecbit: float,
    ) -> Optional[bytes]:
        """Derive NSE key - same as Guardian but with relay context"""
        if not self._neural_weights:
            return None

        kdf_input = b''.join([
            self._neural_weights,
            rdv,
            struct.pack('>f', qsecbit),
            self._collective_entropy,
            peer_id.encode(),
            b'NSE-FORTRESS-KEY-V1',
        ])

        key = hashlib.sha256(kdf_input).digest()
        for _ in range(1000):
            key = hashlib.sha256(key + kdf_input).digest()

        self._keys_derived += 1
        return key

    def validate_ter(
        self,
        ter_bytes: bytes,
        expected_source: str,
    ) -> Tuple[bool, str]:
        """Full TER validation - same as Guardian"""
        if len(ter_bytes) != 64:
            return False, f"Invalid TER length: {len(ter_bytes)}"

        h_entropy = ter_bytes[:32]
        timestamp = struct.unpack('>Q', ter_bytes[52:60])[0]
        sequence = struct.unpack('>H', ter_bytes[60:62])[0]
        chain_hash = struct.unpack('>H', ter_bytes[62:64])[0]

        now_us = int(datetime.now().timestamp() * 1_000_000)
        age_seconds = (now_us - timestamp) / 1_000_000
        if age_seconds > 3600 or age_seconds < -60:
            return False, "Timestamp out of range"

        byte_counts = [0] * 256
        for b in h_entropy:
            byte_counts[b] += 1
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / 32
                import math
                entropy -= p * math.log2(p)
        if entropy < 4.0:
            return False, f"Low entropy: {entropy:.2f}"

        expected_chain = self._compute_chain_hash(ter_bytes[:62])
        if chain_hash != expected_chain:
            return False, "Chain hash mismatch"

        return True, "Valid TER"

    def _compute_chain_hash(self, data: bytes) -> int:
        """Compute CRC16 chain hash"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc

    def report_threat(self, threat: ThreatIntel) -> bool:
        """Report and aggregate threat at regional level"""
        if self.is_threat_known(threat.intel_id):
            return False

        if not threat.seen_by:
            threat.seen_by = []
        threat.seen_by.append(self.node_id)

        self.cache_threat(threat)
        self._regional_threats[threat.intel_id] = threat

        # Propagate to upstream and downstream
        return True

    def get_mesh_status(self) -> Dict[str, Any]:
        """Get Fortress mesh and relay status"""
        return {
            'node_id': self.node_id,
            'tier': 'fortress',
            'initialized': self._initialized,
            'downstream_nodes': len(self._downstream_nodes),
            'relay_sessions': sum(len(peers) for peers in self._relay_sessions.values()),
            'relays_processed': self._relays_processed,
            'keys_derived': self._keys_derived,
            'regional_threats': len(self._regional_threats),
            'threat_cache_size': len(self.threat_cache),
            'sessions': len(self.sessions),
            'vlan_policies': len(self._vlan_policies),
            'status': 'healthy' if self._initialized else 'initializing',
        }

    # =========================================================================
    # RELAY CAPABILITIES (Fortress-specific)
    # =========================================================================

    def register_downstream(
        self,
        node_id: str,
        tier: ProductTier,
    ) -> bool:
        """Register a downstream node for relay"""
        if len(self._downstream_nodes) >= 50:  # Max downstream nodes
            return False
        self._downstream_nodes[node_id] = tier
        self._relay_sessions[node_id] = set()
        return True

    def relay_key_request(
        self,
        source_node: str,
        target_peer: str,
        rdv: bytes,
        qsecbit: float,
    ) -> Optional[bytes]:
        """
        Relay NSE key derivation for a downstream node.

        Fortress derives keys on behalf of constrained Sentinel
        nodes that cannot perform key derivation locally.
        """
        if source_node not in self._downstream_nodes:
            return None

        # Track relay session
        if source_node in self._relay_sessions:
            self._relay_sessions[source_node].add(target_peer)

        self._relays_processed += 1

        # Derive key with relay context
        return self.derive_session_key(target_peer, rdv, qsecbit)

    def unregister_downstream(self, node_id: str) -> None:
        """Remove a downstream node"""
        self._downstream_nodes.pop(node_id, None)
        self._relay_sessions.pop(node_id, None)

    # =========================================================================
    # VLAN-AWARE SECURITY (Fortress-specific)
    # =========================================================================

    def set_vlan_policy(
        self,
        vlan_id: int,
        policy: Dict[str, Any],
    ) -> None:
        """Set security policy for a VLAN"""
        self._vlan_policies[vlan_id] = {
            'vlan_id': vlan_id,
            'allow_nse': policy.get('allow_nse', True),
            'max_sessions': policy.get('max_sessions', 20),
            'threat_sensitivity': policy.get('threat_sensitivity', 'medium'),
            'isolation_level': policy.get('isolation_level', 'standard'),
            'updated_at': datetime.now().isoformat(),
        }

    def get_vlan_policy(self, vlan_id: int) -> Optional[Dict[str, Any]]:
        """Get security policy for a VLAN"""
        return self._vlan_policies.get(vlan_id)

    def get_regional_threat_summary(self) -> Dict[str, Any]:
        """Get aggregated threat summary for the region"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        threat_types: Dict[str, int] = {}

        for threat in self._regional_threats.values():
            severity_counts[threat.severity.lower()] = severity_counts.get(
                threat.severity.lower(), 0
            ) + 1
            threat_types[threat.threat_type] = threat_types.get(
                threat.threat_type, 0
            ) + 1

        return {
            'total_threats': len(self._regional_threats),
            'by_severity': severity_counts,
            'by_type': threat_types,
            'downstream_nodes': len(self._downstream_nodes),
            'coverage_area': 'regional',
        }
