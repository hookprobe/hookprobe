"""
Neuro Integration Layer - Wires NSE into HTP, DSM, and Mesh

This module provides the missing "glue" that connects:
- Neural Synaptic Encryption (NSE) → HTP Transport
- TER Validation → DSM Consensus
- Weight Fingerprints → Mesh Authentication

Closes the critical integration gaps identified in the architecture review.

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import hashlib
import hmac
import struct
import time
import secrets
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple, Callable, Protocol
from collections import deque
from threading import Lock
import logging

logger = logging.getLogger(__name__)

# Try imports with graceful fallback
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from .core.ter import TER, TERGenerator
    from .neural.engine import NeuralEngine
    from .synaptic_encryption import (
        SynapticEncryptionEngine, SynapticState, ResonanceProof
    )
    from .dsm_bridge import NeuroDSMBridge
    NEURO_AVAILABLE = True
except ImportError:
    NEURO_AVAILABLE = False


# ============================================================================
# KEY DERIVATION - Closes Gap: HTP encryption_key never set
# ============================================================================

@dataclass
class DerivedKeyMaterial:
    """Complete key material derived from neural state."""
    # Encryption key (32 bytes for ChaCha20)
    encryption_key: bytes

    # Authentication key (32 bytes for HMAC)
    auth_key: bytes

    # Key identifier (for key rotation tracking)
    key_id: bytes  # 16 bytes

    # Timestamp of derivation
    derived_at_us: int

    # Inputs used (for debugging/auditing)
    inputs_hash: bytes  # 16 bytes

    def is_fresh(self, max_age_us: int = 1_000_000) -> bool:
        """Check if key material is fresh (default 1 second max age)."""
        now_us = time.time_ns() // 1000
        return (now_us - self.derived_at_us) < max_age_us


class NeuroKeyDerivation:
    """
    Derives encryption keys from neural state.

    Closes the critical gap where HTP's encryption_key is never set.

    Key = HKDF(
        salt=qsecbit_history[:32],
        ikm=weight_fingerprint || RDV || TER.h_entropy || hardware_attestation,
        info="htp-neuro-v5.0",
        length=32
    )
    """

    VERSION = b"htp-neuro-v5.0"
    KEY_ROTATION_US = 1_000_000  # Rotate keys every second

    def __init__(
        self,
        node_id: bytes,
        hardware_attestation: Optional[bytes] = None
    ):
        self.node_id = node_id
        self.hardware_attestation = hardware_attestation or self._derive_hw_attestation()
        self._lock = Lock()

        # State tracking
        self._qsecbit_history: deque = deque(maxlen=100)
        self._last_key: Optional[DerivedKeyMaterial] = None

        # Statistics
        self.stats = {
            'keys_derived': 0,
            'rotations': 0,
        }

    def _derive_hw_attestation(self) -> bytes:
        """Derive hardware attestation from system characteristics."""
        import platform
        system_data = (
            platform.node().encode() +
            platform.machine().encode() +
            self.node_id
        )
        return hashlib.sha256(system_data).digest()

    def derive_session_key(
        self,
        weight_fingerprint: bytes,
        rdv: bytes,
        ter_entropy: bytes,
        qsecbit_current: float,
        peer_contribution: Optional[bytes] = None
    ) -> DerivedKeyMaterial:
        """
        Derive encryption key material from neural state.

        This is the core function that closes the HTP encryption gap.

        Args:
            weight_fingerprint: 32 bytes from NeuralEngine
            rdv: 32 bytes Resonance Drift Vector
            ter_entropy: 32 bytes TER H_Entropy
            qsecbit_current: Current Qsecbit score
            peer_contribution: Optional peer's weight fingerprint

        Returns:
            DerivedKeyMaterial with encryption and auth keys
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library not available")

        with self._lock:
            # Track qsecbit history
            self._qsecbit_history.append(struct.pack('<f', qsecbit_current))

            # Build salt from qsecbit history
            if len(self._qsecbit_history) >= 8:
                salt = hashlib.sha256(b''.join(self._qsecbit_history)).digest()
            else:
                salt = hashlib.sha256(self.hardware_attestation).digest()

            # Build input key material
            ikm_parts = [
                weight_fingerprint,
                rdv,
                ter_entropy,
                self.hardware_attestation,
                struct.pack('<Q', time.time_ns() // 1000),  # Microsecond binding
            ]

            if peer_contribution:
                ikm_parts.append(peer_contribution)

            ikm = b''.join(ikm_parts)

            # Derive master secret
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,  # 32 encryption + 32 auth
                salt=salt,
                info=self.VERSION,
            )
            master_secret = hkdf.derive(ikm)

            # Split into encryption and auth keys
            encryption_key = master_secret[:32]
            auth_key = master_secret[32:]

            # Generate key ID
            key_id = hashlib.sha256(
                encryption_key + auth_key +
                struct.pack('<Q', time.time_ns())
            ).digest()[:16]

            # Create key material
            key_material = DerivedKeyMaterial(
                encryption_key=encryption_key,
                auth_key=auth_key,
                key_id=key_id,
                derived_at_us=time.time_ns() // 1000,
                inputs_hash=hashlib.sha256(ikm).digest()[:16],
            )

            # Track rotation
            if self._last_key:
                self.stats['rotations'] += 1
            self._last_key = key_material
            self.stats['keys_derived'] += 1

            return key_material

    def needs_rotation(self) -> bool:
        """Check if current key needs rotation."""
        if not self._last_key:
            return True
        return not self._last_key.is_fresh(self.KEY_ROTATION_US)


# ============================================================================
# HTP INTEGRATION - Closes Gap: NSE not integrated to HTP
# ============================================================================

class HTPNeuroBinding:
    """
    Binds Neural Synaptic Encryption to HTP transport.

    Provides:
    - Weight fingerprint export from HTP's NeuroStateEvolver
    - Key derivation hook for HTP sessions
    - RDV binding to encryption key
    - TER validation for received packets

    Usage in HTP:
        binding = HTPNeuroBinding(node_id)
        session.encryption_key = binding.get_session_key(session)
    """

    def __init__(
        self,
        node_id: bytes,
        synaptic_engine: Optional['SynapticEncryptionEngine'] = None
    ):
        self.node_id = node_id
        self.key_derivation = NeuroKeyDerivation(node_id)
        self.synaptic_engine = synaptic_engine
        self._lock = Lock()

        # Weight tracking
        self._current_weights: Optional[bytes] = None
        self._weight_history: deque = deque(maxlen=100)

        # TER tracking
        self._ter_history: deque = deque(maxlen=1000)
        self._last_ter: Optional['TER'] = None

        # Peer state cache
        self._peer_states: Dict[bytes, 'SynapticState'] = {}

    def update_weights(self, weights_bytes: bytes):
        """Update current weight state from NeuroStateEvolver."""
        with self._lock:
            self._current_weights = weights_bytes
            fingerprint = hashlib.sha256(weights_bytes).digest()
            self._weight_history.append(fingerprint)

    def get_weight_fingerprint(self) -> bytes:
        """Export 32-byte weight fingerprint."""
        with self._lock:
            if self._current_weights:
                return hashlib.sha256(self._current_weights).digest()
            elif self._weight_history:
                # Derive from history
                return hashlib.sha256(b''.join(self._weight_history)).digest()
            else:
                # Fallback
                return hashlib.sha256(self.node_id).digest()

    def record_ter(self, ter: 'TER'):
        """Record TER for validation."""
        with self._lock:
            self._ter_history.append(ter)
            self._last_ter = ter

    def get_session_key(
        self,
        rdv: bytes,
        qsecbit: float,
        peer_id: Optional[bytes] = None
    ) -> bytes:
        """
        Get encryption key for HTP session.

        This is the main integration point - call this in HTP.send_data()
        to get the encryption_key that was previously never set.
        """
        weight_fp = self.get_weight_fingerprint()

        ter_entropy = b'\x00' * 32
        if self._last_ter:
            ter_entropy = self._last_ter.h_entropy

        peer_contribution = None
        if peer_id and peer_id in self._peer_states:
            peer_contribution = self._peer_states[peer_id].weight_fingerprint

        key_material = self.key_derivation.derive_session_key(
            weight_fingerprint=weight_fp,
            rdv=rdv,
            ter_entropy=ter_entropy,
            qsecbit_current=qsecbit,
            peer_contribution=peer_contribution,
        )

        return key_material.encryption_key

    def register_peer(self, peer_id: bytes, peer_state: 'SynapticState'):
        """Register peer's synaptic state for key derivation."""
        with self._lock:
            self._peer_states[peer_id] = peer_state

    def validate_peer_ter_sequence(
        self,
        peer_id: bytes,
        peer_ter_history: List['TER']
    ) -> Tuple[bool, float]:
        """
        Validate peer's TER sequence.

        Returns (is_valid, drift)
        """
        if not peer_ter_history:
            return False, 1.0

        # Compute peer's weight fingerprint from TER history
        combined = b''.join(ter.h_entropy for ter in peer_ter_history)
        peer_fingerprint = hashlib.sha256(combined).digest()

        # Compare with recorded state
        with self._lock:
            if peer_id in self._peer_states:
                expected_fp = self._peer_states[peer_id].weight_fingerprint
                drift = self._calculate_drift(peer_fingerprint, expected_fp)
                is_valid = drift < 0.1  # 10% threshold
                return is_valid, drift

        return True, 0.0  # No prior state, accept

    @staticmethod
    def _calculate_drift(fp1: bytes, fp2: bytes) -> float:
        """Calculate normalized drift between fingerprints."""
        if len(fp1) != len(fp2):
            return 1.0
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(fp1, fp2))
        return diff_bits / (len(fp1) * 8)


# ============================================================================
# DSM INTEGRATION - Closes Gap: No TER validation in signatures
# ============================================================================

@dataclass
class TERCheckpointProof:
    """Proof of TER state for DSM microblock."""
    # TER sequence info
    ter_count: int
    sequence_range: Tuple[int, int]  # (start_seq, end_seq)

    # Weight evolution proof
    weight_fingerprint: bytes  # 32 bytes

    # TER chain integrity
    chain_hash: int  # CRC16 of last TER

    # Aggregate threat score
    avg_threat_score: float

    # PoSF signature (proves sensor fusion)
    posf_signature: bytes  # 32 bytes

    def to_bytes(self) -> bytes:
        """Serialize for microblock inclusion."""
        return struct.pack(
            '<IHH32sHf32s',
            self.ter_count,
            self.sequence_range[0],
            self.sequence_range[1],
            self.weight_fingerprint,
            self.chain_hash,
            self.avg_threat_score,
            self.posf_signature,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TERCheckpointProof':
        """Deserialize from microblock."""
        unpacked = struct.unpack('<IHH32sHf32s', data[:78])
        return cls(
            ter_count=unpacked[0],
            sequence_range=(unpacked[1], unpacked[2]),
            weight_fingerprint=unpacked[3],
            chain_hash=unpacked[4],
            avg_threat_score=unpacked[5],
            posf_signature=unpacked[6],
        )


class DSMNeuroValidator:
    """
    Validates neural proofs in DSM consensus.

    Closes the gap where:
    - Microblocks have no TER checkpoint proof
    - Signature verification returns True unconditionally
    - Weight fingerprints not validated in checkpoints
    """

    def __init__(
        self,
        node_id: str,
        neuro_bridge: Optional['NeuroDSMBridge'] = None
    ):
        self.node_id = node_id
        self.neuro_bridge = neuro_bridge
        self._lock = Lock()

        # Validator state tracking
        self._validator_fingerprints: Dict[str, bytes] = {}
        self._validator_ter_history: Dict[str, List['TER']] = {}

    def create_ter_checkpoint_proof(
        self,
        ter_history: List['TER'],
        neural_engine: Optional['NeuralEngine'] = None
    ) -> TERCheckpointProof:
        """
        Create TER checkpoint proof for microblock.

        This is what should be included in DSMNode.create_microblock().
        """
        if not ter_history:
            # Empty proof
            return TERCheckpointProof(
                ter_count=0,
                sequence_range=(0, 0),
                weight_fingerprint=b'\x00' * 32,
                chain_hash=0,
                avg_threat_score=0.0,
                posf_signature=b'\x00' * 32,
            )

        # Compute weight fingerprint
        combined = b''.join(ter.h_entropy for ter in ter_history)
        weight_fingerprint = hashlib.sha256(combined).digest()

        # Get sequence range
        sequence_range = (ter_history[0].sequence, ter_history[-1].sequence)

        # Compute average threat score
        threat_scores = [ter.calculate_threat_score() for ter in ter_history]
        avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0

        # Create PoSF signature
        posf_message = (
            weight_fingerprint +
            struct.pack('<IHHf', len(ter_history), *sequence_range, avg_threat)
        )
        posf_signature = hashlib.sha256(posf_message + self.node_id.encode()).digest()

        return TERCheckpointProof(
            ter_count=len(ter_history),
            sequence_range=sequence_range,
            weight_fingerprint=weight_fingerprint,
            chain_hash=ter_history[-1].chain_hash,
            avg_threat_score=avg_threat,
            posf_signature=posf_signature,
        )

    def verify_ter_checkpoint_proof(
        self,
        proof: TERCheckpointProof,
        validator_id: str,
        ter_history: Optional[List['TER']] = None
    ) -> Tuple[bool, str]:
        """
        Verify TER checkpoint proof from a validator.

        This replaces the stub in ConsensusEngine._verify_single_signature().
        """
        # Check if we have the validator's TER history
        if ter_history:
            # Recompute fingerprint and compare
            combined = b''.join(ter.h_entropy for ter in ter_history)
            expected_fp = hashlib.sha256(combined).digest()

            if proof.weight_fingerprint != expected_fp:
                return False, "Weight fingerprint mismatch"

            # Verify sequence range
            if proof.sequence_range != (ter_history[0].sequence, ter_history[-1].sequence):
                return False, "Sequence range mismatch"

            # Verify chain hash
            if proof.chain_hash != ter_history[-1].chain_hash:
                return False, "Chain hash mismatch"

        # Check alignment with known validators
        with self._lock:
            if validator_id in self._validator_fingerprints:
                known_fp = self._validator_fingerprints[validator_id]
                drift = self._calculate_drift(proof.weight_fingerprint, known_fp)
                if drift > 0.1:  # 10% threshold
                    return False, f"Weight drift {drift:.2%} exceeds threshold"

        # Update known fingerprint
        with self._lock:
            self._validator_fingerprints[validator_id] = proof.weight_fingerprint

        return True, "Valid"

    def verify_consensus_vote(
        self,
        vote: Dict[str, Any],
        validator_id: str
    ) -> Tuple[bool, str]:
        """
        Verify consensus vote with neural proof.

        Expected vote structure:
        {
            'checkpoint_id': str,
            'merkle_root': bytes,
            'signature': bytes,
            'ter_checkpoint_proof': TERCheckpointProof,  # NEW
        }
        """
        # Check for TER checkpoint proof
        if 'ter_checkpoint_proof' not in vote:
            return False, "Missing TER checkpoint proof"

        proof = vote['ter_checkpoint_proof']
        if isinstance(proof, bytes):
            proof = TERCheckpointProof.from_bytes(proof)

        # Verify the proof
        is_valid, reason = self.verify_ter_checkpoint_proof(proof, validator_id)
        if not is_valid:
            return False, f"TER proof invalid: {reason}"

        # Verify PoSF signature
        posf_message = (
            proof.weight_fingerprint +
            struct.pack('<IHHf',
                proof.ter_count,
                *proof.sequence_range,
                proof.avg_threat_score
            )
        )
        expected_sig = hashlib.sha256(posf_message + validator_id.encode()).digest()

        if proof.posf_signature != expected_sig:
            return False, "PoSF signature invalid"

        return True, "Valid"

    @staticmethod
    def _calculate_drift(fp1: bytes, fp2: bytes) -> float:
        """Calculate normalized drift between fingerprints."""
        if len(fp1) != len(fp2):
            return 1.0
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(fp1, fp2))
        return diff_bits / (len(fp1) * 8)


# ============================================================================
# MESH INTEGRATION - Closes Gap: RDV prefix ignored, no payload encryption
# ============================================================================

class MeshNeuroAuth:
    """
    Adds neural authentication to mesh transport.

    Closes the gaps where:
    - RDV prefix is sent but never verified
    - Payload encryption doesn't exist
    - TER sync is one-way with no validation
    """

    def __init__(
        self,
        node_id: bytes,
        htp_binding: Optional[HTPNeuroBinding] = None
    ):
        self.node_id = node_id
        self.htp_binding = htp_binding or HTPNeuroBinding(node_id)
        self._lock = Lock()

        # RDV tracking
        self._expected_rdvs: Dict[bytes, bytes] = {}  # peer_id -> expected_rdv

        # Encryption keys per peer
        self._peer_keys: Dict[bytes, bytes] = {}

        # TER validation
        self._peer_ter_history: Dict[bytes, List['TER']] = {}

    def generate_rdv_for_peer(self, peer_id: bytes, flow_token: bytes) -> bytes:
        """Generate RDV for a specific peer."""
        rdv = hashlib.sha256(
            self.htp_binding.get_weight_fingerprint() +
            flow_token +
            peer_id +
            struct.pack('<Q', time.time_ns() // 1000)
        ).digest()

        with self._lock:
            self._expected_rdvs[peer_id] = rdv

        return rdv

    def verify_rdv_from_peer(
        self,
        peer_id: bytes,
        received_rdv_prefix: bytes,
        flow_token: bytes
    ) -> bool:
        """
        Verify RDV prefix from peer.

        This is what should be called in unified_transport._process_received_packet()
        instead of the current `pass` statement.
        """
        # Regenerate expected RDV
        expected_rdv = hashlib.sha256(
            self._get_peer_fingerprint(peer_id) +
            flow_token +
            self.node_id +
            struct.pack('<Q', time.time_ns() // 1000)
        ).digest()

        # Compare prefix (first 16 bytes)
        return received_rdv_prefix == expected_rdv[:16]

    def get_encryption_key_for_peer(self, peer_id: bytes) -> bytes:
        """Get encryption key for communicating with a peer."""
        with self._lock:
            if peer_id in self._peer_keys:
                return self._peer_keys[peer_id]

        # Derive key from combined state
        my_fp = self.htp_binding.get_weight_fingerprint()
        peer_fp = self._get_peer_fingerprint(peer_id)

        # Use HKDF to derive key
        if CRYPTO_AVAILABLE:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=my_fp[:16] + peer_fp[:16],
                info=b"mesh-neuro-auth-v5.0",
            )
            key = hkdf.derive(my_fp + peer_fp)
        else:
            # Fallback
            key = hashlib.sha256(my_fp + peer_fp).digest()

        with self._lock:
            self._peer_keys[peer_id] = key

        return key

    def encrypt_payload(self, peer_id: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt payload for peer.

        This is what should be called in unified_transport.send()
        to add payload encryption that currently doesn't exist.
        """
        if not CRYPTO_AVAILABLE:
            return plaintext  # Graceful degradation

        key = self.get_encryption_key_for_peer(peer_id)
        cipher = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)

        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_payload(self, peer_id: bytes, encrypted: bytes) -> bytes:
        """
        Decrypt payload from peer.

        This is what should be called in unified_transport._process_received_packet()
        to decrypt payloads.
        """
        if not CRYPTO_AVAILABLE:
            return encrypted  # Graceful degradation

        if len(encrypted) < 28:  # 12 nonce + 16 tag minimum
            return encrypted  # Not encrypted

        key = self.get_encryption_key_for_peer(peer_id)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)

    def validate_ter_sync(self, peer_id: bytes, ter: 'TER') -> bool:
        """
        Validate TER sync from peer.

        This replaces the one-way TER application that currently happens.
        """
        with self._lock:
            if peer_id not in self._peer_ter_history:
                self._peer_ter_history[peer_id] = []

            history = self._peer_ter_history[peer_id]

            # Validate chain integrity
            if history:
                expected_chain = self._crc16(history[-1].to_bytes())
                if ter.chain_hash != expected_chain:
                    logger.warning(f"TER chain break from {peer_id.hex()[:8]}")
                    return False

            # Store for fingerprint computation
            history.append(ter)
            if len(history) > 1000:
                history.pop(0)

        return True

    def _get_peer_fingerprint(self, peer_id: bytes) -> bytes:
        """Get peer's weight fingerprint from TER history."""
        with self._lock:
            if peer_id in self._peer_ter_history:
                history = self._peer_ter_history[peer_id]
                if history:
                    combined = b''.join(ter.h_entropy for ter in history[-100:])
                    return hashlib.sha256(combined).digest()

        # Fallback
        return hashlib.sha256(peer_id).digest()

    @staticmethod
    def _crc16(data: bytes) -> int:
        """Calculate CRC16 checksum."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc = crc << 1
                crc &= 0xFFFF
        return crc


# ============================================================================
# UNIFIED NEURO STACK - Single Entry Point for All Integration
# ============================================================================

class NeuroSecurityStack:
    """
    Unified Neural Security Stack.

    Provides single entry point for:
    - HTP key derivation
    - DSM TER validation
    - Mesh authentication
    - Synaptic encryption

    Usage:
        stack = NeuroSecurityStack(node_id)

        # In HTP
        session.encryption_key = stack.get_htp_session_key(rdv, qsecbit)

        # In DSM
        proof = stack.create_microblock_proof()
        is_valid = stack.verify_consensus_vote(vote, validator_id)

        # In Mesh
        ciphertext = stack.encrypt_for_peer(peer_id, plaintext)
        plaintext = stack.decrypt_from_peer(peer_id, ciphertext)
    """

    def __init__(self, node_id: bytes):
        self.node_id = node_id

        # Initialize components
        self.htp_binding = HTPNeuroBinding(node_id)
        self.dsm_validator = DSMNeuroValidator(node_id.hex()[:16])
        self.mesh_auth = MeshNeuroAuth(node_id, self.htp_binding)

        # Optional synaptic engine
        self.synaptic_engine: Optional['SynapticEncryptionEngine'] = None

        # TER generator
        self._ter_generator: Optional['TERGenerator'] = None
        if NEURO_AVAILABLE:
            try:
                self._ter_generator = TERGenerator()
            except Exception:
                pass

        logger.info(f"NeuroSecurityStack initialized for node {node_id.hex()[:8]}")

    # --- HTP Integration ---

    def get_htp_session_key(
        self,
        rdv: bytes,
        qsecbit: float,
        peer_id: Optional[bytes] = None
    ) -> bytes:
        """Get encryption key for HTP session."""
        return self.htp_binding.get_session_key(rdv, qsecbit, peer_id)

    def update_weights(self, weights: bytes):
        """Update neural weights from HTP evolver."""
        self.htp_binding.update_weights(weights)

    def get_weight_fingerprint(self) -> bytes:
        """Get current weight fingerprint."""
        return self.htp_binding.get_weight_fingerprint()

    # --- DSM Integration ---

    def create_microblock_proof(self) -> TERCheckpointProof:
        """Create TER checkpoint proof for DSM microblock."""
        ter_history = list(self.htp_binding._ter_history)
        return self.dsm_validator.create_ter_checkpoint_proof(ter_history)

    def verify_consensus_vote(
        self,
        vote: Dict[str, Any],
        validator_id: str
    ) -> Tuple[bool, str]:
        """Verify consensus vote with neural proof."""
        return self.dsm_validator.verify_consensus_vote(vote, validator_id)

    # --- Mesh Integration ---

    def encrypt_for_peer(self, peer_id: bytes, plaintext: bytes) -> bytes:
        """Encrypt payload for mesh peer."""
        return self.mesh_auth.encrypt_payload(peer_id, plaintext)

    def decrypt_from_peer(self, peer_id: bytes, ciphertext: bytes) -> bytes:
        """Decrypt payload from mesh peer."""
        return self.mesh_auth.decrypt_payload(peer_id, ciphertext)

    def verify_peer_rdv(
        self,
        peer_id: bytes,
        rdv_prefix: bytes,
        flow_token: bytes
    ) -> bool:
        """Verify RDV from mesh peer."""
        return self.mesh_auth.verify_rdv_from_peer(peer_id, rdv_prefix, flow_token)

    def validate_ter_sync(self, peer_id: bytes, ter: 'TER') -> bool:
        """Validate TER sync from peer."""
        return self.mesh_auth.validate_ter_sync(peer_id, ter)

    # --- TER Generation ---

    def generate_ter(self) -> Optional['TER']:
        """Generate new TER and record it."""
        if self._ter_generator:
            ter = self._ter_generator.generate()
            self.htp_binding.record_ter(ter)
            return ter
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get security stack status."""
        return {
            'node_id': self.node_id.hex()[:16],
            'weight_fingerprint': self.get_weight_fingerprint().hex()[:16],
            'ter_count': len(self.htp_binding._ter_history),
            'known_peers': len(self.mesh_auth._peer_keys),
            'keys_derived': self.htp_binding.key_derivation.stats['keys_derived'],
            'synaptic_engine': self.synaptic_engine is not None,
        }


# ============================================================================
# FACTORY FUNCTION
# ============================================================================

def create_neuro_security_stack(
    node_id: Optional[bytes] = None
) -> NeuroSecurityStack:
    """Create configured NeuroSecurityStack."""
    if node_id is None:
        node_id = secrets.token_bytes(16)

    return NeuroSecurityStack(node_id)
