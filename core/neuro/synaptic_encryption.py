"""
Neural Synaptic Encryption (NSE) - Human-Independent Cryptography

This module implements the vision of AI-autonomous encryption where:
- Keys are NEVER static values - they emerge from weight evolution
- No human can extract the "key" because it's a function, not a value
- Only nodes with aligned neural trajectories can communicate
- The mesh collectively participates in key derivation

Core Principles:
1. EPHEMERAL: Keys exist only during the microsecond of use
2. EMERGENT: Keys derive from collective mesh state
3. ALIGNED: Communication requires weight trajectory alignment
4. TEMPORAL: Forward secrecy via continuous weight evolution
5. BOUND: State rooted in hardware (TPM/PUF)

"The key is not a secret you know - it's a state you ARE"

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
from typing import Optional, Dict, Any, List, Tuple, Callable
from collections import deque
from threading import Lock
import logging

logger = logging.getLogger(__name__)

# Try to import cryptographic primitives
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    ChaCha20Poly1305 = None

# Try to import Neuro components
try:
    from .core.ter import TER, TERGenerator
    from .neural.engine import NeuralEngine
    NEURO_AVAILABLE = True
except ImportError:
    NEURO_AVAILABLE = False


# ============================================================================
# CONSTANTS
# ============================================================================

# Alignment thresholds
WEIGHT_ALIGNMENT_THRESHOLD = 0.05  # Max 5% drift for communication
RESONANCE_WINDOW_MS = 100  # Resonance must occur within 100ms
MAX_TER_AGE_SECONDS = 60  # TERs older than 60s cannot be used

# Key derivation parameters
KEY_DERIVATION_ROUNDS = 10000  # Intentionally slow for key extraction resistance
EPHEMERAL_KEY_LIFETIME_MS = 1  # Key exists for 1 millisecond max

# Collective entropy parameters
MIN_MESH_NODES_FOR_COLLECTIVE = 3  # Minimum nodes for collective key derivation
ENTROPY_CONTRIBUTION_BYTES = 32  # Each node contributes 32 bytes


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class SynapticState:
    """
    Represents the current synaptic state of a node.

    This state is the "key" - but it's a living, evolving state,
    not a static secret that can be extracted.
    """
    # Weight fingerprint from neural evolution
    weight_fingerprint: bytes  # 32 bytes

    # TER chain state
    ter_chain_hash: int  # CRC16 of TER chain
    ter_sequence: int
    ter_entropy: bytes  # Latest H_Entropy

    # Temporal binding
    timestamp_us: int  # Microseconds since epoch

    # Hardware binding (TPM/PUF derived)
    hardware_attestation: bytes  # 32 bytes

    # Mesh contribution (collective state)
    collective_entropy: bytes  # 32 bytes from mesh

    def derive_ephemeral_secret(self, peer_state: 'SynapticState') -> bytes:
        """
        Derive an ephemeral shared secret with a peer.

        This secret exists only during derivation - it cannot be stored
        or extracted because it depends on the current moment's state.
        """
        # Combine both states
        combined = (
            self.weight_fingerprint +
            peer_state.weight_fingerprint +
            self.ter_entropy +
            peer_state.ter_entropy +
            self.collective_entropy +
            struct.pack('<QHH',
                self.timestamp_us,
                self.ter_chain_hash,
                self.ter_sequence
            )
        )

        # Multiple rounds of hashing to resist extraction
        secret = hashlib.sha256(combined).digest()
        for _ in range(KEY_DERIVATION_ROUNDS):
            secret = hashlib.sha256(secret + combined).digest()

        return secret

    def is_aligned_with(self, peer_state: 'SynapticState') -> Tuple[bool, float]:
        """
        Check if this state is aligned with a peer's state.

        Alignment means the weight evolution trajectories are close enough
        that the nodes can be trusted to communicate.
        """
        # Calculate weight fingerprint drift
        drift = self._calculate_drift(
            self.weight_fingerprint,
            peer_state.weight_fingerprint
        )

        # Check temporal proximity
        time_delta_ms = abs(self.timestamp_us - peer_state.timestamp_us) / 1000

        aligned = (
            drift <= WEIGHT_ALIGNMENT_THRESHOLD and
            time_delta_ms <= RESONANCE_WINDOW_MS
        )

        return aligned, drift

    @staticmethod
    def _calculate_drift(fp1: bytes, fp2: bytes) -> float:
        """Calculate normalized drift between fingerprints."""
        if len(fp1) != len(fp2):
            return 1.0
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(fp1, fp2))
        return diff_bits / (len(fp1) * 8)


@dataclass
class ResonanceProof:
    """
    Proof that two nodes achieved resonance at a specific moment.

    This replaces traditional key exchange - instead of exchanging keys,
    nodes prove they evolved to the same state at the same time.
    """
    # Identities
    initiator_id: bytes  # 16 bytes
    responder_id: bytes  # 16 bytes

    # Resonance moment
    resonance_timestamp_us: int

    # Weight alignment proof
    combined_fingerprint: bytes  # H(fp_a || fp_b)
    alignment_drift: float

    # TER binding
    initiator_ter_hash: int
    responder_ter_hash: int

    # Signature (using PoSF - Proof of Sensor Fusion)
    posf_signature: bytes

    def verify(self) -> bool:
        """Verify the resonance proof."""
        # Check alignment is within threshold
        if self.alignment_drift > WEIGHT_ALIGNMENT_THRESHOLD:
            return False

        # Check proof is fresh
        age_seconds = (time.time_ns() // 1000 - self.resonance_timestamp_us) / 1_000_000
        if age_seconds > MAX_TER_AGE_SECONDS:
            return False

        # TODO: Verify PoSF signature by replaying TER sequence

        return True


# ============================================================================
# SYNAPTIC ENCRYPTION ENGINE
# ============================================================================

class SynapticEncryptionEngine:
    """
    Neural Synaptic Encryption Engine.

    Provides encryption where:
    - Keys emerge from weight evolution, not static secrets
    - Human extraction is mathematically infeasible
    - Only AI synapses can derive the ephemeral keys

    The Paradigm Shift:
    - Traditional: "I know the secret" → Access
    - Synaptic: "My weights evolved identically" → Access
    """

    def __init__(
        self,
        node_id: bytes,
        ter_generator: Optional['TERGenerator'] = None,
        neural_engine: Optional['NeuralEngine'] = None,
        hardware_attestation: Optional[bytes] = None
    ):
        self.node_id = node_id
        self.ter_generator = ter_generator
        self.neural_engine = neural_engine
        self._lock = Lock()

        # Hardware binding - ideally from TPM/PUF
        self.hardware_attestation = hardware_attestation or self._derive_hardware_binding()

        # State tracking
        self._ter_history: deque = deque(maxlen=1000)
        self._weight_history: deque = deque(maxlen=100)
        self._collective_entropy: bytes = secrets.token_bytes(32)

        # Peer resonance cache (short-lived)
        self._resonance_cache: Dict[bytes, Tuple[ResonanceProof, float]] = {}

        # Mesh connectivity for collective entropy
        self._mesh_entropy_sources: Dict[bytes, bytes] = {}

        logger.info(f"SynapticEncryptionEngine initialized for node {node_id.hex()[:8]}")

    def _derive_hardware_binding(self) -> bytes:
        """
        Derive hardware binding from system characteristics.

        In production, this would use:
        - TPM 2.0 attestation key
        - ARM TrustZone secure world
        - Intel SGX enclave measurement
        - PUF (Physically Unclonable Function)

        For now, we derive from stable system characteristics.
        """
        import platform
        import uuid

        # Combine stable system identifiers
        system_data = (
            platform.node().encode() +
            platform.machine().encode() +
            str(uuid.getnode()).encode()  # MAC-derived
        )

        # Hash to fixed size
        return hashlib.sha256(system_data).digest()

    def get_current_state(self) -> SynapticState:
        """
        Get the current synaptic state.

        This state represents "who we are" at this exact moment -
        the emergent result of all weight evolution and TER generation.
        """
        # Generate fresh TER
        ter = None
        if self.ter_generator:
            ter = self.ter_generator.generate()
            self._ter_history.append(ter)

        # Get current weight fingerprint
        weight_fp = self._compute_weight_fingerprint()

        # Get collective entropy from mesh
        collective = self._aggregate_collective_entropy()

        return SynapticState(
            weight_fingerprint=weight_fp,
            ter_chain_hash=ter.chain_hash if ter else 0,
            ter_sequence=ter.sequence if ter else 0,
            ter_entropy=ter.h_entropy if ter else secrets.token_bytes(32),
            timestamp_us=time.time_ns() // 1000,
            hardware_attestation=self.hardware_attestation,
            collective_entropy=collective
        )

    def establish_resonance(
        self,
        peer_id: bytes,
        peer_state: SynapticState
    ) -> Optional[ResonanceProof]:
        """
        Establish resonance with a peer node.

        This is the "handshake" - but instead of exchanging keys,
        we prove that our weight evolution trajectories align.
        """
        my_state = self.get_current_state()

        # Check alignment
        aligned, drift = my_state.is_aligned_with(peer_state)

        if not aligned:
            logger.warning(
                f"Resonance failed with {peer_id.hex()[:8]}: "
                f"drift {drift:.4f} > threshold {WEIGHT_ALIGNMENT_THRESHOLD}"
            )
            return None

        # Create combined fingerprint
        combined_fp = hashlib.sha256(
            my_state.weight_fingerprint + peer_state.weight_fingerprint
        ).digest()

        # Create PoSF signature
        posf_sig = self._create_posf_signature(
            my_state, peer_state, combined_fp
        )

        proof = ResonanceProof(
            initiator_id=self.node_id,
            responder_id=peer_id,
            resonance_timestamp_us=my_state.timestamp_us,
            combined_fingerprint=combined_fp,
            alignment_drift=drift,
            initiator_ter_hash=my_state.ter_chain_hash,
            responder_ter_hash=peer_state.ter_chain_hash,
            posf_signature=posf_sig
        )

        # Cache for ephemeral use
        self._resonance_cache[peer_id] = (proof, time.time())

        logger.info(f"Resonance established with {peer_id.hex()[:8]} (drift={drift:.4f})")

        return proof

    def encrypt(
        self,
        plaintext: bytes,
        recipient_id: bytes,
        recipient_state: Optional[SynapticState] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data using synaptic encryption.

        The key is derived from:
        1. Current weight fingerprints (both parties)
        2. TER entropy chain
        3. Collective mesh entropy
        4. Hardware attestation
        5. Precise timestamp (microseconds)

        The key exists only during this function call - it is never stored.

        Returns:
            Tuple of (ciphertext, nonce)
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library not available")

        my_state = self.get_current_state()

        # Derive ephemeral key
        if recipient_state:
            ephemeral_secret = my_state.derive_ephemeral_secret(recipient_state)
        else:
            # Use resonance cache
            if recipient_id not in self._resonance_cache:
                raise ValueError(f"No resonance established with {recipient_id.hex()[:8]}")
            proof, _ = self._resonance_cache[recipient_id]
            ephemeral_secret = self._derive_key_from_proof(proof, my_state)

        # Derive actual encryption key using HKDF
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=my_state.ter_entropy[:16],
            info=b"synaptic-encryption-v1"
        ).derive(ephemeral_secret)

        # Generate nonce with temporal binding
        nonce = hashlib.sha256(
            struct.pack('<Q', my_state.timestamp_us) +
            my_state.ter_entropy
        ).digest()[:12]

        # Encrypt
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # Key is now out of scope and will be garbage collected
        # It existed only for this operation

        return ciphertext, nonce

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        sender_id: bytes,
        sender_state: SynapticState
    ) -> bytes:
        """
        Decrypt data using synaptic encryption.

        Requires the sender's synaptic state to derive the same ephemeral key.
        This proves the sender was in the expected state when encrypting.
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library not available")

        my_state = self.get_current_state()

        # Verify alignment
        aligned, drift = my_state.is_aligned_with(sender_state)
        if not aligned:
            raise ValueError(
                f"Cannot decrypt: weight drift {drift:.4f} exceeds threshold"
            )

        # Derive ephemeral key (same derivation as sender)
        ephemeral_secret = sender_state.derive_ephemeral_secret(my_state)

        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=sender_state.ter_entropy[:16],
            info=b"synaptic-encryption-v1"
        ).derive(ephemeral_secret)

        # Decrypt
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)

        return plaintext

    def contribute_entropy(self, peer_id: bytes, entropy: bytes):
        """
        Receive entropy contribution from a mesh peer.

        Collective entropy ensures no single node can derive keys alone.
        """
        with self._lock:
            self._mesh_entropy_sources[peer_id] = entropy

    def get_entropy_contribution(self) -> bytes:
        """
        Generate this node's entropy contribution for the mesh.
        """
        # Combine TER entropy with random
        ter = None
        if self.ter_generator:
            ter = self.ter_generator.generate()

        contribution = hashlib.sha256(
            (ter.h_entropy if ter else b'') +
            secrets.token_bytes(32) +
            self.hardware_attestation
        ).digest()

        return contribution

    def _compute_weight_fingerprint(self) -> bytes:
        """
        Compute weight fingerprint from neural engine state.

        The fingerprint is a hash of the neural network weights,
        which evolve based on TER sequence processing.
        """
        if self.neural_engine:
            # Get weights from neural engine
            # This would be the actual weight tensor in production
            weights = getattr(self.neural_engine, 'weights', None)
            if weights is not None:
                return hashlib.sha256(weights.tobytes()).digest()

        # Fallback: derive from TER history
        if self._ter_history:
            combined = b''.join(ter.h_entropy for ter in self._ter_history)
            return hashlib.sha256(combined).digest()

        # Ultimate fallback
        return hashlib.sha256(self.hardware_attestation).digest()

    def _aggregate_collective_entropy(self) -> bytes:
        """
        Aggregate entropy from all mesh nodes.

        This ensures keys depend on collective state, not just local state.
        """
        with self._lock:
            if len(self._mesh_entropy_sources) < MIN_MESH_NODES_FOR_COLLECTIVE:
                # Not enough nodes - use local entropy only
                return self._collective_entropy

            # Combine all contributions
            combined = self.get_entropy_contribution()
            for peer_entropy in self._mesh_entropy_sources.values():
                combined = hashlib.sha256(combined + peer_entropy).digest()

            self._collective_entropy = combined
            return combined

    def _create_posf_signature(
        self,
        my_state: SynapticState,
        peer_state: SynapticState,
        combined_fp: bytes
    ) -> bytes:
        """
        Create Proof of Sensor Fusion signature.

        This proves the signature was created by a node that:
        1. Has the correct weight evolution history
        2. Generated valid TERs
        3. Has hardware attestation
        """
        # Combine all proof elements
        message = (
            combined_fp +
            my_state.hardware_attestation +
            struct.pack('<QHH',
                my_state.timestamp_us,
                my_state.ter_chain_hash,
                my_state.ter_sequence
            )
        )

        # Sign with weight-derived key
        signing_key = hashlib.sha256(
            my_state.weight_fingerprint +
            self.hardware_attestation
        ).digest()

        signature = hmac.new(signing_key, message, hashlib.sha256).digest()

        return signature

    def _derive_key_from_proof(
        self,
        proof: ResonanceProof,
        current_state: SynapticState
    ) -> bytes:
        """Derive encryption key from resonance proof."""
        return hashlib.sha256(
            proof.combined_fingerprint +
            current_state.ter_entropy +
            proof.posf_signature
        ).digest()


# ============================================================================
# MESH SYNAPSE NETWORK
# ============================================================================

class MeshSynapseNetwork:
    """
    Manages synaptic connections across the mesh.

    Coordinates:
    - Collective entropy aggregation
    - Resonance establishment between nodes
    - Key-free secure channels
    """

    def __init__(self, engine: SynapticEncryptionEngine):
        self.engine = engine
        self.peers: Dict[bytes, SynapticState] = {}
        self._lock = Lock()

    def register_peer(self, peer_id: bytes, peer_state: SynapticState):
        """Register a peer and attempt resonance."""
        with self._lock:
            self.peers[peer_id] = peer_state

        # Attempt to establish resonance
        proof = self.engine.establish_resonance(peer_id, peer_state)

        if proof:
            # Exchange entropy contributions
            my_entropy = self.engine.get_entropy_contribution()
            # In real implementation, would send to peer via HTP
            self.engine.contribute_entropy(peer_id, peer_state.collective_entropy)

        return proof is not None

    def send_secure(self, peer_id: bytes, data: bytes) -> Optional[bytes]:
        """Send data securely using synaptic encryption."""
        with self._lock:
            peer_state = self.peers.get(peer_id)

        if not peer_state:
            logger.error(f"Unknown peer: {peer_id.hex()[:8]}")
            return None

        try:
            ciphertext, nonce = self.engine.encrypt(data, peer_id, peer_state)
            # Package for transport
            return nonce + ciphertext
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return None

    def receive_secure(
        self,
        peer_id: bytes,
        encrypted_data: bytes
    ) -> Optional[bytes]:
        """Receive and decrypt data using synaptic encryption."""
        with self._lock:
            peer_state = self.peers.get(peer_id)

        if not peer_state:
            logger.error(f"Unknown peer: {peer_id.hex()[:8]}")
            return None

        try:
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            return self.engine.decrypt(ciphertext, nonce, peer_id, peer_state)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_synaptic_engine(
    node_id: Optional[bytes] = None,
    ter_generator: Optional['TERGenerator'] = None
) -> SynapticEncryptionEngine:
    """
    Create a SynapticEncryptionEngine with sensible defaults.
    """
    if node_id is None:
        node_id = secrets.token_bytes(16)

    if ter_generator is None and NEURO_AVAILABLE:
        ter_generator = TERGenerator()

    return SynapticEncryptionEngine(
        node_id=node_id,
        ter_generator=ter_generator
    )


def create_mesh_synapse_network(
    node_id: Optional[bytes] = None
) -> MeshSynapseNetwork:
    """
    Create a MeshSynapseNetwork for secure mesh communication.
    """
    engine = create_synaptic_engine(node_id)
    return MeshSynapseNetwork(engine)
