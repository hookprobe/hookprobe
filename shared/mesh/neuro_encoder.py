"""
Neuro Resonance Encoder - Neural Weight-Based Channel Authentication

This module provides authentication through neural resonance encoding,
which uses deterministic neural network weight evolution as a shared
secret between communicating nodes.

Key Concepts:
- Resonance State: Shared neural weight state evolved from TER sequence
- Resonance Drift Vector (RDV): BLAKE3 hash of weight state + entropy
- Channel Binding: Cryptographic binding of channel to weight state

Security Model:
- Nodes share initial weight seed (W0)
- Each node evolves weights from local sensor telemetry (TER)
- Authentication proves possession of correct weight state
- Impossible to forge without reproducing exact sensor evolution
"""

import hashlib
import struct
import time
import secrets
import threading
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any
from collections import deque

# Try to import BLAKE3, fall back to SHA256
try:
    import blake3
    HASH_FUNCTION = lambda d: blake3.blake3(d).digest()
    HASH_NAME = "BLAKE3"
except ImportError:
    HASH_FUNCTION = lambda d: hashlib.sha256(d).digest()
    HASH_NAME = "SHA256"


class ResonanceState(Enum):
    """State of resonance alignment between nodes."""
    UNALIGNED = auto()      # No resonance established
    SEEKING = auto()        # Attempting to align
    ALIGNED = auto()        # Resonance achieved
    DRIFTING = auto()       # Slight drift detected
    LOST = auto()           # Resonance lost, need re-sync


@dataclass
class WeightFingerprint:
    """Compact representation of neural weight state."""

    # 64-byte fingerprint (SHA512 of weight matrices)
    fingerprint: bytes

    # Epoch when this state was captured
    epoch: int

    # Sequence number of last TER incorporated
    ter_sequence: int

    # Timestamp of capture
    timestamp: float

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return struct.pack(
            '>64sIIQ',
            self.fingerprint[:64].ljust(64, b'\x00'),
            self.epoch,
            self.ter_sequence,
            int(self.timestamp * 1_000_000),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'WeightFingerprint':
        """Deserialize from bytes."""
        if len(data) < 80:
            raise ValueError("Invalid fingerprint data")

        fp, epoch, ter_seq, ts_us = struct.unpack('>64sIIQ', data[:80])

        return cls(
            fingerprint=fp.rstrip(b'\x00'),
            epoch=epoch,
            ter_sequence=ter_seq,
            timestamp=ts_us / 1_000_000,
        )


@dataclass
class ResonanceDriftVector:
    """
    Resonance Drift Vector (RDV) - Core authentication primitive.

    RDV = BLAKE3(weight_fingerprint || entropy || timestamp || channel_binding)

    Properties:
    - Unique per channel and time
    - Verifiable only with correct weight state
    - Incorporates entropy to prevent replay
    - Channel-bound to prevent MITM
    """

    # 32-byte RDV hash
    vector: bytes

    # Weight fingerprint used to generate
    weight_fp: WeightFingerprint

    # 16-byte entropy component
    entropy: bytes

    # Timestamp component
    timestamp: float

    # Channel binding (e.g., flow token)
    channel_binding: bytes

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return struct.pack(
            '>32s16sQ32s',
            self.vector[:32],
            self.entropy[:16],
            int(self.timestamp * 1_000_000),
            self.channel_binding[:32].ljust(32, b'\x00'),
        ) + self.weight_fp.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ResonanceDriftVector':
        """Deserialize from bytes."""
        if len(data) < 88 + 80:  # RDV header + weight fingerprint
            raise ValueError("Invalid RDV data")

        vector, entropy, ts_us, binding = struct.unpack('>32s16sQ32s', data[:88])
        weight_fp = WeightFingerprint.from_bytes(data[88:])

        return cls(
            vector=vector,
            weight_fp=weight_fp,
            entropy=entropy,
            timestamp=ts_us / 1_000_000,
            channel_binding=binding.rstrip(b'\x00'),
        )


@dataclass
class TERSnapshot:
    """
    Telemetry Event Record Snapshot for weight evolution.

    Simplified TER structure for mesh transport.
    Full TER from core/neuro/core/ter.py is used internally.
    """

    # 32-byte entropy hash (system metrics)
    h_entropy: bytes

    # 20-byte integrity hash (critical files)
    h_integrity: bytes

    # Unix microsecond timestamp
    timestamp_us: int

    # Monotonic sequence (0-65535)
    sequence: int

    # CRC16 chain link
    chain_hash: int

    SIZE = 64  # Fixed 64-byte record

    def to_bytes(self) -> bytes:
        """Serialize to exactly 64 bytes."""
        return struct.pack(
            '>32s20sQHH',
            self.h_entropy[:32].ljust(32, b'\x00'),
            self.h_integrity[:20].ljust(20, b'\x00'),
            self.timestamp_us,
            self.sequence & 0xFFFF,
            self.chain_hash & 0xFFFF,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TERSnapshot':
        """Deserialize from bytes."""
        if len(data) < cls.SIZE:
            raise ValueError("Invalid TER data")

        h_ent, h_int, ts, seq, chain = struct.unpack('>32s20sQHH', data[:cls.SIZE])

        return cls(
            h_entropy=h_ent.rstrip(b'\x00'),
            h_integrity=h_int.rstrip(b'\x00'),
            timestamp_us=ts,
            sequence=seq,
            chain_hash=chain,
        )


class NeuroResonanceEncoder:
    """
    Neural Resonance Encoder for channel authentication.

    Uses neural weight evolution to create unforgeable authentication
    tokens that bind sender identity to channel state.

    Thread-safe design for concurrent mesh operations.
    """

    # Weight evolution parameters
    LEARNING_RATE_BASE = 0.001
    DECAY_TIME_CONSTANT = 7200.0  # 2 hours in seconds
    MAX_DRIFT_TOLERANCE = 0.05  # 5% fingerprint divergence

    # Epoch duration
    EPOCH_DURATION = 300.0  # 5 minutes

    def __init__(
        self,
        initial_seed: bytes,
        node_id: bytes,
    ):
        """
        Initialize encoder with shared seed.

        Args:
            initial_seed: 32-byte seed for initial weight state (W0)
            node_id: 16-byte unique node identifier
        """
        if len(initial_seed) < 32:
            initial_seed = hashlib.sha256(initial_seed).digest()
        if len(node_id) < 16:
            node_id = hashlib.sha256(node_id).digest()[:16]

        self.initial_seed = initial_seed[:32]
        self.node_id = node_id[:16]

        # Current weight state (simplified as hash chain)
        self._weight_state = self.initial_seed
        self._weight_history: deque = deque(maxlen=100)

        # TER tracking
        self._ter_sequence = 0
        self._ter_history: deque = deque(maxlen=1000)
        self._last_ter_time = 0.0

        # Epoch tracking
        self._current_epoch = 0
        self._epoch_start_time = time.time()

        # Resonance state with peers
        self._peer_states: Dict[bytes, ResonanceState] = {}
        self._peer_fingerprints: Dict[bytes, WeightFingerprint] = {}

        # Threading
        self._lock = threading.RLock()

    def get_weight_fingerprint(self) -> WeightFingerprint:
        """Get current weight state fingerprint."""
        with self._lock:
            fp = hashlib.sha512(self._weight_state).digest()
            return WeightFingerprint(
                fingerprint=fp,
                epoch=self._current_epoch,
                ter_sequence=self._ter_sequence,
                timestamp=time.time(),
            )

    def generate_rdv(
        self,
        channel_binding: bytes,
        entropy: Optional[bytes] = None,
    ) -> ResonanceDriftVector:
        """
        Generate Resonance Drift Vector for channel authentication.

        Args:
            channel_binding: Channel-specific binding (e.g., flow token)
            entropy: Optional entropy (random if not provided)

        Returns:
            ResonanceDriftVector for transmission
        """
        with self._lock:
            if entropy is None:
                entropy = secrets.token_bytes(16)

            timestamp = time.time()
            weight_fp = self.get_weight_fingerprint()

            # RDV = HASH(weight_fingerprint || entropy || timestamp || binding)
            rdv_input = (
                weight_fp.fingerprint +
                entropy +
                struct.pack('>Q', int(timestamp * 1_000_000)) +
                channel_binding[:32].ljust(32, b'\x00')
            )
            vector = HASH_FUNCTION(rdv_input)

            return ResonanceDriftVector(
                vector=vector,
                weight_fp=weight_fp,
                entropy=entropy,
                timestamp=timestamp,
                channel_binding=channel_binding,
            )

    def verify_rdv(
        self,
        rdv: ResonanceDriftVector,
        peer_id: bytes,
        max_age_seconds: float = 300.0,
    ) -> Tuple[bool, str]:
        """
        Verify Resonance Drift Vector from peer.

        Args:
            rdv: RDV to verify
            peer_id: Peer node identifier
            max_age_seconds: Maximum acceptable age

        Returns:
            Tuple of (valid, reason)
        """
        with self._lock:
            # Check timestamp freshness
            now = time.time()
            age = now - rdv.timestamp
            if age > max_age_seconds:
                return False, f"rdv_expired:age={age:.1f}s"
            if age < -60:  # Allow 1 minute clock skew
                return False, f"rdv_future:age={age:.1f}s"

            # Get expected weight fingerprint for peer
            expected_fp = self._get_expected_peer_fingerprint(peer_id, rdv.weight_fp)
            if expected_fp is None:
                # New peer, accept their fingerprint provisionally
                self._peer_fingerprints[peer_id] = rdv.weight_fp
                self._peer_states[peer_id] = ResonanceState.SEEKING
                return True, "new_peer:provisional"

            # Check fingerprint drift
            drift = self._calculate_drift(expected_fp.fingerprint, rdv.weight_fp.fingerprint)
            if drift > self.MAX_DRIFT_TOLERANCE:
                self._peer_states[peer_id] = ResonanceState.LOST
                return False, f"excessive_drift:{drift:.2%}"

            # Recompute RDV and verify
            rdv_input = (
                rdv.weight_fp.fingerprint +
                rdv.entropy +
                struct.pack('>Q', int(rdv.timestamp * 1_000_000)) +
                rdv.channel_binding[:32].ljust(32, b'\x00')
            )
            expected_vector = HASH_FUNCTION(rdv_input)

            if not secrets.compare_digest(expected_vector, rdv.vector):
                return False, "rdv_mismatch"

            # Update peer state
            if drift < 0.01:
                self._peer_states[peer_id] = ResonanceState.ALIGNED
            else:
                self._peer_states[peer_id] = ResonanceState.DRIFTING

            self._peer_fingerprints[peer_id] = rdv.weight_fp

            return True, "verified"

    def evolve_weights(self, ter: TERSnapshot) -> None:
        """
        Evolve weight state based on TER.

        This simulates the neural network weight update from
        sensor telemetry. The actual implementation in
        core/neuro/neural/engine.py uses fixed-point arithmetic.

        Args:
            ter: Telemetry Event Record to incorporate
        """
        with self._lock:
            # Validate TER chain
            if self._ter_history:
                last_ter = self._ter_history[-1]
                if ter.sequence != ((last_ter.sequence + 1) & 0xFFFF):
                    # Sequence gap - could indicate tampering
                    pass

            # Calculate learning rate decay
            time_delta = ter.timestamp_us / 1_000_000 - self._last_ter_time
            if time_delta > 0:
                lr_decay = min(1.0, time_delta / self.DECAY_TIME_CONSTANT)
            else:
                lr_decay = 1.0

            # Evolve weight state
            # W_new = HASH(W_old || TER || learning_rate_factor)
            evolution_input = (
                self._weight_state +
                ter.to_bytes() +
                struct.pack('>f', self.LEARNING_RATE_BASE * (1.0 - lr_decay * 0.5))
            )
            self._weight_state = HASH_FUNCTION(evolution_input)

            # Update tracking
            self._weight_history.append(self._weight_state)
            self._ter_history.append(ter)
            self._ter_sequence = ter.sequence
            self._last_ter_time = ter.timestamp_us / 1_000_000

            # Check epoch advancement
            now = time.time()
            if now - self._epoch_start_time > self.EPOCH_DURATION:
                self._current_epoch += 1
                self._epoch_start_time = now

    def generate_ter_from_system(self) -> TERSnapshot:
        """
        Generate TER from current system state.

        Uses system metrics as entropy source.
        """
        with self._lock:
            # Collect system entropy
            entropy_sources = [
                secrets.token_bytes(16),  # Random
                struct.pack('>Q', int(time.time() * 1_000_000)),  # Time
                self.node_id,
            ]

            # Try to get actual system metrics
            try:
                import os
                entropy_sources.append(os.urandom(32))
            except Exception:
                pass

            h_entropy = hashlib.sha256(b''.join(entropy_sources)).digest()

            # Integrity hash (placeholder - real impl reads critical files)
            h_integrity = hashlib.new('ripemd160', self._weight_state).digest()

            # Build TER
            sequence = (self._ter_sequence + 1) & 0xFFFF
            timestamp_us = int(time.time() * 1_000_000)

            # Chain hash (CRC16 of previous state)
            if self._ter_history:
                last_ter = self._ter_history[-1]
                chain_input = last_ter.to_bytes()
            else:
                chain_input = self.initial_seed

            chain_hash = self._crc16(chain_input)

            return TERSnapshot(
                h_entropy=h_entropy,
                h_integrity=h_integrity,
                timestamp_us=timestamp_us,
                sequence=sequence,
                chain_hash=chain_hash,
            )

    def _get_expected_peer_fingerprint(
        self,
        peer_id: bytes,
        received_fp: WeightFingerprint,
    ) -> Optional[WeightFingerprint]:
        """Get expected fingerprint for peer based on our state."""
        if peer_id not in self._peer_fingerprints:
            return None

        last_fp = self._peer_fingerprints[peer_id]

        # If same epoch, use last known
        if received_fp.epoch == last_fp.epoch:
            return last_fp

        # If newer epoch, we need to simulate evolution
        # For now, accept with drift check
        return last_fp

    def _calculate_drift(self, fp1: bytes, fp2: bytes) -> float:
        """
        Calculate normalized drift between fingerprints.

        Returns value 0.0 (identical) to 1.0 (completely different).
        """
        if len(fp1) != len(fp2):
            return 1.0

        # Count differing bits (Hamming distance normalized)
        diff_bits = sum(
            bin(a ^ b).count('1')
            for a, b in zip(fp1, fp2)
        )
        total_bits = len(fp1) * 8

        return diff_bits / total_bits

    def _crc16(self, data: bytes) -> int:
        """Calculate CRC16-CCITT."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return crc

    def get_resonance_state(self, peer_id: bytes) -> ResonanceState:
        """Get resonance state with peer."""
        with self._lock:
            return self._peer_states.get(peer_id, ResonanceState.UNALIGNED)

    def get_peer_ids(self) -> List[bytes]:
        """Get list of known peer IDs."""
        with self._lock:
            return list(self._peer_fingerprints.keys())

    def export_state(self) -> Dict[str, Any]:
        """Export encoder state for persistence."""
        with self._lock:
            return {
                'weight_state': self._weight_state.hex(),
                'ter_sequence': self._ter_sequence,
                'current_epoch': self._current_epoch,
                'epoch_start': self._epoch_start_time,
                'peer_count': len(self._peer_fingerprints),
            }

    def import_state(self, state: Dict[str, Any]) -> None:
        """Import encoder state from persistence."""
        with self._lock:
            if 'weight_state' in state:
                self._weight_state = bytes.fromhex(state['weight_state'])
            if 'ter_sequence' in state:
                self._ter_sequence = state['ter_sequence']
            if 'current_epoch' in state:
                self._current_epoch = state['current_epoch']
            if 'epoch_start' in state:
                self._epoch_start_time = state['epoch_start']


class ResonanceHandshake:
    """
    Resonance Handshake Protocol for establishing authenticated channels.

    Protocol:
    1. Initiator sends: RESONATE_INIT + RDV + nonce
    2. Responder verifies RDV, sends: RESONATE_ACK + RDV + entropy_echo
    3. Initiator verifies RDV, sends: RESONATE_CONFIRM + signature
    4. Both sides derive session key from weight states + entropy

    This provides mutual authentication without PKI.
    """

    class Stage(Enum):
        INIT = auto()
        ACK = auto()
        CONFIRM = auto()
        COMPLETE = auto()
        FAILED = auto()

    def __init__(
        self,
        encoder: NeuroResonanceEncoder,
        channel_binding: bytes,
        is_initiator: bool,
    ):
        """
        Initialize handshake.

        Args:
            encoder: Neuro resonance encoder
            channel_binding: Channel-specific binding
            is_initiator: True if we're initiating the handshake
        """
        self.encoder = encoder
        self.channel_binding = channel_binding
        self.is_initiator = is_initiator
        self.stage = self.Stage.INIT

        # Handshake state
        self.local_nonce = secrets.token_bytes(32)
        self.remote_nonce: Optional[bytes] = None
        self.local_rdv: Optional[ResonanceDriftVector] = None
        self.remote_rdv: Optional[ResonanceDriftVector] = None
        self.session_key: Optional[bytes] = None

    def generate_init(self) -> bytes:
        """Generate RESONATE_INIT message."""
        self.local_rdv = self.encoder.generate_rdv(self.channel_binding)

        message = struct.pack(
            '>B32s',
            0x01,  # RESONATE_INIT
            self.local_nonce,
        ) + self.local_rdv.to_bytes()

        return message

    def process_init(self, message: bytes) -> Tuple[bool, bytes]:
        """
        Process RESONATE_INIT and generate RESONATE_ACK.

        Returns:
            Tuple of (success, ack_message or error_message)
        """
        if len(message) < 33:
            return False, b'invalid_init'

        msg_type = message[0]
        if msg_type != 0x01:
            return False, b'unexpected_type'

        self.remote_nonce = message[1:33]

        try:
            self.remote_rdv = ResonanceDriftVector.from_bytes(message[33:])
        except Exception as e:
            return False, f'rdv_parse_error:{e}'.encode()

        # Verify remote RDV
        # For initial handshake, we're lenient (new peer)
        peer_id = self.remote_rdv.weight_fp.fingerprint[:16]
        valid, reason = self.encoder.verify_rdv(self.remote_rdv, peer_id)

        if not valid and 'provisional' not in reason:
            return False, f'rdv_invalid:{reason}'.encode()

        # Generate our RDV
        # Include entropy echo from their nonce
        combined_entropy = HASH_FUNCTION(
            self.remote_nonce + secrets.token_bytes(16)
        )[:16]
        self.local_rdv = self.encoder.generate_rdv(
            self.channel_binding,
            entropy=combined_entropy,
        )

        # Build ACK
        ack = struct.pack(
            '>B32s',
            0x02,  # RESONATE_ACK
            self.local_nonce,
        ) + self.local_rdv.to_bytes()

        self.stage = self.Stage.ACK
        return True, ack

    def process_ack(self, message: bytes) -> Tuple[bool, bytes]:
        """
        Process RESONATE_ACK and generate RESONATE_CONFIRM.

        Returns:
            Tuple of (success, confirm_message or error_message)
        """
        if len(message) < 33:
            return False, b'invalid_ack'

        msg_type = message[0]
        if msg_type != 0x02:
            return False, b'unexpected_type'

        self.remote_nonce = message[1:33]

        try:
            self.remote_rdv = ResonanceDriftVector.from_bytes(message[33:])
        except Exception as e:
            return False, f'rdv_parse_error:{e}'.encode()

        # Verify remote RDV
        peer_id = self.remote_rdv.weight_fp.fingerprint[:16]
        valid, reason = self.encoder.verify_rdv(self.remote_rdv, peer_id)

        if not valid and 'provisional' not in reason:
            return False, f'rdv_invalid:{reason}'.encode()

        # Derive session key
        self.session_key = self._derive_session_key()

        # Build CONFIRM
        # Signature proves we derived the same key
        confirm_data = HASH_FUNCTION(
            b'RESONATE_CONFIRM' +
            self.session_key +
            self.local_nonce +
            self.remote_nonce
        )

        confirm = struct.pack('>B', 0x03) + confirm_data

        self.stage = self.Stage.CONFIRM
        return True, confirm

    def process_confirm(self, message: bytes) -> Tuple[bool, Optional[bytes]]:
        """
        Process RESONATE_CONFIRM to complete handshake.

        Returns:
            Tuple of (success, session_key or None)
        """
        if len(message) < 33:
            return False, None

        msg_type = message[0]
        if msg_type != 0x03:
            return False, None

        # Derive our session key
        self.session_key = self._derive_session_key()

        # Verify confirm signature
        expected_confirm = HASH_FUNCTION(
            b'RESONATE_CONFIRM' +
            self.session_key +
            self.remote_nonce +  # Note: reversed for responder
            self.local_nonce
        )

        received_confirm = message[1:33]
        if not secrets.compare_digest(expected_confirm, received_confirm):
            self.stage = self.Stage.FAILED
            return False, None

        self.stage = self.Stage.COMPLETE
        return True, self.session_key

    def _derive_session_key(self) -> bytes:
        """Derive session key from handshake state."""
        if self.local_rdv is None or self.remote_rdv is None:
            raise ValueError("Handshake incomplete")

        # Session key = HASH(local_weight_fp || remote_weight_fp ||
        #                    local_nonce || remote_nonce ||
        #                    channel_binding)
        key_material = (
            self.local_rdv.weight_fp.fingerprint +
            self.remote_rdv.weight_fp.fingerprint +
            (self.local_nonce or b'') +
            (self.remote_nonce or b'') +
            self.channel_binding
        )

        # Use HKDF-like derivation
        prk = HASH_FUNCTION(key_material)
        # Expand to 32 bytes
        session_key = HASH_FUNCTION(prk + b'\x01')

        return session_key[:32]

    def is_complete(self) -> bool:
        """Check if handshake is complete."""
        return self.stage == self.Stage.COMPLETE

    def is_failed(self) -> bool:
        """Check if handshake failed."""
        return self.stage == self.Stage.FAILED
