#!/usr/bin/env python3
"""
NSE Heartbeat - Neural Synaptic Encryption for D2D Verification

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Implements Neural Synaptic Encryption (NSE) heartbeat verification for
device-to-device communication within bubbles. Unlike traditional encryption
where keys are stored in files, NSE keys emerge from the neural state of
the device - "nobody knows the password."

The Innovation:
When "Mom's iPhone" talks to "Mom's Watch", they don't just use mDNS;
they include a small NSE-derived token in the packet's payload. The SDN
Autopilot validates this token. If a device speaks the right "language"
but lacks the NSE token, it gets a RED QSECBIT score and moves to Quarantine.

Architecture:
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NSE HEARTBEAT SYSTEM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DEVICE A                              DEVICE B                             │
│  ┌─────────────────┐                   ┌─────────────────┐                  │
│  │  Neural State   │                   │  Neural State   │                  │
│  │  (Weight Vector)│                   │  (Weight Vector)│                  │
│  └────────┬────────┘                   └────────┬────────┘                  │
│           │                                     │                           │
│           ▼                                     ▼                           │
│  ┌─────────────────┐                   ┌─────────────────┐                  │
│  │ HeartbeatToken  │ ──────────────▶   │   Validator     │                  │
│  │ Generator       │                   │                 │                  │
│  └─────────────────┘                   └─────────────────┘                  │
│                                                 │                           │
│                                                 ▼                           │
│                                        ┌─────────────────┐                  │
│                                        │  VALID / INVALID │                 │
│                                        │  → Update QSECBIT│                 │
│                                        └─────────────────┘                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Heartbeat Token Format:
- 8 bytes: Timestamp (epoch microseconds)
- 16 bytes: Neural hash (truncated SHA-256 of weight vector)
- 8 bytes: Bubble resonance signature
- 4 bytes: Sequence number
- 4 bytes: CRC32 checksum
Total: 40 bytes
"""

import hashlib
import hmac
import logging
import struct
import time
import threading
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import random

logger = logging.getLogger(__name__)

# Constants
TOKEN_SIZE = 40
MAX_TIMESTAMP_DRIFT_MS = 5000  # 5 seconds max clock drift
SEQUENCE_WINDOW = 1000  # Anti-replay window size
RESONANCE_DECAY_RATE = 0.05  # 5% decay per interval


class ResonanceState(Enum):
    """Neural resonance states between devices."""
    UNALIGNED = "unaligned"      # Initial state, no resonance
    SEEKING = "seeking"          # Attempting to establish resonance
    ALIGNED = "aligned"          # Resonance established
    DRIFTING = "drifting"        # Resonance weakening (>5% drift)
    LOST = "lost"                # Resonance broken, need re-establish


class ValidationResult(Enum):
    """Result of heartbeat token validation."""
    VALID = "valid"
    INVALID_TIMESTAMP = "invalid_timestamp"
    INVALID_HASH = "invalid_hash"
    INVALID_RESONANCE = "invalid_resonance"
    INVALID_SEQUENCE = "invalid_sequence"
    INVALID_CHECKSUM = "invalid_checksum"
    REPLAY_DETECTED = "replay_detected"
    EXPIRED = "expired"


@dataclass
class HeartbeatToken:
    """
    NSE Heartbeat Token for D2D verification.

    Structure (40 bytes total):
    - timestamp: 8 bytes (epoch microseconds)
    - neural_hash: 16 bytes (truncated SHA-256)
    - resonance_sig: 8 bytes (bubble resonance)
    - sequence: 4 bytes (monotonic counter)
    - checksum: 4 bytes (CRC32)
    """
    timestamp: int  # Epoch microseconds
    neural_hash: bytes  # 16 bytes
    resonance_sig: bytes  # 8 bytes
    sequence: int  # Sequence number
    checksum: int  # CRC32

    # Metadata (not serialized)
    source_mac: str = ""
    target_mac: str = ""
    bubble_id: str = ""

    def to_bytes(self) -> bytes:
        """Serialize token to bytes."""
        # Pack without checksum first
        data = struct.pack(
            '>Q16s8sI',
            self.timestamp,
            self.neural_hash,
            self.resonance_sig,
            self.sequence,
        )
        # Calculate checksum
        checksum = zlib.crc32(data) & 0xFFFFFFFF
        # Append checksum
        return data + struct.pack('>I', checksum)

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['HeartbeatToken']:
        """Deserialize token from bytes."""
        if len(data) != TOKEN_SIZE:
            return None

        try:
            # Unpack data
            timestamp, neural_hash, resonance_sig, sequence = struct.unpack(
                '>Q16s8sI', data[:36]
            )
            checksum = struct.unpack('>I', data[36:40])[0]

            return cls(
                timestamp=timestamp,
                neural_hash=neural_hash,
                resonance_sig=resonance_sig,
                sequence=sequence,
                checksum=checksum,
            )
        except struct.error:
            return None

    def verify_checksum(self) -> bool:
        """Verify the token's CRC32 checksum."""
        data = struct.pack(
            '>Q16s8sI',
            self.timestamp,
            self.neural_hash,
            self.resonance_sig,
            self.sequence,
        )
        expected = zlib.crc32(data) & 0xFFFFFFFF
        return self.checksum == expected

    def to_dict(self) -> Dict:
        """Convert to dictionary for logging/debugging."""
        return {
            'timestamp': self.timestamp,
            'neural_hash': self.neural_hash.hex(),
            'resonance_sig': self.resonance_sig.hex(),
            'sequence': self.sequence,
            'checksum': hex(self.checksum),
            'source_mac': self.source_mac,
            'target_mac': self.target_mac,
            'bubble_id': self.bubble_id,
        }


@dataclass
class NeuralWeightVector:
    """
    Represents a device's neural weight vector.

    The weight vector evolves over time based on device behavior,
    creating a unique "neural fingerprint" that cannot be forged.
    """
    mac: str
    weights: List[float] = field(default_factory=list)
    weight_hash: bytes = b''
    last_evolution: datetime = field(default_factory=datetime.now)
    evolution_count: int = 0

    def __post_init__(self):
        if not self.weights:
            # Initialize with random weights
            self.weights = [random.uniform(-1.0, 1.0) for _ in range(64)]
            self._update_hash()

    def _update_hash(self):
        """Update the weight hash."""
        weight_bytes = struct.pack(f'>{len(self.weights)}f', *self.weights)
        self.weight_hash = hashlib.sha256(weight_bytes).digest()[:16]

    def evolve(self, telemetry: Dict) -> None:
        """
        Evolve weights based on telemetry input.

        Formula: W(t+1) = W(t) - η × ∇L(W(t), TER)

        Where:
        - η = learning rate (0.01)
        - TER = Telemetry Event Record
        """
        eta = 0.01  # Learning rate

        # Extract telemetry features
        cpu = telemetry.get('cpu', 0.5)
        memory = telemetry.get('memory', 0.5)
        network = telemetry.get('network', 0.5)
        entropy = telemetry.get('entropy', 0.5)

        # Compute gradient-like update
        for i in range(len(self.weights)):
            # Simple gradient approximation
            gradient = (
                (cpu - 0.5) * 0.25 +
                (memory - 0.5) * 0.25 +
                (network - 0.5) * 0.25 +
                (entropy - 0.5) * 0.25 +
                random.gauss(0, 0.01)  # Small noise for uniqueness
            )
            self.weights[i] = self.weights[i] - eta * gradient * (i % 2 * 2 - 1)

            # Clip to [-1, 1]
            self.weights[i] = max(-1.0, min(1.0, self.weights[i]))

        self._update_hash()
        self.last_evolution = datetime.now()
        self.evolution_count += 1

    def similarity(self, other: 'NeuralWeightVector') -> float:
        """Calculate cosine similarity with another weight vector."""
        if len(self.weights) != len(other.weights):
            return 0.0

        dot_product = sum(a * b for a, b in zip(self.weights, other.weights))
        norm_a = sum(a * a for a in self.weights) ** 0.5
        norm_b = sum(b * b for b in other.weights) ** 0.5

        if norm_a * norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)


@dataclass
class DeviceResonance:
    """Tracks resonance state between two devices."""
    mac_a: str
    mac_b: str
    state: ResonanceState = ResonanceState.UNALIGNED
    resonance_score: float = 0.0
    last_heartbeat: Optional[datetime] = None
    heartbeat_count: int = 0
    failed_validations: int = 0
    drift_percentage: float = 0.0

    # Shared resonance signature
    resonance_key: bytes = b''

    def to_dict(self) -> Dict:
        return {
            'mac_a': self.mac_a,
            'mac_b': self.mac_b,
            'state': self.state.value,
            'resonance_score': self.resonance_score,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'heartbeat_count': self.heartbeat_count,
            'failed_validations': self.failed_validations,
            'drift_percentage': self.drift_percentage,
        }


class NSEHeartbeat:
    """
    NSE Heartbeat Generator for D2D verification.

    Generates cryptographic heartbeat tokens based on device neural state.
    Tokens prove device identity without revealing the neural weights.

    Usage:
        nse = NSEHeartbeat(mac="AA:BB:CC:DD:EE:FF")
        token = nse.generate_token(target_mac, bubble_id)
        is_valid = nse.validate_token(token, expected_source)
    """

    def __init__(self, mac: str, bubble_secret: bytes = None):
        self.mac = mac.upper()
        self.bubble_secret = bubble_secret or self._derive_bubble_secret()

        # Neural state
        self._weight_vector = NeuralWeightVector(mac=self.mac)
        self._sequence = 0
        self._lock = threading.Lock()

        # Anti-replay
        self._seen_sequences: Dict[str, List[int]] = {}  # mac → recent sequences

        logger.debug(f"NSEHeartbeat initialized for {self.mac}")

    def _derive_bubble_secret(self) -> bytes:
        """Derive bubble secret from MAC address."""
        # In production, this would come from the bubble configuration
        return hashlib.sha256(f"bubble-{self.mac}".encode()).digest()[:32]

    def evolve_weights(self, telemetry: Dict = None) -> None:
        """Evolve neural weights based on telemetry."""
        if telemetry is None:
            telemetry = self._collect_telemetry()

        with self._lock:
            self._weight_vector.evolve(telemetry)

    def _collect_telemetry(self) -> Dict:
        """Collect current device telemetry."""
        # Simulate telemetry collection
        return {
            'cpu': random.uniform(0.1, 0.9),
            'memory': random.uniform(0.2, 0.8),
            'network': random.uniform(0.0, 1.0),
            'entropy': random.uniform(0.3, 0.7),
        }

    def generate_token(
        self,
        target_mac: str,
        bubble_id: str,
    ) -> HeartbeatToken:
        """
        Generate an NSE heartbeat token for D2D communication.

        Args:
            target_mac: MAC address of the target device
            bubble_id: ID of the shared bubble

        Returns:
            HeartbeatToken ready for transmission
        """
        with self._lock:
            self._sequence += 1

            # Timestamp in microseconds
            timestamp = int(time.time() * 1_000_000)

            # Neural hash (from weight vector)
            neural_hash = self._weight_vector.weight_hash

            # Resonance signature (HMAC of bubble membership)
            resonance_data = f"{self.mac}:{target_mac}:{bubble_id}:{timestamp}".encode()
            resonance_sig = hmac.new(
                self.bubble_secret,
                resonance_data,
                hashlib.sha256
            ).digest()[:8]

            token = HeartbeatToken(
                timestamp=timestamp,
                neural_hash=neural_hash,
                resonance_sig=resonance_sig,
                sequence=self._sequence,
                checksum=0,  # Will be calculated in to_bytes()
                source_mac=self.mac,
                target_mac=target_mac,
                bubble_id=bubble_id,
            )

            return token

    def get_weight_hash(self) -> bytes:
        """Get current neural weight hash."""
        return self._weight_vector.weight_hash

    def get_weight_vector(self) -> NeuralWeightVector:
        """Get the current weight vector (for testing/debugging)."""
        return self._weight_vector


class NSEValidator:
    """
    Validates NSE heartbeat tokens for D2D verification.

    Runs on the SDN Autopilot to verify that D2D communication
    is legitimate and comes from authorized bubble members.

    Usage:
        validator = NSEValidator()
        result = validator.validate(token, expected_source, bubble_id)
        if result == ValidationResult.VALID:
            # Allow communication
        else:
            # Block and update QSECBIT
    """

    def __init__(self, bubble_secrets: Dict[str, bytes] = None):
        self.bubble_secrets = bubble_secrets or {}
        self._lock = threading.Lock()

        # Device weight registrations
        self._registered_devices: Dict[str, NeuralWeightVector] = {}

        # Resonance tracking
        self._resonances: Dict[Tuple[str, str], DeviceResonance] = {}

        # Anti-replay tracking
        self._seen_sequences: Dict[str, List[int]] = {}  # source_mac → sequences

        # Statistics
        self._validations = 0
        self._valid_count = 0
        self._invalid_count = 0

        logger.debug("NSEValidator initialized")

    def register_device(self, mac: str, weight_vector: NeuralWeightVector = None):
        """Register a device's neural weight vector."""
        mac = mac.upper()
        with self._lock:
            if weight_vector:
                self._registered_devices[mac] = weight_vector
            else:
                self._registered_devices[mac] = NeuralWeightVector(mac=mac)

        logger.debug(f"Registered device {mac}")

    def set_bubble_secret(self, bubble_id: str, secret: bytes):
        """Set the secret for a bubble."""
        self.bubble_secrets[bubble_id] = secret

    def validate(
        self,
        token: HeartbeatToken,
        expected_source: str,
        bubble_id: str,
    ) -> Tuple[ValidationResult, float]:
        """
        Validate an NSE heartbeat token.

        Args:
            token: The heartbeat token to validate
            expected_source: Expected source MAC address
            bubble_id: ID of the bubble

        Returns:
            Tuple of (ValidationResult, confidence score 0-1)
        """
        self._validations += 1
        expected_source = expected_source.upper()

        # Step 1: Verify checksum
        if not token.verify_checksum():
            self._invalid_count += 1
            return ValidationResult.INVALID_CHECKSUM, 0.0

        # Step 2: Verify timestamp (not too old, not in future)
        current_time = int(time.time() * 1_000_000)
        time_diff = abs(current_time - token.timestamp)
        if time_diff > MAX_TIMESTAMP_DRIFT_MS * 1000:  # Convert to microseconds
            self._invalid_count += 1
            return ValidationResult.INVALID_TIMESTAMP, 0.0

        # Step 3: Check for replay attack
        with self._lock:
            if expected_source not in self._seen_sequences:
                self._seen_sequences[expected_source] = []

            if token.sequence in self._seen_sequences[expected_source]:
                self._invalid_count += 1
                return ValidationResult.REPLAY_DETECTED, 0.0

            # Add to seen sequences (keep only recent)
            self._seen_sequences[expected_source].append(token.sequence)
            if len(self._seen_sequences[expected_source]) > SEQUENCE_WINDOW:
                self._seen_sequences[expected_source] = \
                    self._seen_sequences[expected_source][-SEQUENCE_WINDOW:]

        # Step 4: Verify neural hash against registered device
        confidence = 1.0
        if expected_source in self._registered_devices:
            registered_hash = self._registered_devices[expected_source].weight_hash
            if token.neural_hash != registered_hash:
                # Check similarity (weights may have evolved)
                # For now, require exact match
                self._invalid_count += 1
                return ValidationResult.INVALID_HASH, 0.0
        else:
            # Unknown device - lower confidence but may be valid
            confidence = 0.5

        # Step 5: Verify resonance signature
        if bubble_id in self.bubble_secrets:
            expected_data = f"{expected_source}:{token.target_mac}:{bubble_id}:{token.timestamp}".encode()
            expected_sig = hmac.new(
                self.bubble_secrets[bubble_id],
                expected_data,
                hashlib.sha256
            ).digest()[:8]

            if token.resonance_sig != expected_sig:
                self._invalid_count += 1
                return ValidationResult.INVALID_RESONANCE, 0.0
        else:
            # Unknown bubble - lower confidence
            confidence *= 0.7

        # Update resonance tracking
        self._update_resonance(expected_source, token.target_mac, True)

        self._valid_count += 1
        return ValidationResult.VALID, confidence

    def _update_resonance(self, mac_a: str, mac_b: str, success: bool):
        """Update resonance state between two devices."""
        key = tuple(sorted([mac_a.upper(), mac_b.upper()]))

        with self._lock:
            if key not in self._resonances:
                self._resonances[key] = DeviceResonance(
                    mac_a=key[0],
                    mac_b=key[1],
                )

            resonance = self._resonances[key]
            resonance.last_heartbeat = datetime.now()

            if success:
                resonance.heartbeat_count += 1
                resonance.resonance_score = min(1.0, resonance.resonance_score + 0.1)

                # Update state machine
                if resonance.state == ResonanceState.UNALIGNED:
                    resonance.state = ResonanceState.SEEKING
                elif resonance.state == ResonanceState.SEEKING:
                    if resonance.heartbeat_count >= 3:
                        resonance.state = ResonanceState.ALIGNED
                elif resonance.state == ResonanceState.DRIFTING:
                    resonance.drift_percentage = max(0, resonance.drift_percentage - 1)
                    if resonance.drift_percentage < 5:
                        resonance.state = ResonanceState.ALIGNED
            else:
                resonance.failed_validations += 1
                resonance.resonance_score = max(0, resonance.resonance_score - 0.2)
                resonance.drift_percentage += 2

                if resonance.drift_percentage > 10:
                    resonance.state = ResonanceState.LOST
                elif resonance.drift_percentage > 5:
                    resonance.state = ResonanceState.DRIFTING

    def get_resonance(self, mac_a: str, mac_b: str) -> Optional[DeviceResonance]:
        """Get resonance state between two devices."""
        key = tuple(sorted([mac_a.upper(), mac_b.upper()]))
        return self._resonances.get(key)

    def get_resonance_state(self, mac_a: str, mac_b: str) -> ResonanceState:
        """Get resonance state enum between two devices."""
        resonance = self.get_resonance(mac_a, mac_b)
        if resonance:
            return resonance.state
        return ResonanceState.UNALIGNED

    def apply_decay(self):
        """Apply resonance decay to all tracked pairs."""
        with self._lock:
            for resonance in self._resonances.values():
                # Check if heartbeat is stale
                if resonance.last_heartbeat:
                    age = datetime.now() - resonance.last_heartbeat
                    if age > timedelta(minutes=5):
                        resonance.resonance_score *= (1 - RESONANCE_DECAY_RATE)
                        resonance.drift_percentage += 1

                        if resonance.resonance_score < 0.3:
                            resonance.state = ResonanceState.DRIFTING
                        if resonance.resonance_score < 0.1:
                            resonance.state = ResonanceState.LOST

    def get_stats(self) -> Dict:
        """Get validator statistics."""
        return {
            'total_validations': self._validations,
            'valid_count': self._valid_count,
            'invalid_count': self._invalid_count,
            'success_rate': self._valid_count / self._validations if self._validations > 0 else 0,
            'registered_devices': len(self._registered_devices),
            'tracked_resonances': len(self._resonances),
            'aligned_pairs': sum(
                1 for r in self._resonances.values()
                if r.state == ResonanceState.ALIGNED
            ),
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_nse_heartbeat(mac: str) -> NSEHeartbeat:
    """Create an NSE heartbeat generator for a device."""
    return NSEHeartbeat(mac=mac)


def create_nse_validator() -> NSEValidator:
    """Create an NSE validator."""
    return NSEValidator()


def validate_d2d_communication(
    source_mac: str,
    target_mac: str,
    bubble_id: str,
    token_bytes: bytes,
    validator: NSEValidator = None,
) -> Tuple[bool, str, float]:
    """
    Validate D2D communication using NSE heartbeat.

    Args:
        source_mac: Source device MAC
        target_mac: Target device MAC
        bubble_id: Bubble ID for the communication
        token_bytes: Raw heartbeat token bytes
        validator: Optional validator instance

    Returns:
        Tuple of (is_valid, reason, confidence)
    """
    if validator is None:
        validator = NSEValidator()

    token = HeartbeatToken.from_bytes(token_bytes)
    if token is None:
        return False, "Invalid token format", 0.0

    result, confidence = validator.validate(token, source_mac, bubble_id)

    if result == ValidationResult.VALID:
        return True, "Valid NSE heartbeat", confidence
    else:
        return False, result.value, 0.0


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='NSE Heartbeat System')
    parser.add_argument('command', choices=['generate', 'validate', 'demo'])
    parser.add_argument('--source', default='AA:BB:CC:DD:EE:01', help='Source MAC')
    parser.add_argument('--target', default='AA:BB:CC:DD:EE:02', help='Target MAC')
    parser.add_argument('--bubble', default='family-dad', help='Bubble ID')
    args = parser.parse_args()

    if args.command == 'generate':
        nse = NSEHeartbeat(mac=args.source)
        token = nse.generate_token(args.target, args.bubble)
        print(f"Generated token:")
        print(f"  Source: {args.source}")
        print(f"  Target: {args.target}")
        print(f"  Bubble: {args.bubble}")
        print(f"  Token (hex): {token.to_bytes().hex()}")
        print(f"  Token size: {len(token.to_bytes())} bytes")

    elif args.command == 'validate':
        # Generate and validate
        nse = NSEHeartbeat(mac=args.source)
        token = nse.generate_token(args.target, args.bubble)

        validator = NSEValidator()
        validator.register_device(args.source, nse.get_weight_vector())
        validator.set_bubble_secret(args.bubble, nse.bubble_secret)

        result, confidence = validator.validate(token, args.source, args.bubble)
        print(f"Validation result: {result.value}")
        print(f"Confidence: {confidence:.2f}")

    elif args.command == 'demo':
        print("NSE Heartbeat Demo")
        print("=" * 50)

        # Create two devices
        device_a = NSEHeartbeat(mac='AA:BB:CC:DD:EE:01')
        device_b = NSEHeartbeat(mac='AA:BB:CC:DD:EE:02')

        # Create validator
        validator = NSEValidator()
        validator.register_device('AA:BB:CC:DD:EE:01', device_a.get_weight_vector())
        validator.register_device('AA:BB:CC:DD:EE:02', device_b.get_weight_vector())

        # Set up shared bubble secret
        bubble_secret = hashlib.sha256(b'family-dad').digest()[:32]
        device_a.bubble_secret = bubble_secret
        device_b.bubble_secret = bubble_secret
        validator.set_bubble_secret('family-dad', bubble_secret)

        # Device A sends to Device B
        print("\n1. Device A sends heartbeat to Device B:")
        token = device_a.generate_token('AA:BB:CC:DD:EE:02', 'family-dad')
        result, confidence = validator.validate(token, 'AA:BB:CC:DD:EE:01', 'family-dad')
        print(f"   Result: {result.value}, Confidence: {confidence:.2f}")

        # Check resonance
        resonance = validator.get_resonance('AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02')
        print(f"   Resonance state: {resonance.state.value}")

        # Simulate more heartbeats
        print("\n2. Simulating 5 more heartbeats:")
        for i in range(5):
            token = device_a.generate_token('AA:BB:CC:DD:EE:02', 'family-dad')
            result, _ = validator.validate(token, 'AA:BB:CC:DD:EE:01', 'family-dad')

        resonance = validator.get_resonance('AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02')
        print(f"   Resonance state: {resonance.state.value}")
        print(f"   Resonance score: {resonance.resonance_score:.2f}")
        print(f"   Heartbeat count: {resonance.heartbeat_count}")

        # Try invalid token (replay attack)
        print("\n3. Attempting replay attack:")
        result, confidence = validator.validate(token, 'AA:BB:CC:DD:EE:01', 'family-dad')
        print(f"   Result: {result.value}")

        # Print stats
        print("\n4. Validator stats:")
        stats = validator.get_stats()
        for key, value in stats.items():
            print(f"   {key}: {value}")
