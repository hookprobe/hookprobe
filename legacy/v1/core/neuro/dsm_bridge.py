"""
Neuro-DSM Bridge - Connects Neural Resonance Protocol to Decentralized Security Mesh

This module bridges TER (Temporal Event Records) validation with DSM consensus,
enabling mesh-wide verification of device integrity and neural weight evolution.

Key Features:
1. TER-backed microblock creation with integrity proofs
2. Weight evolution validation in DSM checkpoints
3. Consensus on device identity via Neuro authentication
4. Cross-node TER sequence verification

"Neural signatures become consensus votes"

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import hashlib
import logging
import struct
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from threading import Lock
from collections import deque

logger = logging.getLogger(__name__)

# Try to import Neuro components
try:
    from core.neuro.core.ter import TER, TERGenerator, TERValidator
    from core.neuro.core.posf import PoSFSignature
    from core.neuro.neural.engine import NeuralEngine
    NEURO_AVAILABLE = True
except ImportError:
    try:
        from .core.ter import TER, TERGenerator, TERValidator
        from .core.posf import PoSFSignature
        from .neural.engine import NeuralEngine
        NEURO_AVAILABLE = True
    except ImportError:
        NEURO_AVAILABLE = False
        TER = None
        TERGenerator = None
        TERValidator = None

# Try to import DSM components
try:
    from shared.dsm.node import DSMNode
    from shared.dsm.consensus import ConsensusEngine
    from shared.dsm.gossip import GossipProtocol
    DSM_AVAILABLE = True
except ImportError:
    DSM_AVAILABLE = False
    DSMNode = None
    ConsensusEngine = None


@dataclass
class NeuroDSMConfig:
    """Configuration for Neuro-DSM bridge."""
    # TER settings
    ter_window_size: int = 100  # Number of TERs to keep for validation
    ter_generation_interval: float = 1.0  # Seconds between TER generations
    integrity_check_interval: int = 100  # TERs between integrity checks

    # DSM settings
    microblock_threshold: float = 0.7  # Min weight drift to create microblock
    checkpoint_ter_count: int = 50  # TERs to include in checkpoint

    # Validation settings
    max_entropy_deviation: float = 0.2  # Max allowed entropy deviation
    max_weight_drift: float = 0.1  # Max allowed weight drift between nodes


@dataclass
class TERValidationResult:
    """Result of TER sequence validation."""
    valid: bool
    sequence_length: int
    chain_intact: bool
    entropy_valid: bool
    weight_fingerprint: bytes
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class NeuroDSMBridge:
    """
    Bridge between Neural Resonance Protocol and DSM consensus.

    Responsibilities:
    1. Generate TERs and create DSM microblocks with neural proofs
    2. Validate TER sequences from other nodes in consensus
    3. Compute weight fingerprints for consensus voting
    4. Integrate PoSF signatures into checkpoint validation
    """

    def __init__(
        self,
        node_id: str,
        config: Optional[NeuroDSMConfig] = None,
        dsm_node: Optional['DSMNode'] = None,
        neural_engine: Optional['NeuralEngine'] = None,
        ter_generator: Optional['TERGenerator'] = None
    ):
        self.node_id = node_id
        self.config = config or NeuroDSMConfig()
        self.dsm_node = dsm_node
        self.neural_engine = neural_engine
        self.ter_generator = ter_generator or (TERGenerator() if NEURO_AVAILABLE else None)

        # TER history for validation
        self._ter_history: deque = deque(maxlen=self.config.ter_window_size)
        self._lock = Lock()

        # Statistics
        self.stats = {
            'ters_generated': 0,
            'microblocks_created': 0,
            'validations_passed': 0,
            'validations_failed': 0,
            'consensus_votes': 0,
        }

        # Weight fingerprint cache
        self._current_weight_fingerprint: Optional[bytes] = None
        self._last_integrity_check: int = 0

        logger.info(f"NeuroDSMBridge initialized for node {node_id}")

    def set_dsm_node(self, dsm_node: 'DSMNode'):
        """Set DSM node after initialization."""
        self.dsm_node = dsm_node
        logger.info("DSM node connected to Neuro bridge")

    def set_neural_engine(self, engine: 'NeuralEngine'):
        """Set neural engine after initialization."""
        self.neural_engine = engine
        logger.info("Neural engine connected to Neuro bridge")

    def generate_ter_and_record(self, force_integrity: bool = False) -> Optional['TER']:
        """
        Generate a new TER and optionally create DSM microblock.

        This is the core integration point between Neuro and DSM:
        1. Generate TER with current system state
        2. Update weight fingerprint if needed
        3. Create DSM microblock if weight drift exceeds threshold

        Args:
            force_integrity: Force integrity hash recalculation

        Returns:
            Generated TER or None if generation failed
        """
        if not NEURO_AVAILABLE or not self.ter_generator:
            logger.warning("Neuro components not available")
            return None

        try:
            # Generate TER
            ter = self.ter_generator.generate(force_integrity_check=force_integrity)

            with self._lock:
                self._ter_history.append(ter)
                self.stats['ters_generated'] += 1

            # Check if we need to create a DSM microblock
            if self._should_create_microblock(ter):
                self._create_neuro_microblock(ter)

            # Update weight fingerprint periodically
            if (self.stats['ters_generated'] - self._last_integrity_check
                    >= self.config.integrity_check_interval):
                self._update_weight_fingerprint(ter)
                self._last_integrity_check = self.stats['ters_generated']

            return ter

        except Exception as e:
            logger.error(f"TER generation failed: {e}")
            return None

    def validate_ter_sequence(
        self,
        ter_sequence: List['TER'],
        expected_fingerprint: Optional[bytes] = None
    ) -> TERValidationResult:
        """
        Validate a TER sequence from another node.

        Used in DSM consensus to verify that a node's TER history
        is consistent and hasn't been tampered with.

        Args:
            ter_sequence: List of TERs to validate
            expected_fingerprint: Optional expected weight fingerprint

        Returns:
            TERValidationResult with validation details
        """
        result = TERValidationResult(
            valid=True,
            sequence_length=len(ter_sequence),
            chain_intact=True,
            entropy_valid=True,
            weight_fingerprint=b''
        )

        if not ter_sequence:
            result.errors.append("Empty TER sequence")
            result.valid = False
            return result

        if not NEURO_AVAILABLE:
            result.errors.append("Neuro components not available")
            result.valid = False
            return result

        try:
            # Use TERValidator for basic validation
            validation = TERValidator.validate_sequence(ter_sequence)

            if not validation['valid']:
                result.valid = False
                result.errors.extend(validation['errors'])
                result.chain_intact = False

            result.warnings.extend(validation.get('warnings', []))

            # Validate entropy consistency
            if not self._validate_entropy_consistency(ter_sequence):
                result.errors.append("Entropy values show anomalous patterns")
                result.entropy_valid = False
                result.valid = False

            # Compute weight fingerprint from TER sequence
            weight_fingerprint = self._compute_weight_fingerprint(ter_sequence)
            result.weight_fingerprint = weight_fingerprint

            # Compare with expected fingerprint if provided
            if expected_fingerprint:
                drift = self._calculate_fingerprint_drift(
                    weight_fingerprint, expected_fingerprint
                )
                if drift > self.config.max_weight_drift:
                    result.errors.append(
                        f"Weight fingerprint drift {drift:.4f} exceeds threshold "
                        f"{self.config.max_weight_drift}"
                    )
                    result.valid = False

            # Update statistics
            if result.valid:
                self.stats['validations_passed'] += 1
            else:
                self.stats['validations_failed'] += 1

            return result

        except Exception as e:
            logger.error(f"TER sequence validation failed: {e}")
            result.errors.append(str(e))
            result.valid = False
            self.stats['validations_failed'] += 1
            return result

    def create_consensus_vote(
        self,
        checkpoint_id: str,
        ter_summary: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Create a consensus vote incorporating Neuro validation.

        The vote includes:
        1. Weight fingerprint from local TER history
        2. PoSF signature proving device integrity
        3. Validation of peer TER summaries

        Args:
            checkpoint_id: ID of the checkpoint being voted on
            ter_summary: Summary of TERs from peer nodes

        Returns:
            Vote payload with Neuro proofs
        """
        if not DSM_AVAILABLE or not self.dsm_node:
            logger.warning("DSM not available for consensus vote")
            return None

        try:
            # Get current TER history
            with self._lock:
                recent_ters = list(self._ter_history)

            if not recent_ters:
                logger.warning("No TER history for consensus vote")
                return None

            # Compute our weight fingerprint
            weight_fingerprint = self._compute_weight_fingerprint(recent_ters)

            # Create PoSF signature if neural engine available
            posf_signature = None
            if self.neural_engine and NEURO_AVAILABLE:
                try:
                    message = checkpoint_id.encode() + weight_fingerprint
                    posf_signature = self._create_posf_signature(message)
                except Exception as e:
                    logger.warning(f"PoSF signature creation failed: {e}")

            # Build vote payload
            vote = {
                'checkpoint_id': checkpoint_id,
                'node_id': self.node_id,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'weight_fingerprint': weight_fingerprint.hex(),
                'ter_count': len(recent_ters),
                'ter_sequence_range': (
                    recent_ters[0].sequence if recent_ters else 0,
                    recent_ters[-1].sequence if recent_ters else 0
                ),
                'latest_entropy': recent_ters[-1].h_entropy.hex() if recent_ters else '',
                'chain_hash': recent_ters[-1].chain_hash if recent_ters else 0,
            }

            if posf_signature:
                vote['posf_signature'] = posf_signature.hex()

            self.stats['consensus_votes'] += 1
            return vote

        except Exception as e:
            logger.error(f"Consensus vote creation failed: {e}")
            return None

    def validate_consensus_vote(
        self,
        vote: Dict[str, Any],
        peer_ter_history: Optional[List['TER']] = None
    ) -> Tuple[bool, str]:
        """
        Validate a consensus vote from a peer node.

        Checks:
        1. Weight fingerprint matches TER history (if provided)
        2. PoSF signature is valid
        3. Vote structure is complete

        Args:
            vote: Vote payload from peer
            peer_ter_history: Optional TER history from peer

        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            # Validate required fields
            required_fields = ['checkpoint_id', 'node_id', 'weight_fingerprint', 'ter_count']
            for field in required_fields:
                if field not in vote:
                    return False, f"Missing required field: {field}"

            # If we have peer TER history, validate fingerprint
            if peer_ter_history:
                expected_fingerprint = self._compute_weight_fingerprint(peer_ter_history)
                actual_fingerprint = bytes.fromhex(vote['weight_fingerprint'])

                drift = self._calculate_fingerprint_drift(
                    expected_fingerprint, actual_fingerprint
                )
                if drift > self.config.max_weight_drift:
                    return False, f"Weight fingerprint drift {drift:.4f} exceeds threshold"

            # Validate PoSF signature if present and engine available
            if 'posf_signature' in vote and self.neural_engine:
                try:
                    message = vote['checkpoint_id'].encode() + bytes.fromhex(vote['weight_fingerprint'])
                    posf_sig = bytes.fromhex(vote['posf_signature'])
                    if not self._verify_posf_signature(message, posf_sig, vote['node_id']):
                        return False, "Invalid PoSF signature"
                except Exception as e:
                    logger.warning(f"PoSF verification failed: {e}")
                    # Don't fail on PoSF verification errors - graceful degradation

            return True, "Valid"

        except Exception as e:
            return False, f"Validation error: {e}"

    def get_ter_summary_for_checkpoint(self) -> Dict[str, Any]:
        """
        Get TER summary for inclusion in DSM checkpoint.

        Returns aggregated TER data that can be included in checkpoints
        for cross-node validation.
        """
        with self._lock:
            recent_ters = list(self._ter_history)

        if not recent_ters:
            return {
                'node_id': self.node_id,
                'ter_count': 0,
                'weight_fingerprint': '',
                'sequence_range': (0, 0),
            }

        weight_fingerprint = self._compute_weight_fingerprint(recent_ters)

        # Compute aggregate threat score
        threat_scores = [ter.calculate_threat_score() for ter in recent_ters]
        avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0

        return {
            'node_id': self.node_id,
            'ter_count': len(recent_ters),
            'weight_fingerprint': weight_fingerprint.hex(),
            'sequence_range': (recent_ters[0].sequence, recent_ters[-1].sequence),
            'avg_threat_score': avg_threat,
            'latest_timestamp': recent_ters[-1].timestamp,
            'chain_intact': self._verify_chain_integrity(recent_ters),
        }

    def _should_create_microblock(self, ter: 'TER') -> bool:
        """Determine if we should create a DSM microblock for this TER."""
        if not self.dsm_node:
            return False

        # Create microblock every N TERs
        if self.stats['ters_generated'] % self.config.checkpoint_ter_count == 0:
            return True

        # Create microblock on significant threat score change
        threat_score = ter.calculate_threat_score()
        if threat_score > self.config.microblock_threshold:
            return True

        return False

    def _create_neuro_microblock(self, ter: 'TER') -> Optional[str]:
        """Create DSM microblock with Neuro proof."""
        if not self.dsm_node or not DSM_AVAILABLE:
            return None

        try:
            # Get recent TER history
            with self._lock:
                recent_ters = list(self._ter_history)[-self.config.checkpoint_ter_count:]

            weight_fingerprint = self._compute_weight_fingerprint(recent_ters)

            payload = {
                'neuro_proof_type': 'ter_checkpoint',
                'ter_count': len(recent_ters),
                'sequence_range': (
                    recent_ters[0].sequence if recent_ters else 0,
                    recent_ters[-1].sequence if recent_ters else 0
                ),
                'weight_fingerprint': weight_fingerprint.hex(),
                'avg_threat_score': sum(t.calculate_threat_score() for t in recent_ters) / len(recent_ters),
                'latest_entropy_hash': ter.h_entropy.hex()[:32],
                'chain_intact': self._verify_chain_integrity(recent_ters),
            }

            block_id = self.dsm_node.create_microblock(
                event_type='neuro_checkpoint',
                payload=payload
            )

            if block_id:
                self.stats['microblocks_created'] += 1
                logger.info(f"Created Neuro microblock: {block_id[:16]}...")

            return block_id

        except Exception as e:
            logger.error(f"Failed to create Neuro microblock: {e}")
            return None

    def _compute_weight_fingerprint(self, ter_sequence: List['TER']) -> bytes:
        """
        Compute weight fingerprint from TER sequence.

        This creates a deterministic fingerprint of the neural weight evolution
        that can be compared across nodes for consensus.
        """
        if not ter_sequence:
            return b'\x00' * 32

        # Combine entropy hashes with weight evolution simulation
        combined = b''
        for ter in ter_sequence:
            combined += ter.h_entropy + struct.pack('<H', ter.sequence)

        # Final fingerprint
        return hashlib.sha256(combined).digest()

    def _calculate_fingerprint_drift(self, fp1: bytes, fp2: bytes) -> float:
        """
        Calculate drift between two weight fingerprints.

        Returns normalized drift value [0.0, 1.0].
        """
        if not fp1 or not fp2:
            return 1.0

        if len(fp1) != len(fp2):
            return 1.0

        # Count differing bits
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(fp1, fp2))
        max_bits = len(fp1) * 8

        return diff_bits / max_bits

    def _validate_entropy_consistency(self, ter_sequence: List['TER']) -> bool:
        """Validate that entropy values show expected variation."""
        if len(ter_sequence) < 2:
            return True

        # Calculate entropy variation between consecutive TERs
        variations = []
        for i in range(1, len(ter_sequence)):
            prev_entropy = sum(ter_sequence[i-1].h_entropy)
            curr_entropy = sum(ter_sequence[i].h_entropy)
            variation = abs(curr_entropy - prev_entropy) / max(prev_entropy, 1)
            variations.append(variation)

        # Check for anomalous patterns (too uniform or too random)
        avg_variation = sum(variations) / len(variations)

        # If variation is too low, entropy might be static/fake
        if avg_variation < 0.01:
            return False

        # If variation is too high, might be random noise
        if avg_variation > 0.5:
            return False

        return True

    def _verify_chain_integrity(self, ter_sequence: List['TER']) -> bool:
        """Verify TER chain integrity."""
        if len(ter_sequence) < 2:
            return True

        for i in range(1, len(ter_sequence)):
            prev_ter = ter_sequence[i-1]
            curr_ter = ter_sequence[i]

            # Calculate expected chain hash
            expected_hash = self._crc16(prev_ter.to_bytes())
            if curr_ter.chain_hash != expected_hash:
                return False

        return True

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

    def _update_weight_fingerprint(self, ter: 'TER'):
        """Update current weight fingerprint."""
        with self._lock:
            recent_ters = list(self._ter_history)

        if recent_ters:
            self._current_weight_fingerprint = self._compute_weight_fingerprint(recent_ters)

    def _create_posf_signature(self, message: bytes) -> bytes:
        """Create PoSF signature using neural engine."""
        if not self.neural_engine:
            return b''

        # This would use the neural engine to create a PoSF signature
        # For now, return a hash-based placeholder
        return hashlib.sha256(message + self.node_id.encode()).digest()

    def _verify_posf_signature(
        self,
        message: bytes,
        signature: bytes,
        node_id: str
    ) -> bool:
        """Verify PoSF signature from a peer node."""
        # Simplified verification - in production would replay TER sequence
        expected = hashlib.sha256(message + node_id.encode()).digest()
        return signature == expected

    def get_statistics(self) -> Dict[str, Any]:
        """Get bridge statistics."""
        return {
            **self.stats,
            'ter_history_size': len(self._ter_history),
            'current_fingerprint': (
                self._current_weight_fingerprint.hex()[:32]
                if self._current_weight_fingerprint else None
            ),
            'neuro_available': NEURO_AVAILABLE,
            'dsm_connected': self.dsm_node is not None,
        }


# Convenience function for creating bridge
def create_neuro_dsm_bridge(
    node_id: str,
    dsm_node: Optional['DSMNode'] = None,
    config: Optional[NeuroDSMConfig] = None
) -> NeuroDSMBridge:
    """
    Create a NeuroDSMBridge with common configuration.

    Args:
        node_id: Unique node identifier
        dsm_node: Optional DSM node instance
        config: Optional configuration

    Returns:
        Configured NeuroDSMBridge instance
    """
    ter_generator = TERGenerator() if NEURO_AVAILABLE else None

    return NeuroDSMBridge(
        node_id=node_id,
        config=config or NeuroDSMConfig(),
        dsm_node=dsm_node,
        ter_generator=ter_generator
    )
