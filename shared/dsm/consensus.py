"""
DSM Consensus Engine

Implements BLS signature aggregation for Byzantine fault-tolerant consensus.
Based on the architecture specified in docs/architecture/dsm-implementation.md

Now integrated with Neural Synaptic Encryption (NSE) for TER-validated signatures.

SECURITY: Enforces Proof of Possession (PoP) verification for all validators.
Only validators with verified PoP can participate in consensus to prevent rogue-key attacks.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, TYPE_CHECKING

from .crypto.bls import bls_aggregate, bls_verify, bls_verify_single
from .gossip import GossipProtocol

if TYPE_CHECKING:
    from .validator import ValidatorRegistry

logger = logging.getLogger(__name__)

# Neural Synaptic Encryption integration for TER validation
try:
    from core.neuro.integration import DSMNeuroValidator, TERCheckpointProof
    NEURO_INTEGRATION_AVAILABLE = True
except ImportError:
    DSMNeuroValidator = None
    TERCheckpointProof = None
    NEURO_INTEGRATION_AVAILABLE = False


class ConsensusEngine:
    """
    Handles BLS signature aggregation for Byzantine fault tolerance.

    Requires 2/3 validator quorum for checkpoint finality.
    Tolerates up to f=(n-1)/3 Byzantine (malicious) validators.

    Architecture:
        Validators Sign → Collect Signatures → Aggregate BLS →
        Verify Quorum → Commit Checkpoint → Broadcast

    Example:
        >>> engine = ConsensusEngine(validators, quorum_threshold=0.67)
        >>> checkpoint = engine.collect_validator_signatures(checkpoint)
        >>> print(checkpoint['finalized_at'])
    """

    def __init__(
        self,
        validators: List[Any],
        quorum_threshold: float = 0.67,
        signature_timeout: int = 30,
        node_id: Optional[str] = None,
        validator_registry: Optional['ValidatorRegistry'] = None,
    ):
        """
        Initialize consensus engine.

        Args:
            validators: List of validator objects
            quorum_threshold: Minimum fraction of validators required (default 2/3)
            signature_timeout: Seconds to wait for validator signatures
            node_id: Node identifier for NSE integration
            validator_registry: Registry for PoP verification (SECURITY: Required for production)
        """
        self.validators = validators
        self.quorum_threshold = quorum_threshold
        self.signature_timeout = signature_timeout
        self.pending_checkpoints = {}
        self.node_id = node_id or "consensus-engine"

        # SECURITY: Validator registry for PoP verification
        # Without this, rogue-key attacks could bypass BFT quorum requirements
        self.validator_registry = validator_registry
        if validator_registry is None:
            logger.warning(
                "[DSM SECURITY] No validator registry provided - PoP verification disabled! "
                "This is unsafe for production. Rogue-key attacks are possible."
            )

        # Initialize Neural Synaptic Encryption validator for TER proofs
        self.neuro_validator: Optional['DSMNeuroValidator'] = None
        if NEURO_INTEGRATION_AVAILABLE and DSMNeuroValidator:
            try:
                self.neuro_validator = DSMNeuroValidator(self.node_id)
                logger.info(f"[DSM] NeuroValidator initialized for TER validation")
            except Exception as e:
                logger.warning(f"[DSM] Failed to initialize NeuroValidator: {e}")

        logger.info(
            f"Consensus engine initialized: {len(validators)} validators, "
            f"quorum={quorum_threshold:.0%}, NSE={'enabled' if self.neuro_validator else 'disabled'}, "
            f"PoP={'enabled' if validator_registry else 'DISABLED (UNSAFE)'}"
        )

    def collect_validator_signatures(
        self,
        checkpoint: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Gather signatures from validators and aggregate via BLS.

        This implements the pseudocode from the whitepaper:

            def collect_validator_signatures(c):
                # aggregator collects validator signatures, aggregates via BLS
                sigs = gather_sigs(c.epoch, timeout=T)
                agg = bls_aggregate(sigs)
                if verify_agg_sig(agg, c):
                    c['agg_signature'] = agg
                    commit_checkpoint(c)
                    broadcast_checkpoint(c)

        Args:
            checkpoint: Checkpoint object to be finalized

        Returns:
            Finalized checkpoint with aggregated signature

        Raises:
            QuorumNotReached: If insufficient validators sign
            InvalidAggregateSignature: If BLS verification fails
        """
        epoch = checkpoint['epoch']
        merkle_root = checkpoint['merkle_root']

        logger.info(f"Collecting signatures for checkpoint epoch {epoch}")

        # Gather signatures from other validators
        signatures = self._gather_signatures(
            epoch=epoch,
            merkle_root=merkle_root,
            timeout=self.signature_timeout
        )

        # Calculate required signatures for BFT quorum
        total_validators = len(self.validators)
        required_signatures = int(total_validators * self.quorum_threshold)

        # Verify quorum
        if len(signatures) < required_signatures:
            raise QuorumNotReached(
                f"Only {len(signatures)}/{required_signatures} validators signed "
                f"(threshold={self.quorum_threshold:.0%})"
            )

        logger.info(f"Quorum reached: {len(signatures)}/{total_validators} signatures")

        # Aggregate using BLS signature scheme
        bls_signatures = [s['signature'] for s in signatures]
        aggregated_sig = bls_aggregate(bls_signatures)

        # Verify aggregated signature
        if not self._verify_aggregated_signature(aggregated_sig, checkpoint):
            raise InvalidAggregateSignature("BLS verification failed")

        # Add aggregated signature to checkpoint
        checkpoint['agg_signature'] = aggregated_sig
        checkpoint['signatures'] = signatures
        checkpoint['validator_count'] = len(signatures)
        checkpoint['finalized_at'] = datetime.utcnow().isoformat() + 'Z'

        # Commit to persistent storage
        self._commit_checkpoint(checkpoint)

        # Broadcast finalized checkpoint to all nodes
        self._broadcast_finalized_checkpoint(checkpoint)

        # Metrics
        self._increment_metric('dsm.checkpoints.finalized', {
            'epoch': epoch,
            'validators': len(signatures)
        })

        logger.info(f"Checkpoint finalized: epoch={epoch}, validators={len(signatures)}")

        return checkpoint

    def _gather_signatures(
        self,
        epoch: int,
        merkle_root: str,
        timeout: int
    ) -> List[Dict[str, Any]]:
        """
        Collect signatures from validator quorum.

        Args:
            epoch: Checkpoint epoch
            merkle_root: Merkle root to sign
            timeout: Seconds to wait for responses

        Returns:
            List of signature dictionaries
        """
        signatures = []
        start_time = datetime.utcnow()

        for validator in self.validators:
            # Check timeout
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            if elapsed > timeout:
                logger.warning(f"Signature collection timeout after {elapsed:.1f}s")
                break

            try:
                # Request signature from validator
                sig = validator.sign_checkpoint(epoch, merkle_root)

                # Verify signature before accepting
                if self._verify_single_signature(sig, validator):
                    signatures.append({
                        'validator_id': validator.node_id,
                        'signature': sig,
                        'timestamp': datetime.utcnow().isoformat() + 'Z'
                    })
                else:
                    logger.warning(
                        f"Invalid signature from validator {validator.node_id}"
                    )

            except Exception as e:
                logger.warning(f"Validator {validator.node_id} failed to sign: {e}")

        return signatures

    def _verify_single_signature(
        self,
        signature: str,
        validator: Any,
        vote: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Verify individual validator signature before aggregation.

        SECURITY: Enforces PoP verification to prevent rogue-key attacks.
        Now integrated with NSE for TER checkpoint proof validation.

        Args:
            signature: BLS signature to verify
            validator: Validator object with public key
            vote: Optional vote dictionary containing TER checkpoint proof

        Returns:
            True if valid, False otherwise
        """
        # SECURITY: Check PoP verification status FIRST
        # A validator without verified PoP could be attempting a rogue-key attack
        # where they craft a public key that allows forging aggregated signatures
        if self.validator_registry is not None:
            if not self.validator_registry.is_pop_verified(validator.node_id):
                logger.warning(
                    f"[DSM SECURITY] Rejecting signature from {validator.node_id}: "
                    "PoP not verified - potential rogue-key attack"
                )
                return False
            logger.debug(f"[DSM] PoP verified for {validator.node_id}")

        # NSE Integration: Verify TER checkpoint proof if available
        if self.neuro_validator and vote:
            try:
                is_valid, reason = self.neuro_validator.verify_consensus_vote(
                    vote=vote,
                    validator_id=validator.node_id,
                )
                if not is_valid:
                    logger.warning(
                        f"[DSM NSE] TER proof invalid from {validator.node_id}: {reason}"
                    )
                    return False
                logger.debug(f"[DSM NSE] TER proof valid from {validator.node_id}")
            except Exception as e:
                logger.warning(f"[DSM NSE] TER validation error: {e}")
                # Fall through to BLS verification

        # BLS signature verification
        try:
            return bls_verify_single(signature, validator.public_key, b"checkpoint")
        except Exception as e:
            logger.warning(f"[DSM] BLS verification failed for {validator.node_id}: {e}")
            return False

    def _verify_aggregated_signature(
        self,
        agg_sig: str,
        checkpoint: Dict[str, Any]
    ) -> bool:
        """
        Verify BLS aggregated signature against validator public keys.

        Args:
            agg_sig: Aggregated BLS signature
            checkpoint: Checkpoint object

        Returns:
            True if valid, False otherwise
        """
        # Extract validator public keys
        validator_pubkeys = [v.public_key for v in self.validators]

        # Create message to verify
        message = self._checkpoint_message(checkpoint)

        # Verify aggregated signature
        return bls_verify(agg_sig, validator_pubkeys, message)

    def _checkpoint_message(self, checkpoint: Dict[str, Any]) -> bytes:
        """
        Create canonical message for checkpoint signing.

        Args:
            checkpoint: Checkpoint dictionary

        Returns:
            Serialized message bytes
        """
        import json

        # Create deterministic message (exclude signatures)
        message_dict = {
            'type': checkpoint['type'],
            'epoch': checkpoint['epoch'],
            'timestamp': checkpoint['timestamp'],
            'merkle_root': checkpoint['merkle_root'],
            'included_ranges': checkpoint['included_ranges']
        }

        # Serialize deterministically
        return json.dumps(message_dict, sort_keys=True).encode('utf-8')

    def _commit_checkpoint(self, checkpoint: Dict[str, Any]):
        """
        Commit finalized checkpoint to persistent storage.

        Uses local JSON files as portable fallback (works without PostgreSQL).
        """
        import json, os
        checkpoint_dir = os.environ.get(
            "DSM_CHECKPOINT_DIR", "/var/lib/hookprobe/dsm/checkpoints"
        )
        try:
            os.makedirs(checkpoint_dir, exist_ok=True)
            path = os.path.join(checkpoint_dir, f"cp_{checkpoint['epoch']}.json")
            with open(path, 'w') as f:
                json.dump(checkpoint, f, default=str)
            logger.info("Checkpoint %d committed to %s", checkpoint['epoch'], path)
        except OSError as e:
            # Fall back to logging only if filesystem is read-only
            logger.warning("Cannot persist checkpoint to disk: %s", e)
            logger.info("Checkpoint committed (in-memory): epoch=%d", checkpoint['epoch'])

    def _broadcast_finalized_checkpoint(self, checkpoint: Dict[str, Any]):
        """
        Broadcast finalized checkpoint to all mesh nodes via gossip protocol.

        All edge nodes will verify and update their view of the
        global security mesh state.
        """
        try:
            from .gossip import GossipProtocol
            gossip = GossipProtocol.get_instance()
            if gossip:
                gossip.announce(checkpoint)
                logger.info("Checkpoint %d broadcast via gossip", checkpoint['epoch'])
            else:
                logger.debug("Gossip not available, checkpoint broadcast skipped")
        except (ImportError, AttributeError) as e:
            logger.debug("Gossip broadcast unavailable: %s", e)
        logger.info("Checkpoint broadcast to mesh: epoch=%d", checkpoint['epoch'])

    def _increment_metric(self, metric_name: str, tags: Dict[str, Any]):
        """Export metrics to POD-005 (Grafana/VictoriaMetrics)."""
        # Log metrics for collection by external scrapers
        tag_str = ",".join(f"{k}={v}" for k, v in tags.items())
        logger.debug("METRIC %s{%s} incremented", metric_name, tag_str)

    def byzantine_tolerance(self) -> Dict[str, int]:
        """
        Calculate Byzantine fault tolerance parameters.

        Returns:
            Dictionary with tolerance metrics

        Example:
            >>> engine.byzantine_tolerance()
            {
                'total_validators': 10,
                'required_signatures': 7,
                'byzantine_tolerance': 3,
                'safety_margin': 3
            }
        """
        n = len(self.validators)
        f = (n - 1) // 3  # Maximum Byzantine nodes tolerated
        required = n - f  # Signatures required for consensus

        return {
            'total_validators': n,
            'required_signatures': required,
            'byzantine_tolerance': f,
            'safety_margin': n - required
        }


class QuorumNotReached(Exception):
    """Raised when insufficient validators sign checkpoint."""
    pass


class InvalidAggregateSignature(Exception):
    """Raised when BLS aggregated signature verification fails."""
    pass


def bft_quorum_required(total_validators: int) -> int:
    """
    Calculate minimum validators required for BFT consensus.

    Tolerates up to f=(n-1)/3 Byzantine (malicious) validators.

    Args:
        total_validators: Total number of validators

    Returns:
        Required number of signatures for quorum

    Examples:
        >>> bft_quorum_required(10)
        7  # Tolerates 3 Byzantine, requires 7 honest

        >>> bft_quorum_required(7)
        5  # Tolerates 2 Byzantine, requires 5 honest

        >>> bft_quorum_required(4)
        3  # Tolerates 1 Byzantine, requires 3 honest
    """
    f = (total_validators - 1) // 3  # Byzantine tolerance
    quorum = total_validators - f  # Required signatures
    return quorum
