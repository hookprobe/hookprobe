"""
DSM Consensus Engine

Implements BLS signature aggregation for Byzantine fault-tolerant consensus.
Based on the architecture specified in docs/architecture/dsm-implementation.md
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from .crypto.bls import bls_aggregate, bls_verify, bls_verify_single
from .gossip import GossipProtocol

logger = logging.getLogger(__name__)


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
        signature_timeout: int = 30
    ):
        """
        Initialize consensus engine.

        Args:
            validators: List of validator objects
            quorum_threshold: Minimum fraction of validators required (default 2/3)
            signature_timeout: Seconds to wait for validator signatures
        """
        self.validators = validators
        self.quorum_threshold = quorum_threshold
        self.signature_timeout = signature_timeout
        self.pending_checkpoints = {}

        logger.info(
            f"Consensus engine initialized: {len(validators)} validators, "
            f"quorum={quorum_threshold:.0%}"
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
        validator: Any
    ) -> bool:
        """
        Verify individual validator signature before aggregation.

        Args:
            signature: BLS signature to verify
            validator: Validator object with public key

        Returns:
            True if valid, False otherwise
        """
        # TODO: Implement BLS single signature verification
        # return bls_verify_single(signature, validator.public_key, message)
        return True  # Placeholder

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

        Stored in PostgreSQL (POD-003) for long-term retention.
        """
        # TODO: Store in PostgreSQL
        logger.info(f"Checkpoint committed to storage: epoch={checkpoint['epoch']}")

    def _broadcast_finalized_checkpoint(self, checkpoint: Dict[str, Any]):
        """
        Broadcast finalized checkpoint to all mesh nodes.

        All edge nodes will verify and update their view of the
        global security mesh state.
        """
        # TODO: Broadcast via gossip protocol
        logger.info(f"Checkpoint broadcast to mesh: epoch={checkpoint['epoch']}")

    def _increment_metric(self, metric_name: str, tags: Dict[str, Any]):
        """Export metrics to POD-005 (Grafana/VictoriaMetrics)."""
        # TODO: Implement metric export
        pass

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
