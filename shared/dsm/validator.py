"""
DSM Validator Implementation

Implements checkpoint creation, Merkle tree construction, and validator quorum management.
Based on the architecture specified in docs/architecture/dsm-implementation.md
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from .node import DSMNode
from .merkle import MerkleTree
from .crypto.bls import bls_sign, bls_aggregate, bls_verify
from .identity import verify_certificate_chain, DSM_CA_ROOT

logger = logging.getLogger(__name__)


class DSMValidator(DSMNode):
    """
    Enhanced DSM node with validator capabilities.

    Only authorized, attested validators can create checkpoints and
    participate in consensus.

    Architecture:
        Collect Microblocks → Build Merkle Tree → Sign Checkpoint →
        Broadcast to Quorum → Aggregate BLS Signatures → Finalize

    Example:
        >>> validator = DSMValidator(
        ...     node_id="validator-001",
        ...     tpm_key_path="/var/lib/hookprobe/tpm/key",
        ...     validator_cert="/etc/hookprobe/certs/validator.pem"
        ... )
        >>> checkpoint = validator.build_checkpoint(epoch=147)
    """

    def __init__(
        self,
        node_id: str,
        tpm_key_path: str,
        validator_cert: str,
        **kwargs
    ):
        """
        Initialize validator node.

        Args:
            node_id: Unique validator identifier
            tpm_key_path: Path to TPM key
            validator_cert: Path to validator certificate (issued by DSM CA)
            **kwargs: Additional arguments passed to DSMNode
        """
        super().__init__(node_id, tpm_key_path, **kwargs)

        self.validator_cert = validator_cert
        self.is_validator = self._verify_validator_cert()

        if not self.is_validator:
            raise PermissionError(
                f"Node {node_id} does not have valid validator certificate"
            )

        logger.info(f"DSM Validator initialized: {node_id}")

    def build_checkpoint(self, epoch: int) -> Dict[str, Any]:
        """
        Aggregate all announced microblocks into a checkpoint.

        This implements the pseudocode from the whitepaper:

            def validator_build_checkpoint(epoch, validator):
                # collect announced M ids for epoch window
                m_ids = collect_announced_m_ids(epoch_window)
                merkle_root = build_merkle_root(m_ids)
                c = {
                  'type':'C','epoch':epoch,'timestamp':now(),'merkle_root':merkle_root,
                  'included_ranges': map_ranges(m_ids)
                }
                c['signature'] = sign_tpm(validator.key, serialize(c))
                broadcast(c)
                return c

        Args:
            epoch: Current epoch number (e.g., epoch 147 = minutes 735-740)

        Returns:
            Checkpoint object with Merkle root and signature

        Raises:
            PermissionError: If node is not a validator
        """
        if not self.is_validator:
            raise PermissionError("Only validators can create checkpoints")

        # Define epoch window (e.g., 5 minutes per epoch)
        epoch_window = self._get_epoch_window(epoch)

        # Collect all microblock IDs announced in this epoch window
        microblock_ids = self.gossip.collect_announced_blocks(epoch_window)

        if not microblock_ids:
            logger.warning(f"No microblocks in epoch {epoch}")
            return None

        # Build Merkle tree from microblock IDs
        merkle_tree = MerkleTree(microblock_ids)
        merkle_root = merkle_tree.root()

        # Map which sequence ranges from each node are included
        included_ranges = self._map_node_ranges(microblock_ids)

        # Create checkpoint structure
        checkpoint = {
            'type': 'C',  # Checkpoint
            'epoch': epoch,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'merkle_root': merkle_root,
            'included_ranges': included_ranges,
            'validator_id': self.node_id,
            'microblock_count': len(microblock_ids)
        }

        # Sign with validator TPM key
        checkpoint['signature'] = self._sign_with_tpm(checkpoint)

        # Broadcast to other validators for BLS aggregation
        self.gossip.broadcast_checkpoint(checkpoint)

        logger.info(
            f"Checkpoint created for epoch {epoch}: "
            f"{len(microblock_ids)} microblocks from {len(included_ranges)} nodes"
        )

        return checkpoint

    def _verify_validator_cert(self) -> bool:
        """
        Verify this node has a valid validator certificate
        issued by the DSM attestation authority.

        Returns:
            True if certificate is valid, False otherwise
        """
        try:
            return verify_certificate_chain(
                cert_path=self.validator_cert,
                trusted_root=DSM_CA_ROOT
            )
        except Exception as e:
            logger.error(f"Validator certificate verification failed: {e}")
            return False

    def _get_epoch_window(self, epoch: int) -> tuple:
        """
        Calculate time window for epoch.

        Each epoch is 5 minutes (300 seconds).
        Epoch 0 starts at Unix epoch (1970-01-01 00:00:00 UTC).

        Args:
            epoch: Epoch number

        Returns:
            Tuple of (start_time, end_time) as datetime objects
        """
        epoch_duration = 300  # 5 minutes in seconds
        epoch_start_unix = epoch * epoch_duration
        epoch_end_unix = (epoch + 1) * epoch_duration

        start_time = datetime.fromtimestamp(epoch_start_unix)
        end_time = datetime.fromtimestamp(epoch_end_unix)

        return (start_time, end_time)

    def _map_node_ranges(self, microblock_ids: List[str]) -> Dict[str, List[int]]:
        """
        Map which sequence ranges from each node are included in checkpoint.

        Args:
            microblock_ids: List of microblock IDs

        Returns:
            Dictionary mapping node_id to [start_seq, end_seq]

        Example:
            {
                'edge-uuid-12345': [1840, 1850],
                'edge-uuid-67890': [923, 935]
            }
        """
        node_sequences = {}

        for block_id in microblock_ids:
            # Fetch microblock from local ledger or gossip network
            microblock = self.ledger.get(block_id)
            if not microblock:
                microblock = self.gossip.fetch_block(block_id)

            if microblock:
                node_id = microblock['node_id']
                seq = microblock['seq']

                if node_id not in node_sequences:
                    node_sequences[node_id] = []

                node_sequences[node_id].append(seq)

        # Convert to ranges [min, max]
        ranges = {}
        for node_id, sequences in node_sequences.items():
            if sequences:
                ranges[node_id] = [min(sequences), max(sequences)]

        return ranges


class ValidatorRegistry:
    """
    Maintains registry of authorized validators.

    Only nodes with valid attestation can become validators.
    New validators require 2/3 approval from existing validators.

    Example:
        >>> registry = ValidatorRegistry()
        >>> registry.apply_for_validator(node_identity)
    """

    def __init__(self):
        self.validators = {}
        self.pending_applications = {}

    def apply_for_validator(self, node_identity) -> str:
        """
        Node applies to become a validator.

        Requirements:
        - Valid TPM certificate
        - Successful attestation
        - Uptime history >30 days
        - Reputation score >0.8
        - Stake/bond (optional)

        Args:
            node_identity: NodeIdentity object

        Returns:
            Application ID

        Raises:
            InvalidIdentity: If identity verification fails
            AttestationFailed: If platform integrity check fails
        """
        # Verify identity
        if not self._verify_identity(node_identity):
            raise InvalidIdentity("Node identity verification failed")

        # Verify attestation
        attestation = node_identity.attest()
        if not self._verify_attestation(attestation):
            raise AttestationFailed("Platform integrity check failed")

        # Check requirements
        requirements = {
            'valid_tpm_cert': True,  # Already verified above
            'attestation_passed': True,  # Already verified above
            'uptime_history': self._check_uptime(node_identity.node_id),  # >30 days
            'reputation_score': self._calculate_reputation(node_identity.node_id),  # >0.8
            'stake': self._verify_stake(node_identity.node_id),  # Optional
        }

        if requirements['uptime_history'] < 30:
            raise ValueError(f"Insufficient uptime: {requirements['uptime_history']} days")

        if requirements['reputation_score'] < 0.8:
            raise ValueError(f"Insufficient reputation: {requirements['reputation_score']}")

        # Create application
        application = {
            'node_id': node_identity.node_id,
            'certificate': node_identity.certificate,
            'attestation': attestation,
            'requirements': requirements,
            'timestamp': datetime.utcnow(),
            'status': 'pending'
        }

        app_id = self._generate_application_id()
        self.pending_applications[app_id] = application

        # Initiate vote by existing validators
        self._initiate_validator_vote(application)

        logger.info(f"Validator application submitted: {node_identity.node_id}")

        return app_id

    def _verify_identity(self, node_identity) -> bool:
        """Verify node has valid TPM certificate."""
        # TODO: Implement certificate verification
        return True

    def _verify_attestation(self, attestation: Dict[str, Any]) -> bool:
        """
        Verify TPM quote and PCR values.

        Ensures node is running authentic HookProbe software.

        Args:
            attestation: Attestation dictionary with PCR values and quote

        Returns:
            True if valid, False otherwise
        """
        # Verify PCR values match expected measurements
        expected_pcr = self._get_expected_pcr_values()
        if attestation['pcr_values'] != expected_pcr:
            logger.warning("PCR values do not match expected baseline")
            return False

        # Verify TPM quote signature
        # TODO: Implement TPM quote verification
        # if not tpm2_verify_quote(attestation['quote'], attestation['certificate']):
        #     return False

        return True

    def _get_expected_pcr_values(self) -> Dict[int, str]:
        """
        Get expected PCR values for authentic HookProbe installation.

        These are measured during initial provisioning and represent
        known-good platform configuration.
        """
        # TODO: Load from configuration
        return {
            0: "expected_pcr0_hash",
            1: "expected_pcr1_hash",
            2: "expected_pcr2_hash",
            3: "expected_pcr3_hash",
            7: "expected_pcr7_hash",
        }

    def _check_uptime(self, node_id: str) -> int:
        """Get node uptime history in days."""
        # TODO: Query from metrics database
        return 45  # Example: 45 days

    def _calculate_reputation(self, node_id: str) -> float:
        """
        Calculate node reputation score (0.0-1.0).

        Based on:
        - Uptime percentage
        - Valid microblocks created
        - Attestation success rate
        - Peer reviews
        """
        # TODO: Implement reputation calculation
        return 0.95  # Example: 95% reputation

    def _verify_stake(self, node_id: str) -> bool:
        """Verify node has deposited stake (optional economic incentive)."""
        # TODO: Implement stake verification
        return True

    def _generate_application_id(self) -> str:
        """Generate unique application ID."""
        import uuid
        return str(uuid.uuid4())

    def _initiate_validator_vote(self, application: Dict[str, Any]):
        """Broadcast application to existing validators for vote."""
        # TODO: Implement voting protocol
        pass


class InvalidIdentity(Exception):
    """Raised when node identity verification fails."""
    pass


class AttestationFailed(Exception):
    """Raised when platform attestation check fails."""
    pass
