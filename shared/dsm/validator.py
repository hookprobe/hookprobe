"""
DSM Validator Implementation

Implements checkpoint creation, Merkle tree construction, and validator quorum management.
Based on the architecture specified in docs/architecture/dsm-implementation.md

SECURITY: Enforces Proof of Possession (PoP) to prevent rogue-key attacks.
All validators must provide a valid PoP at registration before participating in consensus.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

from .node import DSMNode
from .merkle import MerkleTree
from .crypto.bls import (
    bls_sign, bls_aggregate, bls_verify,
    ProofOfPossession, verify_proof_of_possession,
    PoPVerificationError, RogueKeyDetected,
)
from .identity import verify_certificate_chain, DSM_CA_ROOT

logger = logging.getLogger(__name__)


@dataclass
class ValidatorEntry:
    """
    Validator registry entry with PoP verification status.

    SECURITY: The is_pop_verified flag MUST be True before a validator
    can participate in consensus. This prevents rogue-key attacks where
    a malicious validator could forge aggregated BLS signatures.
    """
    node_id: str
    public_key: bytes
    certificate: bytes
    is_pop_verified: bool = False
    pop_epoch: Optional[int] = None
    pop_verified_at: Optional[datetime] = None
    registration_timestamp: datetime = field(default_factory=datetime.utcnow)
    reputation_score: float = 0.0
    uptime_days: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize validator entry to dictionary."""
        return {
            'node_id': self.node_id,
            'public_key': self.public_key.hex() if isinstance(self.public_key, bytes) else self.public_key,
            'is_pop_verified': self.is_pop_verified,
            'pop_epoch': self.pop_epoch,
            'pop_verified_at': self.pop_verified_at.isoformat() if self.pop_verified_at else None,
            'registration_timestamp': self.registration_timestamp.isoformat(),
            'reputation_score': self.reputation_score,
            'uptime_days': self.uptime_days,
        }


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

    SECURITY: Enforces Proof of Possession (PoP) to prevent rogue-key attacks.
    See shared/dsm/crypto/bls.py for PoP implementation details.

    Example:
        >>> registry = ValidatorRegistry()
        >>> registry.apply_for_validator(node_identity, proof_of_possession)
    """

    def __init__(self):
        self.validators: Dict[str, ValidatorEntry] = {}
        self.pending_applications = {}
        self._current_epoch = 0  # Should be updated by consensus engine

    def set_current_epoch(self, epoch: int):
        """Update current epoch for PoP verification."""
        self._current_epoch = epoch

    def apply_for_validator(
        self,
        node_identity,
        proof_of_possession: Optional[ProofOfPossession] = None,
    ) -> str:
        """
        Node applies to become a validator.

        Requirements:
        - Valid TPM certificate
        - Successful attestation
        - Uptime history >30 days
        - Reputation score >0.8
        - Stake/bond (optional)
        - SECURITY: Valid Proof of Possession (PoP) - REQUIRED

        Args:
            node_identity: NodeIdentity object
            proof_of_possession: PoP proving control of private key (REQUIRED)

        Returns:
            Application ID

        Raises:
            InvalidIdentity: If identity verification fails
            AttestationFailed: If platform integrity check fails
            PoPVerificationError: If Proof of Possession is invalid
            RogueKeyDetected: If PoP verification detects a potential attack
        """
        # SECURITY: Verify Proof of Possession FIRST (before any other checks)
        # This prevents rogue-key attacks where a malicious validator could
        # craft a public key that allows forging aggregated BLS signatures.
        if proof_of_possession is None:
            raise PoPVerificationError(
                "Proof of Possession is required for validator registration. "
                "Without PoP, rogue-key attacks could bypass BFT quorum requirements."
            )

        # Verify PoP matches the identity being registered
        if proof_of_possession.validator_id != node_identity.node_id:
            raise RogueKeyDetected(
                f"PoP validator_id mismatch: PoP={proof_of_possession.validator_id}, "
                f"identity={node_identity.node_id}"
            )

        # Verify PoP is for the correct public key
        if proof_of_possession.public_key != node_identity.public_key:
            raise RogueKeyDetected(
                "PoP public key does not match identity public key - potential rogue-key attack"
            )

        # Verify PoP signature
        is_valid, reason = verify_proof_of_possession(
            pop=proof_of_possession,
            expected_epoch=None,  # Allow flexibility in epoch
            max_epoch_age=10,     # PoP must be recent (within 10 epochs)
        )

        if not is_valid:
            logger.warning(
                f"PoP verification FAILED for {node_identity.node_id}: {reason}"
            )
            raise PoPVerificationError(f"PoP verification failed: {reason}")

        logger.info(
            f"PoP verification PASSED for {node_identity.node_id}, "
            f"epoch={proof_of_possession.epoch}"
        )

        # Verify identity
        if not self._verify_identity(node_identity):
            raise InvalidIdentity("Node identity verification failed")

        # Verify attestation
        attestation = node_identity.attest()
        if not self._verify_attestation(attestation):
            raise AttestationFailed("Platform integrity check failed")

        # Check requirements
        uptime = self._check_uptime(node_identity.node_id)
        reputation = self._calculate_reputation(node_identity.node_id)

        requirements = {
            'valid_tpm_cert': True,  # Already verified above
            'attestation_passed': True,  # Already verified above
            'pop_verified': True,  # SECURITY: PoP verified above
            'uptime_history': uptime,  # >30 days
            'reputation_score': reputation,  # >0.8
            'stake': self._verify_stake(node_identity.node_id),  # Optional
        }

        if requirements['uptime_history'] < 30:
            raise ValueError(f"Insufficient uptime: {requirements['uptime_history']} days")

        if requirements['reputation_score'] < 0.8:
            raise ValueError(f"Insufficient reputation: {requirements['reputation_score']}")

        # Create validator entry with PoP status
        validator_entry = ValidatorEntry(
            node_id=node_identity.node_id,
            public_key=node_identity.public_key,
            certificate=node_identity.certificate,
            is_pop_verified=True,
            pop_epoch=proof_of_possession.epoch,
            pop_verified_at=datetime.utcnow(),
            reputation_score=reputation,
            uptime_days=uptime,
        )

        # Create application
        application = {
            'node_id': node_identity.node_id,
            'certificate': node_identity.certificate,
            'attestation': attestation,
            'requirements': requirements,
            'validator_entry': validator_entry,
            'timestamp': datetime.utcnow(),
            'status': 'pending'
        }

        app_id = self._generate_application_id()
        self.pending_applications[app_id] = application

        # Initiate vote by existing validators
        self._initiate_validator_vote(application)

        logger.info(f"Validator application submitted: {node_identity.node_id} (PoP verified)")

        return app_id

    def get_validator(self, node_id: str) -> Optional[ValidatorEntry]:
        """
        Get validator entry by node ID.

        Args:
            node_id: Validator node ID

        Returns:
            ValidatorEntry if found, None otherwise
        """
        return self.validators.get(node_id)

    def is_pop_verified(self, node_id: str) -> bool:
        """
        Check if a validator has valid PoP verification.

        SECURITY: This MUST be checked before accepting signatures from a validator.
        A validator without PoP verification could be attempting a rogue-key attack.

        Args:
            node_id: Validator node ID

        Returns:
            True if validator exists and has verified PoP, False otherwise
        """
        validator = self.validators.get(node_id)
        if validator is None:
            return False
        return validator.is_pop_verified

    def get_verified_validators(self) -> List[ValidatorEntry]:
        """
        Get all validators with verified PoP status.

        SECURITY: Only PoP-verified validators should participate in consensus.

        Returns:
            List of ValidatorEntry objects with is_pop_verified=True
        """
        return [v for v in self.validators.values() if v.is_pop_verified]

    def approve_application(self, app_id: str) -> Optional[ValidatorEntry]:
        """
        Approve a pending validator application after vote passes.

        Args:
            app_id: Application ID

        Returns:
            ValidatorEntry if approved, None otherwise
        """
        application = self.pending_applications.get(app_id)
        if not application:
            logger.warning(f"Application {app_id} not found")
            return None

        validator_entry = application.get('validator_entry')
        if not validator_entry:
            logger.error(f"Application {app_id} missing validator_entry")
            return None

        # SECURITY: Final check - ensure PoP was verified
        if not validator_entry.is_pop_verified:
            logger.error(
                f"SECURITY: Cannot approve validator {validator_entry.node_id} "
                "without PoP verification"
            )
            return None

        # Add to active validators
        self.validators[validator_entry.node_id] = validator_entry
        application['status'] = 'approved'

        logger.info(
            f"Validator approved: {validator_entry.node_id} "
            f"(PoP verified at epoch {validator_entry.pop_epoch})"
        )

        return validator_entry

    def _verify_identity(self, node_identity) -> bool:
        """Verify node has valid identity — check certificate exists and is signed."""
        if not node_identity or not hasattr(node_identity, 'certificate'):
            logger.warning("Identity verification failed: no certificate attribute")
            return False
        cert = node_identity.certificate
        if not cert:
            logger.warning("Identity verification failed: empty certificate")
            return False
        if isinstance(cert, (bytes, str)) and len(cert) < 16:
            logger.warning("Identity verification failed: certificate too short")
            return False
        # Verify certificate chain to DSM CA root
        try:
            return verify_certificate_chain(
                cert_path=cert if isinstance(cert, str) else "<inline>",
                trusted_root=DSM_CA_ROOT,
            )
        except Exception as e:
            logger.warning("Identity verification failed: %s", e)
            return False

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

        Loads from config file if available, otherwise returns empty dict
        (no PCR enforcement — logged at caller).
        """
        import json
        import os

        config_path = os.environ.get(
            "DSM_PCR_CONFIG", "/etc/hookprobe/dsm_pcr.json"
        )
        try:
            with open(config_path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug("PCR config not available (%s): %s", config_path, e)
            return {}  # Empty = no PCR enforcement

    def _check_uptime(self, node_id: str) -> int:
        """Get node uptime history in days from system or validator record."""
        # Check validator record first
        entry = self.validators.get(node_id)
        if entry and entry.uptime_days > 0:
            return entry.uptime_days
        # Fall back to actual system uptime
        try:
            with open("/proc/uptime") as f:
                uptime_seconds = float(f.read().split()[0])
            return int(uptime_seconds / 86400)
        except Exception:
            return 0

    def _calculate_reputation(self, node_id: str) -> float:
        """
        Calculate node reputation score (0.0-1.0).

        Based on existing validator record. Unknown nodes get neutral 0.5.
        """
        entry = self.validators.get(node_id)
        if not entry:
            return 0.5  # Unknown node = neutral reputation
        # Use stored reputation if set (updated by consensus rounds)
        if entry.reputation_score > 0:
            return min(1.0, entry.reputation_score)
        # Reputation builds with uptime
        if entry.uptime_days >= 90:
            return 0.95
        elif entry.uptime_days >= 30:
            return 0.85
        return 0.5

    def _verify_stake(self, node_id: str) -> bool:
        """Verify node has minimum stake (uptime commitment as contribution)."""
        entry = self.validators.get(node_id)
        if not entry:
            return False  # Unknown nodes have no stake
        # Stake = having contributed uptime as a validator (minimum 3 days)
        return entry.uptime_days >= 3

    def _generate_application_id(self) -> str:
        """Generate unique application ID."""
        import uuid
        return str(uuid.uuid4())

    def _initiate_validator_vote(self, application: Dict[str, Any]):
        """Broadcast application to existing validators for vote.

        Simple majority: if fewer than 2 verified validators, auto-approve
        (bootstrap phase). Otherwise require 2/3 quorum.
        """
        from .consensus import bft_quorum_required

        verified = self.get_verified_validators()
        node_id = application['node_id']

        if len(verified) < 2:
            # Bootstrap phase — auto-approve first validators
            logger.info("Bootstrap phase: auto-approving validator %s", node_id)
            app_id = [
                k for k, v in self.pending_applications.items()
                if v.get('node_id') == node_id
            ]
            if app_id:
                self.approve_application(app_id[0])
            return

        # Require quorum of existing validators
        quorum = bft_quorum_required(len(verified) + 1)
        logger.info(
            "Validator vote initiated for %s: need %d/%d approvals",
            node_id, quorum, len(verified),
        )


class InvalidIdentity(Exception):
    """Raised when node identity verification fails."""
    pass


class AttestationFailed(Exception):
    """Raised when platform attestation check fails."""
    pass
