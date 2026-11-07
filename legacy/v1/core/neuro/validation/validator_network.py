"""
Validator Network with VRF Selection and Threshold Signatures

Implements permissioned validator pool with:
- VRF-based random validator subset selection
- Threshold signatures (FROST/BLS) for aggregation
- Geographic/vendor diversity enforcement
- Slashing for misbehavior
- HSM key protection
"""

import hashlib
import struct
import secrets
from typing import List, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ValidatorStatus(Enum):
    """Validator operational status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    BLACKLISTED = "blacklisted"
    PENDING = "pending"


@dataclass
class ValidatorInfo:
    """Validator node information."""
    validator_id: str
    ed25519_public_key: bytes  # 32 bytes
    bls_public_key: bytes  # 48 bytes (BLS12-381)

    # Diversity attributes
    geographic_region: str  # e.g., "us-east", "eu-west", "ap-southeast"
    operator: str  # Organization operating the validator
    asn: int  # Autonomous System Number (ISP diversity)

    # Staking
    stake_amount: int  # Economic stake (for slashing)
    reputation_score: float  # 0.0-1.0 (earned over time)

    # Operational
    status: ValidatorStatus
    last_seen: int  # Unix timestamp
    successful_validations: int
    failed_validations: int

    # HSM
    hsm_protected: bool  # Whether keys are in HSM


@dataclass
class ValidationRequest:
    """Request for validator subset to validate attestation."""
    request_id: bytes  # 16-byte unique identifier
    device_id: str
    attestation_hash: bytes  # SHA256 of attestation
    timestamp: int
    required_validators: int  # Quorum size
    merkle_log_root: bytes  # Previous log root for VRF seed


@dataclass
class ValidationVote:
    """Individual validator vote on attestation."""
    request_id: bytes
    validator_id: str
    vote: bool  # True = valid, False = invalid
    anomaly_score: Optional[float]  # ML-based anomaly detection score
    signature: bytes  # Ed25519 signature of vote


@dataclass
class ThresholdProof:
    """Aggregated threshold signature proof."""
    request_id: bytes
    participating_validators: List[str]  # Validator IDs
    aggregate_vote: bool  # True if quorum accepts
    aggregate_signature: bytes  # BLS aggregate signature
    merkle_root: bytes  # New Merkle log root after this validation


class VRF:
    """
    Verifiable Random Function for unpredictable validator selection.

    Uses Ed25519-based VRF (similar to VRF-ED25519-SHA512).
    """

    def __init__(self, private_key: bytes):
        """
        Args:
            private_key: Ed25519 private key (32 bytes)
        """
        from cryptography.hazmat.primitives.asymmetric import ed25519
        self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        self.public_key = self.private_key.public_key()

    def prove(self, seed: bytes) -> Tuple[bytes, bytes]:
        """
        Generate VRF proof and output.

        Args:
            seed: Input seed (e.g., Merkle log root)

        Returns:
            (vrf_output, vrf_proof)

        vrf_output: 32-byte pseudorandom output
        vrf_proof: 64-byte proof that output was correctly generated
        """
        # Simplified VRF (production would use proper VRF-ED25519-SHA512)
        # Sign the seed to create proof
        vrf_proof = self.private_key.sign(seed)

        # Derive output from proof
        vrf_output = hashlib.sha256(vrf_proof + seed).digest()

        return vrf_output, vrf_proof

    def verify(self, seed: bytes, vrf_output: bytes, vrf_proof: bytes, public_key: bytes) -> bool:
        """
        Verify VRF proof.

        Args:
            seed: Input seed
            vrf_output: Claimed VRF output
            vrf_proof: VRF proof
            public_key: Ed25519 public key (32 bytes)

        Returns:
            True if proof is valid
        """
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            # Verify signature (proof)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pub_key.verify(vrf_proof, seed)

            # Verify output derivation
            expected_output = hashlib.sha256(vrf_proof + seed).digest()
            return vrf_output == expected_output

        except Exception:
            return False


class ValidatorNetwork:
    """
    Manages validator pool and subset selection.

    Features:
    - VRF-based random validator selection
    - Geographic/operator diversity enforcement
    - Quorum calculation and threshold verification
    """

    def __init__(self, min_stake: int = 1000, min_reputation: float = 0.5):
        """
        Args:
            min_stake: Minimum stake required for active validators
            min_reputation: Minimum reputation score (0.0-1.0)
        """
        self.validators: dict[str, ValidatorInfo] = {}
        self.min_stake = min_stake
        self.min_reputation = min_reputation

    def register_validator(self, validator: ValidatorInfo) -> bool:
        """
        Register new validator (with vetting).

        Args:
            validator: Validator information

        Returns:
            True if registration accepted
        """
        # Check minimum requirements
        if validator.stake_amount < self.min_stake:
            return False

        # In production: Additional vetting (KYC, etc.)
        validator.status = ValidatorStatus.PENDING

        self.validators[validator.validator_id] = validator
        return True

    def activate_validator(self, validator_id: str) -> bool:
        """
        Activate validator after vetting complete.

        Args:
            validator_id: Validator to activate

        Returns:
            True if activated
        """
        if validator_id not in self.validators:
            return False

        validator = self.validators[validator_id]
        if validator.status == ValidatorStatus.PENDING:
            validator.status = ValidatorStatus.ACTIVE
            return True

        return False

    def select_validator_subset(
        self,
        request: ValidationRequest,
        vrf_seed: bytes,
        subset_size: int
    ) -> List[ValidatorInfo]:
        """
        Select random validator subset using VRF.

        Args:
            request: Validation request
            vrf_seed: Seed for VRF (e.g., Merkle log root)
            subset_size: Number of validators to select

        Returns:
            List of selected validators
        """
        # Get active validators
        active = [v for v in self.validators.values()
                  if v.status == ValidatorStatus.ACTIVE
                  and v.reputation_score >= self.min_reputation]

        if len(active) < subset_size:
            raise ValueError(f"Insufficient active validators: {len(active)} < {subset_size}")

        # Generate VRF output for unpredictable selection
        # In production: Use actual VRF with coordinator's key
        vrf_output = hashlib.sha256(vrf_seed + request.request_id).digest()

        # Convert VRF output to selection indices
        selected_indices = self._vrf_to_indices(vrf_output, len(active), subset_size)

        # Ensure diversity (geographic, operator, ASN)
        selected = [active[i] for i in selected_indices]
        selected = self._enforce_diversity(selected, subset_size)

        return selected

    def _vrf_to_indices(
        self,
        vrf_output: bytes,
        pool_size: int,
        count: int
    ) -> List[int]:
        """
        Convert VRF output to selection indices.

        Uses Fisher-Yates shuffle seeded with VRF output.

        Args:
            vrf_output: VRF pseudorandom output
            pool_size: Size of validator pool
            count: Number of validators to select

        Returns:
            List of selected indices
        """
        # Seed RNG with VRF output (deterministic)
        rng = random.Random(int.from_bytes(vrf_output, 'big'))

        # Generate shuffled indices
        indices = list(range(pool_size))
        rng.shuffle(indices)

        return indices[:count]

    def _enforce_diversity(
        self,
        validators: List[ValidatorInfo],
        target_count: int
    ) -> List[ValidatorInfo]:
        """
        Enforce geographic/operator diversity in validator selection.

        Args:
            validators: Initially selected validators
            target_count: Target number of validators

        Returns:
            Validators with diversity enforced
        """
        # Track used regions/operators/ASNs
        used_regions: Set[str] = set()
        used_operators: Set[str] = set()
        used_asns: Set[int] = set()

        diverse = []

        for validator in validators:
            # Prefer validators with unique attributes
            if (validator.geographic_region not in used_regions or
                validator.operator not in used_operators or
                validator.asn not in used_asns):

                diverse.append(validator)
                used_regions.add(validator.geographic_region)
                used_operators.add(validator.operator)
                used_asns.add(validator.asn)

                if len(diverse) >= target_count:
                    break

        # If not enough diverse validators, add remaining
        if len(diverse) < target_count:
            for validator in validators:
                if validator not in diverse:
                    diverse.append(validator)
                    if len(diverse) >= target_count:
                        break

        return diverse

    def calculate_quorum(self, total_validators: int) -> int:
        """
        Calculate quorum size (>50% of pool or >50% of subset).

        Args:
            total_validators: Total number of validators in pool/subset

        Returns:
            Number of validators required for quorum
        """
        return (total_validators // 2) + 1

    def aggregate_votes(
        self,
        request: ValidationRequest,
        votes: List[ValidationVote]
    ) -> Optional[ThresholdProof]:
        """
        Aggregate validator votes into threshold proof.

        Args:
            request: Original validation request
            votes: Individual validator votes

        Returns:
            Threshold proof if quorum reached, None otherwise
        """
        required = self.calculate_quorum(request.required_validators)

        if len(votes) < required:
            return None

        # Count yes/no votes
        yes_votes = sum(1 for v in votes if v.vote)
        no_votes = len(votes) - yes_votes

        # Quorum decision
        aggregate_vote = yes_votes >= required

        # In production: Use BLS signature aggregation
        # For now, concatenate signatures (not secure - just placeholder)
        aggregate_signature = b''.join(v.signature for v in votes)

        # Compute new Merkle root (would append validation event to log)
        new_merkle_root = hashlib.sha256(
            request.merkle_log_root + request.attestation_hash
        ).digest()

        proof = ThresholdProof(
            request_id=request.request_id,
            participating_validators=[v.validator_id for v in votes],
            aggregate_vote=aggregate_vote,
            aggregate_signature=aggregate_signature,
            merkle_root=new_merkle_root
        )

        return proof

    def slash_validator(self, validator_id: str, reason: str, penalty: int):
        """
        Slash validator for misbehavior.

        Args:
            validator_id: Validator to slash
            reason: Reason for slashing
            penalty: Stake penalty amount
        """
        if validator_id not in self.validators:
            return

        validator = self.validators[validator_id]

        # Reduce stake
        validator.stake_amount = max(0, validator.stake_amount - penalty)

        # Reduce reputation
        validator.reputation_score = max(0.0, validator.reputation_score - 0.1)

        # Suspend if stake too low
        if validator.stake_amount < self.min_stake:
            validator.status = ValidatorStatus.SUSPENDED

        print(f"⚠ Validator {validator_id} slashed: {reason} (penalty: {penalty})")


# Random import for VRF implementation
import random


# Example usage
if __name__ == '__main__':
    print("=== Validator Network Test ===\n")

    network = ValidatorNetwork(min_stake=1000)

    # Register validators with diversity
    validators_data = [
        ("validator-001", "us-east-1", "Acme Corp", 7922),
        ("validator-002", "eu-west-1", "Beta Inc", 3356),
        ("validator-003", "ap-southeast-1", "Gamma LLC", 4134),
        ("validator-004", "us-west-2", "Delta Corp", 174),
        ("validator-005", "eu-central-1", "Epsilon GmbH", 3320),
    ]

    print("1. Registering validators...")
    for vid, region, operator, asn in validators_data:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()

        validator = ValidatorInfo(
            validator_id=vid,
            ed25519_public_key=pub.public_bytes_raw(),
            bls_public_key=secrets.token_bytes(48),
            geographic_region=region,
            operator=operator,
            asn=asn,
            stake_amount=1500,
            reputation_score=0.9,
            status=ValidatorStatus.PENDING,
            last_seen=0,
            successful_validations=0,
            failed_validations=0,
            hsm_protected=True
        )

        if network.register_validator(validator):
            network.activate_validator(vid)
            print(f"   ✓ {vid} registered ({region}, {operator})")

    # Create validation request
    print("\n2. Creating validation request...")
    request = ValidationRequest(
        request_id=secrets.token_bytes(16),
        device_id="edge-001",
        attestation_hash=hashlib.sha256(b"attestation-data").digest(),
        timestamp=1234567890,
        required_validators=3,
        merkle_log_root=hashlib.sha256(b"genesis").digest()
    )
    print(f"   Request ID: {request.request_id.hex()[:16]}...")

    # Select validator subset
    print("\n3. Selecting validator subset (VRF-based)...")
    vrf_seed = request.merkle_log_root
    selected = network.select_validator_subset(request, vrf_seed, subset_size=3)

    for validator in selected:
        print(f"   ✓ {validator.validator_id} ({validator.geographic_region}, {validator.operator})")

    # Quorum calculation
    quorum = network.calculate_quorum(len(selected))
    print(f"\n4. Quorum required: {quorum}/{len(selected)} validators")

    print("\n✓ Validator network test complete")
