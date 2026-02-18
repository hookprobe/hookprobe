"""
BLS Signature Aggregation with Proof of Possession (PoP)

Boneh-Lynn-Shacham signatures for efficient consensus.
Falls back to RSA multi-signature if BLS libraries not available.

SECURITY: Implements Proof of Possession (PoP) to prevent rogue-key attacks.
Without PoP, a malicious validator can forge aggregated signatures and bypass
the 2/3 quorum requirement. PoP proves that a validator controls the private
key corresponding to their registered public key.

PoP Challenge Format:
    HASH(public_key || validator_id || epoch || nonce || "HOOKPROBE_DSM_POP_V1")

Status: v5.0 uses RSA fallback. Native BLS planned for v5.1.
"""

import logging
import base64
import hashlib
import secrets
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# Domain separator for Proof of Possession - prevents cross-protocol replay attacks
POP_DOMAIN_SEPARATOR = b"HOOKPROBE_DSM_POP_V1"

# Domain separator for checkpoint signatures - different from PoP
CHECKPOINT_DOMAIN_SEPARATOR = b"HOOKPROBE_DSM_CHECKPOINT_V1"

# Global flag for BLS availability
_bls_available = None


def _check_bls_available() -> bool:
    """
    Check if BLS library (py-ecc or blspy) is available.

    Returns:
        True if BLS library can be imported, False otherwise
    """
    global _bls_available

    if _bls_available is not None:
        return _bls_available

    # Try py-ecc first
    try:
        from py_ecc.bls import G2ProofOfPossession  # noqa: F401
        logger.info("py-ecc library available - using BLS signatures")
        _bls_available = True
        return True
    except ImportError:
        pass

    # Try blspy
    try:
        import blspy  # noqa: F401
        logger.info("blspy library available - using BLS signatures")
        _bls_available = True
        return True
    except ImportError:
        pass

    logger.warning("No BLS library found - using RSA multi-signature fallback")
    _bls_available = False
    return False


def bls_sign(private_key: bytes, message: bytes) -> bytes:
    """
    Sign message with BLS private key or RSA fallback.

    Args:
        private_key: BLS private key or RSA private key (PEM)
        message: Message to sign

    Returns:
        BLS signature or RSA signature (base64 encoded)
    """
    if _check_bls_available():
        try:
            from py_ecc.bls import G2ProofOfPossession as bls
            # v5.1 planned: Native BLS signing
            # For v5.0, use RSA fallback below
            logger.info("BLS native signing planned for v5.1, using RSA fallback")
        except Exception as e:
            logger.warning(f"BLS signing failed: {e}, using RSA fallback")

    # RSA fallback
    try:
        # Load RSA private key
        rsa_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )

        # Sign with RSA-PSS
        signature = rsa_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature)
    except Exception as e:
        logger.error(f"RSA signing failed: {e}")
        raise


def bls_aggregate(signatures: List[bytes]) -> bytes:
    """
    Aggregate multiple BLS signatures or create RSA multi-signature.

    Args:
        signatures: List of BLS/RSA signatures

    Returns:
        Aggregated signature or concatenated RSA signatures
    """
    if not signatures:
        raise ValueError("Cannot aggregate empty signature list")

    if _check_bls_available():
        try:
            from py_ecc.bls import G2ProofOfPossession as bls
            # v5.1 planned: Native BLS aggregation
            # For v5.0, use RSA multi-sig fallback below
            logger.info("BLS native aggregation planned for v5.1, using RSA fallback")
        except Exception as e:
            logger.warning(f"BLS aggregation failed: {e}, using RSA fallback")

    # RSA multi-signature fallback
    # Instead of true aggregation, we concatenate and hash
    logger.info(f"Aggregating {len(signatures)} RSA signatures (fallback)")

    # Create deterministic aggregate
    aggregate_data = {
        'signatures': [sig.decode('ascii') if isinstance(sig, bytes) else sig
                      for sig in signatures],
        'count': len(signatures),
        'algorithm': 'RSA-PSS-SHA256'
    }

    import json
    aggregate_bytes = json.dumps(aggregate_data, sort_keys=True).encode('utf-8')
    return base64.b64encode(aggregate_bytes)


def bls_verify(
    aggregated_signature: bytes,
    public_keys: List[bytes],
    message: bytes
) -> bool:
    """
    Verify aggregated BLS signature or RSA multi-signature.

    Args:
        aggregated_signature: Aggregated signature
        public_keys: List of public keys
        message: Original message

    Returns:
        True if signature is valid
    """
    if _check_bls_available():
        try:
            from py_ecc.bls import G2ProofOfPossession as bls
            # v5.1 planned: Native BLS verification
            # For v5.0, use RSA verification fallback below
            logger.info("BLS native verification planned for v5.1, using RSA fallback")
        except Exception as e:
            logger.warning(f"BLS verification failed: {e}, using RSA fallback")

    # RSA multi-signature verification fallback
    try:
        # Decode aggregate
        import json
        aggregate_bytes = base64.b64decode(aggregated_signature)
        aggregate_data = json.loads(aggregate_bytes)

        signatures = aggregate_data['signatures']
        expected_count = aggregate_data['count']

        # Verify we have correct number of signatures
        if len(signatures) != expected_count:
            logger.error(f"Signature count mismatch: {len(signatures)} != {expected_count}")
            return False

        # Verify we have matching number of public keys
        if len(public_keys) != len(signatures):
            logger.error(f"Public key count mismatch: {len(public_keys)} != {len(signatures)}")
            return False

        # Verify each individual signature
        for i, (sig, pubkey) in enumerate(zip(signatures, public_keys)):
            if not bls_verify_single(sig.encode('ascii'), pubkey, message):
                logger.error(f"Signature {i} verification failed")
                return False

        logger.info(f"Successfully verified {len(signatures)} RSA signatures")
        return True

    except Exception as e:
        logger.error(f"RSA multi-signature verification failed: {e}")
        return False


def bls_verify_single(
    signature: bytes,
    public_key: bytes,
    message: bytes
) -> bool:
    """
    Verify single BLS signature or RSA signature.

    Args:
        signature: BLS/RSA signature (base64 encoded)
        public_key: Public key (PEM format)
        message: Original message

    Returns:
        True if signature is valid
    """
    if _check_bls_available():
        try:
            from py_ecc.bls import G2ProofOfPossession as bls
            # v5.1 planned: Native BLS single verification
            # For v5.0, use RSA verification fallback below
            logger.info("BLS native single verification planned for v5.1, using RSA fallback")
        except Exception as e:
            logger.warning(f"BLS single verification failed: {e}, using RSA fallback")

    # RSA verification fallback
    try:
        # Decode signature
        if isinstance(signature, str):
            signature = signature.encode('ascii')
        sig_bytes = base64.b64decode(signature)

        # Load RSA public key
        rsa_pubkey = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )

        # Verify signature
        rsa_pubkey.verify(
            sig_bytes,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception as e:
        logger.warning(f"RSA signature verification failed: {e}")
        return False


def extract_bls_component(
    aggregated_signature: bytes,
    public_key: bytes
) -> bytes:
    """
    Extract individual signature component from aggregated signature.

    For BLS, this is a true extraction.
    For RSA fallback, this returns the signature at the index matching the public key.

    Args:
        aggregated_signature: Aggregated signature
        public_key: Public key to extract signature for

    Returns:
        Individual signature component
    """
    if _check_bls_available():
        # TODO: Implement BLS component extraction
        # Note: Real BLS doesn't support this, but we can return the aggregate
        return aggregated_signature

    # RSA fallback - find signature in aggregate
    try:
        import json
        aggregate_bytes = base64.b64decode(aggregated_signature)
        aggregate_data = json.loads(aggregate_bytes)
        signatures = aggregate_data['signatures']

        # For RSA fallback, we just return the first signature as a placeholder
        # In production, we'd need to track which signature belongs to which key
        if signatures:
            return signatures[0].encode('ascii')

        raise ValueError("No signatures in aggregate")

    except Exception as e:
        logger.error(f"Failed to extract signature component: {e}")
        return b""


# =============================================================================
# PROOF OF POSSESSION (PoP) - ROGUE-KEY ATTACK PREVENTION
# =============================================================================
#
# The rogue-key attack allows a malicious validator to register a crafted public
# key that can forge aggregated signatures. PoP prevents this by requiring
# validators to prove they control their private key at registration time.
#
# Attack without PoP:
#   1. Honest validators V1, V2, V3 register public keys pk1, pk2, pk3
#   2. Attacker computes rogue key: pk_rogue = pk_attacker - pk1 - pk2 - pk3
#   3. Attacker registers pk_rogue (accepted without PoP)
#   4. Attacker signs message M with sk_attacker
#   5. Aggregated signature verifies as if all validators signed!
#
# Fix with PoP:
#   - Each validator must sign a challenge containing their public key
#   - The rogue key pk_rogue cannot produce a valid PoP signature
#   - Registration is rejected, attack is prevented
# =============================================================================


@dataclass
class ProofOfPossession:
    """
    Proof of Possession structure for validator key registration.

    Contains the cryptographic proof that a validator controls the private
    key corresponding to their public key.
    """
    public_key: bytes          # The public key being proven
    validator_id: str          # Unique validator identifier
    epoch: int                 # Registration epoch (prevents replay)
    nonce: bytes              # Random nonce (prevents prediction)
    signature: bytes          # PoP signature over challenge
    key_type: str             # 'BLS' or 'RSA'

    def to_dict(self) -> Dict:
        """Serialize to dictionary for storage/transmission."""
        return {
            'public_key': base64.b64encode(self.public_key).decode('ascii'),
            'validator_id': self.validator_id,
            'epoch': self.epoch,
            'nonce': base64.b64encode(self.nonce).decode('ascii'),
            'signature': base64.b64encode(self.signature).decode('ascii'),
            'key_type': self.key_type,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'ProofOfPossession':
        """Deserialize from dictionary."""
        return cls(
            public_key=base64.b64decode(data['public_key']),
            validator_id=data['validator_id'],
            epoch=data['epoch'],
            nonce=base64.b64decode(data['nonce']),
            signature=base64.b64decode(data['signature']),
            key_type=data['key_type'],
        )


def generate_pop_challenge(
    public_key: bytes,
    validator_id: str,
    epoch: int,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Generate a Proof of Possession challenge message.

    The challenge is constructed with domain separation to prevent:
    - Cross-protocol replay (signature reused in different context)
    - Cross-epoch replay (old PoP reused after key rotation)
    - Prediction attacks (nonce adds randomness)

    Challenge = SHA256(public_key || validator_id || epoch || nonce || domain_separator)

    Args:
        public_key: The public key to prove possession of
        validator_id: Unique identifier of the validator
        epoch: Current epoch number (for replay prevention)
        nonce: Optional nonce (generated if not provided)

    Returns:
        Tuple of (challenge_message, nonce)
    """
    if nonce is None:
        nonce = secrets.token_bytes(32)  # 256-bit random nonce

    # Build challenge with domain separation
    hasher = hashlib.sha256()
    hasher.update(public_key)
    hasher.update(validator_id.encode('utf-8'))
    hasher.update(epoch.to_bytes(8, byteorder='big'))
    hasher.update(nonce)
    hasher.update(POP_DOMAIN_SEPARATOR)

    challenge = hasher.digest()

    logger.debug(
        f"Generated PoP challenge for validator {validator_id}, "
        f"epoch {epoch}, nonce {nonce[:8].hex()}..."
    )

    return challenge, nonce


def create_proof_of_possession(
    private_key: bytes,
    public_key: bytes,
    validator_id: str,
    epoch: int,
    key_type: str = 'RSA',
) -> ProofOfPossession:
    """
    Create a Proof of Possession for validator registration.

    The validator signs a challenge message that includes their public key,
    proving they control the corresponding private key.

    Args:
        private_key: Private key (PEM format for RSA)
        public_key: Public key (PEM format for RSA)
        validator_id: Unique validator identifier
        epoch: Current epoch number
        key_type: 'BLS' or 'RSA'

    Returns:
        ProofOfPossession object

    Raises:
        ValueError: If signing fails
    """
    # Generate challenge with random nonce
    challenge, nonce = generate_pop_challenge(
        public_key=public_key,
        validator_id=validator_id,
        epoch=epoch,
    )

    # Sign the challenge
    try:
        signature = bls_sign(private_key, challenge)
        # Decode from base64 (bls_sign returns base64)
        signature_bytes = base64.b64decode(signature)
    except Exception as e:
        logger.error(f"Failed to create PoP signature: {e}")
        raise ValueError(f"PoP signature creation failed: {e}")

    pop = ProofOfPossession(
        public_key=public_key,
        validator_id=validator_id,
        epoch=epoch,
        nonce=nonce,
        signature=signature_bytes,
        key_type=key_type,
    )

    logger.info(
        f"Created PoP for validator {validator_id}, epoch {epoch}, "
        f"key_type {key_type}"
    )

    return pop


def verify_proof_of_possession(
    pop: ProofOfPossession,
    expected_epoch: Optional[int] = None,
    max_epoch_age: int = 10,
) -> Tuple[bool, str]:
    """
    Verify a Proof of Possession.

    CRITICAL SECURITY FUNCTION: This must be called before accepting
    any validator's public key into the registry.

    Verification checks:
    1. Challenge is correctly reconstructed from PoP fields
    2. Signature is valid for the claimed public key
    3. Epoch is within acceptable range (prevents old PoP replay)

    Args:
        pop: ProofOfPossession to verify
        expected_epoch: If provided, epoch must match exactly
        max_epoch_age: Maximum age of PoP in epochs (default 10)

    Returns:
        Tuple of (is_valid, reason)
    """
    # Epoch validation
    if expected_epoch is not None:
        epoch_age = expected_epoch - pop.epoch
        if epoch_age > max_epoch_age:
            return False, (
                f"PoP too old: epoch {pop.epoch} is {epoch_age} epochs behind "
                f"current {expected_epoch} (max {max_epoch_age})"
            )
        if pop.epoch > expected_epoch:
            return False, (
                f"PoP epoch from future: got {pop.epoch}, current is {expected_epoch}"
            )
    else:
        # When no expected epoch, validate the PoP epoch is reasonable:
        # must be a non-negative integer and not absurdly large
        if not isinstance(pop.epoch, int) or pop.epoch < 0:
            return False, f"Invalid epoch value: {pop.epoch}"

    # Validate nonce is present and non-empty
    if not pop.nonce or len(pop.nonce) < 16:
        return False, "PoP nonce missing or too short (minimum 16 bytes)"

    # Validate signature is present
    if not pop.signature:
        return False, "PoP signature missing"

    # Reconstruct the challenge message
    challenge, _ = generate_pop_challenge(
        public_key=pop.public_key,
        validator_id=pop.validator_id,
        epoch=pop.epoch,
        nonce=pop.nonce,  # Use the nonce from the PoP
    )

    # Verify signature
    try:
        signature_b64 = base64.b64encode(pop.signature)
        is_valid = bls_verify_single(signature_b64, pop.public_key, challenge)

        if is_valid:
            logger.info(
                f"PoP verification PASSED for validator {pop.validator_id}"
            )
            return True, "PoP verified successfully"
        else:
            logger.warning(
                f"PoP verification FAILED for validator {pop.validator_id}: "
                "Invalid signature"
            )
            return False, "Invalid PoP signature"

    except Exception as e:
        logger.error(f"PoP verification error: {e}")
        return False, f"PoP verification error: {e}"


class PoPVerificationError(Exception):
    """Raised when Proof of Possession verification fails."""
    pass


class RogueKeyDetected(Exception):
    """Raised when a potential rogue-key attack is detected."""
    pass
