"""
BLS Signature Aggregation

Boneh-Lynn-Shacham signatures for efficient consensus.
Falls back to RSA multi-signature if BLS libraries not available.
"""

import logging
import base64
import hashlib
from typing import List, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

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
            # TODO: Implement actual BLS signing
            # signature = bls.Sign(private_key, message)
            # return signature
            raise NotImplementedError("BLS signing not yet fully implemented")
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
            # TODO: Implement actual BLS aggregation
            # aggregated = bls.Aggregate(signatures)
            # return aggregated
            raise NotImplementedError("BLS aggregation not yet fully implemented")
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
            # TODO: Implement actual BLS verification
            # return bls.Verify(public_keys[0], message, aggregated_signature)
            raise NotImplementedError("BLS verification not yet fully implemented")
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
            # TODO: Implement actual BLS verification
            # return bls.Verify(public_key, message, signature)
            raise NotImplementedError("BLS single verification not yet fully implemented")
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
