"""
MSSP Authentication & Signature Verification

Provides Ed25519 signature verification for recommended actions.
MSSP signs all recommendations so edge nodes can verify authenticity.

Security:
    - MSSP public key is pinned in /etc/hookprobe/mssp-public.pem
    - Recommendations without valid signature are rejected
    - Prevents rogue recommendation injection into the mesh
"""

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# MSSP public key location (pinned on each node during provisioning)
MSSP_PUBLIC_KEY_PATH = Path('/etc/hookprobe/mssp-public.pem')
MSSP_HMAC_KEY_PATH = Path('/etc/hookprobe/mssp-hmac.key')

# Ed25519 support (optional, falls back to HMAC-SHA256)
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    ED25519_AVAILABLE = True
except ImportError:
    ED25519_AVAILABLE = False


def _load_mssp_public_key() -> Optional[object]:
    """Load the MSSP Ed25519 public key from disk."""
    if not ED25519_AVAILABLE:
        return None
    try:
        if MSSP_PUBLIC_KEY_PATH.exists():
            key_data = MSSP_PUBLIC_KEY_PATH.read_bytes()
            return load_pem_public_key(key_data)
    except Exception as e:
        logger.warning("Failed to load MSSP public key: %s", e)
    return None


def _load_hmac_key() -> Optional[bytes]:
    """Load HMAC-SHA256 shared secret for fallback verification."""
    try:
        if MSSP_HMAC_KEY_PATH.exists():
            return MSSP_HMAC_KEY_PATH.read_bytes().strip()
    except Exception as e:
        logger.warning("Failed to load MSSP HMAC key: %s", e)
    return None


def compute_recommendation_digest(action_dict: dict) -> bytes:
    """Compute deterministic digest of a recommendation for signing.

    Excludes the 'signature' field itself from the digest.
    """
    signable = {k: v for k, v in sorted(action_dict.items()) if k != 'signature'}
    canonical = json.dumps(signable, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).digest()


def verify_recommendation_signature(action_dict: dict) -> bool:
    """Verify that a recommended action was signed by MSSP.

    Tries Ed25519 first, falls back to HMAC-SHA256 if Ed25519 is unavailable.

    Args:
        action_dict: The recommendation as a dictionary (must include 'signature')

    Returns:
        True if signature is valid, False otherwise
    """
    signature_hex = action_dict.get('signature', '')
    if not signature_hex:
        logger.warning("Recommendation has no signature — rejecting")
        return False

    digest = compute_recommendation_digest(action_dict)

    # Try Ed25519 first
    if ED25519_AVAILABLE:
        public_key = _load_mssp_public_key()
        if public_key is not None:
            try:
                signature_bytes = bytes.fromhex(signature_hex)
                public_key.verify(signature_bytes, digest)
                return True
            except Exception as e:
                logger.warning("Ed25519 verification failed: %s", e)
                return False

    # Fallback to HMAC-SHA256
    hmac_key = _load_hmac_key()
    if hmac_key:
        expected = hmac.new(hmac_key, digest, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_hex)

    # No verification keys available — warn but allow in dev mode
    dev_mode = os.environ.get('HOOKPROBE_DEV_MODE', '').lower() in ('1', 'true', 'yes')
    if dev_mode:
        logger.warning("No MSSP verification keys — allowing in dev mode")
        return True

    logger.error("No MSSP verification keys available — rejecting recommendation")
    return False


def sign_for_testing(action_dict: dict, hmac_key: bytes) -> str:
    """Sign a recommendation with HMAC-SHA256 for testing purposes.

    NOT for production use — production uses Ed25519 from MSSP server.
    """
    digest = compute_recommendation_digest(action_dict)
    return hmac.new(hmac_key, digest, hashlib.sha256).hexdigest()
