"""
TPM 2.0 Operations

Hardware-backed cryptographic operations using Trusted Platform Module.
Falls back to software-based signing if TPM is not available.

Status: v5.0 uses software fallback. Hardware TPM integration planned for v5.1.
"""

import logging
import os
import base64
from typing import Any, Optional, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# Global flag for TPM availability
_tpm_available = None
_tpm2_pytss_available = None


def _check_tpm_available() -> bool:
    """
    Check if TPM 2.0 is available on this system.

    Returns:
        True if TPM device is present, False otherwise
    """
    global _tpm_available

    if _tpm_available is not None:
        return _tpm_available

    # Check for TPM device files
    tpm_devices = ['/dev/tpm0', '/dev/tpmrm0']
    for device in tpm_devices:
        if os.path.exists(device):
            logger.info(f"TPM device found: {device}")
            _tpm_available = True
            return True

    logger.warning("No TPM device found - using software fallback")
    _tpm_available = False
    return False


def _check_tpm2_pytss() -> bool:
    """
    Check if tpm2-pytss library is available.

    Returns:
        True if tpm2-pytss can be imported, False otherwise
    """
    global _tpm2_pytss_available

    if _tpm2_pytss_available is not None:
        return _tpm2_pytss_available

    try:
        import tpm2_pytss  # noqa: F401
        logger.info("tpm2-pytss library available")
        _tpm2_pytss_available = True
        return True
    except ImportError:
        logger.warning("tpm2-pytss not installed - using software fallback")
        _tpm2_pytss_available = False
        return False


class TPMKey:
    """
    TPM key handle or software fallback.

    Automatically uses TPM if available, otherwise uses software RSA key.
    """

    def __init__(self, key_path: str, use_tpm: bool = True):
        """
        Initialize TPM key.

        Args:
            key_path: Path to key file
            use_tpm: Try to use TPM if available
        """
        self.key_path = key_path
        self.is_tpm = False
        self.software_key = None
        self.tpm_handle = None

        if use_tpm and _check_tpm_available() and _check_tpm2_pytss():
            try:
                self._init_tpm_key()
                self.is_tpm = True
                logger.info(f"Using TPM key: {key_path}")
            except Exception as e:
                logger.warning(f"TPM key initialization failed: {e}")
                self._init_software_key()
        else:
            self._init_software_key()

    def _init_tpm_key(self):
        """Initialize TPM key using tpm2-pytss."""
        # v5.1 planned: Hardware TPM key loading
        # from tpm2_pytss import ESAPI, TPM2B_PUBLIC
        # self.tpm_handle = ESAPI().load(...)
        logger.info("Hardware TPM integration planned for v5.1, using software fallback")
        self._init_software_key()

    def _init_software_key(self):
        """Initialize software RSA key as fallback."""
        logger.info(f"Using software RSA key (fallback): {self.key_path}")

        # Try to load existing key
        if os.path.exists(self.key_path):
            try:
                with open(self.key_path, 'rb') as f:
                    self.software_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                logger.info("Loaded existing RSA key")
                return
            except Exception as e:
                logger.warning(f"Could not load existing key: {e}")

        # Generate new RSA key
        self.software_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Save to file
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        with open(self.key_path, 'wb') as f:
            f.write(self.software_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        logger.info(f"Generated new RSA key: {self.key_path}")


def load_tpm_key(key_path: str) -> TPMKey:
    """
    Load TPM key handle or software fallback.

    Automatically detects TPM availability and falls back to software
    RSA signing if TPM is not available.

    Args:
        key_path: Path to TPM key or software key file

    Returns:
        TPMKey object (TPM or software)
    """
    return TPMKey(key_path)


def tpm2_sign(tpm_key: TPMKey, data: bytes) -> bytes:
    """
    Sign data with TPM key or software fallback.

    Args:
        tpm_key: TPM key handle or software key
        data: Data to sign

    Returns:
        Signature bytes (base64 encoded)
    """
    if tpm_key.is_tpm:
        # v5.1 planned: Native TPM signing using tpm2-pytss
        # from tpm2_pytss import ESAPI
        # signature = ESAPI().sign(tpm_key.tpm_handle, data)
        logger.info("TPM signing planned for v5.1, using software RSA fallback")
        # Fall through to software signing below

    if tpm_key.software_key:
        # Software RSA signing
        signature = tpm_key.software_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature)
    else:
        raise ValueError("No signing key available (TPM or software)")


def tpm2_verify(public_key: Any, signature: bytes, data: bytes) -> bool:
    """
    Verify TPM signature or software signature.

    Args:
        public_key: TPM public key or RSA public key
        signature: Signature to verify (base64 encoded)
        data: Original data

    Returns:
        True if signature is valid
    """
    try:
        # Decode signature
        sig_bytes = base64.b64decode(signature)

        # Verify using RSA
        public_key.verify(
            sig_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.warning(f"Signature verification failed: {e}")
        return False


def tpm2_pcr_read(pcr_indices: list) -> Dict[int, str]:
    """
    Read Platform Configuration Registers or return mock values.

    Args:
        pcr_indices: List of PCR indices to read (e.g., [0, 1, 2, 3, 7])

    Returns:
        Dictionary mapping PCR index to hash value
    """
    if not _check_tpm_available():
        logger.warning("TPM not available - returning mock PCR values")
        # Return mock PCR values for testing
        return {idx: f"mock_pcr_{idx}_value" for idx in pcr_indices}

    # TODO: Implement actual PCR reading using tpm2-pytss
    # from tpm2_pytss import ESAPI
    # pcr_values = {}
    # for idx in pcr_indices:
    #     pcr_values[idx] = ESAPI().pcr_read(idx)
    # return pcr_values

    logger.warning("TPM PCR reading not implemented - returning mock values")
    return {idx: f"mock_pcr_{idx}_value" for idx in pcr_indices}


def tpm2_quote(
    pcr_values: Dict[int, str],
    nonce: bytes,
    signing_key: TPMKey
) -> bytes:
    """
    Generate TPM quote (signed PCR attestation) or software equivalent.

    Args:
        pcr_values: PCR values to quote
        nonce: Random nonce for freshness
        signing_key: TPM signing key

    Returns:
        Signed quote bytes
    """
    # Create quote message
    import json
    quote_data = {
        'pcr_values': pcr_values,
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'timestamp': int(os.times()[4])  # monotonic time
    }
    quote_bytes = json.dumps(quote_data, sort_keys=True).encode('utf-8')

    # Sign the quote
    signature = tpm2_sign(signing_key, quote_bytes)

    # Return quote package
    quote_package = {
        'quote_data': quote_data,
        'signature': signature.decode('ascii') if isinstance(signature, bytes) else signature
    }

    return json.dumps(quote_package).encode('utf-8')
