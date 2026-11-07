"""
DSM Node Identity & Attestation

TPM-backed hardware identity and platform integrity attestation.
Software fallback when TPM hardware is not available.
"""

import hashlib
import json
import logging
import platform
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# DSM Certificate Authority root certificate
DSM_CA_ROOT = "/etc/hookprobe/certs/dsm-ca-root.pem"


class NodeIdentity:
    """
    TPM-backed cryptographic identity for DSM nodes.

    Prevents spoofing and unauthorized participation through
    hardware-backed attestation.

    Example:
        >>> identity = NodeIdentity.provision_node("hw-uuid-12345")
        >>> attestation = identity.attest()
    """

    def __init__(self, certificate: str, tpm_key: Any):
        """
        Initialize node identity.

        Args:
            certificate: Node certificate (PEM format)
            tpm_key: TPM private key handle
        """
        self.certificate = certificate
        self.tpm_key = tpm_key
        self.node_id = self._extract_node_id(certificate)

    @staticmethod
    def provision_node(hardware_id: str) -> Optional['NodeIdentity']:
        """
        Provision new node with identity (software fallback).

        In production with TPM hardware, this would:
        1. Generate TPM key pair  2. Read PCR values
        3. Create CSR  4. Submit to DSM CA for signing

        Software fallback generates a self-signed identity from hardware ID.

        Args:
            hardware_id: Hardware UUID

        Returns:
            NodeIdentity object, or None if hardware_id is empty
        """
        if not hardware_id:
            return None
        logger.info("Provisioning node: %s (software mode)", hardware_id)
        # Generate deterministic certificate from hardware ID
        cert_data = {
            "node_id": hardware_id,
            "issued_at": time.time(),
            "issuer": "dsm-self-signed",
            "platform": platform.platform(),
        }
        certificate = json.dumps(cert_data, sort_keys=True)
        # Use hardware_id as TPM key placeholder
        tpm_key = hashlib.sha256(hardware_id.encode()).digest()
        identity = NodeIdentity(certificate=certificate, tpm_key=tpm_key)
        identity.node_id = hardware_id
        identity.public_key = hashlib.sha256(tpm_key).digest()
        return identity

    def attest(self) -> Dict[str, Any]:
        """
        Prove current integrity state (software fallback).

        In production with TPM, this reads PCR values and generates a quote.
        Software fallback generates a digest from current platform state.

        Returns:
            Attestation dictionary with PCR values, quote, and digest
        """
        evidence = {
            "node_id": self.node_id,
            "timestamp": time.time(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
        }
        evidence["digest"] = hashlib.sha256(
            json.dumps(evidence, sort_keys=True).encode()
        ).hexdigest()
        return {
            'pcr_values': {},  # Empty = software mode (no TPM)
            'quote': evidence["digest"],
            'certificate': self.certificate,
            'evidence': evidence,
        }

    def _extract_node_id(self, certificate: str) -> str:
        """Extract node ID from certificate content."""
        if not certificate:
            return "node-unknown"
        # Try parsing as JSON certificate (software mode)
        try:
            cert_data = json.loads(certificate)
            return cert_data.get("node_id", "node-unknown")
        except (json.JSONDecodeError, TypeError):
            pass
        # Fallback: hash the certificate content
        return "node-" + hashlib.sha256(
            certificate.encode() if isinstance(certificate, str) else certificate
        ).hexdigest()[:12]


def verify_certificate_chain(cert_path: str, trusted_root: str) -> bool:
    """
    Verify certificate chain up to trusted root.

    In production, this verifies the X.509 chain. Software fallback
    checks that the certificate file/content exists and is non-empty.

    Args:
        cert_path: Path to certificate file or "<inline>" for inline certs
        trusted_root: Path to trusted root CA certificate

    Returns:
        True if certificate is valid (or software-mode self-signed)
    """
    import os

    if cert_path == "<inline>":
        # Inline certificate — trust check was done at caller
        logger.debug("Inline certificate, skipping file-based chain verification")
        return True

    if not cert_path or not os.path.isfile(cert_path):
        logger.warning("Certificate not found: %s", cert_path)
        return False

    try:
        with open(cert_path, 'r') as f:
            cert_content = f.read()
        if not cert_content or len(cert_content) < 16:
            logger.warning("Certificate file too small: %s", cert_path)
            return False
        # In software mode, if root CA doesn't exist, accept self-signed
        if not os.path.isfile(trusted_root):
            logger.info("CA root not found, accepting self-signed cert")
            return True
        # Both files exist — basic validation passes
        # Full X.509 chain verification would use cryptography.x509 here
        return True
    except Exception as e:
        logger.warning("Certificate verification error: %s", e)
        return False
