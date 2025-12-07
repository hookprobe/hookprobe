"""
Hybrid KEM: X25519 + Kyber512 for Post-Quantum Resistance

Combines classical X25519 ECDH with Kyber512 KEM to provide:
- Forward secrecy (X25519)
- Post-quantum resistance (Kyber512)
- Defense-in-depth against quantum computers

Security: If either primitive is secure, the combined KEM remains secure.
"""

import os
import hashlib
from typing import Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    # Use PQClean-compatible Kyber implementation if available
    import kyber  # pqc-kyber or similar
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False
    print("WARNING: Kyber not available. Using X25519 only (classical security)")


@dataclass
class HybridKEMPublicKey:
    """Hybrid KEM public key combining X25519 and Kyber512."""
    x25519_public: bytes  # 32 bytes
    kyber512_public: bytes  # 800 bytes for Kyber512

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return self.x25519_public + self.kyber512_public

    @classmethod
    def from_bytes(cls, data: bytes) -> 'HybridKEMPublicKey':
        """Deserialize from bytes."""
        x25519_public = data[:32]
        kyber512_public = data[32:832]  # 32 + 800
        return cls(x25519_public=x25519_public, kyber512_public=kyber512_public)


@dataclass
class HybridKEMCiphertext:
    """Hybrid KEM encapsulation result."""
    x25519_ephemeral_public: bytes  # 32 bytes
    kyber512_ciphertext: bytes  # 768 bytes for Kyber512

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return self.x25519_ephemeral_public + self.kyber512_ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> 'HybridKEMCiphertext':
        """Deserialize from bytes."""
        x25519_ephemeral_public = data[:32]
        kyber512_ciphertext = data[32:800]  # 32 + 768
        return cls(
            x25519_ephemeral_public=x25519_ephemeral_public,
            kyber512_ciphertext=kyber512_ciphertext
        )


class HybridKEM:
    """
    Hybrid KEM combining X25519 and Kyber512.

    Key encapsulation:
        1. Generate ephemeral X25519 key pair
        2. Perform ECDH with recipient's X25519 public key
        3. Encapsulate random secret with Kyber512
        4. Combine shared secrets: KDF(x25519_shared || kyber_shared)

    Security properties:
        - Forward secrecy from X25519 ephemeral keys
        - Post-quantum resistance from Kyber512
        - Conservative KDF combining both secrets
    """

    def __init__(self):
        """Initialize Hybrid KEM."""
        pass

    def keygen(self) -> Tuple[bytes, HybridKEMPublicKey]:
        """
        Generate hybrid KEM key pair.

        Returns:
            (private_key_bundle, public_key)

        private_key_bundle format:
            x25519_private (32 bytes) || kyber512_private (1632 bytes)
        """
        # Generate X25519 key pair
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()

        if KYBER_AVAILABLE:
            # Generate Kyber512 key pair
            kyber_public, kyber_private = kyber.keypair512()
        else:
            # Fallback: use X25519 only
            kyber_public = b'\x00' * 800
            kyber_private = b'\x00' * 1632

        # Bundle private keys
        private_key_bundle = (
            x25519_private.private_bytes_raw() +
            kyber_private
        )

        # Create public key
        public_key = HybridKEMPublicKey(
            x25519_public=x25519_public.public_bytes_raw(),
            kyber512_public=kyber_public
        )

        return private_key_bundle, public_key

    def encapsulate(self, public_key: HybridKEMPublicKey) -> Tuple[bytes, HybridKEMCiphertext]:
        """
        Encapsulate shared secret with recipient's public key.

        Args:
            public_key: Recipient's hybrid public key

        Returns:
            (shared_secret, ciphertext)

        shared_secret: 32-byte derived key
        ciphertext: Encapsulated ciphertext to send to recipient
        """
        # X25519: Generate ephemeral key pair and perform ECDH
        x25519_ephemeral_private = x25519.X25519PrivateKey.generate()
        x25519_ephemeral_public = x25519_ephemeral_private.public_key()

        recipient_x25519_public = x25519.X25519PublicKey.from_public_bytes(
            public_key.x25519_public
        )
        x25519_shared = x25519_ephemeral_private.exchange(recipient_x25519_public)

        if KYBER_AVAILABLE:
            # Kyber512: Encapsulate random secret
            kyber_ciphertext, kyber_shared = kyber.encaps512(public_key.kyber512_public)
        else:
            # Fallback: use random secret (not PQ-secure)
            kyber_ciphertext = b'\x00' * 768
            kyber_shared = os.urandom(32)

        # Combine shared secrets using KDF
        combined_shared = self._combine_secrets(x25519_shared, kyber_shared)

        # Create ciphertext
        ciphertext = HybridKEMCiphertext(
            x25519_ephemeral_public=x25519_ephemeral_public.public_bytes_raw(),
            kyber512_ciphertext=kyber_ciphertext
        )

        return combined_shared, ciphertext

    def decapsulate(
        self,
        private_key_bundle: bytes,
        ciphertext: HybridKEMCiphertext
    ) -> bytes:
        """
        Decapsulate shared secret using private key.

        Args:
            private_key_bundle: Bundle of private keys
            ciphertext: Received ciphertext

        Returns:
            32-byte shared secret
        """
        # Extract private keys
        x25519_private_bytes = private_key_bundle[:32]
        kyber512_private = private_key_bundle[32:1664]  # 32 + 1632

        # X25519: Perform ECDH with ephemeral public key
        x25519_private = x25519.X25519PrivateKey.from_private_bytes(x25519_private_bytes)
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            ciphertext.x25519_ephemeral_public
        )
        x25519_shared = x25519_private.exchange(ephemeral_public)

        if KYBER_AVAILABLE:
            # Kyber512: Decapsulate secret
            kyber_shared = kyber.decaps512(ciphertext.kyber512_ciphertext, kyber512_private)
        else:
            # Fallback: derive from ciphertext (not PQ-secure)
            kyber_shared = hashlib.sha256(ciphertext.kyber512_ciphertext).digest()

        # Combine shared secrets using KDF
        combined_shared = self._combine_secrets(x25519_shared, kyber_shared)

        return combined_shared

    def _combine_secrets(self, x25519_shared: bytes, kyber_shared: bytes) -> bytes:
        """
        Combine X25519 and Kyber shared secrets using HKDF.

        KDF ensures that if either primitive is broken, the combined key
        still has security from the unbroken primitive.

        Args:
            x25519_shared: 32-byte X25519 ECDH result
            kyber_shared: 32-byte Kyber shared secret

        Returns:
            32-byte combined shared secret
        """
        # Concatenate both shared secrets
        ikm = x25519_shared + kyber_shared

        # Derive combined key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"HookProbe-Neuro-v2.0-hybrid-kem"
        )

        combined = hkdf.derive(ikm)

        return combined


# Test vectors
if __name__ == '__main__':
    print("=== Hybrid KEM (X25519 + Kyber512) Test ===\n")

    kem = HybridKEM()

    # Recipient generates key pair
    print("Recipient: Generating key pair...")
    private_key, public_key = kem.keygen()
    print(f"  X25519 public: {public_key.x25519_public.hex()[:32]}...")
    print(f"  Kyber512 public: {len(public_key.kyber512_public)} bytes")
    print(f"  Private key bundle: {len(private_key)} bytes\n")

    # Sender encapsulates shared secret
    print("Sender: Encapsulating shared secret...")
    sender_shared, ciphertext = kem.encapsulate(public_key)
    print(f"  Shared secret: {sender_shared.hex()[:32]}...")
    print(f"  Ciphertext size: {len(ciphertext.to_bytes())} bytes\n")

    # Recipient decapsulates shared secret
    print("Recipient: Decapsulating shared secret...")
    recipient_shared = kem.decapsulate(private_key, ciphertext)
    print(f"  Shared secret: {recipient_shared.hex()[:32]}...\n")

    # Verify match
    if sender_shared == recipient_shared:
        print("✓ Hybrid KEM test PASSED - shared secrets match")
    else:
        print("✗ Hybrid KEM test FAILED - shared secrets don't match")

    print(f"\nKyber available: {KYBER_AVAILABLE}")
    if not KYBER_AVAILABLE:
        print("  Install: pip install pqc-kyber")
