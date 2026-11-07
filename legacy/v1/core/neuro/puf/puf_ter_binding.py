"""
PUF-TER Binding — Binds PUF responses to Telemetry Event Records.

Extends the TER H_Entropy field with PUF response hash, creating
a hardware-anchored TER that cannot be forged even with full software
access. Also provides PUF-seeded weight evolution for NeuralEngine.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import hmac
import logging
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class PufEntropyContribution:
    """PUF contribution to TER H_Entropy."""
    puf_hash: bytes          # SHA-256 of PUF composite response
    binding_nonce: bytes     # Random nonce for this binding
    combined_entropy: bytes  # Final H_Entropy with PUF mixed in


class PufTerBinding:
    """Binds PUF identity to TER generation and neural weight evolution.

    Integration points:
    1. H_Entropy: XOR PUF response hash into entropy calculation
    2. Weight Seed: Use PUF response as entropy seed for weight init
    3. TER Chain: Include PUF hash in chain verification

    Usage:
        binding = PufTerBinding(composite_identity)
        enhanced_entropy = binding.enhance_entropy(original_entropy)
        weight_seed = binding.get_weight_seed()
    """

    def __init__(
        self,
        puf_response: Optional[bytes] = None,
    ):
        """
        Args:
            puf_response: 32-byte PUF composite response.
                If None, binding is inactive (passthrough mode).
        """
        self._puf_response = puf_response
        self._puf_hash: Optional[bytes] = None
        self._active = puf_response is not None

        if self._active:
            self._puf_hash = hashlib.sha256(puf_response).digest()
            logger.info("PUF-TER binding active: hash=%s...",
                       self._puf_hash[:8].hex())
        else:
            logger.info("PUF-TER binding inactive (passthrough mode)")

    @property
    def active(self) -> bool:
        """Whether PUF binding is active."""
        return self._active

    def enhance_entropy(self, original_entropy: bytes) -> bytes:
        """Enhance TER H_Entropy with PUF response.

        Combines original system-derived entropy with PUF hash:
        H_Entropy' = SHA-256(original_entropy || puf_hash)

        If PUF is inactive, returns original entropy unchanged.

        Args:
            original_entropy: Original 32-byte H_Entropy from TER

        Returns:
            Enhanced 32-byte H_Entropy
        """
        if not self._active or not self._puf_hash:
            return original_entropy

        combined = hashlib.sha256(
            original_entropy + self._puf_hash
        ).digest()

        return combined

    def get_weight_seed(self) -> Optional[bytes]:
        """Get PUF-derived seed for neural weight initialization.

        Returns 32-byte seed derived from PUF response, or None
        if PUF binding is inactive.

        This replaces the deterministic seed(42+i) in NeuralEngine.
        """
        if not self._active or not self._puf_response:
            return None

        return hmac.new(
            b"hookprobe-weight-seed-v1",
            self._puf_response,
            hashlib.sha256,
        ).digest()

    def enhance_integrity(self, original_integrity: bytes) -> bytes:
        """Enhance TER H_Integrity with PUF binding.

        Mixes PUF hash into the integrity measurement so that
        TER integrity is tied to physical hardware.

        Args:
            original_integrity: Original 20-byte H_Integrity

        Returns:
            Enhanced 20-byte H_Integrity
        """
        if not self._active or not self._puf_hash:
            return original_integrity

        # RIPEMD160 of combined integrity + PUF hash
        combined = original_integrity + self._puf_hash
        h = hashlib.new("ripemd160", combined)
        return h.digest()

    def create_binding_proof(self, ter_bytes: bytes) -> bytes:
        """Create a proof that a TER is bound to this PUF.

        The proof is HMAC(puf_response, ter_bytes) — only the
        device with the correct PUF can produce this proof.

        Args:
            ter_bytes: Serialized 64-byte TER

        Returns:
            32-byte binding proof
        """
        if not self._active or not self._puf_response:
            return b"\x00" * 32

        return hmac.new(
            self._puf_response,
            ter_bytes,
            hashlib.sha256,
        ).digest()

    def verify_binding_proof(
        self,
        ter_bytes: bytes,
        proof: bytes,
    ) -> bool:
        """Verify that a TER binding proof is correct.

        Args:
            ter_bytes: Serialized 64-byte TER
            proof: 32-byte binding proof to verify

        Returns:
            True if proof is valid
        """
        if not self._active:
            return True  # Passthrough mode accepts all

        expected = self.create_binding_proof(ter_bytes)
        return hmac.compare_digest(expected, proof)

    def get_puf_hash(self) -> Optional[bytes]:
        """Get the SHA-256 hash of the PUF response.

        This is safe to share publicly — it reveals no information
        about the PUF response itself.
        """
        return self._puf_hash

    def get_stats(self) -> Dict:
        """Get binding statistics."""
        return {
            "active": self._active,
            "puf_hash": self._puf_hash[:8].hex() + "..." if self._puf_hash else None,
            "has_response": self._puf_response is not None,
        }
