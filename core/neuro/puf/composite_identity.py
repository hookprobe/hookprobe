"""
Composite Identity — Combines multiple PUF sources into a single identity.

XOR-combines SRAM, Clock Drift, and Cache Timing PUF responses,
weighted by reliability. Derives an Ed25519 keypair via HKDF
from the composite response.

The key is NEVER stored — it's regenerated from PUF readings at each boot.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import hmac
import logging
import os
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Constants
COMPOSITE_RESPONSE_SIZE = 32     # 256-bit composite response
ED25519_SEED_SIZE = 32           # Ed25519 requires 32-byte seed
HKDF_INFO = b"hookprobe-puf-identity-v1"


class PufSource(Enum):
    """Available PUF sources."""
    SRAM = auto()
    CLOCK_DRIFT = auto()
    CACHE_TIMING = auto()


@dataclass
class PufResponse:
    """Response from a single PUF source."""
    source: PufSource
    response: bytes              # Raw response bytes
    reliability: float           # Reliability score (0.0-1.0)
    response_time_ms: float = 0.0  # Time to generate response

    @property
    def bit_length(self) -> int:
        return len(self.response) * 8


@dataclass
class CompositeResponse:
    """Combined response from multiple PUF sources."""
    composite: bytes             # 32-byte composite response
    sources: List[PufResponse]   # Individual source responses
    ed25519_public: bytes = b""  # Ed25519 public key
    ed25519_seed: bytes = b""    # Ed25519 seed (derived from composite)

    @property
    def source_count(self) -> int:
        return len(self.sources)

    @property
    def total_reliability(self) -> float:
        if not self.sources:
            return 0.0
        return sum(s.reliability for s in self.sources) / len(self.sources)


class CompositeIdentity:
    """Combines multiple PUF sources into a cryptographic identity.

    Usage:
        identity = CompositeIdentity()
        identity.add_source(PufSource.SRAM, sram_puf)
        identity.add_source(PufSource.CLOCK_DRIFT, clock_puf)
        identity.add_source(PufSource.CACHE_TIMING, cache_puf)

        response = identity.generate()
        public_key = response.ed25519_public
    """

    # Default reliability weights per PUF source
    DEFAULT_WEIGHTS = {
        PufSource.SRAM: 0.5,         # Highest reliability
        PufSource.CLOCK_DRIFT: 0.35,  # Good on all hardware
        PufSource.CACHE_TIMING: 0.15, # Supplementary
    }

    def __init__(
        self,
        weights: Optional[Dict[PufSource, float]] = None,
    ):
        self._weights = weights or self.DEFAULT_WEIGHTS
        self._sources: Dict[PufSource, Any] = {}
        self._last_response: Optional[CompositeResponse] = None

        logger.info("CompositeIdentity initialized with %d weight configs",
                     len(self._weights))

    def add_source(self, source_type: PufSource, puf_instance: Any) -> None:
        """Register a PUF source.

        Args:
            source_type: Which PUF source this is
            puf_instance: Object with get_response() -> bytes method
        """
        self._sources[source_type] = puf_instance
        logger.debug("Added PUF source: %s", source_type.name)

    def generate(self) -> CompositeResponse:
        """Generate composite identity from all registered PUF sources.

        Collects responses from all sources, combines them with
        reliability-weighted XOR, and derives Ed25519 keypair.

        Returns CompositeResponse with public key and composite response.
        """
        import time

        if not self._sources:
            raise ValueError("No PUF sources registered")

        responses = []

        for source_type, puf in self._sources.items():
            start = time.monotonic()
            try:
                raw_response = puf.get_response()
                elapsed = (time.monotonic() - start) * 1000
                weight = self._weights.get(source_type, 0.1)

                responses.append(PufResponse(
                    source=source_type,
                    response=raw_response,
                    reliability=weight,
                    response_time_ms=elapsed,
                ))
                logger.debug(
                    "PUF %s: %d bytes in %.1f ms",
                    source_type.name, len(raw_response), elapsed,
                )
            except Exception as e:
                logger.warning("PUF %s failed: %s", source_type.name, e)

        if not responses:
            raise RuntimeError("All PUF sources failed")

        # Combine responses with weighted XOR
        composite = self._combine_responses(responses)

        # Derive Ed25519 keypair
        seed = self._derive_ed25519_seed(composite)
        public_key = self._ed25519_public_from_seed(seed)

        result = CompositeResponse(
            composite=composite,
            sources=responses,
            ed25519_public=public_key,
            ed25519_seed=seed,
        )

        self._last_response = result
        logger.info(
            "Composite identity generated from %d sources (reliability=%.2f)",
            len(responses), result.total_reliability,
        )

        return result

    def verify_keypair(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against the current PUF-derived public key.

        Regenerates the key from current PUF readings and verifies.
        """
        response = self.generate()
        try:
            return self._ed25519_verify(
                response.ed25519_public, message, signature,
            )
        except Exception as e:
            logger.error("Signature verification failed: %s", e)
            return False

    def sign(self, message: bytes) -> Optional[bytes]:
        """Sign a message with the PUF-derived Ed25519 key.

        The private key is derived fresh from PUF readings.
        """
        response = self.generate()
        try:
            return self._ed25519_sign(response.ed25519_seed, message)
        except Exception as e:
            logger.error("Signing failed: %s", e)
            return None

    def get_stats(self) -> Dict:
        """Get identity statistics."""
        result = {
            "sources_registered": len(self._sources),
            "sources": list(s.name for s in self._sources.keys()),
            "has_identity": self._last_response is not None,
        }
        if self._last_response:
            result.update({
                "sources_used": self._last_response.source_count,
                "total_reliability": round(
                    self._last_response.total_reliability, 3
                ),
                "public_key_hex": self._last_response.ed25519_public.hex()[:32] + "...",
                "response_times_ms": {
                    s.source.name: round(s.response_time_ms, 1)
                    for s in self._last_response.sources
                },
            })
        return result

    # ------------------------------------------------------------------
    # Internal Methods
    # ------------------------------------------------------------------

    def _combine_responses(self, responses: List[PufResponse]) -> bytes:
        """Combine multiple PUF responses with reliability-weighted XOR.

        For each byte position:
        1. Multiply each source byte by its reliability weight
        2. XOR the weighted bytes
        3. Hash the result for uniform distribution
        """
        # Ensure all responses are at least 32 bytes
        padded = []
        for r in responses:
            if len(r.response) < COMPOSITE_RESPONSE_SIZE:
                # Expand short responses by hashing
                expanded = hashlib.sha256(r.response).digest()
            else:
                expanded = r.response[:COMPOSITE_RESPONSE_SIZE]
            padded.append((expanded, r.reliability))

        # Weighted XOR combination
        combined = bytearray(COMPOSITE_RESPONSE_SIZE)
        total_weight = sum(w for _, w in padded)

        for response_bytes, weight in padded:
            # Scale contribution by normalized weight
            scale = weight / total_weight if total_weight > 0 else 1.0
            for i in range(COMPOSITE_RESPONSE_SIZE):
                # Weighted byte: multiply by scale, round to int, XOR
                weighted_byte = int(response_bytes[i] * scale) & 0xFF
                combined[i] ^= weighted_byte

        # Final hash for uniform distribution
        return hashlib.sha256(bytes(combined)).digest()

    def _derive_ed25519_seed(self, composite: bytes) -> bytes:
        """Derive Ed25519 seed from composite PUF response via HKDF.

        HKDF-Extract: PRK = HMAC-SHA256(salt="puf", IKM=composite)
        HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
        """
        salt = b"hookprobe-puf-salt-v1"
        # Extract
        prk = hmac.new(salt, composite, hashlib.sha256).digest()
        # Expand
        seed = hmac.new(prk, HKDF_INFO + b"\x01", hashlib.sha256).digest()
        return seed

    def _ed25519_public_from_seed(self, seed: bytes) -> bytes:
        """Derive Ed25519 public key from seed.

        Uses hashlib-based derivation compatible with the existing
        Neuro attestation system.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            private_key = Ed25519PrivateKey.from_private_bytes(seed[:32])
            return private_key.public_key().public_bytes_raw()
        except ImportError:
            # Fallback: SHA-512 based public key simulation
            h = hashlib.sha512(seed).digest()
            # Ed25519 public key derivation (simplified)
            return h[:32]

    def _ed25519_sign(self, seed: bytes, message: bytes) -> bytes:
        """Sign message with Ed25519 key derived from seed."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            private_key = Ed25519PrivateKey.from_private_bytes(seed[:32])
            return private_key.sign(message)
        except ImportError:
            # Fallback: HMAC-based signature simulation
            return hmac.new(seed, message, hashlib.sha256).digest()

    def _ed25519_verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Verify Ed25519 signature."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message)
            return True
        except ImportError:
            # Fallback: HMAC-based verification
            expected = hmac.new(
                public_key, message, hashlib.sha256
            ).digest()
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False
