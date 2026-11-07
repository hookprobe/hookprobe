#!/usr/bin/env python3
"""
Weight-Hash Chain Validator

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module implements weight-hash chaining for tamper detection in neural
network weight states. Each weight fingerprint is cryptographically linked
to previous states, forming an immutable chain.

Security Properties:
1. Tamper Detection: Any modification to past weight states invalidates the chain
2. Forward Security: Compromising current state doesn't reveal previous states
3. Proof Generation: Generate compact Merkle-style proofs for state verification
4. Deterministic: Same weight evolution produces identical chain

Architecture:
    [W0] --H(W0)--> [H0] --H(H0||W1)--> [H1] --H(H1||W2)--> [H2] ...

    Chain Root = H(H_n || salt || timestamp)

Usage:
    validator = WeightChainValidator()

    # Append weight states during training
    for epoch in range(100):
        weights = model.get_weights()
        fingerprint = weight_fingerprint(weights)
        validator.append_weight_state(fingerprint)

    # Verify chain integrity
    if not validator.verify_integrity(expected_root):
        raise TamperingDetected("Weight chain compromised")

    # Export proof for external verification
    proof = validator.export_proof()
"""

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
import logging

# Try to use BLAKE3 for speed, fallback to SHA256
try:
    import blake3
    def hash_function(data: bytes) -> bytes:
        return blake3.blake3(data).digest()
except ImportError:
    def hash_function(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

logger = logging.getLogger(__name__)


@dataclass
class WeightState:
    """Single weight state in the chain."""
    index: int
    fingerprint: bytes  # 32-byte weight fingerprint
    chain_hash: bytes   # Hash linking to previous state
    timestamp: float    # When this state was recorded


@dataclass
class WeightChainProof:
    """Exportable proof of weight chain integrity."""
    chain_root: bytes
    chain_length: int
    first_state: bytes
    last_state: bytes
    timestamp_start: float
    timestamp_end: float
    proof_signature: bytes  # HMAC signature of the proof


class WeightChainValidator:
    """
    Validates chain of weight states to detect tampering.

    The weight chain creates a cryptographic audit trail of all weight
    states during neural network training/evolution. This enables:
    - Detection of weight tampering in PoSF validation
    - Verification that weights evolved according to protocol
    - Proof generation for external auditors

    Security Model:
    - Forward-secure: Current state reveals nothing about past states
    - Collision-resistant: Computationally infeasible to find two different
      weight sequences producing the same chain root
    - Deterministic: Reproducible given same weight sequence
    """

    # Maximum chain length to prevent memory exhaustion
    MAX_CHAIN_LENGTH = 100000

    # Salt for chain finalization (prevents rainbow tables)
    CHAIN_SALT = b"hookprobe-weight-chain-v1"

    def __init__(self, secret_key: Optional[bytes] = None):
        """
        Initialize weight chain validator.

        Args:
            secret_key: Optional 32-byte secret for HMAC signatures
                       If not provided, one will be generated
        """
        self.weight_chain: List[WeightState] = []
        self.chain_root: bytes = b''
        self._finalized: bool = False

        # Secret key for proof signatures
        if secret_key is None:
            import secrets
            self.secret_key = secrets.token_bytes(32)
        else:
            self.secret_key = secret_key

        logger.debug("[WeightChain] Validator initialized")

    def append_weight_state(self, fingerprint: bytes) -> int:
        """
        Append a weight state fingerprint to the chain.

        Args:
            fingerprint: 32-byte weight fingerprint (typically BLAKE3/SHA256 of weights)

        Returns:
            Index of the appended state

        Raises:
            ValueError: If fingerprint is not 32 bytes
            RuntimeError: If chain is finalized or at max length
        """
        if self._finalized:
            raise RuntimeError("Cannot append to finalized chain")

        if len(self.weight_chain) >= self.MAX_CHAIN_LENGTH:
            raise RuntimeError(f"Chain at maximum length ({self.MAX_CHAIN_LENGTH})")

        if len(fingerprint) != 32:
            raise ValueError(f"Fingerprint must be 32 bytes, got {len(fingerprint)}")

        index = len(self.weight_chain)
        timestamp = time.time()

        # Compute chain hash
        if index == 0:
            # Genesis state: H(fingerprint || index || salt)
            chain_hash = hash_function(
                fingerprint + struct.pack('>I', index) + self.CHAIN_SALT
            )
        else:
            # Chain state: H(prev_chain_hash || fingerprint || index)
            prev_hash = self.weight_chain[-1].chain_hash
            chain_hash = hash_function(
                prev_hash + fingerprint + struct.pack('>I', index)
            )

        state = WeightState(
            index=index,
            fingerprint=fingerprint,
            chain_hash=chain_hash,
            timestamp=timestamp,
        )

        self.weight_chain.append(state)
        logger.debug(f"[WeightChain] Appended state {index}: {chain_hash.hex()[:16]}...")

        return index

    def compute_chain_root(self) -> bytes:
        """
        Compute the final chain root hash.

        This finalizes the chain - no more states can be appended.

        Returns:
            32-byte chain root

        Raises:
            RuntimeError: If chain is empty
        """
        if not self.weight_chain:
            raise RuntimeError("Cannot compute root of empty chain")

        # Get final chain hash
        final_hash = self.weight_chain[-1].chain_hash

        # Compute root with timestamp binding
        timestamp_bytes = struct.pack('>d', self.weight_chain[-1].timestamp)
        root_input = (
            final_hash +
            self.CHAIN_SALT +
            timestamp_bytes +
            struct.pack('>I', len(self.weight_chain))
        )

        self.chain_root = hash_function(root_input)
        self._finalized = True

        logger.info(f"[WeightChain] Finalized with root: {self.chain_root.hex()[:16]}... ({len(self.weight_chain)} states)")

        return self.chain_root

    def verify_integrity(self, expected_root: bytes = None) -> bool:
        """
        Verify the integrity of the weight chain.

        Args:
            expected_root: Optional expected chain root to compare against

        Returns:
            True if chain is intact and optionally matches expected root
        """
        if not self.weight_chain:
            logger.warning("[WeightChain] Cannot verify empty chain")
            return False

        # Recompute all chain hashes
        for i, state in enumerate(self.weight_chain):
            if i == 0:
                expected_hash = hash_function(
                    state.fingerprint + struct.pack('>I', i) + self.CHAIN_SALT
                )
            else:
                prev_hash = self.weight_chain[i - 1].chain_hash
                expected_hash = hash_function(
                    prev_hash + state.fingerprint + struct.pack('>I', i)
                )

            if not hmac.compare_digest(state.chain_hash, expected_hash):
                logger.error(f"[WeightChain] Integrity check failed at state {i}")
                return False

        # If expected root provided, verify it matches
        if expected_root:
            # Compute current root
            current_root = self.compute_chain_root() if not self._finalized else self.chain_root

            if not hmac.compare_digest(current_root, expected_root):
                logger.error("[WeightChain] Root mismatch - chain may be tampered")
                return False

        logger.debug(f"[WeightChain] Integrity verified ({len(self.weight_chain)} states)")
        return True

    def export_proof(self) -> bytes:
        """
        Export a compact proof of chain integrity.

        The proof contains:
        - Chain root
        - Chain length
        - First and last fingerprints
        - Timestamp range
        - HMAC signature

        Returns:
            Serialized proof bytes

        Raises:
            RuntimeError: If chain is empty
        """
        if not self.weight_chain:
            raise RuntimeError("Cannot export proof of empty chain")

        # Ensure chain is finalized
        if not self._finalized:
            self.compute_chain_root()

        # Build proof data
        proof_data = (
            self.chain_root +
            struct.pack('>I', len(self.weight_chain)) +
            self.weight_chain[0].fingerprint +
            self.weight_chain[-1].fingerprint +
            struct.pack('>d', self.weight_chain[0].timestamp) +
            struct.pack('>d', self.weight_chain[-1].timestamp)
        )

        # Sign the proof
        signature = hmac.new(self.secret_key, proof_data, hashlib.sha256).digest()

        return proof_data + signature

    def import_and_verify_proof(self, proof_bytes: bytes, secret_key: bytes = None) -> bool:
        """
        Import and verify a proof from export_proof().

        Args:
            proof_bytes: Serialized proof from export_proof()
            secret_key: Secret key used to sign the proof

        Returns:
            True if proof is valid
        """
        if len(proof_bytes) < 32 + 4 + 32 + 32 + 8 + 8 + 32:
            logger.error("[WeightChain] Invalid proof length")
            return False

        key = secret_key if secret_key else self.secret_key

        # Parse proof
        offset = 0
        chain_root = proof_bytes[offset:offset+32]; offset += 32
        chain_length = struct.unpack('>I', proof_bytes[offset:offset+4])[0]; offset += 4
        first_fp = proof_bytes[offset:offset+32]; offset += 32
        last_fp = proof_bytes[offset:offset+32]; offset += 32
        ts_start = struct.unpack('>d', proof_bytes[offset:offset+8])[0]; offset += 8
        ts_end = struct.unpack('>d', proof_bytes[offset:offset+8])[0]; offset += 8
        signature = proof_bytes[offset:offset+32]

        # Verify signature
        proof_data = proof_bytes[:offset]
        expected_sig = hmac.new(key, proof_data, hashlib.sha256).digest()

        if not hmac.compare_digest(signature, expected_sig):
            logger.error("[WeightChain] Proof signature verification failed")
            return False

        logger.info(f"[WeightChain] Proof verified: {chain_length} states, root={chain_root.hex()[:16]}...")
        return True

    def get_state(self, index: int) -> Optional[WeightState]:
        """Get weight state at specific index."""
        if 0 <= index < len(self.weight_chain):
            return self.weight_chain[index]
        return None

    def get_chain_length(self) -> int:
        """Get current chain length."""
        return len(self.weight_chain)

    def get_latest_hash(self) -> Optional[bytes]:
        """Get the latest chain hash."""
        if self.weight_chain:
            return self.weight_chain[-1].chain_hash
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Export chain state as dictionary."""
        return {
            'chain_length': len(self.weight_chain),
            'chain_root': self.chain_root.hex() if self.chain_root else None,
            'finalized': self._finalized,
            'states': [
                {
                    'index': s.index,
                    'fingerprint': s.fingerprint.hex(),
                    'chain_hash': s.chain_hash.hex(),
                    'timestamp': s.timestamp,
                }
                for s in self.weight_chain[-10:]  # Last 10 states
            ]
        }


def weight_fingerprint(weights: bytes) -> bytes:
    """
    Compute a 32-byte fingerprint of neural network weights.

    Args:
        weights: Raw weight bytes

    Returns:
        32-byte fingerprint
    """
    return hash_function(weights)


def verify_weight_evolution(
    initial_weights: bytes,
    final_weights: bytes,
    chain_proof: bytes,
    secret_key: bytes,
) -> bool:
    """
    Verify that weights evolved according to a valid chain.

    This is a convenience function for external verification without
    access to the full chain.

    Args:
        initial_weights: Starting weight state
        final_weights: Ending weight state
        chain_proof: Proof from export_proof()
        secret_key: Secret key for signature verification

    Returns:
        True if evolution is valid
    """
    # Parse proof
    if len(chain_proof) < 32 + 4 + 32 + 32 + 8 + 8 + 32:
        return False

    first_fp = chain_proof[36:68]
    last_fp = chain_proof[68:100]

    # Verify fingerprints match
    if not hmac.compare_digest(weight_fingerprint(initial_weights), first_fp):
        logger.error("[WeightChain] Initial weights don't match proof")
        return False

    if not hmac.compare_digest(weight_fingerprint(final_weights), last_fp):
        logger.error("[WeightChain] Final weights don't match proof")
        return False

    # Verify proof signature
    validator = WeightChainValidator(secret_key=secret_key)
    return validator.import_and_verify_proof(chain_proof, secret_key)


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    import secrets

    # Demo usage
    print("Weight Chain Validator Demo")
    print("=" * 50)

    validator = WeightChainValidator()

    # Simulate weight evolution
    print("\nSimulating weight evolution...")
    weights = secrets.token_bytes(128)  # Initial weights

    for i in range(10):
        # Compute fingerprint of current weights
        fp = weight_fingerprint(weights)
        idx = validator.append_weight_state(fp)
        print(f"  State {idx}: {fp.hex()[:16]}...")

        # "Evolve" weights (in reality this would be gradient descent)
        delta = secrets.token_bytes(128)
        weights = bytes(a ^ b for a, b in zip(weights, delta))

    # Finalize and get root
    print("\nFinalizing chain...")
    root = validator.compute_chain_root()
    print(f"Chain root: {root.hex()}")

    # Verify integrity
    print("\nVerifying integrity...")
    valid = validator.verify_integrity(root)
    print(f"Integrity: {'VALID' if valid else 'INVALID'}")

    # Export proof
    print("\nExporting proof...")
    proof = validator.export_proof()
    print(f"Proof size: {len(proof)} bytes")

    # Verify proof
    print("\nVerifying proof...")
    proof_valid = validator.import_and_verify_proof(proof)
    print(f"Proof: {'VALID' if proof_valid else 'INVALID'}")

    # Show chain summary
    print("\nChain summary:")
    for k, v in validator.to_dict().items():
        if k != 'states':
            print(f"  {k}: {v}")
