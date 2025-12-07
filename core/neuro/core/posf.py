"""
Proof-of-Sensor-Fusion (PoSF) - Neural Network Signatures

Uses neural network output as cryptographic signature instead of traditional RSA/ECDSA.
Security derives from infeasibility of forging exact fixed-point weight states.
"""

import hashlib
import os
from typing import Tuple
from ..neural.engine import NeuralEngine, WeightState
from ..neural.fixedpoint import FixedPointArray
from .ter import TER


class PoSFSigner:
    """
    Generate PoSF signatures using neural network.
    """

    def __init__(self, weight_state: WeightState):
        """
        Args:
            weight_state: Current neural network weights
        """
        self.engine = NeuralEngine(weight_state)
        self.weight_state = weight_state

    def sign(self, message_hash: bytes, nonce: bytes = None) -> bytes:
        """
        Generate PoSF signature.

        Args:
            message_hash: SHA256 hash of message to sign (32 bytes)
            nonce: Random 8-byte nonce (generated if not provided)

        Returns:
            32-byte PoSF signature from L_X_SIG_07 layer output
        """
        if nonce is None:
            nonce = os.urandom(8)

        assert len(message_hash) == 32, "Message hash must be 32 bytes (SHA256)"
        assert len(nonce) == 8, "Nonce must be 8 bytes"

        # Combine message and nonce to create 64-byte input
        input_bytes = message_hash + nonce + b'\x00' * 24

        # Convert to fixed-point input vector
        input_vector = self._bytes_to_input_vector(input_bytes)

        # Forward pass through neural network
        signature_fp = self.engine.forward(input_vector, output_layer='L_X_SIG_07')

        # Convert fixed-point output to bytes (32 bytes)
        signature_bytes = self._fp_array_to_bytes(signature_fp)

        return signature_bytes

    def sign_ter(self, ter: TER, nonce: bytes = None) -> Tuple[bytes, bytes]:
        """
        Generate PoSF signature for TER.

        Args:
            ter: Temporal Event Record to sign
            nonce: Optional nonce (generated if not provided)

        Returns:
            (signature, nonce) tuple
        """
        if nonce is None:
            nonce = os.urandom(8)

        # Hash TER
        ter_hash = hashlib.sha256(ter.to_bytes()).digest()

        # Sign the hash
        signature = self.sign(ter_hash, nonce)

        return signature, nonce

    def _bytes_to_input_vector(self, data: bytes) -> FixedPointArray:
        """Convert 64 bytes to fixed-point input vector."""
        assert len(data) == 64, "Input must be 64 bytes"

        # Normalize bytes to [0, 1] range
        normalized = [b / 255.0 for b in data]

        return FixedPointArray(normalized)

    def _fp_array_to_bytes(self, fp_array: FixedPointArray) -> bytes:
        """
        Convert fixed-point array to bytes.

        Each fixed-point value is mapped to a byte: FP → [0.0, 1.0] → [0, 255]
        """
        result = bytearray()

        for i in range(len(fp_array)):
            # Get float value [0.0, 1.0] (sigmoid output)
            fp_val = fp_array[i].to_float()

            # Clamp to [0.0, 1.0] and convert to byte
            byte_val = int(max(0.0, min(1.0, fp_val)) * 255)
            result.append(byte_val)

        return bytes(result)


class PoSFVerifier:
    """
    Verify PoSF signatures using expected weight state.
    """

    def __init__(self, expected_weight_state: WeightState):
        """
        Args:
            expected_weight_state: Expected neural network weights (from simulation)
        """
        self.engine = NeuralEngine(expected_weight_state)
        self.expected_weight_state = expected_weight_state

    def verify(self, message_hash: bytes, nonce: bytes, signature: bytes) -> bool:
        """
        Verify PoSF signature.

        Args:
            message_hash: SHA256 hash of signed message (32 bytes)
            nonce: 8-byte nonce used in signing
            signature: 32-byte PoSF signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        assert len(message_hash) == 32, "Message hash must be 32 bytes"
        assert len(nonce) == 8, "Nonce must be 8 bytes"
        assert len(signature) == 32, "Signature must be 32 bytes"

        # Regenerate signature using expected weights
        signer = PoSFSigner(self.expected_weight_state)
        expected_signature = signer.sign(message_hash, nonce)

        # Bit-for-bit comparison
        return signature == expected_signature

    def verify_ter(self, ter: TER, nonce: bytes, signature: bytes) -> bool:
        """
        Verify PoSF signature for TER.

        Args:
            ter: Temporal Event Record
            nonce: 8-byte nonce used in signing
            signature: 32-byte PoSF signature

        Returns:
            True if signature is valid
        """
        ter_hash = hashlib.sha256(ter.to_bytes()).digest()
        return self.verify(ter_hash, nonce, signature)

    def verify_weight_fingerprint(self, reported_fingerprint: bytes) -> bool:
        """
        Verify weight state fingerprint matches expected state.

        Args:
            reported_fingerprint: 64-byte SHA512 fingerprint from edge

        Returns:
            True if fingerprints match
        """
        expected_fingerprint = self.expected_weight_state.fingerprint()
        return reported_fingerprint == expected_fingerprint


# Example usage
if __name__ == '__main__':
    from ..neural.engine import create_initial_weights
    from .ter import TERGenerator

    print("=== Testing PoSF Signatures ===\n")

    # Create initial weights (shared between edge and cloud)
    W0 = create_initial_weights(seed=42)
    print(f"Initial weight fingerprint: {W0.fingerprint().hex()[:32]}...")

    # Edge: Create signer
    edge_signer = PoSFSigner(W0)

    # Generate test TER
    ter_gen = TERGenerator()
    ter = ter_gen.generate()

    print(f"\nGenerated TER:")
    print(f"  Sequence: {ter.sequence}")
    print(f"  H_Entropy: {ter.h_entropy.hex()[:32]}...")

    # Edge: Sign TER
    signature, nonce = edge_signer.sign_ter(ter)
    print(f"\nPoSF Signature:")
    print(f"  Nonce: {nonce.hex()}")
    print(f"  Signature: {signature.hex()[:32]}...")

    # Cloud: Verify signature
    cloud_verifier = PoSFVerifier(W0)
    is_valid = cloud_verifier.verify_ter(ter, nonce, signature)

    if is_valid:
        print("\n✓ Signature verification PASSED")
    else:
        print("\n❌ Signature verification FAILED")

    # Test with wrong weights (tampered edge)
    print("\n--- Testing with tampered weights ---")
    W_tampered = create_initial_weights(seed=999)  # Different seed
    tampered_signer = PoSFSigner(W_tampered)
    tampered_sig, _ = tampered_signer.sign_ter(ter, nonce)

    is_valid_tampered = cloud_verifier.verify_ter(ter, nonce, tampered_sig)

    if not is_valid_tampered:
        print("✓ Correctly rejected tampered signature")
    else:
        print("❌ Failed to detect tampered signature")
