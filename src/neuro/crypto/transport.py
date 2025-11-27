"""
E2EE Transport Layer - Neuro-Z Secure Communication

ChaCha20-Poly1305 AEAD with keys derived from neural weights via HKDF.
Provides forward secrecy via Curve25519 key exchange.
"""

import os
import hashlib
import struct
from typing import Tuple, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ..neural.engine import WeightState


@dataclass
class NeuroZSession:
    """Active Neuro-Z communication session."""
    session_id: bytes  # 16 bytes
    node_id: str
    peer_id: str
    transport_key: bytes  # 32 bytes (ChaCha20-Poly1305)
    created_timestamp: int
    last_activity_timestamp: int


class NeuroZTransport:
    """
    E2EE transport layer using ChaCha20-Poly1305.

    Key derivation:
      1. Weight fingerprint: SHA512(W_current) → 64 bytes
      2. Curve25519 ECDH: shared_secret → 32 bytes
      3. HKDF: K_transport = HKDF(shared_secret || W_fingerprint)

    This combines:
      - Forward secrecy (Curve25519 ephemeral keys)
      - Weight-based authentication (W_fingerprint)
    """

    def __init__(self, node_id: str, weight_state: WeightState):
        """
        Args:
            node_id: Local node identifier
            weight_state: Current neural network weights
        """
        self.node_id = node_id
        self.weight_state = weight_state

        # Generate ephemeral Curve25519 key pair
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.active_sessions = {}

    def initiate_handshake(self, peer_id: str) -> bytes:
        """
        Initiate handshake with peer.

        Returns:
            CLIENT_HELLO message
        """
        # Generate nonce
        nonce_edge = os.urandom(16)

        # Get weight fingerprint
        w_fingerprint = self.weight_state.fingerprint()

        # Build CLIENT_HELLO
        message = struct.pack(
            '<32s16s64s32s',
            self.node_id.encode('utf-8')[:32],  # Node ID
            nonce_edge,                          # Nonce
            w_fingerprint,                       # Weight fingerprint
            self.public_key.public_bytes_raw()   # Curve25519 public key
        )

        return message

    def handle_server_hello(
        self,
        server_hello: bytes,
        peer_id: str
    ) -> Tuple[bytes, NeuroZSession]:
        """
        Handle SERVER_HELLO and establish session.

        Args:
            server_hello: SERVER_HELLO message from peer
            peer_id: Peer node identifier

        Returns:
            (KEY_CONFIRM message, session)
        """
        # Parse SERVER_HELLO
        peer_node_id = server_hello[:32].decode('utf-8').rstrip('\x00')
        nonce_cloud = server_hello[32:48]
        w_fingerprint_cloud = server_hello[48:112]
        peer_public_key_bytes = server_hello[112:144]

        # Reconstruct peer public key
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)

        # Perform ECDH
        shared_secret = self.private_key.exchange(peer_public_key)

        # Derive transport key
        transport_key = self._derive_transport_key(
            shared_secret=shared_secret,
            w_fingerprint_local=self.weight_state.fingerprint(),
            w_fingerprint_peer=w_fingerprint_cloud,
            session_id=nonce_cloud  # Use cloud nonce as session ID
        )

        # Create session
        import time
        session = NeuroZSession(
            session_id=nonce_cloud,
            node_id=self.node_id,
            peer_id=peer_id,
            transport_key=transport_key,
            created_timestamp=int(time.time() * 1e6),
            last_activity_timestamp=int(time.time() * 1e6)
        )

        self.active_sessions[nonce_cloud] = session

        # Build KEY_CONFIRM (prove we derived correct key)
        confirm_message = self._build_key_confirm(session, nonce_cloud)

        return confirm_message, session

    def encrypt_message(self, session_id: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt message with ChaCha20-Poly1305.

        Args:
            session_id: Active session identifier
            plaintext: Message to encrypt

        Returns:
            nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        session = self.active_sessions.get(session_id)
        if session is None:
            raise ValueError("Invalid session ID")

        # Generate nonce (12 bytes for ChaCha20-Poly1305)
        nonce = os.urandom(12)

        # Encrypt with AEAD
        cipher = ChaCha20Poly1305(session.transport_key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

        # Update session activity
        import time
        session.last_activity_timestamp = int(time.time() * 1e6)

        return nonce + ciphertext

    def decrypt_message(self, session_id: bytes, encrypted_message: bytes) -> bytes:
        """
        Decrypt message with ChaCha20-Poly1305.

        Args:
            session_id: Active session identifier
            encrypted_message: nonce + ciphertext + tag

        Returns:
            Plaintext message
        """
        session = self.active_sessions.get(session_id)
        if session is None:
            raise ValueError("Invalid session ID")

        # Extract nonce and ciphertext
        nonce = encrypted_message[:12]
        ciphertext = encrypted_message[12:]

        # Decrypt with AEAD
        cipher = ChaCha20Poly1305(session.transport_key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)

        # Update session activity
        import time
        session.last_activity_timestamp = int(time.time() * 1e6)

        return plaintext

    def _derive_transport_key(
        self,
        shared_secret: bytes,
        w_fingerprint_local: bytes,
        w_fingerprint_peer: bytes,
        session_id: bytes
    ) -> bytes:
        """
        Derive transport key using HKDF.

        K_transport = HKDF-SHA256(
            IKM = shared_secret || W_local || W_peer,
            salt = session_id,
            info = "HookProbe-Neuro-Z-v1.0-transport"
        )

        Args:
            shared_secret: Curve25519 ECDH result (32 bytes)
            w_fingerprint_local: Local weight fingerprint (64 bytes)
            w_fingerprint_peer: Peer weight fingerprint (64 bytes)
            session_id: Session identifier (16 bytes)

        Returns:
            32-byte transport key
        """
        # Combine inputs
        ikm = shared_secret + w_fingerprint_local + w_fingerprint_peer

        # HKDF derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id,
            info=b"HookProbe-Neuro-Z-v1.0-transport"
        )

        transport_key = hkdf.derive(ikm)

        return transport_key

    def _build_key_confirm(self, session: NeuroZSession, nonce: bytes) -> bytes:
        """
        Build KEY_CONFIRM message to prove correct key derivation.

        Includes HMAC of session parameters using transport key.
        """
        # Build message to sign
        message = session.node_id.encode('utf-8')[:32] + nonce

        # HMAC with transport key
        import hmac
        mac = hmac.new(session.transport_key, message, hashlib.sha256).digest()

        # Build KEY_CONFIRM
        confirm = struct.pack(
            '<32s16s32s',
            session.node_id.encode('utf-8')[:32],
            nonce,
            mac
        )

        return confirm


class NeuroZServer:
    """
    Cloud validator side of Neuro-Z protocol.
    """

    def __init__(self, validator_id: str, weight_state: WeightState):
        """
        Args:
            validator_id: Validator node identifier
            weight_state: Expected edge weight state (from simulation)
        """
        self.validator_id = validator_id
        self.weight_state = weight_state

        # Generate ephemeral Curve25519 key pair
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.active_sessions = {}

    def handle_client_hello(self, client_hello: bytes) -> bytes:
        """
        Handle CLIENT_HELLO and respond with SERVER_HELLO.

        Args:
            client_hello: CLIENT_HELLO message from edge

        Returns:
            SERVER_HELLO message
        """
        # Parse CLIENT_HELLO
        edge_node_id = client_hello[:32].decode('utf-8').rstrip('\x00')
        nonce_edge = client_hello[32:48]
        w_fingerprint_edge = client_hello[48:112]
        edge_public_key_bytes = client_hello[112:144]

        # Verify edge weight fingerprint matches expected
        expected_fingerprint = self.weight_state.fingerprint()
        if w_fingerprint_edge != expected_fingerprint:
            raise ValueError("Edge weight fingerprint mismatch - possible compromise")

        # Generate cloud nonce (session ID)
        nonce_cloud = os.urandom(16)

        # Build SERVER_HELLO
        message = struct.pack(
            '<32s16s64s32s',
            self.validator_id.encode('utf-8')[:32],
            nonce_cloud,
            self.weight_state.fingerprint(),
            self.public_key.public_bytes_raw()
        )

        return message

    def finalize_session(
        self,
        key_confirm: bytes,
        edge_public_key_bytes: bytes,
        nonce_cloud: bytes
    ) -> NeuroZSession:
        """
        Verify KEY_CONFIRM and finalize session.

        Args:
            key_confirm: KEY_CONFIRM message from edge
            edge_public_key_bytes: Edge Curve25519 public key
            nonce_cloud: Cloud nonce (session ID)

        Returns:
            Established session
        """
        # Reconstruct edge public key
        edge_public_key = x25519.X25519PublicKey.from_public_bytes(edge_public_key_bytes)

        # Perform ECDH
        shared_secret = self.private_key.exchange(edge_public_key)

        # Derive transport key (same as edge)
        transport = NeuroZTransport(self.validator_id, self.weight_state)
        transport_key = transport._derive_transport_key(
            shared_secret=shared_secret,
            w_fingerprint_local=self.weight_state.fingerprint(),
            w_fingerprint_peer=self.weight_state.fingerprint(),  # Edge should match
            session_id=nonce_cloud
        )

        # Verify KEY_CONFIRM HMAC
        edge_node_id = key_confirm[:32].decode('utf-8').rstrip('\x00')
        nonce_received = key_confirm[32:48]
        mac_received = key_confirm[48:80]

        # Recompute expected MAC
        import hmac
        message = edge_node_id.encode('utf-8')[:32] + nonce_received
        mac_expected = hmac.new(transport_key, message, hashlib.sha256).digest()

        if mac_received != mac_expected:
            raise ValueError("KEY_CONFIRM verification failed - invalid MAC")

        # Create session
        import time
        session = NeuroZSession(
            session_id=nonce_cloud,
            node_id=self.validator_id,
            peer_id=edge_node_id,
            transport_key=transport_key,
            created_timestamp=int(time.time() * 1e6),
            last_activity_timestamp=int(time.time() * 1e6)
        )

        self.active_sessions[nonce_cloud] = session

        return session


# Example usage
if __name__ == '__main__':
    from ..neural.engine import create_initial_weights

    print("=== Testing Neuro-Z E2EE Transport ===\n")

    # Shared initial weights (provisioned during setup)
    W0 = create_initial_weights(seed=42)
    print(f"Shared weight fingerprint: {W0.fingerprint().hex()[:32]}...\n")

    # Edge: Initialize transport
    edge_transport = NeuroZTransport(node_id='edge-001', weight_state=W0)

    # Edge: Initiate handshake
    print("Edge: Initiating handshake...")
    client_hello = edge_transport.initiate_handshake(peer_id='validator-001')
    print(f"  CLIENT_HELLO: {len(client_hello)} bytes")

    # Cloud: Initialize server
    cloud_server = NeuroZServer(validator_id='validator-001', weight_state=W0)

    # Cloud: Handle CLIENT_HELLO
    print("\nCloud: Handling CLIENT_HELLO...")
    server_hello = cloud_server.handle_client_hello(client_hello)
    print(f"  SERVER_HELLO: {len(server_hello)} bytes")

    # Edge: Handle SERVER_HELLO
    print("\nEdge: Handling SERVER_HELLO...")
    key_confirm, edge_session = edge_transport.handle_server_hello(server_hello, peer_id='validator-001')
    print(f"  KEY_CONFIRM: {len(key_confirm)} bytes")
    print(f"  Session established: {edge_session.session_id.hex()[:16]}...")

    # Cloud: Verify KEY_CONFIRM
    print("\nCloud: Verifying KEY_CONFIRM...")
    edge_pubkey = client_hello[112:144]
    session_id = server_hello[32:48]
    cloud_session = cloud_server.finalize_session(key_confirm, edge_pubkey, session_id)
    print(f"  Session verified: {cloud_session.session_id.hex()[:16]}...")

    # Test encrypted communication
    print("\n--- Testing Encrypted Communication ---")

    # Edge → Cloud
    plaintext_edge = b"Hello from Edge! This is a security event."
    encrypted = edge_transport.encrypt_message(edge_session.session_id, plaintext_edge)
    print(f"\nEdge → Cloud:")
    print(f"  Plaintext: {plaintext_edge.decode()}")
    print(f"  Encrypted: {len(encrypted)} bytes")

    # Cloud decrypt
    decrypted_at_cloud = cloud_transport = NeuroZTransport(node_id='validator-001', weight_state=W0)
    cloud_transport.active_sessions[cloud_session.session_id] = cloud_session
    decrypted = cloud_transport.decrypt_message(cloud_session.session_id, encrypted)
    print(f"  Decrypted at Cloud: {decrypted.decode()}")

    # Verify match
    if decrypted == plaintext_edge:
        print("  ✓ E2EE verification PASSED")
    else:
        print("  ✗ E2EE verification FAILED")

    # Cloud → Edge
    plaintext_cloud = b"Acknowledged. Edge authenticated."
    encrypted2 = cloud_transport.encrypt_message(cloud_session.session_id, plaintext_cloud)
    print(f"\nCloud → Edge:")
    print(f"  Plaintext: {plaintext_cloud.decode()}")
    print(f"  Encrypted: {len(encrypted2)} bytes")

    # Edge decrypt
    decrypted_at_edge = edge_transport.decrypt_message(edge_session.session_id, encrypted2)
    print(f"  Decrypted at Edge: {decrypted_at_edge.decode()}")

    if decrypted_at_edge == plaintext_cloud:
        print("  ✓ Bidirectional E2EE PASSED")
    else:
        print("  ✗ Bidirectional E2EE FAILED")

    print("\n✓ Neuro-Z E2EE transport test complete")
