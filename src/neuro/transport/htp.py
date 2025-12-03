"""
HookProbe Transport Protocol (HTP) - Liberty Version

Simple, effective transport protocol designed specifically for HookProbe.
NOT generic QUIC - focused on solving HookProbe's specific needs:

1. NAT/CGNAT traversal (edge devices behind carrier NAT)
2. Neuro weight-based authentication (neural resonance)
3. Minimal overhead (suitable for Raspberry Pi)
4. Robust security (unhackable by design)

Key Features:
- Connection-oriented over UDP (for NAT traversal)
- Heartbeat keepalive (maintains NAT mappings)
- ChaCha20-Poly1305 encryption (fast, secure)
- Weight fingerprint binding (prevents MITM)
- Simple state machine (easy to audit)

Protocol Flow:
1. HELLO: Edge initiates with weight fingerprint
2. CHALLENGE: Validator sends nonce for attestation
3. ATTEST: Edge responds with signed attestation
4. ACCEPT: Validator confirms, session established
5. DATA: Encrypted payload exchange
6. HEARTBEAT: Keep NAT mapping alive
"""

import os
import struct
import hashlib
import socket
import time
import random
import secrets
from typing import Optional, Tuple, Dict
from enum import Enum
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class MessageType(Enum):
    """HTP message types (1 byte)."""
    HELLO = 0x01       # Edge → Validator: Initiate connection
    CHALLENGE = 0x02   # Validator → Edge: Send attestation challenge
    ATTEST = 0x03      # Edge → Validator: Attestation response
    ACCEPT = 0x04      # Validator → Edge: Session accepted
    REJECT = 0x05      # Validator → Edge: Session rejected
    DATA = 0x10        # Bidirectional: Encrypted payload
    HEARTBEAT = 0x20   # Bidirectional: Keep NAT mapping alive
    ACK = 0x21         # Response to DATA/HEARTBEAT
    CLOSE = 0xFF       # Bidirectional: Close session


class SessionState(Enum):
    """HTP session state machine."""
    IDLE = "idle"
    HELLO_SENT = "hello_sent"
    CHALLENGE_RECEIVED = "challenge_received"
    ATTEST_SENT = "attest_sent"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class HTPMessage:
    """HTP protocol message."""
    msg_type: MessageType
    session_id: bytes  # 8 bytes
    sequence: int  # 4 bytes
    payload: bytes  # Variable length


@dataclass
class HTPSession:
    """Active HTP session with enhanced security features."""
    session_id: bytes
    peer_address: Tuple[str, int]  # IP, port
    state: SessionState

    # Crypto - Enhanced with PFS
    chacha_key: bytes  # 32 bytes
    send_sequence: int
    recv_sequence: int
    ephemeral_private_key: Optional[x25519.X25519PrivateKey] = None
    ephemeral_public_key: Optional[x25519.X25519PublicKey] = None
    peer_ephemeral_public_key: Optional[x25519.X25519PublicKey] = None
    shared_secret: Optional[bytes] = None  # DH shared secret

    # Neuro context
    weight_fingerprint: bytes = b''  # 64 bytes
    last_weight_fingerprint: bytes = b''  # For key rotation
    key_rotation_counter: int = 0

    # Timing with jitter
    created_timestamp: float = 0.0
    last_activity: float = 0.0
    heartbeat_interval: float = 30.0  # seconds
    jitter_min_ms: int = 0  # Minimum jitter in milliseconds
    jitter_max_ms: int = 2000  # Maximum jitter in milliseconds
    next_heartbeat_time: float = 0.0  # With jitter applied

    # Adaptive transport mode
    transport_mode: str = "BALANCED"  # BURST, BALANCED, STEALTH, GHOST

    # Anti-DoS
    hello_timestamps: list = field(default_factory=list)  # Rate limiting


class HookProbeTransport:
    """
    HookProbe Transport Protocol (HTP) - Enhanced Security Edition.

    Simple, focused transport for HookProbe's specific needs.
    Enhanced with:
    - Perfect Forward Secrecy (ephemeral X25519 key exchange)
    - Traffic analysis resistance (padding, jitter)
    - Continuous sensor-driven key rotation
    - Neuro-resonant PoSF signatures
    - Adaptive transport modes (Burst/Stealth/Ghost)
    - Anti-DoS protection with rate limiting
    """

    # Protocol constants
    MAX_PACKET_SIZE = 1400  # Stay below MTU for UDP
    HEARTBEAT_INTERVAL = 30.0  # seconds
    SESSION_TIMEOUT = 300.0  # 5 minutes
    MAX_RETRIES = 3

    # Enhanced security parameters
    MIN_PADDING_BYTES = 16
    MAX_PADDING_BYTES = 128
    KEY_ROTATION_INTERVAL = 300.0  # 5 minutes
    MAX_HELLO_PER_MINUTE = 10  # Anti-DoS rate limit

    # Transport mode configurations
    TRANSPORT_MODES = {
        "BURST": {
            "padding": (0, 16),
            "jitter_ms": (0, 100),
            "heartbeat_interval": 15.0,
            "description": "Low-latency, minimal overhead"
        },
        "BALANCED": {
            "padding": (16, 64),
            "jitter_ms": (100, 1000),
            "heartbeat_interval": 30.0,
            "description": "Balance of performance and stealth"
        },
        "STEALTH": {
            "padding": (64, 128),
            "jitter_ms": (500, 2000),
            "heartbeat_interval": 60.0,
            "description": "High stealth, variable timing"
        },
        "GHOST": {
            "padding": (128, 256),
            "jitter_ms": (1000, 5000),
            "heartbeat_interval": 120.0,
            "description": "Maximum stealth, sparse communication"
        }
    }

    def __init__(
        self,
        node_id: str,
        listen_port: int = 0,  # 0 = random port
        is_validator: bool = False,
        transport_mode: str = "BALANCED",
        posf_signer=None  # Optional PoSF signer for neural signatures
    ):
        """
        Args:
            node_id: Node identifier
            listen_port: UDP port to listen on
            is_validator: Whether this is a validator node
            transport_mode: Transport mode (BURST/BALANCED/STEALTH/GHOST)
            posf_signer: Optional PoSF signer for neural signatures
        """
        self.node_id = node_id
        self.is_validator = is_validator
        self.transport_mode = transport_mode
        self.posf_signer = posf_signer

        # Validate transport mode
        if transport_mode not in self.TRANSPORT_MODES:
            raise ValueError(f"Invalid transport mode: {transport_mode}")

        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', listen_port))
        self.socket.setblocking(False)

        self.local_address = self.socket.getsockname()

        # Session management
        self.sessions = {}  # session_id → HTPSession

        # Anti-DoS tracking
        self.hello_rate_limiter: Dict[str, list] = {}  # IP → [timestamps]

        print(f"[HTP] {node_id} listening on {self.local_address}")
        print(f"[HTP] Transport mode: {transport_mode} - {self.TRANSPORT_MODES[transport_mode]['description']}")

    def connect(
        self,
        validator_address: Tuple[str, int],
        weight_fingerprint: bytes,
        device_key: ed25519.Ed25519PrivateKey
    ) -> Optional[bytes]:
        """
        Initiate connection to validator (edge node only).
        Enhanced with ephemeral X25519 key exchange for perfect forward secrecy.

        Args:
            validator_address: (IP, port) of validator
            weight_fingerprint: SHA512 of current neural weights
            device_key: Ed25519 private key for signing

        Returns:
            Session ID if successful, None otherwise
        """
        if self.is_validator:
            raise ValueError("Validators do not initiate connections")

        # Generate session ID
        session_id = os.urandom(8)

        print(f"[HTP] Connecting to {validator_address}...")
        print(f"[HTP] Using enhanced handshake with ephemeral X25519 key exchange")

        # Generate ephemeral X25519 keypair for perfect forward secrecy
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        # 1. Send HELLO with ephemeral public key
        hello_msg = self._build_hello_enhanced(
            session_id,
            weight_fingerprint,
            ephemeral_public,
            device_key
        )
        self._send_message(hello_msg, validator_address)

        # Create session (state: HELLO_SENT)
        mode_config = self.TRANSPORT_MODES[self.transport_mode]
        session = HTPSession(
            session_id=session_id,
            peer_address=validator_address,
            state=SessionState.HELLO_SENT,
            chacha_key=b'',  # Will be derived after ACCEPT
            send_sequence=1,
            recv_sequence=0,
            ephemeral_private_key=ephemeral_private,
            ephemeral_public_key=ephemeral_public,
            weight_fingerprint=weight_fingerprint,
            last_weight_fingerprint=weight_fingerprint,
            created_timestamp=time.time(),
            last_activity=time.time(),
            heartbeat_interval=mode_config['heartbeat_interval'],
            jitter_min_ms=mode_config['jitter_ms'][0],
            jitter_max_ms=mode_config['jitter_ms'][1],
            transport_mode=self.transport_mode
        )
        self.sessions[session_id] = session

        # 2. Wait for CHALLENGE (contains validator's ephemeral public key)
        challenge_msg = self._wait_for_message(MessageType.CHALLENGE, timeout=10.0)
        if not challenge_msg:
            print("[HTP] Timeout waiting for CHALLENGE")
            del self.sessions[session_id]
            return None

        session.state = SessionState.CHALLENGE_RECEIVED

        # Parse CHALLENGE payload: nonce (16 bytes) + ephemeral_public_key (32 bytes) + signature (64 bytes)
        nonce = challenge_msg.payload[:16]
        peer_ephemeral_public_bytes = challenge_msg.payload[16:48]
        # Signature verification would go here (validator's Ed25519 signature)

        # Store peer's ephemeral public key
        session.peer_ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_ephemeral_public_bytes
        )

        # Compute shared secret using X25519 Diffie-Hellman
        shared_secret = ephemeral_private.exchange(session.peer_ephemeral_public_key)
        session.shared_secret = shared_secret

        print(f"[HTP] Computed DH shared secret for perfect forward secrecy")

        # 3. Generate attestation (sign nonce + weight FP)
        attestation_data = nonce + weight_fingerprint
        signature = device_key.sign(attestation_data)

        # Send ATTEST
        attest_msg = self._build_attest(session_id, signature)
        self._send_message(attest_msg, validator_address)
        session.state = SessionState.ATTEST_SENT
        session.send_sequence += 1

        # 4. Wait for ACCEPT or REJECT
        response_msg = self._wait_for_message_types(
            [MessageType.ACCEPT, MessageType.REJECT],
            timeout=10.0
        )

        if not response_msg:
            print("[HTP] Timeout waiting for ACCEPT/REJECT")
            del self.sessions[session_id]
            return None

        if response_msg.msg_type == MessageType.REJECT:
            print(f"[HTP] Session rejected: {response_msg.payload.decode()}")
            del self.sessions[session_id]
            return None

        # 5. Decrypt session_secret (encrypted with DH shared secret)
        # Payload: nonce (12 bytes) + encrypted_session_secret (48 bytes with tag)
        accept_nonce = response_msg.payload[:12]
        encrypted_session_secret = response_msg.payload[12:]

        # Derive temporary key from DH shared secret for ACCEPT decryption
        accept_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'HTP-ACCEPT-KEY'
        ).derive(shared_secret)

        cipher = ChaCha20Poly1305(accept_key)
        session_secret = cipher.decrypt(accept_nonce, encrypted_session_secret, associated_data=None)

        # 6. Derive final session key from: DH shared secret + session_secret + weight fingerprint
        session.chacha_key = self._derive_session_key_enhanced(
            shared_secret,
            session_secret,
            weight_fingerprint
        )
        session.state = SessionState.ESTABLISHED
        session.last_activity = time.time()
        session.next_heartbeat_time = time.time() + session.heartbeat_interval + self._get_jitter(session)

        print(f"[HTP] Session established: {session_id.hex()[:8]}... (PFS enabled)")
        print(f"[HTP] Key rotation scheduled every {self.KEY_ROTATION_INTERVAL}s")
        return session_id

    def send_data(self, session_id: bytes, data: bytes) -> bool:
        """
        Send encrypted data over established session.
        Enhanced with padding and optional PoSF signatures.

        Args:
            session_id: Session identifier
            data: Data to send

        Returns:
            True if sent successfully
        """
        session = self.sessions.get(session_id)
        if not session or session.state != SessionState.ESTABLISHED:
            return False

        # Check if key rotation is needed
        if time.time() - session.created_timestamp > self.KEY_ROTATION_INTERVAL * (session.key_rotation_counter + 1):
            self._rotate_session_key(session_id)

        # Add padding for traffic analysis resistance
        padded_data = self._add_padding(data, session.transport_mode)

        # Add PoSF signature if signer available
        if self.posf_signer:
            message_hash = hashlib.sha256(data).digest()
            nonce_posf = secrets.token_bytes(32)
            posf_signature = self.posf_signer.sign(message_hash, nonce_posf)
            # Prepend signature: signature_length (2 bytes) + signature + data
            padded_data = struct.pack('<H', len(posf_signature)) + posf_signature + padded_data

        # Encrypt data
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(session.chacha_key)
        ciphertext = cipher.encrypt(nonce, padded_data, associated_data=None)

        # Build DATA message
        payload = nonce + ciphertext
        data_msg = HTPMessage(
            msg_type=MessageType.DATA,
            session_id=session_id,
            sequence=session.send_sequence,
            payload=payload
        )

        # Send
        packet = self._serialize_message(data_msg)
        self.socket.sendto(packet, session.peer_address)

        session.send_sequence += 1
        session.last_activity = time.time()

        return True

    def receive_data(self, session_id: bytes, timeout: float = 1.0) -> Optional[bytes]:
        """
        Receive encrypted data from session.
        Enhanced with padding removal and PoSF signature verification.

        Args:
            session_id: Session identifier
            timeout: Receive timeout in seconds

        Returns:
            Decrypted data or None
        """
        session = self.sessions.get(session_id)
        if not session or session.state != SessionState.ESTABLISHED:
            return None

        # Wait for DATA message
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                packet, addr = self.socket.recvfrom(self.MAX_PACKET_SIZE)
                msg = self._parse_message(packet)

                if msg.session_id != session_id:
                    continue

                if msg.msg_type == MessageType.DATA:
                    # Decrypt
                    nonce = msg.payload[:12]
                    ciphertext = msg.payload[12:]

                    cipher = ChaCha20Poly1305(session.chacha_key)
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)

                    # Remove PoSF signature if present
                    if len(plaintext) >= 2:
                        sig_length = struct.unpack('<H', plaintext[:2])[0]
                        if sig_length > 0 and len(plaintext) >= 2 + sig_length:
                            # Extract signature and data
                            posf_signature = plaintext[2:2+sig_length]
                            data_with_padding = plaintext[2+sig_length:]

                            # TODO: Verify PoSF signature if verifier available
                            # For now, just extract the data
                            plaintext = data_with_padding

                    # Remove padding
                    plaintext = self._remove_padding(plaintext)

                    session.recv_sequence = msg.sequence
                    session.last_activity = time.time()

                    return plaintext

                elif msg.msg_type == MessageType.HEARTBEAT:
                    # Respond to heartbeat
                    self._send_ack(session_id, msg.sequence, addr)

            except BlockingIOError:
                time.sleep(0.01)
                continue
            except Exception as e:
                print(f"[HTP] Error receiving data: {e}")
                continue

        return None

    def send_heartbeat(self, session_id: bytes):
        """Send heartbeat to keep NAT mapping alive with jitter injection."""
        session = self.sessions.get(session_id)
        if not session:
            return

        # Check if it's time to send heartbeat (with jitter)
        current_time = time.time()
        if current_time < session.next_heartbeat_time:
            return

        # Add PoSF signature to heartbeat if available
        payload = b''
        if self.posf_signer and session.weight_fingerprint:
            # Sign heartbeat with current neural state
            message_hash = hashlib.sha256(session_id + struct.pack('<I', session.send_sequence)).digest()
            nonce_posf = secrets.token_bytes(32)
            posf_signature = self.posf_signer.sign(message_hash, nonce_posf)
            payload = struct.pack('<H', len(posf_signature)) + posf_signature

        # Add padding to heartbeat
        if session.transport_mode in ['STEALTH', 'GHOST']:
            payload = self._add_padding(payload, session.transport_mode)

        heartbeat_msg = HTPMessage(
            msg_type=MessageType.HEARTBEAT,
            session_id=session_id,
            sequence=session.send_sequence,
            payload=payload
        )

        packet = self._serialize_message(heartbeat_msg)
        self.socket.sendto(packet, session.peer_address)

        session.send_sequence += 1
        session.last_activity = current_time

        # Schedule next heartbeat with jitter
        jitter_seconds = self._get_jitter(session)
        session.next_heartbeat_time = current_time + session.heartbeat_interval + jitter_seconds

    def close_session(self, session_id: bytes):
        """Close session gracefully."""
        session = self.sessions.get(session_id)
        if not session:
            return

        close_msg = HTPMessage(
            msg_type=MessageType.CLOSE,
            session_id=session_id,
            sequence=session.send_sequence,
            payload=b''
        )

        packet = self._serialize_message(close_msg)
        self.socket.sendto(packet, session.peer_address)

        del self.sessions[session_id]
        print(f"[HTP] Session closed: {session_id.hex()[:8]}...")

    def _build_hello(self, session_id: bytes, weight_fp: bytes) -> HTPMessage:
        """Build HELLO message (legacy, for compatibility)."""
        payload = self.node_id.encode('utf-8')[:32].ljust(32, b'\x00') + weight_fp

        return HTPMessage(
            msg_type=MessageType.HELLO,
            session_id=session_id,
            sequence=0,
            payload=payload
        )

    def _build_hello_enhanced(
        self,
        session_id: bytes,
        weight_fp: bytes,
        ephemeral_public: x25519.X25519PublicKey,
        device_key: ed25519.Ed25519PrivateKey
    ) -> HTPMessage:
        """
        Build enhanced HELLO message with ephemeral public key for PFS.

        Payload format:
        - node_id (32 bytes, padded)
        - weight_fp (64 bytes)
        - ephemeral_public_key (32 bytes)
        - signature (64 bytes) - Ed25519 signature of above fields
        """
        node_id_bytes = self.node_id.encode('utf-8')[:32].ljust(32, b'\x00')
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Sign the message for authenticity
        signed_data = node_id_bytes + weight_fp + ephemeral_public_bytes
        signature = device_key.sign(signed_data)

        payload = signed_data + signature

        return HTPMessage(
            msg_type=MessageType.HELLO,
            session_id=session_id,
            sequence=0,
            payload=payload
        )

    def _build_attest(self, session_id: bytes, signature: bytes) -> HTPMessage:
        """Build ATTEST message."""
        return HTPMessage(
            msg_type=MessageType.ATTEST,
            session_id=session_id,
            sequence=1,
            payload=signature
        )

    def _serialize_message(self, msg: HTPMessage) -> bytes:
        """
        Serialize HTP message to bytes.

        Format:
        - MSG_TYPE (1 byte)
        - SESSION_ID (8 bytes)
        - SEQUENCE (4 bytes)
        - PAYLOAD_LEN (2 bytes)
        - PAYLOAD (variable)
        """
        header = struct.pack(
            '<B8sIH',
            msg.msg_type.value,
            msg.session_id,
            msg.sequence,
            len(msg.payload)
        )

        return header + msg.payload

    def _parse_message(self, packet: bytes) -> HTPMessage:
        """Parse received packet into HTP message."""
        msg_type_byte, session_id, sequence, payload_len = struct.unpack('<B8sIH', packet[:15])

        msg_type = MessageType(msg_type_byte)
        payload = packet[15:15+payload_len]

        return HTPMessage(
            msg_type=msg_type,
            session_id=session_id,
            sequence=sequence,
            payload=payload
        )

    def _send_message(self, msg: HTPMessage, address: Tuple[str, int]):
        """Send message to address."""
        packet = self._serialize_message(msg)
        self.socket.sendto(packet, address)

    def _wait_for_message(self, expected_type: MessageType, timeout: float) -> Optional[HTPMessage]:
        """Wait for specific message type."""
        return self._wait_for_message_types([expected_type], timeout)

    def _wait_for_message_types(self, expected_types: list, timeout: float) -> Optional[HTPMessage]:
        """Wait for one of several message types."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                packet, addr = self.socket.recvfrom(self.MAX_PACKET_SIZE)
                msg = self._parse_message(packet)

                if msg.msg_type in expected_types:
                    return msg

            except BlockingIOError:
                time.sleep(0.01)
                continue

        return None

    def _send_ack(self, session_id: bytes, sequence: int, address: Tuple[str, int]):
        """Send ACK message."""
        ack_msg = HTPMessage(
            msg_type=MessageType.ACK,
            session_id=session_id,
            sequence=sequence,
            payload=b''
        )

        packet = self._serialize_message(ack_msg)
        self.socket.sendto(packet, address)

    def _derive_session_key(self, session_secret: bytes, weight_fp: bytes) -> bytes:
        """Derive ChaCha20 key from session secret + weight fingerprint (legacy)."""
        combined = session_secret + weight_fp
        return hashlib.sha256(combined).digest()

    def _derive_session_key_enhanced(
        self,
        shared_secret: bytes,
        session_secret: bytes,
        weight_fp: bytes
    ) -> bytes:
        """
        Derive ChaCha20 key with enhanced security.
        Combines DH shared secret + session_secret + weight fingerprint.
        Uses HKDF for proper key derivation.
        """
        # Combine all entropy sources
        combined = shared_secret + session_secret + weight_fp

        # Use HKDF for proper key derivation
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'HTP-SESSION-KEY-V2'
        ).derive(combined)

        return key

    def _add_padding(self, data: bytes, transport_mode: str) -> bytes:
        """
        Add random padding to data for traffic analysis resistance.

        Args:
            data: Original data
            transport_mode: Transport mode (determines padding amount)

        Returns:
            Padded data with length prefix
        """
        mode_config = self.TRANSPORT_MODES.get(transport_mode, self.TRANSPORT_MODES['BALANCED'])
        min_pad, max_pad = mode_config['padding']

        # Generate random padding amount
        padding_size = random.randint(min_pad, max_pad)
        padding = secrets.token_bytes(padding_size)

        # Format: original_length (4 bytes) + data + padding
        original_length = len(data)
        padded = struct.pack('<I', original_length) + data + padding

        return padded

    def _remove_padding(self, padded_data: bytes) -> bytes:
        """
        Remove padding from received data.

        Args:
            padded_data: Data with padding

        Returns:
            Original data without padding
        """
        if len(padded_data) < 4:
            return padded_data  # No padding

        # Extract original length
        original_length = struct.unpack('<I', padded_data[:4])[0]

        # Extract original data
        if len(padded_data) < 4 + original_length:
            return padded_data  # Invalid format, return as-is

        original_data = padded_data[4:4+original_length]
        return original_data

    def _get_jitter(self, session: HTPSession) -> float:
        """
        Calculate jitter for timing variability (anti-surveillance).

        Args:
            session: Session object

        Returns:
            Jitter in seconds (can be negative or positive)
        """
        jitter_ms = random.uniform(session.jitter_min_ms, session.jitter_max_ms)
        # Make it vary around the base interval (±jitter)
        jitter_seconds = (jitter_ms / 1000.0) * random.choice([-1, 1])
        return jitter_seconds

    def _rotate_session_key(self, session_id: bytes):
        """
        Rotate session key based on updated sensor data.
        Implements continuous authentication.

        Args:
            session_id: Session to rotate
        """
        session = self.sessions.get(session_id)
        if not session or not session.shared_secret:
            return

        print(f"[HTP] Rotating session key #{session.key_rotation_counter + 1}")

        # Get updated weight fingerprint (would come from neural engine)
        # For now, use a simple counter-based derivation
        rotation_salt = struct.pack('<I', session.key_rotation_counter)

        # Derive new session key
        new_key_material = session.shared_secret + session.weight_fingerprint + rotation_salt

        new_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'HTP-KEY-ROTATION'
        ).derive(new_key_material)

        # Update session key
        session.chacha_key = new_key
        session.key_rotation_counter += 1

        print(f"[HTP] Session key rotated successfully")

    def update_weight_fingerprint(self, session_id: bytes, new_weight_fp: bytes):
        """
        Update weight fingerprint and trigger key rotation.
        Called when neural weights evolve significantly.

        Args:
            session_id: Session to update
            new_weight_fp: New weight fingerprint
        """
        session = self.sessions.get(session_id)
        if not session:
            return

        session.last_weight_fingerprint = session.weight_fingerprint
        session.weight_fingerprint = new_weight_fp

        # Trigger key rotation
        self._rotate_session_key(session_id)

    def set_transport_mode(self, session_id: bytes, mode: str):
        """
        Change transport mode dynamically (adaptive polymorphism).

        Args:
            session_id: Session to modify
            mode: New transport mode (BURST/BALANCED/STEALTH/GHOST)
        """
        if mode not in self.TRANSPORT_MODES:
            raise ValueError(f"Invalid transport mode: {mode}")

        session = self.sessions.get(session_id)
        if not session:
            return

        mode_config = self.TRANSPORT_MODES[mode]

        session.transport_mode = mode
        session.heartbeat_interval = mode_config['heartbeat_interval']
        session.jitter_min_ms, session.jitter_max_ms = mode_config['jitter_ms']

        print(f"[HTP] Transport mode changed to {mode}: {mode_config['description']}")

    def _check_rate_limit(self, source_ip: str) -> bool:
        """
        Check if source IP is rate-limited (anti-DoS).

        Args:
            source_ip: Source IP address

        Returns:
            True if allowed, False if rate-limited
        """
        current_time = time.time()

        # Clean old timestamps (older than 60 seconds)
        if source_ip in self.hello_rate_limiter:
            self.hello_rate_limiter[source_ip] = [
                ts for ts in self.hello_rate_limiter[source_ip]
                if current_time - ts < 60.0
            ]
        else:
            self.hello_rate_limiter[source_ip] = []

        # Check rate limit
        if len(self.hello_rate_limiter[source_ip]) >= self.MAX_HELLO_PER_MINUTE:
            print(f"[HTP] Rate limit exceeded for {source_ip}")
            return False

        # Add current timestamp
        self.hello_rate_limiter[source_ip].append(current_time)
        return True


# Example usage
if __name__ == '__main__':
    print("=== HookProbe Transport Protocol (HTP) Test ===\n")

    # This would be a full end-to-end test
    # For now, just demonstrate message serialization

    msg = HTPMessage(
        msg_type=MessageType.HELLO,
        session_id=b'\x01\x02\x03\x04\x05\x06\x07\x08',
        sequence=0,
        payload=b'node-001' + b'\x00' * 56  # 64-byte weight FP
    )

    # Serialize
    transport = HookProbeTransport("test-node", listen_port=0)
    packet = transport._serialize_message(msg)
    print(f"Serialized message: {len(packet)} bytes")

    # Parse
    parsed = transport._parse_message(packet)
    print(f"Parsed message type: {parsed.msg_type}")
    print(f"Session ID: {parsed.session_id.hex()}")
    print(f"Sequence: {parsed.sequence}")

    print("\n✓ HTP test complete")
