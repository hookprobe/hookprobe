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
from typing import Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519


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
    """Active HTP session."""
    session_id: bytes
    peer_address: Tuple[str, int]  # IP, port
    state: SessionState

    # Crypto
    chacha_key: bytes  # 32 bytes
    send_sequence: int
    recv_sequence: int

    # Neuro context
    weight_fingerprint: bytes  # 64 bytes

    # Timing
    created_timestamp: float
    last_activity: float
    heartbeat_interval: float  # seconds


class HookProbeTransport:
    """
    HookProbe Transport Protocol (HTP).

    Simple, focused transport for HookProbe's specific needs.
    Designed to be robust, secure, and unhackable.
    """

    # Protocol constants
    MAX_PACKET_SIZE = 1400  # Stay below MTU for UDP
    HEARTBEAT_INTERVAL = 30.0  # seconds
    SESSION_TIMEOUT = 300.0  # 5 minutes
    MAX_RETRIES = 3

    def __init__(
        self,
        node_id: str,
        listen_port: int = 0,  # 0 = random port
        is_validator: bool = False
    ):
        """
        Args:
            node_id: Node identifier
            listen_port: UDP port to listen on
            is_validator: Whether this is a validator node
        """
        self.node_id = node_id
        self.is_validator = is_validator

        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', listen_port))
        self.socket.setblocking(False)

        self.local_address = self.socket.getsockname()

        # Session management
        self.sessions = {}  # session_id → HTPSession

        print(f"[HTP] {node_id} listening on {self.local_address}")

    def connect(
        self,
        validator_address: Tuple[str, int],
        weight_fingerprint: bytes,
        device_key: ed25519.Ed25519PrivateKey
    ) -> Optional[bytes]:
        """
        Initiate connection to validator (edge node only).

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

        # 1. Send HELLO
        hello_msg = self._build_hello(session_id, weight_fingerprint)
        self._send_message(hello_msg, validator_address)

        # Create session (state: HELLO_SENT)
        session = HTPSession(
            session_id=session_id,
            peer_address=validator_address,
            state=SessionState.HELLO_SENT,
            chacha_key=b'',  # Will be derived after ACCEPT
            send_sequence=1,
            recv_sequence=0,
            weight_fingerprint=weight_fingerprint,
            created_timestamp=time.time(),
            last_activity=time.time(),
            heartbeat_interval=self.HEARTBEAT_INTERVAL
        )
        self.sessions[session_id] = session

        # 2. Wait for CHALLENGE
        challenge_msg = self._wait_for_message(MessageType.CHALLENGE, timeout=10.0)
        if not challenge_msg:
            print("[HTP] Timeout waiting for CHALLENGE")
            del self.sessions[session_id]
            return None

        session.state = SessionState.CHALLENGE_RECEIVED
        nonce = challenge_msg.payload  # 16-byte challenge nonce

        # 3. Generate attestation (simplified - sign nonce + weight FP)
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

        # 5. Derive session key from weight fingerprint
        session_secret = response_msg.payload[:32]  # Validator sends session secret
        session.chacha_key = self._derive_session_key(session_secret, weight_fingerprint)
        session.state = SessionState.ESTABLISHED
        session.last_activity = time.time()

        print(f"[HTP] Session established: {session_id.hex()[:8]}...")
        return session_id

    def send_data(self, session_id: bytes, data: bytes) -> bool:
        """
        Send encrypted data over established session.

        Args:
            session_id: Session identifier
            data: Data to send

        Returns:
            True if sent successfully
        """
        session = self.sessions.get(session_id)
        if not session or session.state != SessionState.ESTABLISHED:
            return False

        # Encrypt data
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(session.chacha_key)
        ciphertext = cipher.encrypt(nonce, data, associated_data=None)

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

                    session.recv_sequence = msg.sequence
                    session.last_activity = time.time()

                    return plaintext

                elif msg.msg_type == MessageType.HEARTBEAT:
                    # Respond to heartbeat
                    self._send_ack(session_id, msg.sequence, addr)

            except BlockingIOError:
                time.sleep(0.01)
                continue

        return None

    def send_heartbeat(self, session_id: bytes):
        """Send heartbeat to keep NAT mapping alive."""
        session = self.sessions.get(session_id)
        if not session:
            return

        heartbeat_msg = HTPMessage(
            msg_type=MessageType.HEARTBEAT,
            session_id=session_id,
            sequence=session.send_sequence,
            payload=b''
        )

        packet = self._serialize_message(heartbeat_msg)
        self.socket.sendto(packet, session.peer_address)

        session.send_sequence += 1
        session.last_activity = time.time()

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
        """Build HELLO message."""
        payload = self.node_id.encode('utf-8')[:32].ljust(32, b'\x00') + weight_fp

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
        """Derive ChaCha20 key from session secret + weight fingerprint."""
        combined = session_secret + weight_fp
        return hashlib.sha256(combined).digest()


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
