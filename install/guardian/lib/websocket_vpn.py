"""
WebSocket VPN Module for Guardian

Provides secure remote access to Guardian-protected networks through MSSP
using WebSocket transport with HookProbe Transport Protocol (HTP/Noise)
encryption.

Architecture:
    [User] <--WebSocket+TLS--> [MSSP] <--WebSocket+HTP--> [Guardian] <--> [Files/Network]

The Noise Protocol (XX pattern) provides:
- Forward secrecy
- Identity hiding
- Mutual authentication
- End-to-end encryption

Author: HookProbe Team
Version: 5.0.0 Liberty
License: MIT
"""

import asyncio
import logging
import hashlib
import hmac
import os
import struct
import time
import json
import base64
import secrets
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Callable, Any, Tuple, Union
from pathlib import Path
import aiohttp
import ssl

logger = logging.getLogger(__name__)


# ============================================================================
# Protocol Constants
# ============================================================================

# WebSocket VPN Protocol Version
WS_VPN_VERSION = 1

# Noise Protocol Parameters
NOISE_PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
NOISE_DH_LEN = 32       # X25519 key length
NOISE_HASH_LEN = 32     # SHA256 output length
NOISE_CIPHER_KEY_LEN = 32
NOISE_TAG_LEN = 16      # Poly1305 tag length

# Message types
class MessageType(IntEnum):
    # Handshake messages
    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESPONSE = 0x02
    HANDSHAKE_COMPLETE = 0x03

    # Control messages
    PING = 0x10
    PONG = 0x11
    DISCONNECT = 0x12
    ERROR = 0x13

    # Authentication
    AUTH_REQUEST = 0x20
    AUTH_CHALLENGE = 0x21
    AUTH_RESPONSE = 0x22
    AUTH_SUCCESS = 0x23
    AUTH_FAILURE = 0x24

    # File operations
    FILE_LIST = 0x30
    FILE_LIST_RESPONSE = 0x31
    FILE_READ = 0x32
    FILE_READ_RESPONSE = 0x33
    FILE_WRITE = 0x34
    FILE_WRITE_RESPONSE = 0x35
    FILE_DELETE = 0x36
    FILE_DELETE_RESPONSE = 0x37
    FILE_STAT = 0x38
    FILE_STAT_RESPONSE = 0x39

    # Tunnel operations
    TUNNEL_DATA = 0x40
    TUNNEL_OPEN = 0x41
    TUNNEL_CLOSE = 0x42
    TUNNEL_ACK = 0x43

    # Network operations
    NET_INFO = 0x50
    NET_INFO_RESPONSE = 0x51


class ErrorCode(IntEnum):
    OK = 0
    UNKNOWN_ERROR = 1
    PROTOCOL_ERROR = 2
    AUTH_FAILED = 3
    PERMISSION_DENIED = 4
    FILE_NOT_FOUND = 5
    FILE_EXISTS = 6
    IO_ERROR = 7
    TIMEOUT = 8
    RATE_LIMITED = 9
    INVALID_PATH = 10
    FILE_TOO_LARGE = 11


# ============================================================================
# Noise Protocol Implementation
# ============================================================================

class NoiseState:
    """
    Noise Protocol state machine (XX pattern)

    XX Pattern:
      -> e
      <- e, ee, s, es
      -> s, se
    """

    def __init__(self, is_initiator: bool):
        self.is_initiator = is_initiator

        # Key pairs
        self.s_priv: Optional[bytes] = None  # Static private key
        self.s_pub: Optional[bytes] = None   # Static public key
        self.e_priv: Optional[bytes] = None  # Ephemeral private key
        self.e_pub: Optional[bytes] = None   # Ephemeral public key

        # Remote keys
        self.rs: Optional[bytes] = None  # Remote static
        self.re: Optional[bytes] = None  # Remote ephemeral

        # Symmetric state
        self.ck: bytes = b''  # Chaining key
        self.h: bytes = b''   # Handshake hash
        self.k: Optional[bytes] = None  # Cipher key
        self.n: int = 0  # Nonce

        # Session keys (after handshake)
        self.send_key: Optional[bytes] = None
        self.recv_key: Optional[bytes] = None
        self.send_nonce: int = 0
        self.recv_nonce: int = 0

        # Handshake state
        self.handshake_complete = False
        self.message_patterns: List[str] = []

    def initialize(self, prologue: bytes = b''):
        """Initialize Noise state"""
        # Initialize symmetric state with protocol name
        if len(NOISE_PROTOCOL_NAME) <= NOISE_HASH_LEN:
            self.h = NOISE_PROTOCOL_NAME.ljust(NOISE_HASH_LEN, b'\x00')
        else:
            self.h = self._hash(NOISE_PROTOCOL_NAME)

        self.ck = self.h

        # Mix in prologue
        self._mix_hash(prologue)

        # Set message patterns for XX
        if self.is_initiator:
            self.message_patterns = ['e', 'e,ee,s,es', 's,se']
        else:
            self.message_patterns = ['e', 'e,ee,s,es', 's,se']

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate X25519 keypair"""
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()
            return (
                private_key.private_bytes_raw(),
                public_key.public_bytes_raw()
            )
        except ImportError:
            # Fallback: generate random bytes (for testing only)
            logger.warning("cryptography library not available, using mock keys")
            priv = secrets.token_bytes(32)
            pub = hashlib.sha256(priv).digest()
            return priv, pub

    def set_static_keypair(self, private_key: bytes, public_key: bytes):
        """Set static keypair"""
        self.s_priv = private_key
        self.s_pub = public_key

    def set_remote_static(self, public_key: bytes):
        """Set remote static public key (for pre-known peers)"""
        self.rs = public_key

    def _hash(self, data: bytes) -> bytes:
        """SHA-256 hash"""
        return hashlib.sha256(data).digest()

    def _hmac(self, key: bytes, data: bytes) -> bytes:
        """HMAC-SHA256"""
        return hmac.new(key, data, hashlib.sha256).digest()

    def _hkdf(self, chaining_key: bytes, input_key_material: bytes, num_outputs: int) -> List[bytes]:
        """HKDF with SHA-256"""
        temp_key = self._hmac(chaining_key, input_key_material)
        outputs = []

        output = b''
        for i in range(num_outputs):
            output = self._hmac(temp_key, output + bytes([i + 1]))
            outputs.append(output)

        return outputs

    def _mix_hash(self, data: bytes):
        """Mix data into handshake hash"""
        self.h = self._hash(self.h + data)

    def _mix_key(self, input_key_material: bytes):
        """Mix key material into chaining key"""
        outputs = self._hkdf(self.ck, input_key_material, 2)
        self.ck = outputs[0]
        self.k = outputs[1]
        self.n = 0

    def _dh(self, private_key: bytes, public_key: bytes) -> bytes:
        """X25519 Diffie-Hellman"""
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
            priv = X25519PrivateKey.from_private_bytes(private_key)
            pub = X25519PublicKey.from_public_bytes(public_key)
            return priv.exchange(pub)
        except ImportError:
            # Fallback: mock DH (for testing only)
            return self._hash(private_key + public_key)

    def _encrypt(self, key: bytes, nonce: int, ad: bytes, plaintext: bytes) -> bytes:
        """ChaCha20-Poly1305 encryption"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            nonce_bytes = struct.pack('<Q', nonce).ljust(12, b'\x00')
            cipher = ChaCha20Poly1305(key)
            return cipher.encrypt(nonce_bytes, plaintext, ad)
        except ImportError:
            # Fallback: mock encryption (for testing only)
            logger.warning("cryptography library not available, using mock encryption")
            return plaintext + self._hash(key + plaintext)[:16]

    def _decrypt(self, key: bytes, nonce: int, ad: bytes, ciphertext: bytes) -> bytes:
        """ChaCha20-Poly1305 decryption"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            nonce_bytes = struct.pack('<Q', nonce).ljust(12, b'\x00')
            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce_bytes, ciphertext, ad)
        except ImportError:
            # Fallback: mock decryption (for testing only)
            return ciphertext[:-16]

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Encrypt and mix into hash"""
        if self.k is None:
            self._mix_hash(plaintext)
            return plaintext

        ciphertext = self._encrypt(self.k, self.n, self.h, plaintext)
        self._mix_hash(ciphertext)
        self.n += 1
        return ciphertext

    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """Decrypt and mix into hash"""
        if self.k is None:
            self._mix_hash(ciphertext)
            return ciphertext

        plaintext = self._decrypt(self.k, self.n, self.h, ciphertext)
        self._mix_hash(ciphertext)
        self.n += 1
        return plaintext

    def write_message(self, payload: bytes = b'') -> bytes:
        """Write handshake message"""
        if self.handshake_complete:
            raise ValueError("Handshake already complete")

        message = b''

        # Get current pattern
        pattern_idx = 0 if self.is_initiator else 1
        if len(self.message_patterns) == 3:
            if self.e_pub is not None:
                pattern_idx = 2 if self.is_initiator else 1

        pattern = self.message_patterns[min(pattern_idx, len(self.message_patterns) - 1)]
        tokens = pattern.split(',')

        for token in tokens:
            token = token.strip()

            if token == 'e':
                # Generate ephemeral keypair
                self.e_priv, self.e_pub = self.generate_keypair()
                message += self.e_pub
                self._mix_hash(self.e_pub)

            elif token == 's':
                # Encrypt and send static public key
                encrypted_s = self._encrypt_and_hash(self.s_pub)
                message += encrypted_s

            elif token == 'ee':
                # DH with ephemeral keys
                self._mix_key(self._dh(self.e_priv, self.re))

            elif token == 'es':
                if self.is_initiator:
                    self._mix_key(self._dh(self.e_priv, self.rs))
                else:
                    self._mix_key(self._dh(self.s_priv, self.re))

            elif token == 'se':
                if self.is_initiator:
                    self._mix_key(self._dh(self.s_priv, self.re))
                else:
                    self._mix_key(self._dh(self.e_priv, self.rs))

        # Encrypt payload
        if payload:
            message += self._encrypt_and_hash(payload)

        return message

    def read_message(self, message: bytes) -> bytes:
        """Read handshake message"""
        if self.handshake_complete:
            raise ValueError("Handshake already complete")

        offset = 0
        payload = b''

        # Get current pattern
        pattern_idx = 0 if not self.is_initiator else 1
        if len(self.message_patterns) == 3:
            if self.re is not None:
                pattern_idx = 2 if not self.is_initiator else 1

        pattern = self.message_patterns[min(pattern_idx, len(self.message_patterns) - 1)]
        tokens = pattern.split(',')

        for token in tokens:
            token = token.strip()

            if token == 'e':
                # Read remote ephemeral
                self.re = message[offset:offset + NOISE_DH_LEN]
                offset += NOISE_DH_LEN
                self._mix_hash(self.re)

            elif token == 's':
                # Read encrypted remote static
                if self.k is None:
                    self.rs = message[offset:offset + NOISE_DH_LEN]
                    offset += NOISE_DH_LEN
                    self._mix_hash(self.rs)
                else:
                    encrypted_len = NOISE_DH_LEN + NOISE_TAG_LEN
                    self.rs = self._decrypt_and_hash(message[offset:offset + encrypted_len])
                    offset += encrypted_len

            elif token == 'ee':
                self._mix_key(self._dh(self.e_priv, self.re))

            elif token == 'es':
                if self.is_initiator:
                    self._mix_key(self._dh(self.e_priv, self.rs))
                else:
                    self._mix_key(self._dh(self.s_priv, self.re))

            elif token == 'se':
                if self.is_initiator:
                    self._mix_key(self._dh(self.s_priv, self.re))
                else:
                    self._mix_key(self._dh(self.e_priv, self.rs))

        # Decrypt remaining payload
        if offset < len(message):
            payload = self._decrypt_and_hash(message[offset:])

        return payload

    def split(self):
        """Split into transport keys after handshake"""
        outputs = self._hkdf(self.ck, b'', 2)

        if self.is_initiator:
            self.send_key = outputs[0]
            self.recv_key = outputs[1]
        else:
            self.send_key = outputs[1]
            self.recv_key = outputs[0]

        self.send_nonce = 0
        self.recv_nonce = 0
        self.handshake_complete = True

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt transport message"""
        if not self.handshake_complete:
            raise ValueError("Handshake not complete")

        ciphertext = self._encrypt(self.send_key, self.send_nonce, b'', plaintext)
        self.send_nonce += 1
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt transport message"""
        if not self.handshake_complete:
            raise ValueError("Handshake not complete")

        plaintext = self._decrypt(self.recv_key, self.recv_nonce, b'', ciphertext)
        self.recv_nonce += 1
        return plaintext


# ============================================================================
# WebSocket VPN Messages
# ============================================================================

@dataclass
class VPNMessage:
    """VPN protocol message"""
    msg_type: MessageType
    request_id: int = 0
    payload: bytes = b''

    def encode(self) -> bytes:
        """Encode message to bytes"""
        header = struct.pack('!BBI', WS_VPN_VERSION, self.msg_type, self.request_id)
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> 'VPNMessage':
        """Decode message from bytes"""
        if len(data) < 6:
            raise ValueError("Message too short")

        version, msg_type, request_id = struct.unpack('!BBI', data[:6])

        if version != WS_VPN_VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")

        return cls(
            msg_type=MessageType(msg_type),
            request_id=request_id,
            payload=data[6:]
        )


@dataclass
class FileInfo:
    """File information"""
    name: str
    path: str
    size: int
    is_dir: bool
    modified: float
    permissions: int = 0o644

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'path': self.path,
            'size': self.size,
            'is_dir': self.is_dir,
            'modified': self.modified,
            'permissions': self.permissions
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileInfo':
        return cls(**data)


# ============================================================================
# WebSocket VPN Client (Guardian side)
# ============================================================================

class WebSocketVPNClient:
    """
    WebSocket VPN Client for Guardian

    Connects to MSSP and provides secure tunnel for file access
    using Noise Protocol encryption.
    """

    def __init__(
        self,
        mssp_host: str = "mssp.hookprobe.com",
        mssp_port: int = 443,
        websocket_path: str = "/ws/vpn",
        guardian_id: str = "",
        allowed_paths: List[str] = None,
        max_file_size_mb: int = 100
    ):
        self.mssp_host = mssp_host
        self.mssp_port = mssp_port
        self.websocket_path = websocket_path
        self.guardian_id = guardian_id or self._generate_guardian_id()

        # File access settings
        self.allowed_paths = allowed_paths or ["/home", "/srv/files"]
        self.max_file_size = max_file_size_mb * 1024 * 1024

        # Noise state
        self.noise: Optional[NoiseState] = None
        self._static_keypair: Optional[Tuple[bytes, bytes]] = None

        # WebSocket connection
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._session: Optional[aiohttp.ClientSession] = None

        # State
        self._connected = False
        self._authenticated = False
        self._request_id = 0

        # Callbacks
        self._message_handlers: Dict[MessageType, Callable] = {}

        # Statistics
        self.stats = {
            'bytes_sent': 0,
            'bytes_received': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'files_transferred': 0,
            'connection_time': 0
        }

        logger.info(f"WebSocket VPN client initialized for {mssp_host}")

    def _generate_guardian_id(self) -> str:
        """Generate Guardian ID"""
        import socket
        hostname = socket.gethostname()
        return hashlib.sha256(f"guardian:{hostname}".encode()).hexdigest()[:16]

    def _next_request_id(self) -> int:
        """Get next request ID"""
        self._request_id = (self._request_id + 1) & 0xFFFFFFFF
        return self._request_id

    def load_keys(self, private_key_path: str, public_key_path: str):
        """Load static keypair from files"""
        try:
            with open(private_key_path, 'rb') as f:
                private_key = f.read()
            with open(public_key_path, 'rb') as f:
                public_key = f.read()
            self._static_keypair = (private_key, public_key)
            logger.info("Loaded static keypair")
        except FileNotFoundError:
            logger.warning("Keys not found, generating new keypair")
            self._generate_and_save_keys(private_key_path, public_key_path)

    def _generate_and_save_keys(self, private_key_path: str, public_key_path: str):
        """Generate and save new keypair"""
        noise = NoiseState(True)
        private_key, public_key = noise.generate_keypair()
        self._static_keypair = (private_key, public_key)

        # Save keys
        Path(private_key_path).parent.mkdir(parents=True, exist_ok=True)
        with open(private_key_path, 'wb') as f:
            f.write(private_key)
        with open(public_key_path, 'wb') as f:
            f.write(public_key)

        os.chmod(private_key_path, 0o600)
        logger.info(f"Generated new keypair: {public_key_path}")

    async def connect(self) -> bool:
        """Connect to MSSP via WebSocket"""
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()

            # Create aiohttp session
            self._session = aiohttp.ClientSession()

            # Build WebSocket URL
            ws_url = f"wss://{self.mssp_host}:{self.mssp_port}{self.websocket_path}"

            logger.info(f"Connecting to {ws_url}")

            # Connect WebSocket
            self._ws = await self._session.ws_connect(
                ws_url,
                ssl=ssl_context,
                heartbeat=25
            )

            self._connected = True
            self.stats['connection_time'] = time.time()

            # Perform Noise handshake
            await self._perform_handshake()

            logger.info("Connected to MSSP")
            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            await self.disconnect()
            return False

    async def disconnect(self):
        """Disconnect from MSSP"""
        self._connected = False
        self._authenticated = False

        if self._ws:
            await self._ws.close()
            self._ws = None

        if self._session:
            await self._session.close()
            self._session = None

        logger.info("Disconnected from MSSP")

    async def _perform_handshake(self):
        """Perform Noise XX handshake"""
        # Initialize Noise state as initiator
        self.noise = NoiseState(is_initiator=True)
        self.noise.initialize(b"HookProbe-VPN-v1")

        if self._static_keypair:
            self.noise.set_static_keypair(*self._static_keypair)
        else:
            priv, pub = self.noise.generate_keypair()
            self.noise.set_static_keypair(priv, pub)

        # -> e
        msg1 = self.noise.write_message()
        await self._send_raw(VPNMessage(
            msg_type=MessageType.HANDSHAKE_INIT,
            payload=msg1
        ))

        # <- e, ee, s, es
        response = await self._recv_raw()
        if response.msg_type != MessageType.HANDSHAKE_RESPONSE:
            raise ValueError(f"Expected HANDSHAKE_RESPONSE, got {response.msg_type}")

        self.noise.read_message(response.payload)

        # -> s, se
        msg3 = self.noise.write_message(self.guardian_id.encode())
        await self._send_raw(VPNMessage(
            msg_type=MessageType.HANDSHAKE_COMPLETE,
            payload=msg3
        ))

        # Split into transport keys
        self.noise.split()

        logger.info("Noise handshake complete")

    async def _send_raw(self, message: VPNMessage):
        """Send raw message (before encryption established)"""
        if not self._ws:
            raise ConnectionError("Not connected")

        data = message.encode()
        await self._ws.send_bytes(data)
        self.stats['bytes_sent'] += len(data)
        self.stats['messages_sent'] += 1

    async def _recv_raw(self) -> VPNMessage:
        """Receive raw message (before encryption established)"""
        if not self._ws:
            raise ConnectionError("Not connected")

        msg = await self._ws.receive()

        if msg.type == aiohttp.WSMsgType.BINARY:
            self.stats['bytes_received'] += len(msg.data)
            self.stats['messages_received'] += 1
            return VPNMessage.decode(msg.data)
        elif msg.type == aiohttp.WSMsgType.CLOSE:
            raise ConnectionError("Connection closed")
        else:
            raise ValueError(f"Unexpected message type: {msg.type}")

    async def send(self, message: VPNMessage):
        """Send encrypted message"""
        if not self._connected or not self.noise or not self.noise.handshake_complete:
            raise ConnectionError("Not connected or handshake incomplete")

        # Encrypt payload
        plaintext = message.encode()
        ciphertext = self.noise.encrypt(plaintext)

        await self._ws.send_bytes(ciphertext)
        self.stats['bytes_sent'] += len(ciphertext)
        self.stats['messages_sent'] += 1

    async def recv(self) -> VPNMessage:
        """Receive and decrypt message"""
        if not self._connected or not self.noise or not self.noise.handshake_complete:
            raise ConnectionError("Not connected or handshake incomplete")

        msg = await self._ws.receive()

        if msg.type == aiohttp.WSMsgType.BINARY:
            self.stats['bytes_received'] += len(msg.data)
            self.stats['messages_received'] += 1

            # Decrypt
            plaintext = self.noise.decrypt(msg.data)
            return VPNMessage.decode(plaintext)

        elif msg.type == aiohttp.WSMsgType.CLOSE:
            raise ConnectionError("Connection closed")
        else:
            raise ValueError(f"Unexpected message type: {msg.type}")

    def _validate_path(self, path: str) -> bool:
        """Validate file path is within allowed paths"""
        try:
            real_path = os.path.realpath(path)
            for allowed in self.allowed_paths:
                allowed_real = os.path.realpath(allowed)
                if real_path.startswith(allowed_real):
                    return True
            return False
        except Exception:
            return False

    async def handle_file_list(self, path: str) -> List[FileInfo]:
        """Handle file list request"""
        if not self._validate_path(path):
            raise PermissionError(f"Access denied: {path}")

        files = []
        try:
            for entry in os.scandir(path):
                stat = entry.stat()
                files.append(FileInfo(
                    name=entry.name,
                    path=entry.path,
                    size=stat.st_size if not entry.is_dir() else 0,
                    is_dir=entry.is_dir(),
                    modified=stat.st_mtime,
                    permissions=stat.st_mode & 0o777
                ))
        except PermissionError:
            raise PermissionError(f"Access denied: {path}")

        return files

    async def handle_file_read(self, path: str, offset: int = 0, length: int = 0) -> bytes:
        """Handle file read request"""
        if not self._validate_path(path):
            raise PermissionError(f"Access denied: {path}")

        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")

        file_size = os.path.getsize(path)
        if file_size > self.max_file_size:
            raise ValueError(f"File too large: {file_size} > {self.max_file_size}")

        with open(path, 'rb') as f:
            if offset:
                f.seek(offset)
            if length:
                return f.read(length)
            return f.read()

    async def handle_file_write(self, path: str, data: bytes, offset: int = 0) -> int:
        """Handle file write request"""
        if not self._validate_path(path):
            raise PermissionError(f"Access denied: {path}")

        # Check directory exists
        dir_path = os.path.dirname(path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)

        mode = 'r+b' if os.path.exists(path) else 'wb'
        with open(path, mode) as f:
            if offset:
                f.seek(offset)
            written = f.write(data)

        self.stats['files_transferred'] += 1
        return written

    async def handle_file_stat(self, path: str) -> FileInfo:
        """Handle file stat request"""
        if not self._validate_path(path):
            raise PermissionError(f"Access denied: {path}")

        if not os.path.exists(path):
            raise FileNotFoundError(f"Path not found: {path}")

        stat = os.stat(path)
        return FileInfo(
            name=os.path.basename(path),
            path=path,
            size=stat.st_size,
            is_dir=os.path.isdir(path),
            modified=stat.st_mtime,
            permissions=stat.st_mode & 0o777
        )

    async def run_message_loop(self):
        """Main message processing loop"""
        if not self._connected:
            raise ConnectionError("Not connected")

        logger.info("Starting VPN message loop")

        try:
            while self._connected:
                try:
                    message = await asyncio.wait_for(self.recv(), timeout=60)
                    await self._handle_message(message)
                except asyncio.TimeoutError:
                    # Send ping
                    await self.send(VPNMessage(msg_type=MessageType.PING))
                except ConnectionError:
                    break

        except Exception as e:
            logger.error(f"Message loop error: {e}")
        finally:
            await self.disconnect()

    async def _handle_message(self, message: VPNMessage):
        """Handle incoming message"""
        try:
            if message.msg_type == MessageType.PING:
                await self.send(VPNMessage(
                    msg_type=MessageType.PONG,
                    request_id=message.request_id
                ))

            elif message.msg_type == MessageType.FILE_LIST:
                path = message.payload.decode()
                try:
                    files = await self.handle_file_list(path)
                    response = json.dumps([f.to_dict() for f in files]).encode()
                    await self.send(VPNMessage(
                        msg_type=MessageType.FILE_LIST_RESPONSE,
                        request_id=message.request_id,
                        payload=response
                    ))
                except Exception as e:
                    await self._send_error(message.request_id, str(e))

            elif message.msg_type == MessageType.FILE_READ:
                try:
                    request = json.loads(message.payload.decode())
                    data = await self.handle_file_read(
                        request['path'],
                        request.get('offset', 0),
                        request.get('length', 0)
                    )
                    await self.send(VPNMessage(
                        msg_type=MessageType.FILE_READ_RESPONSE,
                        request_id=message.request_id,
                        payload=data
                    ))
                except Exception as e:
                    await self._send_error(message.request_id, str(e))

            elif message.msg_type == MessageType.FILE_WRITE:
                try:
                    # First 4 bytes: path length, then path, then data
                    path_len = struct.unpack('!I', message.payload[:4])[0]
                    path = message.payload[4:4+path_len].decode()
                    data = message.payload[4+path_len:]
                    written = await self.handle_file_write(path, data)
                    await self.send(VPNMessage(
                        msg_type=MessageType.FILE_WRITE_RESPONSE,
                        request_id=message.request_id,
                        payload=struct.pack('!I', written)
                    ))
                except Exception as e:
                    await self._send_error(message.request_id, str(e))

            elif message.msg_type == MessageType.FILE_STAT:
                try:
                    path = message.payload.decode()
                    info = await self.handle_file_stat(path)
                    await self.send(VPNMessage(
                        msg_type=MessageType.FILE_STAT_RESPONSE,
                        request_id=message.request_id,
                        payload=json.dumps(info.to_dict()).encode()
                    ))
                except Exception as e:
                    await self._send_error(message.request_id, str(e))

            elif message.msg_type == MessageType.NET_INFO:
                info = self._get_network_info()
                await self.send(VPNMessage(
                    msg_type=MessageType.NET_INFO_RESPONSE,
                    request_id=message.request_id,
                    payload=json.dumps(info).encode()
                ))

            elif message.msg_type == MessageType.DISCONNECT:
                logger.info("Received disconnect request")
                self._connected = False

            else:
                # Check registered handlers
                handler = self._message_handlers.get(message.msg_type)
                if handler:
                    await handler(message)
                else:
                    logger.warning(f"Unhandled message type: {message.msg_type}")

        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def _send_error(self, request_id: int, error_msg: str):
        """Send error response"""
        await self.send(VPNMessage(
            msg_type=MessageType.ERROR,
            request_id=request_id,
            payload=error_msg.encode()
        ))

    def _get_network_info(self) -> Dict[str, Any]:
        """Get local network information"""
        import socket
        return {
            'guardian_id': self.guardian_id,
            'hostname': socket.gethostname(),
            'allowed_paths': self.allowed_paths,
            'max_file_size_mb': self.max_file_size // (1024 * 1024),
            'stats': self.stats
        }

    def register_handler(self, msg_type: MessageType, handler: Callable):
        """Register message handler"""
        self._message_handlers[msg_type] = handler

    def get_statistics(self) -> Dict[str, Any]:
        """Get VPN statistics"""
        return {
            'connected': self._connected,
            'authenticated': self._authenticated,
            'guardian_id': self.guardian_id,
            'mssp_host': self.mssp_host,
            'stats': self.stats.copy()
        }


# ============================================================================
# WebSocket VPN Service
# ============================================================================

class WebSocketVPNService:
    """
    WebSocket VPN Service for Guardian

    Manages VPN client lifecycle with auto-reconnection.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.client: Optional[WebSocketVPNClient] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start VPN service"""
        self._running = True

        # Create client
        self.client = WebSocketVPNClient(
            mssp_host=self.config.get('mssp_host', 'mssp.hookprobe.com'),
            mssp_port=self.config.get('mssp_port', 443),
            websocket_path=self.config.get('websocket_path', '/ws/vpn'),
            guardian_id=self.config.get('guardian_id', ''),
            allowed_paths=self.config.get('allowed_paths', ['/home', '/srv/files']),
            max_file_size_mb=self.config.get('max_file_size_mb', 100)
        )

        # Load keys
        key_path = self.config.get('private_key_path', '/etc/guardian/keys/vpn.key')
        pub_path = self.config.get('public_key_path', '/etc/guardian/keys/vpn.pub')
        self.client.load_keys(key_path, pub_path)

        # Start connection loop
        self._task = asyncio.create_task(self._connection_loop())

        logger.info("WebSocket VPN service started")

    async def stop(self):
        """Stop VPN service"""
        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        if self.client:
            await self.client.disconnect()

        logger.info("WebSocket VPN service stopped")

    async def _connection_loop(self):
        """Maintain connection with auto-reconnect"""
        reconnect_delay = 5

        while self._running:
            try:
                if await self.client.connect():
                    reconnect_delay = 5  # Reset delay on successful connect
                    await self.client.run_message_loop()
                else:
                    logger.warning(f"Connection failed, retrying in {reconnect_delay}s")

            except Exception as e:
                logger.error(f"VPN error: {e}")

            if self._running:
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, 300)  # Max 5 minutes

    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        if self.client:
            return self.client.get_statistics()
        return {'running': self._running, 'connected': False}


# Export classes
__all__ = [
    'WebSocketVPNClient',
    'WebSocketVPNService',
    'NoiseState',
    'VPNMessage',
    'MessageType',
    'ErrorCode',
    'FileInfo',
]
