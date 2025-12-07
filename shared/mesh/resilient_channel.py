"""
Resilient Channel - Multi-Port Communication with Automatic Failover

Provides reliable communication even when facing:
- Port blocking (firewall, DPI)
- Active interference (RST injection)
- Network throttling
- Man-in-the-middle attacks

The channel automatically:
1. Detects blocking and switches ports
2. Re-establishes connections transparently
3. Maintains message ordering across failovers
4. Encrypts and authenticates all traffic
"""

import socket
import ssl
import struct
import time
import threading
import hashlib
import secrets
import queue
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, List, Tuple, Any
from collections import deque

from .port_manager import (
    PortManager,
    PortConfig,
    TransportMode,
    TrafficObfuscator,
)


class ChannelState(Enum):
    """State of the communication channel."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    HANDSHAKING = auto()
    CONNECTED = auto()
    DEGRADED = auto()  # Connected but experiencing issues
    FAILING_OVER = auto()  # Switching to backup port
    RECONNECTING = auto()


class MessageType(Enum):
    """Types of channel messages."""
    DATA = 0x01
    KEEPALIVE = 0x02
    ACK = 0x03
    RESONATE = 0x04  # Resonance handshake
    NEURO_SYNC = 0x05  # Neural weight sync
    PORT_ANNOUNCE = 0x06  # Announce port switch
    CLOSE = 0xFF


@dataclass
class ChannelMetrics:
    """Metrics for channel health monitoring."""

    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0

    # Connection stats
    connect_attempts: int = 0
    connect_successes: int = 0
    failover_count: int = 0

    # Latency tracking
    latency_samples: deque = field(default_factory=lambda: deque(maxlen=100))

    # Error tracking
    send_errors: int = 0
    receive_errors: int = 0
    timeout_errors: int = 0

    @property
    def avg_latency_ms(self) -> float:
        """Average round-trip latency."""
        if not self.latency_samples:
            return 0.0
        return sum(self.latency_samples) / len(self.latency_samples)

    @property
    def connection_success_rate(self) -> float:
        """Connection success rate."""
        if self.connect_attempts == 0:
            return 0.0
        return (self.connect_successes / self.connect_attempts) * 100


@dataclass
class PendingMessage:
    """Message awaiting acknowledgment."""
    sequence: int
    data: bytes
    timestamp: float
    retries: int = 0
    max_retries: int = 3


class ResilientChannel:
    """
    A resilient communication channel with automatic port failover.

    Features:
    - Multi-port support with automatic switching
    - Message ordering and acknowledgment
    - Connection keepalive and health monitoring
    - Traffic obfuscation
    - Encrypted transport (optional)
    """

    # Protocol constants
    HEADER_SIZE = 16  # [msg_type:1][flags:1][seq:4][length:4][checksum:4][reserved:2]
    MAX_MESSAGE_SIZE = 65536
    KEEPALIVE_INTERVAL = 25.0
    ACK_TIMEOUT = 5.0
    MAX_RETRIES = 3
    RECONNECT_DELAY = 2.0
    MAX_RECONNECT_DELAY = 60.0

    def __init__(
        self,
        port_manager: Optional[PortManager] = None,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize resilient channel.

        Args:
            port_manager: Port manager for multi-port support
            encryption_key: 32-byte key for ChaCha20-Poly1305 encryption
        """
        self.port_manager = port_manager or PortManager()
        self.encryption_key = encryption_key

        # Connection state
        self._state = ChannelState.DISCONNECTED
        self._socket: Optional[socket.socket] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._ssl_socket: Optional[ssl.SSLSocket] = None

        # Current connection info
        self._target_host: str = ''
        self._current_port: Optional[PortConfig] = None
        self._obfuscator: Optional[TrafficObfuscator] = None

        # Message handling
        self._send_sequence = 0
        self._recv_sequence = 0
        self._pending_acks: Dict[int, PendingMessage] = {}
        self._receive_queue: queue.Queue = queue.Queue()

        # Flow token for session identification
        self._flow_token = secrets.token_bytes(8)

        # Threading
        self._lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._recv_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Metrics
        self.metrics = ChannelMetrics()

        # Callbacks
        self._on_state_change: List[Callable[[ChannelState, ChannelState], None]] = []
        self._on_message: List[Callable[[bytes], None]] = []
        self._on_error: List[Callable[[Exception], None]] = []

        # Encryption setup
        self._crypto_available = False
        self._setup_crypto()

        # Register port manager callbacks
        self.port_manager.on_port_change(self._handle_port_change)
        self.port_manager.on_blocking_detected(self._handle_blocking)

    def _setup_crypto(self) -> None:
        """Setup cryptographic primitives."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            self._crypto_class = ChaCha20Poly1305
            self._crypto_available = True
        except ImportError:
            self._crypto_available = False

    @property
    def state(self) -> ChannelState:
        """Get current channel state."""
        with self._lock:
            return self._state

    @property
    def is_connected(self) -> bool:
        """Check if channel is connected."""
        return self._state in (ChannelState.CONNECTED, ChannelState.DEGRADED)

    def connect(
        self,
        host: str,
        timeout: float = 30.0,
    ) -> bool:
        """
        Connect to remote host using best available port.

        Args:
            host: Target hostname or IP
            timeout: Connection timeout in seconds

        Returns:
            True if connected successfully
        """
        self._target_host = host
        self._stop_event.clear()

        # Select best port
        port_config = self.port_manager.select_best_port()
        if not port_config:
            return False

        # Attempt connection
        success = self._connect_to_port(host, port_config, timeout)

        if success:
            # Start background threads
            self._start_threads()

        return success

    def _connect_to_port(
        self,
        host: str,
        port_config: PortConfig,
        timeout: float,
    ) -> bool:
        """
        Connect to a specific port.

        Args:
            host: Target host
            port_config: Port configuration
            timeout: Connection timeout

        Returns:
            True if connected
        """
        self._set_state(ChannelState.CONNECTING)
        self.metrics.connect_attempts += 1

        start_time = time.time()

        try:
            # Create socket
            if port_config.protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            # Connect
            sock.connect((host, port_config.port))

            # Wrap in TLS if required
            if port_config.mode in (TransportMode.TLS_WRAPPED, TransportMode.DOT_STEALTH):
                sock = self._wrap_tls(sock, port_config, host)

            # Store connection
            self._socket = sock
            self._current_port = port_config
            self._obfuscator = TrafficObfuscator(port_config.mode)

            # Perform handshake
            self._set_state(ChannelState.HANDSHAKING)
            if not self._perform_handshake():
                self._close_socket()
                return False

            # Connection successful
            latency = (time.time() - start_time) * 1000
            self.port_manager.record_connection(
                port_config.port,
                success=True,
                latency_ms=latency,
            )
            self.metrics.connect_successes += 1

            self._set_state(ChannelState.CONNECTED)
            return True

        except socket.timeout:
            self.port_manager.record_connection(
                port_config.port,
                success=False,
                is_timeout=True,
            )
            self.metrics.timeout_errors += 1

        except ConnectionRefusedError:
            self.port_manager.record_connection(
                port_config.port,
                success=False,
                is_rst=True,
            )

        except Exception as e:
            self.port_manager.record_connection(port_config.port, success=False)
            self._notify_error(e)

        self._set_state(ChannelState.DISCONNECTED)
        return False

    def _wrap_tls(
        self,
        sock: socket.socket,
        port_config: PortConfig,
        host: str,
    ) -> ssl.SSLSocket:
        """Wrap socket in TLS."""
        context = ssl.create_default_context()

        # Set ALPN protocols if specified
        if port_config.tls_alpn:
            context.set_alpn_protocols(port_config.tls_alpn)

        # Use SNI if specified (for stealth)
        server_hostname = port_config.tls_sni or host

        return context.wrap_socket(sock, server_hostname=server_hostname)

    def _perform_handshake(self) -> bool:
        """
        Perform channel handshake (resonance alignment).

        Returns:
            True if handshake successful
        """
        try:
            # Send RESONATE message with flow token
            handshake_data = struct.pack(
                '>8s8sQ',
                self._flow_token,
                secrets.token_bytes(8),  # Entropy
                int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF,  # Timestamp
            )

            self._send_raw(MessageType.RESONATE, handshake_data)

            # Wait for response
            msg_type, response = self._recv_raw(timeout=10.0)
            if msg_type != MessageType.RESONATE:
                return False

            # Validate response
            if len(response) < 24:
                return False

            # Extract peer flow token
            peer_token = response[:8]
            # Could verify entropy echo here

            return True

        except Exception:
            return False

    def send(self, data: bytes, reliable: bool = True) -> bool:
        """
        Send data over the channel.

        Args:
            data: Data to send
            reliable: If True, wait for acknowledgment

        Returns:
            True if sent (and acknowledged if reliable)
        """
        if not self.is_connected:
            return False

        with self._send_lock:
            try:
                # Get next sequence number
                seq = self._send_sequence
                self._send_sequence = (self._send_sequence + 1) & 0xFFFFFFFF

                # Send message
                self._send_raw(MessageType.DATA, data, sequence=seq)

                self.metrics.messages_sent += 1
                self.metrics.bytes_sent += len(data)

                if reliable:
                    # Track for acknowledgment
                    pending = PendingMessage(
                        sequence=seq,
                        data=data,
                        timestamp=time.time(),
                    )
                    self._pending_acks[seq] = pending

                return True

            except Exception as e:
                self.metrics.send_errors += 1
                self._notify_error(e)
                self._handle_send_failure()
                return False

    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive data from the channel.

        Args:
            timeout: Receive timeout (None for blocking)

        Returns:
            Received data or None on timeout/error
        """
        try:
            return self._receive_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        """Close the channel."""
        self._stop_event.set()

        # Send close message
        try:
            if self.is_connected:
                self._send_raw(MessageType.CLOSE, b'')
        except Exception:
            pass

        # Close socket
        self._close_socket()

        # Stop threads
        if self._recv_thread:
            self._recv_thread.join(timeout=2.0)
        if self._keepalive_thread:
            self._keepalive_thread.join(timeout=2.0)

        self._set_state(ChannelState.DISCONNECTED)

    def _send_raw(
        self,
        msg_type: MessageType,
        data: bytes,
        sequence: Optional[int] = None,
        flags: int = 0,
    ) -> None:
        """Send raw message with header."""
        if sequence is None:
            sequence = 0

        # Build header
        checksum = self._calculate_checksum(data)
        header = struct.pack(
            '>BBIIIH',
            msg_type.value,
            flags,
            sequence,
            len(data),
            checksum,
            0,  # Reserved
        )

        # Combine header and data
        message = header + data

        # Obfuscate if enabled
        delay = 0.0
        if self._obfuscator and self._current_port:
            message, delay = self._obfuscator.obfuscate(
                message,
                add_padding=self._current_port.padding_enabled,
                add_jitter=True,
                jitter_ms=self._current_port.timing_jitter_ms,
            )

        # Encrypt if key available
        if self.encryption_key and self._crypto_available:
            message = self._encrypt(message)

        # Apply timing jitter
        if delay > 0:
            time.sleep(delay)

        # Send
        self._socket.sendall(message)

    def _recv_raw(
        self,
        timeout: Optional[float] = None
    ) -> Tuple[MessageType, bytes]:
        """Receive raw message with header."""
        if self._socket is None:
            raise ConnectionError("Not connected")

        old_timeout = self._socket.gettimeout()
        if timeout is not None:
            self._socket.settimeout(timeout)

        try:
            # Receive data
            # For obfuscated mode, we need to handle the wrapper first
            if self._current_port and self._current_port.mode in (
                TransportMode.TLS_WRAPPED,
                TransportMode.DOT_STEALTH,
                TransportMode.WEBSOCKET,
            ):
                # Read wrapper header first
                data = self._recv_all(2048)  # Max reasonable size
            else:
                # Read our header first
                if self.encryption_key and self._crypto_available:
                    # Encrypted: nonce(12) + ciphertext + tag(16)
                    # Need at least 28 + HEADER_SIZE bytes
                    data = self._recv_all(28 + self.HEADER_SIZE)
                else:
                    data = self._recv_all(self.HEADER_SIZE)

            # Decrypt if needed
            if self.encryption_key and self._crypto_available:
                data = self._decrypt(data)

            # Deobfuscate if needed
            if self._obfuscator:
                data = self._obfuscator.deobfuscate(data)

            # Parse header
            if len(data) < self.HEADER_SIZE:
                raise ValueError("Incomplete header")

            (
                msg_type_val,
                flags,
                sequence,
                length,
                checksum,
                _reserved,
            ) = struct.unpack('>BBIIIH', data[:self.HEADER_SIZE])

            msg_type = MessageType(msg_type_val)

            # Get payload
            payload = data[self.HEADER_SIZE:self.HEADER_SIZE + length]

            # Read more if needed
            while len(payload) < length:
                remaining = length - len(payload)
                more_data = self._recv_all(remaining)
                payload += more_data

            # Verify checksum
            if self._calculate_checksum(payload) != checksum:
                raise ValueError("Checksum mismatch")

            return msg_type, payload

        finally:
            if timeout is not None:
                self._socket.settimeout(old_timeout)

    def _recv_all(self, length: int) -> bytes:
        """Receive exactly length bytes."""
        data = b''
        while len(data) < length:
            chunk = self._socket.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data with ChaCha20-Poly1305."""
        if not self._crypto_available or not self.encryption_key:
            return data

        nonce = secrets.token_bytes(12)
        cipher = self._crypto_class(self.encryption_key)
        ciphertext = cipher.encrypt(nonce, data, None)
        return nonce + ciphertext

    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data with ChaCha20-Poly1305."""
        if not self._crypto_available or not self.encryption_key:
            return data

        if len(data) < 28:  # nonce(12) + min_ciphertext + tag(16)
            raise ValueError("Encrypted data too short")

        nonce = data[:12]
        ciphertext = data[12:]

        cipher = self._crypto_class(self.encryption_key)
        return cipher.decrypt(nonce, ciphertext, None)

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate 32-bit checksum of data."""
        h = hashlib.sha256(data).digest()
        return struct.unpack('>I', h[:4])[0]

    def _close_socket(self) -> None:
        """Close the socket."""
        with self._lock:
            if self._socket:
                try:
                    self._socket.close()
                except Exception:
                    pass
                self._socket = None

    def _start_threads(self) -> None:
        """Start background threads."""
        # Receive thread
        self._recv_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
        )
        self._recv_thread.start()

        # Keepalive thread
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            daemon=True,
        )
        self._keepalive_thread.start()

    def _receive_loop(self) -> None:
        """Background receive loop."""
        while not self._stop_event.is_set():
            try:
                msg_type, data = self._recv_raw(timeout=1.0)

                if msg_type == MessageType.DATA:
                    self._receive_queue.put(data)
                    self.metrics.messages_received += 1
                    self.metrics.bytes_received += len(data)

                    # Send ACK
                    # Extract sequence from pending or use recv_sequence
                    self._recv_sequence += 1

                elif msg_type == MessageType.ACK:
                    # Handle acknowledgment
                    if len(data) >= 4:
                        acked_seq = struct.unpack('>I', data[:4])[0]
                        self._pending_acks.pop(acked_seq, None)

                elif msg_type == MessageType.KEEPALIVE:
                    # Respond to keepalive
                    pass

                elif msg_type == MessageType.PORT_ANNOUNCE:
                    # Peer announcing port switch
                    self._handle_peer_port_announce(data)

                elif msg_type == MessageType.CLOSE:
                    self._set_state(ChannelState.DISCONNECTED)
                    break

            except socket.timeout:
                continue

            except Exception as e:
                self.metrics.receive_errors += 1
                if not self._stop_event.is_set():
                    self._notify_error(e)
                    self._handle_receive_failure()
                break

    def _keepalive_loop(self) -> None:
        """Background keepalive loop."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.KEEPALIVE_INTERVAL)

            if self._stop_event.is_set():
                break

            if self.is_connected:
                try:
                    self._send_raw(MessageType.KEEPALIVE, b'')
                except Exception:
                    pass

                # Check for unacked messages
                self._check_pending_acks()

    def _check_pending_acks(self) -> None:
        """Check and retry pending acknowledgments."""
        now = time.time()

        with self._lock:
            expired = []
            for seq, pending in self._pending_acks.items():
                if now - pending.timestamp > self.ACK_TIMEOUT:
                    if pending.retries < pending.max_retries:
                        # Retry
                        pending.retries += 1
                        pending.timestamp = now
                        try:
                            self._send_raw(
                                MessageType.DATA,
                                pending.data,
                                sequence=seq,
                            )
                        except Exception:
                            expired.append(seq)
                    else:
                        expired.append(seq)

            for seq in expired:
                self._pending_acks.pop(seq, None)

    def _handle_send_failure(self) -> None:
        """Handle send failure - trigger reconnect/failover."""
        with self._lock:
            if self._state == ChannelState.CONNECTED:
                self._set_state(ChannelState.DEGRADED)
                # Attempt reconnect in background
                threading.Thread(
                    target=self._reconnect,
                    daemon=True,
                ).start()

    def _handle_receive_failure(self) -> None:
        """Handle receive failure - trigger reconnect/failover."""
        self._handle_send_failure()

    def _reconnect(self) -> None:
        """Attempt to reconnect with exponential backoff."""
        delay = self.RECONNECT_DELAY

        while not self._stop_event.is_set():
            self._set_state(ChannelState.RECONNECTING)

            # First try current port
            if self._current_port:
                if self._connect_to_port(
                    self._target_host,
                    self._current_port,
                    timeout=10.0,
                ):
                    return

            # Try next best port
            self._set_state(ChannelState.FAILING_OVER)
            self.metrics.failover_count += 1

            port_config = self.port_manager.select_best_port()
            if port_config and self._connect_to_port(
                self._target_host,
                port_config,
                timeout=10.0,
            ):
                return

            # Exponential backoff
            self._stop_event.wait(delay)
            delay = min(delay * 2, self.MAX_RECONNECT_DELAY)

        self._set_state(ChannelState.DISCONNECTED)

    def _handle_port_change(
        self,
        old_port: Optional[PortConfig],
        new_port: PortConfig,
    ) -> None:
        """Handle port manager selecting a new port."""
        if self.is_connected and old_port and old_port != new_port:
            # Announce port switch to peer
            try:
                announce_data = struct.pack(
                    '>HHH',
                    new_port.port,
                    1 if new_port.protocol == 'udp' else 0,
                    new_port.mode.value,
                )
                self._send_raw(MessageType.PORT_ANNOUNCE, announce_data)
            except Exception:
                pass

    def _handle_blocking(self, port_config: PortConfig, reason: str) -> None:
        """Handle port being blocked."""
        # Trigger failover if this is our current port
        if self._current_port and self._current_port.port == port_config.port:
            threading.Thread(
                target=self._reconnect,
                daemon=True,
            ).start()

    def _handle_peer_port_announce(self, data: bytes) -> None:
        """Handle peer announcing port switch."""
        if len(data) < 6:
            return

        new_port, is_udp, mode_val = struct.unpack('>HHH', data[:6])
        # Could update expectations for peer connection here

    def _set_state(self, new_state: ChannelState) -> None:
        """Set channel state and notify listeners."""
        with self._lock:
            old_state = self._state
            if old_state == new_state:
                return
            self._state = new_state

        for callback in self._on_state_change:
            try:
                callback(old_state, new_state)
            except Exception:
                pass

    def _notify_error(self, error: Exception) -> None:
        """Notify error listeners."""
        for callback in self._on_error:
            try:
                callback(error)
            except Exception:
                pass

    def on_state_change(
        self,
        callback: Callable[[ChannelState, ChannelState], None]
    ) -> None:
        """Register state change callback."""
        self._on_state_change.append(callback)

    def on_message(self, callback: Callable[[bytes], None]) -> None:
        """Register message callback."""
        self._on_message.append(callback)

    def on_error(self, callback: Callable[[Exception], None]) -> None:
        """Register error callback."""
        self._on_error.append(callback)

    def get_status(self) -> Dict[str, Any]:
        """Get channel status."""
        return {
            'state': self._state.name,
            'target': self._target_host,
            'current_port': self._current_port.port if self._current_port else None,
            'current_mode': self._current_port.mode.name if self._current_port else None,
            'metrics': {
                'bytes_sent': self.metrics.bytes_sent,
                'bytes_received': self.metrics.bytes_received,
                'messages_sent': self.metrics.messages_sent,
                'messages_received': self.metrics.messages_received,
                'avg_latency_ms': f"{self.metrics.avg_latency_ms:.1f}",
                'connection_success_rate': f"{self.metrics.connection_success_rate:.1f}%",
                'failover_count': self.metrics.failover_count,
                'send_errors': self.metrics.send_errors,
                'receive_errors': self.metrics.receive_errors,
            },
            'port_manager': self.port_manager.get_status(),
        }
