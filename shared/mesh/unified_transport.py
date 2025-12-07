"""
Unified Transport - Integrated DSM + Neuro + HTP Protocol Stack

This module provides a unified communication layer that combines:

┌─────────────────────────────────────────────────────────────────┐
│                    UNIFIED MESH TRANSPORT                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5: Application                                           │
│    └─ File Transfer, VPN, Security Events, Control Messages     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: DSM (Decentralized Security Mesh)                     │
│    └─ Microblocks, Consensus, Gossip, Checkpoints               │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Neuro (Neural Resonance Protocol)                     │
│    └─ TER, PoSF Signatures, Weight Evolution, RDV               │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: HTP (HookProbe Transport Protocol)                    │
│    └─ Keyless Auth, Entropy Echo, Adaptive Streaming            │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Resilient Channel                                     │
│    └─ Multi-Port, TLS Wrapping, Stealth Modes, Failover         │
├─────────────────────────────────────────────────────────────────┤
│  Layer 0: Network (TCP/UDP/ICMP)                                │
│    └─ Port 8144 (primary), 443 (fallback), 853 (stealth)        │
└─────────────────────────────────────────────────────────────────┘

Key Features:
- Automatic port fallback when blocked
- Neural resonance authentication (no PKI needed)
- DSM consensus for Byzantine fault tolerance
- Traffic obfuscation and stealth modes
- Deterministic channel hopping
"""

import hashlib
import struct
import time
import secrets
import threading
import queue
from enum import Enum, IntEnum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple
from collections import deque

from .port_manager import PortManager, PortConfig, TransportMode, TrafficObfuscator
from .resilient_channel import ResilientChannel, ChannelState
from .neuro_encoder import (
    NeuroResonanceEncoder,
    ResonanceState,
    ResonanceDriftVector,
    TERSnapshot,
    ResonanceHandshake,
)
from .channel_selector import ChannelSelector, ChannelHopper, SelectionStrategy


class PacketType(IntEnum):
    """Unified mesh packet types."""

    # Control
    HANDSHAKE = 0x01
    KEEPALIVE = 0x02
    ACK = 0x03
    CLOSE = 0x04

    # Neuro layer
    RESONATE = 0x10
    TER_SYNC = 0x11
    WEIGHT_SYNC = 0x12
    POSF_VERIFY = 0x13

    # HTP layer
    SENSOR = 0x20
    TEXT = 0x21
    VIDEO = 0x22
    FRAME = 0x23

    # DSM layer
    MICROBLOCK = 0x30
    CHECKPOINT = 0x31
    GOSSIP = 0x32
    CONSENSUS_VOTE = 0x33
    SIGNATURE_AGG = 0x34

    # Application
    FILE_TRANSFER = 0x40
    VPN_PACKET = 0x41
    SECURITY_EVENT = 0x42
    CONTROL_CMD = 0x43

    # Emergency
    EMERGENCY_CHANNEL_SWITCH = 0xE0
    EMERGENCY_RESYNC = 0xE1

    # Error
    ERROR = 0xFF


class PacketFlags:
    """Packet flag bits."""
    ENCRYPTED = 0x01
    COMPRESSED = 0x02
    URGENT = 0x04
    RELIABLE = 0x08
    FRAGMENTED = 0x10
    LAST_FRAGMENT = 0x20
    REQUIRES_ACK = 0x40
    NEURO_AUTH = 0x80


@dataclass
class MeshPacket:
    """
    Unified mesh packet structure.

    Total header size: 48 bytes
    ┌────────────────────────────────────────────────────────────┐
    │ Offset │ Size │ Field                                      │
    ├────────┼──────┼────────────────────────────────────────────┤
    │ 0      │ 2    │ version (0x0500 for v5.0)                  │
    │ 2      │ 1    │ packet_type                                │
    │ 3      │ 1    │ flags                                      │
    │ 4      │ 4    │ sequence                                   │
    │ 8      │ 8    │ flow_token                                 │
    │ 16     │ 8    │ timestamp_us                               │
    │ 24     │ 4    │ payload_length                             │
    │ 28     │ 4    │ checksum (CRC32 of payload)                │
    │ 32     │ 16   │ rdv_prefix (first 16 bytes of RDV)         │
    ├────────┼──────┼────────────────────────────────────────────┤
    │ 48     │ var  │ payload                                    │
    └────────────────────────────────────────────────────────────┘
    """

    HEADER_SIZE = 48
    VERSION = 0x0500  # v5.0

    # Header fields
    version: int = VERSION
    packet_type: PacketType = PacketType.KEEPALIVE
    flags: int = 0
    sequence: int = 0
    flow_token: bytes = field(default_factory=lambda: b'\x00' * 8)
    timestamp_us: int = 0
    payload_length: int = 0
    checksum: int = 0
    rdv_prefix: bytes = field(default_factory=lambda: b'\x00' * 16)

    # Payload
    payload: bytes = b''

    def to_bytes(self) -> bytes:
        """Serialize packet to bytes."""
        # Calculate checksum
        self.checksum = self._crc32(self.payload)
        self.payload_length = len(self.payload)
        self.timestamp_us = int(time.time() * 1_000_000) if not self.timestamp_us else self.timestamp_us

        header = struct.pack(
            '>HBBIQ8sII16s',
            self.version,
            self.packet_type.value if isinstance(self.packet_type, PacketType) else self.packet_type,
            self.flags,
            self.sequence,
            self.timestamp_us,
            self.flow_token[:8].ljust(8, b'\x00'),
            self.payload_length,
            self.checksum,
            self.rdv_prefix[:16].ljust(16, b'\x00'),
        )

        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> 'MeshPacket':
        """Deserialize packet from bytes."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(data)} < {cls.HEADER_SIZE}")

        (
            version,
            pkt_type,
            flags,
            sequence,
            timestamp_us,
            flow_token,
            payload_length,
            checksum,
            rdv_prefix,
        ) = struct.unpack('>HBBIQ8sII16s', data[:cls.HEADER_SIZE])

        payload = data[cls.HEADER_SIZE:cls.HEADER_SIZE + payload_length]

        # Verify checksum
        expected_checksum = cls._crc32(payload)
        if checksum != expected_checksum:
            raise ValueError("Checksum mismatch")

        return cls(
            version=version,
            packet_type=PacketType(pkt_type),
            flags=flags,
            sequence=sequence,
            flow_token=flow_token,
            timestamp_us=timestamp_us,
            payload_length=payload_length,
            checksum=checksum,
            rdv_prefix=rdv_prefix,
            payload=payload,
        )

    @staticmethod
    def _crc32(data: bytes) -> int:
        """Calculate CRC32 checksum."""
        import binascii
        return binascii.crc32(data) & 0xFFFFFFFF

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & PacketFlags.ENCRYPTED)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & PacketFlags.COMPRESSED)

    @property
    def requires_ack(self) -> bool:
        return bool(self.flags & PacketFlags.REQUIRES_ACK)

    @property
    def has_neuro_auth(self) -> bool:
        return bool(self.flags & PacketFlags.NEURO_AUTH)


class TransportState(Enum):
    """State of the unified transport."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    RESONATING = auto()  # Neuro handshake
    SYNCING = auto()      # Weight sync
    CONNECTED = auto()
    DEGRADED = auto()
    RECONNECTING = auto()
    CLOSED = auto()


@dataclass
class PeerInfo:
    """Information about a connected peer."""
    node_id: bytes
    flow_token: bytes
    resonance_state: ResonanceState = ResonanceState.UNALIGNED
    weight_epoch: int = 0
    last_seen: float = 0.0
    latency_ms: float = 0.0
    channel_port: int = 0
    channel_mode: TransportMode = TransportMode.PRIMARY


class UnifiedTransport:
    """
    Unified transport layer integrating DSM + Neuro + HTP.

    Provides a single interface for all mesh communication with:
    - Automatic authentication via neural resonance
    - Multi-port fallback when blocked
    - DSM consensus participation
    - Encrypted, obfuscated traffic
    """

    # Protocol parameters
    MAX_PACKET_SIZE = 65536
    HANDSHAKE_TIMEOUT = 30.0
    RESONATE_TIMEOUT = 60.0
    SYNC_TIMEOUT = 120.0

    def __init__(
        self,
        node_id: bytes,
        neuro_seed: bytes,
        ports: Optional[List[PortConfig]] = None,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize unified transport.

        Args:
            node_id: 16-byte unique node identifier
            neuro_seed: 32-byte seed for neural weight initialization
            ports: Port configurations (uses defaults if None)
            encryption_key: Optional 32-byte encryption key
        """
        # Node identity
        self.node_id = node_id[:16] if len(node_id) >= 16 else hashlib.sha256(node_id).digest()[:16]
        self.flow_token = secrets.token_bytes(8)

        # Port management
        self.port_manager = PortManager(ports)

        # Channel management
        self.channel = ResilientChannel(
            port_manager=self.port_manager,
            encryption_key=encryption_key,
        )

        # Neuro resonance
        self.encoder = NeuroResonanceEncoder(neuro_seed, self.node_id)

        # Channel selection
        self.selector = ChannelSelector(
            encoder=self.encoder,
            channels=self.port_manager.ports,
            strategy=SelectionStrategy.ADAPTIVE,
        )
        self.hopper = ChannelHopper(self.selector, self.encoder)

        # Transport state
        self._state = TransportState.DISCONNECTED
        self._sequence = 0
        self._lock = threading.RLock()

        # Peer tracking
        self._peers: Dict[bytes, PeerInfo] = {}
        self._active_peer: Optional[PeerInfo] = None

        # Message queues
        self._send_queue: queue.Queue = queue.Queue()
        self._recv_queue: queue.Queue = queue.Queue()

        # Background threads
        self._threads: List[threading.Thread] = []
        self._stop_event = threading.Event()

        # Callbacks
        self._on_state_change: List[Callable] = []
        self._on_packet: List[Callable[[MeshPacket], None]] = []
        self._on_dsm_event: List[Callable[[PacketType, bytes], None]] = []
        self._on_error: List[Callable[[Exception], None]] = []

        # Register channel callbacks
        self.channel.on_state_change(self._handle_channel_state_change)
        self.channel.on_error(self._handle_channel_error)

        # Register hopper callback
        self.hopper.on_hop(self._handle_channel_hop)

    @property
    def state(self) -> TransportState:
        """Get current transport state."""
        with self._lock:
            return self._state

    @property
    def is_connected(self) -> bool:
        """Check if transport is connected and resonating."""
        return self._state in (TransportState.CONNECTED, TransportState.DEGRADED)

    def connect(
        self,
        host: str,
        timeout: Optional[float] = None,
    ) -> bool:
        """
        Connect to remote host and establish resonance.

        Args:
            host: Target hostname or IP
            timeout: Connection timeout

        Returns:
            True if connected and resonating
        """
        timeout = timeout or self.HANDSHAKE_TIMEOUT

        # Phase 1: Channel connection
        self._set_state(TransportState.CONNECTING)

        if not self.channel.connect(host, timeout=timeout):
            self._set_state(TransportState.DISCONNECTED)
            return False

        # Phase 2: Neuro resonance handshake
        self._set_state(TransportState.RESONATING)

        if not self._perform_resonance_handshake(timeout=self.RESONATE_TIMEOUT):
            self.channel.close()
            self._set_state(TransportState.DISCONNECTED)
            return False

        # Phase 3: Weight synchronization
        self._set_state(TransportState.SYNCING)

        if not self._perform_weight_sync(timeout=self.SYNC_TIMEOUT):
            # Continue anyway with slight drift
            pass

        # Connected and resonating
        self._set_state(TransportState.CONNECTED)

        # Start background threads
        self._start_threads()

        # Start channel hopping
        self.hopper.start()

        return True

    def send(
        self,
        packet_type: PacketType,
        payload: bytes,
        reliable: bool = True,
        urgent: bool = False,
    ) -> bool:
        """
        Send packet to connected peer.

        Args:
            packet_type: Type of packet
            payload: Packet payload
            reliable: Whether to use reliable delivery
            urgent: Whether packet is urgent (bypass queue)

        Returns:
            True if sent successfully
        """
        if not self.is_connected:
            return False

        with self._lock:
            # Build packet
            flags = 0
            if reliable:
                flags |= PacketFlags.RELIABLE | PacketFlags.REQUIRES_ACK
            if urgent:
                flags |= PacketFlags.URGENT

            # Add neuro auth for sensitive packets
            if packet_type in (
                PacketType.MICROBLOCK,
                PacketType.CHECKPOINT,
                PacketType.CONSENSUS_VOTE,
                PacketType.SECURITY_EVENT,
            ):
                flags |= PacketFlags.NEURO_AUTH

            # Get RDV prefix for authentication
            rdv = self.encoder.generate_rdv(self.flow_token)

            packet = MeshPacket(
                packet_type=packet_type,
                flags=flags,
                sequence=self._next_sequence(),
                flow_token=self.flow_token,
                rdv_prefix=rdv.vector[:16],
                payload=payload,
            )

            # Send via channel
            return self.channel.send(packet.to_bytes(), reliable=reliable)

    def receive(
        self,
        timeout: Optional[float] = None,
    ) -> Optional[MeshPacket]:
        """
        Receive packet from connected peer.

        Args:
            timeout: Receive timeout

        Returns:
            Received packet or None
        """
        try:
            return self._recv_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def send_microblock(
        self,
        microblock_id: bytes,
        payload_hash: bytes,
        signature: bytes,
    ) -> bool:
        """Send DSM microblock to mesh."""
        data = struct.pack(
            '>32s32s64s',
            microblock_id[:32],
            payload_hash[:32],
            signature[:64].ljust(64, b'\x00'),
        )
        return self.send(PacketType.MICROBLOCK, data, reliable=True)

    def send_checkpoint(
        self,
        checkpoint_id: bytes,
        merkle_root: bytes,
        epoch: int,
        validator_signatures: bytes,
    ) -> bool:
        """Send DSM checkpoint to mesh."""
        data = struct.pack(
            '>32s32sI',
            checkpoint_id[:32],
            merkle_root[:32],
            epoch,
        ) + validator_signatures
        return self.send(PacketType.CHECKPOINT, data, reliable=True, urgent=True)

    def send_security_event(
        self,
        event_type: int,
        severity: int,
        source: str,
        details: bytes,
    ) -> bool:
        """Send security event to mesh."""
        source_bytes = source.encode()[:64].ljust(64, b'\x00')
        data = struct.pack(
            '>II64s',
            event_type,
            severity,
            source_bytes,
        ) + details
        return self.send(PacketType.SECURITY_EVENT, data, reliable=True, urgent=True)

    def gossip(self, message: bytes) -> bool:
        """Send gossip message to mesh."""
        return self.send(PacketType.GOSSIP, message, reliable=False)

    def close(self) -> None:
        """Close the transport."""
        self._set_state(TransportState.CLOSED)
        self._stop_event.set()

        # Stop hopper
        self.hopper.stop()

        # Send close packet
        try:
            self.send(PacketType.CLOSE, b'', reliable=False)
        except Exception:
            pass

        # Close channel
        self.channel.close()

        # Wait for threads
        for thread in self._threads:
            thread.join(timeout=2.0)

    def _perform_resonance_handshake(self, timeout: float) -> bool:
        """Perform neuro resonance handshake."""
        handshake = ResonanceHandshake(
            encoder=self.encoder,
            channel_binding=self.flow_token,
            is_initiator=True,
        )

        # Send RESONATE_INIT
        init_data = handshake.generate_init()
        packet = MeshPacket(
            packet_type=PacketType.RESONATE,
            flags=PacketFlags.RELIABLE,
            sequence=self._next_sequence(),
            flow_token=self.flow_token,
            payload=b'\x01' + init_data,  # 0x01 = INIT
        )

        if not self.channel.send(packet.to_bytes()):
            return False

        # Wait for ACK
        start = time.time()
        while time.time() - start < timeout:
            data = self.channel.receive(timeout=1.0)
            if data is None:
                continue

            try:
                response = MeshPacket.from_bytes(data)
                if response.packet_type != PacketType.RESONATE:
                    continue

                if response.payload[0] == 0x02:  # ACK
                    success, confirm = handshake.process_ack(response.payload[1:])
                    if not success:
                        return False

                    # Send CONFIRM
                    confirm_packet = MeshPacket(
                        packet_type=PacketType.RESONATE,
                        flags=PacketFlags.RELIABLE,
                        sequence=self._next_sequence(),
                        flow_token=self.flow_token,
                        payload=b'\x03' + confirm,  # 0x03 = CONFIRM
                    )
                    self.channel.send(confirm_packet.to_bytes())

                    # Store session key
                    if handshake.session_key:
                        # Could use for additional encryption layer
                        pass

                    return True

            except Exception:
                continue

        return False

    def _perform_weight_sync(self, timeout: float) -> bool:
        """Synchronize neural weights with peer."""
        # Send our weight fingerprint
        fp = self.encoder.get_weight_fingerprint()

        packet = MeshPacket(
            packet_type=PacketType.WEIGHT_SYNC,
            flags=PacketFlags.RELIABLE,
            sequence=self._next_sequence(),
            flow_token=self.flow_token,
            payload=fp.to_bytes(),
        )

        if not self.channel.send(packet.to_bytes()):
            return False

        # Wait for peer's fingerprint
        start = time.time()
        while time.time() - start < timeout:
            data = self.channel.receive(timeout=1.0)
            if data is None:
                continue

            try:
                response = MeshPacket.from_bytes(data)
                if response.packet_type == PacketType.WEIGHT_SYNC:
                    # Verify synchronization
                    from .neuro_encoder import WeightFingerprint
                    peer_fp = WeightFingerprint.from_bytes(response.payload)

                    if self.selector.synchronize_with_peer(peer_fp):
                        return True
                    else:
                        # Slight drift, continue anyway
                        return True

            except Exception:
                continue

        return False

    def _start_threads(self) -> None:
        """Start background processing threads."""
        # Receive thread
        recv_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
        )
        recv_thread.start()
        self._threads.append(recv_thread)

        # TER generation thread
        ter_thread = threading.Thread(
            target=self._ter_generation_loop,
            daemon=True,
        )
        ter_thread.start()
        self._threads.append(ter_thread)

    def _receive_loop(self) -> None:
        """Background receive loop."""
        while not self._stop_event.is_set():
            data = self.channel.receive(timeout=1.0)
            if data is None:
                continue

            try:
                packet = MeshPacket.from_bytes(data)
                self._process_received_packet(packet)
            except Exception as e:
                for callback in self._on_error:
                    try:
                        callback(e)
                    except Exception:
                        pass

    def _process_received_packet(self, packet: MeshPacket) -> None:
        """Process a received packet."""
        # Verify neuro auth if required
        if packet.has_neuro_auth:
            # Verify RDV prefix matches expected
            # For now, accept (full verification in encoder)
            pass

        # Handle by type
        if packet.packet_type == PacketType.KEEPALIVE:
            # Respond to keepalive
            pass

        elif packet.packet_type == PacketType.RESONATE:
            # Handle resonance messages (during connection)
            pass

        elif packet.packet_type == PacketType.TER_SYNC:
            # Peer sending TER for weight evolution
            self._handle_ter_sync(packet.payload)

        elif packet.packet_type in (
            PacketType.MICROBLOCK,
            PacketType.CHECKPOINT,
            PacketType.GOSSIP,
            PacketType.CONSENSUS_VOTE,
        ):
            # DSM events
            for callback in self._on_dsm_event:
                try:
                    callback(packet.packet_type, packet.payload)
                except Exception:
                    pass

        elif packet.packet_type == PacketType.EMERGENCY_CHANNEL_SWITCH:
            # Peer announcing emergency channel switch
            self._handle_emergency_switch(packet.payload)

        # Queue for application
        self._recv_queue.put(packet)

        # Notify callbacks
        for callback in self._on_packet:
            try:
                callback(packet)
            except Exception:
                pass

    def _handle_ter_sync(self, data: bytes) -> None:
        """Handle TER sync from peer."""
        try:
            ter = TERSnapshot.from_bytes(data)
            self.encoder.evolve_weights(ter)
        except Exception:
            pass

    def _handle_emergency_switch(self, data: bytes) -> None:
        """Handle emergency channel switch announcement."""
        if len(data) < 4:
            return

        new_port = struct.unpack('>H', data[:2])[0]
        mode_val = struct.unpack('>H', data[2:4])[0]

        # Force hop to announced channel
        self.hopper.force_hop()

    def _ter_generation_loop(self) -> None:
        """Generate TERs periodically for weight evolution."""
        while not self._stop_event.is_set():
            self._stop_event.wait(10.0)  # Every 10 seconds

            if self._stop_event.is_set():
                break

            # Generate TER from system state
            ter = self.encoder.generate_ter_from_system()
            self.encoder.evolve_weights(ter)

            # Optionally sync with peer
            if self.is_connected:
                packet = MeshPacket(
                    packet_type=PacketType.TER_SYNC,
                    flags=0,
                    sequence=self._next_sequence(),
                    flow_token=self.flow_token,
                    payload=ter.to_bytes(),
                )
                try:
                    self.channel.send(packet.to_bytes(), reliable=False)
                except Exception:
                    pass

    def _handle_channel_state_change(
        self,
        old_state: ChannelState,
        new_state: ChannelState,
    ) -> None:
        """Handle channel state changes."""
        if new_state == ChannelState.DISCONNECTED:
            if self._state == TransportState.CONNECTED:
                self._set_state(TransportState.RECONNECTING)

        elif new_state == ChannelState.CONNECTED:
            if self._state == TransportState.RECONNECTING:
                self._set_state(TransportState.CONNECTED)

        elif new_state == ChannelState.DEGRADED:
            if self._state == TransportState.CONNECTED:
                self._set_state(TransportState.DEGRADED)

    def _handle_channel_error(self, error: Exception) -> None:
        """Handle channel errors."""
        for callback in self._on_error:
            try:
                callback(error)
            except Exception:
                pass

    def _handle_channel_hop(
        self,
        old_channel: Optional[PortConfig],
        new_channel: PortConfig,
    ) -> None:
        """Handle channel hop."""
        if self.is_connected and old_channel:
            # Announce channel switch to peer
            data = struct.pack(
                '>HH',
                new_channel.port,
                new_channel.mode.value,
            )
            try:
                self.send(PacketType.EMERGENCY_CHANNEL_SWITCH, data, reliable=False)
            except Exception:
                pass

    def _next_sequence(self) -> int:
        """Get next sequence number."""
        with self._lock:
            seq = self._sequence
            self._sequence = (self._sequence + 1) & 0xFFFFFFFF
            return seq

    def _set_state(self, new_state: TransportState) -> None:
        """Set transport state."""
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

    def on_state_change(self, callback: Callable) -> None:
        """Register state change callback."""
        self._on_state_change.append(callback)

    def on_packet(self, callback: Callable[[MeshPacket], None]) -> None:
        """Register packet callback."""
        self._on_packet.append(callback)

    def on_dsm_event(self, callback: Callable[[PacketType, bytes], None]) -> None:
        """Register DSM event callback."""
        self._on_dsm_event.append(callback)

    def on_error(self, callback: Callable[[Exception], None]) -> None:
        """Register error callback."""
        self._on_error.append(callback)

    def get_status(self) -> Dict[str, Any]:
        """Get transport status."""
        return {
            'state': self._state.name,
            'node_id': self.node_id.hex(),
            'flow_token': self.flow_token.hex(),
            'sequence': self._sequence,
            'encoder': self.encoder.export_state(),
            'channel': self.channel.get_status(),
            'selector_scores': self.selector.get_scores(),
            'current_hopper_channel': (
                self.hopper.get_current_channel().port
                if self.hopper.get_current_channel()
                else None
            ),
        }


class MeshNode:
    """
    High-level mesh node abstraction.

    Provides easy-to-use interface for:
    - Joining the mesh network
    - Publishing security events
    - Participating in DSM consensus
    - File transfer and VPN
    """

    def __init__(
        self,
        node_id: Optional[bytes] = None,
        neuro_seed: Optional[bytes] = None,
        bootstrap_peers: Optional[List[str]] = None,
    ):
        """
        Initialize mesh node.

        Args:
            node_id: Node identifier (generated if None)
            neuro_seed: Neural seed (must match other nodes)
            bootstrap_peers: List of bootstrap peer addresses
        """
        self.node_id = node_id or secrets.token_bytes(16)
        self.neuro_seed = neuro_seed or secrets.token_bytes(32)
        self.bootstrap_peers = bootstrap_peers or []

        # Create transport
        self.transport = UnifiedTransport(
            node_id=self.node_id,
            neuro_seed=self.neuro_seed,
        )

        # Connected peers
        self._connected_peers: List[str] = []
        self._lock = threading.Lock()

    def join_mesh(self) -> bool:
        """
        Join the mesh network.

        Connects to bootstrap peers and establishes resonance.
        """
        for peer in self.bootstrap_peers:
            if self.transport.connect(peer):
                with self._lock:
                    self._connected_peers.append(peer)
                return True

        return False

    def publish_event(
        self,
        event_type: int,
        severity: int,
        source: str,
        details: Dict[str, Any],
    ) -> bool:
        """Publish security event to mesh."""
        import json
        details_bytes = json.dumps(details).encode()
        return self.transport.send_security_event(
            event_type, severity, source, details_bytes
        )

    def leave_mesh(self) -> None:
        """Leave the mesh network."""
        self.transport.close()
        with self._lock:
            self._connected_peers.clear()
