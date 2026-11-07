"""
HookProbe Transport Protocol (HTP) - VPN Extension

Extends HTP for VPN tunnel traffic:
- IP packet encapsulation
- File transfer optimization
- Bandwidth management
- Priority queuing (QoS)
- Congestion control

This module works alongside the core HTP protocol to support
VPN traffic from Nexus gateway to Guardian/Fortress devices.
"""

import os
import struct
import socket
import time
import secrets
import hashlib
from enum import Enum
from typing import Optional, Tuple, List, Dict, Callable
from dataclasses import dataclass, field
from collections import deque
from threading import Lock, Thread
import select

from .htp import (
    HTPHeader, HTPState, HookProbeTransport, PacketMode,
    ResonanceLayer, NeuroLayer, blake3_hash
)


class VPNPacketType(Enum):
    """Extended packet types for VPN traffic."""
    IP_PACKET = 0x10       # Encapsulated IP packet
    FILE_CHUNK = 0x11      # File transfer chunk
    FILE_META = 0x12       # File metadata
    CONTROL = 0x13         # Control message
    KEEPALIVE = 0x14       # VPN keepalive
    BANDWIDTH_PROBE = 0x15 # Bandwidth measurement
    QOS_UPDATE = 0x16      # QoS parameter update


class QoSClass(Enum):
    """Quality of Service classes."""
    REALTIME = 0    # Voice/video - lowest latency
    INTERACTIVE = 1  # SSH, remote desktop
    BULK = 2         # File transfers, backups
    BACKGROUND = 3   # Updates, non-urgent


@dataclass
class VPNTunnelConfig:
    """VPN tunnel configuration."""
    tunnel_id: str
    local_ip: str
    remote_ip: str
    mtu: int = 1400
    bandwidth_limit_mbps: int = 50
    qos_enabled: bool = True
    compression_enabled: bool = False
    fragment_enabled: bool = True


@dataclass
class VPNPacketHeader:
    """
    VPN-specific packet header (16 bytes).

    Added on top of standard HTP header for VPN traffic.
    """
    packet_type: int       # uint8_t - VPNPacketType
    qos_class: int         # uint8_t - QoSClass
    fragment_id: int       # uint16_t - Fragment identifier
    fragment_offset: int   # uint16_t - Fragment offset
    fragment_flags: int    # uint8_t - Flags (MF=0x01, DF=0x02)
    reserved: int          # uint8_t - Reserved
    sequence: int          # uint32_t - Sequence number
    total_length: int      # uint32_t - Total packet length

    def serialize(self) -> bytes:
        """Serialize to 16 bytes."""
        return struct.pack(
            '>BBHHBBII',
            self.packet_type,
            self.qos_class,
            self.fragment_id,
            self.fragment_offset,
            self.fragment_flags,
            self.reserved,
            self.sequence,
            self.total_length
        )

    @staticmethod
    def deserialize(data: bytes) -> 'VPNPacketHeader':
        """Deserialize from 16 bytes."""
        (packet_type, qos_class, frag_id, frag_offset,
         frag_flags, reserved, sequence, total_length) = struct.unpack(
            '>BBHHBBII', data[:16]
        )
        return VPNPacketHeader(
            packet_type, qos_class, frag_id, frag_offset,
            frag_flags, reserved, sequence, total_length
        )


@dataclass
class FileTransferContext:
    """Context for file transfer operations."""
    file_id: str
    filename: str
    total_size: int
    chunk_size: int = 1200  # Leave room for headers
    chunks_sent: int = 0
    chunks_acked: int = 0
    started_at: float = 0.0
    completed_at: Optional[float] = None

    @property
    def progress(self) -> float:
        """Transfer progress (0.0 to 1.0)."""
        if self.total_size == 0:
            return 1.0
        return self.chunks_acked * self.chunk_size / self.total_size


class HTPVPNTunnel:
    """
    HTP-based VPN tunnel for IP packet transport.

    Provides:
    - IP packet encapsulation over HTP
    - Fragmentation for large packets
    - QoS prioritization
    - Bandwidth management
    - File transfer optimization
    """

    # Constants
    MAX_MTU = 1400
    FRAGMENT_SIZE = 1300
    KEEPALIVE_INTERVAL = 25.0  # seconds

    # QoS queue limits
    QOS_QUEUE_LIMITS = {
        QoSClass.REALTIME: 50,
        QoSClass.INTERACTIVE: 100,
        QoSClass.BULK: 500,
        QoSClass.BACKGROUND: 1000,
    }

    def __init__(
        self,
        config: VPNTunnelConfig,
        htp_transport: HookProbeTransport,
        flow_token: int
    ):
        """
        Initialize VPN tunnel.

        Args:
            config: Tunnel configuration
            htp_transport: Underlying HTP transport
            flow_token: HTP session flow token
        """
        self.config = config
        self.htp = htp_transport
        self.flow_token = flow_token

        # Packet queues (per QoS class)
        self.tx_queues: Dict[QoSClass, deque] = {
            qos: deque(maxlen=limit)
            for qos, limit in self.QOS_QUEUE_LIMITS.items()
        }

        # Fragmentation state
        self.fragment_id_counter = 0
        self.fragment_lock = Lock()
        self.pending_fragments: Dict[int, Dict[int, bytes]] = {}  # frag_id → {offset → data}

        # Sequence numbers
        self.tx_sequence = 0
        self.rx_sequence = 0

        # Bandwidth tracking
        self.bytes_sent = 0
        self.bytes_received = 0
        self.bandwidth_window_start = time.time()
        self.current_bandwidth_bps = 0

        # File transfers
        self.active_transfers: Dict[str, FileTransferContext] = {}

        # Callbacks
        self.on_packet_received: Optional[Callable[[bytes], None]] = None
        self.on_file_received: Optional[Callable[[str, bytes], None]] = None

        # State
        self.running = False
        self.last_keepalive = time.time()

    def start(self):
        """Start the VPN tunnel."""
        self.running = True
        print(f"[HTP-VPN] Tunnel {self.config.tunnel_id} started")
        print(f"[HTP-VPN] Local: {self.config.local_ip}, Remote: {self.config.remote_ip}")
        print(f"[HTP-VPN] MTU: {self.config.mtu}, Bandwidth: {self.config.bandwidth_limit_mbps} Mbps")

    def stop(self):
        """Stop the VPN tunnel."""
        self.running = False
        print(f"[HTP-VPN] Tunnel {self.config.tunnel_id} stopped")

    def send_ip_packet(
        self,
        ip_packet: bytes,
        qos_class: QoSClass = QoSClass.INTERACTIVE
    ) -> bool:
        """
        Send an IP packet through the VPN tunnel.

        Handles fragmentation if packet exceeds MTU.

        Args:
            ip_packet: Raw IP packet
            qos_class: QoS classification

        Returns:
            True if queued/sent successfully
        """
        if not self.running:
            return False

        # Check bandwidth limit
        if not self._check_bandwidth_limit(len(ip_packet)):
            # Queue for later
            self.tx_queues[qos_class].append(ip_packet)
            return True

        # Fragment if needed
        if len(ip_packet) > self.FRAGMENT_SIZE:
            return self._send_fragmented(ip_packet, qos_class)

        # Send directly
        return self._send_vpn_packet(
            VPNPacketType.IP_PACKET,
            ip_packet,
            qos_class
        )

    def _send_fragmented(
        self,
        data: bytes,
        qos_class: QoSClass
    ) -> bool:
        """
        Send data with fragmentation.

        Args:
            data: Data to send
            qos_class: QoS classification

        Returns:
            True if all fragments sent
        """
        with self.fragment_lock:
            frag_id = self.fragment_id_counter
            self.fragment_id_counter = (self.fragment_id_counter + 1) & 0xFFFF

        total_length = len(data)
        offset = 0
        success = True

        while offset < total_length:
            chunk = data[offset:offset + self.FRAGMENT_SIZE]
            is_last = (offset + len(chunk)) >= total_length

            # Build fragment header
            flags = 0 if is_last else 0x01  # MF (More Fragments)

            header = VPNPacketHeader(
                packet_type=VPNPacketType.IP_PACKET.value,
                qos_class=qos_class.value,
                fragment_id=frag_id,
                fragment_offset=offset,
                fragment_flags=flags,
                reserved=0,
                sequence=self._next_sequence(),
                total_length=total_length
            )

            # Send via HTP
            payload = header.serialize() + chunk
            if not self.htp.send_data(self.flow_token, payload, PacketMode.FRAME):
                success = False

            self.bytes_sent += len(chunk)
            offset += len(chunk)

        return success

    def _send_vpn_packet(
        self,
        packet_type: VPNPacketType,
        data: bytes,
        qos_class: QoSClass = QoSClass.INTERACTIVE
    ) -> bool:
        """
        Send a VPN packet through HTP.

        Args:
            packet_type: VPN packet type
            data: Packet data
            qos_class: QoS classification

        Returns:
            True if sent successfully
        """
        header = VPNPacketHeader(
            packet_type=packet_type.value,
            qos_class=qos_class.value,
            fragment_id=0,
            fragment_offset=0,
            fragment_flags=0x02,  # DF (Don't Fragment)
            reserved=0,
            sequence=self._next_sequence(),
            total_length=len(data)
        )

        payload = header.serialize() + data
        success = self.htp.send_data(self.flow_token, payload, PacketMode.FRAME)

        if success:
            self.bytes_sent += len(data)

        return success

    def receive_packet(self, timeout: float = 0.1) -> Optional[bytes]:
        """
        Receive a packet from the VPN tunnel.

        Handles fragment reassembly.

        Args:
            timeout: Receive timeout in seconds

        Returns:
            Complete IP packet or None
        """
        payload = self.htp.receive_data(self.flow_token, timeout)
        if not payload or len(payload) < 16:
            return None

        # Parse VPN header
        vpn_header = VPNPacketHeader.deserialize(payload[:16])
        data = payload[16:]

        self.bytes_received += len(data)

        # Handle based on packet type
        if vpn_header.packet_type == VPNPacketType.IP_PACKET.value:
            # Check for fragments
            if vpn_header.fragment_flags & 0x01 or vpn_header.fragment_offset > 0:
                return self._reassemble_fragment(vpn_header, data)
            return data

        elif vpn_header.packet_type == VPNPacketType.FILE_CHUNK.value:
            self._handle_file_chunk(vpn_header, data)
            return None

        elif vpn_header.packet_type == VPNPacketType.KEEPALIVE.value:
            self.last_keepalive = time.time()
            return None

        return data

    def _reassemble_fragment(
        self,
        header: VPNPacketHeader,
        data: bytes
    ) -> Optional[bytes]:
        """
        Reassemble fragmented packet.

        Args:
            header: VPN packet header
            data: Fragment data

        Returns:
            Complete packet if reassembly complete, None otherwise
        """
        frag_id = header.fragment_id

        if frag_id not in self.pending_fragments:
            self.pending_fragments[frag_id] = {}

        self.pending_fragments[frag_id][header.fragment_offset] = data

        # Check if we have all fragments
        total_received = sum(len(d) for d in self.pending_fragments[frag_id].values())

        if total_received >= header.total_length and not (header.fragment_flags & 0x01):
            # Reassemble
            offsets = sorted(self.pending_fragments[frag_id].keys())
            complete = b''.join(
                self.pending_fragments[frag_id][off] for off in offsets
            )
            del self.pending_fragments[frag_id]
            return complete

        return None

    def send_file(
        self,
        file_path: str,
        qos_class: QoSClass = QoSClass.BULK
    ) -> Optional[str]:
        """
        Send a file through the VPN tunnel.

        Optimized for large file transfers with resume support.

        Args:
            file_path: Path to file
            qos_class: QoS classification

        Returns:
            Transfer ID or None on error
        """
        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            file_id = hashlib.sha256(f"{filename}:{file_size}:{time.time()}".encode()).hexdigest()[:16]

            # Create transfer context
            ctx = FileTransferContext(
                file_id=file_id,
                filename=filename,
                total_size=file_size,
                started_at=time.time()
            )
            self.active_transfers[file_id] = ctx

            # Send file metadata
            meta = {
                'file_id': file_id,
                'filename': filename,
                'size': file_size,
                'chunk_size': ctx.chunk_size,
            }
            meta_bytes = str(meta).encode()

            header = VPNPacketHeader(
                packet_type=VPNPacketType.FILE_META.value,
                qos_class=qos_class.value,
                fragment_id=0,
                fragment_offset=0,
                fragment_flags=0,
                reserved=0,
                sequence=self._next_sequence(),
                total_length=len(meta_bytes)
            )

            self.htp.send_data(
                self.flow_token,
                header.serialize() + meta_bytes,
                PacketMode.FRAME
            )

            # Send file chunks
            with open(file_path, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk = f.read(ctx.chunk_size)
                    if not chunk:
                        break

                    # Build chunk header with file_id and chunk_num
                    chunk_header = struct.pack('>16sI', file_id.encode()[:16], chunk_num)

                    header = VPNPacketHeader(
                        packet_type=VPNPacketType.FILE_CHUNK.value,
                        qos_class=qos_class.value,
                        fragment_id=0,
                        fragment_offset=chunk_num * ctx.chunk_size,
                        fragment_flags=0x01 if len(chunk) == ctx.chunk_size else 0,
                        reserved=0,
                        sequence=self._next_sequence(),
                        total_length=file_size
                    )

                    payload = header.serialize() + chunk_header + chunk
                    self.htp.send_data(self.flow_token, payload, PacketMode.FRAME)

                    ctx.chunks_sent += 1
                    chunk_num += 1

                    # Rate limit based on bandwidth
                    self._apply_rate_limit()

            ctx.completed_at = time.time()
            print(f"[HTP-VPN] File sent: {filename} ({file_size} bytes)")
            return file_id

        except Exception as e:
            print(f"[HTP-VPN] File send error: {e}")
            return None

    def _handle_file_chunk(self, header: VPNPacketHeader, data: bytes):
        """Handle received file chunk."""
        if len(data) < 20:
            return

        # Parse chunk header
        file_id = data[:16].decode().rstrip('\x00')
        chunk_num = struct.unpack('>I', data[16:20])[0]
        chunk_data = data[20:]

        # Store chunk (simplified - in production use disk-backed storage)
        if file_id not in self.active_transfers:
            self.active_transfers[file_id] = FileTransferContext(
                file_id=file_id,
                filename="",
                total_size=header.total_length,
                started_at=time.time()
            )

        ctx = self.active_transfers[file_id]
        ctx.chunks_acked += 1

        # Check if complete
        if not (header.fragment_flags & 0x01):
            ctx.completed_at = time.time()
            if self.on_file_received:
                # In production, assemble full file from chunks
                self.on_file_received(file_id, chunk_data)

    def send_keepalive(self):
        """Send keepalive packet."""
        self._send_vpn_packet(
            VPNPacketType.KEEPALIVE,
            struct.pack('>Q', int(time.time() * 1000)),
            QoSClass.REALTIME
        )
        self.last_keepalive = time.time()

    def process_queues(self):
        """
        Process queued packets with QoS prioritization.

        Higher priority queues are processed first.
        """
        for qos_class in [QoSClass.REALTIME, QoSClass.INTERACTIVE,
                          QoSClass.BULK, QoSClass.BACKGROUND]:
            queue = self.tx_queues[qos_class]

            # Process up to 10 packets per class per cycle
            for _ in range(min(10, len(queue))):
                if not self._check_bandwidth_limit(100):  # Rough estimate
                    return

                try:
                    packet = queue.popleft()
                    self.send_ip_packet(packet, qos_class)
                except IndexError:
                    break

    def _next_sequence(self) -> int:
        """Get next sequence number."""
        self.tx_sequence = (self.tx_sequence + 1) & 0xFFFFFFFF
        return self.tx_sequence

    def _check_bandwidth_limit(self, packet_size: int) -> bool:
        """
        Check if sending packet would exceed bandwidth limit.

        Args:
            packet_size: Size of packet to send

        Returns:
            True if within limit
        """
        now = time.time()
        elapsed = now - self.bandwidth_window_start

        if elapsed >= 1.0:
            # Reset window
            self.current_bandwidth_bps = (self.bytes_sent * 8) / elapsed
            self.bytes_sent = 0
            self.bandwidth_window_start = now

        # Check limit
        limit_bps = self.config.bandwidth_limit_mbps * 1_000_000
        projected_bps = ((self.bytes_sent + packet_size) * 8) / max(elapsed, 0.001)

        return projected_bps < limit_bps

    def _apply_rate_limit(self):
        """Apply rate limiting delay if needed."""
        # Calculate current rate
        now = time.time()
        elapsed = now - self.bandwidth_window_start

        if elapsed > 0:
            current_rate_bps = (self.bytes_sent * 8) / elapsed
            limit_bps = self.config.bandwidth_limit_mbps * 1_000_000

            if current_rate_bps > limit_bps * 0.9:
                # Slow down
                delay = (self.bytes_sent * 8 / limit_bps) - elapsed
                if delay > 0:
                    time.sleep(min(delay, 0.1))

    def get_stats(self) -> Dict:
        """Get tunnel statistics."""
        now = time.time()
        elapsed = now - self.bandwidth_window_start

        return {
            'tunnel_id': self.config.tunnel_id,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'current_bandwidth_bps': self.current_bandwidth_bps,
            'tx_sequence': self.tx_sequence,
            'rx_sequence': self.rx_sequence,
            'pending_fragments': len(self.pending_fragments),
            'active_transfers': len(self.active_transfers),
            'queue_depths': {
                qos.name: len(queue)
                for qos, queue in self.tx_queues.items()
            },
        }


class HTPVPNManager:
    """
    Manages multiple VPN tunnels over HTP.

    Used by Nexus to maintain tunnels to Guardian/Fortress devices.
    """

    def __init__(self, node_id: str):
        """
        Initialize VPN manager.

        Args:
            node_id: Nexus node identifier
        """
        self.node_id = node_id
        self.htp = HookProbeTransport(node_id=node_id, enable_encryption=True)
        self.tunnels: Dict[str, HTPVPNTunnel] = {}
        self.running = False

    def create_tunnel(
        self,
        device_address: Tuple[str, int],
        config: VPNTunnelConfig
    ) -> Optional[HTPVPNTunnel]:
        """
        Create a new VPN tunnel to a device.

        Args:
            device_address: (IP, port) of Guardian/Fortress
            config: Tunnel configuration

        Returns:
            VPN tunnel or None on error
        """
        try:
            # Initiate HTP resonance
            flow_token = self.htp.initiate_resonance(device_address)

            # Complete resonance (simplified)
            self.htp.complete_resonance(flow_token, 0)

            # Create tunnel
            tunnel = HTPVPNTunnel(config, self.htp, flow_token)
            tunnel.start()

            self.tunnels[config.tunnel_id] = tunnel
            return tunnel

        except Exception as e:
            print(f"[HTP-VPN Manager] Failed to create tunnel: {e}")
            return None

    def get_tunnel(self, tunnel_id: str) -> Optional[HTPVPNTunnel]:
        """Get tunnel by ID."""
        return self.tunnels.get(tunnel_id)

    def stop_tunnel(self, tunnel_id: str):
        """Stop and remove a tunnel."""
        if tunnel_id in self.tunnels:
            self.tunnels[tunnel_id].stop()
            del self.tunnels[tunnel_id]

    def stop_all(self):
        """Stop all tunnels."""
        for tunnel in self.tunnels.values():
            tunnel.stop()
        self.tunnels.clear()


# Example usage
if __name__ == '__main__':
    print("=== HTP VPN Extension Test ===")

    config = VPNTunnelConfig(
        tunnel_id="test-tunnel-001",
        local_ip="10.250.0.1",
        remote_ip="10.200.1.10",
        bandwidth_limit_mbps=50
    )

    print(f"Tunnel config: {config}")
    print(f"VPN packet header size: {len(VPNPacketHeader(0,0,0,0,0,0,0,0).serialize())} bytes")
    print("HTP VPN extension loaded successfully")
