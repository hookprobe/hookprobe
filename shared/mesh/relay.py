#!/usr/bin/env python3
"""
HookProbe Mesh Relay Module
"The Bridge Between Worlds"

Version: 5.0.0

Implements relay capabilities for mesh nodes when direct P2P is impossible:
- TURN-style relay for symmetric NAT traversal
- Lightweight relay protocol for HookProbe mesh
- Automatic relay selection and load balancing
- Relay cascading for multi-hop scenarios

Innovation: "Emergent Relay Network"
When MSSP is unavailable, Fortress/Nexus nodes with public IPs
automatically form an emergent relay network, distributing load
and providing redundancy.
"""

import os
import sys
import time
import socket
import struct
import hashlib
import logging
import asyncio
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, List, Optional, Tuple, Set, Callable, Any
from threading import Thread, Lock, Event
from collections import defaultdict
import heapq

logger = logging.getLogger("mesh.relay")


# ============================================================
# CONSTANTS
# ============================================================

# Relay protocol version
RELAY_PROTOCOL_VERSION = 1

# Message types
class RelayMsgType(IntEnum):
    # Control messages
    ALLOCATE_REQUEST = 0x01
    ALLOCATE_RESPONSE = 0x02
    REFRESH_REQUEST = 0x03
    REFRESH_RESPONSE = 0x04
    RELEASE = 0x05

    # Data messages
    SEND_INDICATION = 0x10
    DATA_INDICATION = 0x11

    # Peer messages
    CREATE_PERMISSION = 0x20
    PERMISSION_RESPONSE = 0x21
    CHANNEL_BIND = 0x22
    CHANNEL_BIND_RESPONSE = 0x23

    # Status messages
    HEARTBEAT = 0x30
    HEARTBEAT_ACK = 0x31
    ERROR = 0x40


# Error codes
class RelayError(IntEnum):
    OK = 0
    UNAUTHORIZED = 1
    ALLOCATION_QUOTA_REACHED = 2
    INSUFFICIENT_CAPACITY = 3
    STALE_NONCE = 4
    ADDRESS_FAMILY_NOT_SUPPORTED = 5
    PEER_NOT_FOUND = 6
    UNKNOWN_ERROR = 255


# Default timeouts
DEFAULT_ALLOCATION_LIFETIME = 600  # 10 minutes
DEFAULT_PERMISSION_LIFETIME = 300  # 5 minutes
DEFAULT_CHANNEL_LIFETIME = 600     # 10 minutes


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class RelayAllocation:
    """A relay allocation for a client"""
    allocation_id: bytes  # 16 bytes unique ID
    client_id: str
    client_addr: Tuple[str, int]
    relay_addr: Tuple[str, int]
    created_at: float
    expires_at: float
    permissions: Dict[str, float] = field(default_factory=dict)  # peer_addr -> expires_at
    channels: Dict[int, str] = field(default_factory=dict)  # channel_id -> peer_addr
    bytes_relayed: int = 0
    packets_relayed: int = 0


@dataclass
class RelayChannel:
    """A bound channel for efficient relay"""
    channel_id: int
    peer_addr: Tuple[str, int]
    allocation_id: bytes
    expires_at: float


@dataclass
class RelayStats:
    """Statistics for a relay node"""
    allocations_active: int = 0
    allocations_total: int = 0
    bytes_relayed: int = 0
    packets_relayed: int = 0
    uptime: float = 0.0
    capacity_percent: float = 0.0


@dataclass
class RelayNodeInfo:
    """Information about a relay node in the network"""
    node_id: str
    public_ip: str
    public_port: int
    region: str
    tier: str
    capacity: int
    current_load: int
    latency_ms: float
    last_seen: float
    priority: int = 0

    def load_factor(self) -> float:
        """Calculate load factor (0.0 - 1.0)"""
        if self.capacity == 0:
            return 1.0
        return self.current_load / self.capacity


# ============================================================
# RELAY MESSAGE CODEC
# ============================================================

class RelayMessageCodec:
    """
    Codec for relay protocol messages.

    Message format:
    [version:1][type:1][length:2][transaction_id:8][payload:var]
    """

    HEADER_SIZE = 12

    @staticmethod
    def encode(msg_type: RelayMsgType, transaction_id: bytes,
               payload: bytes = b"") -> bytes:
        """Encode a relay message"""
        header = struct.pack(
            ">BBHQ",
            RELAY_PROTOCOL_VERSION,
            msg_type,
            len(payload),
            int.from_bytes(transaction_id[:8], "big")
        )
        return header + payload

    @staticmethod
    def decode(data: bytes) -> Tuple[int, RelayMsgType, bytes, bytes]:
        """
        Decode a relay message.

        Returns:
            (version, msg_type, transaction_id, payload)
        """
        if len(data) < RelayMessageCodec.HEADER_SIZE:
            raise ValueError("Message too short")

        version, msg_type, length, txn_int = struct.unpack(">BBHQ", data[:12])
        transaction_id = txn_int.to_bytes(8, "big")
        payload = data[12:12+length]

        return version, RelayMsgType(msg_type), transaction_id, payload

    @staticmethod
    def encode_allocate_request(client_id: str, requested_lifetime: int) -> bytes:
        """Encode ALLOCATE_REQUEST payload"""
        return struct.pack(">I", requested_lifetime) + client_id.encode()[:32].ljust(32, b"\x00")

    @staticmethod
    def decode_allocate_request(payload: bytes) -> Tuple[int, str]:
        """Decode ALLOCATE_REQUEST payload"""
        lifetime = struct.unpack(">I", payload[:4])[0]
        client_id = payload[4:36].rstrip(b"\x00").decode()
        return lifetime, client_id

    @staticmethod
    def encode_allocate_response(success: bool, relay_ip: str, relay_port: int,
                                 allocation_id: bytes, lifetime: int,
                                 error: RelayError = RelayError.OK) -> bytes:
        """Encode ALLOCATE_RESPONSE payload"""
        flags = 0x80 if success else 0x00
        ip_bytes = socket.inet_aton(relay_ip) if relay_ip else b"\x00\x00\x00\x00"
        return struct.pack(
            ">BBHI",
            flags,
            error,
            relay_port,
            lifetime
        ) + ip_bytes + allocation_id

    @staticmethod
    def decode_allocate_response(payload: bytes) -> Tuple[bool, str, int, bytes, int, RelayError]:
        """Decode ALLOCATE_RESPONSE payload"""
        flags, error, port, lifetime = struct.unpack(">BBHI", payload[:8])
        success = bool(flags & 0x80)
        relay_ip = socket.inet_ntoa(payload[8:12])
        allocation_id = payload[12:28]
        return success, relay_ip, port, allocation_id, lifetime, RelayError(error)

    @staticmethod
    def encode_data(allocation_id: bytes, peer_addr: Tuple[str, int],
                    data: bytes) -> bytes:
        """Encode DATA_INDICATION payload"""
        ip_bytes = socket.inet_aton(peer_addr[0])
        return allocation_id + struct.pack(">H", peer_addr[1]) + ip_bytes + data

    @staticmethod
    def decode_data(payload: bytes) -> Tuple[bytes, Tuple[str, int], bytes]:
        """Decode DATA_INDICATION payload"""
        allocation_id = payload[:16]
        port = struct.unpack(">H", payload[16:18])[0]
        ip = socket.inet_ntoa(payload[18:22])
        data = payload[22:]
        return allocation_id, (ip, port), data


# ============================================================
# RELAY SERVER
# ============================================================

class RelayServer:
    """
    Relay server for mesh nodes.

    Provides TURN-style relay capabilities for nodes that
    cannot establish direct P2P connections.
    """

    def __init__(self, listen_ip: str = "0.0.0.0", listen_port: int = 3478,
                 max_allocations: int = 100, node_id: str = None):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.max_allocations = max_allocations
        self.node_id = node_id or f"relay-{socket.gethostname()}"

        # Allocations
        self.allocations: Dict[bytes, RelayAllocation] = {}
        self.client_allocations: Dict[str, Set[bytes]] = defaultdict(set)

        # Socket
        self.sock: Optional[socket.socket] = None
        self.relay_sockets: Dict[bytes, socket.socket] = {}  # allocation_id -> socket

        # State
        self.running = False
        self.started_at = 0.0
        self._lock = Lock()

        # Stats
        self.stats = RelayStats()

    def start(self) -> bool:
        """Start the relay server"""
        if self.running:
            return True

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.listen_ip, self.listen_port))
            self.sock.setblocking(False)

            self.running = True
            self.started_at = time.time()

            # Start processing thread
            Thread(target=self._process_loop, daemon=True).start()

            # Start maintenance thread
            Thread(target=self._maintenance_loop, daemon=True).start()

            logger.info(f"[RELAY] Server started on {self.listen_ip}:{self.listen_port}")
            return True

        except Exception as e:
            logger.error(f"[RELAY] Failed to start: {e}")
            return False

    def stop(self):
        """Stop the relay server"""
        self.running = False

        # Close all relay sockets
        for sock in self.relay_sockets.values():
            try:
                sock.close()
            except Exception:
                pass

        if self.sock:
            self.sock.close()

        logger.info("[RELAY] Server stopped")

    def _process_loop(self):
        """Main processing loop"""
        while self.running:
            try:
                self.sock.settimeout(0.1)
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self._handle_message(data, addr)
                except socket.timeout:
                    pass

                # Process relay socket data
                self._process_relay_data()

            except Exception as e:
                logger.error(f"[RELAY] Process error: {e}")

    def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming message"""
        try:
            version, msg_type, txn_id, payload = RelayMessageCodec.decode(data)

            if msg_type == RelayMsgType.ALLOCATE_REQUEST:
                self._handle_allocate(txn_id, payload, addr)
            elif msg_type == RelayMsgType.REFRESH_REQUEST:
                self._handle_refresh(txn_id, payload, addr)
            elif msg_type == RelayMsgType.RELEASE:
                self._handle_release(txn_id, payload, addr)
            elif msg_type == RelayMsgType.SEND_INDICATION:
                self._handle_send(txn_id, payload, addr)
            elif msg_type == RelayMsgType.CREATE_PERMISSION:
                self._handle_permission(txn_id, payload, addr)
            elif msg_type == RelayMsgType.HEARTBEAT:
                self._handle_heartbeat(txn_id, addr)

        except Exception as e:
            logger.warning(f"[RELAY] Message handling error: {e}")

    def _handle_allocate(self, txn_id: bytes, payload: bytes,
                        addr: Tuple[str, int]):
        """Handle allocation request"""
        lifetime, client_id = RelayMessageCodec.decode_allocate_request(payload)

        with self._lock:
            # Check capacity
            if len(self.allocations) >= self.max_allocations:
                response = self._build_allocate_error(
                    txn_id, RelayError.ALLOCATION_QUOTA_REACHED
                )
                self.sock.sendto(response, addr)
                return

            # Check if client already has allocation
            existing = self.client_allocations.get(client_id)
            if existing:
                # Return existing allocation
                alloc_id = next(iter(existing))
                alloc = self.allocations.get(alloc_id)
                if alloc:
                    response = self._build_allocate_success(
                        txn_id, alloc.relay_addr, alloc.allocation_id,
                        int(alloc.expires_at - time.time())
                    )
                    self.sock.sendto(response, addr)
                    return

            # Create new allocation
            allocation_id = os.urandom(16)
            relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            relay_sock.bind(("0.0.0.0", 0))
            relay_addr = relay_sock.getsockname()
            relay_sock.setblocking(False)

            allocation = RelayAllocation(
                allocation_id=allocation_id,
                client_id=client_id,
                client_addr=addr,
                relay_addr=relay_addr,
                created_at=time.time(),
                expires_at=time.time() + min(lifetime, DEFAULT_ALLOCATION_LIFETIME)
            )

            self.allocations[allocation_id] = allocation
            self.client_allocations[client_id].add(allocation_id)
            self.relay_sockets[allocation_id] = relay_sock

            self.stats.allocations_active += 1
            self.stats.allocations_total += 1

        # Send success response
        response = self._build_allocate_success(
            txn_id, relay_addr, allocation_id,
            min(lifetime, DEFAULT_ALLOCATION_LIFETIME)
        )
        self.sock.sendto(response, addr)

        logger.info(f"[RELAY] Allocation created for {client_id}: "
                   f"{relay_addr[0]}:{relay_addr[1]}")

    def _handle_refresh(self, txn_id: bytes, payload: bytes,
                       addr: Tuple[str, int]):
        """Handle allocation refresh"""
        allocation_id = payload[:16]
        lifetime = struct.unpack(">I", payload[16:20])[0] if len(payload) >= 20 else DEFAULT_ALLOCATION_LIFETIME

        with self._lock:
            alloc = self.allocations.get(allocation_id)
            if alloc and alloc.client_addr == addr:
                alloc.expires_at = time.time() + min(lifetime, DEFAULT_ALLOCATION_LIFETIME)

                response = RelayMessageCodec.encode(
                    RelayMsgType.REFRESH_RESPONSE,
                    txn_id,
                    struct.pack(">I", int(alloc.expires_at - time.time()))
                )
                self.sock.sendto(response, addr)
            else:
                response = RelayMessageCodec.encode(
                    RelayMsgType.ERROR,
                    txn_id,
                    struct.pack(">B", RelayError.PEER_NOT_FOUND)
                )
                self.sock.sendto(response, addr)

    def _handle_release(self, txn_id: bytes, payload: bytes,
                       addr: Tuple[str, int]):
        """Handle allocation release"""
        allocation_id = payload[:16]

        with self._lock:
            alloc = self.allocations.pop(allocation_id, None)
            if alloc:
                self.client_allocations[alloc.client_id].discard(allocation_id)
                sock = self.relay_sockets.pop(allocation_id, None)
                if sock:
                    sock.close()
                self.stats.allocations_active -= 1
                logger.info(f"[RELAY] Allocation released: {alloc.client_id}")

    def _handle_send(self, txn_id: bytes, payload: bytes,
                    addr: Tuple[str, int]):
        """Handle send indication (client -> peer)"""
        allocation_id, peer_addr, data = RelayMessageCodec.decode_data(payload)

        with self._lock:
            alloc = self.allocations.get(allocation_id)
            if not alloc or alloc.client_addr != addr:
                return

            # Check permission
            peer_key = f"{peer_addr[0]}:{peer_addr[1]}"
            if peer_key not in alloc.permissions:
                return

            # Forward data
            relay_sock = self.relay_sockets.get(allocation_id)
            if relay_sock:
                try:
                    relay_sock.sendto(data, peer_addr)
                    alloc.bytes_relayed += len(data)
                    alloc.packets_relayed += 1
                    self.stats.bytes_relayed += len(data)
                    self.stats.packets_relayed += 1
                except Exception as e:
                    logger.debug(f"[RELAY] Send failed: {e}")

    def _handle_permission(self, txn_id: bytes, payload: bytes,
                          addr: Tuple[str, int]):
        """Handle create permission request"""
        allocation_id = payload[:16]
        peer_port = struct.unpack(">H", payload[16:18])[0]
        peer_ip = socket.inet_ntoa(payload[18:22])

        with self._lock:
            alloc = self.allocations.get(allocation_id)
            if alloc and alloc.client_addr == addr:
                peer_key = f"{peer_ip}:{peer_port}"
                alloc.permissions[peer_key] = time.time() + DEFAULT_PERMISSION_LIFETIME

                response = RelayMessageCodec.encode(
                    RelayMsgType.PERMISSION_RESPONSE,
                    txn_id,
                    struct.pack(">B", RelayError.OK)
                )
                self.sock.sendto(response, addr)
                logger.debug(f"[RELAY] Permission created: {peer_ip}:{peer_port}")
            else:
                response = RelayMessageCodec.encode(
                    RelayMsgType.PERMISSION_RESPONSE,
                    txn_id,
                    struct.pack(">B", RelayError.PEER_NOT_FOUND)
                )
                self.sock.sendto(response, addr)

    def _handle_heartbeat(self, txn_id: bytes, addr: Tuple[str, int]):
        """Handle heartbeat"""
        response = RelayMessageCodec.encode(
            RelayMsgType.HEARTBEAT_ACK,
            txn_id,
            b""
        )
        self.sock.sendto(response, addr)

    def _process_relay_data(self):
        """Process data received on relay sockets (peer -> client)"""
        with self._lock:
            for alloc_id, relay_sock in list(self.relay_sockets.items()):
                try:
                    relay_sock.settimeout(0)
                    data, peer_addr = relay_sock.recvfrom(65535)

                    alloc = self.allocations.get(alloc_id)
                    if not alloc:
                        continue

                    # Check permission
                    peer_key = f"{peer_addr[0]}:{peer_addr[1]}"
                    if peer_key not in alloc.permissions:
                        continue

                    # Forward to client
                    indication = RelayMessageCodec.encode(
                        RelayMsgType.DATA_INDICATION,
                        os.urandom(8),
                        RelayMessageCodec.encode_data(alloc_id, peer_addr, data)
                    )
                    self.sock.sendto(indication, alloc.client_addr)

                    alloc.bytes_relayed += len(data)
                    alloc.packets_relayed += 1
                    self.stats.bytes_relayed += len(data)
                    self.stats.packets_relayed += 1

                except socket.timeout:
                    pass
                except Exception:
                    pass

    def _maintenance_loop(self):
        """Maintenance loop for cleanup"""
        while self.running:
            time.sleep(30)

            now = time.time()
            with self._lock:
                # Clean expired allocations
                expired = [
                    aid for aid, alloc in self.allocations.items()
                    if now > alloc.expires_at
                ]
                for aid in expired:
                    alloc = self.allocations.pop(aid, None)
                    if alloc:
                        self.client_allocations[alloc.client_id].discard(aid)
                        sock = self.relay_sockets.pop(aid, None)
                        if sock:
                            sock.close()
                        self.stats.allocations_active -= 1
                        logger.debug(f"[RELAY] Allocation expired: {alloc.client_id}")

                # Clean expired permissions
                for alloc in self.allocations.values():
                    expired_perms = [
                        p for p, exp in alloc.permissions.items()
                        if now > exp
                    ]
                    for p in expired_perms:
                        del alloc.permissions[p]

                # Update stats
                self.stats.uptime = now - self.started_at
                self.stats.capacity_percent = (
                    len(self.allocations) / self.max_allocations * 100
                    if self.max_allocations > 0 else 0
                )

    def _build_allocate_success(self, txn_id: bytes, relay_addr: Tuple[str, int],
                               allocation_id: bytes, lifetime: int) -> bytes:
        """Build successful allocate response"""
        payload = RelayMessageCodec.encode_allocate_response(
            True, relay_addr[0], relay_addr[1], allocation_id, lifetime
        )
        return RelayMessageCodec.encode(RelayMsgType.ALLOCATE_RESPONSE, txn_id, payload)

    def _build_allocate_error(self, txn_id: bytes, error: RelayError) -> bytes:
        """Build error allocate response"""
        payload = RelayMessageCodec.encode_allocate_response(
            False, "0.0.0.0", 0, b"\x00" * 16, 0, error
        )
        return RelayMessageCodec.encode(RelayMsgType.ALLOCATE_RESPONSE, txn_id, payload)

    def get_stats(self) -> RelayStats:
        """Get relay server statistics"""
        with self._lock:
            return RelayStats(
                allocations_active=self.stats.allocations_active,
                allocations_total=self.stats.allocations_total,
                bytes_relayed=self.stats.bytes_relayed,
                packets_relayed=self.stats.packets_relayed,
                uptime=time.time() - self.started_at if self.started_at else 0,
                capacity_percent=len(self.allocations) / self.max_allocations * 100 if self.max_allocations else 0
            )


# ============================================================
# RELAY CLIENT
# ============================================================

class RelayClient:
    """
    Client for connecting through a relay server.

    Establishes and maintains relay allocations for NAT traversal.
    """

    def __init__(self, client_id: str, relay_addr: Tuple[str, int]):
        self.client_id = client_id
        self.relay_addr = relay_addr

        self.sock: Optional[socket.socket] = None
        self.allocation_id: Optional[bytes] = None
        self.relay_endpoint: Optional[Tuple[str, int]] = None
        self.expires_at: float = 0

        self._lock = Lock()
        self._running = False

    def allocate(self, lifetime: int = DEFAULT_ALLOCATION_LIFETIME,
                timeout: float = 5.0) -> bool:
        """
        Request a relay allocation.

        Returns:
            True if allocation successful
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

        try:
            # Build allocate request
            txn_id = os.urandom(8)
            payload = RelayMessageCodec.encode_allocate_request(self.client_id, lifetime)
            request = RelayMessageCodec.encode(RelayMsgType.ALLOCATE_REQUEST, txn_id, payload)

            self.sock.sendto(request, self.relay_addr)
            response, _ = self.sock.recvfrom(1024)

            _, msg_type, recv_txn, recv_payload = RelayMessageCodec.decode(response)

            if msg_type == RelayMsgType.ALLOCATE_RESPONSE:
                success, ip, port, alloc_id, life, error = RelayMessageCodec.decode_allocate_response(recv_payload)

                if success:
                    with self._lock:
                        self.allocation_id = alloc_id
                        self.relay_endpoint = (ip, port)
                        self.expires_at = time.time() + life

                    logger.info(f"[RELAY] Allocation obtained: {ip}:{port}")

                    # Start refresh thread
                    self._running = True
                    Thread(target=self._refresh_loop, daemon=True).start()

                    return True
                else:
                    logger.warning(f"[RELAY] Allocation failed: {error.name}")

        except socket.timeout:
            logger.warning("[RELAY] Allocation request timed out")
        except Exception as e:
            logger.error(f"[RELAY] Allocation error: {e}")

        return False

    def release(self):
        """Release the relay allocation"""
        if not self.allocation_id:
            return

        self._running = False

        try:
            txn_id = os.urandom(8)
            request = RelayMessageCodec.encode(
                RelayMsgType.RELEASE,
                txn_id,
                self.allocation_id
            )
            self.sock.sendto(request, self.relay_addr)
        except Exception:
            pass

        with self._lock:
            self.allocation_id = None
            self.relay_endpoint = None

        if self.sock:
            self.sock.close()

    def create_permission(self, peer_addr: Tuple[str, int],
                         timeout: float = 3.0) -> bool:
        """Create permission for a peer to send through relay"""
        if not self.allocation_id:
            return False

        try:
            self.sock.settimeout(timeout)
            txn_id = os.urandom(8)
            payload = self.allocation_id + struct.pack(">H", peer_addr[1]) + socket.inet_aton(peer_addr[0])
            request = RelayMessageCodec.encode(RelayMsgType.CREATE_PERMISSION, txn_id, payload)

            self.sock.sendto(request, self.relay_addr)
            response, _ = self.sock.recvfrom(1024)

            _, msg_type, _, recv_payload = RelayMessageCodec.decode(response)
            if msg_type == RelayMsgType.PERMISSION_RESPONSE:
                return recv_payload[0] == RelayError.OK

        except Exception as e:
            logger.warning(f"[RELAY] Permission creation failed: {e}")

        return False

    def send_to_peer(self, peer_addr: Tuple[str, int], data: bytes):
        """Send data to a peer through the relay"""
        if not self.allocation_id:
            return

        try:
            txn_id = os.urandom(8)
            payload = RelayMessageCodec.encode_data(self.allocation_id, peer_addr, data)
            indication = RelayMessageCodec.encode(RelayMsgType.SEND_INDICATION, txn_id, payload)
            self.sock.sendto(indication, self.relay_addr)
        except Exception as e:
            logger.debug(f"[RELAY] Send failed: {e}")

    def receive(self, timeout: float = 1.0) -> Optional[Tuple[Tuple[str, int], bytes]]:
        """
        Receive data from the relay.

        Returns:
            (peer_addr, data) or None
        """
        if not self.sock:
            return None

        try:
            self.sock.settimeout(timeout)
            data, _ = self.sock.recvfrom(65535)

            _, msg_type, _, payload = RelayMessageCodec.decode(data)
            if msg_type == RelayMsgType.DATA_INDICATION:
                _, peer_addr, recv_data = RelayMessageCodec.decode_data(payload)
                return (peer_addr, recv_data)

        except socket.timeout:
            pass
        except Exception as e:
            logger.debug(f"[RELAY] Receive error: {e}")

        return None

    def _refresh_loop(self):
        """Periodically refresh allocation"""
        while self._running:
            try:
                # Refresh at half the lifetime
                with self._lock:
                    time_left = self.expires_at - time.time()

                if time_left < DEFAULT_ALLOCATION_LIFETIME / 2:
                    self._refresh()

                time.sleep(30)

            except Exception as e:
                logger.debug(f"[RELAY] Refresh error: {e}")

    def _refresh(self) -> bool:
        """Refresh the allocation"""
        if not self.allocation_id:
            return False

        try:
            self.sock.settimeout(3.0)
            txn_id = os.urandom(8)
            payload = self.allocation_id + struct.pack(">I", DEFAULT_ALLOCATION_LIFETIME)
            request = RelayMessageCodec.encode(RelayMsgType.REFRESH_REQUEST, txn_id, payload)

            self.sock.sendto(request, self.relay_addr)
            response, _ = self.sock.recvfrom(1024)

            _, msg_type, _, recv_payload = RelayMessageCodec.decode(response)
            if msg_type == RelayMsgType.REFRESH_RESPONSE:
                new_lifetime = struct.unpack(">I", recv_payload[:4])[0]
                with self._lock:
                    self.expires_at = time.time() + new_lifetime
                return True

        except Exception as e:
            logger.warning(f"[RELAY] Refresh failed: {e}")

        return False


# ============================================================
# RELAY NETWORK
# ============================================================

class RelayNetwork:
    """
    Manages the emergent relay network.

    Discovers and maintains list of available relay nodes,
    provides optimal relay selection based on load and latency.
    """

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.relay_nodes: Dict[str, RelayNodeInfo] = {}
        self._lock = Lock()

    def register_node(self, info: RelayNodeInfo):
        """Register a relay node"""
        with self._lock:
            info.last_seen = time.time()
            self.relay_nodes[info.node_id] = info
            logger.debug(f"[RELAY_NET] Registered relay: {info.node_id}")

    def unregister_node(self, node_id: str):
        """Unregister a relay node"""
        with self._lock:
            self.relay_nodes.pop(node_id, None)

    def get_best_relay(self, exclude: Set[str] = None,
                      prefer_region: str = None) -> Optional[RelayNodeInfo]:
        """
        Get the best available relay node.

        Selection criteria:
        1. Same region preferred
        2. Lowest load factor
        3. Lowest latency
        """
        exclude = exclude or set()

        with self._lock:
            available = [
                n for n in self.relay_nodes.values()
                if n.node_id not in exclude
                and time.time() - n.last_seen < 300
                and n.load_factor() < 0.9
            ]

            if not available:
                return None

            # Score nodes
            def score(node: RelayNodeInfo) -> float:
                region_bonus = 0.2 if prefer_region and node.region == prefer_region else 0
                load_score = 1 - node.load_factor()
                latency_score = max(0, 1 - node.latency_ms / 1000)
                return region_bonus + load_score * 0.5 + latency_score * 0.3

            return max(available, key=score)

    def get_relay_list(self, count: int = 3,
                      region: str = None) -> List[RelayNodeInfo]:
        """Get list of best relay nodes"""
        relays = []
        exclude = set()

        for _ in range(count):
            relay = self.get_best_relay(exclude, region)
            if relay:
                relays.append(relay)
                exclude.add(relay.node_id)
            else:
                break

        return relays

    def cleanup_stale(self, max_age: float = 300):
        """Remove stale relay nodes"""
        now = time.time()
        with self._lock:
            stale = [
                nid for nid, info in self.relay_nodes.items()
                if now - info.last_seen > max_age
            ]
            for nid in stale:
                del self.relay_nodes[nid]


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    "RelayMsgType",
    "RelayError",

    # Data classes
    "RelayAllocation",
    "RelayChannel",
    "RelayStats",
    "RelayNodeInfo",

    # Components
    "RelayMessageCodec",
    "RelayServer",
    "RelayClient",
    "RelayNetwork",
]
