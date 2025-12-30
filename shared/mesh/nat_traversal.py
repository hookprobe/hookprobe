#!/usr/bin/env python3
"""
HookProbe NAT Traversal Module
"Breaking Through Barriers"

Version: 5.0.0

Implements NAT/CGNAT traversal for mesh connectivity:
- STUN: Discover public IP and port mapping
- ICE: Interactive Connectivity Establishment
- UDP Hole Punching: Direct P2P through symmetric NAT
- TURN Relay: Fallback when direct connection impossible

The Innovation: "Mesh Promotion Protocol"
When MSSP is unavailable, nodes with public IPs automatically
become temporary coordinators (mini-MSSPs) to maintain mesh coherence.
"""

import os
import sys
import time
import socket
import struct
import random
import hashlib
import logging
import asyncio
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, List, Optional, Tuple, Set, Callable
from threading import Thread, Lock
from collections import deque

logger = logging.getLogger("mesh.nat")


# ============================================================
# CONSTANTS
# ============================================================

# STUN Message Types (RFC 5389)
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_BINDING_ERROR = 0x0111

# STUN Attributes
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_SOFTWARE = 0x8022
STUN_ATTR_FINGERPRINT = 0x8028

# STUN Magic Cookie (RFC 5389)
STUN_MAGIC_COOKIE = 0x2112A442

# Public STUN servers (fallback)
PUBLIC_STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 443),
]

# HookProbe STUN servers (primary)
HOOKPROBE_STUN_SERVERS = [
    ("stun.hookprobe.com", 3478),
    ("stun-eu.hookprobe.com", 3478),
    ("stun-ap.hookprobe.com", 3478),
]


# ============================================================
# NAT TYPE DETECTION
# ============================================================

class NATType(IntEnum):
    """NAT type classification (RFC 3489 style)"""
    UNKNOWN = 0
    OPEN = 1              # No NAT, public IP
    FULL_CONE = 2         # Any external host can send
    RESTRICTED_CONE = 3   # Only hosts we've sent to can reply
    PORT_RESTRICTED = 4   # Only host:port we've sent to can reply
    SYMMETRIC = 5         # Different mapping per destination
    BLOCKED = 6           # UDP blocked


class ConnectivityType(IntEnum):
    """Connectivity result types"""
    DIRECT = auto()       # Direct P2P connection
    HOLE_PUNCHED = auto() # NAT hole punching succeeded
    RELAYED = auto()      # Using relay node
    FAILED = auto()       # Could not establish connection


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class STUNResult:
    """Result of STUN query"""
    success: bool
    public_ip: Optional[str] = None
    public_port: Optional[int] = None
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    nat_type: NATType = NATType.UNKNOWN
    latency_ms: float = 0.0
    server: str = ""


@dataclass
class ICECandidate:
    """ICE candidate for connectivity"""
    type: str  # "host", "srflx" (server reflexive), "relay"
    ip: str
    port: int
    priority: int
    foundation: str
    component: int = 1
    transport: str = "udp"
    related_ip: Optional[str] = None
    related_port: Optional[int] = None

    def to_sdp(self) -> str:
        """Convert to SDP format"""
        return (f"a=candidate:{self.foundation} {self.component} "
                f"{self.transport} {self.priority} {self.ip} {self.port} "
                f"typ {self.type}")

    @classmethod
    def from_tuple(cls, addr: Tuple[str, int], ctype: str = "host",
                   priority: int = 0) -> "ICECandidate":
        """Create from (ip, port) tuple"""
        foundation = hashlib.md5(
            f"{addr[0]}:{addr[1]}".encode(), usedforsecurity=False
        ).hexdigest()[:8]
        return cls(
            type=ctype,
            ip=addr[0],
            port=addr[1],
            priority=priority or cls._calc_priority(ctype),
            foundation=foundation
        )

    @staticmethod
    def _calc_priority(ctype: str) -> int:
        """Calculate ICE priority based on candidate type"""
        type_pref = {"host": 126, "srflx": 100, "relay": 0}
        local_pref = 65535
        component = 1
        return (type_pref.get(ctype, 0) << 24) + (local_pref << 8) + (256 - component)


@dataclass
class PeerEndpoint:
    """Peer endpoint information for connection"""
    node_id: str
    candidates: List[ICECandidate] = field(default_factory=list)
    nat_type: NATType = NATType.UNKNOWN
    selected_candidate: Optional[ICECandidate] = None
    connectivity: ConnectivityType = ConnectivityType.FAILED
    relay_node: Optional[str] = None


# ============================================================
# STUN CLIENT
# ============================================================

class STUNClient:
    """
    STUN client for NAT discovery.

    Discovers public IP/port and NAT type by querying STUN servers.
    """

    def __init__(self, stun_servers: List[Tuple[str, int]] = None,
                 timeout: float = 3.0):
        self.stun_servers = stun_servers or (HOOKPROBE_STUN_SERVERS + PUBLIC_STUN_SERVERS)
        self.timeout = timeout
        self._transaction_id = os.urandom(12)

    def discover(self, local_port: int = 0) -> STUNResult:
        """
        Discover public IP and port via STUN.

        Args:
            local_port: Local port to bind (0 for random)

        Returns:
            STUNResult with public endpoint information
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            sock.bind(("0.0.0.0", local_port))
            local_addr = sock.getsockname()

            for server in self.stun_servers:
                try:
                    result = self._query_server(sock, server)
                    if result.success:
                        result.local_ip = local_addr[0]
                        result.local_port = local_addr[1]
                        return result
                except Exception as e:
                    logger.debug(f"STUN server {server} failed: {e}")
                    continue

            return STUNResult(success=False, nat_type=NATType.BLOCKED)

        finally:
            sock.close()

    def _query_server(self, sock: socket.socket,
                      server: Tuple[str, int]) -> STUNResult:
        """Query a single STUN server"""
        # Build STUN Binding Request
        self._transaction_id = os.urandom(12)
        request = self._build_binding_request()

        start = time.time()
        sock.sendto(request, server)
        response, _ = sock.recvfrom(1024)
        latency = (time.time() - start) * 1000

        # Parse response
        public_ip, public_port = self._parse_binding_response(response)

        if public_ip:
            return STUNResult(
                success=True,
                public_ip=public_ip,
                public_port=public_port,
                latency_ms=latency,
                server=f"{server[0]}:{server[1]}"
            )

        return STUNResult(success=False)

    def _build_binding_request(self) -> bytes:
        """Build STUN Binding Request message"""
        # Message Type (2) + Message Length (2) + Magic Cookie (4) + Transaction ID (12)
        header = struct.pack(">HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE)
        return header + self._transaction_id

    def _parse_binding_response(self, data: bytes) -> Tuple[Optional[str], Optional[int]]:
        """Parse STUN Binding Response for mapped address"""
        if len(data) < 20:
            return None, None

        msg_type, msg_len, magic = struct.unpack(">HHI", data[:8])

        if msg_type != STUN_BINDING_RESPONSE:
            return None, None

        if magic != STUN_MAGIC_COOKIE:
            return None, None

        # Parse attributes
        pos = 20  # After header
        while pos + 4 <= len(data):
            attr_type, attr_len = struct.unpack(">HH", data[pos:pos+4])
            pos += 4

            if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS:
                return self._parse_xor_mapped_address(data[pos:pos+attr_len])
            elif attr_type == STUN_ATTR_MAPPED_ADDRESS:
                return self._parse_mapped_address(data[pos:pos+attr_len])

            # Align to 4 bytes
            pos += attr_len + (4 - attr_len % 4) % 4

        return None, None

    def _parse_xor_mapped_address(self, data: bytes) -> Tuple[Optional[str], Optional[int]]:
        """Parse XOR-MAPPED-ADDRESS attribute"""
        if len(data) < 8:
            return None, None

        family = data[1]
        xport = struct.unpack(">H", data[2:4])[0]
        port = xport ^ (STUN_MAGIC_COOKIE >> 16)

        if family == 0x01:  # IPv4
            xaddr = struct.unpack(">I", data[4:8])[0]
            addr = xaddr ^ STUN_MAGIC_COOKIE
            ip = socket.inet_ntoa(struct.pack(">I", addr))
            return ip, port

        return None, None

    def _parse_mapped_address(self, data: bytes) -> Tuple[Optional[str], Optional[int]]:
        """Parse MAPPED-ADDRESS attribute (legacy)"""
        if len(data) < 8:
            return None, None

        family = data[1]
        port = struct.unpack(">H", data[2:4])[0]

        if family == 0x01:  # IPv4
            ip = socket.inet_ntoa(data[4:8])
            return ip, port

        return None, None

    def detect_nat_type(self, local_port: int = 0) -> NATType:
        """
        Detect NAT type using multiple STUN queries.

        Returns:
            NATType classification
        """
        # First query - get initial mapping
        result1 = self.discover(local_port)
        if not result1.success:
            return NATType.BLOCKED

        # Check if public IP matches local IP (no NAT)
        try:
            local_ips = self._get_local_ips()
            if result1.public_ip in local_ips:
                return NATType.OPEN
        except Exception:
            pass

        # Second query to different server
        if len(self.stun_servers) > 1:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.bind(("0.0.0.0", result1.local_port))  # Same local port
                result2 = self._query_server(sock, self.stun_servers[1])

                if result2.success:
                    if (result1.public_ip == result2.public_ip and
                        result1.public_port == result2.public_port):
                        # Same mapping = Cone NAT
                        return NATType.FULL_CONE
                    else:
                        # Different mapping = Symmetric NAT
                        return NATType.SYMMETRIC
            finally:
                sock.close()

        # Assume restricted cone if we can't determine
        return NATType.PORT_RESTRICTED

    def _get_local_ips(self) -> Set[str]:
        """Get all local IP addresses"""
        ips = set()
        try:
            hostname = socket.gethostname()
            ips.add(socket.gethostbyname(hostname))
        except Exception:
            pass

        # Try to get IP by connecting to external host
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass

        return ips


# ============================================================
# ICE AGENT
# ============================================================

class ICEAgent:
    """
    ICE (Interactive Connectivity Establishment) agent.

    Coordinates NAT traversal using candidate gathering,
    connectivity checks, and candidate prioritization.
    """

    def __init__(self, node_id: str, stun_client: STUNClient = None,
                 relay_servers: List[Tuple[str, int]] = None):
        self.node_id = node_id
        self.stun = stun_client or STUNClient()
        self.relay_servers = relay_servers or []

        self.local_candidates: List[ICECandidate] = []
        self.remote_candidates: List[ICECandidate] = []
        self.selected_pair: Optional[Tuple[ICECandidate, ICECandidate]] = None

        self._sock: Optional[socket.socket] = None
        self._local_port: int = 0
        self._lock = Lock()

    def gather_candidates(self, local_port: int = 0) -> List[ICECandidate]:
        """
        Gather all ICE candidates (host, server reflexive, relay).

        Args:
            local_port: Local port to use (0 for random)

        Returns:
            List of gathered ICE candidates
        """
        candidates = []

        # Create and bind socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", local_port))
        self._local_port = self._sock.getsockname()[1]

        # 1. Host candidates (local addresses)
        host_candidates = self._gather_host_candidates()
        candidates.extend(host_candidates)

        # 2. Server reflexive candidates (STUN)
        srflx_candidates = self._gather_srflx_candidates()
        candidates.extend(srflx_candidates)

        # 3. Relay candidates (TURN) - if available
        if self.relay_servers:
            relay_candidates = self._gather_relay_candidates()
            candidates.extend(relay_candidates)

        # Sort by priority (highest first)
        candidates.sort(key=lambda c: c.priority, reverse=True)

        with self._lock:
            self.local_candidates = candidates

        logger.info(f"[ICE] Gathered {len(candidates)} candidates")
        return candidates

    def _gather_host_candidates(self) -> List[ICECandidate]:
        """Gather host (local) candidates"""
        candidates = []

        # Get local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            candidate = ICECandidate.from_tuple(
                (local_ip, self._local_port),
                ctype="host",
                priority=ICECandidate._calc_priority("host")
            )
            candidates.append(candidate)
            logger.debug(f"[ICE] Host candidate: {local_ip}:{self._local_port}")

        except Exception as e:
            logger.warning(f"[ICE] Failed to get host candidate: {e}")

        return candidates

    def _gather_srflx_candidates(self) -> List[ICECandidate]:
        """Gather server reflexive candidates via STUN"""
        candidates = []

        result = self.stun.discover(self._local_port)
        if result.success and result.public_ip:
            candidate = ICECandidate(
                type="srflx",
                ip=result.public_ip,
                port=result.public_port,
                priority=ICECandidate._calc_priority("srflx"),
                foundation=hashlib.md5(
                    f"srflx:{result.public_ip}:{result.public_port}".encode(),
                    usedforsecurity=False
                ).hexdigest()[:8],
                related_ip=result.local_ip,
                related_port=result.local_port
            )
            candidates.append(candidate)
            logger.debug(f"[ICE] SRFLX candidate: {result.public_ip}:{result.public_port}")

        return candidates

    def _gather_relay_candidates(self) -> List[ICECandidate]:
        """Gather relay candidates via TURN"""
        # Placeholder - TURN requires authentication
        # In production, this would allocate relay addresses
        return []

    def set_remote_candidates(self, candidates: List[ICECandidate]):
        """Set remote peer's ICE candidates"""
        with self._lock:
            self.remote_candidates = sorted(
                candidates,
                key=lambda c: c.priority,
                reverse=True
            )
        logger.info(f"[ICE] Set {len(candidates)} remote candidates")

    def check_connectivity(self, timeout: float = 5.0) -> Optional[Tuple[ICECandidate, ICECandidate]]:
        """
        Perform connectivity checks to find working candidate pair.

        Returns:
            Tuple of (local_candidate, remote_candidate) if successful
        """
        if not self._sock or not self.remote_candidates:
            return None

        self._sock.settimeout(0.5)

        # Try candidates in priority order
        for remote in self.remote_candidates:
            for local in self.local_candidates:
                if self._check_pair(local, remote, timeout / len(self.remote_candidates)):
                    with self._lock:
                        self.selected_pair = (local, remote)
                    logger.info(f"[ICE] Selected pair: {local.ip}:{local.port} <-> {remote.ip}:{remote.port}")
                    return self.selected_pair

        return None

    def _check_pair(self, local: ICECandidate, remote: ICECandidate,
                    timeout: float) -> bool:
        """Check connectivity for a candidate pair"""
        try:
            # Send connectivity check
            check_id = os.urandom(8)
            check_msg = b"HOOKPROBE_ICE_CHECK:" + check_id + self.node_id.encode()[:16]

            addr = (remote.ip, remote.port)
            self._sock.sendto(check_msg, addr)

            # Wait for response
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, recv_addr = self._sock.recvfrom(1024)
                    if data.startswith(b"HOOKPROBE_ICE_RESPONSE:") and check_id in data:
                        return True
                except socket.timeout:
                    continue

        except Exception as e:
            logger.debug(f"[ICE] Check failed {remote.ip}:{remote.port}: {e}")

        return False

    def respond_to_checks(self):
        """Process and respond to incoming connectivity checks"""
        if not self._sock:
            return

        try:
            self._sock.settimeout(0.1)
            data, addr = self._sock.recvfrom(1024)

            if data.startswith(b"HOOKPROBE_ICE_CHECK:"):
                check_id = data[20:28]
                response = b"HOOKPROBE_ICE_RESPONSE:" + check_id + self.node_id.encode()[:16]
                self._sock.sendto(response, addr)

        except socket.timeout:
            pass
        except Exception as e:
            logger.debug(f"[ICE] Response error: {e}")


# ============================================================
# UDP HOLE PUNCHER
# ============================================================

class UDPHolePuncher:
    """
    UDP hole punching for symmetric NAT traversal.

    Uses coordinated simultaneous connection attempts
    to punch holes through NAT devices.
    """

    def __init__(self, local_port: int = 0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", local_port))
        self.local_port = self.sock.getsockname()[1]

    def punch(self, target_ip: str, target_port: int,
              rendezvous_time: float = None,
              attempts: int = 10,
              interval: float = 0.1) -> bool:
        """
        Attempt to punch hole through NAT.

        Args:
            target_ip: Remote peer's public IP
            target_port: Remote peer's public port
            rendezvous_time: Synchronized start time (Unix timestamp)
            attempts: Number of punch attempts
            interval: Time between attempts

        Returns:
            True if hole punched successfully
        """
        target = (target_ip, target_port)

        # Wait for rendezvous time if specified
        if rendezvous_time:
            wait_time = rendezvous_time - time.time()
            if wait_time > 0:
                time.sleep(wait_time)

        # Send punch packets
        punch_msg = b"HOOKPROBE_PUNCH:" + struct.pack(">d", time.time())

        for i in range(attempts):
            try:
                self.sock.sendto(punch_msg, target)
                time.sleep(interval)
            except Exception as e:
                logger.debug(f"[PUNCH] Send failed: {e}")

        # Try to receive response
        self.sock.settimeout(2.0)
        try:
            for _ in range(attempts):
                data, addr = self.sock.recvfrom(1024)
                if addr[0] == target_ip and data.startswith(b"HOOKPROBE_PUNCH"):
                    logger.info(f"[PUNCH] Hole punched to {target_ip}:{target_port}")
                    return True
        except socket.timeout:
            pass

        return False

    def listen_for_punch(self, expected_ip: str = None,
                        timeout: float = 5.0) -> Optional[Tuple[str, int]]:
        """
        Listen for incoming punch packets.

        Returns:
            (ip, port) of punching peer if successful
        """
        self.sock.settimeout(timeout)
        start = time.time()

        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(1024)
                if data.startswith(b"HOOKPROBE_PUNCH"):
                    if expected_ip is None or addr[0] == expected_ip:
                        # Send response
                        self.sock.sendto(b"HOOKPROBE_PUNCH_ACK", addr)
                        return addr
            except socket.timeout:
                continue

        return None


# ============================================================
# MESH PROMOTION PROTOCOL
# ============================================================

class MeshPromotion(IntEnum):
    """Node promotion levels when MSSP unavailable"""
    LEAF = 0          # Regular node, no promotion
    BRIDGE = 1        # Can relay between local networks
    COORDINATOR = 2   # Can coordinate peer discovery
    SUPER_NODE = 3    # Full MSSP-lite capabilities


@dataclass
class PromotedNode:
    """Information about a promoted node acting as coordinator"""
    node_id: str
    public_ip: str
    public_port: int
    promotion_level: MeshPromotion
    capacity: int  # Max peers it can handle
    current_load: int
    region: str
    promoted_at: float
    last_seen: float


class MeshPromotionManager:
    """
    Manages mesh node promotion when MSSP is unavailable.

    The Innovation: Automatic coordinator election based on:
    1. Public IP availability (required)
    2. Node tier (Fortress/Nexus preferred)
    3. Network capacity
    4. Geographic distribution
    """

    # Promotion capacity by tier
    TIER_CAPACITY = {
        "sentinel": 5,
        "guardian": 10,
        "fortress": 50,
        "nexus": 100,
    }

    def __init__(self, node_id: str, tier: str = "sentinel",
                 region: str = "unknown"):
        self.node_id = node_id
        self.tier = tier
        self.region = region

        self.promotion_level = MeshPromotion.LEAF
        self.is_promoted = False
        self.public_endpoint: Optional[Tuple[str, int]] = None

        # Known promoted nodes
        self.coordinators: Dict[str, PromotedNode] = {}
        self._lock = Lock()

        # STUN for public IP detection
        self.stun = STUNClient()

    def check_promotability(self) -> Tuple[bool, MeshPromotion]:
        """
        Check if this node can be promoted to coordinator.

        Returns:
            (can_promote, suggested_level)
        """
        # Check for public IP
        result = self.stun.discover()
        if not result.success:
            return False, MeshPromotion.LEAF

        # Detect NAT type
        nat_type = self.stun.detect_nat_type()

        # Only open or full cone NAT can be coordinators
        if nat_type not in (NATType.OPEN, NATType.FULL_CONE):
            return False, MeshPromotion.LEAF

        self.public_endpoint = (result.public_ip, result.public_port)

        # Determine promotion level based on tier
        if self.tier in ("nexus", "mssp"):
            return True, MeshPromotion.SUPER_NODE
        elif self.tier == "fortress":
            return True, MeshPromotion.COORDINATOR
        elif self.tier == "guardian":
            return True, MeshPromotion.BRIDGE
        else:
            return True, MeshPromotion.BRIDGE

    def promote(self, level: MeshPromotion = None) -> bool:
        """
        Promote this node to a coordinator role.

        Returns:
            True if promotion successful
        """
        can_promote, suggested_level = self.check_promotability()
        if not can_promote:
            return False

        level = level or suggested_level

        with self._lock:
            self.promotion_level = level
            self.is_promoted = True

        logger.info(f"[PROMOTION] Node promoted to {level.name}: "
                   f"{self.public_endpoint[0]}:{self.public_endpoint[1]}")
        return True

    def demote(self):
        """Demote this node back to leaf"""
        with self._lock:
            self.promotion_level = MeshPromotion.LEAF
            self.is_promoted = False
        logger.info("[PROMOTION] Node demoted to LEAF")

    def register_coordinator(self, node: PromotedNode):
        """Register a known promoted coordinator"""
        with self._lock:
            self.coordinators[node.node_id] = node
            logger.debug(f"[PROMOTION] Registered coordinator: {node.node_id}")

    def unregister_coordinator(self, node_id: str):
        """Unregister a coordinator"""
        with self._lock:
            self.coordinators.pop(node_id, None)

    def get_best_coordinator(self) -> Optional[PromotedNode]:
        """Get the best available coordinator for connection"""
        with self._lock:
            if not self.coordinators:
                return None

            # Sort by: promotion level (desc), load ratio (asc), last_seen (desc)
            available = [
                n for n in self.coordinators.values()
                if time.time() - n.last_seen < 300  # Last 5 minutes
            ]

            if not available:
                return None

            return min(available, key=lambda n: (
                -n.promotion_level,
                n.current_load / max(n.capacity, 1),
                -(time.time() - n.last_seen)
            ))

    def get_my_promotion_info(self) -> Optional[PromotedNode]:
        """Get this node's promotion info if promoted"""
        if not self.is_promoted or not self.public_endpoint:
            return None

        return PromotedNode(
            node_id=self.node_id,
            public_ip=self.public_endpoint[0],
            public_port=self.public_endpoint[1],
            promotion_level=self.promotion_level,
            capacity=self.TIER_CAPACITY.get(self.tier, 5),
            current_load=0,  # Would be updated by actual peer count
            region=self.region,
            promoted_at=time.time(),
            last_seen=time.time()
        )


# ============================================================
# RENDEZVOUS SERVICE
# ============================================================

class RendezvousPoint:
    """
    Decentralized rendezvous point for peer discovery.

    When MSSP is unavailable, nodes can discover each other
    through promoted coordinators acting as rendezvous points.
    """

    def __init__(self, promotion_manager: MeshPromotionManager):
        self.manager = promotion_manager
        self.waiting_peers: Dict[str, Tuple[str, int, float]] = {}  # node_id -> (ip, port, time)
        self._lock = Lock()

    def register(self, node_id: str, endpoint: Tuple[str, int]) -> bool:
        """Register a peer at this rendezvous point"""
        with self._lock:
            self.waiting_peers[node_id] = (endpoint[0], endpoint[1], time.time())
        return True

    def unregister(self, node_id: str):
        """Unregister a peer"""
        with self._lock:
            self.waiting_peers.pop(node_id, None)

    def lookup(self, node_id: str) -> Optional[Tuple[str, int]]:
        """Look up a peer's endpoint"""
        with self._lock:
            peer = self.waiting_peers.get(node_id)
            if peer:
                return (peer[0], peer[1])
        return None

    def get_all_peers(self) -> List[Tuple[str, str, int]]:
        """Get all registered peers"""
        with self._lock:
            return [
                (node_id, ip, port)
                for node_id, (ip, port, _) in self.waiting_peers.items()
            ]

    def cleanup(self, max_age: float = 300.0):
        """Remove stale peer registrations"""
        now = time.time()
        with self._lock:
            expired = [
                nid for nid, (_, _, ts) in self.waiting_peers.items()
                if now - ts > max_age
            ]
            for nid in expired:
                del self.waiting_peers[nid]


# ============================================================
# NAT TRAVERSAL MANAGER
# ============================================================

class NATTraversalManager:
    """
    High-level NAT traversal manager combining all techniques.

    Provides a simple interface for establishing P2P connections
    through NAT/CGNAT with automatic fallback to relay.
    """

    def __init__(self, node_id: str, tier: str = "sentinel",
                 region: str = "unknown"):
        self.node_id = node_id
        self.tier = tier
        self.region = region

        # Components
        self.stun = STUNClient()
        self.ice = ICEAgent(node_id, self.stun)
        self.promotion = MeshPromotionManager(node_id, tier, region)
        self.rendezvous = RendezvousPoint(self.promotion)

        # State
        self.public_endpoint: Optional[Tuple[str, int]] = None
        self.nat_type: NATType = NATType.UNKNOWN
        self.ready = False

        # Connected peers
        self.peer_connections: Dict[str, PeerEndpoint] = {}
        self._lock = Lock()

    def initialize(self) -> bool:
        """
        Initialize NAT traversal, discover public endpoint.

        Returns:
            True if initialization successful
        """
        # Discover public endpoint
        result = self.stun.discover()
        if result.success:
            self.public_endpoint = (result.public_ip, result.public_port)
            self.nat_type = self.stun.detect_nat_type()
            logger.info(f"[NAT] Public endpoint: {self.public_endpoint}, "
                       f"NAT type: {self.nat_type.name}")
        else:
            logger.warning("[NAT] Could not discover public endpoint")
            self.nat_type = NATType.BLOCKED

        # Check if we can be promoted
        if self.nat_type in (NATType.OPEN, NATType.FULL_CONE):
            self.promotion.promote()

        self.ready = True
        return result.success

    def connect_to_peer(self, peer_id: str,
                        peer_candidates: List[ICECandidate] = None,
                        coordinator: PromotedNode = None) -> PeerEndpoint:
        """
        Establish connection to a peer through NAT.

        Args:
            peer_id: Remote peer's node ID
            peer_candidates: Remote peer's ICE candidates (if known)
            coordinator: Coordinator to use for introduction

        Returns:
            PeerEndpoint with connection details
        """
        endpoint = PeerEndpoint(node_id=peer_id)

        # Gather our candidates
        local_candidates = self.ice.gather_candidates()

        if peer_candidates:
            # Direct ICE connectivity check
            self.ice.set_remote_candidates(peer_candidates)
            result = self.ice.check_connectivity()

            if result:
                endpoint.candidates = local_candidates
                endpoint.selected_candidate = result[1]
                endpoint.connectivity = ConnectivityType.DIRECT
                logger.info(f"[NAT] Direct connection to {peer_id}")

                with self._lock:
                    self.peer_connections[peer_id] = endpoint
                return endpoint

        # Try hole punching if we have peer's public endpoint
        if peer_candidates:
            srflx = next((c for c in peer_candidates if c.type == "srflx"), None)
            if srflx:
                puncher = UDPHolePuncher(self.ice._local_port)
                if puncher.punch(srflx.ip, srflx.port):
                    endpoint.connectivity = ConnectivityType.HOLE_PUNCHED
                    endpoint.selected_candidate = srflx

                    with self._lock:
                        self.peer_connections[peer_id] = endpoint
                    return endpoint

        # Fallback to relay through coordinator
        if coordinator:
            endpoint.connectivity = ConnectivityType.RELAYED
            endpoint.relay_node = coordinator.node_id
            logger.info(f"[NAT] Relayed connection to {peer_id} via {coordinator.node_id}")

            with self._lock:
                self.peer_connections[peer_id] = endpoint
            return endpoint

        # Connection failed
        endpoint.connectivity = ConnectivityType.FAILED
        logger.warning(f"[NAT] Failed to connect to {peer_id}")
        return endpoint

    def get_my_candidates(self) -> List[ICECandidate]:
        """Get this node's ICE candidates"""
        if not self.ice.local_candidates:
            self.ice.gather_candidates()
        return self.ice.local_candidates

    def get_connection_status(self, peer_id: str) -> Optional[PeerEndpoint]:
        """Get connection status to a peer"""
        with self._lock:
            return self.peer_connections.get(peer_id)


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    "NATType",
    "ConnectivityType",
    "MeshPromotion",

    # Data classes
    "STUNResult",
    "ICECandidate",
    "PeerEndpoint",
    "PromotedNode",

    # Components
    "STUNClient",
    "ICEAgent",
    "UDPHolePuncher",
    "MeshPromotionManager",
    "RendezvousPoint",
    "NATTraversalManager",
]
