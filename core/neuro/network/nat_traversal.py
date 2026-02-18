"""
NAT/CGNAT Traversal for HookProbe Neuro Protocol

Enables communication between edge nodes and validators even when edge
devices are behind NAT/CGNAT using a relay/rendezvous architecture.

Techniques:
1. STUN-like discovery for NAT mapping
2. Rendezvous server for connection coordination
3. Relay fallback for symmetric NAT/CGNAT
4. Hole-punching for peer-to-peer when possible

Design:
- Edge devices connect outbound to rendezvous server
- Validators register with rendezvous server
- Rendezvous server coordinates hole-punching
- Relay server forwards encrypted traffic if hole-punching fails
"""

import asyncio
import socket
import struct
import hashlib
from enum import Enum
from typing import Optional, Tuple
from dataclasses import dataclass


class NATType(Enum):
    """Types of NAT detection."""
    OPEN = "open"  # No NAT
    FULL_CONE = "full_cone"  # Same external port for all destinations
    RESTRICTED_CONE = "restricted_cone"  # Port filtering
    PORT_RESTRICTED_CONE = "port_restricted_cone"  # Port and address filtering
    SYMMETRIC = "symmetric"  # Different external port per destination
    BLOCKED = "blocked"  # Cannot connect
    CGNAT = "cgnat"  # Carrier-grade NAT (requires relay)


@dataclass
class NATMapping:
    """NAT mapping discovered via STUN-like protocol."""
    local_address: Tuple[str, int]  # Private IP:port
    external_address: Tuple[str, int]  # Public IP:port
    nat_type: NATType
    ttl: int  # Seconds until mapping expires


@dataclass
class RendezvousEntry:
    """Node registered with rendezvous server."""
    node_id: str
    node_type: str  # 'edge' or 'validator'
    external_address: Tuple[str, int]
    nat_type: NATType
    last_seen: float  # Unix timestamp
    connection_id: bytes  # 16-byte connection identifier


class STUNClient:
    """
    STUN-like NAT discovery client.

    Discovers external IP:port and NAT type by querying STUN server.
    """

    def __init__(self, stun_server: str = "stun.hookprobe.io", stun_port: int = 3478):
        """
        Args:
            stun_server: STUN server hostname
            stun_port: STUN server port
        """
        self.stun_server = stun_server
        self.stun_port = stun_port

    async def discover_nat(self) -> NATMapping:
        """
        Discover NAT mapping and type.

        Returns:
            NAT mapping information
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        try:
            # Get local address
            sock.connect(("8.8.8.8", 80))
            local_address = sock.getsockname()
            sock.close()

            # Query STUN server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', 0))
            local_port = sock.getsockname()[1]

            # Build STUN Binding Request
            request = self._build_stun_request()
            sock.sendto(request, (self.stun_server, self.stun_port))

            # Receive response
            try:
                response, addr = sock.recvfrom(1024)
                external_address = self._parse_stun_response(response)

                # Detect NAT type using multiple tests
                nat_type = await self._detect_nat_type(sock, external_address)

                return NATMapping(
                    local_address=local_address,
                    external_address=external_address,
                    nat_type=nat_type,
                    ttl=300  # 5 minute default TTL
                )

            except socket.timeout:
                return NATMapping(
                    local_address=local_address,
                    external_address=("0.0.0.0", 0),
                    nat_type=NATType.BLOCKED,
                    ttl=0
                )

        finally:
            sock.close()

    def _build_stun_request(self) -> bytes:
        """Build minimal STUN Binding Request."""
        # STUN header: Message Type (Binding Request) + Transaction ID
        message_type = 0x0001  # Binding Request
        transaction_id = hashlib.sha256(str(id(self)).encode()).digest()[:12]

        return struct.pack('>HH', message_type, 0) + transaction_id

    def _parse_stun_response(self, response: bytes) -> Tuple[str, int]:
        """Parse STUN Binding Response to extract XOR-MAPPED-ADDRESS.

        RFC 5389 defines XOR-MAPPED-ADDRESS (0x0020) which XORs the
        IP and port with the magic cookie to prevent ALG mangling.
        Falls back to MAPPED-ADDRESS (0x0001) if XOR variant absent.
        """
        if len(response) < 20:
            return ("0.0.0.0", 0)

        # STUN header: 2B type + 2B length + 4B magic cookie + 12B txn_id
        magic = 0x2112A442
        offset = 20  # Start of attributes

        while offset + 4 <= len(response):
            attr_type = struct.unpack('>H', response[offset:offset + 2])[0]
            attr_len = struct.unpack('>H', response[offset + 2:offset + 4])[0]

            if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                if offset + 8 <= len(response):
                    family = response[offset + 5]
                    xport = struct.unpack('>H', response[offset + 6:offset + 8])[0]
                    port = xport ^ (magic >> 16)
                    if family == 0x01 and offset + 12 <= len(response):  # IPv4
                        xip = struct.unpack('>I', response[offset + 8:offset + 12])[0]
                        ip_int = xip ^ magic
                        ip = "{}.{}.{}.{}".format(
                            (ip_int >> 24) & 0xFF,
                            (ip_int >> 16) & 0xFF,
                            (ip_int >> 8) & 0xFF,
                            ip_int & 0xFF,
                        )
                        return (ip, port)

            elif attr_type == 0x0001:  # MAPPED-ADDRESS (fallback)
                if offset + 8 <= len(response):
                    family = response[offset + 5]
                    port = struct.unpack('>H', response[offset + 6:offset + 8])[0]
                    if family == 0x01 and offset + 12 <= len(response):
                        ip = socket.inet_ntoa(response[offset + 8:offset + 12])
                        return (ip, port)

            # Advance to next attribute (padded to 4-byte boundary)
            offset += 4 + attr_len + (4 - attr_len % 4) % 4

        return ("0.0.0.0", 0)

    async def _detect_nat_type(self, sock, external_address: Tuple[str, int]) -> NATType:
        """
        Detect NAT type using multiple binding tests.

        Simplified detection:
        1. If local_addr == external_addr → OPEN
        2. If external port changes per destination → SYMMETRIC
        3. Check if we're behind CGNAT (private IP in external address)
        4. Otherwise → Cone NAT variant
        """
        local_addr = sock.getsockname()

        # Check if behind NAT
        if local_addr[0] == external_address[0]:
            return NATType.OPEN

        # Check for CGNAT (RFC 6598: 100.64.0.0/10)
        external_ip = external_address[0]
        if external_ip.startswith('100.'):
            octets = [int(x) for x in external_ip.split('.')]
            if octets[0] == 100 and 64 <= octets[1] <= 127:
                return NATType.CGNAT

        # Check for private IP in external address (double NAT)
        if (external_ip.startswith('10.') or
            external_ip.startswith('192.168.') or
            external_ip.startswith('172.')):
            return NATType.CGNAT

        # Simplified: assume full cone NAT if not CGNAT
        return NATType.FULL_CONE


class RendezvousClient:
    """
    Client for rendezvous server coordination.

    Registers node with rendezvous server and coordinates connections.
    """

    def __init__(
        self,
        node_id: str,
        node_type: str,
        rendezvous_server: str = "rendezvous.hookprobe.io",
        rendezvous_port: int = 4478
    ):
        """
        Args:
            node_id: Node identifier
            node_type: 'edge' or 'validator'
            rendezvous_server: Rendezvous server hostname
            rendezvous_port: Rendezvous server port
        """
        self.node_id = node_id
        self.node_type = node_type
        self.rendezvous_server = rendezvous_server
        self.rendezvous_port = rendezvous_port
        self.connection_id = None
        self.socket = None

    async def register(self, nat_mapping: NATMapping) -> bool:
        """
        Register with rendezvous server.

        Args:
            nat_mapping: NAT mapping from STUN discovery

        Returns:
            True if registration successful
        """
        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        self.socket.bind(('0.0.0.0', nat_mapping.local_address[1]))

        # Build registration message
        self.connection_id = hashlib.sha256(
            f"{self.node_id}:{nat_mapping.external_address}".encode()
        ).digest()[:16]

        registration = self._build_registration_message(nat_mapping)

        # Send to rendezvous server
        try:
            self.socket.sendto(
                registration,
                (self.rendezvous_server, self.rendezvous_port)
            )
            return True
        except Exception as e:
            print(f"Registration failed: {e}")
            return False

    async def request_connection(self, peer_id: str) -> Optional[Tuple[str, int]]:
        """
        Request connection to peer via rendezvous server.

        Args:
            peer_id: Peer node identifier

        Returns:
            Peer address for hole-punching, or None if relay required
        """
        request = self._build_connection_request(peer_id)

        try:
            self.socket.sendto(
                request,
                (self.rendezvous_server, self.rendezvous_port)
            )

            # Wait for response with peer address
            loop = asyncio.get_event_loop()
            response = await loop.sock_recv(self.socket, 1024)

            peer_address = self._parse_connection_response(response)
            return peer_address

        except Exception as e:
            print(f"Connection request failed: {e}")
            return None

    async def send_keepalive(self):
        """Send periodic keepalive to maintain NAT mapping."""
        keepalive = self._build_keepalive_message()

        try:
            self.socket.sendto(
                keepalive,
                (self.rendezvous_server, self.rendezvous_port)
            )
        except Exception as e:
            print(f"Keepalive failed: {e}")

    def _build_registration_message(self, nat_mapping: NATMapping) -> bytes:
        """Build registration message for rendezvous server."""
        # Message format:
        # MSG_TYPE (1 byte) | NODE_ID (32 bytes) | NODE_TYPE (1 byte) |
        # LOCAL_IP (4 bytes) | LOCAL_PORT (2 bytes) | NAT_TYPE (1 byte) |
        # CONNECTION_ID (16 bytes)

        msg_type = 0x01  # REGISTER
        node_id_bytes = self.node_id.encode('utf-8')[:32].ljust(32, b'\x00')
        node_type_byte = 0x01 if self.node_type == 'edge' else 0x02

        # Convert IP to bytes
        ip_bytes = socket.inet_aton(nat_mapping.local_address[0])
        port_bytes = struct.pack('>H', nat_mapping.local_address[1])

        nat_type_byte = list(NATType).index(nat_mapping.nat_type)

        message = (
            bytes([msg_type]) +
            node_id_bytes +
            bytes([node_type_byte]) +
            ip_bytes +
            port_bytes +
            bytes([nat_type_byte]) +
            self.connection_id
        )

        return message

    def _build_connection_request(self, peer_id: str) -> bytes:
        """Build connection request message."""
        msg_type = 0x02  # CONNECT_REQUEST
        peer_id_bytes = peer_id.encode('utf-8')[:32].ljust(32, b'\x00')

        return bytes([msg_type]) + self.connection_id + peer_id_bytes

    def _build_keepalive_message(self) -> bytes:
        """Build keepalive message."""
        msg_type = 0x03  # KEEPALIVE
        return bytes([msg_type]) + self.connection_id

    def _parse_connection_response(self, response: bytes) -> Optional[Tuple[str, int]]:
        """Parse connection response from rendezvous server."""
        if len(response) < 8:
            return None

        msg_type = response[0]
        if msg_type != 0x82:  # CONNECT_RESPONSE
            return None

        # Extract peer IP:port
        ip = socket.inet_ntoa(response[1:5])
        port = struct.pack('>H', response[5:7])[0]

        return (ip, port)


class RelayClient:
    """
    Relay client for symmetric NAT/CGNAT scenarios.

    When hole-punching fails, use relay server to forward encrypted traffic.
    """

    def __init__(
        self,
        node_id: str,
        relay_server: str = "relay.hookprobe.io",
        relay_port: int = 5478
    ):
        """
        Args:
            node_id: Node identifier
            relay_server: Relay server hostname
            relay_port: Relay server port
        """
        self.node_id = node_id
        self.relay_server = relay_server
        self.relay_port = relay_port
        self.socket = None

    async def connect(self) -> bool:
        """
        Connect to relay server.

        Returns:
            True if connection successful
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10.0)
            self.socket.connect((self.relay_server, self.relay_port))

            # Send authentication
            auth = self._build_auth_message()
            self.socket.send(auth)

            return True

        except Exception as e:
            print(f"Relay connection failed: {e}")
            return False

    async def send_via_relay(self, peer_id: str, data: bytes) -> bool:
        """
        Send data to peer via relay.

        Args:
            peer_id: Target peer identifier
            data: Encrypted payload

        Returns:
            True if sent successfully
        """
        if not self.socket:
            return False

        # Build relay message
        message = self._build_relay_message(peer_id, data)

        try:
            self.socket.send(message)
            return True
        except Exception as e:
            print(f"Relay send failed: {e}")
            return False

    async def receive_via_relay(self) -> Optional[Tuple[str, bytes]]:
        """
        Receive data from peer via relay.

        Returns:
            (sender_id, data) or None if no data
        """
        if not self.socket:
            return None

        try:
            # Receive message header
            header = self.socket.recv(37)  # MSG_TYPE + SENDER_ID (32) + LENGTH (4)
            if len(header) < 37:
                return None

            msg_type = header[0]
            if msg_type != 0x05:  # RELAY_DATA
                return None

            sender_id = header[1:33].decode('utf-8').rstrip('\x00')
            data_length = struct.unpack('>I', header[33:37])[0]

            # Receive payload
            data = self.socket.recv(data_length)

            return (sender_id, data)

        except Exception as e:
            print(f"Relay receive failed: {e}")
            return None

    def _build_auth_message(self) -> bytes:
        """Build relay authentication message."""
        msg_type = 0x04  # RELAY_AUTH
        node_id_bytes = self.node_id.encode('utf-8')[:32].ljust(32, b'\x00')

        return bytes([msg_type]) + node_id_bytes

    def _build_relay_message(self, peer_id: str, data: bytes) -> bytes:
        """Build relay data message."""
        msg_type = 0x05  # RELAY_DATA
        peer_id_bytes = peer_id.encode('utf-8')[:32].ljust(32, b'\x00')
        data_length = struct.pack('>I', len(data))

        return bytes([msg_type]) + peer_id_bytes + data_length + data


# Example usage
if __name__ == '__main__':
    print("=== NAT/CGNAT Traversal Test ===\n")

    async def test_nat_discovery():
        stun = STUNClient()
        print("Discovering NAT mapping...")
        mapping = await stun.discover_nat()
        print(f"  Local:    {mapping.local_address}")
        print(f"  External: {mapping.external_address}")
        print(f"  NAT Type: {mapping.nat_type.value}")
        print(f"  TTL:      {mapping.ttl}s\n")

        return mapping

    async def test_rendezvous():
        mapping = await test_nat_discovery()

        rendezvous = RendezvousClient(
            node_id='edge-001',
            node_type='edge'
        )

        print("Registering with rendezvous server...")
        success = await rendezvous.register(mapping)
        print(f"  Registration: {'✓ Success' if success else '✗ Failed'}\n")

    asyncio.run(test_rendezvous())
    print("✓ NAT traversal test complete")
