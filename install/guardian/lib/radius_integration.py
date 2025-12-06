"""
RADIUS Integration for Guardian

Provides MAC-based authentication and VLAN assignment using RADIUS/FreeRADIUS.
Supports dynamic VLAN assignment, MAC authentication bypass (MAB), and
integration with the OpenFlow controller for policy enforcement.

Author: HookProbe Team
Version: 5.0.0 Liberty
License: MIT
"""

import asyncio
import hashlib
import hmac
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Callable, Set, Tuple, Any
from collections import defaultdict
import threading
import json

logger = logging.getLogger(__name__)


# RADIUS Constants
RADIUS_AUTH_PORT = 1812
RADIUS_ACCT_PORT = 1813
RADIUS_COA_PORT = 3799  # Change of Authorization

RADIUS_MAX_PACKET_SIZE = 4096
RADIUS_HEADER_SIZE = 20


class RADIUSCode(IntEnum):
    """RADIUS packet codes"""
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13
    DISCONNECT_REQUEST = 40
    DISCONNECT_ACK = 41
    DISCONNECT_NAK = 42
    COA_REQUEST = 43
    COA_ACK = 44
    COA_NAK = 45


class RADIUSAttribute(IntEnum):
    """Standard RADIUS attributes"""
    USER_NAME = 1
    USER_PASSWORD = 2
    CHAP_PASSWORD = 3
    NAS_IP_ADDRESS = 4
    NAS_PORT = 5
    SERVICE_TYPE = 6
    FRAMED_PROTOCOL = 7
    FRAMED_IP_ADDRESS = 8
    FRAMED_IP_NETMASK = 9
    FRAMED_ROUTING = 10
    FILTER_ID = 11
    FRAMED_MTU = 12
    FRAMED_COMPRESSION = 13
    LOGIN_IP_HOST = 14
    LOGIN_SERVICE = 15
    LOGIN_TCP_PORT = 16
    REPLY_MESSAGE = 18
    CALLBACK_NUMBER = 19
    CALLBACK_ID = 20
    FRAMED_ROUTE = 22
    FRAMED_IPX_NETWORK = 23
    STATE = 24
    CLASS = 25
    VENDOR_SPECIFIC = 26
    SESSION_TIMEOUT = 27
    IDLE_TIMEOUT = 28
    TERMINATION_ACTION = 29
    CALLED_STATION_ID = 30
    CALLING_STATION_ID = 31
    NAS_IDENTIFIER = 32
    PROXY_STATE = 33
    LOGIN_LAT_SERVICE = 34
    LOGIN_LAT_NODE = 35
    LOGIN_LAT_GROUP = 36
    FRAMED_APPLETALK_LINK = 37
    FRAMED_APPLETALK_NETWORK = 38
    FRAMED_APPLETALK_ZONE = 39
    ACCT_STATUS_TYPE = 40
    ACCT_DELAY_TIME = 41
    ACCT_INPUT_OCTETS = 42
    ACCT_OUTPUT_OCTETS = 43
    ACCT_SESSION_ID = 44
    ACCT_AUTHENTIC = 45
    ACCT_SESSION_TIME = 46
    ACCT_INPUT_PACKETS = 47
    ACCT_OUTPUT_PACKETS = 48
    ACCT_TERMINATE_CAUSE = 49
    ACCT_MULTI_SESSION_ID = 50
    ACCT_LINK_COUNT = 51
    CHAP_CHALLENGE = 60
    NAS_PORT_TYPE = 61
    PORT_LIMIT = 62
    LOGIN_LAT_PORT = 63
    TUNNEL_TYPE = 64
    TUNNEL_MEDIUM_TYPE = 65
    TUNNEL_CLIENT_ENDPOINT = 66
    TUNNEL_SERVER_ENDPOINT = 67
    ACCT_TUNNEL_CONNECTION = 68
    TUNNEL_PASSWORD = 69
    ARAP_PASSWORD = 70
    ARAP_FEATURES = 71
    ARAP_ZONE_ACCESS = 72
    ARAP_SECURITY = 73
    ARAP_SECURITY_DATA = 74
    PASSWORD_RETRY = 75
    PROMPT = 76
    CONNECT_INFO = 77
    CONFIGURATION_TOKEN = 78
    EAP_MESSAGE = 79
    MESSAGE_AUTHENTICATOR = 80
    TUNNEL_PRIVATE_GROUP_ID = 81
    TUNNEL_ASSIGNMENT_ID = 82
    TUNNEL_PREFERENCE = 83
    ARAP_CHALLENGE_RESPONSE = 84
    ACCT_INTERIM_INTERVAL = 85
    ACCT_TUNNEL_PACKETS_LOST = 86
    NAS_PORT_ID = 87
    FRAMED_POOL = 88
    TUNNEL_CLIENT_AUTH_ID = 90
    TUNNEL_SERVER_AUTH_ID = 91
    NAS_FILTER_RULE = 92
    ORIGINATING_LINE_INFO = 94
    NAS_IPV6_ADDRESS = 95
    FRAMED_INTERFACE_ID = 96
    FRAMED_IPV6_PREFIX = 97
    LOGIN_IPV6_HOST = 98
    FRAMED_IPV6_ROUTE = 99
    FRAMED_IPV6_POOL = 100
    ERROR_CAUSE = 101


# Vendor-Specific Attributes
VENDOR_MICROSOFT = 311
VENDOR_CISCO = 9


class TunnelType(IntEnum):
    """Tunnel types for VLAN assignment"""
    PPTP = 1
    L2F = 2
    L2TP = 3
    ATMP = 4
    VTP = 5
    AH = 6
    IP_IP = 7
    MIN_IP_IP = 8
    ESP = 9
    GRE = 10
    DVS = 11
    IP_IN_IP = 12
    VLAN = 13


class TunnelMedium(IntEnum):
    """Tunnel medium types"""
    IPV4 = 1
    IPV6 = 2
    NSAP = 3
    HDLC = 4
    BBN_1822 = 5
    IEEE_802 = 6
    E_163 = 7
    E_164 = 8
    F_69 = 9
    X_121 = 10
    IPX = 11
    APPLETALK = 12
    DECNET_IV = 13
    BANYAN_VINES = 14
    E_164_NSAP = 15


class NASPortType(IntEnum):
    """NAS Port types"""
    ASYNC = 0
    SYNC = 1
    ISDN_SYNC = 2
    ISDN_ASYNC_V120 = 3
    ISDN_ASYNC_V110 = 4
    VIRTUAL = 5
    PIAFS = 6
    HDLC_CLEAR = 7
    X_25 = 8
    X_75 = 9
    G_3_FAX = 10
    SDSL = 11
    ADSL_CAP = 12
    ADSL_DMT = 13
    IDSL = 14
    ETHERNET = 15
    XDSL = 16
    CABLE = 17
    WIRELESS_OTHER = 18
    WIRELESS_802_11 = 19


class ServiceType(IntEnum):
    """Service types"""
    LOGIN = 1
    FRAMED = 2
    CALLBACK_LOGIN = 3
    CALLBACK_FRAMED = 4
    OUTBOUND = 5
    ADMINISTRATIVE = 6
    NAS_PROMPT = 7
    AUTHENTICATE_ONLY = 8
    CALLBACK_NAS_PROMPT = 9
    CALL_CHECK = 10
    CALLBACK_ADMINISTRATIVE = 11


@dataclass
class RADIUSPacket:
    """RADIUS packet structure"""
    code: RADIUSCode
    identifier: int
    authenticator: bytes
    attributes: Dict[int, List[bytes]] = field(default_factory=dict)

    def add_attribute(self, attr_type: int, value: bytes):
        """Add an attribute to the packet"""
        if attr_type not in self.attributes:
            self.attributes[attr_type] = []
        self.attributes[attr_type].append(value)

    def get_attribute(self, attr_type: int) -> Optional[bytes]:
        """Get first attribute value of given type"""
        attrs = self.attributes.get(attr_type, [])
        return attrs[0] if attrs else None

    def get_all_attributes(self, attr_type: int) -> List[bytes]:
        """Get all attribute values of given type"""
        return self.attributes.get(attr_type, [])

    def encode(self, secret: bytes) -> bytes:
        """Encode packet to bytes"""
        # Build attributes
        attr_data = b''
        for attr_type, values in self.attributes.items():
            for value in values:
                if len(value) <= 253:
                    attr_data += struct.pack('!BB', attr_type, len(value) + 2) + value

        # Calculate length
        length = RADIUS_HEADER_SIZE + len(attr_data)

        # Build packet
        packet = struct.pack('!BBH', self.code, self.identifier, length)
        packet += self.authenticator
        packet += attr_data

        return packet

    @classmethod
    def decode(cls, data: bytes) -> 'RADIUSPacket':
        """Decode packet from bytes"""
        if len(data) < RADIUS_HEADER_SIZE:
            raise ValueError("Packet too short")

        code, identifier, length = struct.unpack('!BBH', data[:4])
        authenticator = data[4:20]

        # Parse attributes
        attributes = {}
        offset = RADIUS_HEADER_SIZE

        while offset < length:
            if offset + 2 > len(data):
                break

            attr_type, attr_len = struct.unpack('!BB', data[offset:offset+2])
            if attr_len < 2:
                break

            value = data[offset+2:offset+attr_len]

            if attr_type not in attributes:
                attributes[attr_type] = []
            attributes[attr_type].append(value)

            offset += attr_len

        return cls(
            code=RADIUSCode(code),
            identifier=identifier,
            authenticator=authenticator,
            attributes=attributes
        )


@dataclass
class MACAuthEntry:
    """MAC authentication database entry"""
    mac: str
    vlan_id: int
    device_type: str = "unknown"
    description: str = ""
    auth_time: float = 0
    expiry_time: float = 0
    session_id: str = ""
    status: str = "pending"
    qsecbit_score: float = 100.0
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RADIUSClientConfig:
    """RADIUS client configuration"""
    server: str
    secret: bytes
    auth_port: int = RADIUS_AUTH_PORT
    acct_port: int = RADIUS_ACCT_PORT
    timeout: float = 5.0
    retries: int = 3
    nas_identifier: str = "guardian"
    nas_ip_address: Optional[str] = None


class RADIUSClient:
    """
    RADIUS client for Guardian

    Supports MAC Authentication Bypass (MAB) and dynamic VLAN assignment.
    """

    def __init__(self, config: RADIUSClientConfig):
        self.config = config
        self._socket = None
        self._identifier = 0
        self._identifier_lock = threading.Lock()
        self._pending_requests: Dict[int, asyncio.Future] = {}

    def _get_identifier(self) -> int:
        """Get next packet identifier"""
        with self._identifier_lock:
            self._identifier = (self._identifier + 1) % 256
            return self._identifier

    def _create_authenticator(self) -> bytes:
        """Create random authenticator"""
        return os.urandom(16)

    def _encrypt_password(self, password: str, authenticator: bytes) -> bytes:
        """Encrypt password using RADIUS method"""
        secret = self.config.secret
        password_bytes = password.encode('utf-8')

        # Pad to 16-byte boundary
        if len(password_bytes) % 16:
            password_bytes += b'\x00' * (16 - (len(password_bytes) % 16))

        # Encrypt
        result = b''
        prev_block = authenticator

        for i in range(0, len(password_bytes), 16):
            block = password_bytes[i:i+16]
            digest = hashlib.md5(secret + prev_block).digest()
            encrypted = bytes(a ^ b for a, b in zip(block, digest))
            result += encrypted
            prev_block = encrypted

        return result

    def _calculate_response_authenticator(
        self,
        code: RADIUSCode,
        identifier: int,
        request_auth: bytes,
        attributes: bytes
    ) -> bytes:
        """Calculate response authenticator"""
        length = RADIUS_HEADER_SIZE + len(attributes)
        data = struct.pack('!BBH', code, identifier, length)
        data += request_auth
        data += attributes
        data += self.config.secret

        return hashlib.md5(data).digest()

    def _calculate_message_authenticator(
        self,
        packet: bytes
    ) -> bytes:
        """Calculate Message-Authenticator attribute"""
        return hmac.new(self.config.secret, packet, hashlib.md5).digest()

    async def _send_request(self, packet: RADIUSPacket, port: int) -> Optional[RADIUSPacket]:
        """Send RADIUS request and wait for response"""
        loop = asyncio.get_event_loop()

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.settimeout(self.config.timeout)

        try:
            # Encode packet
            data = packet.encode(self.config.secret)

            # Send request
            await loop.sock_sendto(sock, data, (self.config.server, port))

            # Wait for response with retries
            for attempt in range(self.config.retries):
                try:
                    response_data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, RADIUS_MAX_PACKET_SIZE),
                        timeout=self.config.timeout
                    )

                    response = RADIUSPacket.decode(response_data)

                    # Verify identifier matches
                    if response.identifier == packet.identifier:
                        return response

                except asyncio.TimeoutError:
                    if attempt < self.config.retries - 1:
                        logger.warning(f"RADIUS timeout, attempt {attempt + 1}/{self.config.retries}")
                        await loop.sock_sendto(sock, data, (self.config.server, port))
                    continue

        except Exception as e:
            logger.error(f"RADIUS request failed: {e}")
        finally:
            sock.close()

        return None

    async def authenticate_mac(
        self,
        mac: str,
        nas_port: int = 0,
        nas_port_id: str = "",
        called_station_id: str = ""
    ) -> Tuple[bool, Optional[int], Dict[str, Any]]:
        """
        Authenticate device by MAC address (MAB)

        Returns:
            Tuple of (success, vlan_id, attributes)
        """
        mac = mac.lower().replace(':', '-')
        mac_no_sep = mac.replace('-', '')

        # Create Access-Request
        authenticator = self._create_authenticator()
        packet = RADIUSPacket(
            code=RADIUSCode.ACCESS_REQUEST,
            identifier=self._get_identifier(),
            authenticator=authenticator
        )

        # Add attributes
        # User-Name = MAC address
        packet.add_attribute(RADIUSAttribute.USER_NAME, mac.encode())

        # User-Password = MAC address (for MAB)
        encrypted_pass = self._encrypt_password(mac_no_sep, authenticator)
        packet.add_attribute(RADIUSAttribute.USER_PASSWORD, encrypted_pass)

        # Calling-Station-Id = MAC address
        calling_mac = mac.upper().replace('-', ':')
        packet.add_attribute(RADIUSAttribute.CALLING_STATION_ID, calling_mac.encode())

        # Called-Station-Id
        if called_station_id:
            packet.add_attribute(RADIUSAttribute.CALLED_STATION_ID, called_station_id.encode())

        # NAS attributes
        packet.add_attribute(RADIUSAttribute.NAS_IDENTIFIER, self.config.nas_identifier.encode())

        if self.config.nas_ip_address:
            ip_bytes = socket.inet_aton(self.config.nas_ip_address)
            packet.add_attribute(RADIUSAttribute.NAS_IP_ADDRESS, ip_bytes)

        packet.add_attribute(RADIUSAttribute.NAS_PORT, struct.pack('!I', nas_port))
        packet.add_attribute(RADIUSAttribute.NAS_PORT_TYPE, struct.pack('!I', NASPortType.ETHERNET))

        if nas_port_id:
            packet.add_attribute(RADIUSAttribute.NAS_PORT_ID, nas_port_id.encode())

        # Service-Type = Call-Check (for MAB)
        packet.add_attribute(RADIUSAttribute.SERVICE_TYPE, struct.pack('!I', ServiceType.CALL_CHECK))

        # Send request
        response = await self._send_request(packet, self.config.auth_port)

        if response is None:
            logger.error(f"No RADIUS response for MAC {mac}")
            return False, None, {}

        result_attrs = {}

        if response.code == RADIUSCode.ACCESS_ACCEPT:
            logger.info(f"MAC {mac} authenticated successfully")

            # Extract VLAN from Tunnel-Private-Group-ID
            vlan_id = None
            tunnel_pvt_grp = response.get_attribute(RADIUSAttribute.TUNNEL_PRIVATE_GROUP_ID)
            if tunnel_pvt_grp:
                # First byte is tag, rest is VLAN ID string
                vlan_str = tunnel_pvt_grp[1:].decode() if len(tunnel_pvt_grp) > 1 else tunnel_pvt_grp.decode()
                try:
                    vlan_id = int(vlan_str)
                except ValueError:
                    pass

            # Also check for Tunnel-Type and Tunnel-Medium-Type
            tunnel_type = response.get_attribute(RADIUSAttribute.TUNNEL_TYPE)
            tunnel_medium = response.get_attribute(RADIUSAttribute.TUNNEL_MEDIUM_TYPE)

            if tunnel_type:
                result_attrs['tunnel_type'] = struct.unpack('!I', tunnel_type.ljust(4, b'\x00')[:4])[0]
            if tunnel_medium:
                result_attrs['tunnel_medium'] = struct.unpack('!I', tunnel_medium.ljust(4, b'\x00')[:4])[0]

            # Extract other useful attributes
            filter_id = response.get_attribute(RADIUSAttribute.FILTER_ID)
            if filter_id:
                result_attrs['filter_id'] = filter_id.decode()

            session_timeout = response.get_attribute(RADIUSAttribute.SESSION_TIMEOUT)
            if session_timeout:
                result_attrs['session_timeout'] = struct.unpack('!I', session_timeout)[0]

            reply_message = response.get_attribute(RADIUSAttribute.REPLY_MESSAGE)
            if reply_message:
                result_attrs['reply_message'] = reply_message.decode()

            return True, vlan_id, result_attrs

        elif response.code == RADIUSCode.ACCESS_REJECT:
            logger.warning(f"MAC {mac} authentication rejected")

            reply_message = response.get_attribute(RADIUSAttribute.REPLY_MESSAGE)
            if reply_message:
                result_attrs['reply_message'] = reply_message.decode()

            return False, None, result_attrs

        elif response.code == RADIUSCode.ACCESS_CHALLENGE:
            logger.info(f"MAC {mac} received challenge (EAP may be required)")
            return False, None, {'challenge': True}

        return False, None, {}

    async def send_accounting_start(
        self,
        mac: str,
        session_id: str,
        nas_port: int = 0
    ) -> bool:
        """Send accounting start packet"""
        mac = mac.lower().replace(':', '-')

        authenticator = self._create_authenticator()
        packet = RADIUSPacket(
            code=RADIUSCode.ACCOUNTING_REQUEST,
            identifier=self._get_identifier(),
            authenticator=authenticator
        )

        # Acct-Status-Type = Start (1)
        packet.add_attribute(RADIUSAttribute.ACCT_STATUS_TYPE, struct.pack('!I', 1))

        # Acct-Session-Id
        packet.add_attribute(RADIUSAttribute.ACCT_SESSION_ID, session_id.encode())

        # User-Name
        packet.add_attribute(RADIUSAttribute.USER_NAME, mac.encode())

        # Calling-Station-Id
        calling_mac = mac.upper().replace('-', ':')
        packet.add_attribute(RADIUSAttribute.CALLING_STATION_ID, calling_mac.encode())

        # NAS attributes
        packet.add_attribute(RADIUSAttribute.NAS_IDENTIFIER, self.config.nas_identifier.encode())
        packet.add_attribute(RADIUSAttribute.NAS_PORT, struct.pack('!I', nas_port))
        packet.add_attribute(RADIUSAttribute.NAS_PORT_TYPE, struct.pack('!I', NASPortType.ETHERNET))

        response = await self._send_request(packet, self.config.acct_port)
        return response is not None and response.code == RADIUSCode.ACCOUNTING_RESPONSE

    async def send_accounting_stop(
        self,
        mac: str,
        session_id: str,
        session_time: int,
        input_octets: int,
        output_octets: int,
        terminate_cause: int = 1
    ) -> bool:
        """Send accounting stop packet"""
        mac = mac.lower().replace(':', '-')

        authenticator = self._create_authenticator()
        packet = RADIUSPacket(
            code=RADIUSCode.ACCOUNTING_REQUEST,
            identifier=self._get_identifier(),
            authenticator=authenticator
        )

        # Acct-Status-Type = Stop (2)
        packet.add_attribute(RADIUSAttribute.ACCT_STATUS_TYPE, struct.pack('!I', 2))

        # Session attributes
        packet.add_attribute(RADIUSAttribute.ACCT_SESSION_ID, session_id.encode())
        packet.add_attribute(RADIUSAttribute.ACCT_SESSION_TIME, struct.pack('!I', session_time))
        packet.add_attribute(RADIUSAttribute.ACCT_INPUT_OCTETS, struct.pack('!I', input_octets))
        packet.add_attribute(RADIUSAttribute.ACCT_OUTPUT_OCTETS, struct.pack('!I', output_octets))
        packet.add_attribute(RADIUSAttribute.ACCT_TERMINATE_CAUSE, struct.pack('!I', terminate_cause))

        # User-Name
        packet.add_attribute(RADIUSAttribute.USER_NAME, mac.encode())

        # NAS attributes
        packet.add_attribute(RADIUSAttribute.NAS_IDENTIFIER, self.config.nas_identifier.encode())

        response = await self._send_request(packet, self.config.acct_port)
        return response is not None and response.code == RADIUSCode.ACCOUNTING_RESPONSE


class RADIUSServer:
    """
    Local RADIUS server for Guardian

    Provides MAC authentication and VLAN assignment from local database.
    Can be used when external RADIUS is not available.
    """

    def __init__(
        self,
        bind_addr: str = '0.0.0.0',
        auth_port: int = RADIUS_AUTH_PORT,
        acct_port: int = RADIUS_ACCT_PORT,
        secret: bytes = b'guardian_secret'
    ):
        self.bind_addr = bind_addr
        self.auth_port = auth_port
        self.acct_port = acct_port
        self.secret = secret

        # MAC database
        self.mac_database: Dict[str, MACAuthEntry] = {}

        # Default VLAN assignments
        self.default_vlan = 200  # Guest VLAN
        self.vlan_rules: List[Tuple[str, int]] = []  # (MAC pattern, VLAN)

        # Statistics
        self.stats = {
            'auth_requests': 0,
            'auth_accepts': 0,
            'auth_rejects': 0,
            'acct_requests': 0,
            'acct_responses': 0
        }

        # Callbacks
        self.auth_handlers: List[Callable] = []
        self.acct_handlers: List[Callable] = []

        self._auth_socket = None
        self._acct_socket = None
        self._running = False

        logger.info(f"RADIUS Server initialized on {bind_addr}:{auth_port}")

    def add_mac(
        self,
        mac: str,
        vlan_id: int,
        device_type: str = "unknown",
        description: str = ""
    ):
        """Add MAC to authentication database"""
        mac = mac.lower().replace('-', ':')
        self.mac_database[mac] = MACAuthEntry(
            mac=mac,
            vlan_id=vlan_id,
            device_type=device_type,
            description=description,
            status="registered"
        )
        logger.info(f"Added MAC {mac} to RADIUS database, VLAN={vlan_id}")

    def remove_mac(self, mac: str):
        """Remove MAC from database"""
        mac = mac.lower().replace('-', ':')
        if mac in self.mac_database:
            del self.mac_database[mac]
            logger.info(f"Removed MAC {mac} from RADIUS database")

    def add_vlan_rule(self, mac_prefix: str, vlan_id: int):
        """Add VLAN assignment rule by MAC prefix"""
        self.vlan_rules.append((mac_prefix.lower(), vlan_id))
        logger.info(f"Added VLAN rule: {mac_prefix}* -> VLAN {vlan_id}")

    def get_vlan_for_mac(self, mac: str) -> int:
        """Get VLAN assignment for MAC address"""
        mac = mac.lower().replace('-', ':')

        # Check exact match
        entry = self.mac_database.get(mac)
        if entry:
            return entry.vlan_id

        # Check prefix rules
        mac_clean = mac.replace(':', '')
        for prefix, vlan_id in self.vlan_rules:
            prefix_clean = prefix.replace(':', '')
            if mac_clean.startswith(prefix_clean):
                return vlan_id

        return self.default_vlan

    async def start(self):
        """Start RADIUS server"""
        self._running = True

        # Create UDP sockets
        loop = asyncio.get_event_loop()

        # Auth socket
        self._auth_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._auth_socket.setblocking(False)
        self._auth_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._auth_socket.bind((self.bind_addr, self.auth_port))

        # Accounting socket
        self._acct_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._acct_socket.setblocking(False)
        self._acct_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._acct_socket.bind((self.bind_addr, self.acct_port))

        logger.info(f"RADIUS server listening on auth:{self.auth_port}, acct:{self.acct_port}")

        # Start handlers
        await asyncio.gather(
            self._handle_auth(),
            self._handle_acct()
        )

    async def stop(self):
        """Stop RADIUS server"""
        self._running = False

        if self._auth_socket:
            self._auth_socket.close()
        if self._acct_socket:
            self._acct_socket.close()

        logger.info("RADIUS server stopped")

    async def _handle_auth(self):
        """Handle authentication requests"""
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self._auth_socket, RADIUS_MAX_PACKET_SIZE)
                await self._process_auth_request(data, addr)
            except Exception as e:
                if self._running:
                    logger.error(f"Auth handler error: {e}")

    async def _handle_acct(self):
        """Handle accounting requests"""
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self._acct_socket, RADIUS_MAX_PACKET_SIZE)
                await self._process_acct_request(data, addr)
            except Exception as e:
                if self._running:
                    logger.error(f"Acct handler error: {e}")

    async def _process_auth_request(self, data: bytes, addr: Tuple[str, int]):
        """Process authentication request"""
        try:
            packet = RADIUSPacket.decode(data)
        except Exception as e:
            logger.error(f"Failed to decode RADIUS packet: {e}")
            return

        if packet.code != RADIUSCode.ACCESS_REQUEST:
            return

        self.stats['auth_requests'] += 1

        # Get username (MAC)
        username_attr = packet.get_attribute(RADIUSAttribute.USER_NAME)
        if not username_attr:
            await self._send_reject(packet, addr, "No username")
            return

        username = username_attr.decode().lower().replace('-', ':')

        # Get calling station ID
        calling_station = packet.get_attribute(RADIUSAttribute.CALLING_STATION_ID)
        if calling_station:
            calling_mac = calling_station.decode().lower().replace('-', ':')
        else:
            calling_mac = username

        logger.debug(f"Auth request for MAC: {calling_mac} from {addr}")

        # Authenticate and get VLAN
        vlan_id = self.get_vlan_for_mac(calling_mac)

        # Check if in database
        entry = self.mac_database.get(calling_mac)

        if entry and entry.status == "blocked":
            await self._send_reject(packet, addr, "MAC blocked")
            return

        # Accept and assign VLAN
        await self._send_accept(packet, addr, vlan_id, calling_mac)

        # Update database
        if entry:
            entry.auth_time = time.time()
            entry.status = "authenticated"
            entry.session_id = hashlib.md5(
                f"{calling_mac}{time.time()}".encode()
            ).hexdigest()[:16]

        # Notify handlers
        for handler in self.auth_handlers:
            try:
                await handler(calling_mac, vlan_id, True)
            except Exception as e:
                logger.error(f"Auth handler callback error: {e}")

    async def _send_accept(
        self,
        request: RADIUSPacket,
        addr: Tuple[str, int],
        vlan_id: int,
        mac: str
    ):
        """Send Access-Accept response"""
        response = RADIUSPacket(
            code=RADIUSCode.ACCESS_ACCEPT,
            identifier=request.identifier,
            authenticator=b'\x00' * 16  # Will be calculated
        )

        # Add VLAN assignment attributes
        # Tunnel-Type = VLAN (13)
        response.add_attribute(RADIUSAttribute.TUNNEL_TYPE, struct.pack('!I', TunnelType.VLAN))

        # Tunnel-Medium-Type = IEEE-802 (6)
        response.add_attribute(RADIUSAttribute.TUNNEL_MEDIUM_TYPE, struct.pack('!I', TunnelMedium.IEEE_802))

        # Tunnel-Private-Group-ID = VLAN ID
        vlan_str = str(vlan_id).encode()
        response.add_attribute(RADIUSAttribute.TUNNEL_PRIVATE_GROUP_ID, b'\x00' + vlan_str)

        # Build response
        attr_data = b''
        for attr_type, values in response.attributes.items():
            for value in values:
                attr_data += struct.pack('!BB', attr_type, len(value) + 2) + value

        # Calculate authenticator
        length = RADIUS_HEADER_SIZE + len(attr_data)
        auth_data = struct.pack('!BBH', RADIUSCode.ACCESS_ACCEPT, request.identifier, length)
        auth_data += request.authenticator
        auth_data += attr_data
        auth_data += self.secret

        response.authenticator = hashlib.md5(auth_data).digest()

        # Encode and send
        response_data = response.encode(self.secret)
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(self._auth_socket, response_data, addr)

        self.stats['auth_accepts'] += 1
        logger.info(f"Access-Accept sent for {mac}, VLAN={vlan_id}")

    async def _send_reject(
        self,
        request: RADIUSPacket,
        addr: Tuple[str, int],
        reason: str
    ):
        """Send Access-Reject response"""
        response = RADIUSPacket(
            code=RADIUSCode.ACCESS_REJECT,
            identifier=request.identifier,
            authenticator=b'\x00' * 16
        )

        # Add reply message
        response.add_attribute(RADIUSAttribute.REPLY_MESSAGE, reason.encode())

        # Build and send
        attr_data = b''
        for attr_type, values in response.attributes.items():
            for value in values:
                attr_data += struct.pack('!BB', attr_type, len(value) + 2) + value

        length = RADIUS_HEADER_SIZE + len(attr_data)
        auth_data = struct.pack('!BBH', RADIUSCode.ACCESS_REJECT, request.identifier, length)
        auth_data += request.authenticator
        auth_data += attr_data
        auth_data += self.secret

        response.authenticator = hashlib.md5(auth_data).digest()

        response_data = response.encode(self.secret)
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(self._auth_socket, response_data, addr)

        self.stats['auth_rejects'] += 1
        logger.info(f"Access-Reject sent: {reason}")

    async def _process_acct_request(self, data: bytes, addr: Tuple[str, int]):
        """Process accounting request"""
        try:
            packet = RADIUSPacket.decode(data)
        except Exception as e:
            logger.error(f"Failed to decode accounting packet: {e}")
            return

        if packet.code != RADIUSCode.ACCOUNTING_REQUEST:
            return

        self.stats['acct_requests'] += 1

        # Get status type
        status_type = packet.get_attribute(RADIUSAttribute.ACCT_STATUS_TYPE)
        if status_type:
            status = struct.unpack('!I', status_type)[0]
            status_names = {1: 'Start', 2: 'Stop', 3: 'Interim-Update'}
            logger.debug(f"Accounting {status_names.get(status, status)} from {addr}")

        # Send response
        response = RADIUSPacket(
            code=RADIUSCode.ACCOUNTING_RESPONSE,
            identifier=packet.identifier,
            authenticator=b'\x00' * 16
        )

        # Calculate authenticator
        length = RADIUS_HEADER_SIZE
        auth_data = struct.pack('!BBH', RADIUSCode.ACCOUNTING_RESPONSE, packet.identifier, length)
        auth_data += packet.authenticator
        auth_data += self.secret

        response.authenticator = hashlib.md5(auth_data).digest()

        response_data = response.encode(self.secret)
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(self._acct_socket, response_data, addr)

        self.stats['acct_responses'] += 1

        # Notify handlers
        for handler in self.acct_handlers:
            try:
                await handler(packet)
            except Exception as e:
                logger.error(f"Acct handler callback error: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get server statistics"""
        return {
            'server': {
                'bind_addr': self.bind_addr,
                'auth_port': self.auth_port,
                'acct_port': self.acct_port,
                'running': self._running
            },
            'stats': self.stats.copy(),
            'mac_database_size': len(self.mac_database),
            'vlan_rules_count': len(self.vlan_rules),
            'default_vlan': self.default_vlan
        }


class MACAuthService:
    """
    Unified MAC Authentication Service

    Combines local RADIUS server functionality with external RADIUS client
    for comprehensive MAC-based authentication and VLAN assignment.
    """

    def __init__(
        self,
        external_radius: Optional[RADIUSClientConfig] = None,
        local_port: int = RADIUS_AUTH_PORT,
        local_secret: bytes = b'guardian_secret'
    ):
        # External RADIUS client
        self.external_client = RADIUSClient(external_radius) if external_radius else None

        # Local RADIUS server
        self.local_server = RADIUSServer(
            auth_port=local_port,
            secret=local_secret
        )

        # MAC tracking
        self.authenticated_macs: Dict[str, MACAuthEntry] = {}

        # VLAN assignment callbacks
        self.vlan_assignment_handlers: List[Callable] = []

        logger.info("MAC Authentication Service initialized")

    async def authenticate(
        self,
        mac: str,
        nas_port: int = 0,
        prefer_external: bool = True
    ) -> Tuple[bool, Optional[int], Dict[str, Any]]:
        """
        Authenticate MAC address

        Tries external RADIUS first if available, falls back to local.
        """
        mac = mac.lower().replace('-', ':')

        # Check if already authenticated
        if mac in self.authenticated_macs:
            entry = self.authenticated_macs[mac]
            if entry.status == "authenticated" and time.time() < entry.expiry_time:
                return True, entry.vlan_id, {'cached': True}

        # Try external RADIUS
        if prefer_external and self.external_client:
            try:
                success, vlan_id, attrs = await self.external_client.authenticate_mac(
                    mac,
                    nas_port=nas_port
                )

                if success:
                    await self._record_authentication(mac, vlan_id, attrs, "external")
                    return success, vlan_id, attrs

            except Exception as e:
                logger.warning(f"External RADIUS failed: {e}")

        # Fall back to local
        vlan_id = self.local_server.get_vlan_for_mac(mac)
        await self._record_authentication(mac, vlan_id, {}, "local")

        return True, vlan_id, {'source': 'local'}

    async def _record_authentication(
        self,
        mac: str,
        vlan_id: Optional[int],
        attrs: Dict[str, Any],
        source: str
    ):
        """Record authentication result"""
        session_timeout = attrs.get('session_timeout', 86400)  # Default 24h

        entry = MACAuthEntry(
            mac=mac,
            vlan_id=vlan_id or self.local_server.default_vlan,
            auth_time=time.time(),
            expiry_time=time.time() + session_timeout,
            session_id=hashlib.md5(f"{mac}{time.time()}".encode()).hexdigest()[:16],
            status="authenticated",
            attributes={'source': source, **attrs}
        )

        self.authenticated_macs[mac] = entry

        # Notify handlers
        for handler in self.vlan_assignment_handlers:
            try:
                await handler(mac, entry.vlan_id)
            except Exception as e:
                logger.error(f"VLAN assignment handler error: {e}")

    def add_mac_vlan_mapping(self, mac: str, vlan_id: int, device_type: str = ""):
        """Add static MAC to VLAN mapping"""
        self.local_server.add_mac(mac, vlan_id, device_type)

    def add_vendor_vlan_rule(self, oui_prefix: str, vlan_id: int):
        """Add vendor OUI to VLAN mapping"""
        self.local_server.add_vlan_rule(oui_prefix, vlan_id)

    def set_default_vlan(self, vlan_id: int):
        """Set default VLAN for unknown devices"""
        self.local_server.default_vlan = vlan_id

    def register_vlan_handler(self, handler: Callable):
        """Register VLAN assignment callback"""
        self.vlan_assignment_handlers.append(handler)

    def get_authenticated_macs(self) -> Dict[str, MACAuthEntry]:
        """Get all authenticated MACs"""
        return dict(self.authenticated_macs)

    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        return {
            'authenticated_macs': len(self.authenticated_macs),
            'local_server': self.local_server.get_statistics(),
            'external_radius': self.external_client is not None
        }


# Export classes
__all__ = [
    'RADIUSClient',
    'RADIUSServer',
    'RADIUSClientConfig',
    'RADIUSPacket',
    'MACAuthService',
    'MACAuthEntry',
    'RADIUSCode',
    'RADIUSAttribute',
    'TunnelType',
    'TunnelMedium',
    'NASPortType',
    'ServiceType'
]
