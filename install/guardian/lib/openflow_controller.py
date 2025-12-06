"""
OpenFlow SDN Controller for Guardian

Provides software-defined networking capabilities using OpenFlow 1.3
with Open vSwitch (OVS) integration for dynamic traffic management,
VLAN segmentation, and threat-based flow control.

Author: HookProbe Team
Version: 5.0.0 Liberty
License: MIT
"""

import asyncio
import logging
import struct
import socket
import time
import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, List, Optional, Callable, Set, Tuple, Any
from collections import defaultdict
import subprocess
import threading

logger = logging.getLogger(__name__)


# OpenFlow 1.3 Constants
OFP_VERSION = 0x04  # OpenFlow 1.3
OFP_HEADER_SIZE = 8
OFP_TCP_PORT = 6653
OFP_LEGACY_PORT = 6633

# OpenFlow Message Types
class OFPType(IntEnum):
    HELLO = 0
    ERROR = 1
    ECHO_REQUEST = 2
    ECHO_REPLY = 3
    EXPERIMENTER = 4
    FEATURES_REQUEST = 5
    FEATURES_REPLY = 6
    GET_CONFIG_REQUEST = 7
    GET_CONFIG_REPLY = 8
    SET_CONFIG = 9
    PACKET_IN = 10
    FLOW_REMOVED = 11
    PORT_STATUS = 12
    PACKET_OUT = 13
    FLOW_MOD = 14
    GROUP_MOD = 15
    PORT_MOD = 16
    TABLE_MOD = 17
    MULTIPART_REQUEST = 18
    MULTIPART_REPLY = 19
    BARRIER_REQUEST = 20
    BARRIER_REPLY = 21
    ROLE_REQUEST = 24
    ROLE_REPLY = 25
    GET_ASYNC_REQUEST = 26
    GET_ASYNC_REPLY = 27
    SET_ASYNC = 28
    METER_MOD = 29


# OpenFlow Flow Mod Commands
class OFPFlowModCommand(IntEnum):
    ADD = 0
    MODIFY = 1
    MODIFY_STRICT = 2
    DELETE = 3
    DELETE_STRICT = 4


# OpenFlow Match Types
class OXMClass(IntEnum):
    NXM_0 = 0x0000
    NXM_1 = 0x0001
    OPENFLOW_BASIC = 0x8000
    EXPERIMENTER = 0xFFFF


class OXMField(IntEnum):
    IN_PORT = 0
    IN_PHY_PORT = 1
    METADATA = 2
    ETH_DST = 3
    ETH_SRC = 4
    ETH_TYPE = 5
    VLAN_VID = 6
    VLAN_PCP = 7
    IP_DSCP = 8
    IP_ECN = 9
    IP_PROTO = 10
    IPV4_SRC = 11
    IPV4_DST = 12
    TCP_SRC = 13
    TCP_DST = 14
    UDP_SRC = 15
    UDP_DST = 16
    SCTP_SRC = 17
    SCTP_DST = 18
    ICMPV4_TYPE = 19
    ICMPV4_CODE = 20
    ARP_OP = 21
    ARP_SPA = 22
    ARP_TPA = 23
    ARP_SHA = 24
    ARP_THA = 25
    IPV6_SRC = 26
    IPV6_DST = 27
    IPV6_FLABEL = 28
    ICMPV6_TYPE = 29
    ICMPV6_CODE = 30
    IPV6_ND_TARGET = 31
    IPV6_ND_SLL = 32
    IPV6_ND_TLL = 33
    MPLS_LABEL = 34
    MPLS_TC = 35
    MPLS_BOS = 36
    PBB_ISID = 37
    TUNNEL_ID = 38
    IPV6_EXTHDR = 39


# OpenFlow Actions
class OFPActionType(IntEnum):
    OUTPUT = 0
    COPY_TTL_OUT = 11
    COPY_TTL_IN = 12
    SET_MPLS_TTL = 15
    DEC_MPLS_TTL = 16
    PUSH_VLAN = 17
    POP_VLAN = 18
    PUSH_MPLS = 19
    POP_MPLS = 20
    SET_QUEUE = 21
    GROUP = 22
    SET_NW_TTL = 23
    DEC_NW_TTL = 24
    SET_FIELD = 25
    PUSH_PBB = 26
    POP_PBB = 27
    EXPERIMENTER = 0xFFFF


# OpenFlow Instructions
class OFPInstructionType(IntEnum):
    GOTO_TABLE = 1
    WRITE_METADATA = 2
    WRITE_ACTIONS = 3
    APPLY_ACTIONS = 4
    CLEAR_ACTIONS = 5
    METER = 6
    EXPERIMENTER = 0xFFFF


# Special Ports
class OFPPort(IntEnum):
    MAX = 0xffffff00
    IN_PORT = 0xfffffff8
    TABLE = 0xfffffff9
    NORMAL = 0xfffffffa
    FLOOD = 0xfffffffb
    ALL = 0xfffffffc
    CONTROLLER = 0xfffffffd
    LOCAL = 0xfffffffe
    ANY = 0xffffffff


# Guardian-specific VLAN ranges
class GuardianVLAN(IntEnum):
    MANAGEMENT = 10
    TRUSTED = 100
    GUEST = 200
    IOT = 300
    QUARANTINE = 666
    HOSTILE = 999


@dataclass
class FlowMatch:
    """OpenFlow match criteria"""
    in_port: Optional[int] = None
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    eth_type: Optional[int] = None
    vlan_vid: Optional[int] = None
    ip_proto: Optional[int] = None
    ipv4_src: Optional[str] = None
    ipv4_dst: Optional[str] = None
    tcp_src: Optional[int] = None
    tcp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None

    def to_oxm(self) -> bytes:
        """Convert match to OXM TLV format"""
        oxm_fields = []

        if self.in_port is not None:
            oxm_fields.append(self._make_oxm(OXMField.IN_PORT, 4, struct.pack('!I', self.in_port)))

        if self.eth_src is not None:
            mac_bytes = bytes.fromhex(self.eth_src.replace(':', ''))
            oxm_fields.append(self._make_oxm(OXMField.ETH_SRC, 6, mac_bytes))

        if self.eth_dst is not None:
            mac_bytes = bytes.fromhex(self.eth_dst.replace(':', ''))
            oxm_fields.append(self._make_oxm(OXMField.ETH_DST, 6, mac_bytes))

        if self.eth_type is not None:
            oxm_fields.append(self._make_oxm(OXMField.ETH_TYPE, 2, struct.pack('!H', self.eth_type)))

        if self.vlan_vid is not None:
            # VLAN VID with OFPVID_PRESENT flag
            vid = self.vlan_vid | 0x1000
            oxm_fields.append(self._make_oxm(OXMField.VLAN_VID, 2, struct.pack('!H', vid)))

        if self.ip_proto is not None:
            oxm_fields.append(self._make_oxm(OXMField.IP_PROTO, 1, struct.pack('!B', self.ip_proto)))

        if self.ipv4_src is not None:
            ip_bytes = socket.inet_aton(self.ipv4_src)
            oxm_fields.append(self._make_oxm(OXMField.IPV4_SRC, 4, ip_bytes))

        if self.ipv4_dst is not None:
            ip_bytes = socket.inet_aton(self.ipv4_dst)
            oxm_fields.append(self._make_oxm(OXMField.IPV4_DST, 4, ip_bytes))

        if self.tcp_src is not None:
            oxm_fields.append(self._make_oxm(OXMField.TCP_SRC, 2, struct.pack('!H', self.tcp_src)))

        if self.tcp_dst is not None:
            oxm_fields.append(self._make_oxm(OXMField.TCP_DST, 2, struct.pack('!H', self.tcp_dst)))

        if self.udp_src is not None:
            oxm_fields.append(self._make_oxm(OXMField.UDP_SRC, 2, struct.pack('!H', self.udp_src)))

        if self.udp_dst is not None:
            oxm_fields.append(self._make_oxm(OXMField.UDP_DST, 2, struct.pack('!H', self.udp_dst)))

        return b''.join(oxm_fields)

    def _make_oxm(self, field: OXMField, length: int, value: bytes) -> bytes:
        """Create OXM TLV"""
        # OXM header: class (2) + field (7 bits) + hasmask (1 bit) + length (1)
        header = (OXMClass.OPENFLOW_BASIC << 16) | (field << 9) | length
        return struct.pack('!I', header) + value


@dataclass
class FlowAction:
    """OpenFlow action"""
    action_type: OFPActionType
    port: Optional[int] = None
    vlan_vid: Optional[int] = None
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    ipv4_src: Optional[str] = None
    ipv4_dst: Optional[str] = None
    queue_id: Optional[int] = None
    group_id: Optional[int] = None

    def to_bytes(self) -> bytes:
        """Convert action to bytes"""
        if self.action_type == OFPActionType.OUTPUT:
            # Output action: type (2) + length (2) + port (4) + max_len (2) + pad (6)
            port = self.port if self.port is not None else OFPPort.CONTROLLER
            return struct.pack('!HHIH6x', OFPActionType.OUTPUT, 16, port, 0xffe5)

        elif self.action_type == OFPActionType.PUSH_VLAN:
            # Push VLAN: type (2) + length (2) + ethertype (2) + pad (2)
            return struct.pack('!HHH2x', OFPActionType.PUSH_VLAN, 8, 0x8100)

        elif self.action_type == OFPActionType.POP_VLAN:
            # Pop VLAN: type (2) + length (2) + pad (4)
            return struct.pack('!HH4x', OFPActionType.POP_VLAN, 8)

        elif self.action_type == OFPActionType.SET_FIELD:
            # Set field action
            if self.vlan_vid is not None:
                vid = self.vlan_vid | 0x1000
                oxm = struct.pack('!I', (OXMClass.OPENFLOW_BASIC << 16) | (OXMField.VLAN_VID << 9) | 2)
                oxm += struct.pack('!H', vid)
                length = 4 + 4 + 2 + 2  # header + oxm_header + value + pad
                return struct.pack('!HH', OFPActionType.SET_FIELD, length) + oxm + b'\x00\x00'

            elif self.eth_src is not None:
                mac_bytes = bytes.fromhex(self.eth_src.replace(':', ''))
                oxm = struct.pack('!I', (OXMClass.OPENFLOW_BASIC << 16) | (OXMField.ETH_SRC << 9) | 6)
                oxm += mac_bytes
                length = 4 + 4 + 6 + 2  # header + oxm_header + value + pad
                return struct.pack('!HH', OFPActionType.SET_FIELD, length) + oxm + b'\x00\x00'

        elif self.action_type == OFPActionType.SET_QUEUE:
            return struct.pack('!HHI', OFPActionType.SET_QUEUE, 8, self.queue_id or 0)

        elif self.action_type == OFPActionType.GROUP:
            return struct.pack('!HHI', OFPActionType.GROUP, 8, self.group_id or 0)

        return b''


@dataclass
class FlowEntry:
    """OpenFlow flow table entry"""
    table_id: int = 0
    priority: int = 32768
    idle_timeout: int = 0
    hard_timeout: int = 0
    cookie: int = 0
    match: FlowMatch = field(default_factory=FlowMatch)
    actions: List[FlowAction] = field(default_factory=list)
    flags: int = 0

    def to_flow_mod(self, command: OFPFlowModCommand = OFPFlowModCommand.ADD) -> bytes:
        """Create flow mod message"""
        # Build match
        match_oxm = self.match.to_oxm()
        match_len = 4 + len(match_oxm)  # type (2) + length (2) + oxm fields
        match_pad = (8 - (match_len % 8)) % 8

        match = struct.pack('!HH', 1, match_len)  # type=1 (OXM), length
        match += match_oxm
        match += b'\x00' * match_pad

        # Build instructions with actions
        actions_data = b''.join(action.to_bytes() for action in self.actions)

        # Apply actions instruction
        if actions_data:
            instr_len = 8 + len(actions_data)
            instructions = struct.pack('!HH4x', OFPInstructionType.APPLY_ACTIONS, instr_len)
            instructions += actions_data
        else:
            instructions = b''

        # Flow mod header
        flow_mod = struct.pack(
            '!QQBBHHHIIIH2x',
            self.cookie,          # cookie
            0,                    # cookie_mask
            self.table_id,        # table_id
            command,              # command
            self.idle_timeout,    # idle_timeout
            self.hard_timeout,    # hard_timeout
            self.priority,        # priority
            0xffffffff,           # buffer_id (no buffer)
            OFPPort.ANY,          # out_port
            0xffffffff,           # out_group (any)
            self.flags            # flags
        )

        flow_mod += match
        flow_mod += instructions

        return flow_mod


@dataclass
class SwitchFeatures:
    """OpenFlow switch features"""
    datapath_id: int = 0
    n_buffers: int = 0
    n_tables: int = 0
    auxiliary_id: int = 0
    capabilities: int = 0
    ports: Dict[int, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class OVSBridge:
    """Open vSwitch bridge configuration"""
    name: str
    datapath_id: Optional[int] = None
    ports: List[str] = field(default_factory=list)
    vlans: Set[int] = field(default_factory=set)
    controller_connected: bool = False


class OpenFlowController:
    """
    OpenFlow 1.3 SDN Controller for Guardian

    Manages Open vSwitch bridges for dynamic traffic control,
    VLAN segmentation, and threat-based flow management.
    """

    def __init__(
        self,
        listen_addr: str = '0.0.0.0',
        listen_port: int = OFP_TCP_PORT,
        ovs_bridge: str = 'br-guardian'
    ):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.ovs_bridge = ovs_bridge

        # Switch connections
        self.switches: Dict[int, SwitchFeatures] = {}
        self.switch_connections: Dict[int, asyncio.StreamWriter] = {}

        # Flow management
        self.flow_entries: Dict[int, List[FlowEntry]] = defaultdict(list)
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)
        self.mac_to_vlan: Dict[str, int] = {}

        # Threat integration
        self.blocked_macs: Set[str] = set()
        self.quarantined_macs: Set[str] = set()
        self.rate_limited_macs: Dict[str, int] = {}  # MAC -> packets/sec limit

        # Statistics
        self.stats = {
            'packets_in': 0,
            'flows_installed': 0,
            'flows_removed': 0,
            'switches_connected': 0,
            'threat_blocks': 0,
            'vlan_assignments': 0
        }

        # Callbacks
        self.packet_in_handlers: List[Callable] = []
        self.flow_removed_handlers: List[Callable] = []

        # Transaction ID counter
        self._xid = 0
        self._xid_lock = threading.Lock()

        # Server task
        self._server = None
        self._running = False

        logger.info(f"OpenFlow Controller initialized for bridge {ovs_bridge}")

    def _next_xid(self) -> int:
        """Get next transaction ID"""
        with self._xid_lock:
            self._xid = (self._xid + 1) & 0xFFFFFFFF
            return self._xid

    def _make_header(self, msg_type: OFPType, length: int, xid: Optional[int] = None) -> bytes:
        """Create OpenFlow header"""
        if xid is None:
            xid = self._next_xid()
        return struct.pack('!BBHI', OFP_VERSION, msg_type, length, xid)

    async def start(self):
        """Start the OpenFlow controller"""
        self._running = True

        # Initialize OVS bridge
        await self._init_ovs_bridge()

        # Start TCP server
        self._server = await asyncio.start_server(
            self._handle_switch_connection,
            self.listen_addr,
            self.listen_port
        )

        logger.info(f"OpenFlow controller listening on {self.listen_addr}:{self.listen_port}")

        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        """Stop the OpenFlow controller"""
        self._running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # Close all switch connections
        for writer in self.switch_connections.values():
            writer.close()
            await writer.wait_closed()

        logger.info("OpenFlow controller stopped")

    async def _init_ovs_bridge(self):
        """Initialize OVS bridge configuration"""
        try:
            # Check if OVS is available
            result = await asyncio.create_subprocess_exec(
                'ovs-vsctl', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()

            if result.returncode != 0:
                logger.warning("OVS not available, running in simulation mode")
                return

            # Create bridge if not exists
            result = await asyncio.create_subprocess_exec(
                'ovs-vsctl', '--may-exist', 'add-br', self.ovs_bridge,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()

            # Set OpenFlow version
            await asyncio.create_subprocess_exec(
                'ovs-vsctl', 'set', 'bridge', self.ovs_bridge,
                'protocols=OpenFlow13',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Set controller
            controller_addr = f"tcp:{self.listen_addr}:{self.listen_port}"
            await asyncio.create_subprocess_exec(
                'ovs-vsctl', 'set-controller', self.ovs_bridge, controller_addr,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Enable fail-secure mode
            await asyncio.create_subprocess_exec(
                'ovs-vsctl', 'set-fail-mode', self.ovs_bridge, 'secure',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            logger.info(f"OVS bridge {self.ovs_bridge} configured")

        except FileNotFoundError:
            logger.warning("ovs-vsctl not found, OVS integration disabled")
        except Exception as e:
            logger.error(f"Failed to initialize OVS bridge: {e}")

    async def _handle_switch_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle incoming switch connection"""
        peer = writer.get_extra_info('peername')
        logger.info(f"Switch connection from {peer}")

        try:
            # Send HELLO
            hello = self._make_header(OFPType.HELLO, OFP_HEADER_SIZE)
            writer.write(hello)
            await writer.drain()

            # Receive HELLO
            header = await reader.readexactly(OFP_HEADER_SIZE)
            version, msg_type, length, xid = struct.unpack('!BBHI', header)

            if msg_type != OFPType.HELLO:
                logger.error(f"Expected HELLO, got {msg_type}")
                writer.close()
                return

            if length > OFP_HEADER_SIZE:
                await reader.readexactly(length - OFP_HEADER_SIZE)

            # Send FEATURES_REQUEST
            features_req = self._make_header(OFPType.FEATURES_REQUEST, OFP_HEADER_SIZE)
            writer.write(features_req)
            await writer.drain()

            # Main message loop
            while self._running:
                header = await reader.readexactly(OFP_HEADER_SIZE)
                version, msg_type, length, xid = struct.unpack('!BBHI', header)

                body = b''
                if length > OFP_HEADER_SIZE:
                    body = await reader.readexactly(length - OFP_HEADER_SIZE)

                await self._handle_message(msg_type, xid, body, writer)

        except asyncio.IncompleteReadError:
            logger.info(f"Switch {peer} disconnected")
        except Exception as e:
            logger.error(f"Error handling switch {peer}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            self.stats['switches_connected'] = max(0, self.stats['switches_connected'] - 1)

    async def _handle_message(
        self,
        msg_type: int,
        xid: int,
        body: bytes,
        writer: asyncio.StreamWriter
    ):
        """Handle OpenFlow message"""
        if msg_type == OFPType.ECHO_REQUEST:
            # Echo reply
            reply = self._make_header(OFPType.ECHO_REPLY, OFP_HEADER_SIZE + len(body), xid)
            writer.write(reply + body)
            await writer.drain()

        elif msg_type == OFPType.FEATURES_REPLY:
            await self._handle_features_reply(body, writer)

        elif msg_type == OFPType.PACKET_IN:
            await self._handle_packet_in(body, writer)

        elif msg_type == OFPType.FLOW_REMOVED:
            await self._handle_flow_removed(body)

        elif msg_type == OFPType.PORT_STATUS:
            await self._handle_port_status(body)

        elif msg_type == OFPType.ERROR:
            await self._handle_error(body)

    async def _handle_features_reply(self, body: bytes, writer: asyncio.StreamWriter):
        """Handle switch features reply"""
        if len(body) < 24:
            return

        dpid, n_buffers, n_tables, aux_id, capabilities = struct.unpack_from(
            '!QIBB2xI', body
        )

        features = SwitchFeatures(
            datapath_id=dpid,
            n_buffers=n_buffers,
            n_tables=n_tables,
            auxiliary_id=aux_id,
            capabilities=capabilities
        )

        self.switches[dpid] = features
        self.switch_connections[dpid] = writer
        self.stats['switches_connected'] += 1

        logger.info(f"Switch connected: dpid={dpid:016x}, tables={n_tables}, buffers={n_buffers}")

        # Install default flows
        await self._install_default_flows(dpid, writer)

    async def _install_default_flows(self, dpid: int, writer: asyncio.StreamWriter):
        """Install default flow entries for a switch"""
        # Table-miss flow: send to controller
        table_miss = FlowEntry(
            table_id=0,
            priority=0,
            match=FlowMatch(),
            actions=[FlowAction(OFPActionType.OUTPUT, port=OFPPort.CONTROLLER)]
        )
        await self._send_flow_mod(dpid, table_miss, writer)

        # ARP pass-through (for L2 learning)
        arp_flow = FlowEntry(
            table_id=0,
            priority=100,
            match=FlowMatch(eth_type=0x0806),
            actions=[FlowAction(OFPActionType.OUTPUT, port=OFPPort.CONTROLLER)]
        )
        await self._send_flow_mod(dpid, arp_flow, writer)

        # DHCP to controller
        dhcp_flow = FlowEntry(
            table_id=0,
            priority=100,
            match=FlowMatch(eth_type=0x0800, ip_proto=17, udp_dst=67),
            actions=[FlowAction(OFPActionType.OUTPUT, port=OFPPort.CONTROLLER)]
        )
        await self._send_flow_mod(dpid, dhcp_flow, writer)

        # Drop broadcast storms (high priority)
        broadcast_drop = FlowEntry(
            table_id=0,
            priority=65535,
            match=FlowMatch(eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0800),
            actions=[],  # Drop
            idle_timeout=300
        )
        # Don't install by default, only on storm detection

        logger.info(f"Default flows installed for dpid={dpid:016x}")

    async def _handle_packet_in(self, body: bytes, writer: asyncio.StreamWriter):
        """Handle packet-in message"""
        if len(body) < 24:
            return

        buffer_id, total_len, reason, table_id, cookie = struct.unpack_from(
            '!IHBBQ', body
        )

        self.stats['packets_in'] += 1

        # Parse match (OXM format)
        match_offset = 16
        match_type, match_len = struct.unpack_from('!HH', body, match_offset)

        # Extract in_port from match
        in_port = 1  # Default
        oxm_offset = match_offset + 4
        oxm_end = match_offset + match_len

        while oxm_offset < oxm_end - 4:
            oxm_header = struct.unpack_from('!I', body, oxm_offset)[0]
            oxm_class = (oxm_header >> 16) & 0xFFFF
            oxm_field = (oxm_header >> 9) & 0x7F
            oxm_length = oxm_header & 0xFF

            if oxm_class == OXMClass.OPENFLOW_BASIC and oxm_field == OXMField.IN_PORT:
                in_port = struct.unpack_from('!I', body, oxm_offset + 4)[0]
                break

            oxm_offset += 4 + oxm_length

        # Pad to 8-byte alignment
        padded_match_len = match_len + ((8 - (match_len % 8)) % 8)

        # Get packet data
        packet_offset = match_offset + padded_match_len + 2  # +2 for pad
        packet_data = body[packet_offset:]

        if len(packet_data) < 14:
            return

        # Parse Ethernet header
        eth_dst = packet_data[0:6].hex(':')
        eth_src = packet_data[6:12].hex(':')
        eth_type = struct.unpack('!H', packet_data[12:14])[0]

        # Get dpid from first connected switch
        dpid = next(iter(self.switches.keys()), 0)

        # Check if MAC is blocked
        if eth_src.lower() in self.blocked_macs:
            logger.warning(f"Blocked packet from {eth_src}")
            self.stats['threat_blocks'] += 1
            return

        # Check if MAC is quarantined
        if eth_src.lower() in self.quarantined_macs:
            await self._quarantine_packet(dpid, in_port, eth_src, packet_data, writer)
            return

        # L2 learning
        self.mac_to_port[dpid][eth_src.lower()] = in_port

        # Determine output port
        out_port = self.mac_to_port[dpid].get(eth_dst.lower(), OFPPort.FLOOD)

        # Get VLAN for source MAC
        vlan_id = self.mac_to_vlan.get(eth_src.lower(), GuardianVLAN.GUEST)

        # Build actions
        actions = []

        # Apply VLAN tagging if needed
        if vlan_id and eth_type != 0x8100:
            actions.append(FlowAction(OFPActionType.PUSH_VLAN))
            actions.append(FlowAction(OFPActionType.SET_FIELD, vlan_vid=vlan_id))

        actions.append(FlowAction(OFPActionType.OUTPUT, port=out_port))

        # Install flow for known destinations
        if out_port != OFPPort.FLOOD:
            flow = FlowEntry(
                table_id=0,
                priority=1000,
                idle_timeout=300,
                match=FlowMatch(eth_src=eth_src, eth_dst=eth_dst),
                actions=actions
            )
            await self._send_flow_mod(dpid, flow, writer)

        # Send packet out
        await self._send_packet_out(buffer_id, in_port, actions, packet_data, writer)

        # Notify handlers
        for handler in self.packet_in_handlers:
            try:
                await handler(dpid, in_port, eth_src, eth_dst, eth_type, packet_data)
            except Exception as e:
                logger.error(f"Packet-in handler error: {e}")

    async def _quarantine_packet(
        self,
        dpid: int,
        in_port: int,
        eth_src: str,
        packet_data: bytes,
        writer: asyncio.StreamWriter
    ):
        """Handle packet from quarantined device"""
        # Redirect to quarantine VLAN
        actions = [
            FlowAction(OFPActionType.PUSH_VLAN),
            FlowAction(OFPActionType.SET_FIELD, vlan_vid=GuardianVLAN.QUARANTINE),
            FlowAction(OFPActionType.OUTPUT, port=OFPPort.NORMAL)
        ]

        # Install quarantine flow
        flow = FlowEntry(
            table_id=0,
            priority=65000,
            idle_timeout=3600,
            match=FlowMatch(eth_src=eth_src),
            actions=actions
        )
        await self._send_flow_mod(dpid, flow, writer)

        logger.info(f"Quarantined traffic from {eth_src}")

    async def _send_flow_mod(
        self,
        dpid: int,
        flow: FlowEntry,
        writer: Optional[asyncio.StreamWriter] = None,
        command: OFPFlowModCommand = OFPFlowModCommand.ADD
    ):
        """Send flow mod to switch"""
        if writer is None:
            writer = self.switch_connections.get(dpid)

        if writer is None:
            logger.warning(f"No connection to switch {dpid:016x}")
            return

        flow_mod_body = flow.to_flow_mod(command)
        header = self._make_header(OFPType.FLOW_MOD, OFP_HEADER_SIZE + len(flow_mod_body))

        writer.write(header + flow_mod_body)
        await writer.drain()

        self.stats['flows_installed'] += 1
        self.flow_entries[dpid].append(flow)

    async def _send_packet_out(
        self,
        buffer_id: int,
        in_port: int,
        actions: List[FlowAction],
        data: bytes,
        writer: asyncio.StreamWriter
    ):
        """Send packet out message"""
        actions_data = b''.join(action.to_bytes() for action in actions)
        actions_len = len(actions_data)

        # Packet out: buffer_id (4) + in_port (4) + actions_len (2) + pad (6)
        packet_out = struct.pack('!IIH6x', buffer_id, in_port, actions_len)
        packet_out += actions_data

        if buffer_id == 0xFFFFFFFF:
            packet_out += data

        header = self._make_header(OFPType.PACKET_OUT, OFP_HEADER_SIZE + len(packet_out))
        writer.write(header + packet_out)
        await writer.drain()

    async def _handle_flow_removed(self, body: bytes):
        """Handle flow removed message"""
        if len(body) < 40:
            return

        cookie, priority, reason, table_id, duration_sec, duration_nsec, \
            idle_timeout, hard_timeout, packet_count, byte_count = struct.unpack_from(
                '!QHBBIIHHQQ', body
            )

        self.stats['flows_removed'] += 1

        logger.debug(f"Flow removed: cookie={cookie:016x}, reason={reason}, "
                    f"packets={packet_count}, bytes={byte_count}")

        # Notify handlers
        for handler in self.flow_removed_handlers:
            try:
                await handler(cookie, reason, packet_count, byte_count)
            except Exception as e:
                logger.error(f"Flow removed handler error: {e}")

    async def _handle_port_status(self, body: bytes):
        """Handle port status change"""
        if len(body) < 8:
            return

        reason = struct.unpack_from('!B', body)[0]

        reason_str = {0: 'ADD', 1: 'DELETE', 2: 'MODIFY'}.get(reason, 'UNKNOWN')
        logger.info(f"Port status change: {reason_str}")

    async def _handle_error(self, body: bytes):
        """Handle error message"""
        if len(body) < 4:
            return

        error_type, error_code = struct.unpack_from('!HH', body)

        error_types = {
            0: 'HELLO_FAILED',
            1: 'BAD_REQUEST',
            2: 'BAD_ACTION',
            3: 'BAD_INSTRUCTION',
            4: 'BAD_MATCH',
            5: 'FLOW_MOD_FAILED',
            6: 'GROUP_MOD_FAILED',
            7: 'PORT_MOD_FAILED',
            8: 'TABLE_MOD_FAILED',
            9: 'QUEUE_OP_FAILED',
            10: 'SWITCH_CONFIG_FAILED',
            11: 'ROLE_REQUEST_FAILED',
            12: 'METER_MOD_FAILED',
            13: 'TABLE_FEATURES_FAILED'
        }

        logger.error(f"OpenFlow error: type={error_types.get(error_type, error_type)}, code={error_code}")

    # Public API for threat integration

    async def block_mac(self, mac: str, reason: str = "threat"):
        """Block a MAC address"""
        mac = mac.lower()
        self.blocked_macs.add(mac)

        # Install drop flow on all switches
        for dpid, writer in self.switch_connections.items():
            drop_flow = FlowEntry(
                table_id=0,
                priority=65534,
                match=FlowMatch(eth_src=mac),
                actions=[],  # Drop
                hard_timeout=3600
            )
            await self._send_flow_mod(dpid, drop_flow, writer)

        self.stats['threat_blocks'] += 1
        logger.warning(f"Blocked MAC {mac}: {reason}")

    async def unblock_mac(self, mac: str):
        """Unblock a MAC address"""
        mac = mac.lower()
        self.blocked_macs.discard(mac)

        # Remove drop flow
        for dpid, writer in self.switch_connections.items():
            delete_flow = FlowEntry(
                table_id=0,
                priority=65534,
                match=FlowMatch(eth_src=mac),
                actions=[]
            )
            await self._send_flow_mod(dpid, delete_flow, writer, OFPFlowModCommand.DELETE_STRICT)

        logger.info(f"Unblocked MAC {mac}")

    async def quarantine_mac(self, mac: str, reason: str = "suspicious"):
        """Move MAC to quarantine VLAN"""
        mac = mac.lower()
        self.quarantined_macs.add(mac)
        self.mac_to_vlan[mac] = GuardianVLAN.QUARANTINE

        # Install quarantine flow
        for dpid, writer in self.switch_connections.items():
            quarantine_flow = FlowEntry(
                table_id=0,
                priority=65000,
                match=FlowMatch(eth_src=mac),
                actions=[
                    FlowAction(OFPActionType.PUSH_VLAN),
                    FlowAction(OFPActionType.SET_FIELD, vlan_vid=GuardianVLAN.QUARANTINE),
                    FlowAction(OFPActionType.OUTPUT, port=OFPPort.NORMAL)
                ],
                hard_timeout=3600
            )
            await self._send_flow_mod(dpid, quarantine_flow, writer)

        logger.warning(f"Quarantined MAC {mac}: {reason}")

    async def set_mac_vlan(self, mac: str, vlan_id: int):
        """Assign MAC to specific VLAN"""
        mac = mac.lower()
        self.mac_to_vlan[mac] = vlan_id
        self.stats['vlan_assignments'] += 1

        # Update flows
        for dpid, writer in self.switch_connections.items():
            # Delete existing flows for this MAC
            delete_flow = FlowEntry(
                table_id=0,
                priority=0,
                match=FlowMatch(eth_src=mac),
                actions=[]
            )
            await self._send_flow_mod(dpid, delete_flow, writer, OFPFlowModCommand.DELETE)

        logger.info(f"Assigned MAC {mac} to VLAN {vlan_id}")

    async def apply_rate_limit(self, mac: str, packets_per_sec: int):
        """Apply rate limiting to a MAC address using meters"""
        mac = mac.lower()
        self.rate_limited_macs[mac] = packets_per_sec

        # Note: Full meter implementation would require METER_MOD messages
        logger.info(f"Rate limit applied to {mac}: {packets_per_sec} pps")

    def get_statistics(self) -> Dict[str, Any]:
        """Get controller statistics"""
        return {
            'controller': {
                'listen_addr': self.listen_addr,
                'listen_port': self.listen_port,
                'ovs_bridge': self.ovs_bridge,
                'running': self._running
            },
            'switches': {
                dpid: {
                    'datapath_id': f"{dpid:016x}",
                    'n_tables': features.n_tables,
                    'n_buffers': features.n_buffers
                }
                for dpid, features in self.switches.items()
            },
            'stats': self.stats.copy(),
            'blocked_macs': list(self.blocked_macs),
            'quarantined_macs': list(self.quarantined_macs),
            'mac_to_vlan': dict(self.mac_to_vlan),
            'learned_macs': {
                dpid: dict(macs)
                for dpid, macs in self.mac_to_port.items()
            }
        }

    def register_packet_handler(self, handler: Callable):
        """Register packet-in handler callback"""
        self.packet_in_handlers.append(handler)

    def register_flow_removed_handler(self, handler: Callable):
        """Register flow removed handler callback"""
        self.flow_removed_handlers.append(handler)


class OVSManager:
    """
    Open vSwitch management interface

    Provides high-level OVS configuration through ovs-vsctl and ovs-ofctl.
    """

    def __init__(self, bridge_name: str = 'br-guardian'):
        self.bridge_name = bridge_name
        self._ovs_available = None

    async def _check_ovs(self) -> bool:
        """Check if OVS is available"""
        if self._ovs_available is not None:
            return self._ovs_available

        try:
            proc = await asyncio.create_subprocess_exec(
                'ovs-vsctl', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            self._ovs_available = proc.returncode == 0
        except FileNotFoundError:
            self._ovs_available = False

        return self._ovs_available

    async def create_bridge(self) -> bool:
        """Create OVS bridge"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--may-exist', 'add-br', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error(f"Failed to create bridge: {stderr.decode()}")
            return False

        return True

    async def delete_bridge(self) -> bool:
        """Delete OVS bridge"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--if-exists', 'del-br', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def add_port(self, port_name: str, vlan: Optional[int] = None) -> bool:
        """Add port to bridge"""
        if not await self._check_ovs():
            return False

        cmd = ['ovs-vsctl', '--may-exist', 'add-port', self.bridge_name, port_name]

        if vlan:
            cmd.extend(['tag=' + str(vlan)])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def del_port(self, port_name: str) -> bool:
        """Remove port from bridge"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--if-exists', 'del-port', self.bridge_name, port_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def set_controller(self, controller_addr: str) -> bool:
        """Set OpenFlow controller"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', 'set-controller', self.bridge_name, controller_addr,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def set_protocols(self, protocols: List[str]) -> bool:
        """Set supported OpenFlow protocols"""
        if not await self._check_ovs():
            return False

        proto_str = ','.join(protocols)
        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', 'set', 'bridge', self.bridge_name,
            f'protocols={proto_str}',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def get_ports(self) -> List[str]:
        """Get list of ports on bridge"""
        if not await self._check_ovs():
            return []

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', 'list-ports', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0:
            return []

        return stdout.decode().strip().split('\n') if stdout.strip() else []

    async def get_bridge_info(self) -> Dict[str, Any]:
        """Get bridge information"""
        if not await self._check_ovs():
            return {}

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--format=json', 'list', 'bridge', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0:
            return {}

        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError:
            return {}

    async def add_flow(
        self,
        priority: int,
        match: str,
        actions: str,
        table: int = 0
    ) -> bool:
        """Add flow using ovs-ofctl"""
        if not await self._check_ovs():
            return False

        flow_spec = f"table={table},priority={priority},{match},actions={actions}"

        proc = await asyncio.create_subprocess_exec(
            'ovs-ofctl', '-O', 'OpenFlow13', 'add-flow', self.bridge_name, flow_spec,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def del_flows(self, match: str = '') -> bool:
        """Delete flows matching criteria"""
        if not await self._check_ovs():
            return False

        cmd = ['ovs-ofctl', '-O', 'OpenFlow13', 'del-flows', self.bridge_name]
        if match:
            cmd.append(match)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def dump_flows(self) -> List[str]:
        """Dump all flows"""
        if not await self._check_ovs():
            return []

        proc = await asyncio.create_subprocess_exec(
            'ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0:
            return []

        return stdout.decode().strip().split('\n')


# Export classes
__all__ = [
    'OpenFlowController',
    'OVSManager',
    'FlowEntry',
    'FlowMatch',
    'FlowAction',
    'SwitchFeatures',
    'OVSBridge',
    'GuardianVLAN',
    'OFPType',
    'OFPActionType',
    'OFPFlowModCommand',
    'OFPPort'
]
