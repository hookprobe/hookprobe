"""
Mesh Peer Server — accepts incoming mesh consciousness connections.

Implements the server side of the three-layer mesh protocol:
1. ResilientChannel handshake (MessageType.RESONATE echo)
2. UnifiedTransport resonance (MeshPacket RESONATE INIT→ACK→CONFIRM)
3. Consciousness peer info exchange (CONTROL_CMD with JSON)

After a successful handshake, the peer is registered in the local
MeshConsciousness and gossip / threat intelligence flows bidirectionally.

Usage:
    server = MeshPeerServer(consciousness, host='0.0.0.0', port=8144)
    server.start()         # non-blocking, spawns accept thread
    server.get_status()    # {"peers": [...], "sessions": N}
    server.stop()
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import socket
import ssl
import struct
import threading
import time
import zlib
from dataclasses import dataclass
from enum import IntEnum
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants (duplicated from resilient_channel / unified_transport
# to keep this module self-contained inside the container image)
# ---------------------------------------------------------------------------

# ResilientChannel message header: >BBIIIH = 16 bytes
CHANNEL_HEADER_SIZE = 16
CHANNEL_HEADER_FMT = '>BBIIIH'


# Max payload size for a single channel message (1 MB)
MAX_CHANNEL_PAYLOAD = 1 * 1024 * 1024


class ChannelMsgType(IntEnum):
    DATA = 0x01
    KEEPALIVE = 0x02
    ACK = 0x03
    RESONATE = 0x04
    NEURO_SYNC = 0x05
    PORT_ANNOUNCE = 0x06
    CLOSE = 0xFF


# MeshPacket header: 48 bytes
MESH_HEADER_SIZE = 48
MESH_HEADER_FMT = '>HBBIQ8sII16s'
MESH_VERSION = 0x0500


class PacketType(IntEnum):
    HANDSHAKE = 0x01
    KEEPALIVE = 0x02
    ACK = 0x03
    CLOSE = 0x04
    RESONATE = 0x10
    TER_SYNC = 0x11
    WEIGHT_SYNC = 0x12
    POSF_VERIFY = 0x13
    GOSSIP = 0x32
    SECURITY_EVENT = 0x42
    CONTROL_CMD = 0x43


class PacketFlags:
    RELIABLE = 0x08


# ---------------------------------------------------------------------------
# Server-side transport wrapper for an accepted connection
# ---------------------------------------------------------------------------

@dataclass
class PeerSession:
    """An accepted peer connection."""
    node_id: str
    tier: str
    endpoint: str
    connected_at: float
    last_seen: float
    sock: socket.socket
    lock: threading.Lock
    running: bool = True
    recv_thread: Optional[threading.Thread] = None
    capabilities: List[str] = None

    def to_status(self) -> Dict[str, Any]:
        return {
            'node_id': self.node_id,
            'tier': self.tier,
            'endpoint': self.endpoint,
            'connected_seconds': int(time.time() - self.connected_at),
            'last_seen_seconds_ago': int(time.time() - self.last_seen),
        }


class MeshPeerServer:
    """
    TCP server that accepts incoming mesh peer connections.

    Speaks the ResilientChannel + MeshPacket protocol stack so that
    remote MeshConsciousness instances can connect as peers.
    """

    def __init__(
        self,
        node_id: str = 'fortress001',
        tier: str = 'FORTRESS',
        host: str = '0.0.0.0',
        port: int = 8144,
        neuro_seed: bytes = b'',
        bootstrap_peers: Optional[List[str]] = None,
    ):
        self.node_id = node_id
        self.tier = tier
        self.host = host
        self.port = port
        self.neuro_seed = neuro_seed or secrets.token_bytes(32)

        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None
        self._bootstrap_thread: Optional[threading.Thread] = None
        self._peers: Dict[str, PeerSession] = {}
        self._connected_endpoints: set = set()  # track outbound connections
        self._lock = threading.Lock()

        # Bootstrap peers for outbound connections (e.g. MSSP relay)
        self._bootstrap_peers: List[str] = bootstrap_peers or []

        # Flow token for this server
        self._flow_token = secrets.token_bytes(8)

        # Neuro encoder for proper resonance handshake
        _node_id_bytes = hashlib.sha256(node_id.encode()).digest()[:16]
        try:
            from shared.mesh.neuro_encoder import NeuroResonanceEncoder
            self._encoder = NeuroResonanceEncoder(self.neuro_seed, _node_id_bytes)
        except ImportError:
            try:
                from neuro_encoder import NeuroResonanceEncoder
                self._encoder = NeuroResonanceEncoder(self.neuro_seed, _node_id_bytes)
            except ImportError:
                self._encoder = None

        # Gossip intelligence received from peers
        self._received_intel: List[Dict] = []
        self._intel_lock = threading.Lock()

        # Callbacks
        self._on_intel_received: List = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start listening for peer connections and connecting to bootstrap peers."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(2.0)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(10)

        # Wrap listen socket in TLS if certs exist and port is 8443/443.
        # Outbound bootstrap connections already wrap in TLS for these ports,
        # so the server side must match.
        self._tls_enabled = False
        if self.port in (443, 8443):
            cert_paths = [
                ('/etc/nginx/ssl/mssp.hookprobe.com.crt',
                 '/etc/nginx/ssl/mssp.hookprobe.com.key'),
                ('/opt/hookprobe/mesh/data/mesh.crt',
                 '/opt/hookprobe/mesh/data/mesh.key'),
            ]
            for cert_file, key_file in cert_paths:
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(cert_file, key_file)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    self._server_sock = ctx.wrap_socket(
                        self._server_sock, server_side=True,
                    )
                    self._tls_enabled = True
                    logger.info("TLS enabled on port %d (%s)", self.port, cert_file)
                    break
            if not self._tls_enabled:
                logger.warning(
                    "Port %d expects TLS but no certs found — running plain TCP",
                    self.port,
                )

        self._running = True

        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True,
        )
        self._accept_thread.start()
        logger.info(
            "MeshPeerServer listening on %s:%d/%s",
            self.host, self.port, "tls" if self._tls_enabled else "tcp",
        )

        # Start outbound bootstrap connections (e.g. to MSSP relay)
        if self._bootstrap_peers:
            self._bootstrap_thread = threading.Thread(
                target=self._bootstrap_loop, daemon=True,
            )
            self._bootstrap_thread.start()
            logger.info(
                "Bootstrap peers: %s", ', '.join(self._bootstrap_peers),
            )

    def stop(self) -> None:
        """Stop the server and disconnect all peers."""
        self._running = False
        with self._lock:
            for peer in self._peers.values():
                peer.running = False
                try:
                    peer.sock.close()
                except Exception:
                    pass
            self._peers.clear()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        logger.info("MeshPeerServer stopped")

    # ------------------------------------------------------------------
    # Status API
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Return mesh status for the health endpoint."""
        with self._lock:
            peers = [p.to_status() for p in self._peers.values()]
            connected_out = list(self._connected_endpoints)
        with self._intel_lock:
            intel_count = len(self._received_intel)
        return {
            'mesh_active': self._running,
            'peer_count': len(peers),
            'peers': peers,
            'intel_received': intel_count,
            'bootstrap_peers': self._bootstrap_peers,
            'connected_outbound': connected_out,
        }

    # ------------------------------------------------------------------
    # Accept loop
    # ------------------------------------------------------------------

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.error("Accept error", exc_info=True)
                break

            endpoint = f"{addr[0]}:{addr[1]}"
            logger.info("Incoming mesh peer from %s", endpoint)
            threading.Thread(
                target=self._handle_peer, args=(conn, endpoint),
                daemon=True,
            ).start()

    # ------------------------------------------------------------------
    # Outbound bootstrap (connect to MSSP relay, other Fortresses)
    # ------------------------------------------------------------------

    def _bootstrap_loop(self) -> None:
        """Periodically connect outbound to bootstrap peers (MSSP, etc.).

        This enables mesh connectivity when this node is behind NAT/CGNAT
        and cannot accept inbound connections from the internet.  Both sides
        connect outbound to MSSP; MSSP relays gossip between them.
        """
        # Initial delay to let the server socket bind first
        time.sleep(5)

        while self._running:
            for endpoint in self._bootstrap_peers:
                # Skip if already connected to this endpoint
                with self._lock:
                    if endpoint in self._connected_endpoints:
                        continue

                try:
                    host, port_str = endpoint.rsplit(':', 1)
                    port = int(port_str)
                except ValueError:
                    logger.warning("Invalid bootstrap peer: %s", endpoint)
                    continue

                try:
                    logger.info(
                        "Bootstrap connecting to %s:%d ...", host, port,
                    )
                    sock = socket.create_connection(
                        (host, port), timeout=15,
                    )
                    # Wrap in TLS for Cloudflare-proxied ports (443, 8443)
                    if port in (443, 8443):
                        ctx = ssl.create_default_context()
                        sock = ctx.wrap_socket(
                            sock, server_hostname=host,
                        )
                        logger.debug(
                            "TLS wrapped for %s:%d", host, port,
                        )
                    with self._lock:
                        self._connected_endpoints.add(endpoint)

                    threading.Thread(
                        target=self._handle_outbound_peer,
                        args=(sock, endpoint),
                        daemon=True,
                    ).start()

                except Exception as e:
                    logger.debug(
                        "Bootstrap connect to %s failed: %s", endpoint, e,
                    )

            # Retry every 60 seconds
            for _ in range(60):
                if not self._running:
                    return
                time.sleep(1)

    def _handle_outbound_peer(
        self, sock: socket.socket, endpoint: str,
    ) -> None:
        """Handle an outbound connection — same handshake as inbound."""
        try:
            self._handle_peer(sock, endpoint)
        finally:
            with self._lock:
                self._connected_endpoints.discard(endpoint)

    # ------------------------------------------------------------------
    # Per-peer handler
    # ------------------------------------------------------------------

    def _handle_peer(self, sock: socket.socket, endpoint: str) -> None:
        """Handle full handshake + message loop for one peer."""
        sock.settimeout(30.0)
        try:
            # Layer 1: ResilientChannel RESONATE handshake
            if not self._channel_handshake(sock):
                logger.warning("Channel handshake failed from %s", endpoint)
                sock.close()
                return

            # Layer 2: MeshPacket resonance handshake (INIT→ACK→CONFIRM)
            if not self._resonance_handshake(sock):
                logger.warning("Resonance handshake failed from %s", endpoint)
                sock.close()
                return

            # Layer 3: Weight sync (receive + respond)
            self._weight_sync(sock)

            # Layer 4: Peer info exchange
            peer_info = self._peer_info_exchange(sock, endpoint)
            if not peer_info:
                logger.warning("Peer info exchange failed from %s", endpoint)
                sock.close()
                return

            # Register peer
            session = PeerSession(
                node_id=peer_info.get('node_id', 'unknown'),
                tier=peer_info.get('tier', 'UNKNOWN'),
                endpoint=endpoint,
                connected_at=time.time(),
                last_seen=time.time(),
                sock=sock,
                lock=threading.Lock(),
                capabilities=peer_info.get('capabilities', []),
            )

            with self._lock:
                self._peers[session.node_id] = session

            logger.info(
                "Mesh peer connected: %s (%s) from %s",
                session.node_id[:16], session.tier, endpoint,
            )

            # Enter message loop
            sock.settimeout(120.0)
            self._message_loop(session)

        except Exception as e:
            logger.warning("Peer handler error for %s: %s", endpoint, e)
        finally:
            # Cleanup
            try:
                sock.close()
            except Exception:
                pass
            with self._lock:
                # Remove peer if it was registered
                to_remove = [
                    k for k, v in self._peers.items() if v.sock is sock
                ]
                for k in to_remove:
                    logger.info("Peer disconnected: %s", k)
                    del self._peers[k]

    # ------------------------------------------------------------------
    # Layer 1: ResilientChannel RESONATE
    # ------------------------------------------------------------------

    def _channel_handshake(self, sock: socket.socket) -> bool:
        """Server side of ResilientChannel RESONATE handshake."""
        try:
            # Receive client's RESONATE
            msg_type, payload = self._recv_channel_msg(sock, timeout=10.0)
            logger.debug(
                "Channel handshake: got type=0x%02x len=%d",
                msg_type.value, len(payload),
            )
            if msg_type != ChannelMsgType.RESONATE:
                return False
            if len(payload) < 24:
                return False

            # Send our RESONATE response
            response = struct.pack(
                '>8s8sQ',
                self._flow_token,
                secrets.token_bytes(8),
                int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF,
            )
            self._send_channel_msg(sock, ChannelMsgType.RESONATE, response)
            return True

        except Exception as e:
            logger.debug("Channel handshake error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Layer 2: MeshPacket RESONATE (INIT→ACK→CONFIRM)
    # ------------------------------------------------------------------

    def _recv_data_msg(self, sock: socket.socket, timeout: float) -> bytes:
        """Receive next DATA channel message, skipping ACKs/keepalives."""
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for DATA message")
            msg_type, raw = self._recv_channel_msg(sock, timeout=remaining)
            if msg_type == ChannelMsgType.DATA:
                return raw
            # Client's _receive_loop sends channel ACKs (0x02) and
            # keepalives (0x03) — skip them on the server side.
            logger.debug(
                "Skipping channel msg type=0x%02x len=%d (waiting for DATA)",
                msg_type.value, len(raw),
            )

    def _resonance_handshake(self, sock: socket.socket) -> bool:
        """Server side of UnifiedTransport resonance handshake."""
        try:
            # Receive RESONATE INIT (inside a DATA channel message)
            raw = self._recv_data_msg(sock, timeout=30.0)
            logger.debug("Resonance INIT: got %d bytes", len(raw))

            pkt = self._parse_mesh_packet(raw)
            if pkt is None:
                logger.debug("Failed to parse mesh packet from %d bytes", len(raw))
                return False
            if pkt['type'] != PacketType.RESONATE:
                logger.debug("Expected RESONATE (0x10), got 0x%02x", pkt['type'])
                return False

            payload = pkt['payload']
            if len(payload) < 1 or payload[0] != 0x01:  # INIT
                return False

            # Use ResonanceHandshake to generate a proper ACK that the
            # client's process_ack() can parse (nonce + valid RDV).
            # The client strips the first marker byte before calling
            # process_ack, and process_ack expects [0x02][nonce][RDV],
            # so we produce [0x02] + process_init() output which itself
            # starts with [0x02][nonce][RDV].
            try:
                try:
                    from shared.mesh.neuro_encoder import ResonanceHandshake
                except ImportError:
                    from neuro_encoder import ResonanceHandshake
                handshake = ResonanceHandshake(
                    encoder=self._encoder,
                    channel_binding=self._flow_token,
                    is_initiator=False,
                )
                ok, ack_body = handshake.process_init(payload[1:])
                if not ok:
                    logger.debug("ResonanceHandshake.process_init failed: %s", ack_body)
                    return False
                ack_data = b'\x02' + ack_body
            except Exception as e:
                logger.debug("ResonanceHandshake import/use failed, falling back: %s", e)
                ack_data = b'\x02' + secrets.token_bytes(64)

            ack_pkt = self._build_mesh_packet(
                PacketType.RESONATE, ack_data,
            )
            self._send_channel_msg(sock, ChannelMsgType.DATA, ack_pkt)
            logger.debug("Resonance ACK sent, waiting for CONFIRM...")

            # Receive CONFIRM
            raw = self._recv_data_msg(sock, timeout=30.0)

            pkt = self._parse_mesh_packet(raw)
            if pkt is None or pkt['type'] != PacketType.RESONATE:
                return False
            if len(pkt['payload']) < 1 or pkt['payload'][0] != 0x03:  # CONFIRM
                return False

            logger.debug("Resonance CONFIRM received — handshake complete")
            return True

        except Exception as e:
            logger.debug("Resonance handshake error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Layer 3: Weight sync
    # ------------------------------------------------------------------

    def _weight_sync(self, sock: socket.socket) -> bool:
        """Server side of weight fingerprint exchange."""
        try:
            raw = self._recv_data_msg(sock, timeout=30.0)

            pkt = self._parse_mesh_packet(raw)
            if pkt is None or pkt['type'] != PacketType.WEIGHT_SYNC:
                return False

            # Respond with our weight fingerprint (proper 80-byte format)
            # Format: >64sIIQ (fingerprint, epoch, ter_sequence, timestamp_us)
            if self._encoder:
                our_fp = self._encoder.get_weight_fingerprint().to_bytes()
            else:
                our_fp = struct.pack(
                    '>64sIIQ',
                    secrets.token_bytes(64), 1, 0,
                    int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF,
                )
            resp_pkt = self._build_mesh_packet(
                PacketType.WEIGHT_SYNC, our_fp,
            )
            self._send_channel_msg(sock, ChannelMsgType.DATA, resp_pkt)
            return True

        except Exception as e:
            logger.debug("Weight sync error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Layer 4: Peer info exchange
    # ------------------------------------------------------------------

    def _peer_info_exchange(
        self, sock: socket.socket, endpoint: str,
    ) -> Optional[Dict]:
        """Exchange peer info (JSON over CONTROL_CMD)."""
        try:
            # Receive peer info from client
            msg_type, raw = self._recv_channel_msg(sock, timeout=10.0)
            if msg_type != ChannelMsgType.DATA:
                return None

            pkt = self._parse_mesh_packet(raw)
            if pkt is None or pkt['type'] != PacketType.CONTROL_CMD:
                return None

            msg = json.loads(pkt['payload'].decode())
            if msg.get('type') != 'peer_info':
                return None

            peer_data = msg['data']

            # Validate peer fields
            p_node_id = peer_data.get('node_id', '')
            if len(p_node_id) > 64:
                peer_data['node_id'] = p_node_id[:64]
            valid_tiers = {'SENTINEL', 'GUARDIAN', 'FORTRESS', 'NEXUS', 'UNKNOWN'}
            if peer_data.get('tier', 'UNKNOWN') not in valid_tiers:
                peer_data['tier'] = 'UNKNOWN'
            caps = peer_data.get('capabilities', [])
            if isinstance(caps, list) and len(caps) > 20:
                peer_data['capabilities'] = caps[:20]

            # Reject duplicate node_id (prevent impersonation)
            decoded_nid = peer_data.get('node_id', '')
            with self._lock:
                if decoded_nid in self._peers:
                    logger.warning(
                        "Duplicate node_id %s from %s — rejecting",
                        decoded_nid[:16], endpoint,
                    )
                    return None

            # Send our info back
            our_info = {
                'type': 'peer_info',
                'data': {
                    'node_id': self.node_id.encode().hex()
                    if isinstance(self.node_id, str)
                    else self.node_id.hex(),
                    'tier': self.tier,
                    'weight_fp': secrets.token_bytes(16).hex(),
                    'capabilities': [
                        'gossip', 'threat_intel', 'resonance',
                        'dsm', 'cortex', 'route',
                    ],
                },
            }
            info_pkt = self._build_mesh_packet(
                PacketType.CONTROL_CMD,
                json.dumps(our_info).encode(),
            )
            self._send_channel_msg(sock, ChannelMsgType.DATA, info_pkt)

            return peer_data

        except Exception as e:
            logger.debug("Peer info exchange error: %s", e)
            return None

    # ------------------------------------------------------------------
    # Message loop (post-handshake)
    # ------------------------------------------------------------------

    def _message_loop(self, session: PeerSession) -> None:
        """Read messages from a connected peer."""
        while session.running and self._running:
            try:
                msg_type, raw = self._recv_channel_msg(
                    session.sock, timeout=60.0,
                )
            except socket.timeout:
                # Send keepalive
                try:
                    self._send_channel_msg(
                        session.sock, ChannelMsgType.KEEPALIVE, b'',
                    )
                except Exception:
                    break
                continue
            except Exception:
                break

            session.last_seen = time.time()

            if msg_type == ChannelMsgType.KEEPALIVE:
                continue
            elif msg_type == ChannelMsgType.CLOSE:
                break
            elif msg_type == ChannelMsgType.DATA:
                pkt = self._parse_mesh_packet(raw)
                if pkt is None:
                    continue
                self._handle_mesh_packet(session, pkt)

    def _handle_mesh_packet(
        self, session: PeerSession, pkt: Dict,
    ) -> None:
        """Handle a mesh-layer packet from a peer."""
        ptype = pkt['type']

        if ptype == PacketType.GOSSIP:
            self._handle_gossip(session, pkt['payload'])
        elif ptype == PacketType.SECURITY_EVENT:
            self._handle_security_event(session, pkt['payload'])
        elif ptype == PacketType.KEEPALIVE:
            pass
        elif ptype == PacketType.CONTROL_CMD:
            self._handle_control(session, pkt['payload'])
        else:
            logger.debug(
                "Unhandled mesh packet type 0x%02x from %s",
                ptype, session.node_id,
            )

    def _handle_gossip(self, session: PeerSession, payload: bytes) -> None:
        """Handle received threat intelligence gossip."""
        try:
            intel = json.loads(payload.decode())
        except Exception:
            intel = {'raw': payload.hex(), 'type': 'binary'}

        intel['_source'] = session.node_id
        intel['_received_at'] = time.time()

        with self._intel_lock:
            self._received_intel.append(intel)
            # Cap at 1000 entries
            if len(self._received_intel) > 1000:
                self._received_intel = self._received_intel[-500:]

        for cb in self._on_intel_received:
            try:
                cb(intel)
            except Exception:
                pass

        logger.info(
            "Gossip received from %s: %s",
            session.node_id[:16],
            str(intel)[:120],
        )

    def _handle_security_event(
        self, session: PeerSession, payload: bytes,
    ) -> None:
        """Handle a security event from a peer."""
        logger.info(
            "Security event from %s (%d bytes)",
            session.node_id[:16], len(payload),
        )

    def _handle_control(self, session: PeerSession, payload: bytes) -> None:
        """Handle control command from a peer."""
        try:
            msg = json.loads(payload.decode())
            if msg.get('type') == 'get_peers':
                # Respond with peer list
                with self._lock:
                    peer_list = [
                        {'node_id': p.node_id, 'tier': p.tier}
                        for p in self._peers.values()
                    ]
                resp = json.dumps({
                    'type': 'peer_list',
                    'peers': peer_list,
                }).encode()
                resp_pkt = self._build_mesh_packet(
                    PacketType.CONTROL_CMD, resp,
                )
                with session.lock:
                    self._send_channel_msg(
                        session.sock, ChannelMsgType.DATA, resp_pkt,
                    )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Send gossip to all peers
    # ------------------------------------------------------------------

    def broadcast_gossip(self, intel: Dict) -> int:
        """Send threat intelligence to all connected peers. Returns count."""
        payload = json.dumps(intel).encode()
        pkt = self._build_mesh_packet(PacketType.GOSSIP, payload)
        sent = 0
        with self._lock:
            for session in list(self._peers.values()):
                try:
                    with session.lock:
                        self._send_channel_msg(
                            session.sock, ChannelMsgType.DATA, pkt,
                        )
                    sent += 1
                except Exception:
                    pass
        return sent

    # ------------------------------------------------------------------
    # Wire protocol helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _recv_channel_msg(
        sock: socket.socket, timeout: float = 10.0,
    ) -> Tuple[ChannelMsgType, bytes]:
        """Receive a ResilientChannel-framed message."""
        old_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        try:
            header = _recv_exact(sock, CHANNEL_HEADER_SIZE)
            (
                msg_type_val, flags, sequence, length, checksum, _reserved,
            ) = struct.unpack(CHANNEL_HEADER_FMT, header)

            payload = b''
            if length > MAX_CHANNEL_PAYLOAD:
                raise ValueError(
                    f"Payload too large: {length} > {MAX_CHANNEL_PAYLOAD}"
                )
            if length > 0:
                payload = _recv_exact(sock, length)

            return ChannelMsgType(msg_type_val), payload
        finally:
            sock.settimeout(old_timeout)

    @staticmethod
    def _send_channel_msg(
        sock: socket.socket,
        msg_type: ChannelMsgType,
        data: bytes,
        sequence: int = 0,
    ) -> None:
        """Send a ResilientChannel-framed message."""
        checksum = _channel_checksum(data)
        header = struct.pack(
            CHANNEL_HEADER_FMT,
            msg_type.value, 0, sequence, len(data), checksum, 0,
        )
        sock.sendall(header + data)

    def _build_mesh_packet(
        self, ptype: PacketType, payload: bytes,
    ) -> bytes:
        """Build a MeshPacket (48-byte header + payload)."""
        checksum = _mesh_checksum(payload)
        header = struct.pack(
            MESH_HEADER_FMT,
            MESH_VERSION,
            ptype.value,
            PacketFlags.RELIABLE,
            0,  # sequence
            int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF,
            self._flow_token,
            len(payload),
            checksum,
            b'\x00' * 16,  # rdv_prefix
        )
        return header + payload

    @staticmethod
    def _parse_mesh_packet(raw: bytes) -> Optional[Dict]:
        """Parse a MeshPacket from raw bytes."""
        if len(raw) < MESH_HEADER_SIZE:
            return None
        try:
            (
                version, ptype, flags, seq, ts, flow, plen, cksum, rdv,
            ) = struct.unpack(MESH_HEADER_FMT, raw[:MESH_HEADER_SIZE])
            payload = raw[MESH_HEADER_SIZE:MESH_HEADER_SIZE + plen]
            return {
                'type': PacketType(ptype),
                'flags': flags,
                'sequence': seq,
                'payload': payload,
            }
        except Exception:
            return None


def _channel_checksum(data: bytes) -> int:
    """Match ResilientChannel._calculate_checksum (SHA256-based)."""
    h = hashlib.sha256(data).digest()
    return struct.unpack('>I', h[:4])[0]


def _mesh_checksum(data: bytes) -> int:
    """Match MeshPacket._crc32 (CRC32-based) in unified_transport."""
    return zlib.crc32(data) & 0xFFFFFFFF


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    """Receive exactly *length* bytes from sock."""
    buf = b''
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# HTTP API for health/status/gossip (replaces inline Python in entrypoint)
# ---------------------------------------------------------------------------

class _MeshAPIHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for mesh health/status/gossip."""

    server_ref: 'MeshPeerServer' = None
    start_time: float = 0.0
    node_id: str = ''
    gossip_token: str = ''  # shared secret for /gossip POST

    def log_message(self, fmt, *args):
        logger.debug("HTTP %s", fmt % args)

    def do_GET(self):
        if self.path == '/health':
            body = json.dumps({'status': 'healthy'})
            self._respond(200, body)
        elif self.path == '/status':
            status = {
                'status': 'healthy',
                'service': 'mesh-orchestrator',
                'node_id': self.node_id,
                'uptime': int(time.time() - self.start_time),
            }
            if self.server_ref:
                status['mesh'] = self.server_ref.get_status()
            self._respond(200, json.dumps(status))
        else:
            self._respond(404, '{"error": "not found"}')

    def do_POST(self):
        if self.path == '/gossip':
            # Authenticate: require X-Gossip-Token header
            if self.gossip_token:
                token = self.headers.get('X-Gossip-Token', '')
                if not secrets.compare_digest(token, self.gossip_token):
                    self._respond(403, '{"error": "forbidden"}')
                    return
            length = int(self.headers.get('Content-Length', 0))
            if length > 0 and length < 65536:
                body = self.rfile.read(length)
                try:
                    intel = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._respond(400, '{"error": "invalid json"}')
                    return
                sent = 0
                if self.server_ref:
                    sent = self.server_ref.broadcast_gossip(intel)
                self._respond(200, json.dumps({'sent_to_peers': sent}))
            else:
                self._respond(400, '{"error": "missing or oversized body"}')
        else:
            self._respond(404, '{"error": "not found"}')

    def _respond(self, code: int, body: str):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())


def _start_http_api(
    server_ref: MeshPeerServer, port: int, node_id: str,
    gossip_token: str = '',
) -> threading.Thread:
    """Start the HTTP API in a daemon thread. Returns the thread."""
    _MeshAPIHandler.server_ref = server_ref
    _MeshAPIHandler.start_time = time.time()
    _MeshAPIHandler.node_id = node_id
    _MeshAPIHandler.gossip_token = gossip_token
    httpd = HTTPServer(('127.0.0.1', port), _MeshAPIHandler)
    httpd.timeout = 2.0
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    logger.info("MeshHTTPAPI listening on 127.0.0.1:%d", port)
    return t


# ---------------------------------------------------------------------------
# Standalone entry point (run inside the fts-mesh container)
# ---------------------------------------------------------------------------

def _parse_bootstrap_peers(raw: str) -> List[str]:
    """Parse comma-separated bootstrap peers, filtering empty/invalid entries."""
    peers = []
    for p in raw.split(','):
        p = p.strip()
        if p and ':' in p:
            peers.append(p)
    return peers


def main():
    import argparse
    import os

    parser = argparse.ArgumentParser(description='Mesh Peer Server')
    parser.add_argument(
        '--port', type=int,
        default=int(os.environ.get('MESH_PEER_PORT', '8144')),
    )
    parser.add_argument(
        '--api-port', type=int,
        default=int(os.environ.get('CORTEX_WS_PORT', '8766')),
        help='HTTP API port for health/status/gossip',
    )
    parser.add_argument(
        '--node-id',
        default=os.environ.get('MESH_NODE_ID', 'fortress001'),
    )
    parser.add_argument(
        '--bootstrap',
        default=os.environ.get('MESH_BOOTSTRAP_PEERS', ''),
        help='Comma-separated bootstrap peers (e.g. mssp.hookprobe.com:8443)',
    )
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )

    bootstrap_peers = _parse_bootstrap_peers(args.bootstrap)

    server = MeshPeerServer(
        node_id=args.node_id,
        tier='FORTRESS',
        port=args.port,
        bootstrap_peers=bootstrap_peers,
    )
    server.start()

    # Start HTTP API (health/status/gossip)
    gossip_token = os.environ.get('MESH_GOSSIP_TOKEN', '')
    _start_http_api(server, args.api_port, args.node_id, gossip_token)

    # Block forever, writing status to /tmp for compatibility
    status_file = '/tmp/mesh_status.json'
    try:
        while True:
            time.sleep(10)
            status = server.get_status()
            try:
                tmp = status_file + '.tmp'
                with open(tmp, 'w') as f:
                    json.dump(status, f)
                os.replace(tmp, status_file)
            except Exception:
                pass
            if status['peer_count'] > 0 or int(time.time()) % 60 < 10:
                logger.info(
                    "Mesh status: %d peers, %d intel received",
                    status['peer_count'], status['intel_received'],
                )
    except KeyboardInterrupt:
        server.stop()


if __name__ == '__main__':
    main()
