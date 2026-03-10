#!/usr/bin/env python3
"""
HTP VPN Gateway — Server-side HookProbe Transport Protocol

Accepts incoming HTP VPN connections from Guardian/Fortress/Sentinel nodes
and routes their traffic to the internet through an encrypted tunnel.

Runs on any machine with a public IP (MSSP server, Fortress, cloud VM).
Handles multiple concurrent clients with per-client IP assignment.

Protocol (mirrors products/guardian/lib/htp_vpn_client.py):
    1. Client → HELLO  (version + node_id + nonce + flow_token)
    2. GW     → CHALLENGE (version + challenge)
    3. Client → ATTEST (version + HMAC + flow_token)
    4. GW     → ACCEPT/REJECT
    5. Bidirectional encrypted IP packets (ChaCha20-Poly1305)

Also responds to STUN Binding Requests on the same port, so nodes
can discover their public IP:port for NAT traversal.

Architecture:
    [Guardian]──UDP 8144──→[Gateway TUN htp-gw]──→[Internet]
    [Fortress]──UDP 8144──→[      ↑ same      ]──→[Internet]

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import argparse
import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("mesh.gateway")

# ============================================================
# CONSTANTS
# ============================================================

# HTP protocol
HTP_VERSION = 0x0001
HELLO = 0x01
CHALLENGE = 0x02
ATTEST = 0x03
ACCEPT = 0x04
REJECT = 0x05
CLOSE = 0x09
IP_PACKET = 0x10
KEEPALIVE = 0x14

# TUN device
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA

# Network
TUN_DEVICE_NAME = "htp-gw"
TUN_GATEWAY_IP = "10.250.0.1"
TUN_SUBNET = "10.250.0.0/24"
TUN_MTU = 1400
CLIENT_IP_BASE = 2  # First client gets 10.250.0.2

# Timing
KEEPALIVE_INTERVAL = 25
SESSION_TIMEOUT = 75  # 3 × keepalive
HANDSHAKE_TIMEOUT = 30  # Pending handshake expiry
MAINTENANCE_INTERVAL = 15

# STUN (RFC 5389)
STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_SOFTWARE = 0x8022

# Limits
DEFAULT_MAX_CLIENTS = 10
DEFAULT_LISTEN_PORT = 8144


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class PendingHandshake:
    """Tracks a handshake in progress (between HELLO and ATTEST)."""
    node_id: str
    client_nonce: bytes
    gateway_challenge: bytes
    flow_token: int
    client_addr: Tuple[str, int]
    created_at: float


@dataclass
class GatewaySession:
    """An established VPN session with a client."""
    flow_token: int
    node_id: str
    session_key: bytes
    client_addr: Tuple[str, int]
    assigned_ip: str  # e.g., "10.250.0.2"
    created_at: float
    last_activity: float
    tx_sequence: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0


# ============================================================
# IP HEADER UTILITIES
# ============================================================

def _ip_checksum(header: bytes) -> int:
    """Calculate IPv4 header checksum (RFC 791)."""
    if len(header) % 2:
        header += b'\x00'
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def rewrite_src_ip(packet: bytes, new_ip: str) -> bytes:
    """Rewrite IPv4 source address and recalculate checksum."""
    if len(packet) < 20:
        return packet
    ihl = (packet[0] & 0x0F) * 4
    pkt = bytearray(packet)
    pkt[12:16] = socket.inet_aton(new_ip)
    # Zero checksum field, recalculate
    pkt[10:12] = b'\x00\x00'
    pkt[10:12] = struct.pack('>H', _ip_checksum(bytes(pkt[:ihl])))
    return bytes(pkt)


def rewrite_dst_ip(packet: bytes, new_ip: str) -> bytes:
    """Rewrite IPv4 destination address and recalculate checksum."""
    if len(packet) < 20:
        return packet
    ihl = (packet[0] & 0x0F) * 4
    pkt = bytearray(packet)
    pkt[16:20] = socket.inet_aton(new_ip)
    pkt[10:12] = b'\x00\x00'
    pkt[10:12] = struct.pack('>H', _ip_checksum(bytes(pkt[:ihl])))
    return bytes(pkt)


def get_dst_ip(packet: bytes) -> Optional[str]:
    """Extract destination IP from IPv4 packet."""
    if len(packet) < 20:
        return None
    return socket.inet_ntoa(packet[16:20])


def get_src_ip(packet: bytes) -> Optional[str]:
    """Extract source IP from IPv4 packet."""
    if len(packet) < 20:
        return None
    return socket.inet_ntoa(packet[12:16])


# ============================================================
# HTP VPN GATEWAY
# ============================================================

class HTPVPNGateway:
    """HTP VPN Gateway — accepts client VPN connections and routes to internet.

    Can run on MSSP, Fortress, or any Linux machine with internet access.
    Supports multiple concurrent clients with per-client IP assignment.
    Also responds to STUN binding requests for NAT discovery.
    """

    def __init__(self, listen_port: int = DEFAULT_LISTEN_PORT,
                 wan_interface: str = "eth0",
                 max_clients: int = DEFAULT_MAX_CLIENTS,
                 bind_address: str = "0.0.0.0",
                 psk: str = ""):
        self.listen_port = listen_port
        self.wan_interface = wan_interface
        self.max_clients = max_clients
        self.bind_address = bind_address  # nosec: VPN gateway intentionally listens on all interfaces
        self.psk = psk  # Pre-shared key (device_token) — included in session key derivation

        # State
        self.sessions: Dict[int, GatewaySession] = {}        # flow_token → session
        self.pending: Dict[Tuple[str, int], PendingHandshake] = {}  # addr → pending
        self.addr_to_flow: Dict[Tuple[str, int], int] = {}   # addr → flow_token
        self.ip_to_flow: Dict[str, int] = {}                 # assigned_ip → flow_token
        self._used_ips: set = set()

        # Sockets / TUN
        self.sock: Optional[socket.socket] = None
        self.tun_fd: Optional[int] = None
        self._lock = threading.Lock()
        self._running = False

        # Rate limiting: track HELLO timestamps per source IP
        self._hello_times: Dict[str, list] = {}  # ip → [timestamps]
        self._hello_rate_limit = 5  # max HELLOs per IP per 60s

        # Stats
        self.started_at: float = 0
        self.total_sessions: int = 0

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    def start(self) -> bool:
        """Start the gateway: bind socket, create TUN, start threads."""
        if self._running:
            return True

        # Create TUN device
        if not self._create_tun():
            return False

        # Create UDP socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.bind_address, self.listen_port))
            self.sock.settimeout(0.5)
        except Exception as e:
            logger.error("Failed to bind UDP port %d: %s", self.listen_port, e)
            self._destroy_tun()
            return False

        # Set up NAT
        self._setup_nat()

        self._running = True
        self.started_at = time.time()

        # Start threads
        threading.Thread(target=self._process_loop, name="gw-recv", daemon=True).start()
        threading.Thread(target=self._tun_read_loop, name="gw-tun", daemon=True).start()
        threading.Thread(target=self._maintenance_loop, name="gw-maint", daemon=True).start()

        logger.info("HTP Gateway started on UDP :%d (TUN %s, WAN %s, max %d clients)",
                     self.listen_port, TUN_DEVICE_NAME, self.wan_interface, self.max_clients)
        return True

    def stop(self):
        """Stop the gateway and clean up."""
        if not self._running:
            return
        self._running = False
        logger.info("Stopping HTP Gateway...")

        # Send CLOSE to all clients
        for session in list(self.sessions.values()):
            self._send_close(session)

        # Clean up
        self.sessions.clear()
        self.pending.clear()
        self.addr_to_flow.clear()
        self.ip_to_flow.clear()
        self._used_ips.clear()

        self._cleanup_nat()
        self._destroy_tun()

        if self.sock:
            self.sock.close()
            self.sock = None

        logger.info("HTP Gateway stopped (served %d total sessions)", self.total_sessions)

    # =========================================================================
    # TUN DEVICE
    # =========================================================================

    def _create_tun(self) -> bool:
        """Create TUN device for routing client traffic."""
        try:
            self.tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack("16sH", TUN_DEVICE_NAME.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)

            subprocess.run(
                ["ip", "addr", "add", f"{TUN_GATEWAY_IP}/24", "dev", TUN_DEVICE_NAME],
                check=True, capture_output=True
            )
            subprocess.run(
                ["ip", "link", "set", TUN_DEVICE_NAME, "mtu", str(TUN_MTU)],
                check=True, capture_output=True
            )
            subprocess.run(
                ["ip", "link", "set", TUN_DEVICE_NAME, "up"],
                check=True, capture_output=True
            )

            logger.info("TUN device %s created (%s/24)", TUN_DEVICE_NAME, TUN_GATEWAY_IP)
            return True
        except Exception as e:
            logger.error("Failed to create TUN device: %s", e)
            return False

    def _destroy_tun(self):
        """Destroy TUN device."""
        if self.tun_fd is not None:
            try:
                os.close(self.tun_fd)
            except OSError:
                pass
            self.tun_fd = None

        try:
            subprocess.run(
                ["ip", "link", "delete", TUN_DEVICE_NAME],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    # =========================================================================
    # NAT SETUP
    # =========================================================================

    def _setup_nat(self):
        """Enable IP forwarding and NAT masquerade for VPN traffic."""
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
        except Exception as e:
            logger.warning("Could not enable IP forwarding: %s", e)

        try:
            # Check if rule exists first
            result = subprocess.run(
                ["iptables", "-t", "nat", "-C", "POSTROUTING",
                 "-s", TUN_SUBNET, "-o", self.wan_interface, "-j", "MASQUERADE"],
                capture_output=True
            )
            if result.returncode != 0:
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", "POSTROUTING",
                     "-s", TUN_SUBNET, "-o", self.wan_interface, "-j", "MASQUERADE"],
                    check=True, capture_output=True
                )
                logger.info("NAT masquerade enabled: %s → %s", TUN_SUBNET, self.wan_interface)
        except Exception as e:
            logger.error("Failed to set up NAT: %s", e)

    def _cleanup_nat(self):
        """Remove NAT rules."""
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING",
                 "-s", TUN_SUBNET, "-o", self.wan_interface, "-j", "MASQUERADE"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    # =========================================================================
    # CLIENT IP ASSIGNMENT
    # =========================================================================

    def _assign_client_ip(self) -> Optional[str]:
        """Assign a unique IP to a new client."""
        for i in range(CLIENT_IP_BASE, CLIENT_IP_BASE + self.max_clients):
            ip = f"10.250.0.{i}"
            if ip not in self._used_ips:
                self._used_ips.add(ip)
                return ip
        return None

    def _release_client_ip(self, ip: str):
        """Release a client IP back to the pool."""
        self._used_ips.discard(ip)

    # =========================================================================
    # MAIN PROCESSING LOOP
    # =========================================================================

    def _process_loop(self):
        """Main UDP receive loop — dispatches by packet type."""
        while self._running:
            try:
                try:
                    data, addr = self.sock.recvfrom(65535)
                except socket.timeout:
                    continue

                if len(data) < 3:
                    continue

                # Check for STUN (magic cookie at bytes 4-8)
                if len(data) >= 8:
                    possible_cookie = struct.unpack(">I", data[4:8])[0]
                    if possible_cookie == STUN_MAGIC_COOKIE:
                        self._handle_stun(data, addr)
                        continue

                # HTP protocol — disambiguate handshake vs data frames
                # Handshake frames start with HTP_VERSION (0x0001) + packet type
                # Data frames start with flow_token (8 bytes, random) + seq + type
                version = struct.unpack(">H", data[:2])[0]

                if version == HTP_VERSION:
                    # Handshake frame: >HB (version + type)
                    ptype = data[2]
                    if ptype == HELLO:
                        self._handle_hello(data, addr)
                    elif ptype == ATTEST:
                        self._handle_attest(data, addr)
                    else:
                        logger.debug("Unknown handshake type 0x%02x from %s", ptype, addr)
                elif len(data) >= 13:
                    # Data frame: >QIB (flow_token + sequence + type)
                    self._handle_data(data, addr)
                else:
                    logger.debug("Short packet (%d bytes) from %s", len(data), addr)

            except Exception as e:
                if self._running:
                    logger.warning("Process loop error: %s", e)

    # =========================================================================
    # HANDSHAKE
    # =========================================================================

    def _handle_hello(self, data: bytes, addr: Tuple[str, int]):
        """Handle HELLO from client — send CHALLENGE."""
        if len(data) < 75:
            logger.debug("HELLO too short (%d bytes) from %s", len(data), addr)
            return

        # Rate limit HELLOs per source IP
        src_ip = addr[0]
        now = time.time()
        times = self._hello_times.get(src_ip, [])
        times = [t for t in times if now - t < 60]
        if len(times) >= self._hello_rate_limit:
            logger.warning("HELLO rate limit exceeded from %s (%d/60s)", src_ip, len(times))
            return
        times.append(now)
        self._hello_times[src_ip] = times

        version, ptype, node_id_raw, client_nonce, flow_token = struct.unpack(
            ">HB32s32sQ", data[:75]
        )
        node_id = node_id_raw.rstrip(b"\x00").decode("utf-8", errors="replace")

        # Check capacity
        with self._lock:
            if len(self.sessions) >= self.max_clients:
                logger.warning("Rejecting %s (%s): max clients reached", node_id, addr)
                self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
                return

        # Generate challenge
        gateway_challenge = secrets.token_bytes(32)

        pending = PendingHandshake(
            node_id=node_id,
            client_nonce=client_nonce,
            gateway_challenge=gateway_challenge,
            flow_token=flow_token,
            client_addr=addr,
            created_at=time.time(),
        )

        with self._lock:
            self.pending[addr] = pending

        # Send CHALLENGE
        challenge_pkt = struct.pack(">HB", HTP_VERSION, CHALLENGE) + gateway_challenge
        self.sock.sendto(challenge_pkt, addr)
        logger.debug("CHALLENGE sent to %s (%s)", node_id, addr)

    def _handle_attest(self, data: bytes, addr: Tuple[str, int]):
        """Handle ATTEST from client — verify and establish session."""
        if len(data) < 43:
            return

        version, ptype, received_mac, flow_token = struct.unpack(">HB32sQ", data[:43])

        with self._lock:
            pending = self.pending.pop(addr, None)

        if not pending:
            logger.debug("ATTEST from %s with no pending handshake", addr)
            return

        if flow_token != pending.flow_token:
            logger.warning("ATTEST flow_token mismatch from %s", addr)
            self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
            return

        # Derive session key (must match client's derivation)
        key_material = pending.client_nonce + pending.gateway_challenge
        if self.psk:
            key_material += self.psk.encode()
        session_key = hashlib.sha256(key_material).digest()

        # Verify HMAC
        expected_mac = hmac.new(
            session_key,
            pending.client_nonce + pending.gateway_challenge,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(received_mac, expected_mac):
            logger.warning("ATTEST MAC mismatch from %s (%s)", pending.node_id, addr)
            self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
            return

        # Assign client IP
        client_ip = self._assign_client_ip()
        if not client_ip:
            logger.error("No IPs available for %s", pending.node_id)
            self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
            return

        # Create session
        now = time.time()
        session = GatewaySession(
            flow_token=flow_token,
            node_id=pending.node_id,
            session_key=session_key,
            client_addr=addr,
            assigned_ip=client_ip,
            created_at=now,
            last_activity=now,
        )

        with self._lock:
            # Remove any old session from same address
            old_flow = self.addr_to_flow.pop(addr, None)
            if old_flow and old_flow in self.sessions:
                old_session = self.sessions.pop(old_flow)
                self.ip_to_flow.pop(old_session.assigned_ip, None)
                self._release_client_ip(old_session.assigned_ip)

            self.sessions[flow_token] = session
            self.addr_to_flow[addr] = flow_token
            self.ip_to_flow[client_ip] = flow_token
            self.total_sessions += 1

        # Send ACCEPT (with assigned IP for future multi-client awareness)
        accept_pkt = struct.pack(">HB", HTP_VERSION, ACCEPT) + socket.inet_aton(client_ip)
        self.sock.sendto(accept_pkt, addr)

        logger.info("Session established: %s (%s) → %s [flow=%016x]",
                     pending.node_id, addr, client_ip, flow_token)

    # =========================================================================
    # DATA HANDLING
    # =========================================================================

    def _handle_data(self, data: bytes, addr: Tuple[str, int]):
        """Handle data frames from established sessions."""
        if len(data) < 13:
            return

        flow_token, sequence, ptype = struct.unpack(">QIB", data[:13])

        with self._lock:
            session = self.sessions.get(flow_token)

        if not session:
            return

        # Update source address if changed (NAT rebinding)
        if session.client_addr != addr:
            with self._lock:
                self.addr_to_flow.pop(session.client_addr, None)
                session.client_addr = addr
                self.addr_to_flow[addr] = flow_token

        session.last_activity = time.time()

        if ptype == IP_PACKET:
            payload = data[13:]
            ip_packet = self._decrypt_packet(payload, session.session_key)
            if ip_packet and self.tun_fd is not None:
                # Rewrite source IP from client's hardcoded 10.250.0.2 → assigned IP
                ip_packet = rewrite_src_ip(ip_packet, session.assigned_ip)
                try:
                    os.write(self.tun_fd, ip_packet)
                    session.bytes_received += len(ip_packet)
                    session.packets_received += 1
                except OSError as e:
                    logger.warning("TUN write error: %s", e)

        elif ptype == KEEPALIVE:
            # Echo keepalive back
            self.sock.sendto(data, addr)

        elif ptype == CLOSE:
            logger.info("Client %s sent CLOSE", session.node_id)
            self._remove_session(flow_token)

    def _tun_read_loop(self):
        """Read packets from TUN and route to correct client."""
        import select as sel

        while self._running and self.tun_fd is not None:
            try:
                ready, _, _ = sel.select([self.tun_fd], [], [], 1.0)
                if not ready:
                    continue

                packet = os.read(self.tun_fd, 65535)
                if not packet or len(packet) < 20:
                    continue

                # Get destination IP to find which client
                dst_ip = get_dst_ip(packet)
                if not dst_ip:
                    continue

                with self._lock:
                    flow_token = self.ip_to_flow.get(dst_ip)
                    session = self.sessions.get(flow_token) if flow_token else None

                if not session:
                    continue

                # Rewrite destination from assigned IP → 10.250.0.2 (what client expects)
                packet = rewrite_dst_ip(packet, "10.250.0.2")

                # Encrypt and send
                encrypted = self._encrypt_packet(packet, session.session_key)
                session.tx_sequence = (session.tx_sequence + 1) & 0xFFFFFFFF

                frame = struct.pack(">QIB", session.flow_token, session.tx_sequence, IP_PACKET)
                frame += encrypted

                self.sock.sendto(frame, session.client_addr)
                session.bytes_sent += len(packet)
                session.packets_sent += 1

            except OSError as e:
                if self._running:
                    logger.warning("TUN read error: %s", e)
                    break
            except Exception as e:
                if self._running:
                    logger.warning("TUN→UDP error: %s", e)

    # =========================================================================
    # ENCRYPTION
    # =========================================================================

    @staticmethod
    def _encrypt_packet(plaintext: bytes, session_key: bytes) -> bytes:
        """Encrypt IP packet with ChaCha20-Poly1305."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            nonce = secrets.token_bytes(12)
            cipher = ChaCha20Poly1305(session_key)
            ciphertext = cipher.encrypt(nonce, plaintext, None)
            return nonce + ciphertext
        except ImportError:
            logger.warning("cryptography not installed — sending unencrypted")
            return plaintext
        except Exception as e:
            logger.warning("Encrypt error: %s", e)
            return plaintext

    @staticmethod
    def _decrypt_packet(encrypted: bytes, session_key: bytes) -> Optional[bytes]:
        """Decrypt IP packet with ChaCha20-Poly1305."""
        if len(encrypted) < 28:  # 12 nonce + 16 tag minimum
            return encrypted  # Possibly unencrypted

        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            cipher = ChaCha20Poly1305(session_key)
            return cipher.decrypt(nonce, ciphertext, None)
        except ImportError:
            return encrypted
        except Exception:
            return None

    # =========================================================================
    # STUN RESPONDER
    # =========================================================================

    def _handle_stun(self, data: bytes, addr: Tuple[str, int]):
        """Respond to STUN Binding Request with client's public IP:port."""
        if len(data) < 20:
            return

        msg_type = struct.unpack(">H", data[:2])[0]
        if msg_type != STUN_BINDING_REQUEST:
            return

        txn_id = data[8:20]  # 12-byte transaction ID

        # Build XOR-MAPPED-ADDRESS attribute
        xport = addr[1] ^ (STUN_MAGIC_COOKIE >> 16)
        xaddr = struct.unpack(">I", socket.inet_aton(addr[0]))[0] ^ STUN_MAGIC_COOKIE
        xma_value = struct.pack(">BBH I", 0, 0x01, xport, xaddr)  # family=IPv4

        # Build SOFTWARE attribute
        sw_value = b"HookProbe-Gateway/1.0"
        sw_pad = (4 - len(sw_value) % 4) % 4

        # Attributes
        attrs = struct.pack(">HH", STUN_ATTR_XOR_MAPPED_ADDRESS, len(xma_value)) + xma_value
        attrs += struct.pack(">HH", STUN_ATTR_SOFTWARE, len(sw_value)) + sw_value + b"\x00" * sw_pad

        # STUN response header
        header = struct.pack(">HHI", STUN_BINDING_RESPONSE, len(attrs), STUN_MAGIC_COOKIE)
        response = header + txn_id + attrs

        self.sock.sendto(response, addr)
        logger.debug("STUN response to %s:%d", addr[0], addr[1])

    # =========================================================================
    # SESSION MANAGEMENT
    # =========================================================================

    def _send_close(self, session: GatewaySession):
        """Send CLOSE frame to client."""
        try:
            close_frame = struct.pack(">QIB", session.flow_token, 0, CLOSE)
            self.sock.sendto(close_frame, session.client_addr)
        except Exception:
            pass

    def _remove_session(self, flow_token: int):
        """Remove a session and free resources."""
        with self._lock:
            session = self.sessions.pop(flow_token, None)
            if session:
                self.addr_to_flow.pop(session.client_addr, None)
                self.ip_to_flow.pop(session.assigned_ip, None)
                self._release_client_ip(session.assigned_ip)
                logger.info("Session removed: %s (%s) [%d pkts, %.1f KB]",
                            session.node_id, session.assigned_ip,
                            session.packets_sent + session.packets_received,
                            (session.bytes_sent + session.bytes_received) / 1024)

    def _maintenance_loop(self):
        """Periodic cleanup of expired sessions and pending handshakes."""
        while self._running:
            time.sleep(MAINTENANCE_INTERVAL)
            now = time.time()

            # Expire dead sessions
            expired = []
            with self._lock:
                for flow_token, session in self.sessions.items():
                    if now - session.last_activity > SESSION_TIMEOUT:
                        expired.append(flow_token)

            for flow_token in expired:
                session = self.sessions.get(flow_token)
                if session:
                    logger.info("Session timeout: %s (%.0fs idle)",
                                session.node_id, now - session.last_activity)
                    self._send_close(session)
                    self._remove_session(flow_token)

            # Expire stale pending handshakes
            stale = []
            with self._lock:
                for addr, pending in self.pending.items():
                    if now - pending.created_at > HANDSHAKE_TIMEOUT:
                        stale.append(addr)
                for addr in stale:
                    self.pending.pop(addr, None)

    # =========================================================================
    # STATUS
    # =========================================================================

    def get_status(self) -> dict:
        """Get gateway status for monitoring."""
        with self._lock:
            sessions_info = []
            for s in self.sessions.values():
                sessions_info.append({
                    "node_id": s.node_id,
                    "addr": f"{s.client_addr[0]}:{s.client_addr[1]}",
                    "assigned_ip": s.assigned_ip,
                    "uptime_s": int(time.time() - s.created_at),
                    "bytes_sent": s.bytes_sent,
                    "bytes_received": s.bytes_received,
                })

        return {
            "running": self._running,
            "listen_port": self.listen_port,
            "wan_interface": self.wan_interface,
            "uptime_s": int(time.time() - self.started_at) if self.started_at else 0,
            "active_sessions": len(sessions_info),
            "max_clients": self.max_clients,
            "total_sessions": self.total_sessions,
            "sessions": sessions_info,
        }


# ============================================================
# CLI ENTRY POINT
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="HookProbe HTP VPN Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Accepts HTP VPN connections and routes traffic to internet.\n"
               "Deploy on MSSP, Fortress, or any machine with internet access.",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT,
                        help=f"UDP listen port (default: {DEFAULT_LISTEN_PORT})")
    parser.add_argument("--wan", default="eth0",
                        help="WAN interface for NAT masquerade (default: eth0)")
    parser.add_argument("--max-clients", type=int, default=DEFAULT_MAX_CLIENTS,
                        help=f"Maximum concurrent VPN clients (default: {DEFAULT_MAX_CLIENTS})")
    parser.add_argument("--bind", default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--psk", default="",
                        help="Pre-shared key (device_token) for client authentication")
    parser.add_argument("--psk-file", default="",
                        help="File containing pre-shared key (one line, stripped)")
    parser.add_argument("--config", help="Config file path (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    parser.add_argument("--status", action="store_true",
                        help="Print status and exit (requires running gateway)")

    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Load config file if specified
    port = args.port
    wan = args.wan
    max_clients = args.max_clients
    bind_addr = args.bind

    # Resolve PSK
    psk = args.psk
    if args.psk_file:
        try:
            psk = Path(args.psk_file).read_text().strip()
        except Exception as e:
            logger.error("Failed to read PSK file %s: %s", args.psk_file, e)
            sys.exit(1)

    if args.config:
        try:
            conf = json.loads(Path(args.config).read_text())
            port = conf.get("port", port)
            wan = conf.get("wan_interface", wan)
            max_clients = conf.get("max_clients", max_clients)
            bind_addr = conf.get("bind_address", bind_addr)
            if not psk:
                psk = conf.get("psk", "")
        except Exception as e:
            logger.error("Failed to load config %s: %s", args.config, e)
            sys.exit(1)

    # Check root
    if os.geteuid() != 0:
        logger.error("Gateway requires root for TUN device and iptables")
        sys.exit(1)

    if psk:
        logger.info("PSK authentication enabled")
    else:
        logger.warning("No PSK configured — any client can connect (use --psk or --psk-file)")

    # Create and start gateway
    gateway = HTPVPNGateway(
        listen_port=port,
        wan_interface=wan,
        max_clients=max_clients,
        bind_address=bind_addr,
        psk=psk,
    )

    # Signal handling
    def shutdown(signum, frame):
        logger.info("Signal %d received, shutting down...", signum)
        gateway.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    if not gateway.start():
        logger.error("Gateway failed to start")
        sys.exit(1)

    # Keep main thread alive
    try:
        while gateway._running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        gateway.stop()


if __name__ == "__main__":
    main()
