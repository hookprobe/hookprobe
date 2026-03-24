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
REKEY = 0x18
REKEY_ACK = 0x19

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
TCP_PROXY_PORT = 19999  # Transparent TCP proxy port (iptables REDIRECT target)

# Timing
KEEPALIVE_INTERVAL = 25
SESSION_TIMEOUT = 75  # 3 × keepalive
HANDSHAKE_TIMEOUT = 30  # Pending handshake expiry
MAINTENANCE_INTERVAL = 15
REKEY_INTERVAL = 300  # Rekey sessions every 5 minutes
OLD_KEY_TTL = 10  # Keep old key valid for 10s after rekey

# STUN (RFC 5389)
STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_SOFTWARE = 0x8022

# HKDF context strings (must match client)
HKDF_SALT_SESSION = b"htp-vpn-session-salt-v2"
HKDF_INFO_SESSION = b"htp-vpn-session-key-v2"
HKDF_SALT_REKEY = b"htp-vpn-rekey-salt-v2"
HKDF_INFO_REKEY = b"htp-vpn-rekey-v2"

# ATTEST rate limiting
ATTEST_MAX_FAILURES = 3
ATTEST_BLOCK_DURATION = 300  # 5 minutes

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
    # Rekey state
    old_session_key: Optional[bytes] = None
    old_key_expires: float = 0
    last_rekey: float = 0
    rekey_pending_nonce: Optional[bytes] = None


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
        self.node_to_flow: Dict[str, int] = {}              # node_id → flow_token
        self._used_ips: set = set()

        # Sockets / TUN
        self.sock: Optional[socket.socket] = None
        self.tun_fd: Optional[int] = None
        self._lock = threading.Lock()
        self._running = False

        # Rate limiting: track HELLO timestamps per source IP
        self._hello_times: Dict[str, list] = {}  # ip → [timestamps]
        self._hello_rate_limit = 5  # max HELLOs per IP per 60s

        # ATTEST failure rate limiting: ip → [failure_timestamps]
        self._attest_failures: Dict[str, list] = {}

        # Ed25519 server identity key (persistent across restarts)
        self._signing_key, self._verify_key_bytes = self._load_or_create_identity()

        # Stats
        self.started_at: float = 0
        self.total_sessions: int = 0

    # =========================================================================
    # CRYPTOGRAPHIC HELPERS
    # =========================================================================

    @staticmethod
    def _load_or_create_identity():
        """Load or create Ed25519 signing key for server identity verification."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        key_path = Path("/opt/hookprobe/mesh/data/gateway_ed25519.key")
        pub_path = Path("/opt/hookprobe/mesh/data/gateway_ed25519.pub")

        try:
            if key_path.exists():
                key_data = key_path.read_bytes()
                signing_key = serialization.load_pem_private_key(key_data, password=None)
                pub_bytes = signing_key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                logger.info("Loaded Ed25519 identity key from %s", key_path)
                return signing_key, pub_bytes
        except Exception as e:
            logger.warning("Failed to load identity key: %s (generating new)", e)

        # Generate new keypair
        signing_key = Ed25519PrivateKey.generate()
        pub_bytes = signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            key_path.chmod(0o600)
            pub_path.write_bytes(pub_bytes)
            logger.info("Generated new Ed25519 identity key → %s", key_path)
            logger.info("Server public key (hex): %s", pub_bytes.hex())
        except Exception as e:
            logger.warning("Could not persist identity key: %s", e)

        return signing_key, pub_bytes

    @staticmethod
    def _hkdf_derive(ikm: bytes, salt: bytes, info: bytes) -> bytes:
        """Derive a 32-byte key using HKDF-SHA256."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(ikm)

    def _is_attest_blocked(self, ip: str) -> bool:
        """Check if IP is blocked due to ATTEST failures."""
        failures = self._attest_failures.get(ip, [])
        now = time.time()
        # Clean old failures
        failures = [t for t in failures if now - t < ATTEST_BLOCK_DURATION]
        self._attest_failures[ip] = failures
        return len(failures) >= ATTEST_MAX_FAILURES

    def _record_attest_failure(self, ip: str):
        """Record a failed ATTEST attempt."""
        if ip not in self._attest_failures:
            self._attest_failures[ip] = []
        self._attest_failures[ip].append(time.time())

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
        threading.Thread(target=self._tcp_proxy_loop, name="gw-tcpproxy", daemon=True).start()

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
        self.node_to_flow.clear()
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
        """Enable IP forwarding, FORWARD rules, and NAT masquerade for VPN traffic."""
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
        except Exception as e:
            logger.warning("Could not enable IP forwarding: %s", e)

        # Disable reverse path filter on TUN (packets arrive with VPN-subnet src)
        for sysctl_path in [
            f"/proc/sys/net/ipv4/conf/{TUN_DEVICE_NAME}/rp_filter",
            "/proc/sys/net/ipv4/conf/all/rp_filter",
        ]:
            try:
                Path(sysctl_path).write_text("0")
            except Exception:
                pass

        # Explicit FORWARD rules (required in container environments where
        # the default FORWARD policy may be DROP or restrictive)
        for fwd_rule in [
            ["-i", TUN_DEVICE_NAME, "-o", self.wan_interface, "-j", "ACCEPT"],
            ["-i", self.wan_interface, "-o", TUN_DEVICE_NAME,
             "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]:
            try:
                chk = subprocess.run(
                    ["iptables", "-C", "FORWARD"] + fwd_rule, capture_output=True
                )
                if chk.returncode != 0:
                    subprocess.run(
                        ["iptables", "-A", "FORWARD"] + fwd_rule,
                        check=True, capture_output=True
                    )
            except Exception as e:
                logger.warning("FORWARD rule setup failed: %s", e)

        try:
            # Check if MASQUERADE rule exists first
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

        # Transparent TCP proxy: REDIRECT all TCP from TUN to local proxy port.
        # PREROUTING nat works in rootless podman (unlike POSTROUTING).
        # The proxy uses SO_ORIGINAL_DST to find the real destination.
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "PREROUTING",
                 "-i", TUN_DEVICE_NAME, "-p", "tcp",
                 "-j", "REDIRECT", "--to-port", str(TCP_PROXY_PORT)],
                check=True, capture_output=True
            )
            logger.info("TCP transparent proxy: TUN TCP → localhost:%d", TCP_PROXY_PORT)
        except Exception as e:
            logger.warning("TCP REDIRECT setup failed: %s", e)

    def _cleanup_nat(self):
        """Remove NAT and FORWARD rules."""
        for fwd_rule in [
            ["-i", TUN_DEVICE_NAME, "-o", self.wan_interface, "-j", "ACCEPT"],
            ["-i", self.wan_interface, "-o", TUN_DEVICE_NAME,
             "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]:
            try:
                subprocess.run(
                    ["iptables", "-D", "FORWARD"] + fwd_rule,
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
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

        # Send CHALLENGE with Ed25519 signature for server identity verification
        # Format: version(2) + type(1) + challenge(32) + pubkey(32) + signature(64) = 131 bytes
        challenge_payload = gateway_challenge
        try:
            sig = self._signing_key.sign(gateway_challenge + pending.client_nonce)
            challenge_pkt = struct.pack(">HB", HTP_VERSION, CHALLENGE) + challenge_payload
            challenge_pkt += self._verify_key_bytes + sig
        except Exception as e:
            logger.error("Ed25519 signing failed: %s — rejecting %s", e, node_id)
            with self._lock:
                self.pending.pop(addr, None)
            self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
            return
        self.sock.sendto(challenge_pkt, addr)
        logger.debug("CHALLENGE sent to %s (%s)", node_id, addr)

    def _handle_attest(self, data: bytes, addr: Tuple[str, int]):
        """Handle ATTEST from client — verify and establish session."""
        if len(data) < 43:
            return

        # Check ATTEST rate limiting
        src_ip = addr[0]
        if self._is_attest_blocked(src_ip):
            logger.warning("ATTEST blocked (rate limited) from %s", src_ip)
            return

        version, ptype, received_mac, flow_token = struct.unpack(">HB32sQ", data[:43])

        with self._lock:
            pending = self.pending.pop(addr, None)

        if not pending:
            logger.debug("ATTEST from %s with no pending handshake", addr)
            return

        if flow_token != pending.flow_token:
            logger.warning("ATTEST flow_token mismatch from %s", addr)
            self._record_attest_failure(src_ip)
            self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
            return

        # Derive session key using HKDF-SHA256 (must match client's derivation)
        # IKM includes both nonces + PSK; salt is a constant (independent of IKM per RFC 5869)
        # Localhost (bridge) connections skip PSK — they're internal to the container.
        is_localhost = (src_ip in ('127.0.0.1', '::1'))
        ikm = pending.client_nonce + pending.gateway_challenge
        if self.psk and not is_localhost:
            ikm += self.psk.encode()
        session_key = self._hkdf_derive(ikm, HKDF_SALT_SESSION, HKDF_INFO_SESSION)

        # Verify HMAC
        expected_mac = hmac.new(
            session_key,
            pending.client_nonce + pending.gateway_challenge,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(received_mac, expected_mac):
            # If PSK mismatch, try without PSK for backwards compatibility
            if self.psk and not is_localhost:
                ikm_nopsk = pending.client_nonce + pending.gateway_challenge
                session_key_nopsk = self._hkdf_derive(ikm_nopsk, HKDF_SALT_SESSION, HKDF_INFO_SESSION)
                expected_nopsk = hmac.new(
                    session_key_nopsk,
                    pending.client_nonce + pending.gateway_challenge,
                    hashlib.sha256,
                ).digest()
                if hmac.compare_digest(received_mac, expected_nopsk):
                    logger.warning("ATTEST from %s matched WITHOUT PSK — using no-PSK session", pending.node_id)
                    session_key = session_key_nopsk
                else:
                    logger.warning("ATTEST MAC mismatch from %s (%s)", pending.node_id, addr)
                    self._record_attest_failure(src_ip)
                    self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
                    return
            else:
                logger.warning("ATTEST MAC mismatch from %s (%s)", pending.node_id, addr)
                self._record_attest_failure(src_ip)
                self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
            return

        # Single atomic lock block: evict stale sessions, assign IP, register
        # — prevents IP pool race and capacity TOCTOU under concurrent handshakes.
        with self._lock:
            # Evict existing session from the same node_id (reconnect)
            old_flow = self.node_to_flow.get(pending.node_id)
            if old_flow and old_flow in self.sessions:
                old_session = self.sessions.pop(old_flow)
                self.addr_to_flow.pop(old_session.client_addr, None)
                self.ip_to_flow.pop(old_session.assigned_ip, None)
                self.node_to_flow.pop(old_session.node_id, None)
                self._release_client_ip(old_session.assigned_ip)
                logger.info("Evicted stale session for %s (%s) on reconnect",
                            old_session.node_id, old_session.assigned_ip)

            # Remove any old session from same address (NAT rebinding)
            old_addr_flow = self.addr_to_flow.pop(addr, None)
            if old_addr_flow and old_addr_flow in self.sessions:
                old_session = self.sessions.pop(old_addr_flow)
                self.ip_to_flow.pop(old_session.assigned_ip, None)
                self.node_to_flow.pop(old_session.node_id, None)
                self._release_client_ip(old_session.assigned_ip)

            # Capacity check (accurate inside lock)
            if len(self.sessions) >= self.max_clients:
                logger.error("Max clients reached (%d), rejecting %s",
                             self.max_clients, pending.node_id)
                self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
                return

            # Assign client IP (inside lock — prevents duplicate assignment)
            client_ip = self._assign_client_ip()
            if not client_ip:
                logger.error("No IPs available for %s", pending.node_id)
                self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
                return

            # Guard against flow_token collision from different clients
            if flow_token in self.sessions and self.sessions[flow_token].client_addr != addr:
                logger.warning("Flow token collision from %s (existing: %s)",
                               addr, self.sessions[flow_token].client_addr)
                self._release_client_ip(client_ip)
                self.sock.sendto(struct.pack(">HB", HTP_VERSION, REJECT), addr)
                return

            # Create and register session
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
            self.sessions[flow_token] = session
            self.addr_to_flow[addr] = flow_token
            self.ip_to_flow[client_ip] = flow_token
            self.node_to_flow[pending.node_id] = flow_token
            self.total_sessions += 1

        # Send ACCEPT outside lock (with assigned IP)
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
            ip_packet = self._decrypt_with_fallback(payload, session)
            if not ip_packet or self.tun_fd is None:
                pass
            elif len(ip_packet) < 20 or (ip_packet[0] >> 4) != 4:
                # Drop non-IPv4 (IPv6, malformed) — only IPv4 tunneling supported
                logger.debug("Dropped non-IPv4 packet (ver=%d) from %s",
                             ip_packet[0] >> 4 if ip_packet else 0, session.node_id)
            else:
                # Rewrite source IP from client's local TUN IP → assigned IP.
                # EXCEPT for bridge sessions (hsg-bridge): the bridge forwards
                # iPhone packets with their original VPN IP (10.250.0.128+).
                # Rewriting would change it to the bridge's IP (10.250.0.2),
                # breaking the reverse path (responses can't route back).
                is_bridge = (session.node_id == "hsg-bridge")
                if not is_bridge:
                    ip_packet = rewrite_src_ip(ip_packet, session.assigned_ip)
                else:
                    # Bridge forwards packets from multiple iPhones. Register
                    # each iPhone's VPN IP so mesh relay can find them.
                    src = get_src_ip(ip_packet)
                    if src and src.startswith("10.250.0.") and src != session.assigned_ip:
                        with self._lock:
                            if src not in self.ip_to_flow:
                                self.ip_to_flow[src] = flow_token
                                logger.info("Registered bridge client %s → bridge session", src)

                # Mesh relay: allow client-to-client routing for mesh peers
                # (iPhone → Fortress/Guardian). Forward directly without TUN roundtrip.
                dst = get_dst_ip(ip_packet)
                if dst and dst.startswith("10.250.0.") and dst != TUN_GATEWAY_IP and dst != session.assigned_ip:
                    # Snapshot mutable dst_session state under lock to avoid races
                    dst_key = None
                    dst_addr = None
                    dst_flow_token = 0
                    dst_seq = 0
                    with self._lock:
                        dst_flow = self.ip_to_flow.get(dst)
                        dst_session = self.sessions.get(dst_flow) if dst_flow else None
                        if dst_session:
                            dst_key = dst_session.session_key
                            dst_addr = dst_session.client_addr
                            dst_flow_token = dst_session.flow_token
                            dst_session.tx_sequence = (dst_session.tx_sequence + 1) & 0xFFFFFFFF
                            dst_seq = dst_session.tx_sequence
                            dst_session.bytes_sent += len(ip_packet)
                            dst_session.packets_sent += 1
                            dst_session.last_activity = time.time()
                            session.bytes_received += len(ip_packet)
                            session.packets_received += 1
                    # Encrypt and send outside lock (crypto is the slow path)
                    if dst_key:
                        encrypted = self._encrypt_packet(ip_packet, dst_key)
                        if encrypted:
                            frame = struct.pack(">QIB", dst_flow_token, dst_seq, IP_PACKET)
                            frame += encrypted
                            self.sock.sendto(frame, dst_addr)
                            logger.debug("Mesh relay %s→%s", session.assigned_ip, dst)
                        else:
                            logger.debug("Mesh relay encrypt failed %s→%s", session.assigned_ip, dst)
                    else:
                        logger.debug("No peer for mesh relay %s→%s", session.assigned_ip, dst)
                else:
                    # Userspace forwarding: rootless podman NAT doesn't work
                    # for forwarded packets, so proxy UDP/TCP via container sockets.
                    forwarded = self._userspace_forward(ip_packet, session)
                    if not forwarded:
                        # Fallback to TUN device
                        try:
                            os.write(self.tun_fd, ip_packet)
                        except OSError as e:
                            logger.debug("TUN write error: %s", e)
                    session.bytes_received += len(ip_packet)
                    session.packets_received += 1

        elif ptype == KEEPALIVE:
            # Echo keepalive back
            self.sock.sendto(data, addr)

        elif ptype == CLOSE:
            logger.info("Client %s sent CLOSE", session.node_id)
            self._remove_session(flow_token)

        elif ptype == REKEY_ACK:
            self._handle_rekey_ack(data[13:], session)

    # =========================================================================
    # SESSION REKEYING (Forward Secrecy)
    # =========================================================================

    def _initiate_rekey(self, session: GatewaySession):
        """Send REKEY to client with fresh nonce for key rotation."""
        rekey_nonce = secrets.token_bytes(32)
        session.rekey_pending_nonce = rekey_nonce

        # Encrypt the rekey nonce with current session key
        encrypted_nonce = self._encrypt_packet(rekey_nonce, session.session_key)

        session.tx_sequence = (session.tx_sequence + 1) & 0xFFFFFFFF
        frame = struct.pack(">QIB", session.flow_token, session.tx_sequence, REKEY)
        frame += encrypted_nonce

        try:
            self.sock.sendto(frame, session.client_addr)
            logger.info("REKEY sent to %s", session.node_id)
        except Exception as e:
            logger.warning("REKEY send failed to %s: %s", session.node_id, e)
            session.rekey_pending_nonce = None

    def _handle_rekey_ack(self, payload: bytes, session: GatewaySession):
        """Handle REKEY_ACK — client proved it derived the new key."""
        if not session.rekey_pending_nonce:
            logger.debug("REKEY_ACK from %s with no pending rekey", session.node_id)
            return

        # Derive the new key using HKDF (same derivation as client)
        new_key = self._hkdf_derive(
            ikm=session.session_key + session.rekey_pending_nonce,
            salt=HKDF_SALT_REKEY,
            info=HKDF_INFO_REKEY,
        )

        # Verify: decrypt the ACK payload with the new key
        # Client sends the rekey_nonce encrypted with the new key as proof
        proof = self._decrypt_packet(payload, new_key)
        if not proof or proof != session.rekey_pending_nonce:
            logger.warning("REKEY_ACK verification failed from %s", session.node_id)
            session.rekey_pending_nonce = None
            return

        # Commit key rotation
        session.old_session_key = session.session_key
        session.old_key_expires = time.time() + OLD_KEY_TTL
        session.session_key = new_key
        session.last_rekey = time.time()
        session.rekey_pending_nonce = None
        logger.info("REKEY complete for %s (forward secrecy)", session.node_id)

    def _userspace_forward(self, ip_packet: bytes, session: GatewaySession) -> bool:
        """Userspace UDP/TCP proxy — bypasses broken kernel NAT in rootless podman.

        UDP flows use persistent sockets (same source port) to support QUIC.
        TCP connections use per-connection proxy threads.
        Non-blocking: the main receive loop is NOT blocked.
        """
        if len(ip_packet) < 20:
            return False

        ihl = (ip_packet[0] & 0x0F) * 4
        protocol = ip_packet[9]

        src_ip = socket.inet_ntoa(ip_packet[12:16])
        dst_ip = socket.inet_ntoa(ip_packet[16:20])

        if protocol == 17 and len(ip_packet) >= ihl + 8:  # UDP
            src_port = struct.unpack(">H", ip_packet[ihl:ihl + 2])[0]
            dst_port = struct.unpack(">H", ip_packet[ihl + 2:ihl + 4])[0]
            payload = ip_packet[ihl + 8:]

            # Persistent flow key: reuse same proxy socket for QUIC connections
            flow_key = (src_ip, src_port, dst_ip, dst_port)

            with self._lock:
                if not hasattr(self, '_udp_flows'):
                    self._udp_flows = {}
                flow = self._udp_flows.get(flow_key)

            if flow:
                # Existing flow — send on existing socket (non-blocking)
                try:
                    flow['sock'].sendto(payload, (dst_ip, dst_port))
                    flow['last_activity'] = time.time()
                except Exception:
                    # Socket died — remove and let it be recreated
                    with self._lock:
                        self._udp_flows.pop(flow_key, None)
                    try:
                        flow['sock'].close()
                    except Exception:
                        pass
            else:
                # New flow — create persistent socket + reader thread
                t = threading.Thread(
                    target=self._udp_flow_thread,
                    args=(flow_key, src_ip, src_port, dst_ip, dst_port, payload, session),
                    daemon=True,
                )
                t.start()
            return True

        if protocol == 6:  # TCP — handled by iptables REDIRECT + transparent proxy
            # TCP goes to TUN → PREROUTING REDIRECT → local transparent proxy
            # The proxy handles SO_ORIGINAL_DST to find the real destination
            return False  # Let TUN + iptables handle it

        if protocol == 1 and len(ip_packet) >= ihl + 8:  # ICMP
            icmp_type = ip_packet[ihl]
            if icmp_type == 8:  # Echo Request (ping)
                t = threading.Thread(
                    target=self._icmp_proxy_thread,
                    args=(src_ip, dst_ip, ip_packet[ihl:], session),
                    daemon=True,
                )
                t.start()
                return True

        # TCP: write to TUN device (kernel handles routing for direct clients)
        return False

    def _udp_flow_thread(self, flow_key, src_ip, src_port, dst_ip, dst_port,
                         initial_payload, session):
        """Persistent UDP flow thread — maintains a single socket for the flow's lifetime.
        Supports QUIC which requires consistent source port across packets."""
        proxy_sock = None
        try:
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            proxy_sock.settimeout(1.0)  # Short timeout for responsive read loop

            # Register flow so subsequent packets reuse this socket
            flow_entry = {'sock': proxy_sock, 'last_activity': time.time()}
            with self._lock:
                if not hasattr(self, '_udp_flows'):
                    self._udp_flows = {}
                self._udp_flows[flow_key] = flow_entry

            # Send initial packet
            proxy_sock.sendto(initial_payload, (dst_ip, dst_port))

            # Read loop — receive responses and send back to client
            idle_count = 0
            while self._running and idle_count < 30:  # 30s idle timeout
                try:
                    resp_data, _ = proxy_sock.recvfrom(65535)
                    idle_count = 0  # Reset idle counter on data

                    resp_pkt = self._build_udp_response(
                        dst_ip, src_ip, dst_port, src_port, resp_data
                    )
                    if resp_pkt:
                        self._send_to_client(resp_pkt, session)
                except socket.timeout:
                    idle_count += 1
                    # Check if flow is still active
                    if time.time() - flow_entry['last_activity'] > 30:
                        break
                except Exception:
                    break

        except Exception as e:
            logger.debug("UDP flow %s:%d→%s:%d: %s",
                         src_ip, src_port, dst_ip, dst_port, e)
        finally:
            with self._lock:
                if hasattr(self, '_udp_flows'):
                    self._udp_flows.pop(flow_key, None)
            if proxy_sock:
                try:
                    proxy_sock.close()
                except Exception:
                    pass

    def _build_udp_response(self, src_ip: str, dst_ip: str,
                            src_port: int, dst_port: int,
                            payload: bytes) -> Optional[bytes]:
        """Build an IPv4+UDP packet for a response."""
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack(">HHHH", src_port, dst_port, udp_len, 0)  # checksum=0

        # IPv4 header (20 bytes, no options)
        total_len = 20 + udp_len
        ip_hdr = bytearray(20)
        ip_hdr[0] = 0x45  # version=4, ihl=5
        struct.pack_into(">H", ip_hdr, 2, total_len)
        ip_hdr[8] = 64  # TTL
        ip_hdr[9] = 17  # Protocol = UDP
        ip_hdr[12:16] = socket.inet_aton(src_ip)
        ip_hdr[16:20] = socket.inet_aton(dst_ip)
        # Checksum
        ip_hdr[10:12] = b'\x00\x00'
        ip_hdr[10:12] = struct.pack('>H', _ip_checksum(bytes(ip_hdr)))

        return bytes(ip_hdr) + udp_hdr + payload

    def _send_to_client(self, ip_packet: bytes, session: GatewaySession):
        """Send an IP packet back to a VPN client via HTP."""
        encrypted = self._encrypt_packet(ip_packet, session.session_key)
        if not encrypted:
            return
        with self._lock:
            session.tx_sequence = (session.tx_sequence + 1) & 0xFFFFFFFF
            seq = session.tx_sequence
            addr = session.client_addr
            ft = session.flow_token
            session.bytes_sent += len(ip_packet)
            session.packets_sent += 1

        frame = struct.pack(">QIB", ft, seq, IP_PACKET)
        frame += encrypted
        self.sock.sendto(frame, addr)

    def _icmp_proxy_thread(self, src_ip, dst_ip, icmp_payload, session):
        """Thread worker: forward ICMP echo request and return reply."""
        try:
            # Use raw ICMP socket to send ping and get reply
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            icmp_sock.settimeout(3.0)

            # Send the ICMP echo request payload as-is
            icmp_sock.sendto(icmp_payload, (dst_ip, 0))

            # Receive ICMP echo reply
            reply_data, reply_addr = icmp_sock.recvfrom(65535)
            icmp_sock.close()

            # Build response IP packet: src=dst_ip, dst=src_ip
            total_len = 20 + len(reply_data)
            ip_hdr = bytearray(20)
            ip_hdr[0] = 0x45
            struct.pack_into(">H", ip_hdr, 2, total_len)
            ip_hdr[8] = 64   # TTL
            ip_hdr[9] = 1    # ICMP
            ip_hdr[12:16] = socket.inet_aton(dst_ip)
            ip_hdr[16:20] = socket.inet_aton(src_ip)
            ip_hdr[10:12] = b'\x00\x00'
            ip_hdr[10:12] = struct.pack('>H', _ip_checksum(bytes(ip_hdr)))

            resp_pkt = bytes(ip_hdr) + reply_data
            self._send_to_client(resp_pkt, session)
            logger.debug("ICMP echo %s→%s OK", src_ip, dst_ip)
        except Exception as e:
            logger.debug("ICMP echo %s→%s: %s", src_ip, dst_ip, e)

    def _tcp_proxy_loop(self):
        """Transparent TCP proxy — accepts redirected connections from iptables PREROUTING.

        Uses SO_ORIGINAL_DST to recover the real destination before REDIRECT,
        connects to it via the container's own IP, and relays data bidirectionally.
        This bypasses the broken POSTROUTING NAT in rootless podman.
        """
        SO_ORIGINAL_DST = 80  # Linux-specific getsockopt for original destination

        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(1.0)
            srv.bind(('0.0.0.0', TCP_PROXY_PORT))
            srv.listen(128)
            logger.info("TCP transparent proxy listening on :%d", TCP_PROXY_PORT)
        except Exception as e:
            logger.error("TCP proxy bind failed: %s", e)
            return

        while self._running:
            try:
                client_sock, client_addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                continue

            # Get original destination via SO_ORIGINAL_DST
            try:
                dst_raw = client_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                dst_port = struct.unpack(">H", dst_raw[2:4])[0]
                dst_ip = socket.inet_ntoa(dst_raw[4:8])
            except Exception as e:
                logger.debug("TCP proxy: SO_ORIGINAL_DST failed: %s", e)
                client_sock.close()
                continue

            # Skip if destination is ourselves (redirect loop)
            if dst_port == TCP_PROXY_PORT:
                client_sock.close()
                continue

            threading.Thread(
                target=self._tcp_relay,
                args=(client_sock, dst_ip, dst_port),
                daemon=True,
            ).start()

        srv.close()

    def _tcp_relay(self, client_sock, dst_ip, dst_port):
        """Relay data between client and destination."""
        import select as sel
        server_sock = None
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.settimeout(10.0)
            server_sock.connect((dst_ip, dst_port))
            server_sock.settimeout(None)
            client_sock.settimeout(None)

            logger.debug("TCP relay %s:%d established", dst_ip, dst_port)

            while self._running:
                readable, _, _ = sel.select([client_sock, server_sock], [], [], 30.0)
                if not readable:
                    break  # Idle timeout

                for sock in readable:
                    try:
                        data = sock.recv(65536)
                    except Exception:
                        data = b''
                    if not data:
                        return  # Connection closed
                    target = server_sock if sock is client_sock else client_sock
                    try:
                        target.sendall(data)
                    except Exception:
                        return
        except Exception as e:
            logger.debug("TCP relay %s:%d: %s", dst_ip, dst_port, e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            if server_sock:
                try:
                    server_sock.close()
                except Exception:
                    pass

    def _decrypt_with_fallback(
        self, encrypted: bytes, session: GatewaySession,
    ) -> Optional[bytes]:
        """Decrypt trying current key first, then old key if in grace period."""
        result = self._decrypt_packet(encrypted, session.session_key)
        if result is not None:
            return result
        # Try old key during grace period
        if (session.old_session_key
                and time.time() < session.old_key_expires):
            return self._decrypt_packet(encrypted, session.old_session_key)
        return None

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

                # Only process IPv4 packets
                if (packet[0] >> 4) != 4:
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

                # Rewrite destination to client's assigned IP — EXCEPT for bridge
                # sessions where the original dst IP (10.250.0.128) must be preserved
                # so synapseFromHTPlayer can find the correct iPhone ESP session.
                if session.node_id != "hsg-bridge":
                    packet = rewrite_dst_ip(packet, session.assigned_ip)

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
            raise RuntimeError("cryptography package required for VPN encryption")
        except Exception as e:
            logger.warning("Encrypt error: %s", e)
            return None

    @staticmethod
    def _decrypt_packet(encrypted: bytes, session_key: bytes) -> Optional[bytes]:
        """Decrypt IP packet with ChaCha20-Poly1305."""
        if len(encrypted) < 28:  # 12 nonce + 16 tag minimum
            return None  # Too short for valid ciphertext

        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            cipher = ChaCha20Poly1305(session_key)
            return cipher.decrypt(nonce, ciphertext, None)
        except ImportError:
            raise RuntimeError("cryptography package required for VPN encryption")
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
                self.node_to_flow.pop(session.node_id, None)
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

            # Initiate rekey for sessions due for rotation
            with self._lock:
                rekey_candidates = [
                    s for s in self.sessions.values()
                    if (now - (s.last_rekey or s.created_at) > REKEY_INTERVAL
                        and not s.rekey_pending_nonce)
                ]
            for session in rekey_candidates:
                with self._lock:
                    if not session.rekey_pending_nonce:  # re-check under lock
                        self._initiate_rekey(session)

            # Expire old keys past their TTL
            with self._lock:
                for session in self.sessions.values():
                    if (session.old_session_key
                            and now > session.old_key_expires):
                        session.old_session_key = None

            # Prune stale rate-limit entries to prevent unbounded dict growth
            cutoff_hello = now - 60
            cutoff_attest = now - ATTEST_BLOCK_DURATION
            self._hello_times = {
                ip: ts for ip, ts in self._hello_times.items()
                if any(t > cutoff_hello for t in ts)
            }
            self._attest_failures = {
                ip: ts for ip, ts in self._attest_failures.items()
                if any(t > cutoff_attest for t in ts)
            }

            # Write status file for mesh_server.py dashboard integration
            self._write_status_file()

    # =========================================================================
    # STATUS
    # =========================================================================

    _STATUS_FILE = "/tmp/htp_gateway_status.json"

    def _write_status_file(self):
        """Write compact status to a file for mesh_server.py to read."""
        try:
            with self._lock:
                client_count = len(self.sessions)
            status = {
                "active": self._running,
                "clients": client_count,
                "uptime_s": int(time.time() - self.started_at) if self.started_at else 0,
                "ts": time.time(),
            }
            tmp = self._STATUS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(status, f)
            os.replace(tmp, self._STATUS_FILE)
        except Exception:
            pass  # Non-critical — dashboard shows stale data

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
        logger.warning("No PSK configured — running without pre-shared key authentication")
        logger.warning("Only localhost bridge (HSG) connections are expected without PSK")

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
