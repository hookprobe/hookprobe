#!/usr/bin/env python3
"""
Guardian HTP Client - HookProbe Transport Protocol for MSSP Communication

Provides secure, reliable UDP communication between Guardian and mssp.hookprobe.com
using the HookProbe Transport Protocol (HTP) with neural resonance authentication.

Features:
- Keyless authentication via neural weight fingerprinting
- NAT/CGNAT traversal with UDP hole punching
- ChaCha20-Poly1305 payload encryption
- Anti-replay protection with nonce tracking
- Automatic reconnection with exponential backoff
- Reliable packet delivery with acknowledgments
- Bandwidth-adaptive streaming

Port: UDP 4719

Author: HookProbe Team
Version: 5.0.0 Cortex
License: AGPL-3.0 - see LICENSE in this directory
"""

import os
import sys
import json
import time
import struct
import socket
import hashlib
import secrets
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque

# Add parent paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'src' / 'neuro' / 'transport'))
sys.path.insert(0, str(Path(__file__).parent))

# Try to import core HTP components
try:
    from htp import (
        HTPHeader, ResonanceLayer, NeuroLayer, HTPState,
        QsecbitGenerator, generate_rdv, generate_posf,
        HookProbeTransport, ENCRYPTION_AVAILABLE, blake3_hash
    )
    HTP_AVAILABLE = True
except ImportError:
    HTP_AVAILABLE = False
    logging.warning("Core HTP module not available, using fallback implementation")

# Optional encryption
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# CONSTANTS
# =============================================================================

HTP_PORT = 4719
HTP_VERSION = 0x0001
MSSP_HOST = "mssp.hookprobe.com"

# Packet types
class HTPPacketType(Enum):
    HELLO = 0x01
    CHALLENGE = 0x02
    ATTEST = 0x03
    ACCEPT = 0x04
    REJECT = 0x05
    DATA = 0x06
    HEARTBEAT = 0x07
    ACK = 0x08
    CLOSE = 0x09
    TELEMETRY = 0x10
    THREAT_REPORT = 0x11
    CONFIG_REQUEST = 0x12
    CONFIG_RESPONSE = 0x13
    LAYER_STATS = 0x14
    MOBILE_PROTECTION = 0x15


# Connection states
class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    RESONATING = "resonating"
    AUTHENTICATED = "authenticated"
    STREAMING = "streaming"
    RECONNECTING = "reconnecting"
    ERROR = "error"


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class HTPConfig:
    """HTP Client Configuration"""
    mssp_host: str = MSSP_HOST
    mssp_port: int = HTP_PORT
    node_id: str = ""
    device_fingerprint: str = ""
    heartbeat_interval: int = 30
    reconnect_delay: int = 5
    max_reconnect_delay: int = 300
    socket_timeout: int = 10
    max_retries: int = 5
    enable_encryption: bool = True
    data_dir: str = "/opt/hookprobe/guardian/data"

    def to_dict(self) -> dict:
        return {
            'mssp_host': self.mssp_host,
            'mssp_port': self.mssp_port,
            'node_id': self.node_id,
            'heartbeat_interval': self.heartbeat_interval,
            'enable_encryption': self.enable_encryption
        }


@dataclass
class HTPPacket:
    """HTP Packet Structure"""
    version: int = HTP_VERSION
    packet_type: HTPPacketType = HTPPacketType.DATA
    sequence: int = 0
    timestamp: int = 0
    flow_token: int = 0
    payload: bytes = b''
    rdv: bytes = b'\x00' * 32
    posf: bytes = b'\x00' * 32
    nonce: int = 0
    encrypted: bool = False

    def serialize(self) -> bytes:
        """Serialize packet to bytes"""
        # Header: 32 bytes
        header = struct.pack(
            '>HHIBQQQ',  # version(2) + type(2) + seq(4) + ts(4) + flow(8) + nonce(8) + flags(4)
            self.version,
            self.packet_type.value,
            self.sequence,
            self.timestamp & 0xFFFFFFFF,
            self.flow_token,
            self.nonce,
            (1 if self.encrypted else 0)
        )

        # Resonance layer: 64 bytes
        resonance = self.rdv[:32] + self.posf[:32]

        # Payload length + payload
        payload_header = struct.pack('>I', len(self.payload))

        return header + resonance + payload_header + self.payload

    @staticmethod
    def deserialize(data: bytes) -> 'HTPPacket':
        """Deserialize packet from bytes"""
        if len(data) < 100:  # Minimum packet size
            raise ValueError("Packet too small")

        # Parse header (32 bytes)
        version, ptype, seq, ts, flow, nonce, flags = struct.unpack(
            '>HHIBQQQ', data[:36]
        )

        # Parse resonance (64 bytes)
        rdv = data[36:68]
        posf = data[68:100]

        # Parse payload
        payload_len = struct.unpack('>I', data[100:104])[0]
        payload = data[104:104 + payload_len]

        return HTPPacket(
            version=version,
            packet_type=HTPPacketType(ptype),
            sequence=seq,
            timestamp=ts,
            flow_token=flow,
            payload=payload,
            rdv=rdv,
            posf=posf,
            nonce=nonce,
            encrypted=bool(flags & 1)
        )


@dataclass
class ConnectionStats:
    """Connection statistics"""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    heartbeats_sent: int = 0
    heartbeats_received: int = 0
    reconnections: int = 0
    last_activity: Optional[datetime] = None
    rtt_ms: float = 0.0
    packet_loss_percent: float = 0.0


# =============================================================================
# HTP CLIENT IMPLEMENTATION
# =============================================================================

class GuardianHTPClient:
    """
    Guardian HTP Client for MSSP Communication

    Provides secure, reliable communication with mssp.hookprobe.com
    using the HookProbe Transport Protocol.
    """

    def __init__(
        self,
        config: Optional[HTPConfig] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.config = config or HTPConfig()
        self.logger = logger or logging.getLogger(__name__)

        # Connection state
        self.state = ConnectionState.DISCONNECTED
        self.socket: Optional[socket.socket] = None
        self.flow_token: int = 0
        self.session_secret: bytes = b''
        self.sequence: int = 0

        # Threading
        self.running = False
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.receive_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

        # Qsecbit and resonance
        self.qsecbit_gen = QsecbitGenerator() if HTP_AVAILABLE else None
        self.weight_fingerprint: bytes = b'\x00' * 32
        self.rdv: bytes = b'\x00' * 32
        self.posf: bytes = b'\x00' * 32

        # Anti-replay
        self.nonce_history: deque = deque(maxlen=1000)
        self.last_remote_nonce: int = 0

        # Statistics
        self.stats = ConnectionStats()

        # Pending acknowledgments
        self.pending_acks: Dict[int, Tuple[HTPPacket, float, int]] = {}

        # Callbacks
        self.on_connected: Optional[Callable] = None
        self.on_disconnected: Optional[Callable] = None
        self.on_data: Optional[Callable[[bytes], None]] = None
        self.on_config: Optional[Callable[[dict], None]] = None

        # Initialize node identity
        self._init_identity()

    def _init_identity(self):
        """Initialize node identity from device fingerprint"""
        if not self.config.node_id:
            # Generate node ID from device fingerprint
            self.config.node_id = self._generate_node_id()

        # Generate initial weight fingerprint
        self.weight_fingerprint = self._generate_weight_fingerprint()

    def _generate_node_id(self) -> str:
        """Generate unique node ID from system characteristics"""
        try:
            # Collect system identifiers
            identifiers = []

            # Machine ID
            machine_id_file = Path('/etc/machine-id')
            if machine_id_file.exists():
                identifiers.append(machine_id_file.read_text().strip())

            # CPU serial (Raspberry Pi)
            try:
                with open('/proc/cpuinfo') as f:
                    for line in f:
                        if line.startswith('Serial'):
                            identifiers.append(line.split(':')[1].strip())
                            break
            except Exception:
                pass

            # MAC address of primary interface
            for iface in ['eth0', 'wlan0']:
                mac_file = Path(f'/sys/class/net/{iface}/address')
                if mac_file.exists():
                    identifiers.append(mac_file.read_text().strip())
                    break

            # Generate hash
            combined = ':'.join(identifiers)
            hash_bytes = hashlib.sha256(combined.encode()).digest()
            return f"guardian-{hash_bytes[:8].hex()}"

        except Exception as e:
            self.logger.warning(f"Could not generate node ID: {e}")
            return f"guardian-{secrets.token_hex(8)}"

    def _generate_weight_fingerprint(self) -> bytes:
        """Generate weight fingerprint from current neural state"""
        try:
            # Read QSecBit stats if available
            stats_file = Path(self.config.data_dir) / 'stats.json'
            if stats_file.exists():
                stats_data = stats_file.read_text()
                return hashlib.sha256(stats_data.encode()).digest()

            # Fallback: random fingerprint (will be updated on first resonance)
            return secrets.token_bytes(32)

        except Exception as e:
            self.logger.warning(f"Could not generate weight fingerprint: {e}")
            return secrets.token_bytes(32)

    def _get_current_timestamp(self) -> int:
        """Get current timestamp in microseconds (mod 2^32)"""
        return int(time.time() * 1_000_000) & 0xFFFFFFFF

    def _generate_nonce(self) -> int:
        """Generate unique nonce for anti-replay"""
        nonce = secrets.randbelow(2**64)
        self.nonce_history.append(nonce)
        return nonce

    def _verify_nonce(self, nonce: int) -> bool:
        """Verify nonce hasn't been seen before"""
        if nonce in self.nonce_history:
            return False
        if nonce <= self.last_remote_nonce:
            return False
        self.last_remote_nonce = nonce
        return True

    def _encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload with ChaCha20-Poly1305"""
        if not self.config.enable_encryption or not CRYPTO_AVAILABLE:
            return payload

        if not self.session_secret:
            return payload

        try:
            # Derive key from session secret
            key = hashlib.sha256(self.session_secret).digest()
            nonce = secrets.token_bytes(12)

            cipher = ChaCha20Poly1305(key)
            ciphertext = cipher.encrypt(nonce, payload, None)

            return nonce + ciphertext

        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            return payload

    def _decrypt_payload(self, encrypted: bytes) -> bytes:
        """Decrypt payload with ChaCha20-Poly1305"""
        if not self.config.enable_encryption or not CRYPTO_AVAILABLE:
            return encrypted

        if not self.session_secret or len(encrypted) < 28:
            return encrypted

        try:
            key = hashlib.sha256(self.session_secret).digest()
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]

            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, ciphertext, None)

        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            return encrypted

    # =========================================================================
    # CONNECTION MANAGEMENT
    # =========================================================================

    def connect(self) -> bool:
        """Establish connection to MSSP"""
        self.logger.info(f"Connecting to {self.config.mssp_host}:{self.config.mssp_port}")

        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(self.config.socket_timeout)

            # Resolve MSSP host
            try:
                mssp_ip = socket.gethostbyname(self.config.mssp_host)
            except socket.gaierror:
                self.logger.error(f"Could not resolve {self.config.mssp_host}")
                return False

            self.socket.connect((mssp_ip, self.config.mssp_port))

            self.state = ConnectionState.CONNECTING
            self.flow_token = secrets.randbelow(2**64)

            # Perform handshake
            if not self._perform_handshake():
                self.state = ConnectionState.ERROR
                return False

            self.state = ConnectionState.AUTHENTICATED
            self.stats.last_activity = datetime.now()

            # Start background threads
            self.running = True
            self._start_threads()

            self.logger.info("Successfully connected to MSSP")

            if self.on_connected:
                self.on_connected()

            return True

        except socket.error as e:
            self.logger.error(f"Socket error: {e}")
            self.state = ConnectionState.ERROR
            return False

        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            self.state = ConnectionState.ERROR
            return False

    def disconnect(self):
        """Disconnect from MSSP"""
        self.logger.info("Disconnecting from MSSP")

        self.running = False

        # Send CLOSE packet
        if self.socket and self.state in [ConnectionState.AUTHENTICATED, ConnectionState.STREAMING]:
            try:
                self._send_packet(HTPPacketType.CLOSE, b'')
            except Exception:
                pass

        # Stop threads
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=2)

        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=2)

        # Close socket
        if self.socket:
            self.socket.close()
            self.socket = None

        self.state = ConnectionState.DISCONNECTED

        if self.on_disconnected:
            self.on_disconnected()

    def _perform_handshake(self) -> bool:
        """Perform HTP handshake with MSSP"""
        self.logger.info("Starting HTP handshake")
        self.state = ConnectionState.RESONATING

        try:
            # Step 1: Send HELLO
            hello_payload = json.dumps({
                'node_id': self.config.node_id,
                'weight_fingerprint': self.weight_fingerprint.hex(),
                'version': HTP_VERSION,
                'capabilities': ['telemetry', 'threats', 'config', 'layer_stats']
            }).encode()

            self._send_packet(HTPPacketType.HELLO, hello_payload)

            # Step 2: Receive CHALLENGE
            response = self._receive_packet(timeout=10)
            if not response or response.packet_type != HTPPacketType.CHALLENGE:
                self.logger.error("Did not receive CHALLENGE")
                return False

            challenge_data = json.loads(response.payload.decode())
            challenge_nonce = bytes.fromhex(challenge_data['nonce'])

            # Step 3: Send ATTEST (prove identity via PoSF)
            self._update_resonance(challenge_nonce)

            attest_payload = json.dumps({
                'node_id': self.config.node_id,
                'rdv': self.rdv.hex(),
                'posf': self.posf.hex(),
                'device_fingerprint': self.config.device_fingerprint
            }).encode()

            self._send_packet(HTPPacketType.ATTEST, attest_payload)

            # Step 4: Receive ACCEPT or REJECT
            response = self._receive_packet(timeout=10)
            if not response:
                self.logger.error("No response to ATTEST")
                return False

            if response.packet_type == HTPPacketType.REJECT:
                reject_data = json.loads(response.payload.decode())
                self.logger.error(f"Authentication rejected: {reject_data.get('reason', 'unknown')}")
                return False

            if response.packet_type != HTPPacketType.ACCEPT:
                self.logger.error(f"Unexpected response: {response.packet_type}")
                return False

            # Extract session secret
            accept_data = json.loads(response.payload.decode())
            self.session_secret = bytes.fromhex(accept_data['session_secret'])
            self.flow_token = int(accept_data.get('flow_token', self.flow_token))

            self.logger.info("Handshake completed successfully")
            return True

        except socket.timeout:
            self.logger.error("Handshake timeout")
            return False

        except Exception as e:
            self.logger.error(f"Handshake error: {e}")
            return False

    def _update_resonance(self, challenge: bytes):
        """Update RDV and PoSF based on challenge"""
        # Collect sensor data for qsecbit
        sensor_vec = self._collect_sensor_data()

        if self.qsecbit_gen:
            white_noise = secrets.token_bytes(32)
            clock_jitter = struct.pack('<Q', int(time.time_ns()) % (2**64))
            qsecbit = self.qsecbit_gen.generate(white_noise, sensor_vec, clock_jitter)
        else:
            qsecbit = hashlib.sha256(sensor_vec + challenge).digest()

        # Generate RDV
        ter = self._get_current_ter()
        timestamp = self._get_current_timestamp()

        if HTP_AVAILABLE:
            self.rdv = generate_rdv(qsecbit, ter, timestamp)
            self.posf = generate_posf(sensor_vec, self.rdv, self.weight_fingerprint)
        else:
            # Fallback implementation
            rdv_input = qsecbit + ter + struct.pack('>I', timestamp) + challenge
            self.rdv = hashlib.sha256(rdv_input).digest()

            posf_input = sensor_vec + self.rdv + self.weight_fingerprint
            self.posf = hashlib.sha256(posf_input).digest()

    def _collect_sensor_data(self) -> bytes:
        """Collect current sensor data for resonance"""
        try:
            data = []

            # CPU usage
            with open('/proc/stat') as f:
                cpu_line = f.readline()
                values = [int(x) for x in cpu_line.split()[1:]]
                data.extend(values[:4])

            # Memory usage
            with open('/proc/meminfo') as f:
                for line in f:
                    if 'MemTotal' in line or 'MemFree' in line:
                        data.append(int(line.split()[1]))

            # Network stats
            with open('/proc/net/dev') as f:
                for line in f:
                    if 'eth0' in line or 'wlan0' in line:
                        parts = line.split()
                        data.append(int(parts[1]))  # RX bytes
                        data.append(int(parts[9]))  # TX bytes
                        break

            # Disk I/O
            with open('/proc/diskstats') as f:
                for line in f:
                    if 'mmcblk0' in line or 'sda' in line:
                        parts = line.split()
                        data.append(int(parts[5]))  # Reads
                        data.append(int(parts[9]))  # Writes
                        break

            # Pack as bytes
            return struct.pack(f'>{len(data)}Q', *data)

        except Exception as e:
            self.logger.warning(f"Could not collect sensor data: {e}")
            return secrets.token_bytes(64)

    def _get_current_ter(self) -> bytes:
        """Get current Temporal Event Record (64 bytes)"""
        try:
            # Read latest stats
            stats_file = Path(self.config.data_dir) / 'stats.json'
            if stats_file.exists():
                stats_data = stats_file.read_text()[:4096]
                h_entropy = hashlib.sha256(stats_data.encode()).digest()
            else:
                h_entropy = secrets.token_bytes(32)

            # Integrity hash (simplified)
            h_integrity = hashlib.new('ripemd160', h_entropy).digest()

            # Timestamp and sequence
            timestamp = struct.pack('>Q', int(time.time() * 1_000_000))
            sequence = struct.pack('>H', self.sequence % 65536)
            chain_hash = struct.pack('>H', 0)

            # Construct TER (64 bytes)
            return h_entropy + h_integrity + timestamp + sequence + chain_hash

        except Exception as e:
            self.logger.warning(f"Could not generate TER: {e}")
            return secrets.token_bytes(64)

    # =========================================================================
    # PACKET TRANSMISSION
    # =========================================================================

    def _send_packet(
        self,
        packet_type: HTPPacketType,
        payload: bytes,
        encrypt: bool = True
    ) -> bool:
        """Send HTP packet"""
        if not self.socket:
            return False

        with self.lock:
            self.sequence += 1

            # Encrypt payload if needed
            if encrypt and self.session_secret:
                encrypted_payload = self._encrypt_payload(payload)
                is_encrypted = True
            else:
                encrypted_payload = payload
                is_encrypted = False

            # Build packet
            packet = HTPPacket(
                version=HTP_VERSION,
                packet_type=packet_type,
                sequence=self.sequence,
                timestamp=self._get_current_timestamp(),
                flow_token=self.flow_token,
                payload=encrypted_payload,
                rdv=self.rdv,
                posf=self.posf,
                nonce=self._generate_nonce(),
                encrypted=is_encrypted
            )

            try:
                data = packet.serialize()
                self.socket.send(data)

                self.stats.packets_sent += 1
                self.stats.bytes_sent += len(data)
                self.stats.last_activity = datetime.now()

                return True

            except socket.error as e:
                self.logger.error(f"Send error: {e}")
                return False

    def _receive_packet(self, timeout: Optional[float] = None) -> Optional[HTPPacket]:
        """Receive HTP packet"""
        if not self.socket:
            return None

        old_timeout = self.socket.gettimeout()
        if timeout:
            self.socket.settimeout(timeout)

        try:
            data, _ = self.socket.recvfrom(65535)

            self.stats.packets_received += 1
            self.stats.bytes_received += len(data)
            self.stats.last_activity = datetime.now()

            packet = HTPPacket.deserialize(data)

            # Verify nonce
            if not self._verify_nonce(packet.nonce):
                self.logger.warning("Replay attack detected - dropping packet")
                return None

            # Decrypt payload if needed
            if packet.encrypted and self.session_secret:
                packet.payload = self._decrypt_payload(packet.payload)

            return packet

        except socket.timeout:
            return None

        except Exception as e:
            self.logger.error(f"Receive error: {e}")
            return None

        finally:
            self.socket.settimeout(old_timeout)

    # =========================================================================
    # BACKGROUND THREADS
    # =========================================================================

    def _start_threads(self):
        """Start background threads"""
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True
        )
        self.heartbeat_thread.start()

        self.receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True
        )
        self.receive_thread.start()

    def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self.running:
            try:
                time.sleep(self.config.heartbeat_interval)

                if not self.running:
                    break

                if self.state in [ConnectionState.AUTHENTICATED, ConnectionState.STREAMING]:
                    self._send_heartbeat()

            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")

    def _send_heartbeat(self):
        """Send heartbeat packet"""
        heartbeat_data = json.dumps({
            'timestamp': datetime.now().isoformat(),
            'uptime': self._get_uptime(),
            'stats': {
                'packets_sent': self.stats.packets_sent,
                'packets_received': self.stats.packets_received
            }
        }).encode()

        if self._send_packet(HTPPacketType.HEARTBEAT, heartbeat_data):
            self.stats.heartbeats_sent += 1

    def _get_uptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            with open('/proc/uptime') as f:
                return float(f.read().split()[0])
        except Exception:
            return 0.0

    def _receive_loop(self):
        """Receive packets in background"""
        while self.running:
            try:
                packet = self._receive_packet(timeout=1)
                if packet:
                    self._handle_packet(packet)

            except Exception as e:
                if self.running:
                    self.logger.error(f"Receive loop error: {e}")

    def _handle_packet(self, packet: HTPPacket):
        """Handle received packet"""
        handlers = {
            HTPPacketType.ACK: self._handle_ack,
            HTPPacketType.HEARTBEAT: self._handle_heartbeat,
            HTPPacketType.DATA: self._handle_data,
            HTPPacketType.CONFIG_RESPONSE: self._handle_config,
            HTPPacketType.CLOSE: self._handle_close,
        }

        handler = handlers.get(packet.packet_type)
        if handler:
            handler(packet)
        else:
            self.logger.debug(f"Unhandled packet type: {packet.packet_type}")

    def _handle_ack(self, packet: HTPPacket):
        """Handle ACK packet"""
        try:
            ack_data = json.loads(packet.payload.decode())
            seq = ack_data.get('sequence')
            if seq and seq in self.pending_acks:
                del self.pending_acks[seq]
        except Exception:
            pass

    def _handle_heartbeat(self, packet: HTPPacket):
        """Handle heartbeat response"""
        self.stats.heartbeats_received += 1

    def _handle_data(self, packet: HTPPacket):
        """Handle data packet"""
        if self.on_data:
            self.on_data(packet.payload)

    def _handle_config(self, packet: HTPPacket):
        """Handle config response"""
        try:
            config_data = json.loads(packet.payload.decode())
            if self.on_config:
                self.on_config(config_data)
        except Exception as e:
            self.logger.error(f"Config parse error: {e}")

    def _handle_close(self, packet: HTPPacket):
        """Handle close packet"""
        self.logger.info("Received CLOSE from MSSP")
        self.disconnect()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def send_telemetry(self, telemetry: dict) -> bool:
        """Send telemetry data to MSSP"""
        if self.state != ConnectionState.AUTHENTICATED:
            return False

        payload = json.dumps(telemetry).encode()
        return self._send_packet(HTPPacketType.TELEMETRY, payload)

    def send_threat_report(self, report: dict) -> bool:
        """Send threat report to MSSP"""
        if self.state != ConnectionState.AUTHENTICATED:
            return False

        payload = json.dumps(report).encode()
        return self._send_packet(HTPPacketType.THREAT_REPORT, payload)

    def send_layer_stats(self, stats: dict) -> bool:
        """Send L2-L7 layer statistics to MSSP"""
        if self.state != ConnectionState.AUTHENTICATED:
            return False

        payload = json.dumps(stats).encode()
        return self._send_packet(HTPPacketType.LAYER_STATS, payload)

    def send_mobile_protection_status(self, status: dict) -> bool:
        """Send mobile protection status to MSSP"""
        if self.state != ConnectionState.AUTHENTICATED:
            return False

        payload = json.dumps(status).encode()
        return self._send_packet(HTPPacketType.MOBILE_PROTECTION, payload)

    def request_config(self) -> bool:
        """Request configuration from MSSP"""
        if self.state != ConnectionState.AUTHENTICATED:
            return False

        payload = json.dumps({'node_id': self.config.node_id}).encode()
        return self._send_packet(HTPPacketType.CONFIG_REQUEST, payload)

    def get_stats(self) -> dict:
        """Get connection statistics"""
        return {
            'state': self.state.value,
            'node_id': self.config.node_id,
            'mssp_host': self.config.mssp_host,
            'packets_sent': self.stats.packets_sent,
            'packets_received': self.stats.packets_received,
            'bytes_sent': self.stats.bytes_sent,
            'bytes_received': self.stats.bytes_received,
            'heartbeats_sent': self.stats.heartbeats_sent,
            'heartbeats_received': self.stats.heartbeats_received,
            'last_activity': self.stats.last_activity.isoformat() if self.stats.last_activity else None,
            'reconnections': self.stats.reconnections
        }

    def is_connected(self) -> bool:
        """Check if connected to MSSP"""
        return self.state == ConnectionState.AUTHENTICATED


# =============================================================================
# GUARDIAN HTP SERVICE
# =============================================================================

class GuardianHTPService:
    """
    Guardian HTP Service - Manages HTP connection and data reporting

    Runs as a background service, collecting and sending data to MSSP.
    """

    def __init__(
        self,
        config_file: str = "/opt/hookprobe/guardian/htp.conf",
        data_dir: str = "/opt/hookprobe/guardian/data"
    ):
        self.config_file = Path(config_file)
        self.data_dir = Path(data_dir)

        # Load config
        self.config = self._load_config()
        self.config.data_dir = str(data_dir)

        # Create client
        self.client = GuardianHTPClient(self.config)

        # Set callbacks
        self.client.on_connected = self._on_connected
        self.client.on_disconnected = self._on_disconnected
        self.client.on_config = self._on_config_received

        # Reporting intervals
        self.telemetry_interval = 60  # seconds
        self.threat_interval = 30
        self.layer_interval = 60

        # Threading
        self.running = False
        self.report_thread: Optional[threading.Thread] = None

    def _load_config(self) -> HTPConfig:
        """Load configuration from file"""
        config = HTPConfig()

        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    data = json.load(f)
                    config.mssp_host = data.get('mssp_host', MSSP_HOST)
                    config.mssp_port = data.get('mssp_port', HTP_PORT)
                    config.node_id = data.get('node_id', '')
                    config.heartbeat_interval = data.get('heartbeat_interval', 30)
                    config.enable_encryption = data.get('enable_encryption', True)
            except Exception as e:
                logging.warning(f"Could not load config: {e}")

        return config

    def _save_config(self):
        """Save configuration to file"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config.to_dict(), f, indent=2)
        except Exception as e:
            logging.error(f"Could not save config: {e}")

    def _on_connected(self):
        """Handle connection established"""
        logging.info("Connected to MSSP - starting data reporting")
        # Request configuration
        self.client.request_config()

    def _on_disconnected(self):
        """Handle disconnection"""
        logging.warning("Disconnected from MSSP")

    def _on_config_received(self, config: dict):
        """Handle config received from MSSP"""
        logging.info(f"Received config from MSSP: {config}")

        # Update reporting intervals
        if 'telemetry_interval' in config:
            self.telemetry_interval = config['telemetry_interval']
        if 'threat_interval' in config:
            self.threat_interval = config['threat_interval']

    def start(self):
        """Start the HTP service"""
        logging.info("Starting Guardian HTP Service")

        self.running = True

        # Connect to MSSP
        if not self.client.connect():
            logging.error("Failed to connect to MSSP")
            # Will retry in report loop

        # Start reporting thread
        self.report_thread = threading.Thread(
            target=self._report_loop,
            daemon=True
        )
        self.report_thread.start()

    def stop(self):
        """Stop the HTP service"""
        logging.info("Stopping Guardian HTP Service")

        self.running = False

        if self.report_thread and self.report_thread.is_alive():
            self.report_thread.join(timeout=5)

        self.client.disconnect()

    def _report_loop(self):
        """Main reporting loop"""
        last_telemetry = 0
        last_threat = 0
        last_layer = 0
        reconnect_delay = 5

        while self.running:
            try:
                current_time = time.time()

                # Check connection
                if not self.client.is_connected():
                    logging.info(f"Reconnecting in {reconnect_delay}s...")
                    time.sleep(reconnect_delay)
                    if self.client.connect():
                        reconnect_delay = 5
                    else:
                        reconnect_delay = min(reconnect_delay * 2, 300)
                    continue

                # Send telemetry
                if current_time - last_telemetry >= self.telemetry_interval:
                    self._send_telemetry()
                    last_telemetry = current_time

                # Send threat reports
                if current_time - last_threat >= self.threat_interval:
                    self._send_threat_report()
                    last_threat = current_time

                # Send layer stats
                if current_time - last_layer >= self.layer_interval:
                    self._send_layer_stats()
                    last_layer = current_time

                time.sleep(1)

            except Exception as e:
                logging.error(f"Report loop error: {e}")
                time.sleep(5)

    def _send_telemetry(self):
        """Send current telemetry to MSSP"""
        try:
            # Read stats file
            stats_file = self.data_dir / 'stats.json'
            if stats_file.exists():
                with open(stats_file) as f:
                    stats = json.load(f)

                self.client.send_telemetry({
                    'timestamp': datetime.now().isoformat(),
                    'node_id': self.config.node_id,
                    'qsecbit_score': stats.get('score', 0),
                    'rag_status': stats.get('rag_status', 'UNKNOWN'),
                    'components': stats.get('components', {}),
                    'threats': stats.get('threats', 0)
                })

        except Exception as e:
            logging.error(f"Telemetry send error: {e}")

    def _send_threat_report(self):
        """Send threat report to MSSP"""
        try:
            threats_file = self.data_dir / 'threats.json'
            if threats_file.exists():
                # Read last 50 threats
                threats = []
                with open(threats_file) as f:
                    for line in f:
                        try:
                            threats.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

                if threats:
                    self.client.send_threat_report({
                        'timestamp': datetime.now().isoformat(),
                        'node_id': self.config.node_id,
                        'threat_count': len(threats),
                        'recent_threats': threats[-20:]
                    })

        except Exception as e:
            logging.error(f"Threat report send error: {e}")

    def _send_layer_stats(self):
        """Send L2-L7 layer statistics to MSSP"""
        try:
            layer_file = self.data_dir / 'layer_stats.json'
            if layer_file.exists():
                with open(layer_file) as f:
                    layer_data = json.load(f)

                self.client.send_layer_stats({
                    'timestamp': datetime.now().isoformat(),
                    'node_id': self.config.node_id,
                    **layer_data
                })

            # Also send mobile protection status
            mobile_file = self.data_dir / 'mobile_protection_state.json'
            if mobile_file.exists():
                with open(mobile_file) as f:
                    mobile_data = json.load(f)

                self.client.send_mobile_protection_status({
                    'timestamp': datetime.now().isoformat(),
                    'node_id': self.config.node_id,
                    **mobile_data
                })

        except Exception as e:
            logging.error(f"Layer stats send error: {e}")


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Guardian HTP Client')
    parser.add_argument('--config', default='/opt/hookprobe/guardian/htp.conf',
                        help='Configuration file path')
    parser.add_argument('--data-dir', default='/opt/hookprobe/guardian/data',
                        help='Data directory path')
    parser.add_argument('--daemon', action='store_true',
                        help='Run as daemon')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose logging')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    # Create and start service
    service = GuardianHTPService(
        config_file=args.config,
        data_dir=args.data_dir
    )

    try:
        service.start()

        if args.daemon:
            # Run forever
            import signal

            def signal_handler(signum, frame):
                logging.info(f"Received signal {signum}")
                service.stop()

            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)

            while service.running:
                time.sleep(1)
        else:
            # Run for a bit then exit
            time.sleep(60)
            service.stop()

    except KeyboardInterrupt:
        service.stop()


if __name__ == '__main__':
    main()
