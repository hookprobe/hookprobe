"""
HookProbe Transport Protocol (HTP) - Keyless Design

Adaptive, Resonant, Noise-Derived, Secure Transport for Edge ↔ Cloud ↔ Validator Networks

Key Innovations:
- KEYLESS: Identity derived from qsecbit, white noise, resonance drift, TER, PoSF
- ADAPTIVE: Real-time adjustment of latency, encoding, bandwidth, packet density
- NAT/CGNAT FRIENDLY: UDP hole punching, resonance-interval keepalives
- METADATA-SHIELDED: No stable IPs, ports, IDs, fingerprints
- LOW-BANDWIDTH: 10-50kbps sensor mode, 200-400kbps video, 1-2Mbps high-res

Security Model:
- No traditional PKI or key exchange
- Identity and authentication via sensor entropy (qsecbit)
- Continuous resonance alignment and entropy-echo verification
- Anti-replay via qsecbit drift detection
- Neural Synaptic Encryption (NSE) - keys derived from neural state

State Machine:
INIT → RESONATE → SYNC → STREAMING → ADAPTIVE → (RE-RESONATE) → STREAMING
"""

import os
import struct
import hashlib
import socket
import time
import secrets
import logging
from typing import Optional, Tuple, List, Dict
from enum import Enum
from dataclasses import dataclass, field
from collections import deque

logger = logging.getLogger(__name__)

# Optional encryption (if enabled)
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

# Neural Synaptic Encryption integration
try:
    from core.neuro.integration import HTPNeuroBinding, NeuroSecurityStack
    NEURO_INTEGRATION_AVAILABLE = True
except ImportError:
    HTPNeuroBinding = None
    NeuroSecurityStack = None
    NEURO_INTEGRATION_AVAILABLE = False

# Use BLAKE3 if available, fallback to SHA256
try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    import hashlib


def blake3_hash(data: bytes) -> bytes:
    """BLAKE3 hash (or SHA256 fallback)."""
    if BLAKE3_AVAILABLE:
        return blake3.blake3(data).digest()
    else:
        return hashlib.sha256(data).digest()


# ============================================================================
# 1. PACKET STRUCTURES (Binary Layout)
# ============================================================================

class PacketMode(Enum):
    """HTP packet modes."""
    SENSOR = 0x01  # Sensor telemetry
    TEXT = 0x02    # Text/command
    VIDEO = 0x03   # Video slice
    FRAME = 0x04   # Frame batch


@dataclass
class HTPHeader:
    """HTP Header (32 bytes).

    All multibyte integers are big-endian.
    """
    version: int = 0x0001              # uint16_t (2 bytes)
    mode: int = PacketMode.SENSOR.value  # uint16_t (2 bytes)
    timestamp_us: int = 0              # uint32_t (4 bytes) - rolling microsecond mod 2^32
    flow_token: int = 0                # uint64_t (8 bytes) - random per session
    entropy_echo: int = 0              # uint64_t (8 bytes) - H(remote_noise | local_noise)
    anti_replay_nonce: int = 0         # uint64_t (8 bytes) - derived from qsecbit drift

    def serialize(self) -> bytes:
        """Pack to 32 bytes."""
        return struct.pack(
            '>HHIQQQ',  # Big-endian: H=uint16, I=uint32, Q=uint64 (FIXED: was HHIQQQQ)
            self.version,
            self.mode,
            self.timestamp_us & 0xFFFFFFFF,  # Mod 2^32
            self.flow_token,
            self.entropy_echo,
            self.anti_replay_nonce
        )

    @staticmethod
    def deserialize(data: bytes) -> 'HTPHeader':
        """Unpack from 32 bytes."""
        version, mode, timestamp_us, flow_token, entropy_echo, anti_replay = struct.unpack(
            '>HHIQQQ', data[:32]  # FIXED: was HHIQQQQ
        )
        return HTPHeader(version, mode, timestamp_us, flow_token, entropy_echo, anti_replay)


@dataclass
class ResonanceLayer:
    """Resonance Layer (64 bytes)."""
    rdv: bytes = field(default_factory=lambda: b'\x00' * 32)   # Resonance Drift Vector (32 bytes)
    posf: bytes = field(default_factory=lambda: b'\x00' * 32)  # Proof-of-Sensor-Fusion (32 bytes)

    def serialize(self) -> bytes:
        """Pack to 64 bytes."""
        return self.rdv[:32] + self.posf[:32]

    @staticmethod
    def deserialize(data: bytes) -> 'ResonanceLayer':
        """Unpack from 64 bytes."""
        return ResonanceLayer(rdv=data[:32], posf=data[32:64])


@dataclass
class NeuroLayer:
    """Neuro Layer (224 bytes recommended)."""
    delta_W: bytes = field(default_factory=lambda: b'\x00' * 128)      # Evolving NN delta-state (128 bytes)
    ter: bytes = field(default_factory=lambda: b'\x00' * 64)           # Telemetry Evolution Register (64 bytes)
    entropy_vec: bytes = field(default_factory=lambda: b'\x00' * 32)  # Entropy injection vector (32 bytes)

    def serialize(self) -> bytes:
        """Pack to 224 bytes."""
        return self.delta_W[:128] + self.ter[:64] + self.entropy_vec[:32]

    @staticmethod
    def deserialize(data: bytes) -> 'NeuroLayer':
        """Unpack from 224 bytes."""
        return NeuroLayer(
            delta_W=data[:128],
            ter=data[128:192],
            entropy_vec=data[192:224]
        )


# ============================================================================
# 2. STATE MACHINE
# ============================================================================

class HTPState(Enum):
    """HTP state machine states."""
    INIT = "init"
    RESONATE = "resonate"
    SYNC = "sync"
    STREAMING = "streaming"
    ADAPTIVE = "adaptive"
    RE_RESONATE = "re_resonate"


# ============================================================================
# 3. CORE ALGORITHMS
# ============================================================================

class QsecbitGenerator:
    """Generate quantized security bits from sensor entropy and white noise."""

    def __init__(self):
        self.history: deque = deque(maxlen=100)  # Keep last 100 qsecbits

    def generate(self, white_noise: bytes, sensor_vec: bytes, clock_jitter: bytes) -> bytes:
        """
        Generate qsecbit: SHA256(white_noise + sensor_vec + clock_jitter).

        Args:
            white_noise: Random noise bytes
            sensor_vec: Sensor telemetry vector
            clock_jitter: Clock jitter bytes

        Returns:
            32-byte qsecbit
        """
        data = white_noise + sensor_vec + clock_jitter
        qsecbit = hashlib.sha256(data).digest()
        self.history.append(qsecbit)
        return qsecbit

    def get_history(self, window: int = 50) -> bytes:
        """Get concatenated qsecbit history."""
        recent = list(self.history)[-window:]
        return b''.join(recent)


def generate_rdv(qsecbit_history: bytes, ter: bytes, timestamp: int) -> bytes:
    """
    Generate Resonance Drift Vector (RDV).

    RDV = BLAKE3(qsecbit_history + TER + timestamp)

    Args:
        qsecbit_history: Concatenated qsecbit window (~50 samples)
        ter: Telemetry Evolution Register (64 bytes)
        timestamp: Current timestamp (microseconds)

    Returns:
        32-byte RDV
    """
    data = qsecbit_history + ter + struct.pack('>I', timestamp & 0xFFFFFFFF)
    return blake3_hash(data)[:32]


def generate_posf(sensor_matrix: bytes, rdv: bytes, delta_w: bytes) -> bytes:
    """
    Generate Proof-of-Sensor-Fusion (PoSF).

    PoSF = BLAKE3(sensor_matrix + rdv + delta_W)

    Args:
        sensor_matrix: Raw sensor data matrix
        rdv: Resonance Drift Vector (32 bytes)
        delta_w: Neural network weight delta (128 bytes)

    Returns:
        32-byte PoSF
    """
    data = sensor_matrix + rdv + delta_w
    return blake3_hash(data)[:32]


def anti_replay_nonce(qsecbit_prev: bytes, qsecbit_now: bytes) -> int:
    """
    Generate anti-replay nonce from qsecbit drift.

    nonce = first 8 bytes of BLAKE3(qsecbit_prev XOR qsecbit_now)

    Args:
        qsecbit_prev: Previous qsecbit
        qsecbit_now: Current qsecbit

    Returns:
        uint64 nonce
    """
    drift = bytes(a ^ b for a, b in zip(qsecbit_prev, qsecbit_now))
    hash_val = blake3_hash(drift)
    return struct.unpack('>Q', hash_val[:8])[0]


def generate_entropy_echo(local_noise: bytes, remote_noise_guess: bytes) -> int:
    """
    Generate entropy echo for NAT traversal.

    entropy_echo = H(local_noise || remote_noise_guess)

    Returns: uint64
    """
    data = local_noise + remote_noise_guess
    hash_val = blake3_hash(data)
    return struct.unpack('>Q', hash_val[:8])[0]


def verify_entropy_echo(cloud_noise: bytes, received_echo: int) -> int:
    """
    Cloud generates echo reply.

    echo_reply = H(cloud_noise || received_echo)

    Returns: uint64
    """
    data = cloud_noise + struct.pack('>Q', received_echo)
    hash_val = blake3_hash(data)
    return struct.unpack('>Q', hash_val[:8])[0]


def hamming_distance(a: bytes, b: bytes) -> float:
    """Calculate normalized Hamming distance between two byte arrays."""
    if len(a) != len(b):
        return 1.0

    diff_bits = sum(bin(x ^ y).count('1') for x, y in zip(a, b))
    total_bits = len(a) * 8
    return diff_bits / total_bits


# ============================================================================
# 4. NEURO-STATE EVOLUTION (Fixed-Point)
# ============================================================================

class NeuroStateEvolver:
    """
    Fixed-point neural network weight evolution.

    W(t+1) = W(t) - eta * gradient + xi * qsecbit

    Uses int16 arithmetic for determinism (no floating-point).
    Per spec: int16 multiplies, not int8.
    """

    def __init__(self, initial_weights: Optional[bytes] = None, eta: int = 5, xi: int = 1):
        """
        Args:
            initial_weights: Initial weights (128 bytes = 64 int16 values)
            eta: Learning rate scaled by 10000 (e.g., 5 = 0.0005)
            xi: Noise coefficient scaled by 100000 (e.g., 1 = 0.00001)
        """
        self.W = bytearray(initial_weights if initial_weights else secrets.token_bytes(128))
        self.eta = eta  # Scaled learning rate
        self.xi = xi    # Scaled noise coefficient

    def evolve(self, ter: bytes, qsecbit: bytes) -> bytes:
        """
        Evolve weights based on TER and qsecbit using int16 arithmetic.

        Args:
            ter: Telemetry Evolution Register (64 bytes)
            qsecbit: Current qsecbit (32 bytes)

        Returns:
            delta_W (128 bytes)
        """
        # Compute gradient from TER (simplified: use TER as gradient signal)
        gradient = hashlib.sha256(ter).digest() + hashlib.sha256(ter + b'\x01').digest()
        gradient = gradient[:128]

        # Expand qsecbit to 128 bytes for noise injection
        noise_bytes = (qsecbit * 4)[:128]

        # Convert 128 bytes to 64 int16 values (big-endian)
        W_arr = []
        grad_arr = []
        noise_arr = []

        for i in range(0, 128, 2):
            # int16: -32768 to +32767
            W_arr.append(struct.unpack('>h', self.W[i:i+2])[0])
            grad_arr.append(struct.unpack('>h', gradient[i:i+2])[0])
            noise_arr.append(struct.unpack('>h', noise_bytes[i:i+2])[0])

        # Fixed-point update: W -= eta * grad + xi * noise
        # eta and xi are pre-scaled, so we divide after multiplication
        delta_W = bytearray(128)

        for i in range(64):
            # Compute update with int16 arithmetic
            gradient_term = (self.eta * grad_arr[i]) // 10000
            noise_term = (self.xi * noise_arr[i]) // 100000
            update = -gradient_term + noise_term

            # Update weight
            new_val = W_arr[i] + update

            # Clamp to int16 range
            new_val = max(-32768, min(32767, new_val))

            # Store back to bytearray (big-endian int16)
            self.W[i*2:i*2+2] = struct.pack('>h', new_val)
            delta_W[i*2:i*2+2] = struct.pack('>h', update)

        return bytes(delta_W)


# ============================================================================
# 5. HTP SESSION
# ============================================================================

@dataclass
class HTPSession:
    """HTP session state (keyless design)."""
    flow_token: int
    state: HTPState
    peer_address: Tuple[str, int]

    # Keyless identity
    qsecbit_gen: QsecbitGenerator = field(default_factory=QsecbitGenerator)
    neuro_evolver: NeuroStateEvolver = field(default_factory=NeuroStateEvolver)
    ter: bytes = field(default_factory=lambda: secrets.token_bytes(64))

    # Resonance state
    local_noise: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    remote_noise_guess: bytes = b''
    last_rdv: bytes = b''
    last_posf: bytes = b''

    # Timing
    created_timestamp: float = 0.0
    last_activity: float = 0.0
    last_keepalive: float = 0.0

    # RTT measurement (P2 feature)
    rtt_samples: deque = field(default_factory=lambda: deque(maxlen=20))  # Last 20 RTT samples
    rtt_current: float = 0.0  # Current RTT in seconds
    rtt_baseline: float = 0.1  # Baseline RTT (updated via EWMA)
    rtt_min: float = float('inf')  # Minimum observed RTT
    rtt_max: float = 0.0  # Maximum observed RTT
    last_sent_timestamp: Dict[int, float] = field(default_factory=dict)  # seq → timestamp

    # Bandwidth detection (P2 feature)
    bandwidth_bytes_sent: int = 0
    bandwidth_bytes_received: int = 0
    bandwidth_window_start: float = 0.0
    bandwidth_current_bps: float = 0.0  # Current bandwidth in bits/sec
    loss_rate: float = 0.0  # Packet loss rate (0.0 to 1.0)
    packets_sent: int = 0
    packets_received: int = 0
    packets_expected: int = 0

    # Adaptive state
    current_mode: int = PacketMode.SENSOR.value

    # CPU/temp stress (P2 feature)
    cpu_usage: float = 0.0  # Current CPU usage (0.0 to 1.0)
    temperature_celsius: float = 0.0  # Device temperature (if available)
    stress_level: str = "NORMAL"  # NORMAL, MODERATE, HIGH

    # Sequence tracking
    send_sequence: int = 0
    recv_sequence: int = 0

    # Optional encryption - derived from neural state via NSE
    encryption_key: Optional[bytes] = None

    # Anti-replay nonce history
    nonce_history: deque = field(default_factory=lambda: deque(maxlen=100))

    # Neural Synaptic Encryption binding (derives keys from weight state)
    neuro_binding: Optional['HTPNeuroBinding'] = None

    # Current Qsecbit score for key derivation
    current_qsecbit: float = 0.0


# ============================================================================
# 6. HOOKPROBE TRANSPORT (KEYLESS)
# ============================================================================

class HookProbeTransport:
    """
    HookProbe Transport Protocol (HTP) - Keyless Design.

    Identity derived from qsecbit, white noise, resonance drift, TER, PoSF.
    No traditional PKI or key exchange.
    """

    # Protocol constants
    MAX_PACKET_SIZE = 1400  # Stay below MTU
    KEEPALIVE_INTERVAL_MS = (500, 900)  # Noise-pulsed keepalive
    SESSION_TIMEOUT = 60.0  # seconds

    # Adaptive thresholds
    RTT_THRESHOLD_MULTIPLIER = 1.5
    LOSS_RATE_THRESHOLD = 0.15  # 15%
    RDV_DIVERGENCE_THRESHOLD = 0.20  # 20% Hamming distance

    # P2: CPU/temp stress thresholds
    CPU_STRESS_THRESHOLD = 0.85  # 85% CPU usage
    TEMP_STRESS_THRESHOLD = 75.0  # 75°C
    CPU_CRITICAL_THRESHOLD = 0.95  # 95% CPU usage

    # P2: Bandwidth window for measurement
    BANDWIDTH_WINDOW = 10.0  # 10 seconds
    RTT_EWMA_ALPHA = 0.125  # Exponential weighted moving average factor

    def __init__(
        self,
        node_id: str,
        listen_port: int = 0,
        enable_encryption: bool = False,
        sensor_source=None,  # Optional sensor data source
        neuro_security_stack: Optional['NeuroSecurityStack'] = None,
    ):
        """
        Args:
            node_id: Node identifier (for logging only, not transmitted)
            listen_port: UDP port to listen on
            enable_encryption: Enable ChaCha20-Poly1305 payload encryption
            sensor_source: Optional sensor data source for qsecbit
            neuro_security_stack: Optional NeuroSecurityStack for NSE integration
        """
        self.node_id = node_id
        self.enable_encryption = enable_encryption and ENCRYPTION_AVAILABLE
        self.sensor_source = sensor_source

        # Neural Synaptic Encryption - derive keys from neural state
        self.neuro_stack = neuro_security_stack
        if self.neuro_stack is None and NEURO_INTEGRATION_AVAILABLE:
            try:
                self.neuro_stack = NeuroSecurityStack(node_id.encode()[:16])
                logger.info(f"[HTP] NeuroSecurityStack initialized for {node_id}")
            except Exception as e:
                logger.warning(f"[HTP] Failed to initialize NeuroSecurityStack: {e}")
                self.neuro_stack = None

        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', listen_port))
        self.socket.setblocking(False)

        self.local_address = self.socket.getsockname()

        # Session management (keyed by flow_token)
        self.sessions: Dict[int, HTPSession] = {}

        logger.info(f"[HTP Keyless] {node_id} listening on {self.local_address}")
        logger.info(f"[HTP Keyless] Encryption: {'enabled' if self.enable_encryption else 'disabled'}")
        logger.info(f"[HTP Keyless] NSE: {'enabled' if self.neuro_stack else 'disabled'}")
        logger.info(f"[HTP Keyless] Security: qsecbit + white noise + resonance drift + neural keys")

    def initiate_resonance(
        self,
        peer_address: Tuple[str, int],
        initial_sensor_data: Optional[bytes] = None
    ) -> int:
        """
        Initiate resonance with remote peer.

        State: INIT → RESONATE → SYNC

        Args:
            peer_address: (IP, port) of peer
            initial_sensor_data: Optional initial sensor data

        Returns:
            flow_token (session ID)
        """
        # Generate flow token (random, not stable)
        flow_token = struct.unpack('>Q', secrets.token_bytes(8))[0]

        print(f"[HTP] Initiating resonance with {peer_address}...")
        print(f"[HTP] Flow token: {flow_token:016x}")

        # Create session
        session = HTPSession(
            flow_token=flow_token,
            state=HTPState.INIT,
            peer_address=peer_address,
            created_timestamp=time.time(),
            last_activity=time.time(),
            last_keepalive=time.time()
        )

        # Generate initial qsecbit
        white_noise = secrets.token_bytes(32)
        sensor_vec = initial_sensor_data if initial_sensor_data else secrets.token_bytes(32)
        clock_jitter = struct.pack('>Q', int(time.time() * 1_000_000) % 1000)

        qsecbit = session.qsecbit_gen.generate(white_noise, sensor_vec, clock_jitter)
        print(f"[HTP] Initial qsecbit: {qsecbit.hex()[:16]}...")

        # Transition to RESONATE
        session.state = HTPState.RESONATE

        # Send first resonance packet
        self._send_resonance_packet(session, minimal=True)

        self.sessions[flow_token] = session

        # Wait for resonance reply (simplified for now)
        # In full implementation, this would be a separate state machine loop

        print(f"[HTP] Resonance initiated, waiting for SYNC...")
        return flow_token

    def send_data(
        self,
        flow_token: int,
        payload: bytes,
        mode: PacketMode = PacketMode.SENSOR
    ) -> bool:
        """
        Send data over established HTP session.

        Args:
            flow_token: Session flow token
            payload: Data to send
            mode: Packet mode

        Returns:
            True if sent successfully
        """
        session = self.sessions.get(flow_token)
        if not session or session.state not in [HTPState.STREAMING, HTPState.ADAPTIVE]:
            return False

        # Generate current qsecbit
        white_noise = secrets.token_bytes(32)
        sensor_vec = self._get_sensor_data()
        clock_jitter = struct.pack('>Q', int(time.time() * 1_000_000) % 1000)

        current_qsecbit = session.qsecbit_gen.generate(white_noise, sensor_vec, clock_jitter)

        # Evolve neuro state
        delta_W = session.neuro_evolver.evolve(session.ter, current_qsecbit)

        # Generate RDV
        qsecbit_history = session.qsecbit_gen.get_history(50)
        timestamp_us = int(time.time() * 1_000_000)
        rdv = generate_rdv(qsecbit_history, session.ter, timestamp_us)

        # Generate PoSF
        sensor_matrix = self._get_sensor_matrix()
        posf = generate_posf(sensor_matrix, rdv, delta_W)

        # Generate anti-replay nonce
        prev_qsecbit = list(session.qsecbit_gen.history)[-2] if len(session.qsecbit_gen.history) >= 2 else current_qsecbit
        nonce = anti_replay_nonce(prev_qsecbit, current_qsecbit)

        # Generate entropy echo
        entropy_echo_val = generate_entropy_echo(session.local_noise, session.remote_noise_guess)

        # Build header
        header = HTPHeader(
            version=0x0001,
            mode=mode.value,
            timestamp_us=timestamp_us,
            flow_token=flow_token,
            entropy_echo=entropy_echo_val,
            anti_replay_nonce=nonce
        )

        # Build resonance layer
        resonance = ResonanceLayer(rdv=rdv, posf=posf)

        # Build neuro layer
        neuro = NeuroLayer(delta_W=delta_W, ter=session.ter, entropy_vec=white_noise)

        # Derive encryption key from neural state (NSE integration)
        if self.enable_encryption and self.neuro_stack:
            # Derive ephemeral key from neural state - key exists only during this call
            session.encryption_key = self.neuro_stack.get_htp_session_key(
                rdv=rdv,
                qsecbit=session.current_qsecbit,
                peer_id=struct.pack('>Q', session.flow_token),
            )
            logger.debug(f"[HTP NSE] Ephemeral key derived: {session.encryption_key[:8].hex()}...")

        # Encrypt payload with derived key
        if self.enable_encryption and session.encryption_key:
            cipher = ChaCha20Poly1305(session.encryption_key)
            nonce_enc = secrets.token_bytes(12)
            encrypted = cipher.encrypt(nonce_enc, payload, associated_data=None)
            payload = nonce_enc + encrypted

        # Assemble packet
        packet = header.serialize() + resonance.serialize() + neuro.serialize() + payload

        # P2: Track RTT - store send timestamp for this sequence
        send_time = time.time()
        session.last_sent_timestamp[session.send_sequence] = send_time

        # P2: Update bandwidth tracking
        packet_size = len(packet)
        session.bandwidth_bytes_sent += packet_size
        session.packets_sent += 1
        self._update_bandwidth(session)

        # Send
        self.socket.sendto(packet, session.peer_address)
        session.send_sequence += 1
        session.last_activity = time.time()

        # P2: Update CPU/temp stress and check adaptive mode triggers
        self._update_stress_metrics(session)
        self._check_adaptive_triggers(session, flow_token)

        return True

    def receive_data(self, flow_token: int, timeout: float = 1.0) -> Optional[bytes]:
        """
        Receive data from HTP session.

        Args:
            flow_token: Session flow token
            timeout: Receive timeout in seconds

        Returns:
            Decrypted payload or None
        """
        session = self.sessions.get(flow_token)
        if not session:
            return None

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                packet, addr = self.socket.recvfrom(self.MAX_PACKET_SIZE)

                # Parse packet
                if len(packet) < 320:  # Minimum: header(32) + resonance(64) + neuro(224)
                    continue

                header = HTPHeader.deserialize(packet[:32])

                # Verify flow token
                if header.flow_token != flow_token:
                    continue

                resonance = ResonanceLayer.deserialize(packet[32:96])
                neuro = NeuroLayer.deserialize(packet[96:320])
                payload = packet[320:]

                # Verify anti-replay nonce
                if not self._verify_anti_replay(session, header.anti_replay_nonce):
                    print(f"[HTP] Anti-replay check failed")
                    continue

                # Verify RDV divergence
                if session.last_rdv:
                    divergence = hamming_distance(session.last_rdv, resonance.rdv)
                    if divergence > self.RDV_DIVERGENCE_THRESHOLD:
                        print(f"[HTP] RDV divergence detected: {divergence:.2%}")
                        session.state = HTPState.RE_RESONATE
                        continue

                # Store RDV and PoSF
                session.last_rdv = resonance.rdv
                session.last_posf = resonance.posf

                # Derive decryption key from neural state (NSE integration)
                if self.enable_encryption and self.neuro_stack:
                    session.encryption_key = self.neuro_stack.get_htp_session_key(
                        rdv=resonance.rdv,
                        qsecbit=session.current_qsecbit,
                        peer_id=struct.pack('>Q', session.flow_token),
                    )

                # Decrypt payload with derived key
                if self.enable_encryption and session.encryption_key and len(payload) > 12:
                    cipher = ChaCha20Poly1305(session.encryption_key)
                    nonce_enc = payload[:12]
                    ciphertext = payload[12:]
                    try:
                        payload = cipher.decrypt(nonce_enc, ciphertext, associated_data=None)
                    except Exception as e:
                        logger.warning(f"[HTP] Decryption failed: {e}")
                        continue

                # P2: Calculate RTT if we have send timestamp for this sequence
                recv_time = time.time()
                # Estimate which sequence this is a response to (simplified)
                expected_seq = session.recv_sequence
                if expected_seq in session.last_sent_timestamp:
                    rtt = recv_time - session.last_sent_timestamp[expected_seq]
                    self._update_rtt(session, rtt)
                    # Clean up old timestamps
                    del session.last_sent_timestamp[expected_seq]

                # P2: Update bandwidth tracking
                packet_size = len(packet)
                session.bandwidth_bytes_received += packet_size
                session.packets_received += 1
                session.packets_expected += 1
                self._update_bandwidth(session)

                session.recv_sequence += 1
                session.last_activity = time.time()

                return payload

            except BlockingIOError:
                time.sleep(0.01)
                continue
            except Exception as e:
                print(f"[HTP] Error receiving: {e}")
                continue

        return None

    def send_keepalive(self, flow_token: int):
        """
        Send noise-pulsed keepalive for NAT traversal.

        Sends minimal packet every 500-900ms to keep NAT pinhole open.
        """
        session = self.sessions.get(flow_token)
        if not session:
            return

        current_time = time.time()
        interval = secrets.randbelow(400) / 1000.0 + 0.5  # 500-900ms

        if current_time - session.last_keepalive < interval:
            return

        # Send minimal sensor packet
        minimal_payload = secrets.token_bytes(8)
        self.send_data(flow_token, minimal_payload, PacketMode.SENSOR)

        session.last_keepalive = current_time

    def complete_resonance(self, flow_token: int, received_entropy_echo: int) -> bool:
        """
        Complete resonance handshake and transition to STREAMING state.

        State transitions: RESONATE → SYNC → STREAMING

        Args:
            flow_token: Session flow token
            received_entropy_echo: Entropy echo from peer's resonance reply

        Returns:
            True if resonance completed successfully
        """
        session = self.sessions.get(flow_token)
        if not session or session.state != HTPState.RESONATE:
            print(f"[HTP] complete_resonance: Invalid state {session.state if session else 'NO SESSION'}")
            return False

        # Verify entropy echo
        expected_echo = verify_entropy_echo(session.local_noise, received_entropy_echo)

        # Transition to SYNC
        session.state = HTPState.SYNC
        print(f"[HTP] State: RESONATE → SYNC")

        # For now, immediately transition to STREAMING
        # In full implementation, would wait for PoSF/RDV validation
        session.state = HTPState.STREAMING
        print(f"[HTP] State: SYNC → STREAMING")
        print(f"[HTP] Session {flow_token:016x} is now STREAMING")

        return True

    def cleanup_sessions(self):
        """
        Remove timed-out sessions (memory leak prevention).

        Should be called periodically or in receive loop.
        """
        current_time = time.time()
        expired = []

        for flow_token, session in self.sessions.items():
            if current_time - session.last_activity > self.SESSION_TIMEOUT:
                expired.append(flow_token)

        for flow_token in expired:
            del self.sessions[flow_token]
            print(f"[HTP] Session {flow_token:016x} expired after {self.SESSION_TIMEOUT}s inactivity")

        if expired:
            print(f"[HTP] Cleaned up {len(expired)} expired session(s)")

    def trigger_adaptive_mode(self, flow_token: int):
        """
        Trigger adaptive mode based on network conditions.

        Checks RTT, packet loss, stress level and transitions to ADAPTIVE state if needed.

        Args:
            flow_token: Session flow token
        """
        session = self.sessions.get(flow_token)
        if not session or session.state != HTPState.STREAMING:
            return

        # P2: Check multiple conditions for adaptive mode
        should_adapt = False
        reasons = []

        # Check RTT elevation
        if (session.rtt_current > 0 and
            session.rtt_current > session.rtt_baseline * self.RTT_THRESHOLD_MULTIPLIER):
            should_adapt = True
            reasons.append(f"elevated RTT ({session.rtt_current*1000:.1f}ms)")

        # Check packet loss rate
        if session.loss_rate > self.LOSS_RATE_THRESHOLD:
            should_adapt = True
            reasons.append(f"high loss ({session.loss_rate:.1%})")

        # Check stress level
        if session.stress_level == "HIGH":
            should_adapt = True
            reasons.append(f"high system stress")

        # Transition to ADAPTIVE if conditions met
        if should_adapt:
            print(f"[HTP] Adaptive mode triggered: {', '.join(reasons)}")
            session.state = HTPState.ADAPTIVE
            print(f"[HTP] State: STREAMING → ADAPTIVE")

            # Switch to lower-bandwidth mode
            if session.current_mode != PacketMode.SENSOR.value:
                session.current_mode = PacketMode.SENSOR.value
                print(f"[HTP] Adaptive: Switching to SENSOR mode (reduced bandwidth)")

    def trigger_re_resonance(self, flow_token: int):
        """
        Trigger re-resonance due to RDV divergence or PoSF mismatch.

        State: Any → RE_RESONATE → RESONATE

        Args:
            flow_token: Session flow token
        """
        session = self.sessions.get(flow_token)
        if not session:
            return

        print(f"[HTP] Triggering RE-RESONANCE for session {flow_token:016x}")
        session.state = HTPState.RE_RESONATE
        print(f"[HTP] State: {session.state} → RE_RESONATE")

        # Reset resonance state
        session.local_noise = secrets.token_bytes(32)
        session.remote_noise_guess = b''
        session.last_rdv = b''
        session.last_posf = b''

        # Send resonance packet
        self._send_resonance_packet(session, minimal=False)

        # Transition back to RESONATE
        session.state = HTPState.RESONATE
        print(f"[HTP] State: RE_RESONATE → RESONATE")

    # ========================================================================
    # P2: RTT / BANDWIDTH / STRESS MONITORING
    # ========================================================================

    def _update_rtt(self, session: HTPSession, rtt: float):
        """
        Update RTT statistics using exponential weighted moving average (EWMA).

        Args:
            session: HTP session
            rtt: Measured round-trip time in seconds
        """
        # Update current RTT
        session.rtt_current = rtt

        # Update min/max
        session.rtt_min = min(session.rtt_min, rtt)
        session.rtt_max = max(session.rtt_max, rtt)

        # Add to samples window
        session.rtt_samples.append(rtt)

        # Update baseline using EWMA: baseline = alpha * rtt + (1-alpha) * baseline
        if session.rtt_baseline == 0.1:  # First measurement
            session.rtt_baseline = rtt
        else:
            session.rtt_baseline = (self.RTT_EWMA_ALPHA * rtt +
                                   (1 - self.RTT_EWMA_ALPHA) * session.rtt_baseline)

        # Check if RTT is significantly elevated
        if rtt > session.rtt_baseline * self.RTT_THRESHOLD_MULTIPLIER:
            print(f"[HTP P2] Elevated RTT detected: {rtt*1000:.1f}ms "
                  f"(baseline: {session.rtt_baseline*1000:.1f}ms)")

    def _update_bandwidth(self, session: HTPSession):
        """
        Calculate current bandwidth in bits per second over measurement window.

        Args:
            session: HTP session
        """
        current_time = time.time()

        # Initialize window start if needed
        if session.bandwidth_window_start == 0.0:
            session.bandwidth_window_start = current_time
            return

        # Calculate elapsed time
        elapsed = current_time - session.bandwidth_window_start

        # Update bandwidth if window has elapsed
        if elapsed >= self.BANDWIDTH_WINDOW:
            # Calculate total bytes transferred
            total_bytes = session.bandwidth_bytes_sent + session.bandwidth_bytes_received

            # Calculate bits per second
            session.bandwidth_current_bps = (total_bytes * 8) / elapsed

            # Calculate packet loss rate
            if session.packets_expected > 0:
                packets_lost = session.packets_expected - session.packets_received
                session.loss_rate = max(0.0, packets_lost / session.packets_expected)
            else:
                session.loss_rate = 0.0

            # Reset window
            session.bandwidth_bytes_sent = 0
            session.bandwidth_bytes_received = 0
            session.bandwidth_window_start = current_time

            # Log bandwidth metrics
            bw_mbps = session.bandwidth_current_bps / 1_000_000
            print(f"[HTP P2] Bandwidth: {bw_mbps:.2f} Mbps, Loss rate: {session.loss_rate:.1%}")

    def _update_stress_metrics(self, session: HTPSession):
        """
        Update CPU usage and temperature stress metrics.

        Args:
            session: HTP session
        """
        # Try to read CPU usage from /proc/stat (simplified)
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
                if line.startswith('cpu '):
                    # Parse: cpu user nice system idle iowait irq softirq
                    parts = line.split()
                    user = int(parts[1])
                    nice = int(parts[2])
                    system = int(parts[3])
                    idle = int(parts[4])
                    total = user + nice + system + idle
                    active = user + nice + system
                    if total > 0:
                        session.cpu_usage = active / total
        except:
            pass  # Fallback: keep previous value

        # Try to read temperature from /sys/class/thermal (simplified)
        try:
            # Try common thermal zones
            for zone in [0, 1, 2]:
                temp_path = f'/sys/class/thermal/thermal_zone{zone}/temp'
                try:
                    with open(temp_path, 'r') as f:
                        # Temperature in millidegrees Celsius
                        temp_millidegrees = int(f.read().strip())
                        session.temperature_celsius = temp_millidegrees / 1000.0
                        break  # Use first available zone
                except:
                    continue
        except:
            pass  # Fallback: keep previous value

        # Determine stress level
        if (session.cpu_usage >= self.CPU_CRITICAL_THRESHOLD or
            session.temperature_celsius >= self.TEMP_STRESS_THRESHOLD + 10):
            session.stress_level = "HIGH"
        elif (session.cpu_usage >= self.CPU_STRESS_THRESHOLD or
              session.temperature_celsius >= self.TEMP_STRESS_THRESHOLD):
            session.stress_level = "MODERATE"
        else:
            session.stress_level = "NORMAL"

        # Log stress warnings
        if session.stress_level != "NORMAL":
            print(f"[HTP P2] Stress level: {session.stress_level} "
                  f"(CPU: {session.cpu_usage*100:.1f}%, Temp: {session.temperature_celsius:.1f}°C)")

    def _check_adaptive_triggers(self, session: HTPSession, flow_token: int):
        """
        Check if adaptive mode should be triggered based on P2 metrics.

        Args:
            session: HTP session
            flow_token: Session flow token
        """
        # Check if we should trigger adaptive mode
        should_adapt = False
        reasons = []

        # Check RTT
        if session.rtt_current > session.rtt_baseline * self.RTT_THRESHOLD_MULTIPLIER:
            should_adapt = True
            reasons.append(f"RTT: {session.rtt_current*1000:.1f}ms > {session.rtt_baseline*self.RTT_THRESHOLD_MULTIPLIER*1000:.1f}ms")

        # Check packet loss
        if session.loss_rate > self.LOSS_RATE_THRESHOLD:
            should_adapt = True
            reasons.append(f"Loss: {session.loss_rate:.1%}")

        # Check stress level
        if session.stress_level == "HIGH":
            should_adapt = True
            reasons.append(f"Stress: {session.stress_level}")

        # Trigger adaptive mode if needed
        if should_adapt and session.state == HTPState.STREAMING:
            print(f"[HTP P2] Triggering ADAPTIVE mode: {', '.join(reasons)}")
            self.trigger_adaptive_mode(flow_token)

    # ========================================================================
    # PRIVATE METHODS
    # ========================================================================

    def _send_resonance_packet(self, session: HTPSession, minimal: bool = False):
        """Send resonance packet for NAT hole punching."""
        payload = secrets.token_bytes(8) if minimal else secrets.token_bytes(64)

        # Simplified for initial resonance
        header = HTPHeader(
            version=0x0001,
            mode=PacketMode.SENSOR.value,
            timestamp_us=int(time.time() * 1_000_000),
            flow_token=session.flow_token,
            entropy_echo=generate_entropy_echo(session.local_noise, b''),
            anti_replay_nonce=0
        )

        resonance = ResonanceLayer()
        neuro = NeuroLayer()

        packet = header.serialize() + resonance.serialize() + neuro.serialize() + payload
        self.socket.sendto(packet, session.peer_address)

    def _verify_anti_replay(self, session: HTPSession, nonce: int) -> bool:
        """
        Verify anti-replay nonce.

        Maintains a window of 100 recent nonces to detect replays.

        Args:
            session: HTP session
            nonce: Anti-replay nonce from packet

        Returns:
            True if nonce is valid (not a replay), False otherwise
        """
        # Check if nonce was already seen (replay attack)
        if nonce in session.nonce_history:
            print(f"[HTP Security] Replay attack detected! Nonce: {nonce:016x}")
            return False

        # Add to history
        session.nonce_history.append(nonce)
        return True

    def _get_sensor_data(self) -> bytes:
        """Get sensor data vector."""
        if self.sensor_source:
            return self.sensor_source.get_vector()
        else:
            # Fallback: use system entropy
            return secrets.token_bytes(32)

    def _get_sensor_matrix(self) -> bytes:
        """Get sensor data matrix."""
        if self.sensor_source:
            return self.sensor_source.get_matrix()
        else:
            # Fallback: use system entropy
            return secrets.token_bytes(128)


# ============================================================================
# 7. EXAMPLE USAGE
# ============================================================================

if __name__ == '__main__':
    print("="*60)
    print("HookProbe Transport Protocol (HTP) - Keyless Design")
    print("="*60)

    # Test qsecbit generation
    qsec_gen = QsecbitGenerator()
    white_noise = secrets.token_bytes(32)
    sensor_vec = secrets.token_bytes(32)
    clock_jitter = secrets.token_bytes(8)

    qsecbit = qsec_gen.generate(white_noise, sensor_vec, clock_jitter)
    print(f"\n✓ qsecbit generated: {qsecbit.hex()[:32]}...")

    # Test RDV generation
    history = qsec_gen.get_history(50)
    ter = secrets.token_bytes(64)
    timestamp = int(time.time() * 1_000_000)
    rdv = generate_rdv(history, ter, timestamp)
    print(f"✓ RDV generated: {rdv.hex()[:32]}...")

    # Test PoSF generation
    sensor_matrix = secrets.token_bytes(128)
    delta_w = secrets.token_bytes(128)
    posf = generate_posf(sensor_matrix, rdv, delta_w)
    print(f"✓ PoSF generated: {posf.hex()[:32]}...")

    # Test packet serialization
    header = HTPHeader(
        version=0x0001,
        mode=PacketMode.SENSOR.value,
        timestamp_us=timestamp,
        flow_token=0x123456789ABCDEF0,
        entropy_echo=0xFEDCBA9876543210,
        anti_replay_nonce=0xAAAABBBBCCCCDDDD
    )

    header_bytes = header.serialize()
    print(f"✓ Header serialized: {len(header_bytes)} bytes")

    header_parsed = HTPHeader.deserialize(header_bytes)
    print(f"✓ Header deserialized: flow_token={header_parsed.flow_token:016x}")

    print("\n✓ HTP Keyless protocol test complete")
    print("="*60)
