"""
Port Manager - Multi-Port Fallback with Stealth Mode Support

HTP Port Selection Strategy:
┌─────────────────────────────────────────────────────────────────┐
│  HTP PORT SELECTION (UDP-First Design)                          │
├─────────────────────────────────────────────────────────────────┤
│  PRIMARY:    8144/UDP + 8144/TCP                                │
│  FALLBACK:   443/UDP (QUIC cover) + 443/TCP (TLS-wrapped)       │
│  STEALTH:    853/UDP (DoQ cover) + 853/TCP (DoT cover)          │
│  EMERGENCY:  80/TCP (WebSocket) + ICMP tunnel                   │
├─────────────────────────────────────────────────────────────────┤
│  Rationale:                                                     │
│  • HTP is UDP-native for low-latency mesh communication         │
│  • 8144: Unassigned, unlikely to conflict, 8xxx usually allowed │
│  • 443/UDP: QUIC traffic is common, perfect cover               │
│  • 443/TCP: TLS 1.3 fallback, blends with HTTPS                 │
│  • 853/UDP: DNS-over-QUIC (DoQ) cover, increasingly common      │
│  • 853/TCP: DNS-over-TLS (DoT) cover, widely allowed            │
│  • All encrypted = looks like legitimate encrypted traffic      │
│  • Configurable per-deployment for maximum flexibility          │
└─────────────────────────────────────────────────────────────────┘
"""

import socket
import time
import struct
import hashlib
import secrets
import threading
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Callable
from collections import deque


class TransportMode(Enum):
    """Transport mode determines protocol wrapping and behavior."""

    # Primary mode: Raw HTP over UDP (preferred) or TCP
    PRIMARY_UDP = auto()
    PRIMARY_TCP = auto()

    # QUIC cover: HTP disguised as QUIC traffic on 443/UDP
    # Perfect cover - QUIC is encrypted and common
    QUIC_STEALTH = auto()

    # TLS wrapped: HTP inside TLS 1.3 on 443/TCP
    # Fallback when UDP blocked, blends with HTTPS
    TLS_WRAPPED = auto()

    # DNS-over-QUIC (DoQ) cover: HTP on 853/UDP
    # Looks like legitimate encrypted DNS, very stealthy
    DOQ_STEALTH = auto()

    # DNS-over-TLS (DoT) cover: HTP on 853/TCP
    # Widely allowed, common for privacy-focused DNS
    DOT_STEALTH = auto()

    # WebSocket tunnel: HTTP/2 WebSocket on 80/443
    # Most compatible, works through most proxies
    WEBSOCKET = auto()

    # ICMP tunnel: Last resort when all ports blocked
    # Uses ICMP echo as carrier, very limited bandwidth
    ICMP_TUNNEL = auto()


class PortState(Enum):
    """State of a port binding."""
    UNKNOWN = auto()
    AVAILABLE = auto()
    BLOCKED = auto()
    DEGRADED = auto()  # Working but with issues
    PROBING = auto()


@dataclass
class PortConfig:
    """Configuration for a single port binding."""

    port: int
    protocol: str  # 'tcp', 'udp', or 'both'
    mode: TransportMode
    priority: int  # Lower = higher priority

    # TLS configuration (for TLS_WRAPPED and DOT_STEALTH)
    tls_sni: Optional[str] = None
    tls_alpn: Optional[List[str]] = None

    # Obfuscation settings
    padding_enabled: bool = True
    timing_jitter_ms: int = 50

    # Health tracking
    state: PortState = PortState.UNKNOWN
    last_success: float = 0.0
    last_failure: float = 0.0
    failure_count: int = 0
    success_count: int = 0

    # Latency tracking (rolling average)
    latency_samples: deque = field(default_factory=lambda: deque(maxlen=50))

    @property
    def avg_latency_ms(self) -> float:
        """Get average latency in milliseconds."""
        if not self.latency_samples:
            return float('inf')
        return sum(self.latency_samples) / len(self.latency_samples)

    @property
    def success_rate(self) -> float:
        """Get success rate as percentage."""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return (self.success_count / total) * 100

    def record_success(self, latency_ms: float) -> None:
        """Record successful connection."""
        self.last_success = time.time()
        self.success_count += 1
        self.failure_count = max(0, self.failure_count - 1)  # Decay failures
        self.latency_samples.append(latency_ms)

        if self.state in (PortState.BLOCKED, PortState.UNKNOWN):
            self.state = PortState.AVAILABLE

    def record_failure(self) -> None:
        """Record connection failure."""
        self.last_failure = time.time()
        self.failure_count += 1

        # Mark as blocked after 3 consecutive failures
        if self.failure_count >= 3:
            self.state = PortState.BLOCKED


# Default port configurations - UDP-first design for HTP
# Priority order: UDP variants preferred, then TCP fallbacks
DEFAULT_PORTS = [
    # === Priority 1: Primary HTP on 8144 ===
    PortConfig(
        port=8144,
        protocol='udp',
        mode=TransportMode.PRIMARY_UDP,
        priority=1,
        padding_enabled=True,
        timing_jitter_ms=0,
    ),
    PortConfig(
        port=8144,
        protocol='tcp',
        mode=TransportMode.PRIMARY_TCP,
        priority=2,
        padding_enabled=True,
        timing_jitter_ms=0,
    ),

    # === Priority 3-4: 443 Stealth (QUIC + TLS) ===
    # QUIC cover on 443/UDP - Perfect stealth, looks like HTTP/3
    PortConfig(
        port=443,
        protocol='udp',
        mode=TransportMode.QUIC_STEALTH,
        priority=3,
        padding_enabled=True,
        timing_jitter_ms=10,
    ),
    # TLS wrapped on 443/TCP - Fallback, blends with HTTPS
    PortConfig(
        port=443,
        protocol='tcp',
        mode=TransportMode.TLS_WRAPPED,
        priority=4,
        tls_sni='cloudflare.com',  # Blend with CDN traffic
        tls_alpn=['h2', 'http/1.1'],
        padding_enabled=True,
        timing_jitter_ms=25,
    ),

    # === Priority 5-6: 853 Stealth (DoQ + DoT) ===
    # DNS-over-QUIC on 853/UDP - Excellent stealth, encrypted DNS cover
    PortConfig(
        port=853,
        protocol='udp',
        mode=TransportMode.DOQ_STEALTH,
        priority=5,
        padding_enabled=True,
        timing_jitter_ms=20,
    ),
    # DNS-over-TLS on 853/TCP - Widely allowed, DNS privacy cover
    PortConfig(
        port=853,
        protocol='tcp',
        mode=TransportMode.DOT_STEALTH,
        priority=6,
        tls_sni='dns.cloudflare.com',  # Legitimate DoT endpoint
        tls_alpn=['dot'],
        padding_enabled=True,
        timing_jitter_ms=50,
    ),

    # === Priority 7+: Emergency fallbacks ===
    # WebSocket on 80/TCP - Maximum compatibility
    PortConfig(
        port=80,
        protocol='tcp',
        mode=TransportMode.WEBSOCKET,
        priority=7,
        padding_enabled=True,
        timing_jitter_ms=100,
    ),
    # WebSocket on 443/TCP (different from TLS mode - uses WS upgrade)
    PortConfig(
        port=443,
        protocol='tcp',
        mode=TransportMode.WEBSOCKET,
        priority=8,
        tls_sni='www.google.com',  # Common CDN
        tls_alpn=['http/1.1'],
        padding_enabled=True,
        timing_jitter_ms=100,
    ),
]


class BlockingDetector:
    """Detects network blocking patterns and triggers fallback."""

    # Detection thresholds
    CONSECUTIVE_FAILURES = 3
    FAILURE_RATE_THRESHOLD = 0.7  # 70% failure rate
    RST_FLOOD_THRESHOLD = 5  # RST packets in window
    TIMEOUT_PATTERN_THRESHOLD = 0.8  # 80% timeouts

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.connection_history: deque = deque(maxlen=window_size)
        self.rst_events: deque = deque(maxlen=50)
        self.timeout_events: deque = deque(maxlen=50)
        self._lock = threading.Lock()

    def record_event(
        self,
        success: bool,
        is_rst: bool = False,
        is_timeout: bool = False
    ) -> None:
        """Record a connection event."""
        now = time.time()
        with self._lock:
            self.connection_history.append((now, success))
            if is_rst:
                self.rst_events.append(now)
            if is_timeout:
                self.timeout_events.append(now)

    def is_likely_blocked(self) -> Tuple[bool, str]:
        """
        Analyze patterns to detect if port is being blocked.

        Returns:
            Tuple of (is_blocked, reason)
        """
        with self._lock:
            now = time.time()
            window_start = now - 60  # Last 60 seconds

            # Check consecutive failures
            recent = [s for t, s in self.connection_history if t > window_start]
            if len(recent) >= self.CONSECUTIVE_FAILURES:
                consecutive_fail = all(not s for s in recent[-self.CONSECUTIVE_FAILURES:])
                if consecutive_fail:
                    return True, "consecutive_failures"

            # Check failure rate
            if len(recent) >= 10:
                failure_rate = sum(1 for s in recent if not s) / len(recent)
                if failure_rate >= self.FAILURE_RATE_THRESHOLD:
                    return True, f"high_failure_rate:{failure_rate:.1%}"

            # Check RST flood (active blocking)
            rst_recent = [t for t in self.rst_events if t > window_start]
            if len(rst_recent) >= self.RST_FLOOD_THRESHOLD:
                return True, "rst_flood"

            # Check timeout pattern (passive blocking/throttling)
            timeout_recent = [t for t in self.timeout_events if t > window_start]
            if len(timeout_recent) >= 5:
                timeout_rate = len(timeout_recent) / len(recent) if recent else 1.0
                if timeout_rate >= self.TIMEOUT_PATTERN_THRESHOLD:
                    return True, f"timeout_pattern:{timeout_rate:.1%}"

            return False, "ok"


class PortManager:
    """
    Manages multi-port communication with automatic fallback.

    Features:
    - Priority-based port selection
    - Automatic blocking detection
    - Health monitoring and recovery
    - Stealth mode switching
    """

    def __init__(
        self,
        ports: Optional[List[PortConfig]] = None,
        probe_interval: float = 30.0,
        recovery_interval: float = 300.0,
    ):
        """
        Initialize port manager.

        Args:
            ports: List of port configurations (uses defaults if None)
            probe_interval: Seconds between health probes
            recovery_interval: Seconds before retrying blocked ports
        """
        self.ports = ports or list(DEFAULT_PORTS)
        self.probe_interval = probe_interval
        self.recovery_interval = recovery_interval

        # Per-port blocking detectors
        self.detectors: Dict[int, BlockingDetector] = {
            p.port: BlockingDetector() for p in self.ports
        }

        # Current active port
        self._active_port: Optional[PortConfig] = None
        self._lock = threading.RLock()

        # Callbacks
        self._on_port_change: List[Callable[[PortConfig, PortConfig], None]] = []
        self._on_blocking_detected: List[Callable[[PortConfig, str], None]] = []

        # Background probe thread
        self._probe_thread: Optional[threading.Thread] = None
        self._stop_probe = threading.Event()

    @property
    def active_port(self) -> Optional[PortConfig]:
        """Get the currently active port configuration."""
        with self._lock:
            return self._active_port

    def select_best_port(self) -> Optional[PortConfig]:
        """
        Select the best available port based on priority and health.

        Selection criteria:
        1. Port is not blocked
        2. Lowest priority number (highest priority)
        3. Best success rate
        4. Lowest latency

        Returns:
            Best available PortConfig or None if all blocked
        """
        with self._lock:
            available = [
                p for p in self.ports
                if p.state != PortState.BLOCKED
            ]

            if not available:
                # All ports blocked - try recovery
                return self._attempt_recovery()

            # Sort by: priority, success_rate (desc), latency (asc)
            available.sort(
                key=lambda p: (
                    p.priority,
                    -p.success_rate,
                    p.avg_latency_ms,
                )
            )

            best = available[0]

            # Notify if port changed
            if self._active_port != best:
                old_port = self._active_port
                self._active_port = best
                self._notify_port_change(old_port, best)

            return best

    def _attempt_recovery(self) -> Optional[PortConfig]:
        """Attempt to recover a blocked port for emergency use."""
        now = time.time()

        # Find port blocked longest ago
        recoverable = [
            p for p in self.ports
            if p.state == PortState.BLOCKED
            and (now - p.last_failure) > self.recovery_interval
        ]

        if recoverable:
            # Sort by priority and try lowest priority blocked port
            recoverable.sort(key=lambda p: p.priority)
            port = recoverable[0]
            port.state = PortState.PROBING
            port.failure_count = 0
            return port

        return None

    def record_connection(
        self,
        port: int,
        success: bool,
        latency_ms: float = 0.0,
        is_rst: bool = False,
        is_timeout: bool = False,
    ) -> None:
        """
        Record connection attempt result.

        Args:
            port: Port number
            success: Whether connection succeeded
            latency_ms: Connection latency (on success)
            is_rst: Whether failure was due to RST packet
            is_timeout: Whether failure was due to timeout
        """
        with self._lock:
            port_config = self._get_port_config(port)
            if not port_config:
                return

            # Record in detector
            detector = self.detectors.get(port)
            if detector:
                detector.record_event(success, is_rst, is_timeout)

            # Update port stats
            if success:
                port_config.record_success(latency_ms)
            else:
                port_config.record_failure()

                # Check for blocking
                if detector:
                    is_blocked, reason = detector.is_likely_blocked()
                    if is_blocked and port_config.state != PortState.BLOCKED:
                        port_config.state = PortState.BLOCKED
                        self._notify_blocking_detected(port_config, reason)

                        # Trigger port change
                        self.select_best_port()

    def _get_port_config(self, port: int) -> Optional[PortConfig]:
        """Get port configuration by port number."""
        for p in self.ports:
            if p.port == port:
                return p
        return None

    def probe_port(self, port_config: PortConfig, target: str) -> bool:
        """
        Probe a port to check if it's available.

        Args:
            port_config: Port configuration to probe
            target: Target host to probe

        Returns:
            True if port is available
        """
        start = time.time()

        try:
            if port_config.protocol in ('tcp', 'both'):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((target, port_config.port))
                sock.close()

            latency = (time.time() - start) * 1000
            self.record_connection(
                port_config.port,
                success=True,
                latency_ms=latency
            )
            return True

        except socket.timeout:
            self.record_connection(
                port_config.port,
                success=False,
                is_timeout=True
            )
            return False

        except ConnectionRefusedError:
            self.record_connection(
                port_config.port,
                success=False,
                is_rst=True
            )
            return False

        except Exception:
            self.record_connection(port_config.port, success=False)
            return False

    def start_health_monitoring(self, target: str) -> None:
        """Start background health monitoring thread."""
        if self._probe_thread and self._probe_thread.is_alive():
            return

        self._stop_probe.clear()
        self._probe_thread = threading.Thread(
            target=self._health_monitor_loop,
            args=(target,),
            daemon=True,
        )
        self._probe_thread.start()

    def stop_health_monitoring(self) -> None:
        """Stop background health monitoring."""
        self._stop_probe.set()
        if self._probe_thread:
            self._probe_thread.join(timeout=5.0)

    def _health_monitor_loop(self, target: str) -> None:
        """Background health monitoring loop."""
        while not self._stop_probe.is_set():
            for port_config in self.ports:
                if self._stop_probe.is_set():
                    break

                # Skip probing the active port too frequently
                if port_config == self._active_port:
                    continue

                # Probe blocked ports for recovery
                if port_config.state == PortState.BLOCKED:
                    now = time.time()
                    if (now - port_config.last_failure) > self.recovery_interval:
                        self.probe_port(port_config, target)

            self._stop_probe.wait(self.probe_interval)

    def on_port_change(
        self,
        callback: Callable[[PortConfig, PortConfig], None]
    ) -> None:
        """Register callback for port change events."""
        self._on_port_change.append(callback)

    def on_blocking_detected(
        self,
        callback: Callable[[PortConfig, str], None]
    ) -> None:
        """Register callback for blocking detection events."""
        self._on_blocking_detected.append(callback)

    def _notify_port_change(
        self,
        old_port: Optional[PortConfig],
        new_port: PortConfig
    ) -> None:
        """Notify listeners of port change."""
        for callback in self._on_port_change:
            try:
                callback(old_port, new_port)
            except Exception:
                pass  # Don't let callback errors break the manager

    def _notify_blocking_detected(
        self,
        port_config: PortConfig,
        reason: str
    ) -> None:
        """Notify listeners of blocking detection."""
        for callback in self._on_blocking_detected:
            try:
                callback(port_config, reason)
            except Exception:
                pass

    def get_status(self) -> Dict:
        """Get current status of all ports."""
        with self._lock:
            return {
                'active_port': self._active_port.port if self._active_port else None,
                'active_mode': self._active_port.mode.name if self._active_port else None,
                'ports': [
                    {
                        'port': p.port,
                        'protocol': p.protocol,
                        'mode': p.mode.name,
                        'state': p.state.name,
                        'priority': p.priority,
                        'success_rate': f"{p.success_rate:.1f}%",
                        'avg_latency_ms': f"{p.avg_latency_ms:.1f}",
                        'failure_count': p.failure_count,
                    }
                    for p in sorted(self.ports, key=lambda x: x.priority)
                ]
            }


class TrafficObfuscator:
    """
    Obfuscates HTP traffic to avoid DPI detection.

    Techniques:
    - Random padding to normalize packet sizes
    - Timing jitter to break statistical patterns
    - Entropy injection to appear as random noise
    - Protocol mimicry for stealth modes
    """

    # Target packet sizes for padding (mimic common protocols)
    PADDING_TARGETS = [64, 128, 256, 512, 1024, 1280, 1400]

    def __init__(self, mode: TransportMode):
        self.mode = mode
        self._rng = secrets.SystemRandom()

    def obfuscate(
        self,
        data: bytes,
        add_padding: bool = True,
        add_jitter: bool = True,
        jitter_ms: int = 50,
    ) -> Tuple[bytes, float]:
        """
        Obfuscate data before transmission.

        Args:
            data: Original data to obfuscate
            add_padding: Whether to add random padding
            add_jitter: Whether to add timing jitter
            jitter_ms: Maximum jitter in milliseconds

        Returns:
            Tuple of (obfuscated_data, delay_seconds)
        """
        result = data
        delay = 0.0

        # Add padding to reach target size
        if add_padding:
            result = self._add_padding(result)

        # Calculate jitter delay
        if add_jitter:
            delay = self._rng.uniform(0, jitter_ms / 1000.0)

        # Mode-specific obfuscation
        if self.mode == TransportMode.TLS_WRAPPED:
            result = self._wrap_tls_style(result)
        elif self.mode == TransportMode.QUIC_STEALTH:
            result = self._wrap_quic_style(result)
        elif self.mode == TransportMode.DOT_STEALTH:
            result = self._wrap_dot_style(result)
        elif self.mode == TransportMode.DOQ_STEALTH:
            result = self._wrap_doq_style(result)
        elif self.mode == TransportMode.WEBSOCKET:
            result = self._wrap_websocket_style(result)
        # PRIMARY_UDP and PRIMARY_TCP don't need wrapping

        return result, delay

    def deobfuscate(self, data: bytes) -> bytes:
        """
        Remove obfuscation from received data.

        Args:
            data: Obfuscated data

        Returns:
            Original data
        """
        # Mode-specific unwrapping
        if self.mode == TransportMode.TLS_WRAPPED:
            data = self._unwrap_tls_style(data)
        elif self.mode == TransportMode.QUIC_STEALTH:
            data = self._unwrap_quic_style(data)
        elif self.mode == TransportMode.DOT_STEALTH:
            data = self._unwrap_dot_style(data)
        elif self.mode == TransportMode.DOQ_STEALTH:
            data = self._unwrap_doq_style(data)
        elif self.mode == TransportMode.WEBSOCKET:
            data = self._unwrap_websocket_style(data)
        # PRIMARY_UDP and PRIMARY_TCP don't need unwrapping

        # Remove padding
        return self._remove_padding(data)

    def _add_padding(self, data: bytes) -> bytes:
        """Add random padding to reach a target size."""
        current_len = len(data) + 4  # +4 for length prefix

        # Find smallest target that fits
        target = current_len
        for size in self.PADDING_TARGETS:
            if size >= current_len:
                target = size
                break
        else:
            # Data larger than max target, pad to next 64-byte boundary
            target = ((current_len + 63) // 64) * 64

        padding_len = target - current_len
        padding = secrets.token_bytes(padding_len)

        # Format: [original_len:4][original_data][random_padding]
        return struct.pack('>I', len(data)) + data + padding

    def _remove_padding(self, data: bytes) -> bytes:
        """Remove padding from data."""
        if len(data) < 4:
            return data

        original_len = struct.unpack('>I', data[:4])[0]
        if original_len + 4 > len(data):
            return data  # Invalid, return as-is

        return data[4:4 + original_len]

    def _wrap_tls_style(self, data: bytes) -> bytes:
        """Wrap data to look like TLS Application Data."""
        # TLS 1.3 Application Data: 0x17 0x03 0x03 [length:2] [data]
        header = struct.pack('>BBB', 0x17, 0x03, 0x03)
        length = struct.pack('>H', len(data))
        return header + length + data

    def _unwrap_tls_style(self, data: bytes) -> bytes:
        """Unwrap TLS-style wrapped data."""
        if len(data) < 5:
            return data
        if data[0] == 0x17 and data[1:3] == b'\x03\x03':
            length = struct.unpack('>H', data[3:5])[0]
            return data[5:5 + length]
        return data

    def _wrap_dot_style(self, data: bytes) -> bytes:
        """Wrap data to look like DNS-over-TLS message."""
        # DoT uses TCP with 2-byte length prefix, then DNS message
        # We'll prepend a fake DNS header to look like a query
        dns_header = struct.pack(
            '>HHHHHH',
            self._rng.randint(0, 65535),  # Transaction ID
            0x0100,  # Flags: Standard query
            1,  # Questions
            0,  # Answers
            0,  # Authority
            0,  # Additional
        )
        # Fake question: random subdomain of cloudflare.com
        fake_query = self._generate_fake_dns_query()

        # Actual data goes in the "additional" section as TXT record
        total = dns_header + fake_query + data
        length_prefix = struct.pack('>H', len(total))
        return length_prefix + total

    def _unwrap_dot_style(self, data: bytes) -> bytes:
        """Unwrap DoT-style wrapped data."""
        if len(data) < 2:
            return data
        length = struct.unpack('>H', data[:2])[0]
        if length + 2 > len(data):
            return data

        # Skip DNS header (12 bytes) and find our data
        dns_data = data[2:2 + length]
        if len(dns_data) < 12:
            return data

        # Skip header and query section to get to our data
        pos = 12
        while pos < len(dns_data) and dns_data[pos] != 0:
            pos += dns_data[pos] + 1
        pos += 5  # Skip null terminator and QTYPE/QCLASS

        if pos < len(dns_data):
            return dns_data[pos:]
        return data

    def _generate_fake_dns_query(self) -> bytes:
        """Generate a fake DNS query that looks legitimate."""
        # Random subdomain
        subdomain = secrets.token_hex(8)
        labels = [subdomain.encode(), b'cdn', b'cloudflare', b'com']

        query = b''
        for label in labels:
            query += struct.pack('B', len(label)) + label
        query += b'\x00'  # Root label
        query += struct.pack('>HH', 1, 1)  # Type A, Class IN

        return query

    def _wrap_websocket_style(self, data: bytes) -> bytes:
        """Wrap data as WebSocket binary frame."""
        # WebSocket frame: FIN=1, RSV=0, Opcode=2 (binary)
        first_byte = 0x82

        if len(data) <= 125:
            second_byte = len(data) | 0x80  # Mask bit set (client->server)
            header = struct.pack('BB', first_byte, second_byte)
        elif len(data) <= 65535:
            second_byte = 126 | 0x80
            header = struct.pack('>BBH', first_byte, second_byte, len(data))
        else:
            second_byte = 127 | 0x80
            header = struct.pack('>BBQ', first_byte, second_byte, len(data))

        # Generate masking key and mask data
        mask_key = secrets.token_bytes(4)
        masked_data = bytes(
            b ^ mask_key[i % 4] for i, b in enumerate(data)
        )

        return header + mask_key + masked_data

    def _unwrap_websocket_style(self, data: bytes) -> bytes:
        """Unwrap WebSocket-style frame."""
        if len(data) < 2:
            return data

        first_byte = data[0]
        second_byte = data[1]

        # Check if it's a binary frame
        if (first_byte & 0x0F) != 0x02:
            return data

        masked = bool(second_byte & 0x80)
        length = second_byte & 0x7F
        pos = 2

        if length == 126:
            if len(data) < 4:
                return data
            length = struct.unpack('>H', data[2:4])[0]
            pos = 4
        elif length == 127:
            if len(data) < 10:
                return data
            length = struct.unpack('>Q', data[2:10])[0]
            pos = 10

        if masked:
            if len(data) < pos + 4:
                return data
            mask_key = data[pos:pos + 4]
            pos += 4
            payload = data[pos:pos + length]
            return bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        return data[pos:pos + length]

    def _wrap_quic_style(self, data: bytes) -> bytes:
        """
        Wrap data to look like QUIC Initial/Handshake packet.

        QUIC is the perfect cover for UDP traffic because:
        - It's encrypted and looks like random data
        - Very common (HTTP/3, Google services)
        - Uses 443/UDP which is usually allowed
        - Connection IDs provide session tracking

        QUIC Long Header Format (simplified):
        [Header Form:1=Long][Fixed:1][Type:2][Version:4][DCID Len:1][DCID:var][SCID Len:1][SCID:var]
        """
        # QUIC version 1 (RFC 9000)
        quic_version = 0x00000001

        # Generate random connection IDs (8 bytes each, common size)
        dcid = secrets.token_bytes(8)  # Destination Connection ID
        scid = secrets.token_bytes(8)  # Source Connection ID

        # Long header: Form=1, Fixed=1, Type=00 (Initial), Reserved=00
        # Bits: 1 1 00 00 00 = 0xC0
        header_byte = 0xC0

        # Build header
        header = struct.pack(
            '>BI',
            header_byte,
            quic_version,
        )
        header += struct.pack('B', len(dcid)) + dcid
        header += struct.pack('B', len(scid)) + scid

        # Token length (0 for our purposes, but include field)
        # Variable-length integer encoding for token length
        header += struct.pack('B', 0)  # Token length = 0

        # Payload length (variable-length integer, 2-byte form for simplicity)
        # 0x40 | (length >> 8), length & 0xFF for lengths 64-16383
        payload_len = len(data) + 16  # +16 for fake packet number and auth tag
        if payload_len < 64:
            header += struct.pack('B', payload_len)
        else:
            header += struct.pack('>H', 0x4000 | payload_len)

        # Fake packet number (4 bytes) - will be encrypted in real QUIC
        pkt_num = secrets.token_bytes(4)

        # Our data as "encrypted" payload (already encrypted by HTP)
        # Add fake AEAD tag (16 bytes) to look authentic
        fake_tag = secrets.token_bytes(16)

        return header + pkt_num + data + fake_tag

    def _unwrap_quic_style(self, data: bytes) -> bytes:
        """Unwrap QUIC-style wrapped data."""
        if len(data) < 10:
            return data

        # Check for long header (bit 7 set)
        if not (data[0] & 0x80):
            return data  # Short header, not our format

        # Skip header byte and version
        pos = 5

        # Skip DCID
        if pos >= len(data):
            return data
        dcid_len = data[pos]
        pos += 1 + dcid_len

        # Skip SCID
        if pos >= len(data):
            return data
        scid_len = data[pos]
        pos += 1 + scid_len

        # Skip token length (variable-length integer)
        if pos >= len(data):
            return data
        token_len = data[pos]
        if token_len & 0xC0 == 0x40:  # 2-byte form
            if pos + 1 >= len(data):
                return data
            token_len = ((token_len & 0x3F) << 8) | data[pos + 1]
            pos += 2
        else:
            pos += 1
        pos += token_len

        # Read payload length
        if pos >= len(data):
            return data
        payload_len = data[pos]
        if payload_len & 0xC0 == 0x40:  # 2-byte form
            if pos + 1 >= len(data):
                return data
            payload_len = ((payload_len & 0x3F) << 8) | data[pos + 1]
            pos += 2
        else:
            pos += 1

        # Skip packet number (4 bytes)
        pos += 4

        # Extract payload (minus 16-byte fake tag)
        if pos + 16 >= len(data):
            return data

        return data[pos:len(data) - 16]

    def _wrap_doq_style(self, data: bytes) -> bytes:
        """
        Wrap data to look like DNS-over-QUIC (DoQ) traffic.

        DoQ (RFC 9250) uses QUIC for DNS queries. It's excellent cover because:
        - Uses 853/UDP (same as DoT but UDP)
        - Encrypted DNS is increasingly common
        - Traffic patterns are bursty (like security telemetry)
        - Multiple DNS resolvers support it (Cloudflare, Google, etc.)

        Format: QUIC packet containing DNS wire format message
        """
        # Generate fake DNS query to embed
        fake_dns = self._generate_dns_query_for_doq()

        # Combine fake DNS with our actual data
        # Real DoQ would have DNS in QUIC stream, we embed our data after
        combined = fake_dns + struct.pack('>H', len(data)) + data

        # Wrap in QUIC-style packet
        return self._wrap_quic_style(combined)

    def _unwrap_doq_style(self, data: bytes) -> bytes:
        """Unwrap DoQ-style wrapped data."""
        # First unwrap QUIC layer
        quic_payload = self._unwrap_quic_style(data)

        if len(quic_payload) < 14:  # Minimum DNS header + our length prefix
            return data

        # Skip past the fake DNS query to find our data
        # DNS header is 12 bytes, then question section
        pos = 12

        # Skip question section (QNAME + QTYPE + QCLASS)
        while pos < len(quic_payload) and quic_payload[pos] != 0:
            label_len = quic_payload[pos]
            pos += 1 + label_len
        pos += 5  # null terminator + QTYPE(2) + QCLASS(2)

        if pos + 2 > len(quic_payload):
            return data

        # Read our data length
        our_len = struct.unpack('>H', quic_payload[pos:pos + 2])[0]
        pos += 2

        if pos + our_len > len(quic_payload):
            return data

        return quic_payload[pos:pos + our_len]

    def _generate_dns_query_for_doq(self) -> bytes:
        """Generate a fake DNS query for DoQ wrapping."""
        # DNS header
        transaction_id = self._rng.randint(0, 65535)
        flags = 0x0100  # Standard query, recursion desired
        questions = 1
        answers = 0
        authority = 0
        additional = 0

        header = struct.pack(
            '>HHHHHH',
            transaction_id,
            flags,
            questions,
            answers,
            authority,
            additional,
        )

        # Question section - random subdomain of a common domain
        subdomain = secrets.token_hex(6)
        domains = [
            (subdomain, 'api', 'cloudflare', 'com'),
            (subdomain, 'dns', 'google', 'com'),
            (subdomain, 'resolver', 'quad9', 'net'),
        ]
        labels = domains[self._rng.randint(0, len(domains) - 1)]

        question = b''
        for label in labels:
            label_bytes = label.encode() if isinstance(label, str) else label
            question += struct.pack('B', len(label_bytes)) + label_bytes
        question += b'\x00'  # Root label
        question += struct.pack('>HH', 1, 1)  # Type A, Class IN

        return header + question
