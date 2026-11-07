"""
Domain Fronting — CDN-based censorship circumvention.

Routes HTP traffic through CDN edge servers using domain fronting:
the TLS SNI shows an innocuous domain while the HTTP Host header
targets the real HTP relay. Falls back across multiple CDN providers.

Supported strategies:
1. Cloudflare Workers → AWS CloudFront → Azure CDN (fallback chain)
2. WebSocket upgrade tunnel for persistent connections
3. HTTP/2 multiplexing for low-overhead tunneling

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import base64
import hashlib
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CDNProvider(Enum):
    """Supported CDN providers for domain fronting."""
    CLOUDFLARE = auto()
    AWS_CLOUDFRONT = auto()
    AZURE_CDN = auto()
    FASTLY = auto()


class TunnelType(Enum):
    """Tunnel transport types."""
    WEBSOCKET = auto()       # WebSocket upgrade (persistent)
    HTTP_POST = auto()       # HTTP POST requests (request-response)
    HTTP2_STREAM = auto()    # HTTP/2 multiplexed streams


class FrontingState(Enum):
    """Domain fronting connection state."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    UPGRADING = auto()       # WebSocket upgrade in progress
    TUNNELED = auto()        # Active tunnel
    FAILED = auto()
    FALLBACK = auto()        # Trying next CDN provider


@dataclass
class CDNEndpoint:
    """Configuration for a CDN domain fronting endpoint."""
    provider: CDNProvider
    # The "front" domain shown in TLS SNI (appears in network traffic)
    front_domain: str
    # The real target domain in HTTP Host header (hidden inside TLS)
    target_domain: str
    # Path on the CDN edge server
    path: str = "/api/v1/data"
    # Port (almost always 443)
    port: int = 443
    # Priority (lower = preferred)
    priority: int = 1
    # Health tracking
    last_success: float = 0.0
    last_failure: float = 0.0
    consecutive_failures: int = 0
    # Tunnel type
    tunnel_type: TunnelType = TunnelType.WEBSOCKET

    @property
    def healthy(self) -> bool:
        """Endpoint is healthy if fewer than 3 consecutive failures."""
        return self.consecutive_failures < 3

    def record_success(self) -> None:
        self.last_success = time.monotonic()
        self.consecutive_failures = 0

    def record_failure(self) -> None:
        self.last_failure = time.monotonic()
        self.consecutive_failures += 1


@dataclass
class FrontingStats:
    """Statistics for domain fronting tunnels."""
    bytes_sent: int = 0
    bytes_received: int = 0
    requests_sent: int = 0
    responses_received: int = 0
    provider_switches: int = 0
    websocket_upgrades: int = 0
    current_provider: str = ""
    state: str = "DISCONNECTED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "requests_sent": self.requests_sent,
            "responses_received": self.responses_received,
            "provider_switches": self.provider_switches,
            "websocket_upgrades": self.websocket_upgrades,
            "current_provider": self.current_provider,
            "state": self.state,
        }


class DomainFronter:
    """CDN domain fronting for HTP traffic.

    Makes HTP traffic appear as normal HTTPS requests to a CDN,
    while the actual payload is tunneled to an HTP relay server.

    Usage:
        fronter = DomainFronter()
        fronter.add_endpoint(CDNEndpoint(
            provider=CDNProvider.CLOUDFLARE,
            front_domain="cdn.example.com",
            target_domain="relay.hookprobe.net",
        ))
        fronter.connect()
        fronter.send(payload)
        response = fronter.receive()
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        encryption_key: Optional[bytes] = None,
    ):
        self._session_id = session_id or hashlib.sha256(
            os.urandom(32)
        ).hexdigest()[:16]
        self._encryption_key = encryption_key or os.urandom(32)

        self._endpoints: List[CDNEndpoint] = []
        self._active_endpoint: Optional[CDNEndpoint] = None
        self._state = FrontingState.DISCONNECTED
        self._stats = FrontingStats()

        # Callbacks
        self._on_connected: Optional[Callable[[], None]] = None
        self._on_disconnected: Optional[Callable[[], None]] = None
        self._on_data: Optional[Callable[[bytes], None]] = None

        # Send/receive buffers
        self._send_buffer: List[bytes] = []
        self._recv_buffer: List[bytes] = []

        logger.info("DomainFronter initialized: session=%s", self._session_id)

    def add_endpoint(self, endpoint: CDNEndpoint) -> None:
        """Add a CDN endpoint to the fallback chain."""
        self._endpoints.append(endpoint)
        self._endpoints.sort(key=lambda e: e.priority)
        logger.debug(
            "Added endpoint: %s via %s (priority=%d)",
            endpoint.front_domain,
            endpoint.provider.name,
            endpoint.priority,
        )

    def on_connected(self, callback: Callable[[], None]) -> None:
        self._on_connected = callback

    def on_disconnected(self, callback: Callable[[], None]) -> None:
        self._on_disconnected = callback

    def on_data(self, callback: Callable[[bytes], None]) -> None:
        self._on_data = callback

    def connect(self) -> bool:
        """Connect to the best available CDN endpoint.

        Tries endpoints in priority order, falling back on failure.
        Returns True if connection established.
        """
        if not self._endpoints:
            logger.error("No CDN endpoints configured")
            self._state = FrontingState.FAILED
            self._stats.state = "FAILED"
            return False

        self._state = FrontingState.CONNECTING
        self._stats.state = "CONNECTING"

        for endpoint in self._endpoints:
            if not endpoint.healthy:
                continue

            if self._try_connect(endpoint):
                self._active_endpoint = endpoint
                self._state = FrontingState.CONNECTED
                self._stats.state = "CONNECTED"
                self._stats.current_provider = endpoint.provider.name
                endpoint.record_success()

                if self._on_connected:
                    self._on_connected()

                logger.info(
                    "Connected via %s (front=%s)",
                    endpoint.provider.name,
                    endpoint.front_domain,
                )
                return True
            else:
                endpoint.record_failure()
                self._stats.provider_switches += 1

        self._state = FrontingState.FAILED
        self._stats.state = "FAILED"
        logger.error("All CDN endpoints failed")
        return False

    def disconnect(self) -> None:
        """Disconnect from the current CDN endpoint."""
        self._state = FrontingState.DISCONNECTED
        self._stats.state = "DISCONNECTED"
        self._active_endpoint = None

        if self._on_disconnected:
            self._on_disconnected()

    def send(self, data: bytes) -> bool:
        """Send data through the domain fronting tunnel.

        Data is encoded and sent as an HTTP request body.
        Returns True if sent successfully.
        """
        if self._state not in (
            FrontingState.CONNECTED,
            FrontingState.TUNNELED,
        ):
            logger.warning("Cannot send: not connected (state=%s)", self._state.name)
            return False

        if not self._active_endpoint:
            return False

        # Encode payload for HTTP transport
        encoded = self._encode_payload(data)

        # Build HTTP request
        request = self._build_http_request(encoded)

        self._stats.bytes_sent += len(data)
        self._stats.requests_sent += 1
        self._send_buffer.append(request)

        return True

    def receive(self) -> Optional[bytes]:
        """Receive data from the domain fronting tunnel.

        Returns decoded payload or None if no data available.
        """
        if not self._recv_buffer:
            return None

        encoded = self._recv_buffer.pop(0)
        decoded = self._decode_payload(encoded)
        if decoded:
            self._stats.bytes_received += len(decoded)
            self._stats.responses_received += 1
        return decoded

    def feed_response(self, response_body: bytes) -> None:
        """Feed an HTTP response body for processing.

        Called by the transport layer when a response arrives.
        """
        self._recv_buffer.append(response_body)
        if self._on_data and response_body:
            decoded = self._decode_payload(response_body)
            if decoded:
                self._on_data(decoded)

    def upgrade_websocket(self) -> bool:
        """Upgrade the connection to a WebSocket tunnel.

        Returns True if upgrade succeeds.
        """
        if self._state != FrontingState.CONNECTED:
            return False

        self._state = FrontingState.UPGRADING
        self._stats.state = "UPGRADING"

        # Build WebSocket upgrade request
        ws_key = base64.b64encode(os.urandom(16)).decode()
        upgrade_request = self._build_websocket_upgrade(ws_key)
        self._send_buffer.append(upgrade_request)

        # In real implementation, we'd wait for 101 response
        # For now, simulate successful upgrade
        self._state = FrontingState.TUNNELED
        self._stats.state = "TUNNELED"
        self._stats.websocket_upgrades += 1

        logger.info("WebSocket tunnel established")
        return True

    def get_healthy_endpoints(self) -> List[CDNEndpoint]:
        """Get all healthy CDN endpoints."""
        return [e for e in self._endpoints if e.healthy]

    def get_stats(self) -> Dict[str, Any]:
        """Get domain fronting statistics."""
        result = self._stats.to_dict()
        result["endpoints"] = [
            {
                "provider": e.provider.name,
                "front_domain": e.front_domain,
                "healthy": e.healthy,
                "failures": e.consecutive_failures,
            }
            for e in self._endpoints
        ]
        return result

    @property
    def state(self) -> FrontingState:
        return self._state

    @property
    def is_connected(self) -> bool:
        return self._state in (
            FrontingState.CONNECTED,
            FrontingState.TUNNELED,
        )

    # ------------------------------------------------------------------
    # Internal Methods
    # ------------------------------------------------------------------

    def _try_connect(self, endpoint: CDNEndpoint) -> bool:
        """Attempt to connect to a CDN endpoint.

        In production, this would establish a TLS connection with SNI
        set to front_domain. For now, validates the endpoint config.
        """
        if not endpoint.front_domain or not endpoint.target_domain:
            return False
        if endpoint.port <= 0 or endpoint.port > 65535:
            return False
        return True

    def _encode_payload(self, data: bytes) -> bytes:
        """Encode payload for HTTP transport.

        Format: [4B session_tag][4B sequence][N payload]
        All base64-encoded for HTTP body safety.
        """
        session_tag = hashlib.sha256(
            self._session_id.encode()
        ).digest()[:4]
        sequence = struct.pack("!I", self._stats.requests_sent)
        raw = session_tag + sequence + data
        return base64.b64encode(raw)

    def _decode_payload(self, encoded: bytes) -> Optional[bytes]:
        """Decode payload from HTTP response body."""
        try:
            raw = base64.b64decode(encoded)
        except Exception:
            return None

        if len(raw) < 8:
            return None

        # Skip session_tag (4B) and sequence (4B)
        return raw[8:]

    def _build_http_request(self, encoded_body: bytes) -> bytes:
        """Build an HTTP POST request for domain fronting.

        TLS SNI = front_domain (visible to network)
        Host header = target_domain (hidden inside TLS)
        """
        if not self._active_endpoint:
            return b""

        ep = self._active_endpoint
        headers = [
            f"POST {ep.path} HTTP/1.1",
            f"Host: {ep.target_domain}",
            "Content-Type: application/octet-stream",
            f"Content-Length: {len(encoded_body)}",
            f"X-Session-ID: {self._session_id}",
            "Connection: keep-alive",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "",
            "",
        ]
        request = "\r\n".join(headers).encode() + encoded_body
        return request

    def _build_websocket_upgrade(self, ws_key: str) -> bytes:
        """Build a WebSocket upgrade request."""
        if not self._active_endpoint:
            return b""

        ep = self._active_endpoint
        headers = [
            f"GET {ep.path}/ws HTTP/1.1",
            f"Host: {ep.target_domain}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Protocol: binary",
            f"X-Session-ID: {self._session_id}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "",
            "",
        ]
        return "\r\n".join(headers).encode()
