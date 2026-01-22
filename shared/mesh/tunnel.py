#!/usr/bin/env python3
"""
HookProbe Tunnel Integration Module
"Public Presence Without Public IP"

Version: 5.0.0

Enables mesh nodes to become relay/STUN servers without public IPs
by using tunnel services (Cloudflare Tunnel, ngrok, Tailscale Funnel).

Architecture:
1. Fortress/Nexus runs tunnel client (cloudflared, ngrok, etc.)
2. Gets stable FQDN (e.g., fortress-01.hookprobe.com)
3. Registers FQDN with mesh registry as trusted relay endpoint
4. Admin approves the tunnel registration
5. Other nodes use the FQDN for relay/signaling

Supported Providers:
- Cloudflare Tunnel (cloudflared) - Recommended, free tier
- ngrok - Easy setup, limited free tier
- Tailscale Funnel - Good for existing Tailscale users
- Custom - Bring your own tunnel solution
"""

import os
import sys
import json
import time
import socket
import hashlib
import logging
import subprocess
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Callable, Any
from threading import Thread, Lock, Event
from pathlib import Path
import urllib.request
import urllib.error

logger = logging.getLogger("mesh.tunnel")


# ============================================================
# ENUMS AND CONSTANTS
# ============================================================

class TunnelProvider(Enum):
    """Supported tunnel providers"""
    CLOUDFLARE = "cloudflare"
    NGROK = "ngrok"
    TAILSCALE = "tailscale"
    CUSTOM = "custom"


class TunnelStatus(Enum):
    """Tunnel connection status"""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    ERROR = auto()
    PENDING_APPROVAL = auto()
    APPROVED = auto()
    REJECTED = auto()


class RegistrationStatus(Enum):
    """Mesh registry registration status"""
    UNREGISTERED = auto()
    PENDING = auto()
    APPROVED = auto()
    REJECTED = auto()
    EXPIRED = auto()


# Default ports for tunnel services
TUNNEL_PORTS = {
    "relay": 3478,      # TURN relay
    "signaling": 8144,  # Mesh signaling
    "websocket": 8080,  # WebSocket relay
    "health": 9090,     # Health check
}


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class TunnelEndpoint:
    """A tunnel endpoint that can be used by mesh nodes"""
    node_id: str
    provider: TunnelProvider
    fqdn: str
    ports: Dict[str, int] = field(default_factory=dict)  # service -> port
    region: str = "unknown"
    tier: str = "fortress"
    status: TunnelStatus = TunnelStatus.DISCONNECTED
    registration_status: RegistrationStatus = RegistrationStatus.UNREGISTERED
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    approved_by: Optional[str] = None
    approved_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_relay_url(self) -> str:
        """Get relay server URL"""
        port = self.ports.get("relay", TUNNEL_PORTS["relay"])
        return f"udp://{self.fqdn}:{port}"

    def get_signaling_url(self) -> str:
        """Get signaling server URL"""
        port = self.ports.get("signaling", TUNNEL_PORTS["signaling"])
        return f"wss://{self.fqdn}:{port}/signaling"

    def get_websocket_url(self) -> str:
        """Get WebSocket relay URL"""
        port = self.ports.get("websocket", TUNNEL_PORTS["websocket"])
        return f"wss://{self.fqdn}:{port}/relay"

    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        return {
            "node_id": self.node_id,
            "provider": self.provider.value,
            "fqdn": self.fqdn,
            "ports": self.ports,
            "region": self.region,
            "tier": self.tier,
            "status": self.status.name,
            "registration_status": self.registration_status.name,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TunnelEndpoint":
        """Deserialize from dictionary"""
        return cls(
            node_id=data["node_id"],
            provider=TunnelProvider(data["provider"]),
            fqdn=data["fqdn"],
            ports=data.get("ports", {}),
            region=data.get("region", "unknown"),
            tier=data.get("tier", "fortress"),
            status=TunnelStatus[data.get("status", "DISCONNECTED")],
            registration_status=RegistrationStatus[data.get("registration_status", "UNREGISTERED")],
            created_at=data.get("created_at", time.time()),
            last_seen=data.get("last_seen", time.time()),
            approved_by=data.get("approved_by"),
            approved_at=data.get("approved_at"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TunnelConfig:
    """Configuration for tunnel setup"""
    provider: TunnelProvider = TunnelProvider.CLOUDFLARE
    # Cloudflare-specific
    cloudflare_token: Optional[str] = None
    cloudflare_tunnel_id: Optional[str] = None
    cloudflare_hostname: Optional[str] = None
    # ngrok-specific
    ngrok_authtoken: Optional[str] = None
    ngrok_domain: Optional[str] = None
    # Tailscale-specific
    tailscale_funnel: bool = False
    # General
    local_relay_port: int = 3478
    local_signaling_port: int = 8144
    local_websocket_port: int = 8080
    auto_start: bool = True
    restart_on_failure: bool = True
    health_check_interval: int = 30

    @classmethod
    def from_env(cls) -> "TunnelConfig":
        """Create config from environment variables"""
        provider_str = os.environ.get("TUNNEL_PROVIDER", "cloudflare")
        try:
            provider = TunnelProvider(provider_str)
        except ValueError:
            provider = TunnelProvider.CLOUDFLARE

        return cls(
            provider=provider,
            cloudflare_token=os.environ.get("CLOUDFLARE_TUNNEL_TOKEN"),
            cloudflare_tunnel_id=os.environ.get("CLOUDFLARE_TUNNEL_ID"),
            cloudflare_hostname=os.environ.get("CLOUDFLARE_HOSTNAME"),
            ngrok_authtoken=os.environ.get("NGROK_AUTHTOKEN"),
            ngrok_domain=os.environ.get("NGROK_DOMAIN"),
            tailscale_funnel=os.environ.get("TAILSCALE_FUNNEL", "false").lower() == "true",
            local_relay_port=int(os.environ.get("LOCAL_RELAY_PORT", "3478")),
            local_signaling_port=int(os.environ.get("LOCAL_SIGNALING_PORT", "8144")),
            local_websocket_port=int(os.environ.get("LOCAL_WEBSOCKET_PORT", "8080")),
            auto_start=os.environ.get("TUNNEL_AUTO_START", "true").lower() == "true",
            restart_on_failure=os.environ.get("TUNNEL_RESTART_ON_FAILURE", "true").lower() == "true",
        )


# ============================================================
# TUNNEL PROVIDER INTERFACE
# ============================================================

class TunnelProviderBase(ABC):
    """Abstract base class for tunnel providers"""

    def __init__(self, config: TunnelConfig, node_id: str):
        self.config = config
        self.node_id = node_id
        self.status = TunnelStatus.DISCONNECTED
        self.fqdn: Optional[str] = None
        self.process: Optional[subprocess.Popen] = None
        self._lock = Lock()

    @abstractmethod
    def start(self) -> bool:
        """Start the tunnel"""
        pass

    @abstractmethod
    def stop(self):
        """Stop the tunnel"""
        pass

    @abstractmethod
    def get_fqdn(self) -> Optional[str]:
        """Get the assigned FQDN"""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if tunnel is healthy"""
        pass

    def get_endpoint(self) -> Optional[TunnelEndpoint]:
        """Get tunnel endpoint information"""
        if not self.fqdn:
            return None

        return TunnelEndpoint(
            node_id=self.node_id,
            provider=self.config.provider,
            fqdn=self.fqdn,
            ports={
                "relay": self.config.local_relay_port,
                "signaling": self.config.local_signaling_port,
                "websocket": self.config.local_websocket_port,
            },
            status=self.status,
        )


# ============================================================
# CLOUDFLARE TUNNEL PROVIDER
# ============================================================

class CloudflareTunnelProvider(TunnelProviderBase):
    """
    Cloudflare Tunnel provider using cloudflared.

    Setup:
    1. Install cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/
    2. Create tunnel: cloudflared tunnel create hookprobe-fortress
    3. Configure DNS: cloudflared tunnel route dns <tunnel-id> <hostname>
    4. Set CLOUDFLARE_TUNNEL_TOKEN environment variable
    """

    CLOUDFLARED_PATH = shutil.which("cloudflared") or "/usr/local/bin/cloudflared"

    def __init__(self, config: TunnelConfig, node_id: str):
        super().__init__(config, node_id)
        self.fqdn = config.cloudflare_hostname

    def start(self) -> bool:
        """Start Cloudflare tunnel"""
        if not self.config.cloudflare_token:
            logger.error("[TUNNEL] Cloudflare token not configured")
            return False

        if not os.path.exists(self.CLOUDFLARED_PATH):
            logger.error(f"[TUNNEL] cloudflared not found at {self.CLOUDFLARED_PATH}")
            return False

        try:
            with self._lock:
                self.status = TunnelStatus.CONNECTING

            # Build command
            cmd = [
                self.CLOUDFLARED_PATH,
                "tunnel",
                "--no-autoupdate",
                "run",
                "--token", self.config.cloudflare_token,
            ]

            # Start process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait briefly and check if started
            time.sleep(2)
            if self.process.poll() is None:
                with self._lock:
                    self.status = TunnelStatus.CONNECTED
                    self.fqdn = self.config.cloudflare_hostname

                logger.info(f"[TUNNEL] Cloudflare tunnel connected: {self.fqdn}")
                return True
            else:
                stderr = self.process.stderr.read() if self.process.stderr else ""
                logger.error(f"[TUNNEL] Cloudflare tunnel failed: {stderr}")
                with self._lock:
                    self.status = TunnelStatus.ERROR
                return False

        except Exception as e:
            logger.error(f"[TUNNEL] Cloudflare tunnel error: {e}")
            with self._lock:
                self.status = TunnelStatus.ERROR
            return False

    def stop(self):
        """Stop Cloudflare tunnel"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

        with self._lock:
            self.status = TunnelStatus.DISCONNECTED

        logger.info("[TUNNEL] Cloudflare tunnel stopped")

    def get_fqdn(self) -> Optional[str]:
        return self.fqdn

    def is_healthy(self) -> bool:
        """Check tunnel health"""
        if not self.process:
            return False

        # Check process is running
        if self.process.poll() is not None:
            return False

        # Optionally check connectivity
        if self.fqdn:
            try:
                socket.gethostbyname(self.fqdn)
                return True
            except socket.gaierror:
                return False

        return True


# ============================================================
# NGROK TUNNEL PROVIDER
# ============================================================

class NgrokTunnelProvider(TunnelProviderBase):
    """
    ngrok tunnel provider.

    Setup:
    1. Install ngrok: https://ngrok.com/download
    2. Get authtoken: https://dashboard.ngrok.com/get-started/your-authtoken
    3. Set NGROK_AUTHTOKEN environment variable
    """

    NGROK_PATH = shutil.which("ngrok") or "/usr/local/bin/ngrok"
    NGROK_API = "http://127.0.0.1:4040/api/tunnels"

    def __init__(self, config: TunnelConfig, node_id: str):
        super().__init__(config, node_id)

    def start(self) -> bool:
        """Start ngrok tunnel"""
        if not self.config.ngrok_authtoken:
            logger.error("[TUNNEL] ngrok authtoken not configured")
            return False

        if not os.path.exists(self.NGROK_PATH):
            logger.error(f"[TUNNEL] ngrok not found at {self.NGROK_PATH}")
            return False

        try:
            with self._lock:
                self.status = TunnelStatus.CONNECTING

            # Set authtoken
            subprocess.run(
                [self.NGROK_PATH, "config", "add-authtoken", self.config.ngrok_authtoken],
                capture_output=True
            )

            # Build command
            cmd = [
                self.NGROK_PATH,
                "http",
                str(self.config.local_websocket_port),
            ]

            if self.config.ngrok_domain:
                cmd.extend(["--domain", self.config.ngrok_domain])

            # Start process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for tunnel to establish and get URL
            time.sleep(3)
            self.fqdn = self._get_ngrok_url()

            if self.fqdn:
                with self._lock:
                    self.status = TunnelStatus.CONNECTED
                logger.info(f"[TUNNEL] ngrok tunnel connected: {self.fqdn}")
                return True
            else:
                with self._lock:
                    self.status = TunnelStatus.ERROR
                return False

        except Exception as e:
            logger.error(f"[TUNNEL] ngrok tunnel error: {e}")
            with self._lock:
                self.status = TunnelStatus.ERROR
            return False

    def _get_ngrok_url(self) -> Optional[str]:
        """Get ngrok tunnel URL from API"""
        try:
            req = urllib.request.Request(self.NGROK_API)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                tunnels = data.get("tunnels", [])
                for tunnel in tunnels:
                    public_url = tunnel.get("public_url", "")
                    if public_url.startswith("https://"):
                        # Extract hostname
                        return public_url.replace("https://", "").split("/")[0]
        except Exception as e:
            logger.debug(f"[TUNNEL] Failed to get ngrok URL: {e}")
        return None

    def stop(self):
        """Stop ngrok tunnel"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

        with self._lock:
            self.status = TunnelStatus.DISCONNECTED
            self.fqdn = None

        logger.info("[TUNNEL] ngrok tunnel stopped")

    def get_fqdn(self) -> Optional[str]:
        if not self.fqdn:
            self.fqdn = self._get_ngrok_url()
        return self.fqdn

    def is_healthy(self) -> bool:
        if not self.process:
            return False
        if self.process.poll() is not None:
            return False
        return self._get_ngrok_url() is not None


# ============================================================
# TAILSCALE FUNNEL PROVIDER
# ============================================================

class TailscaleFunnelProvider(TunnelProviderBase):
    """
    Tailscale Funnel provider.

    Setup:
    1. Install Tailscale: https://tailscale.com/download
    2. Enable Funnel: tailscale funnel --bg <port>
    3. Set TAILSCALE_FUNNEL=true
    """

    TAILSCALE_PATH = shutil.which("tailscale") or "/usr/bin/tailscale"

    def __init__(self, config: TunnelConfig, node_id: str):
        super().__init__(config, node_id)

    def start(self) -> bool:
        """Start Tailscale Funnel"""
        if not os.path.exists(self.TAILSCALE_PATH):
            logger.error(f"[TUNNEL] tailscale not found at {self.TAILSCALE_PATH}")
            return False

        try:
            with self._lock:
                self.status = TunnelStatus.CONNECTING

            # Get Tailscale hostname
            result = subprocess.run(
                [self.TAILSCALE_PATH, "status", "--json"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                status = json.loads(result.stdout)
                dns_name = status.get("Self", {}).get("DNSName", "")
                if dns_name:
                    self.fqdn = dns_name.rstrip(".")

            # Enable Funnel
            result = subprocess.run(
                [self.TAILSCALE_PATH, "funnel", "--bg",
                 str(self.config.local_websocket_port)],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                with self._lock:
                    self.status = TunnelStatus.CONNECTED
                logger.info(f"[TUNNEL] Tailscale Funnel enabled: {self.fqdn}")
                return True
            else:
                logger.error(f"[TUNNEL] Tailscale Funnel failed: {result.stderr}")
                with self._lock:
                    self.status = TunnelStatus.ERROR
                return False

        except Exception as e:
            logger.error(f"[TUNNEL] Tailscale Funnel error: {e}")
            with self._lock:
                self.status = TunnelStatus.ERROR
            return False

    def stop(self):
        """Stop Tailscale Funnel"""
        try:
            subprocess.run(
                [self.TAILSCALE_PATH, "funnel", "off"],
                capture_output=True
            )
        except Exception:
            pass

        with self._lock:
            self.status = TunnelStatus.DISCONNECTED

        logger.info("[TUNNEL] Tailscale Funnel stopped")

    def get_fqdn(self) -> Optional[str]:
        return self.fqdn

    def is_healthy(self) -> bool:
        try:
            result = subprocess.run(
                [self.TAILSCALE_PATH, "status", "--json"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False


# ============================================================
# TUNNEL MANAGER
# ============================================================

class TunnelManager:
    """
    Manages tunnel lifecycle and registration with mesh registry.

    Responsibilities:
    1. Start/stop tunnel based on configuration
    2. Register tunnel endpoint with mesh registry
    3. Monitor tunnel health
    4. Handle reconnection on failure
    5. Manage approval workflow
    """

    def __init__(self, node_id: str, tier: str = "fortress",
                 region: str = "unknown", config: TunnelConfig = None):
        self.node_id = node_id
        self.tier = tier
        self.region = region
        self.config = config or TunnelConfig.from_env()

        # Provider instance
        self.provider: Optional[TunnelProviderBase] = None
        self.endpoint: Optional[TunnelEndpoint] = None

        # State
        self.running = False
        self._health_check_thread: Optional[Thread] = None
        self._stop_event = Event()
        self._lock = Lock()

        # Callbacks
        self.on_connected: Optional[Callable[[TunnelEndpoint], None]] = None
        self.on_disconnected: Optional[Callable[[], None]] = None
        self.on_approved: Optional[Callable[[TunnelEndpoint], None]] = None

    def start(self) -> bool:
        """Start tunnel and register with mesh registry"""
        if self.running:
            return True

        # Create provider
        self.provider = self._create_provider()
        if not self.provider:
            logger.error("[TUNNEL] Failed to create provider")
            return False

        # Start tunnel
        if not self.provider.start():
            return False

        # Create endpoint
        self.endpoint = self.provider.get_endpoint()
        if self.endpoint:
            self.endpoint.region = self.region
            self.endpoint.tier = self.tier

        self.running = True
        self._stop_event.clear()

        # Start health check
        self._health_check_thread = Thread(target=self._health_check_loop, daemon=True)
        self._health_check_thread.start()

        # Notify
        if self.on_connected and self.endpoint:
            self.on_connected(self.endpoint)

        logger.info(f"[TUNNEL] Manager started, FQDN: {self.provider.get_fqdn()}")
        return True

    def stop(self):
        """Stop tunnel"""
        self.running = False
        self._stop_event.set()

        if self.provider:
            self.provider.stop()

        if self.on_disconnected:
            self.on_disconnected()

        logger.info("[TUNNEL] Manager stopped")

    def _create_provider(self) -> Optional[TunnelProviderBase]:
        """Create tunnel provider based on configuration"""
        provider_map = {
            TunnelProvider.CLOUDFLARE: CloudflareTunnelProvider,
            TunnelProvider.NGROK: NgrokTunnelProvider,
            TunnelProvider.TAILSCALE: TailscaleFunnelProvider,
        }

        provider_class = provider_map.get(self.config.provider)
        if provider_class:
            return provider_class(self.config, self.node_id)

        logger.error(f"[TUNNEL] Unknown provider: {self.config.provider}")
        return None

    def _health_check_loop(self):
        """Periodic health check"""
        while not self._stop_event.wait(self.config.health_check_interval):
            if not self.running:
                break

            if self.provider and not self.provider.is_healthy():
                logger.warning("[TUNNEL] Health check failed, attempting restart")

                if self.config.restart_on_failure:
                    self.provider.stop()
                    time.sleep(5)
                    self.provider.start()

    def get_endpoint(self) -> Optional[TunnelEndpoint]:
        """Get current tunnel endpoint"""
        return self.endpoint

    def get_fqdn(self) -> Optional[str]:
        """Get tunnel FQDN"""
        if self.provider:
            return self.provider.get_fqdn()
        return None

    def is_connected(self) -> bool:
        """Check if tunnel is connected"""
        return (self.provider is not None and
                self.provider.status == TunnelStatus.CONNECTED)


# ============================================================
# TUNNEL REGISTRY (Coordinator Side)
# ============================================================

class TunnelRegistry:
    """
    Registry of trusted tunnel endpoints (managed by coordinator).

    Features:
    - Stores registered tunnel endpoints
    - Admin approval workflow
    - Automatic expiration of stale entries
    - Region-aware endpoint selection
    """

    def __init__(self, storage_path: str = None):
        self.storage_path = storage_path or "/var/lib/hookprobe/tunnels.json"
        self.endpoints: Dict[str, TunnelEndpoint] = {}
        self._lock = Lock()

        # Load existing registrations
        self._load()

    def register(self, endpoint: TunnelEndpoint) -> bool:
        """
        Register a new tunnel endpoint (requires admin approval).

        Returns:
            True if registration accepted (pending approval)
        """
        with self._lock:
            # Check if already registered
            existing = self.endpoints.get(endpoint.node_id)
            if existing and existing.registration_status == RegistrationStatus.APPROVED:
                # Update last seen
                existing.last_seen = time.time()
                existing.fqdn = endpoint.fqdn
                existing.status = endpoint.status
                self._save()
                return True

            # New registration - pending approval
            endpoint.registration_status = RegistrationStatus.PENDING
            endpoint.created_at = time.time()
            self.endpoints[endpoint.node_id] = endpoint
            self._save()

            logger.info(f"[REGISTRY] New tunnel registered (pending approval): "
                       f"{endpoint.node_id} -> {endpoint.fqdn}")
            return True

    def approve(self, node_id: str, approver: str) -> bool:
        """Approve a pending tunnel registration"""
        with self._lock:
            endpoint = self.endpoints.get(node_id)
            if not endpoint:
                return False

            endpoint.registration_status = RegistrationStatus.APPROVED
            endpoint.approved_by = approver
            endpoint.approved_at = time.time()
            self._save()

            logger.info(f"[REGISTRY] Tunnel approved: {node_id} by {approver}")
            return True

    def reject(self, node_id: str, reason: str = None) -> bool:
        """Reject a pending tunnel registration"""
        with self._lock:
            endpoint = self.endpoints.get(node_id)
            if not endpoint:
                return False

            endpoint.registration_status = RegistrationStatus.REJECTED
            if reason:
                endpoint.metadata["rejection_reason"] = reason
            self._save()

            logger.info(f"[REGISTRY] Tunnel rejected: {node_id}")
            return True

    def revoke(self, node_id: str) -> bool:
        """Revoke an approved tunnel"""
        with self._lock:
            if node_id in self.endpoints:
                del self.endpoints[node_id]
                self._save()
                logger.info(f"[REGISTRY] Tunnel revoked: {node_id}")
                return True
            return False

    def get_approved_endpoints(self, region: str = None,
                               tier: str = None) -> List[TunnelEndpoint]:
        """Get list of approved tunnel endpoints"""
        with self._lock:
            result = []
            now = time.time()

            for endpoint in self.endpoints.values():
                # Check status
                if endpoint.registration_status != RegistrationStatus.APPROVED:
                    continue

                # Check freshness (last seen within 10 minutes)
                if now - endpoint.last_seen > 600:
                    continue

                # Filter by region
                if region and endpoint.region != region:
                    continue

                # Filter by tier
                if tier and endpoint.tier != tier:
                    continue

                result.append(endpoint)

            return result

    def get_pending_approvals(self) -> List[TunnelEndpoint]:
        """Get list of endpoints pending approval"""
        with self._lock:
            return [
                ep for ep in self.endpoints.values()
                if ep.registration_status == RegistrationStatus.PENDING
            ]

    def get_endpoint(self, node_id: str) -> Optional[TunnelEndpoint]:
        """Get specific endpoint by node ID"""
        with self._lock:
            return self.endpoints.get(node_id)

    def update_heartbeat(self, node_id: str) -> bool:
        """Update last seen timestamp for an endpoint"""
        with self._lock:
            endpoint = self.endpoints.get(node_id)
            if endpoint:
                endpoint.last_seen = time.time()
                return True
            return False

    def cleanup_stale(self, max_age: float = 3600) -> int:
        """Remove stale endpoints (not seen for max_age seconds)"""
        now = time.time()
        with self._lock:
            stale = [
                nid for nid, ep in self.endpoints.items()
                if now - ep.last_seen > max_age
            ]
            for nid in stale:
                del self.endpoints[nid]

            if stale:
                self._save()

            return len(stale)

    def _load(self):
        """Load registry from disk"""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                    for item in data:
                        ep = TunnelEndpoint.from_dict(item)
                        self.endpoints[ep.node_id] = ep
                logger.info(f"[REGISTRY] Loaded {len(self.endpoints)} tunnel endpoints")
        except Exception as e:
            logger.warning(f"[REGISTRY] Failed to load: {e}")

    def _save(self):
        """Save registry to disk"""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            with open(self.storage_path, "w") as f:
                data = [ep.to_dict() for ep in self.endpoints.values()]
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"[REGISTRY] Failed to save: {e}")


# ============================================================
# TUNNEL CLIENT (Mesh Node Side)
# ============================================================

class TunnelRegistrationClient:
    """
    Client for registering tunnel with mesh registry.

    Used by Fortress/Nexus nodes to:
    1. Register their tunnel endpoint
    2. Send heartbeats
    3. Check approval status
    """

    def __init__(self, registry_endpoint: str, node_id: str):
        self.registry_endpoint = registry_endpoint
        self.node_id = node_id

    def register(self, endpoint: TunnelEndpoint) -> Tuple[bool, RegistrationStatus]:
        """
        Register tunnel endpoint with mesh registry.

        Returns:
            (success, status)
        """
        try:
            url = f"{self.registry_endpoint}/api/v1/tunnels/register"
            data = json.dumps(endpoint.to_dict()).encode()

            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                status = RegistrationStatus[result.get("status", "PENDING")]
                return True, status

        except urllib.error.HTTPError as e:
            logger.warning(f"[TUNNEL_CLIENT] Registration failed: {e.code}")
            return False, RegistrationStatus.UNREGISTERED
        except Exception as e:
            logger.warning(f"[TUNNEL_CLIENT] Registration error: {e}")
            return False, RegistrationStatus.UNREGISTERED

    def heartbeat(self) -> bool:
        """Send heartbeat to mesh registry"""
        try:
            url = f"{self.registry_endpoint}/api/v1/tunnels/{self.node_id}/heartbeat"
            req = urllib.request.Request(url, method="POST")

            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200

        except Exception as e:
            logger.debug(f"[TUNNEL_CLIENT] Heartbeat failed: {e}")
            return False

    def check_status(self) -> RegistrationStatus:
        """Check registration status"""
        try:
            url = f"{self.registry_endpoint}/api/v1/tunnels/{self.node_id}/status"
            req = urllib.request.Request(url)

            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode())
                return RegistrationStatus[result.get("status", "UNREGISTERED")]

        except Exception:
            return RegistrationStatus.UNREGISTERED

    def get_approved_relays(self, region: str = None) -> List[TunnelEndpoint]:
        """Get list of approved relay endpoints from mesh registry"""
        try:
            url = f"{self.registry_endpoint}/api/v1/tunnels/approved"
            if region:
                url += f"?region={region}"

            req = urllib.request.Request(url)

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return [TunnelEndpoint.from_dict(ep) for ep in data.get("endpoints", [])]

        except Exception as e:
            logger.debug(f"[TUNNEL_CLIENT] Failed to get relays: {e}")
            return []


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    "TunnelProvider",
    "TunnelStatus",
    "RegistrationStatus",

    # Data classes
    "TunnelEndpoint",
    "TunnelConfig",

    # Providers
    "TunnelProviderBase",
    "CloudflareTunnelProvider",
    "NgrokTunnelProvider",
    "TailscaleFunnelProvider",

    # Managers
    "TunnelManager",
    "TunnelRegistry",
    "TunnelRegistrationClient",
]
