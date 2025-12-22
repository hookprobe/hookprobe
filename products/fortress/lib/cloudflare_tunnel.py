"""
Fortress Cloudflare Tunnel Manager
"Access your business security from anywhere"

Version: 1.0.0

Provides simplified Cloudflare Tunnel management for small businesses.
Allows business owners to access their Fortress dashboard remotely via
a subdomain on their existing website (e.g., fortress.mybakery.com).

Architecture:
1. Business already has website on Cloudflare (mybakery.com)
2. Install Fortress at their shop for network security
3. Create Cloudflare Tunnel to expose Fortress dashboard
4. Add DNS record: fortress.mybakery.com -> tunnel
5. Owner accesses https://fortress.mybakery.com from phone

Requirements:
- Cloudflare account with website already added
- cloudflared binary installed
- Tunnel token from Cloudflare dashboard

This module wraps shared/mesh/tunnel.py for Fortress-specific use cases.
"""

import os
import sys
import json
import time
import shutil
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from threading import Thread, Lock, Event

logger = logging.getLogger("fortress.tunnel")


class TunnelState(Enum):
    """Cloudflare Tunnel states"""
    NOT_INSTALLED = "not_installed"      # cloudflared not present
    UNCONFIGURED = "unconfigured"        # No token/tunnel configured
    CONFIGURED = "configured"            # Token saved but not running
    CONNECTING = "connecting"            # Starting up
    CONNECTED = "connected"              # Active and healthy
    ERROR = "error"                      # Failed to connect
    DISCONNECTED = "disconnected"        # Stopped


@dataclass
class TunnelConfig:
    """Fortress tunnel configuration"""
    token: Optional[str] = None
    hostname: Optional[str] = None       # e.g., fortress.mybakery.com
    local_port: int = 8443               # Fortress web UI port
    auto_start: bool = True              # Start on boot
    created_at: Optional[float] = None
    last_connected: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            'token': self.token,
            'hostname': self.hostname,
            'local_port': self.local_port,
            'auto_start': self.auto_start,
            'created_at': self.created_at,
            'last_connected': self.last_connected,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'TunnelConfig':
        return cls(
            token=data.get('token'),
            hostname=data.get('hostname'),
            local_port=data.get('local_port', 8443),
            auto_start=data.get('auto_start', True),
            created_at=data.get('created_at'),
            last_connected=data.get('last_connected'),
        )


@dataclass
class TunnelStatus:
    """Current tunnel status"""
    state: TunnelState = TunnelState.NOT_INSTALLED
    hostname: Optional[str] = None
    uptime_seconds: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    connections: int = 0
    last_error: Optional[str] = None
    cloudflared_version: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'state': self.state.value,
            'hostname': self.hostname,
            'uptime_seconds': self.uptime_seconds,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'connections': self.connections,
            'last_error': self.last_error,
            'cloudflared_version': self.cloudflared_version,
        }


class CloudflareTunnelManager:
    """
    Manages Cloudflare Tunnel for Fortress web dashboard access.

    Features:
    - Install cloudflared binary
    - Configure tunnel with token
    - Start/stop tunnel
    - Systemd service management
    - Health monitoring
    - Status reporting for web UI

    Usage:
        manager = CloudflareTunnelManager()

        # Check if cloudflared installed
        if not manager.is_cloudflared_installed():
            manager.install_cloudflared()

        # Configure tunnel
        manager.configure(token="your-tunnel-token", hostname="fortress.mybakery.com")

        # Start tunnel
        manager.start()

        # Get status for web UI
        status = manager.get_status()
    """

    CONFIG_DIR = "/opt/hookprobe/fortress/tunnel"
    CONFIG_FILE = "/opt/hookprobe/fortress/tunnel/config.json"
    SYSTEMD_SERVICE = "fts-tunnel.service"
    CLOUDFLARED_PATHS = [
        "/usr/local/bin/cloudflared",
        "/usr/bin/cloudflared",
        shutil.which("cloudflared"),
    ]

    def __init__(self, config_dir: str = None):
        self.config_dir = Path(config_dir or self.CONFIG_DIR)
        self.config_file = self.config_dir / "config.json"
        self.config: Optional[TunnelConfig] = None
        self.process: Optional[subprocess.Popen] = None
        self._lock = Lock()
        self._stop_event = Event()
        self._monitor_thread: Optional[Thread] = None
        self._start_time: Optional[float] = None
        self._last_error: Optional[str] = None

        # Load existing config
        self._load_config()

    # ============================================================
    # INSTALLATION
    # ============================================================

    def is_cloudflared_installed(self) -> bool:
        """Check if cloudflared binary is available."""
        return self.get_cloudflared_path() is not None

    def get_cloudflared_path(self) -> Optional[str]:
        """Get path to cloudflared binary."""
        for path in self.CLOUDFLARED_PATHS:
            if path and os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    def get_cloudflared_version(self) -> Optional[str]:
        """Get cloudflared version."""
        path = self.get_cloudflared_path()
        if not path:
            return None

        try:
            result = subprocess.run(
                [path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse "cloudflared version 2024.1.0 (built 2024-01-01)"
                version_line = result.stdout.strip().split('\n')[0]
                parts = version_line.split()
                if len(parts) >= 3:
                    return parts[2]
        except Exception:
            pass
        return None

    def install_cloudflared(self) -> Tuple[bool, str]:
        """
        Install cloudflared binary.

        Returns:
            (success, message)
        """
        # Detect architecture
        import platform
        machine = platform.machine().lower()

        if machine in ('x86_64', 'amd64'):
            arch = 'amd64'
        elif machine in ('aarch64', 'arm64'):
            arch = 'arm64'
        elif machine.startswith('arm'):
            arch = 'arm'
        else:
            return False, f"Unsupported architecture: {machine}"

        # Download URL
        url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}"
        dest = "/usr/local/bin/cloudflared"

        try:
            logger.info(f"[TUNNEL] Downloading cloudflared for {arch}...")

            # Download
            result = subprocess.run(
                ["curl", "-fsSL", "-o", "/tmp/cloudflared", url],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                return False, f"Download failed: {result.stderr}"

            # Install
            subprocess.run(["sudo", "mv", "/tmp/cloudflared", dest], check=True)
            subprocess.run(["sudo", "chmod", "+x", dest], check=True)

            # Verify
            if self.is_cloudflared_installed():
                version = self.get_cloudflared_version()
                logger.info(f"[TUNNEL] cloudflared {version} installed successfully")
                return True, f"cloudflared {version} installed"
            else:
                return False, "Installation verification failed"

        except subprocess.TimeoutExpired:
            return False, "Download timed out"
        except Exception as e:
            return False, f"Installation error: {e}"

    # ============================================================
    # CONFIGURATION
    # ============================================================

    def _load_config(self):
        """Load configuration from disk."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.config = TunnelConfig.from_dict(data)
                logger.info(f"[TUNNEL] Loaded config for {self.config.hostname}")
        except Exception as e:
            logger.warning(f"[TUNNEL] Failed to load config: {e}")
            self.config = None

    def _save_config(self):
        """Save configuration to disk."""
        if not self.config:
            return

        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config.to_dict(), f, indent=2)

            # Secure the file (contains token)
            os.chmod(self.config_file, 0o600)
            logger.info(f"[TUNNEL] Saved config for {self.config.hostname}")
        except Exception as e:
            logger.error(f"[TUNNEL] Failed to save config: {e}")

    def configure(self, token: str, hostname: str, local_port: int = 8443,
                  auto_start: bool = True) -> Tuple[bool, str]:
        """
        Configure the tunnel with Cloudflare token.

        Args:
            token: Cloudflare tunnel token (from dashboard)
            hostname: The subdomain to use (e.g., fortress.mybakery.com)
            local_port: Local port to expose (default: 8443 for Fortress web UI)
            auto_start: Start tunnel on boot

        Returns:
            (success, message)
        """
        if not token:
            return False, "Token is required"

        if not hostname:
            return False, "Hostname is required"

        # Validate token format (basic check)
        if len(token) < 50:
            return False, "Invalid token format"

        with self._lock:
            self.config = TunnelConfig(
                token=token,
                hostname=hostname,
                local_port=local_port,
                auto_start=auto_start,
                created_at=time.time(),
            )
            self._save_config()

        # Install systemd service if auto_start
        if auto_start:
            self._install_systemd_service()

        return True, f"Tunnel configured for {hostname}"

    def get_config(self) -> Optional[TunnelConfig]:
        """Get current configuration."""
        return self.config

    def clear_config(self) -> Tuple[bool, str]:
        """Clear tunnel configuration."""
        try:
            # Stop tunnel if running
            self.stop()

            # Remove systemd service
            self._remove_systemd_service()

            # Remove config file
            if self.config_file.exists():
                self.config_file.unlink()

            self.config = None
            return True, "Configuration cleared"
        except Exception as e:
            return False, f"Failed to clear config: {e}"

    # ============================================================
    # TUNNEL CONTROL
    # ============================================================

    def start(self) -> Tuple[bool, str]:
        """
        Start the Cloudflare tunnel.

        Returns:
            (success, message)
        """
        if not self.is_cloudflared_installed():
            return False, "cloudflared not installed"

        if not self.config or not self.config.token:
            return False, "Tunnel not configured"

        if self.is_running():
            return True, "Tunnel already running"

        cloudflared = self.get_cloudflared_path()

        try:
            with self._lock:
                # Build command
                cmd = [
                    cloudflared,
                    "tunnel",
                    "--no-autoupdate",
                    "run",
                    "--token", self.config.token,
                ]

                # Start process
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                self._start_time = time.time()
                self._stop_event.clear()

            # Wait briefly and verify
            time.sleep(3)

            if self.process.poll() is None:
                # Process still running - success
                self.config.last_connected = time.time()
                self._save_config()

                # Start monitor thread
                self._start_monitor()

                logger.info(f"[TUNNEL] Started tunnel to {self.config.hostname}")
                return True, f"Tunnel connected to {self.config.hostname}"
            else:
                # Process exited
                stderr = self.process.stderr.read() if self.process.stderr else ""
                self._last_error = stderr[:200]
                logger.error(f"[TUNNEL] Failed to start: {stderr}")
                return False, f"Tunnel failed to start: {self._last_error}"

        except Exception as e:
            self._last_error = str(e)
            logger.error(f"[TUNNEL] Start error: {e}")
            return False, f"Failed to start tunnel: {e}"

    def stop(self) -> Tuple[bool, str]:
        """Stop the Cloudflare tunnel."""
        self._stop_event.set()

        with self._lock:
            if self.process:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.process = None

        self._start_time = None
        logger.info("[TUNNEL] Stopped tunnel")
        return True, "Tunnel stopped"

    def restart(self) -> Tuple[bool, str]:
        """Restart the tunnel."""
        self.stop()
        time.sleep(1)
        return self.start()

    def is_running(self) -> bool:
        """Check if tunnel process is running."""
        with self._lock:
            return self.process is not None and self.process.poll() is None

    def _start_monitor(self):
        """Start health monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return

        self._monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _monitor_loop(self):
        """Monitor tunnel health and restart if needed."""
        while not self._stop_event.wait(30):
            if not self.is_running() and self.config and self.config.auto_start:
                logger.warning("[TUNNEL] Tunnel died, attempting restart...")
                self.start()

    # ============================================================
    # SYSTEMD SERVICE
    # ============================================================

    def _install_systemd_service(self) -> bool:
        """Install systemd service for auto-start."""
        if not self.config:
            return False

        cloudflared = self.get_cloudflared_path()
        if not cloudflared:
            return False

        service_content = f"""[Unit]
Description=Fortress Cloudflare Tunnel
Documentation=https://hookprobe.com/docs/fortress/remote-access
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart={cloudflared} tunnel --no-autoupdate run --token {self.config.token}
Restart=on-failure
RestartSec=10
KillMode=process
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
"""

        try:
            service_path = f"/etc/systemd/system/{self.SYSTEMD_SERVICE}"

            # Write service file
            with open("/tmp/fts-tunnel.service", 'w') as f:
                f.write(service_content)

            subprocess.run(["sudo", "mv", "/tmp/fts-tunnel.service", service_path], check=True)
            subprocess.run(["sudo", "chmod", "644", service_path], check=True)
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "enable", self.SYSTEMD_SERVICE], check=True)

            logger.info("[TUNNEL] Systemd service installed")
            return True
        except Exception as e:
            logger.error(f"[TUNNEL] Failed to install systemd service: {e}")
            return False

    def _remove_systemd_service(self) -> bool:
        """Remove systemd service."""
        try:
            subprocess.run(["sudo", "systemctl", "stop", self.SYSTEMD_SERVICE],
                          capture_output=True)
            subprocess.run(["sudo", "systemctl", "disable", self.SYSTEMD_SERVICE],
                          capture_output=True)

            service_path = f"/etc/systemd/system/{self.SYSTEMD_SERVICE}"
            if os.path.exists(service_path):
                subprocess.run(["sudo", "rm", service_path], check=True)
                subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)

            logger.info("[TUNNEL] Systemd service removed")
            return True
        except Exception as e:
            logger.error(f"[TUNNEL] Failed to remove systemd service: {e}")
            return False

    def is_service_enabled(self) -> bool:
        """Check if systemd service is enabled."""
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", self.SYSTEMD_SERVICE],
                capture_output=True,
                text=True
            )
            return result.returncode == 0 and "enabled" in result.stdout
        except Exception:
            return False

    def is_service_active(self) -> bool:
        """Check if systemd service is active."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", self.SYSTEMD_SERVICE],
                capture_output=True,
                text=True
            )
            return result.returncode == 0 and "active" in result.stdout
        except Exception:
            return False

    # ============================================================
    # STATUS
    # ============================================================

    def get_status(self) -> TunnelStatus:
        """Get comprehensive tunnel status for web UI."""
        status = TunnelStatus()

        # Check cloudflared installation
        status.cloudflared_version = self.get_cloudflared_version()

        if not self.is_cloudflared_installed():
            status.state = TunnelState.NOT_INSTALLED
            return status

        if not self.config or not self.config.token:
            status.state = TunnelState.UNCONFIGURED
            return status

        status.hostname = self.config.hostname

        # Check running state
        if self.is_running() or self.is_service_active():
            status.state = TunnelState.CONNECTED

            if self._start_time:
                status.uptime_seconds = int(time.time() - self._start_time)

            # Try to get metrics (would need cloudflared metrics endpoint)
            # For now, just mark as connected
        else:
            status.state = TunnelState.CONFIGURED

        status.last_error = self._last_error

        return status

    def get_state(self) -> TunnelState:
        """Get simple tunnel state."""
        return self.get_status().state

    # ============================================================
    # VALIDATION
    # ============================================================

    def validate_token(self, token: str) -> Tuple[bool, str]:
        """
        Validate a tunnel token by attempting a dry-run connection.

        Returns:
            (valid, message)
        """
        if not self.is_cloudflared_installed():
            return False, "cloudflared not installed"

        cloudflared = self.get_cloudflared_path()

        try:
            # Run cloudflared tunnel info with the token
            # This validates the token without starting the tunnel
            result = subprocess.run(
                [cloudflared, "tunnel", "--token", token, "info"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return True, "Token is valid"
            else:
                error = result.stderr or result.stdout
                return False, f"Invalid token: {error[:100]}"

        except subprocess.TimeoutExpired:
            return False, "Validation timed out"
        except Exception as e:
            return False, f"Validation error: {e}"

    def test_connectivity(self) -> Tuple[bool, str]:
        """
        Test if the tunnel is reachable from the internet.

        Returns:
            (reachable, message)
        """
        if not self.config or not self.config.hostname:
            return False, "Tunnel not configured"

        try:
            import socket

            # Try to resolve the hostname
            ip = socket.gethostbyname(self.config.hostname)

            # Hostname resolves - tunnel is likely working
            return True, f"Hostname resolves to {ip}"

        except socket.gaierror:
            return False, f"Cannot resolve {self.config.hostname}"
        except Exception as e:
            return False, f"Connectivity test failed: {e}"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_tunnel_manager() -> CloudflareTunnelManager:
    """Get singleton tunnel manager instance."""
    if not hasattr(get_tunnel_manager, '_instance'):
        get_tunnel_manager._instance = CloudflareTunnelManager()
    return get_tunnel_manager._instance


def is_tunnel_available() -> bool:
    """Quick check if tunnel functionality is available."""
    manager = get_tunnel_manager()
    return manager.is_cloudflared_installed()


def get_tunnel_status() -> Dict[str, Any]:
    """Get tunnel status as dictionary (for API responses)."""
    manager = get_tunnel_manager()
    return manager.get_status().to_dict()


# ============================================================
# CLI INTERFACE (for testing)
# ============================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Fortress Cloudflare Tunnel Manager")
    parser.add_argument("command", choices=["status", "install", "configure", "start", "stop", "test"])
    parser.add_argument("--token", help="Cloudflare tunnel token")
    parser.add_argument("--hostname", help="Hostname (e.g., fortress.mybakery.com)")

    args = parser.parse_args()
    manager = CloudflareTunnelManager()

    if args.command == "status":
        status = manager.get_status()
        print(f"State: {status.state.value}")
        print(f"Hostname: {status.hostname}")
        print(f"Version: {status.cloudflared_version}")
        print(f"Uptime: {status.uptime_seconds}s")
        if status.last_error:
            print(f"Last Error: {status.last_error}")

    elif args.command == "install":
        success, msg = manager.install_cloudflared()
        print(msg)
        sys.exit(0 if success else 1)

    elif args.command == "configure":
        if not args.token or not args.hostname:
            print("Error: --token and --hostname required")
            sys.exit(1)
        success, msg = manager.configure(args.token, args.hostname)
        print(msg)
        sys.exit(0 if success else 1)

    elif args.command == "start":
        success, msg = manager.start()
        print(msg)
        sys.exit(0 if success else 1)

    elif args.command == "stop":
        success, msg = manager.stop()
        print(msg)
        sys.exit(0 if success else 1)

    elif args.command == "test":
        success, msg = manager.test_connectivity()
        print(msg)
        sys.exit(0 if success else 1)
