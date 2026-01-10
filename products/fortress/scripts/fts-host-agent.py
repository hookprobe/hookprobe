#!/usr/bin/env python3
"""
FTS Host Agent - Secure bridge between containerized web UI and host hostapd.

This agent listens on a Unix Domain Socket and executes validated hostapd_cli
commands on behalf of the fts-web container. It implements strict input
validation to prevent command injection attacks.

Security Model:
- Runs as dedicated low-privilege user (fts-agent)
- Only accepts connections from mounted UDS (no network exposure)
- Validates all MAC addresses with strict regex
- Whitelists allowed commands and interfaces
- HMAC-signed requests for authentication (optional, via shared secret)

Part of HookProbe Fortress - G.N.C. Security Architecture
"""

import json
import hashlib
import hmac
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

# Configuration
SOCKET_PATH = "/var/run/fts-host-agent.sock"
SECRET_FILE = "/etc/hookprobe/fts-agent-secret"
LOG_FILE = "/var/log/fortress/fts-host-agent.log"
PID_FILE = "/var/run/fts-host-agent.pid"

# Security: Strict MAC address validation (prevents command injection)
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

# Security: Whitelisted interfaces only
ALLOWED_INTERFACES = frozenset(['wlan_24ghz', 'wlan_5ghz', 'wlan0', 'wlan1'])

# Security: Whitelisted commands only
ALLOWED_COMMANDS = frozenset(['deauthenticate', 'list_sta', 'status'])

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE) if os.path.isdir(os.path.dirname(LOG_FILE)) else logging.StreamHandler(),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class HostAgent:
    """Secure host agent for hostapd control."""

    def __init__(self):
        self.socket_path = SOCKET_PATH
        self.secret: Optional[bytes] = None
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self._load_secret()

    def _load_secret(self) -> None:
        """Load shared secret for HMAC authentication."""
        try:
            if os.path.exists(SECRET_FILE):
                with open(SECRET_FILE, 'rb') as f:
                    self.secret = f.read().strip()
                logger.info("Loaded authentication secret")
            else:
                logger.warning(f"No secret file at {SECRET_FILE} - running without auth")
        except Exception as e:
            logger.error(f"Failed to load secret: {e}")

    def _verify_hmac(self, message: bytes, signature: str) -> bool:
        """Verify HMAC signature of request."""
        if not self.secret:
            return True  # No secret configured, skip auth

        expected = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def _validate_mac(self, mac: str) -> Tuple[bool, str]:
        """Validate MAC address format strictly."""
        if not mac:
            return False, "MAC address required"

        # Normalize
        mac = mac.upper().replace('-', ':')

        # Strict regex validation
        if not MAC_REGEX.match(mac):
            return False, f"Invalid MAC format: {mac}"

        return True, mac

    def _validate_interface(self, iface: str) -> Tuple[bool, str]:
        """Validate interface is whitelisted."""
        if not iface:
            return False, "Interface required"

        if iface not in ALLOWED_INTERFACES:
            return False, f"Interface not allowed: {iface}"

        return True, iface

    def _validate_command(self, cmd: str) -> Tuple[bool, str]:
        """Validate command is whitelisted."""
        if not cmd:
            return False, "Command required"

        if cmd not in ALLOWED_COMMANDS:
            return False, f"Command not allowed: {cmd}"

        return True, cmd

    def _execute_hostapd_cli(self, command: str, interface: str, mac: Optional[str] = None) -> dict:
        """Execute validated hostapd_cli command."""
        # Build command
        cmd = ['hostapd_cli', '-i', interface, command]
        if mac:
            cmd.append(mac)

        logger.info(f"Executing: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            success = result.returncode == 0
            if command == 'deauthenticate':
                success = success and 'OK' in result.stdout

            return {
                'success': success,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode
            }
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'hostapd_cli not found on host'
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def handle_request(self, data: bytes) -> bytes:
        """Process incoming request and return response."""
        try:
            request = json.loads(data.decode('utf-8'))
        except json.JSONDecodeError as e:
            return json.dumps({'success': False, 'error': f'Invalid JSON: {e}'}).encode()

        # Verify HMAC if secret is configured
        signature = request.get('signature', '')
        if self.secret:
            # Signature should be over the action + mac + interface
            msg = f"{request.get('action', '')}{request.get('mac', '')}{request.get('interface', '')}".encode()
            if not self._verify_hmac(msg, signature):
                logger.warning("HMAC verification failed")
                return json.dumps({'success': False, 'error': 'Authentication failed'}).encode()

        action = request.get('action', '')

        # Handle different actions
        if action == 'deauthenticate':
            return self._handle_deauth(request)
        elif action == 'list_clients':
            return self._handle_list_clients(request)
        elif action == 'status':
            return self._handle_status(request)
        elif action == 'ping':
            return json.dumps({'success': True, 'message': 'pong', 'version': '1.0.0'}).encode()
        else:
            return json.dumps({'success': False, 'error': f'Unknown action: {action}'}).encode()

    def _handle_deauth(self, request: dict) -> bytes:
        """Handle deauthenticate request."""
        mac = request.get('mac', '')
        interfaces = request.get('interfaces', list(ALLOWED_INTERFACES))

        # Validate MAC
        valid, mac_or_error = self._validate_mac(mac)
        if not valid:
            return json.dumps({'success': False, 'error': mac_or_error}).encode()
        mac = mac_or_error

        results = {
            'success': False,
            'mac': mac,
            'interfaces_tried': [],
            'deauth_sent': False
        }

        # Try each interface
        for iface in interfaces:
            valid, iface_or_error = self._validate_interface(iface)
            if not valid:
                continue

            result = self._execute_hostapd_cli('deauthenticate', iface, mac)
            results['interfaces_tried'].append({
                'interface': iface,
                'result': result
            })

            if result.get('success'):
                results['deauth_sent'] = True
                results['success'] = True
                logger.info(f"Successfully deauthenticated {mac} from {iface}")

        if not results['deauth_sent']:
            logger.warning(f"Failed to deauth {mac} from any interface")

        return json.dumps(results).encode()

    def _handle_list_clients(self, request: dict) -> bytes:
        """Handle list_clients request."""
        interface = request.get('interface', 'wlan_24ghz')

        valid, iface_or_error = self._validate_interface(interface)
        if not valid:
            return json.dumps({'success': False, 'error': iface_or_error}).encode()

        result = self._execute_hostapd_cli('list_sta', interface)

        clients = []
        if result.get('success') and result.get('stdout'):
            # Parse MAC addresses from output
            for line in result['stdout'].split('\n'):
                line = line.strip()
                if MAC_REGEX.match(line):
                    clients.append(line)

        return json.dumps({
            'success': True,
            'interface': interface,
            'clients': clients
        }).encode()

    def _handle_status(self, request: dict) -> bytes:
        """Handle status request."""
        interface = request.get('interface', 'wlan_24ghz')

        valid, iface_or_error = self._validate_interface(interface)
        if not valid:
            return json.dumps({'success': False, 'error': iface_or_error}).encode()

        result = self._execute_hostapd_cli('status', interface)
        return json.dumps({
            'success': result.get('success', False),
            'interface': interface,
            'status': result.get('stdout', ''),
            'error': result.get('error')
        }).encode()

    def cleanup(self) -> None:
        """Clean up socket and PID file."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass

        if os.path.exists(PID_FILE):
            try:
                os.unlink(PID_FILE)
            except Exception:
                pass

    def run(self) -> None:
        """Main event loop."""
        # Write PID file
        try:
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
        except Exception as e:
            logger.warning(f"Could not write PID file: {e}")

        # Remove existing socket
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        # Create Unix Domain Socket
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(self.socket_path)
            # Set permissions: owner rw, group rw, others none
            os.chmod(self.socket_path, 0o660)
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Allow periodic running check

            logger.info(f"FTS Host Agent listening on {self.socket_path}")
            self.running = True

            while self.running:
                try:
                    client, _ = self.server_socket.accept()
                    client.settimeout(10.0)

                    try:
                        # Read request (max 4KB)
                        data = client.recv(4096)
                        if data:
                            response = self.handle_request(data)
                            client.sendall(response)
                    except socket.timeout:
                        logger.warning("Client timeout")
                    finally:
                        client.close()

                except socket.timeout:
                    continue  # Normal timeout, check running flag
                except Exception as e:
                    if self.running:
                        logger.error(f"Error handling client: {e}")

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise
        finally:
            self.cleanup()


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info(f"Received signal {signum}, shutting down...")
    if agent:
        agent.running = False


agent: Optional[HostAgent] = None


def main():
    global agent

    # Ensure log directory exists
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, mode=0o755)
        except Exception:
            pass

    # Set up signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logger.info("Starting FTS Host Agent v1.0.0")
    logger.info("G.N.C. Security Architecture - Host-side hostapd bridge")

    agent = HostAgent()

    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        if agent:
            agent.cleanup()

    logger.info("FTS Host Agent stopped")


if __name__ == '__main__':
    main()
