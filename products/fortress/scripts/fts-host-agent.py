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

import fcntl
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
# Note: Socket in directory for container bind mount compatibility
SOCKET_PATH = "/var/run/fts-host-agent/fts-host-agent.sock"
SECRET_FILE = "/etc/hookprobe/fts-agent-secret"
LOG_FILE = "/var/log/fortress/fts-host-agent.log"
PID_FILE = "/var/run/fts-host-agent.pid"

# Security: Strict MAC address validation (prevents command injection)
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

# Security: Whitelisted interfaces only
ALLOWED_INTERFACES = frozenset(['wlan_24ghz', 'wlan_5ghz', 'wlan0', 'wlan1'])

# Security: Whitelisted commands only
# deny_acl ADD/DEL for WiFi MAC blocking (prevents reconnection after deauth)
ALLOWED_COMMANDS = frozenset(['deauthenticate', 'list_sta', 'status', 'deny_acl'])

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
        elif action == 'block_mac':
            return self._handle_block_mac(request)
        elif action == 'unblock_mac':
            return self._handle_unblock_mac(request)
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

    def _handle_block_mac(self, request: dict) -> bytes:
        """Handle block_mac request - adds MAC to hostapd deny ACL.

        Uses file-based blocking: modifies deny.mac file once, then
        reloads config on all requested interfaces.
        """
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
            'interfaces_blocked': [],
        }

        # Add MAC to deny file (single file modification)
        file_result = self._modify_deny_file('ADD', mac)
        if not file_result.get('success') and not file_result.get('already_blocked'):
            return json.dumps({'success': False, 'error': file_result.get('error', 'Failed to modify deny file')}).encode()

        # Reload config on each valid interface
        for iface in interfaces:
            valid, iface_or_error = self._validate_interface(iface)
            if not valid:
                continue

            reload_result = self._reload_hostapd_config(iface)
            if reload_result.get('success'):
                results['interfaces_blocked'].append(iface)
                results['success'] = True
                logger.info(f"Blocked {mac} on {iface}")

        return json.dumps(results).encode()

    def _handle_unblock_mac(self, request: dict) -> bytes:
        """Handle unblock_mac request - removes MAC from hostapd deny ACL.

        Uses file-based blocking: modifies deny.mac file once, then
        reloads config on all requested interfaces.
        """
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
            'interfaces_unblocked': [],
        }

        # Remove MAC from deny file (single file modification)
        file_result = self._modify_deny_file('DEL', mac)
        if not file_result.get('success') and not file_result.get('not_blocked'):
            return json.dumps({'success': False, 'error': file_result.get('error', 'Failed to modify deny file')}).encode()

        # Reload config on each valid interface
        for iface in interfaces:
            valid, iface_or_error = self._validate_interface(iface)
            if not valid:
                continue

            reload_result = self._reload_hostapd_config(iface)
            if reload_result.get('success'):
                results['interfaces_unblocked'].append(iface)
                results['success'] = True
                logger.info(f"Unblocked {mac} on {iface}")

        return json.dumps(results).encode()

    def _modify_deny_file(self, action: str, mac: str) -> dict:
        """Modify the deny.mac file (add or remove a MAC address).

        Uses file locking (fcntl.flock) to prevent race conditions when
        multiple requests try to modify the file simultaneously.
        """
        deny_file = '/etc/hostapd/deny.mac'
        lock_file = '/var/run/fts-host-agent/deny.mac.lock'
        mac_upper = mac.upper()

        try:
            # Ensure lock file directory exists
            os.makedirs(os.path.dirname(lock_file), exist_ok=True)

            # Use exclusive lock to prevent race conditions
            with open(lock_file, 'w') as lock_fd:
                try:
                    # Acquire exclusive lock (blocks until available, timeout via SIGALRM if needed)
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                    logger.debug(f"Acquired lock for deny file modification")

                    # Read current deny list
                    current_macs = set()
                    if os.path.exists(deny_file):
                        with open(deny_file, 'r') as f:
                            for line in f:
                                line = line.strip().upper()
                                if line and MAC_REGEX.match(line):
                                    current_macs.add(line)

                    # Modify the list
                    if action == 'ADD':
                        if mac_upper in current_macs:
                            logger.info(f"MAC {mac_upper} already in deny list")
                            return {'success': True, 'already_blocked': True}
                        current_macs.add(mac_upper)
                    elif action == 'DEL':
                        if mac_upper not in current_macs:
                            logger.info(f"MAC {mac_upper} not in deny list")
                            return {'success': True, 'not_blocked': True}
                        current_macs.discard(mac_upper)
                    else:
                        return {'success': False, 'error': 'Invalid action'}

                    # Write updated list atomically (write to temp, then rename)
                    temp_file = deny_file + '.tmp'
                    with open(temp_file, 'w') as f:
                        for m in sorted(current_macs):
                            f.write(m + '\n')
                    os.rename(temp_file, deny_file)

                    logger.info(f"Updated deny file: {action} {mac_upper}")
                    return {'success': True}

                finally:
                    # Release lock (automatic on fd close, but explicit is clearer)
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                    logger.debug(f"Released lock for deny file modification")

        except PermissionError:
            return {'success': False, 'error': f'Permission denied writing to {deny_file}'}
        except BlockingIOError:
            return {'success': False, 'error': 'Could not acquire file lock (timeout)'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _reload_hostapd_config(self, interface: str) -> dict:
        """Reload hostapd config for an interface to apply ACL changes."""
        cmd = ['hostapd_cli', '-i', interface, 'reload_config']
        logger.info(f"Executing: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            success = result.returncode == 0 and 'OK' in result.stdout
            return {
                'success': success,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Command timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _execute_deny_acl(self, action: str, interface: str, mac: str) -> dict:
        """Execute hostapd deny ACL modification via file + reload_config.

        Note: hostapd_cli deny_acl ADD/DEL doesn't work on hostapd 2.11,
        so we use file-based blocking instead:
        1. Read/modify /etc/hostapd/deny.mac
        2. Call reload_config to apply changes
        """
        if action not in ('ADD', 'DEL'):
            return {'success': False, 'error': 'Invalid deny_acl action'}

        deny_file = '/etc/hostapd/deny.mac'
        mac_upper = mac.upper()

        try:
            # Read current deny list
            current_macs = set()
            if os.path.exists(deny_file):
                with open(deny_file, 'r') as f:
                    for line in f:
                        line = line.strip().upper()
                        if line and MAC_REGEX.match(line):
                            current_macs.add(line)

            # Modify the list
            if action == 'ADD':
                if mac_upper in current_macs:
                    logger.info(f"MAC {mac_upper} already in deny list")
                    return {'success': True, 'stdout': 'Already blocked', 'already_blocked': True}
                current_macs.add(mac_upper)
            else:  # DEL
                if mac_upper not in current_macs:
                    logger.info(f"MAC {mac_upper} not in deny list")
                    return {'success': True, 'stdout': 'Not blocked', 'not_blocked': True}
                current_macs.discard(mac_upper)

            # Write updated list
            with open(deny_file, 'w') as f:
                for m in sorted(current_macs):
                    f.write(m + '\n')

            logger.info(f"Updated deny list: {action} {mac_upper}")

            # Reload config to apply changes
            cmd = ['hostapd_cli', '-i', interface, 'reload_config']
            logger.info(f"Executing: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            success = result.returncode == 0 and 'OK' in result.stdout

            return {
                'success': success,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Command timeout'}
        except PermissionError:
            return {'success': False, 'error': f'Permission denied writing to {deny_file}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

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

        # Ensure socket directory exists
        socket_dir = os.path.dirname(self.socket_path)
        if socket_dir and not os.path.exists(socket_dir):
            os.makedirs(socket_dir, mode=0o755)
            logger.info(f"Created socket directory: {socket_dir}")

        # Remove existing socket
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        # Create Unix Domain Socket
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(self.socket_path)
            # Security: Set restrictive permissions (owner + group rw)
            # Container runs as uid/gid 1000 (fortress user), so we set group to 1000
            # This prevents arbitrary local users from sending commands
            os.chmod(self.socket_path, 0o660)
            # Set group to container's gid (1000) for fts-web access
            CONTAINER_GID = 1000  # Container runs as uid/gid 1000
            try:
                os.chown(self.socket_path, -1, CONTAINER_GID)
                logger.info(f"Socket permissions: 0660, group gid {CONTAINER_GID}")
            except PermissionError:
                # Running as non-root, fall back to world-accessible
                logger.warning("Cannot chown socket (not root), using 0o666")
                os.chmod(self.socket_path, 0o666)
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
