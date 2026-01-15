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
        elif action == 'revoke_lease':
            return self._handle_revoke_lease(request)
        elif action == 'apply_policy':
            return self._handle_apply_policy(request)
        elif action == 'l1_status':
            return self._handle_l1_status(request)
        elif action == 'l1_survival_enter':
            return self._handle_l1_survival_enter(request)
        elif action == 'l1_survival_exit':
            return self._handle_l1_survival_exit(request)
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

    def _handle_revoke_lease(self, request: dict) -> bytes:
        """Handle revoke_lease request - removes DHCP lease and clears ARP entry.

        This fully disconnects a device by:
        1. Removing the DHCP lease from dnsmasq.leases
        2. Sending SIGHUP to dnsmasq to reload leases
        3. Deleting the ARP entry for the device's IP
        """
        mac = request.get('mac', '')

        # Validate MAC
        valid, mac_or_error = self._validate_mac(mac)
        if not valid:
            return json.dumps({'success': False, 'error': mac_or_error}).encode()
        mac = mac_or_error.lower()  # dnsmasq uses lowercase

        results = {
            'success': False,
            'mac': mac,
            'lease_removed': False,
            'arp_cleared': False,
            'ip_address': None
        }

        # Find and remove lease from dnsmasq.leases
        lease_file = '/var/lib/misc/dnsmasq.leases'
        try:
            if os.path.exists(lease_file):
                with open(lease_file, 'r') as f:
                    lines = f.readlines()

                new_lines = []
                removed_ip = None
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1].lower() == mac:
                        removed_ip = parts[2]
                        results['ip_address'] = removed_ip
                        logger.info(f"Removing lease for {mac} (IP: {removed_ip})")
                    else:
                        new_lines.append(line)

                if removed_ip:
                    # Write updated lease file
                    with open(lease_file, 'w') as f:
                        f.writelines(new_lines)
                    results['lease_removed'] = True

                    # Send SIGHUP to dnsmasq to reload leases
                    try:
                        subprocess.run(['pkill', '-HUP', 'dnsmasq'], timeout=5)
                        logger.info("Sent SIGHUP to dnsmasq")
                    except Exception as e:
                        logger.warning(f"Failed to signal dnsmasq: {e}")

                    # Clear ARP entry
                    try:
                        subprocess.run(['ip', 'neigh', 'del', removed_ip, 'dev', 'FTS'],
                                       timeout=5, capture_output=True)
                        results['arp_cleared'] = True
                        logger.info(f"Cleared ARP entry for {removed_ip}")
                    except Exception as e:
                        logger.warning(f"Failed to clear ARP: {e}")

                    results['success'] = True
                else:
                    results['error'] = 'No lease found for this MAC'
            else:
                results['error'] = f'Lease file not found: {lease_file}'

        except PermissionError:
            results['error'] = f'Permission denied accessing {lease_file}'
        except Exception as e:
            results['error'] = str(e)

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

    def _handle_apply_policy(self, request: dict) -> bytes:
        """Handle apply_policy request - apply OpenFlow policy rules via nac-policy-sync.sh.

        This calls the nac-policy-sync.sh script's apply_policy function to set
        OpenFlow rules on the OVS bridge (FTS) for network access control.

        Valid policies:
        - quarantine: Block all traffic except DHCP/DNS (highest priority)
        - lan_only: Device-to-device only, no internet
        - internet_only: Internet only, no LAN access
        - smart_home: Full LAN + internet access with discovery
        - full_access: Unrestricted access (removes all per-device rules)
        """
        mac = request.get('mac', '')
        policy = request.get('policy', '')
        priority_mode = request.get('priority_mode', 'default')

        # Validate MAC
        valid, mac_or_error = self._validate_mac(mac)
        if not valid:
            return json.dumps({'success': False, 'error': mac_or_error}).encode()
        mac = mac_or_error

        # Validate policy
        valid_policies = ['quarantine', 'isolated', 'lan_only', 'internet_only', 'smart_home', 'full_access']
        if policy not in valid_policies:
            return json.dumps({
                'success': False,
                'error': f'Invalid policy: {policy}. Valid: {", ".join(valid_policies)}'
            }).encode()

        # Validate priority_mode
        if priority_mode not in ('default', 'override'):
            priority_mode = 'default'

        results = {
            'success': False,
            'mac': mac,
            'policy': policy,
            'priority_mode': priority_mode
        }

        # Path to nac-policy-sync.sh
        nac_script = '/opt/hookprobe/fortress/devices/common/nac-policy-sync.sh'

        if not os.path.exists(nac_script):
            results['error'] = f'NAC policy script not found: {nac_script}'
            return json.dumps(results).encode()

        try:
            # Source the script and call apply_policy function
            # We use bash to source the script and call the function directly
            cmd = [
                'bash', '-c',
                f'source "{nac_script}" && apply_policy "{mac}" "{policy}" "{priority_mode}"'
            ]
            logger.info(f"Applying policy: {policy} to {mac} (mode: {priority_mode})")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # Allow more time for OpenFlow rules
            )

            results['stdout'] = result.stdout.strip()
            results['stderr'] = result.stderr.strip()
            results['returncode'] = result.returncode

            if result.returncode == 0:
                results['success'] = True
                logger.info(f"Successfully applied {policy} policy to {mac}")
            else:
                results['error'] = f'Script returned {result.returncode}'
                logger.error(f"Failed to apply policy: {result.stderr}")

        except subprocess.TimeoutExpired:
            results['error'] = 'Command timeout'
            logger.error(f"Timeout applying policy {policy} to {mac}")
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Error applying policy: {e}")

        return json.dumps(results).encode()

    def _handle_l1_status(self, request: dict) -> bytes:
        """Handle L1/Cellular status request - reads modem data via mmcli.

        Returns cellular connection info including:
        - Network type (5G SA, 5G NSA, LTE, 4G, 3G)
        - Carrier name
        - Signal metrics (RSRP, SINR, SNR)
        - Cell info (Cell ID, PCI, TAC, Band)
        - Trust score (computed from signal quality + tower verification)
        """
        results = {
            'success': True,
            'network_type': None,
            'carrier': None,
            'cell_id': None,
            'pci': None,
            'tac': None,
            'band': None,
            'mcc_mnc': None,
            'rsrp': None,
            'sinr': None,
            'snr': None,
            'timing_advance': None,
            'distance_km': None,
            'handovers_1h': 0,
            'tower_status': 'unknown',
            'trust_score': 50,
            'trust_components': {
                'identity': 50,
                'snr': 50,
                'stability': 50,
                'temporal': 50,
                'handover': 100
            },
            'survival_mode': False,
            'vpn_ready': False,
            # Security gauge fields
            'rrc_state': None,
            'neighbor_count': None,
            'earfcn_valid': None,
            'expected_band': None
        }

        try:
            # Try to find modem using mmcli
            modem_id = self._find_modem()
            if modem_id is None:
                # No modem found - return demo/fallback data
                results['error'] = 'No modem found'
                results['network_type'] = 'No Modem'
                results['trust_score'] = 0
                return json.dumps(results).encode()

            # Get modem status
            modem_info = self._get_modem_info(modem_id)
            if modem_info:
                results.update(modem_info)

            # Get signal quality
            signal_info = self._get_signal_info(modem_id)
            if signal_info:
                results.update(signal_info)

            # Get location/cell info
            location_info = self._get_location_info(modem_id)
            if location_info:
                results.update(location_info)

            # Try mbimcli for more detailed signal/registration info
            mbim_info = self._get_mbim_info()
            if mbim_info:
                # Merge mbim data - prefer mbim values for certain fields
                if mbim_info.get('sinr') and not results.get('sinr'):
                    results['sinr'] = mbim_info['sinr']
                if mbim_info.get('network_type_detail'):
                    results['network_type_detail'] = mbim_info['network_type_detail']
                # Update SNR with best value (prefer 5G if available)
                if mbim_info.get('snr_5g') is not None:
                    results['snr'] = mbim_info['snr_5g']
                    results['snr_5g'] = mbim_info['snr_5g']
                if mbim_info.get('snr_lte') is not None:
                    results['snr_lte'] = mbim_info['snr_lte']
                if mbim_info.get('rsrp_5g') is not None:
                    results['rsrp_5g'] = mbim_info['rsrp_5g']
                if mbim_info.get('rsrp_lte') is not None:
                    results['rsrp_lte'] = mbim_info['rsrp_lte']

            # Try qmicli for PCI, Band, EARFCN, neighbors (Sierra Wireless)
            qmi_info = self._get_qmi_info()
            if qmi_info:
                # QMI provides PCI, Band, neighbors that mmcli/mbimcli don't
                if qmi_info.get('pci') and not results.get('pci'):
                    results['pci'] = qmi_info['pci']
                if qmi_info.get('band') and not results.get('band'):
                    results['band'] = qmi_info['band']
                if qmi_info.get('earfcn'):
                    results['earfcn'] = qmi_info['earfcn']
                if qmi_info.get('neighbors'):
                    results['neighbors'] = qmi_info['neighbors']
                if qmi_info.get('global_cell_id'):
                    results['global_cell_id'] = qmi_info['global_cell_id']
                if qmi_info.get('nr_arfcn'):
                    results['nr_arfcn'] = qmi_info['nr_arfcn']
                # Distance from timing advance
                if qmi_info.get('distance_km') is not None and not results.get('distance_km'):
                    results['distance_km'] = qmi_info['distance_km']
                    results['timing_advance'] = qmi_info.get('timing_advance')
                # Prefer QMI signal values (more accurate)
                if qmi_info.get('rsrp_5g') is not None:
                    results['rsrp_5g'] = qmi_info['rsrp_5g']
                if qmi_info.get('rsrp_lte') is not None:
                    results['rsrp_lte'] = qmi_info['rsrp_lte']
                if qmi_info.get('snr_5g') is not None:
                    results['snr_5g'] = qmi_info['snr_5g']
                    results['snr'] = qmi_info['snr_5g']  # Use 5G SNR as primary
                if qmi_info.get('snr_lte') is not None:
                    results['snr_lte'] = qmi_info['snr_lte']
                if qmi_info.get('rsrq_5g') is not None:
                    results['rsrq_5g'] = qmi_info['rsrq_5g']
                if qmi_info.get('rsrq_lte') is not None:
                    results['rsrq_lte'] = qmi_info['rsrq_lte']
                if qmi_info.get('rssi') is not None:
                    results['rssi'] = qmi_info['rssi']
                # Security gauge fields
                if qmi_info.get('rrc_state'):
                    results['rrc_state'] = qmi_info['rrc_state']
                if qmi_info.get('neighbor_count') is not None:
                    results['neighbor_count'] = qmi_info['neighbor_count']
                if 'earfcn_valid' in qmi_info:
                    results['earfcn_valid'] = qmi_info['earfcn_valid']
                if qmi_info.get('expected_band'):
                    results['expected_band'] = qmi_info['expected_band']

            # Compute trust score based on signal quality
            results['trust_score'], results['trust_components'] = self._compute_l1_trust(results)

            # Check VPN readiness
            results['vpn_ready'] = self._check_vpn_ready()

            # Check survival mode state
            results['survival_mode'] = self._check_survival_mode()

            logger.info(f"L1 status: {results.get('network_type')} on {results.get('carrier')}")

        except Exception as e:
            logger.error(f"Error getting L1 status: {e}")
            results['error'] = str(e)

        return json.dumps(results).encode()

    def _find_modem(self) -> Optional[int]:
        """Find first available modem using mmcli."""
        try:
            result = subprocess.run(
                ['mmcli', '-L'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and '/Modem/' in result.stdout:
                # Parse modem ID from output like "/org/freedesktop/ModemManager1/Modem/0"
                for line in result.stdout.split('\n'):
                    if '/Modem/' in line:
                        parts = line.split('/Modem/')
                        if len(parts) > 1:
                            modem_part = parts[1].split()[0].strip()
                            return int(modem_part)
            return None
        except FileNotFoundError:
            logger.debug("mmcli not installed")
            return None
        except Exception as e:
            logger.debug(f"Error finding modem: {e}")
            return None

    def _get_modem_info(self, modem_id: int) -> dict:
        """Get modem basic info."""
        info = {}
        try:
            result = subprocess.run(
                ['mmcli', '-m', str(modem_id)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout

                # Parse carrier/operator
                for line in output.split('\n'):
                    line = line.strip()
                    if 'operator name:' in line.lower():
                        info['carrier'] = line.split(':', 1)[1].strip()
                    elif 'access tech:' in line.lower():
                        tech = line.split(':', 1)[1].strip().upper()
                        if '5G' in tech and 'SA' in tech:
                            info['network_type'] = '5G SA'
                        elif '5G' in tech or 'NR' in tech:
                            info['network_type'] = '5G'
                        elif 'LTE' in tech:
                            info['network_type'] = 'LTE'
                        elif 'HSPA' in tech or 'UMTS' in tech:
                            info['network_type'] = '3G'
                        elif 'EDGE' in tech or 'GPRS' in tech:
                            info['network_type'] = '2G'
                        else:
                            info['network_type'] = tech

        except Exception as e:
            logger.debug(f"Error getting modem info: {e}")
        return info

    def _get_signal_info(self, modem_id: int) -> dict:
        """Get signal quality metrics."""
        info = {}
        try:
            result = subprocess.run(
                ['mmcli', '-m', str(modem_id), '--signal-get'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout

                for line in output.split('\n'):
                    line = line.strip().lower()
                    if 'rsrp:' in line:
                        try:
                            val = line.split('rsrp:')[1].strip().split()[0]
                            info['rsrp'] = float(val)
                        except (ValueError, IndexError):
                            pass
                    elif 'rsrq:' in line:
                        try:
                            val = line.split('rsrq:')[1].strip().split()[0]
                            info['rsrq'] = float(val)
                        except (ValueError, IndexError):
                            pass
                    elif 'sinr:' in line:
                        try:
                            val = line.split('sinr:')[1].strip().split()[0]
                            info['sinr'] = float(val)
                        except (ValueError, IndexError):
                            pass
                    elif 'snr:' in line:
                        try:
                            val = line.split('snr:')[1].strip().split()[0]
                            info['snr'] = float(val)
                        except (ValueError, IndexError):
                            pass
                    # Handle 's/n:' format (mmcli signal output)
                    elif 's/n:' in line:
                        try:
                            val = line.split('s/n:')[1].strip().split()[0]
                            info['snr'] = float(val)
                        except (ValueError, IndexError):
                            pass

                # If no SNR, estimate from SINR
                if 'snr' not in info and 'sinr' in info:
                    info['snr'] = info['sinr']

        except Exception as e:
            logger.debug(f"Error getting signal info: {e}")
        return info

    def _get_location_info(self, modem_id: int) -> dict:
        """Get cell location info."""
        info = {}
        try:
            result = subprocess.run(
                ['mmcli', '-m', str(modem_id), '--location-get'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout

                for line in output.split('\n'):
                    line_lower = line.strip().lower()
                    # Cell ID - handle both 'cell id:' and 'cid:'
                    if 'cell id:' in line_lower or 'cid:' in line_lower:
                        try:
                            # Find the ':' and get everything after
                            idx = line.find(':')
                            if idx > -1:
                                val = line[idx+1:].strip().split()[0]
                                info['cell_id'] = val
                        except (ValueError, IndexError):
                            pass
                    # TAC - handle 'tracking area code:', 'tac:', 'lac:'
                    elif 'tracking area code:' in line_lower:
                        try:
                            idx = line.lower().find('tracking area code:')
                            val = line[idx + len('tracking area code:'):].strip().split()[0]
                            info['tac'] = val
                        except (ValueError, IndexError):
                            pass
                    elif 'location area code:' in line_lower:
                        try:
                            idx = line.lower().find('location area code:')
                            val = line[idx + len('location area code:'):].strip().split()[0]
                            info['lac'] = val
                        except (ValueError, IndexError):
                            pass
                    elif ('lac:' in line_lower or 'tac:' in line_lower) and 'tracking' not in line_lower and 'location' not in line_lower:
                        try:
                            val = line.split(':')[-1].strip().split()[0]
                            info['tac'] = val
                        except (ValueError, IndexError):
                            pass
                    # MCC - handle 'operator mcc:' and 'mcc:'
                    elif 'operator mcc:' in line_lower:
                        try:
                            idx = line.lower().find('operator mcc:')
                            val = line[idx + len('operator mcc:'):].strip().split()[0]
                            info['mcc'] = val
                        except (ValueError, IndexError):
                            pass
                    elif 'mcc:' in line_lower and 'operator' not in line_lower:
                        try:
                            val = line.split(':')[-1].strip().split()[0]
                            info['mcc'] = val
                        except (ValueError, IndexError):
                            pass
                    # MNC - handle 'operator mnc:' and 'mnc:'
                    elif 'operator mnc:' in line_lower:
                        try:
                            idx = line.lower().find('operator mnc:')
                            val = line[idx + len('operator mnc:'):].strip().split()[0]
                            info['mnc'] = val
                        except (ValueError, IndexError):
                            pass
                    elif 'mnc:' in line_lower and 'operator' not in line_lower:
                        try:
                            val = line.split(':')[-1].strip().split()[0]
                            info['mnc'] = val
                        except (ValueError, IndexError):
                            pass

                # Build MCC-MNC
                if 'mcc' in info and 'mnc' in info:
                    info['mcc_mnc'] = f"{info['mcc']}-{info['mnc']}"
                    del info['mcc']
                    del info['mnc']

        except Exception as e:
            logger.debug(f"Error getting location info: {e}")
        return info

    def _find_mbim_device(self) -> Optional[str]:
        """Find MBIM device path."""
        import glob
        # Look for cdc-wdm devices
        devices = glob.glob('/dev/cdc-wdm*')
        for dev in sorted(devices):
            try:
                # Quick test if this is a valid MBIM device
                result = subprocess.run(
                    ['mbimcli', '-d', dev, '-p', '--query-device-caps'],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if result.returncode == 0:
                    return dev
            except Exception:
                continue
        return None

    def _get_mbim_info(self) -> dict:
        """Get detailed signal info from mbimcli.

        Returns additional data not available from mmcli:
        - Separate 5G and LTE signal values
        - Network type detail (5G-NSA, 5G-SA, LTE)
        """
        info = {}
        try:
            # Find MBIM device
            mbim_dev = self._find_mbim_device()
            if not mbim_dev:
                return info

            # Query signal state for detailed RSRP/SNR
            result = subprocess.run(
                ['mbimcli', '-d', mbim_dev, '-p', '--query-signal-state'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout
                current_tech = None

                for line in output.split('\n'):
                    line_lower = line.strip().lower()

                    # Detect technology section
                    if "rsrp/snr info: '5g" in line_lower or "rsrp/snr info: '5g-nsa'" in line_lower:
                        current_tech = '5g'
                    elif "rsrp/snr info: 'lte'" in line_lower:
                        current_tech = 'lte'

                    # Parse RSRP
                    if 'rsrp:' in line_lower and 'threshold' not in line_lower:
                        try:
                            val = line.split(':')[1].strip().split()[0].replace("'", "")
                            rsrp_val = float(val)
                            if current_tech == '5g':
                                info['rsrp_5g'] = rsrp_val
                            elif current_tech == 'lte':
                                info['rsrp_lte'] = rsrp_val
                        except (ValueError, IndexError):
                            pass

                    # Parse SNR
                    if 'snr:' in line_lower and 'threshold' not in line_lower:
                        try:
                            val = line.split(':')[1].strip().split()[0].replace("'", "")
                            snr_val = float(val)
                            if current_tech == '5g':
                                info['snr_5g'] = snr_val
                            elif current_tech == 'lte':
                                info['snr_lte'] = snr_val
                        except (ValueError, IndexError):
                            pass

            # Query registration state for data class detail
            result = subprocess.run(
                ['mbimcli', '-d', mbim_dev, '-p', '--query-registration-state'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout
                for line in output.split('\n'):
                    line_lower = line.strip().lower()
                    if 'available data classes:' in line_lower:
                        classes = line.split(':')[1].strip().replace("'", "")
                        if '5g-nsa' in classes.lower():
                            info['network_type_detail'] = '5G NSA'
                        elif '5g' in classes.lower():
                            info['network_type_detail'] = '5G SA'
                        elif 'lte' in classes.lower():
                            info['network_type_detail'] = 'LTE'

        except FileNotFoundError:
            logger.debug("mbimcli not installed")
        except Exception as e:
            logger.debug(f"Error getting MBIM info: {e}")

        return info

    def _find_qmi_device(self) -> Optional[str]:
        """Find QMI device path."""
        import glob
        devices = glob.glob('/dev/cdc-wdm*')
        for dev in sorted(devices):
            try:
                result = subprocess.run(
                    ['qmicli', '-d', dev, '-p', '--dms-get-manufacturer'],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if result.returncode == 0:
                    return dev
            except Exception:
                continue
        return None

    def _get_qmi_info(self) -> dict:
        """Get detailed cell info from qmicli (Sierra Wireless).

        Returns PCI, Band, EARFCN, neighbors, timing advance, and RRC state.
        """
        info = {}
        try:
            qmi_dev = self._find_qmi_device()
            if not qmi_dev:
                return info

            # Get SWI status for Band info and RRC state
            result = subprocess.run(
                ['qmicli', '-d', qmi_dev, '-p', '--nas-swi-get-status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout
                for line in output.split('\n'):
                    line_stripped = line.strip()
                    if "Band:" in line_stripped:
                        # Parse: Band: 'bc-3' -> B3
                        match = line_stripped.split("'")
                        if len(match) >= 2:
                            band_raw = match[1]  # bc-3
                            # Convert bc-3 to B3, bc-7 to B7, etc.
                            if band_raw.startswith('bc-'):
                                info['band'] = f"B{band_raw[3:]}"
                            else:
                                info['band'] = band_raw
                    # RRC State - EMM connection state
                    elif "EMM connection state:" in line_stripped:
                        # Parse: EMM connection state: 'rrc-connecting' -> rrc-connecting
                        match = line_stripped.split("'")
                        if len(match) >= 2:
                            info['rrc_state'] = match[1]  # rrc-idle, rrc-connecting, rrc-connected

            # Get signal info
            result = subprocess.run(
                ['qmicli', '-d', qmi_dev, '-p', '--nas-get-signal-info'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout
                current_tech = None
                for line in output.split('\n'):
                    line_stripped = line.strip()
                    if line_stripped == 'LTE:':
                        current_tech = 'lte'
                    elif line_stripped == '5G:':
                        current_tech = '5g'
                    elif "RSRP:" in line_stripped:
                        val = line_stripped.split("'")[1].split()[0] if "'" in line_stripped else None
                        if val:
                            if current_tech == '5g':
                                info['rsrp_5g'] = float(val)
                            elif current_tech == 'lte':
                                info['rsrp_lte'] = float(val)
                    elif "SNR:" in line_stripped:
                        val = line_stripped.split("'")[1].split()[0] if "'" in line_stripped else None
                        if val:
                            if current_tech == '5g':
                                info['snr_5g'] = float(val)
                            elif current_tech == 'lte':
                                info['snr_lte'] = float(val)
                    elif "RSRQ:" in line_stripped:
                        val = line_stripped.split("'")[1].split()[0] if "'" in line_stripped else None
                        if val:
                            if current_tech == '5g':
                                info['rsrq_5g'] = float(val)
                            elif current_tech == 'lte':
                                info['rsrq_lte'] = float(val)
                    elif "RSSI:" in line_stripped:
                        val = line_stripped.split("'")[1].split()[0] if "'" in line_stripped else None
                        if val and current_tech == 'lte':
                            info['rssi'] = float(val)

            # Get cell location info for PCI and neighbors
            result = subprocess.run(
                ['qmicli', '-d', qmi_dev, '-p', '--nas-get-cell-location-info'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout
                pcis = []
                serving_pci = None
                in_intra = False

                for line in output.split('\n'):
                    line_stripped = line.strip()

                    if 'Intrafrequency LTE Info' in line_stripped:
                        in_intra = True
                    elif 'Interfrequency LTE Info' in line_stripped:
                        in_intra = False

                    # Get serving cell PCI
                    if "Serving Cell ID:" in line_stripped:
                        val = line_stripped.split("'")[1] if "'" in line_stripped else None
                        if val:
                            serving_pci = val
                            info['pci'] = val

                    # Get EARFCN
                    if "EUTRA Absolute RF Channel Number:" in line_stripped:
                        val = line_stripped.split("'")[1] if "'" in line_stripped else None
                        if val and 'earfcn' not in info:
                            info['earfcn'] = val

                    # Get Global Cell ID
                    if "Global Cell ID:" in line_stripped:
                        val = line_stripped.split("'")[1] if "'" in line_stripped else None
                        if val:
                            info['global_cell_id'] = val

                    # Get neighbor PCIs (from intrafrequency section)
                    if "Physical Cell ID:" in line_stripped and in_intra:
                        val = line_stripped.split("'")[1] if "'" in line_stripped else None
                        if val and val != serving_pci:
                            pcis.append(val)

                    # Get timing advance
                    if "LTE Timing Advance:" in line_stripped:
                        val = line_stripped.split("'")[1].split()[0] if "'" in line_stripped else None
                        if val:
                            try:
                                ta_us = float(val)
                                # TA in µs, distance = TA * c / 2 where c ≈ 300m/µs
                                info['timing_advance'] = ta_us
                                info['distance_km'] = round(ta_us * 0.3 / 2, 2)
                            except ValueError:
                                pass

                    # Get 5G ARFCN
                    if "5GNR ARFCN:" in line_stripped:
                        val = line_stripped.split("'")[1] if "'" in line_stripped else None
                        if val:
                            info['nr_arfcn'] = val

                if pcis:
                    info['neighbors'] = ','.join(pcis[:5])  # Limit to 5 neighbors
                    info['neighbor_count'] = len(pcis)  # Total neighbor count

        except FileNotFoundError:
            logger.debug("qmicli not installed")
        except Exception as e:
            logger.debug(f"Error getting QMI info: {e}")

        # EARFCN-to-Band validation (security check for protocol spoofing)
        if 'earfcn' in info and 'band' in info:
            earfcn_valid, expected_band = self._validate_earfcn_band(
                int(info['earfcn']), info['band']
            )
            info['earfcn_valid'] = earfcn_valid
            if not earfcn_valid:
                info['expected_band'] = expected_band
                logger.warning(f"EARFCN spoofing detected: EARFCN {info['earfcn']} "
                              f"should be {expected_band}, not {info['band']}")

        return info

    def _validate_earfcn_band(self, earfcn: int, claimed_band: str) -> Tuple[bool, str]:
        """Validate that EARFCN belongs to claimed Band.

        Returns:
            Tuple of (is_valid, expected_band_for_earfcn)
        """
        # LTE EARFCN to Band mapping (FDD DL bands)
        # Reference: 3GPP TS 36.101
        earfcn_bands = [
            (0, 599, 'B1'),       # Band 1: 2100 MHz
            (600, 1199, 'B2'),    # Band 2: 1900 MHz (PCS)
            (1200, 1949, 'B3'),   # Band 3: 1800 MHz (DCS)
            (1950, 2399, 'B4'),   # Band 4: AWS-1
            (2400, 2649, 'B5'),   # Band 5: 850 MHz
            (2650, 2749, 'B6'),   # Band 6: UMTS 800
            (2750, 3449, 'B7'),   # Band 7: 2600 MHz
            (3450, 3799, 'B8'),   # Band 8: 900 MHz
            (3800, 4149, 'B9'),   # Band 9: 1800 MHz Japan
            (4150, 4749, 'B10'),  # Band 10: AWS-3
            (4750, 4949, 'B11'),  # Band 11: 1500 MHz Lower
            (5010, 5179, 'B12'),  # Band 12: 700 MHz Lower A/B/C
            (5180, 5279, 'B13'),  # Band 13: 700 MHz Upper C
            (5280, 5379, 'B14'),  # Band 14: 700 MHz Public Safety
            (5730, 5849, 'B17'),  # Band 17: 700 MHz Lower B/C
            (5850, 5999, 'B18'),  # Band 18: 800 MHz Lower
            (6000, 6149, 'B19'),  # Band 19: 800 MHz Upper
            (6150, 6449, 'B20'),  # Band 20: 800 MHz DD
            (6450, 6599, 'B21'),  # Band 21: 1500 MHz Upper
            (6600, 7399, 'B22'),  # Band 22: 3500 MHz
            (7500, 7699, 'B23'),  # Band 23: 2000 MHz S-band
            (7700, 8039, 'B24'),  # Band 24: 1600 MHz L-band
            (8040, 8689, 'B25'),  # Band 25: Extended PCS
            (8690, 9039, 'B26'),  # Band 26: Extended 850
            (9040, 9209, 'B27'),  # Band 27: 800 MHz SMR
            (9210, 9659, 'B28'),  # Band 28: 700 MHz APT
            (9660, 9769, 'B29'),  # Band 29: 700 MHz SDL
            (9770, 9869, 'B30'),  # Band 30: 2300 MHz WCS
            (9870, 9919, 'B31'),  # Band 31: 450 MHz
            (9920, 10359, 'B32'), # Band 32: 1500 MHz L-band SDL
            (36000, 36199, 'B33'),# Band 33: TDD 1900 MHz
            (36200, 36349, 'B34'),# Band 34: TDD 2000 MHz
            (36350, 36949, 'B35'),# Band 35: TDD PCS
            (36950, 37549, 'B36'),# Band 36: TDD PCS
            (37550, 37749, 'B37'),# Band 37: TDD PCS Gap
            (37750, 38249, 'B38'),# Band 38: TDD 2600 MHz
            (38250, 38649, 'B39'),# Band 39: TDD 1900 MHz
            (38650, 39649, 'B40'),# Band 40: TDD 2300 MHz
            (39650, 41589, 'B41'),# Band 41: TDD 2500 MHz
            (41590, 43589, 'B42'),# Band 42: TDD 3500 MHz
            (43590, 45589, 'B43'),# Band 43: TDD 3700 MHz
            (65536, 66435, 'B65'),# Band 65: Extended Band 1
            (66436, 67335, 'B66'),# Band 66: Extended AWS
            (67336, 67535, 'B67'),# Band 67: 700 MHz EU SDL
            (67536, 67835, 'B68'),# Band 68: 700 MHz ME
            (67836, 68335, 'B69'),# Band 69: 2600 MHz SDL
            (68336, 68585, 'B70'),# Band 70: AWS-3 Supplemental
            (68586, 68935, 'B71'),# Band 71: 600 MHz
            (68936, 68985, 'B72'),# Band 72: 450 MHz PMR
            (68986, 69035, 'B73'),# Band 73: 450 MHz
            (69036, 69465, 'B74'),# Band 74: L-band
            (69466, 70315, 'B75'),# Band 75: 1500 MHz SDL
            (70316, 70365, 'B76'),# Band 76: 1500 MHz SDL
        ]

        # Normalize claimed band
        claimed_upper = claimed_band.upper()
        if not claimed_upper.startswith('B'):
            claimed_upper = f'B{claimed_upper}'

        # Find the band for this EARFCN
        actual_band = None
        for start, end, band in earfcn_bands:
            if start <= earfcn <= end:
                actual_band = band
                break

        if actual_band is None:
            return True, 'Unknown'  # Can't validate, assume OK

        return actual_band == claimed_upper, actual_band

    def _compute_l1_trust(self, data: dict) -> Tuple[int, dict]:
        """Compute L1 trust score based on signal quality and tower verification.

        Returns:
            Tuple of (trust_score, components_dict)
        """
        components = {
            'identity': 50,  # Tower identity verification (OpenCellID)
            'snr': 50,       # Signal-to-noise ratio
            'stability': 90, # Signal stability (placeholder)
            'temporal': 95,  # Temporal consistency (placeholder)
            'handover': 100  # Handover frequency (placeholder)
        }

        # Identity score based on tower verification
        mcc_mnc = data.get('mcc_mnc', '')
        cell_id = data.get('cell_id', '')
        carrier = data.get('carrier', '')

        # Rule 1: Known carrier eNB patterns (reduces false positives)
        # Vodafone RO eNB pattern: 226-01 with cell ID starting with 0E45
        if mcc_mnc == '226-01' and cell_id.startswith('0E45'):
            components['identity'] = 100  # Vodafone RO internal pattern confirmed
        # Orange RO eNB pattern
        elif mcc_mnc == '226-10' and cell_id:
            components['identity'] = 95  # Orange RO carrier confirmed
        # Telekom RO eNB pattern
        elif mcc_mnc == '226-06' and cell_id:
            components['identity'] = 95  # Telekom RO carrier confirmed
        # Generic known carrier with cell ID
        elif cell_id and carrier:
            components['identity'] = 80  # Known carrier, but not pattern verified
        else:
            components['identity'] = 30

        # SNR score - use best available (5G NSA has both LTE and NR signals)
        snr_candidates = [
            data.get('snr'),
            data.get('snr_5g'),
            data.get('snr_lte'),
            data.get('sinr')
        ]
        snr = max((s for s in snr_candidates if s is not None), default=None)
        if snr is not None:
            if snr >= 20:
                components['snr'] = 100
            elif snr >= 10:
                components['snr'] = 80
            elif snr >= 5:
                components['snr'] = 60
            elif snr >= 0:
                components['snr'] = 40
            else:
                components['snr'] = 20

        # RSRP-based stability - use best available signal strength
        rsrp_candidates = [
            data.get('rsrp'),
            data.get('rsrp_5g'),
            data.get('rsrp_lte')
        ]
        # RSRP is negative, so "best" is the highest (least negative) value
        rsrp = max((r for r in rsrp_candidates if r is not None), default=None)
        if rsrp is not None:
            if rsrp >= -80:
                components['stability'] = 100
            elif rsrp >= -90:
                components['stability'] = 85
            elif rsrp >= -100:
                components['stability'] = 70
            elif rsrp >= -110:
                components['stability'] = 50
            else:
                components['stability'] = 30

        # Rule 2: 5G NSA Anchor Logic - rrc-connecting is normal during 5G handshake
        rrc_state = data.get('rrc_state', '')
        network_type = data.get('network_type_detail', '') or data.get('network_type', '')
        is_5g = '5g' in network_type.lower()

        if rrc_state == 'rrc-connecting' and is_5g:
            # 5G NSA requires LTE anchor - connecting state is normal during handshake
            components['temporal'] = 95  # Don't penalize for 5G handshake
        elif rrc_state == 'rrc-connected':
            # Best state - active data connection
            components['temporal'] = 100
        elif rrc_state == 'rrc-idle':
            # Normal idle state - phone is dormant
            components['temporal'] = 95
        elif rrc_state == 'rrc-connecting':
            # LTE-only connecting state - could be suspicious if prolonged
            components['temporal'] = 75  # Slightly lower for non-5G connecting

        # Rule 3: Dynamic Neighbor Density - adjust for signal range
        neighbor_count = data.get('neighbor_count')
        if neighbor_count is not None and rsrp is not None:
            if neighbor_count >= 2 and rsrp < -90:
                # At range edge, fewer neighbors is expected
                components['handover'] = 100  # Normal (range limited)
            elif neighbor_count >= 3:
                # Good number of neighbors
                components['handover'] = 100
            elif neighbor_count >= 1:
                # Low neighbors but present
                components['handover'] = 85
            else:
                # No neighbors visible - suspicious unless at extreme range
                components['handover'] = rsrp < -100 and 70 or 50

        # Weighted trust score
        # Weights: identity=35%, snr=20%, stability=15%, temporal=15%, handover=15%
        trust_score = int(
            components['identity'] * 0.35 +
            components['snr'] * 0.20 +
            components['stability'] * 0.15 +
            components['temporal'] * 0.15 +
            components['handover'] * 0.15
        )

        return trust_score, components

    def _check_vpn_ready(self) -> bool:
        """Check if VPN is ready for survival mode."""
        # Check if WireGuard or OpenVPN interface exists
        try:
            result = subprocess.run(
                ['ip', 'link', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                return 'wg0' in output or 'tun0' in output or 'wg-fortress' in output
        except Exception:
            pass
        return False

    def _check_survival_mode(self) -> bool:
        """Check if survival mode is currently active."""
        survival_file = '/var/run/fortress/l1_survival_mode'
        return os.path.exists(survival_file)

    def _handle_l1_survival_enter(self, request: dict) -> bytes:
        """Enter L1 survival mode - lock down cellular protocols."""
        results = {
            'success': False,
            'actions_taken': []
        }

        try:
            # Create survival mode marker file
            survival_dir = '/var/run/fortress'
            os.makedirs(survival_dir, exist_ok=True)
            survival_file = os.path.join(survival_dir, 'l1_survival_mode')

            with open(survival_file, 'w') as f:
                f.write(json.dumps({
                    'activated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'trigger': request.get('trigger', 'manual')
                }))
            results['actions_taken'].append('survival_mode_enabled')

            # Attempt to disable 2G/3G fallback (if supported)
            modem_id = self._find_modem()
            if modem_id is not None:
                try:
                    # Try to set modem to LTE-only mode
                    subprocess.run(
                        ['mmcli', '-m', str(modem_id), '--set-allowed-modes=4g'],
                        capture_output=True,
                        timeout=10
                    )
                    results['actions_taken'].append('protocol_lockdown_2g_3g')
                except Exception as e:
                    logger.warning(f"Could not set LTE-only mode: {e}")

            results['success'] = True
            logger.info("Entered L1 survival mode")

        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Failed to enter survival mode: {e}")

        return json.dumps(results).encode()

    def _handle_l1_survival_exit(self, request: dict) -> bytes:
        """Exit L1 survival mode - restore normal operation."""
        results = {
            'success': False,
            'actions_taken': []
        }

        try:
            # Remove survival mode marker file
            survival_file = '/var/run/fortress/l1_survival_mode'
            if os.path.exists(survival_file):
                os.unlink(survival_file)
                results['actions_taken'].append('survival_mode_disabled')

            # Restore normal modem modes
            modem_id = self._find_modem()
            if modem_id is not None:
                try:
                    # Restore auto mode selection
                    subprocess.run(
                        ['mmcli', '-m', str(modem_id), '--set-allowed-modes=any'],
                        capture_output=True,
                        timeout=10
                    )
                    results['actions_taken'].append('protocol_lockdown_removed')
                except Exception as e:
                    logger.warning(f"Could not restore modem modes: {e}")

            results['success'] = True
            logger.info("Exited L1 survival mode")

        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Failed to exit survival mode: {e}")

        return json.dumps(results).encode()

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
