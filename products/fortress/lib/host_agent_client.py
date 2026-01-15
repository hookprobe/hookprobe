"""
FTS Host Agent Client - Unix Domain Socket client for hostapd control.

This module provides a secure client interface for the fts-web container to
communicate with the host-side agent for WiFi device management.

Part of HookProbe Fortress - G.N.C. Security Architecture
"""

import hashlib
import hmac
import json
import logging
import os
import re
import socket
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Socket path (mounted into container as directory)
# Note: Directory mount required for podman/docker socket bind mounts
SOCKET_PATH = "/var/run/fts-host-agent/fts-host-agent.sock"
SECRET_FILE = "/etc/hookprobe/fts-agent-secret"

# MAC validation regex
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

# Default interfaces to try
DEFAULT_INTERFACES = ['wlan_24ghz', 'wlan_5ghz', 'wlan0', 'wlan1']


class HostAgentClient:
    """Client for communicating with FTS Host Agent via Unix Domain Socket."""

    def __init__(self, socket_path: str = SOCKET_PATH, timeout: float = 10.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self.secret: Optional[bytes] = None
        self._load_secret()

    def _load_secret(self) -> None:
        """Load shared secret for HMAC authentication."""
        try:
            if os.path.exists(SECRET_FILE):
                with open(SECRET_FILE, 'rb') as f:
                    self.secret = f.read().strip()
        except Exception as e:
            logger.debug(f"Could not load secret: {e}")

    def _sign_request(self, action: str, mac: str = '', interface: str = '') -> str:
        """Generate HMAC signature for request."""
        if not self.secret:
            return ''
        msg = f"{action}{mac}{interface}".encode()
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

    def _validate_mac(self, mac: str) -> str:
        """Validate and normalize MAC address."""
        if not mac:
            raise ValueError("MAC address required")

        # Normalize
        mac = mac.upper().replace('-', ':')

        # Strict validation
        if not MAC_REGEX.match(mac):
            raise ValueError(f"Invalid MAC address format: {mac}")

        return mac

    def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to host agent and receive response."""
        if not os.path.exists(self.socket_path):
            return {
                'success': False,
                'error': 'Host agent socket not available',
                'socket_missing': True
            }

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            sock.connect(self.socket_path)

            # Send request
            data = json.dumps(request).encode('utf-8')
            sock.sendall(data)

            # Receive response
            response_data = sock.recv(8192)
            sock.close()

            if response_data:
                return json.loads(response_data.decode('utf-8'))
            else:
                return {'success': False, 'error': 'Empty response from agent'}

        except socket.timeout:
            return {'success': False, 'error': 'Connection timeout'}
        except ConnectionRefusedError:
            return {'success': False, 'error': 'Host agent not running'}
        except FileNotFoundError:
            return {'success': False, 'error': 'Host agent socket not found', 'socket_missing': True}
        except json.JSONDecodeError as e:
            return {'success': False, 'error': f'Invalid response: {e}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def ping(self) -> Dict[str, Any]:
        """Check if host agent is available."""
        return self._send_request({
            'action': 'ping',
            'signature': self._sign_request('ping')
        })

    def is_available(self) -> bool:
        """Check if host agent is available and responding."""
        result = self.ping()
        return result.get('success', False) and result.get('message') == 'pong'

    def deauthenticate(
        self,
        mac: str,
        interfaces: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Deauthenticate a WiFi client.

        Args:
            mac: MAC address of device to disconnect
            interfaces: List of interfaces to try (default: all)

        Returns:
            Dict with success status, interfaces tried, and results
        """
        try:
            mac = self._validate_mac(mac)
        except ValueError as e:
            return {'success': False, 'error': str(e)}

        if interfaces is None:
            interfaces = DEFAULT_INTERFACES

        request = {
            'action': 'deauthenticate',
            'mac': mac,
            'interfaces': interfaces,
            'signature': self._sign_request('deauthenticate', mac)
        }

        return self._send_request(request)

    def list_clients(self, interface: str = 'wlan_24ghz') -> Dict[str, Any]:
        """
        List connected WiFi clients on an interface.

        Args:
            interface: WiFi interface to query

        Returns:
            Dict with list of connected MAC addresses
        """
        request = {
            'action': 'list_clients',
            'interface': interface,
            'signature': self._sign_request('list_clients', '', interface)
        }

        return self._send_request(request)

    def status(self, interface: str = 'wlan_24ghz') -> Dict[str, Any]:
        """
        Get hostapd status for an interface.

        Args:
            interface: WiFi interface to query

        Returns:
            Dict with hostapd status information
        """
        request = {
            'action': 'status',
            'interface': interface,
            'signature': self._sign_request('status', '', interface)
        }

        return self._send_request(request)

    def block_mac(
        self,
        mac: str,
        interfaces: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Block a MAC address from connecting to WiFi (adds to deny ACL).

        Args:
            mac: MAC address to block
            interfaces: List of interfaces to block on (default: all)

        Returns:
            Dict with success status and interfaces blocked
        """
        try:
            mac = self._validate_mac(mac)
        except ValueError as e:
            return {'success': False, 'error': str(e)}

        if interfaces is None:
            interfaces = DEFAULT_INTERFACES

        request = {
            'action': 'block_mac',
            'mac': mac,
            'interfaces': interfaces,
            'signature': self._sign_request('block_mac', mac)
        }

        return self._send_request(request)

    def unblock_mac(
        self,
        mac: str,
        interfaces: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Unblock a MAC address (removes from deny ACL).

        Args:
            mac: MAC address to unblock
            interfaces: List of interfaces to unblock on (default: all)

        Returns:
            Dict with success status and interfaces unblocked
        """
        try:
            mac = self._validate_mac(mac)
        except ValueError as e:
            return {'success': False, 'error': str(e)}

        if interfaces is None:
            interfaces = DEFAULT_INTERFACES

        request = {
            'action': 'unblock_mac',
            'mac': mac,
            'interfaces': interfaces,
            'signature': self._sign_request('unblock_mac', mac)
        }

        return self._send_request(request)

    def revoke_lease(self, mac: str) -> Dict[str, Any]:
        """
        Revoke DHCP lease and clear ARP entry for a device.

        Args:
            mac: MAC address of device

        Returns:
            Dict with success status and details (lease_removed, arp_cleared, ip_address)
        """
        try:
            mac = self._validate_mac(mac)
        except ValueError as e:
            return {'success': False, 'error': str(e)}

        request = {
            'action': 'revoke_lease',
            'mac': mac,
            'signature': self._sign_request('revoke_lease', mac)
        }

        return self._send_request(request)

    def apply_policy(
        self,
        mac: str,
        policy: str,
        priority_mode: str = 'default'
    ) -> Dict[str, Any]:
        """
        Apply OpenFlow network policy rules for a device.

        This calls the host-side nac-policy-sync.sh script to apply OpenFlow
        rules on the OVS bridge for network access control.

        Args:
            mac: MAC address of device
            policy: Policy to apply. Valid values:
                - 'quarantine': Block all traffic except DHCP/DNS (highest priority)
                - 'lan_only': Device-to-device only, no internet
                - 'internet_only': Internet only, no LAN access
                - 'smart_home': Full LAN + internet access with discovery
                - 'full_access': Unrestricted access (removes all per-device rules)
            priority_mode: 'default' for bubble rules, 'override' for device-specific

        Returns:
            Dict with success status, policy applied, and any output/errors
        """
        try:
            mac = self._validate_mac(mac)
        except ValueError as e:
            return {'success': False, 'error': str(e)}

        valid_policies = ['quarantine', 'isolated', 'lan_only', 'internet_only', 'smart_home', 'full_access']
        if policy not in valid_policies:
            return {
                'success': False,
                'error': f'Invalid policy: {policy}. Valid: {", ".join(valid_policies)}'
            }

        request = {
            'action': 'apply_policy',
            'mac': mac,
            'policy': policy,
            'priority_mode': priority_mode,
            'signature': self._sign_request('apply_policy', mac)
        }

        return self._send_request(request)

    def l1_status(self) -> Dict[str, Any]:
        """
        Get L1/Cellular status including signal metrics and trust score.

        Returns:
            Dict with cellular connection info:
            - network_type: 5G SA, 5G, LTE, 4G, 3G, etc.
            - carrier: Carrier/operator name
            - cell_id, pci, tac, band: Cell identification
            - rsrp, sinr, snr: Signal metrics
            - trust_score: L1 trust score (0-100)
            - trust_components: Breakdown of trust score
            - survival_mode: Whether survival mode is active
            - vpn_ready: Whether VPN is pre-established
        """
        request = {
            'action': 'l1_status',
            'signature': self._sign_request('l1_status')
        }
        return self._send_request(request)

    def l1_survival_enter(self, trigger: str = 'manual') -> Dict[str, Any]:
        """
        Enter L1 survival mode - lock down cellular protocols.

        This activates survival mode protections:
        - Disables 2G/3G fallback (forces LTE/5G)
        - Prepares VPN tunnel activation

        Args:
            trigger: Reason for entering ('manual', 'imsi_catcher', 'jamming', 'low_trust')

        Returns:
            Dict with success status and actions taken
        """
        request = {
            'action': 'l1_survival_enter',
            'trigger': trigger,
            'signature': self._sign_request('l1_survival_enter')
        }
        return self._send_request(request)

    def l1_survival_exit(self) -> Dict[str, Any]:
        """
        Exit L1 survival mode - restore normal operation.

        Returns:
            Dict with success status and actions taken
        """
        request = {
            'action': 'l1_survival_exit',
            'signature': self._sign_request('l1_survival_exit')
        }
        return self._send_request(request)

    def timed_block(
        self,
        mac: str,
        block_duration_seconds: int = 60,
        interfaces: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Block, deauth, revoke lease, then auto-unblock after duration.

        This is the enterprise-style disconnect that prevents immediate reconnection
        but allows the device to reconnect after the block period expires.

        Args:
            mac: MAC address of device
            block_duration_seconds: How long to block (default: 60s, min: 10s, max: 3600s)
            interfaces: List of interfaces to block on (default: all)

        Returns:
            Dict with success status and details including:
            - blocked: Whether MAC was blocked
            - deauth_sent: Whether deauth was sent
            - lease_revoked: Whether DHCP lease was revoked
            - unblock_scheduled: Whether auto-unblock timer was started
            - block_duration_seconds: Actual block duration used
        """
        try:
            mac = self._validate_mac(mac)
        except ValueError as e:
            return {'success': False, 'error': str(e)}

        if interfaces is None:
            interfaces = DEFAULT_INTERFACES

        request = {
            'action': 'timed_block',
            'mac': mac,
            'interfaces': interfaces,
            'block_duration_seconds': block_duration_seconds,
            'signature': self._sign_request('timed_block', mac)
        }

        return self._send_request(request)


# Module-level singleton
_client: Optional[HostAgentClient] = None


def get_host_agent_client() -> HostAgentClient:
    """Get or create the host agent client singleton."""
    global _client
    if _client is None:
        _client = HostAgentClient()
    return _client


def deauthenticate_device(mac: str, interfaces: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Convenience function to deauthenticate a device.

    Args:
        mac: MAC address of device to disconnect
        interfaces: Optional list of interfaces to try

    Returns:
        Dict with success status and details
    """
    client = get_host_agent_client()
    return client.deauthenticate(mac, interfaces)


def block_device(mac: str, interfaces: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Block a device from WiFi (adds MAC to deny ACL).

    Args:
        mac: MAC address of device to block
        interfaces: Optional list of interfaces to block on

    Returns:
        Dict with success status and details
    """
    client = get_host_agent_client()
    return client.block_mac(mac, interfaces)


def unblock_device(mac: str, interfaces: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Unblock a device from WiFi (removes MAC from deny ACL).

    Args:
        mac: MAC address of device to unblock
        interfaces: Optional list of interfaces to unblock on

    Returns:
        Dict with success status and details
    """
    client = get_host_agent_client()
    return client.unblock_mac(mac, interfaces)


def disconnect_device(mac: str, interfaces: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Properly disconnect a device: block MAC first, then deauth.

    This prevents the device from immediately reconnecting.

    Args:
        mac: MAC address of device to disconnect
        interfaces: Optional list of interfaces

    Returns:
        Dict with success status and details
    """
    client = get_host_agent_client()

    # Step 1: Block the MAC to prevent reconnection
    block_result = client.block_mac(mac, interfaces)

    # Step 2: Deauthenticate to kick the device
    deauth_result = client.deauthenticate(mac, interfaces)

    return {
        'success': block_result.get('success', False) or deauth_result.get('success', False),
        'blocked': block_result.get('success', False),
        'deauth_sent': deauth_result.get('deauth_sent', False),
        'interfaces_blocked': block_result.get('interfaces_blocked', []),
        'interfaces_tried': deauth_result.get('interfaces_tried', []),
    }


def is_host_agent_available() -> bool:
    """Check if the host agent is available."""
    client = get_host_agent_client()
    return client.is_available()


def revoke_lease(mac: str) -> Dict[str, Any]:
    """
    Revoke DHCP lease and clear ARP entry for a device.

    Args:
        mac: MAC address of device

    Returns:
        Dict with success status and details
    """
    client = get_host_agent_client()
    return client.revoke_lease(mac)


def timed_block_device(
    mac: str,
    block_duration_seconds: int = 60,
    interfaces: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Block, deauth, revoke lease, then auto-unblock after duration.

    This is the enterprise-style disconnect (Cisco/Aruba pattern):
    - Blocks the MAC to prevent immediate reconnection
    - Sends deauth frame to kick from WiFi
    - Revokes DHCP lease and clears ARP
    - Automatically unblocks after the specified duration

    The device cannot reconnect during the block period (typically 60s),
    which stops the auto-reconnect loop. After the timer expires, the
    device can manually reconnect.

    Args:
        mac: MAC address of device
        block_duration_seconds: How long to block (default: 60s)
        interfaces: Optional list of interfaces

    Returns:
        Dict with success status and details
    """
    client = get_host_agent_client()
    return client.timed_block(mac, block_duration_seconds, interfaces)


def apply_policy(
    mac: str,
    policy: str,
    priority_mode: str = 'default'
) -> Dict[str, Any]:
    """
    Apply OpenFlow network policy rules for a device.

    This is the main function for network access control. It calls the host-side
    nac-policy-sync.sh script to apply OpenFlow rules on the OVS bridge.

    Args:
        mac: MAC address of device
        policy: Policy to apply:
            - 'quarantine': Block all traffic except DHCP/DNS (highest priority)
            - 'lan_only': Device-to-device only, no internet
            - 'internet_only': Internet only, no LAN access
            - 'smart_home': Full LAN + internet access with discovery
            - 'full_access': Unrestricted access (removes all per-device rules)
        priority_mode: 'default' for bubble rules, 'override' for device-specific

    Returns:
        Dict with success status, policy applied, and any output/errors
    """
    client = get_host_agent_client()
    return client.apply_policy(mac, policy, priority_mode)


def get_l1_status() -> Dict[str, Any]:
    """
    Get L1/Cellular status from the host modem.

    Returns:
        Dict with cellular connection info including network type, carrier,
        signal metrics, cell info, trust score, and survival mode status.
    """
    client = get_host_agent_client()
    return client.l1_status()


def enter_l1_survival_mode(trigger: str = 'manual') -> Dict[str, Any]:
    """
    Enter L1 survival mode - lock down cellular protocols.

    Args:
        trigger: Reason for entering ('manual', 'imsi_catcher', 'jamming', 'low_trust')

    Returns:
        Dict with success status and actions taken
    """
    client = get_host_agent_client()
    return client.l1_survival_enter(trigger)


def exit_l1_survival_mode() -> Dict[str, Any]:
    """
    Exit L1 survival mode - restore normal operation.

    Returns:
        Dict with success status and actions taken
    """
    client = get_host_agent_client()
    return client.l1_survival_exit()
