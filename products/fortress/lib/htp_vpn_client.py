"""
Fortress HTP VPN Client - Secure tunnel through MSSP gateway.

Routes Fortress traffic through the HookProbe mesh via an encrypted
HTP tunnel to the MSSP gateway (mesh.hookprobe.com:8144 UDP).

Key differences from Guardian VPN client:
- PBR routing (table 300, fwmark 0x300) instead of replacing default route
- Three kill switch modes: OFF, HOST, FULL
- OVS bridge + container network awareness
- WAN failover integration (coexists with tables 100/200)
- State file at /run/fortress/vpn-state.json for web UI

Protocol: HTP (HELLO → CHALLENGE → ATTEST → ACCEPT)
Encryption: ChaCha20-Poly1305 AEAD with HKDF-SHA256 key derivation
Auth: PSK + Ed25519 TOFU (Trust-On-First-Use)
"""

import hashlib
import hmac
import json
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger('fortress.vpn')

# =========================================================================
# CONSTANTS
# =========================================================================

# HTP protocol version
HTP_VERSION = 0x0001

# Handshake frame: [version:2][type:1][payload...]
# Data frame:      [flow_token:8][seq:4][type:1][payload...]
HANDSHAKE_HEADER_SIZE = 3   # version(2) + type(1)
DATA_HEADER_SIZE = 13       # flow_token(8) + seq(4) + type(1)

# Packet types — handshake (version+type header)
PKT_HELLO = 0x01
PKT_CHALLENGE = 0x02
PKT_ATTEST = 0x03
PKT_ACCEPT = 0x04
PKT_REJECT = 0x05

# Packet types — data (flow_token+seq+type header)
PKT_CLOSE = 0x09
PKT_IP_PACKET = 0x10
PKT_KEEPALIVE = 0x14
PKT_REKEY = 0x18
PKT_REKEY_ACK = 0x19

# HKDF context strings (must match gateway exactly)
HKDF_SALT_SESSION = b"htp-vpn-session-salt-v2"
HKDF_INFO_SESSION = b"htp-vpn-session-key-v2"
HKDF_SALT_REKEY = b"htp-vpn-rekey-salt-v2"
HKDF_INFO_REKEY = b"htp-vpn-rekey-v2"

# Timeouts
HANDSHAKE_TIMEOUT = 15
KEEPALIVE_INTERVAL = 25
RECONNECT_BASE_DELAY = 5
RECONNECT_MAX_DELAY = 120
RECONNECT_MAX_RETRIES = 10
OLD_KEY_TTL = 10  # seconds to keep old key after rekey

# Networking
TUN_MTU = 1400
VPN_ROUTING_TABLE = 300
VPN_FWMARK = 0x300
VPN_FWMASK = 0xf00
VPN_RULE_PRIORITY = 45  # Must be < 50 (wan_primary source rule) and < 60 (wan_backup)

# Paths
CONFIG_FILE = Path('/etc/hookprobe/fortress_vpn.json')
NODE_CONF = Path('/etc/hookprobe/node.conf')
FORTRESS_CONF = Path('/etc/hookprobe/fortress.conf')
STATE_FILE = Path('/run/fortress/vpn-state.json')
WAN_STATE_FILE = Path('/run/fortress/wan-failover.state')
KNOWN_HOSTS_FILE = Path('/etc/hookprobe/vpn_known_hosts.json')


class VPNState(Enum):
    STOPPED = 'stopped'
    CONNECTING = 'connecting'
    CONNECTED = 'connected'
    RECONNECTING = 'reconnecting'
    ERROR = 'error'


class KillSwitchMode(Enum):
    OFF = 'off'      # No kill switch — VPN is best-effort
    HOST = 'host'    # Only Fortress host traffic through VPN; LAN uses local breakout
    FULL = 'full'    # ALL traffic (host + LAN + containers) through tunnel


@dataclass
class VPNConfig:
    """Fortress VPN configuration."""
    gateway_host: str = 'mesh.hookprobe.com'
    gateway_port: int = 8144
    device_token: str = ''          # PSK for authentication
    tun_device: str = 'htp0'
    tun_local_ip: str = ''          # Assigned by gateway
    tun_remote_ip: str = ''         # Gateway tunnel IP
    kill_switch: str = 'host'       # off / host / full
    wan_interface: str = ''         # Auto-detected from WAN state
    enabled: bool = False           # Must be explicitly enabled

    @classmethod
    def load(cls) -> 'VPNConfig':
        """Load config from /etc/hookprobe/fortress_vpn.json + node.conf."""
        config = cls()

        # Load JSON config
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                config.gateway_host = data.get('gateway_host', config.gateway_host)
                config.gateway_port = data.get('gateway_port', config.gateway_port)
                config.device_token = data.get('device_token', config.device_token)
                config.tun_device = data.get('tun_device', config.tun_device)
                config.kill_switch = data.get('kill_switch', config.kill_switch)
                config.enabled = data.get('enabled', config.enabled)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Config parse error: %s", e)

        # Fallback: PSK from node.conf (MSSP registration)
        if not config.device_token and NODE_CONF.exists():
            try:
                for line in NODE_CONF.read_text().splitlines():
                    if line.strip().startswith('API_KEY='):
                        val = line.split('=', 1)[1].strip().strip('"').strip("'")
                        if val:
                            config.device_token = val
                            break
            except (OSError, ValueError):
                pass

        # Auto-detect WAN interface from failover state
        if not config.wan_interface:
            config.wan_interface = _detect_active_wan()

        return config

    @property
    def kill_switch_mode(self) -> KillSwitchMode:
        try:
            return KillSwitchMode(self.kill_switch)
        except ValueError:
            return KillSwitchMode.HOST


def _detect_active_wan() -> str:
    """Detect active WAN interface from failover state or fortress.conf."""
    # Try WAN failover state first
    if WAN_STATE_FILE.exists():
        try:
            for line in WAN_STATE_FILE.read_text().splitlines():
                if line.startswith('ACTIVE_WAN='):
                    active = line.split('=', 1)[1].strip().strip('"')
                    if active == 'backup':
                        # Read backup interface name
                        for l2 in WAN_STATE_FILE.read_text().splitlines():
                            if l2.startswith('BACKUP_IFACE='):
                                return l2.split('=', 1)[1].strip().strip('"')
                    else:
                        for l2 in WAN_STATE_FILE.read_text().splitlines():
                            if l2.startswith('PRIMARY_IFACE='):
                                return l2.split('=', 1)[1].strip().strip('"')
        except OSError:
            pass

    # Fallback: fortress.conf
    if FORTRESS_CONF.exists():
        try:
            for line in FORTRESS_CONF.read_text().splitlines():
                if line.startswith('WAN_IFACE='):
                    return line.split('=', 1)[1].strip().strip('"')
        except OSError:
            pass

    # Last resort: default route interface
    try:
        out = subprocess.check_output(
            ['ip', '-4', 'route', 'show', 'default'],
            text=True, timeout=5
        )
        for part in out.split():
            if part == 'dev':
                idx = out.split().index('dev')
                return out.split()[idx + 1]
    except Exception:
        pass

    return 'eth0'


def _run(cmd: list, check=True, timeout=10, **kwargs) -> subprocess.CompletedProcess:
    """Run a shell command, logging on failure."""
    try:
        return subprocess.run(cmd, check=check, timeout=timeout,
                              capture_output=True, text=True, **kwargs)
    except subprocess.CalledProcessError as e:
        logger.debug("Command failed: %s → %s", ' '.join(cmd), e.stderr.strip())
        if check:
            raise
        return e
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", ' '.join(cmd))
        raise


# =========================================================================
# CRYPTO (ChaCha20-Poly1305 AEAD)
# =========================================================================

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography package not installed — VPN unavailable")


def _hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive key material using HKDF-SHA256 with explicit salt."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


# =========================================================================
# VPN CLIENT
# =========================================================================

class FortressVPNClient:
    """HTP VPN client for Fortress with PBR routing and kill switch."""

    def __init__(self, config: VPNConfig):
        self.config = config
        self.state = VPNState.STOPPED
        self._running = False
        self._lock = threading.Lock()

        # Connection state
        self.udp_socket: Optional[socket.socket] = None
        self.tun_fd: Optional[int] = None
        self.gateway_addr: Optional[tuple] = None
        self.flow_token: int = 0
        self.session_key: Optional[bytes] = None
        self.old_session_key: Optional[bytes] = None
        self.old_key_expires: float = 0
        self.sequence: int = 0

        # Ed25519 TOFU
        self._ed25519_key: Optional[object] = None
        self._gateway_pubkey: Optional[bytes] = None

        # Stats
        self.bytes_sent: int = 0
        self.bytes_received: int = 0
        self.packets_sent: int = 0
        self.packets_received: int = 0
        self.connected_since: Optional[float] = None
        self.reconnect_count: int = 0
        self.last_keepalive: float = 0

        # Saved routing state for teardown
        self._original_wan_gateway: str = ''
        self._original_wan_iface: str = ''

        # Threads
        self._tun_thread: Optional[threading.Thread] = None
        self._udp_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None

    # -----------------------------------------------------------------
    # STATE MANAGEMENT
    # -----------------------------------------------------------------

    def _set_state(self, new_state: VPNState):
        old = self.state
        self.state = new_state
        if old != new_state:
            logger.info("VPN state: %s → %s", old.value, new_state.value)
        self._write_state_file()

    def _write_state_file(self):
        """Write status to /run/fortress/vpn-state.json for web UI."""
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            status = self.get_status()
            tmp = str(STATE_FILE) + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(status, f)
            os.replace(tmp, str(STATE_FILE))
        except Exception:
            pass

    # -----------------------------------------------------------------
    # TUN DEVICE
    # -----------------------------------------------------------------

    def _create_tun(self) -> bool:
        """Create TUN device for VPN tunnel."""
        try:
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000

            tun_fd = os.open('/dev/net/tun', os.O_RDWR)
            ifr = struct.pack('16sH', self.config.tun_device.encode(), IFF_TUN | IFF_NO_PI)
            import fcntl
            fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

            self.tun_fd = tun_fd

            # Configure interface
            _run(['ip', 'link', 'set', self.config.tun_device, 'mtu', str(TUN_MTU)])
            _run(['ip', 'link', 'set', self.config.tun_device, 'up'])
            logger.info("TUN device %s created (fd=%d)", self.config.tun_device, tun_fd)
            return True

        except Exception as e:
            logger.error("Failed to create TUN: %s", e)
            return False

    def _configure_tun_ip(self):
        """Set IP on TUN after handshake assigns it."""
        if self.config.tun_local_ip and self.config.tun_remote_ip:
            _run([
                'ip', 'addr', 'replace',
                f'{self.config.tun_local_ip}/24',
                'dev', self.config.tun_device
            ])
            logger.info("TUN IP: %s → %s", self.config.tun_local_ip, self.config.tun_remote_ip)

    def _destroy_tun(self):
        """Remove TUN device."""
        if self.tun_fd is not None:
            try:
                os.close(self.tun_fd)
            except OSError:
                pass
            self.tun_fd = None

        try:
            _run(['ip', 'link', 'del', self.config.tun_device], check=False)
        except Exception:
            pass

    # -----------------------------------------------------------------
    # ROUTING (PBR Table 300)
    # -----------------------------------------------------------------

    def _setup_routing(self) -> bool:
        """Set up PBR routing through VPN tunnel."""
        try:
            # Save current WAN info for gateway host route
            self._original_wan_iface = self.config.wan_interface or _detect_active_wan()
            try:
                out = subprocess.check_output(
                    ['ip', '-4', 'route', 'show', 'default'],
                    text=True, timeout=5
                )
                parts = out.strip().split()
                if 'via' in parts:
                    self._original_wan_gateway = parts[parts.index('via') + 1]
            except Exception:
                pass

            # Ensure routing table 300 is registered
            rt_tables = Path('/etc/iproute2/rt_tables')
            if rt_tables.exists():
                content = rt_tables.read_text()
                if '300' not in content:
                    with open(str(rt_tables), 'a') as f:
                        f.write('\n300\twan_vpn\n')

            # Host route to gateway via WAN (so VPN packets don't loop)
            gw_ip = self.gateway_addr[0] if self.gateway_addr else ''
            if gw_ip and self._original_wan_gateway:
                _run([
                    'ip', 'route', 'replace', f'{gw_ip}/32',
                    'via', self._original_wan_gateway,
                    'dev', self._original_wan_iface
                ])

            # Default route through VPN tunnel in table 300
            # src is critical: PBR rerouting (type route chain) may not update
            # the source IP from the initial routing decision. Without explicit src,
            # packets could go through TUN with the WAN IP (e.g., 10.179.5.2),
            # and the gateway wouldn't be able to route responses back.
            _run([
                'ip', 'route', 'replace', 'default',
                'via', self.config.tun_remote_ip,
                'dev', self.config.tun_device,
                'src', self.config.tun_local_ip,
                'table', str(VPN_ROUTING_TABLE)
            ])

            # IP rule: marked traffic → table 300
            # Remove stale rule first
            _run([
                'ip', 'rule', 'del', 'fwmark',
                f'{VPN_FWMARK}/{VPN_FWMASK}',
                'table', str(VPN_ROUTING_TABLE)
            ], check=False)
            _run([
                'ip', 'rule', 'add', 'fwmark',
                f'{VPN_FWMARK}/{VPN_FWMASK}',
                'table', str(VPN_ROUTING_TABLE),
                'priority', str(VPN_RULE_PRIORITY)
            ])

            # Mark traffic based on kill switch mode
            self._apply_traffic_marks()

            logger.info("PBR routing configured: table %d, fwmark 0x%x",
                        VPN_ROUTING_TABLE, VPN_FWMARK)
            return True

        except Exception as e:
            logger.error("Routing setup failed: %s", e)
            return False

    def _apply_traffic_marks(self):
        """Apply nftables marks based on kill switch mode."""
        mode = self.config.kill_switch_mode

        # Clean up old VPN marking rules
        _run(['nft', 'delete', 'table', 'inet', 'fortress_vpn'], check=False)

        if mode == KillSwitchMode.OFF:
            # Best-effort: mark only host-originated traffic to internet
            self._nft_create_vpn_table(mark_host=True, mark_lan=False,
                                       kill_switch=False)
        elif mode == KillSwitchMode.HOST:
            # Mark host traffic, enable kill switch for host only
            # LAN clients keep using local breakout (tables 100/200)
            self._nft_create_vpn_table(mark_host=True, mark_lan=False,
                                       kill_switch=True)
        elif mode == KillSwitchMode.FULL:
            # Mark ALL outbound traffic (host + LAN + containers)
            self._nft_create_vpn_table(mark_host=True, mark_lan=True,
                                       kill_switch=True)

    def _nft_create_vpn_table(self, mark_host: bool, mark_lan: bool,
                               kill_switch: bool):
        """Create nftables table for VPN traffic marking and kill switch."""
        wan = self.config.wan_interface or _detect_active_wan()
        gw_ip = self.gateway_addr[0] if self.gateway_addr else ''
        tun = self.config.tun_device
        lan_net = self._get_lan_network()

        rules = ['table inet fortress_vpn {']

        # OUTPUT chain: mark host-originated traffic
        if mark_host:
            rules.append('    chain output {')
            rules.append('        type route hook output priority mangle; policy accept;')
            # Don't mark traffic to LAN, loopback, or container networks
            rules.append('        oifname "lo" accept')
            rules.append(f'        oifname "{tun}" accept')
            rules.append('        ip daddr 10.200.0.0/16 accept')
            rules.append('        ip daddr 172.20.200.0/22 accept')
            rules.append('        ip daddr 127.0.0.0/8 accept')
            # Don't mark VPN gateway traffic (would loop)
            if gw_ip:
                rules.append(f'        ip daddr {gw_ip} accept')
            # Mark everything else for VPN
            rules.append(f'        meta mark set {VPN_FWMARK:#x}')
            rules.append('    }')

        # FORWARD chain: mark LAN→internet traffic (FULL mode only)
        if mark_lan:
            rules.append('    chain forward {')
            rules.append('        type filter hook forward priority mangle; policy accept;')
            # Only mark traffic heading to WAN (not LAN↔LAN or LAN↔container)
            rules.append(f'        oifname != "{wan}" accept')
            rules.append(f'        oifname "{tun}" accept')
            # Don't mark VPN gateway traffic
            if gw_ip:
                rules.append(f'        ip daddr {gw_ip} accept')
            rules.append(f'        meta mark set {VPN_FWMARK:#x}')
            rules.append('    }')

        # Kill switch: drop non-tunnel traffic to WAN
        # Uses destination-prefix filtering (not oifname) to survive WAN failover
        if kill_switch:
            if mark_host and not mark_lan:
                # HOST mode: only protect host output
                rules.append('    chain ks_output {')
                rules.append('        type filter hook output priority filter + 10; policy accept;')
                # Allow traffic to local/tunnel/RFC1918 destinations
                rules.append('        oifname "lo" accept')
                rules.append(f'        oifname "{tun}" accept')
                rules.append('        ip daddr 10.0.0.0/8 accept')
                rules.append('        ip daddr 172.16.0.0/12 accept')
                rules.append('        ip daddr 192.168.0.0/16 accept')
                rules.append('        ip daddr 127.0.0.0/8 accept')
                # Allow VPN gateway (so encrypted UDP gets through)
                if gw_ip:
                    rules.append(f'        ip daddr {gw_ip} accept')
                # Allow DHCP to broadcast only (WAN renewal)
                rules.append('        ip daddr 255.255.255.255 udp dport 67 accept')
                rules.append('        udp sport 68 udp dport 67 accept')
                # Drop IPv6 to WAN (no IPv6 tunnel support yet)
                rules.append('        ip6 daddr fe80::/10 accept')
                rules.append('        ip6 daddr fc00::/7 accept')
                rules.append('        ip6 daddr ::1/128 accept')
                rules.append('        meta nfproto ipv6 drop')
                # Drop everything else from host to internet
                rules.append('        drop')
                rules.append('    }')
            elif mark_lan:
                # FULL mode: protect both host and forwarded traffic
                rules.append('    chain ks_output {')
                rules.append('        type filter hook output priority filter + 10; policy accept;')
                rules.append('        oifname "lo" accept')
                rules.append(f'        oifname "{tun}" accept')
                rules.append('        ip daddr 10.0.0.0/8 accept')
                rules.append('        ip daddr 172.16.0.0/12 accept')
                rules.append('        ip daddr 192.168.0.0/16 accept')
                if gw_ip:
                    rules.append(f'        ip daddr {gw_ip} accept')
                rules.append('        ip daddr 255.255.255.255 udp dport 67 accept')
                rules.append('        ip6 daddr fe80::/10 accept')
                rules.append('        ip6 daddr fc00::/7 accept')
                rules.append('        meta nfproto ipv6 drop')
                rules.append('        drop')
                rules.append('    }')
                rules.append('    chain ks_forward {')
                rules.append('        type filter hook forward priority filter + 10; policy accept;')
                rules.append(f'        oifname "{tun}" accept')
                if gw_ip:
                    rules.append(f'        ip daddr {gw_ip} accept')
                # Allow LAN↔LAN and LAN↔container
                rules.append('        ip daddr 10.0.0.0/8 accept')
                rules.append('        ip daddr 172.16.0.0/12 accept')
                rules.append('        ip daddr 192.168.0.0/16 accept')
                rules.append('        meta nfproto ipv6 drop')
                rules.append('        drop')
                rules.append('    }')

        # SNAT: guarantee correct source IP on TUN-bound packets.
        # PBR rerouting (type route chain) may preserve the original WAN source
        # IP from the initial routing decision. The gateway identifies clients by
        # their assigned VPN IP, so packets MUST have src=tun_local_ip.
        rules.append('    chain vpn_snat {')
        rules.append('        type nat hook postrouting priority srcnat; policy accept;')
        rules.append(f'        oifname "{tun}" masquerade')
        rules.append('    }')

        rules.append('}')

        nft_script = '\n'.join(rules)
        try:
            proc = subprocess.run(
                ['nft', '-f', '-'],
                input=nft_script, text=True,
                capture_output=True, timeout=10
            )
            if proc.returncode != 0:
                logger.error("nft load failed: %s", proc.stderr.strip())
            else:
                logger.info("nftables VPN rules applied (mode=%s, kill_switch=%s)",
                            self.config.kill_switch, kill_switch)
        except Exception as e:
            logger.error("nftables setup error: %s", e)

    def _get_lan_network(self) -> str:
        """Get LAN network from fortress.conf."""
        if FORTRESS_CONF.exists():
            try:
                for line in FORTRESS_CONF.read_text().splitlines():
                    if line.startswith('LAN_NETWORK='):
                        return line.split('=', 1)[1].strip().strip('"')
            except OSError:
                pass
        return '10.200.0.0/23'

    def _teardown_routing(self):
        """Remove VPN routing and restore normal traffic flow."""
        # Remove nftables VPN table
        _run(['nft', 'delete', 'table', 'inet', 'fortress_vpn'], check=False)

        # Remove IP rule
        _run([
            'ip', 'rule', 'del', 'fwmark',
            f'{VPN_FWMARK}/{VPN_FWMASK}',
            'table', str(VPN_ROUTING_TABLE)
        ], check=False)

        # Flush VPN routing table
        _run(['ip', 'route', 'flush', 'table', str(VPN_ROUTING_TABLE)], check=False)

        # Remove gateway host route
        gw_ip = self.gateway_addr[0] if self.gateway_addr else ''
        if gw_ip:
            _run(['ip', 'route', 'del', f'{gw_ip}/32'], check=False)

        logger.info("VPN routing cleaned up")

    # -----------------------------------------------------------------
    # UDP SOCKET
    # -----------------------------------------------------------------

    def _create_udp_socket(self) -> bool:
        """Create UDP socket bound to WAN interface."""
        try:
            # Resolve gateway
            gw_host = self.config.gateway_host
            try:
                gw_ip = socket.gethostbyname(gw_host)
            except socket.gaierror as e:
                logger.error("Cannot resolve %s: %s", gw_host, e)
                return False

            self.gateway_addr = (gw_ip, self.config.gateway_port)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(HANDSHAKE_TIMEOUT)

            # Bind to WAN interface so VPN packets don't loop through TUN
            wan = self.config.wan_interface or _detect_active_wan()
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                wan.encode() + b'\0')
            except PermissionError:
                logger.warning("SO_BINDTODEVICE requires root — continuing unbound")

            self.udp_socket = sock
            logger.info("UDP socket ready: %s → %s:%d (via %s)",
                        sock.getsockname(), gw_ip, self.config.gateway_port, wan)
            return True

        except Exception as e:
            logger.error("UDP socket creation failed: %s", e)
            return False

    # -----------------------------------------------------------------
    # HTP HANDSHAKE
    # -----------------------------------------------------------------

    def _perform_handshake(self) -> bool:
        """HTP handshake: HELLO → CHALLENGE → ATTEST → ACCEPT.

        Packet formats (must match Guardian client and MSSP gateway):
          HELLO:     version(2) + type(1) + node_id(32) + nonce(32) + flow_token(8) = 75 bytes
          CHALLENGE: version(2) + type(1) + challenge(32) [+ pubkey(32) + sig(64)] = 35 or 131 bytes
          ATTEST:    version(2) + type(1) + hmac(32) + flow_token(8) = 43 bytes
          ACCEPT:    version(2) + type(1) + assigned_ip(4) = 7 bytes
        """
        if not HAS_CRYPTO:
            logger.error("cryptography package required for VPN")
            return False

        try:
            import secrets as _secrets

            # Generate session parameters
            self.flow_token = _secrets.randbelow(2**64)
            client_nonce = os.urandom(32)
            node_id = f"fortress-{_secrets.token_hex(8)}"

            # Step 1: HELLO
            # Format: version(2) + type(1) + node_id(32) + nonce(32) + flow_token(8)
            hello = struct.pack(
                '>HB32s32sQ',
                HTP_VERSION,
                PKT_HELLO,
                node_id.encode()[:32].ljust(32, b'\x00'),
                client_nonce,
                self.flow_token,
            )
            self.udp_socket.sendto(hello, self.gateway_addr)
            logger.debug("→ HELLO (%d bytes) flow=%016x", len(hello), self.flow_token)

            # Step 2: Receive CHALLENGE
            data, addr = self.udp_socket.recvfrom(4096)
            if len(data) < HANDSHAKE_HEADER_SIZE:
                logger.error("CHALLENGE too short (%d bytes)", len(data))
                return False

            version, ptype = struct.unpack('>HB', data[:3])
            if ptype != PKT_CHALLENGE:
                logger.error("Expected CHALLENGE (0x02), got 0x%02x", ptype)
                return False

            # Extract challenge (32 bytes after header)
            if len(data) < 35:
                logger.error("CHALLENGE payload too short (%d)", len(data))
                return False
            gateway_challenge = data[3:35]

            # Verify Ed25519 server identity if present (TOFU)
            # Format: challenge(32) + pubkey(32) + signature(64) = 128 bytes after header
            if len(data) >= 131:
                server_pubkey_bytes = data[35:67]
                server_sig = data[67:131]
                try:
                    server_pub = Ed25519PublicKey.from_public_bytes(server_pubkey_bytes)
                    server_pub.verify(server_sig, gateway_challenge + client_nonce)
                    logger.info("Server identity verified (Ed25519)")
                except Exception as e:
                    logger.error("Server Ed25519 signature FAILED: %s — aborting", e)
                    return False
                # Only TOFU-pin after successful signature verification
                self._tofu_verify(server_pubkey_bytes)
            elif len(data) >= 67:
                logger.warning("Server sent pubkey without signature — ignoring")
            else:
                # Reject unsigned CHALLENGE if we have a pinned TOFU key
                host_key = f"{self.config.gateway_host}:{self.config.gateway_port}"
                known = self._load_known_hosts()
                if known.get(host_key):
                    logger.error("Known gateway %s has TOFU key but sent unsigned "
                                 "CHALLENGE — possible downgrade attack, aborting", host_key)
                    return False
                logger.debug("Server sent unsigned CHALLENGE (no pinned key — accepting)")

            # Step 3: Derive session key using HKDF-SHA256
            # IKM = nonce + challenge + PSK (same as Guardian)
            ikm = client_nonce + gateway_challenge
            if self.config.device_token:
                ikm += self.config.device_token.encode()
            self.session_key = _hkdf_derive(ikm, HKDF_SALT_SESSION, HKDF_INFO_SESSION)

            # Build ATTEST: prove we derived the correct key
            attest_mac = hmac.new(
                self.session_key,
                client_nonce + gateway_challenge,
                hashlib.sha256
            ).digest()

            # Format: version(2) + type(1) + hmac(32) + flow_token(8) = 43 bytes
            attest = struct.pack(
                '>HB32sQ',
                HTP_VERSION,
                PKT_ATTEST,
                attest_mac,
                self.flow_token,
            )
            self.udp_socket.sendto(attest, self.gateway_addr)
            logger.debug("→ ATTEST (%d bytes)", len(attest))

            # Step 4: Receive ACCEPT or REJECT
            data, addr = self.udp_socket.recvfrom(4096)
            if len(data) < HANDSHAKE_HEADER_SIZE:
                logger.error("ACCEPT/REJECT too short (%d)", len(data))
                return False

            version, ptype = struct.unpack('>HB', data[:3])
            if ptype == PKT_REJECT:
                reason = data[3:].decode('utf-8', errors='replace')
                logger.error("Gateway REJECTED: %s", reason)
                return False

            if ptype != PKT_ACCEPT:
                logger.error("Expected ACCEPT (0x04), got 0x%02x", ptype)
                return False

            # Parse ACCEPT: version(2) + type(1) + assigned_ip(4)
            if len(data) >= 7:
                assigned_ip = socket.inet_ntoa(data[3:7])
                # Validate IP is within VPN subnet
                import ipaddress
                try:
                    if ipaddress.ip_address(assigned_ip) not in ipaddress.ip_network('10.250.0.0/24'):
                        logger.error("Gateway assigned IP %s outside VPN subnet — rejecting",
                                     assigned_ip)
                        return False
                except ValueError:
                    logger.error("Gateway sent invalid IP in ACCEPT")
                    return False
                self.config.tun_local_ip = assigned_ip
                self.config.tun_remote_ip = '10.250.0.1'
                logger.info("Handshake OK: flow=%016x assigned_ip=%s",
                            self.flow_token, assigned_ip)
            else:
                # Fallback IPs
                self.config.tun_local_ip = '10.250.0.2'
                self.config.tun_remote_ip = '10.250.0.1'
                logger.info("Handshake OK (no IP in ACCEPT): flow=%016x", self.flow_token)

            # Configure TUN with assigned IP
            self._configure_tun_ip()
            return True

        except socket.timeout:
            logger.error("Handshake timed out")
            return False
        except Exception as e:
            logger.error("Handshake error: %s", e)
            return False

    def _tofu_verify(self, gateway_pubkey: bytes):
        """Trust-On-First-Use for gateway Ed25519 public key."""
        known = {}
        if KNOWN_HOSTS_FILE.exists():
            try:
                known = json.loads(KNOWN_HOSTS_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        host_key = f"{self.config.gateway_host}:{self.config.gateway_port}"
        stored = known.get(host_key)

        if stored is None:
            # First connection — trust this key
            known[host_key] = gateway_pubkey.hex()
            try:
                KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
                KNOWN_HOSTS_FILE.write_text(json.dumps(known, indent=2))
                os.chmod(str(KNOWN_HOSTS_FILE), 0o600)
            except OSError:
                pass
            logger.info("TOFU: Trusted new gateway key for %s", host_key)
        elif stored != gateway_pubkey.hex():
            logger.critical(
                "TOFU: Gateway key CHANGED for %s — possible MITM! "
                "Expected: %s... Got: %s...",
                host_key, stored[:16], gateway_pubkey.hex()[:16]
            )
            raise ConnectionError("Gateway key mismatch — possible MITM attack")
        else:
            logger.debug("TOFU: Gateway key verified for %s", host_key)

        self._gateway_pubkey = gateway_pubkey

    # -----------------------------------------------------------------
    # ENCRYPTION / DECRYPTION
    # -----------------------------------------------------------------

    def _encrypt_packet(self, plaintext: bytes) -> bytes:
        """Encrypt IP packet with ChaCha20-Poly1305."""
        if not self.session_key:
            return b''
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(self.session_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def _decrypt_packet(self, data: bytes) -> Optional[bytes]:
        """Decrypt IP packet with ChaCha20-Poly1305."""
        if len(data) < 28:  # 12 nonce + 16 tag minimum
            return None

        nonce = data[:12]
        ciphertext = data[12:]

        # Try current key first
        if self.session_key:
            try:
                cipher = ChaCha20Poly1305(self.session_key)
                return cipher.decrypt(nonce, ciphertext, None)
            except Exception:
                pass

        # Try old key during grace period
        if self.old_session_key and time.time() < self.old_key_expires:
            try:
                cipher = ChaCha20Poly1305(self.old_session_key)
                return cipher.decrypt(nonce, ciphertext, None)
            except Exception:
                pass

        return None

    def _handle_rekey(self, payload: bytes):
        """Handle REKEY from gateway — decrypt nonce, derive new key, send ACK.

        Gateway sends: encrypted(rekey_nonce) using current session key.
        Client must:
          1. Decrypt to get rekey_nonce (32 bytes)
          2. Derive new key: HKDF(old_key + rekey_nonce, REKEY_SALT, REKEY_INFO)
          3. Send REKEY_ACK: encrypt rekey_nonce with NEW key as proof
        """
        try:
            # Decrypt the rekey nonce with current session key
            if len(payload) < 28:  # 12 nonce + 16 tag minimum
                return
            enc_nonce = payload[:12]
            ciphertext = payload[12:]
            cipher = ChaCha20Poly1305(self.session_key)
            rekey_nonce = cipher.decrypt(enc_nonce, ciphertext, None)

            if len(rekey_nonce) != 32:
                logger.warning("REKEY nonce wrong size: %d", len(rekey_nonce))
                return

            # Derive new session key
            new_key = _hkdf_derive(
                self.session_key + rekey_nonce,
                HKDF_SALT_REKEY,
                HKDF_INFO_REKEY,
            )

            # Send REKEY_ACK: encrypt rekey_nonce with NEW key as proof
            import secrets as _secrets
            ack_cipher = ChaCha20Poly1305(new_key)
            ack_nonce = _secrets.token_bytes(12)
            ack_payload = ack_nonce + ack_cipher.encrypt(ack_nonce, rekey_nonce, None)

            self.sequence = (self.sequence + 1) & 0xFFFFFFFF
            frame = struct.pack('>QIB', self.flow_token, self.sequence, PKT_REKEY_ACK)
            frame += ack_payload

            if self.udp_socket and self.gateway_addr:
                self.udp_socket.sendto(frame, self.gateway_addr)

            # Commit key rotation with grace period for old key
            self.old_session_key = self.session_key
            self.old_key_expires = time.time() + OLD_KEY_TTL
            self.session_key = new_key
            logger.info("REKEY complete (forward secrecy)")

        except Exception as e:
            logger.warning("REKEY handler error: %s", e)

    # -----------------------------------------------------------------
    # PACKET FORWARDING
    # -----------------------------------------------------------------

    def _tun_to_udp(self):
        """Read from TUN, encrypt, send to gateway."""
        import select as sel
        while self._running:
            try:
                if self.tun_fd is None:
                    break
                # Use select() with 1s timeout so thread can exit cleanly
                ready, _, _ = sel.select([self.tun_fd], [], [], 1.0)
                if not ready:
                    continue
                packet = os.read(self.tun_fd, 65535)
                if not packet:
                    continue

                encrypted = self._encrypt_packet(packet)
                if not encrypted:
                    continue

                self.sequence += 1
                frame = struct.pack(
                    '>QIB',
                    self.flow_token,
                    self.sequence & 0xFFFFFFFF,
                    PKT_IP_PACKET
                ) + encrypted

                if self.udp_socket and self.gateway_addr:
                    self.udp_socket.sendto(frame, self.gateway_addr)
                    self.bytes_sent += len(packet)
                    self.packets_sent += 1

            except OSError as e:
                if self._running:
                    logger.warning("TUN read error: %s", e)
                    break
            except Exception as e:
                if self._running:
                    logger.warning("TUN→UDP error: %s", e)

    def _udp_to_tun(self):
        """Read from UDP, decrypt, write to TUN."""
        if self.udp_socket:
            self.udp_socket.settimeout(2.0)

        while self._running:
            try:
                data, addr = self.udp_socket.recvfrom(65536)
                if len(data) < DATA_HEADER_SIZE:
                    continue

                ptype = data[12]
                payload = data[DATA_HEADER_SIZE:]

                if ptype == PKT_IP_PACKET:
                    ip_packet = self._decrypt_packet(payload)
                    if ip_packet and self.tun_fd is not None:
                        os.write(self.tun_fd, ip_packet)
                        self.bytes_received += len(ip_packet)
                        self.packets_received += 1

                elif ptype == PKT_REKEY:
                    self._handle_rekey(payload)

                elif ptype == PKT_KEEPALIVE:
                    self.last_keepalive = time.time()

                elif ptype == PKT_CLOSE:
                    logger.warning("Gateway sent CLOSE")
                    self._running = False

            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    logger.warning("UDP read error: %s", e)
                    break
            except Exception as e:
                if self._running:
                    logger.warning("UDP→TUN error: %s", e)

    def _keepalive_loop(self):
        """Send periodic keepalives and detect dead connection."""
        while self._running:
            try:
                time.sleep(KEEPALIVE_INTERVAL)
                if not self._running:
                    break

                # Send keepalive
                frame = struct.pack(
                    '>QIB Q',
                    self.flow_token,
                    0,
                    PKT_KEEPALIVE,
                    int(time.time() * 1000)
                )
                if self.udp_socket and self.gateway_addr:
                    self.udp_socket.sendto(frame, self.gateway_addr)

                # Dead peer detection
                if self.last_keepalive > 0:
                    silence = time.time() - self.last_keepalive
                    if silence > KEEPALIVE_INTERVAL * 3:
                        logger.warning("No keepalive for %.0fs — reconnecting", silence)
                        self._running = False

            except Exception as e:
                if self._running:
                    logger.warning("Keepalive error: %s", e)

    # -----------------------------------------------------------------
    # PUBLIC API
    # -----------------------------------------------------------------

    def start(self) -> bool:
        """Start VPN tunnel. Returns True if connected."""
        if self.state == VPNState.CONNECTED:
            logger.info("VPN already connected")
            return True

        self._set_state(VPNState.CONNECTING)
        logger.info("Starting HTP VPN to %s:%d (kill_switch=%s)",
                     self.config.gateway_host, self.config.gateway_port,
                     self.config.kill_switch)

        # Step 1: Create TUN
        if not self._create_tun():
            self._set_state(VPNState.ERROR)
            return False

        # Step 2: UDP socket
        if not self._create_udp_socket():
            self._destroy_tun()
            self._set_state(VPNState.ERROR)
            return False

        # Step 3: HTP handshake
        if not self._perform_handshake():
            self._cleanup()
            self._set_state(VPNState.ERROR)
            return False

        # Step 4: PBR routing
        if not self._setup_routing():
            self._cleanup()
            self._set_state(VPNState.ERROR)
            return False

        # Step 5: Start forwarding threads
        self._running = True
        self.connected_since = time.time()
        self.last_keepalive = time.time()

        self._tun_thread = threading.Thread(
            target=self._tun_to_udp, name='fts-vpn-tun', daemon=True
        )
        self._udp_thread = threading.Thread(
            target=self._udp_to_tun, name='fts-vpn-udp', daemon=True
        )
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop, name='fts-vpn-ka', daemon=True
        )

        self._tun_thread.start()
        self._udp_thread.start()
        self._keepalive_thread.start()

        self._set_state(VPNState.CONNECTED)
        logger.info("HTP VPN connected via %s (%s)",
                     self.config.tun_device, self.config.tun_local_ip)
        return True

    def stop(self):
        """Stop VPN and restore normal routing."""
        if self.state == VPNState.STOPPED:
            return

        logger.info("Stopping HTP VPN")
        self._running = False

        # CRITICAL: tear down nftables kill switch FIRST, before anything else.
        # If anything below fails or hangs, at least WAN traffic is restored.
        self._teardown_routing()

        # Send CLOSE to gateway
        try:
            if self.udp_socket and self.gateway_addr:
                close_frame = struct.pack('>QIB', self.flow_token, 0, PKT_CLOSE)
                self.udp_socket.sendto(close_frame, self.gateway_addr)
        except Exception:
            pass

        # Wait for threads
        for t in [self._tun_thread, self._udp_thread, self._keepalive_thread]:
            if t and t.is_alive():
                t.join(timeout=3)

        self._cleanup()

        self.connected_since = None
        self._set_state(VPNState.STOPPED)
        logger.info("HTP VPN stopped — normal routing restored")

    def _cleanup(self):
        """Clean up socket and TUN."""
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except Exception:
                pass
            self.udp_socket = None
        self._destroy_tun()

    def reconnect(self):
        """Reconnect with exponential backoff. Gives up after RECONNECT_MAX_RETRIES."""
        delay = RECONNECT_BASE_DELAY
        self._set_state(VPNState.RECONNECTING)
        attempts = 0

        while self.state == VPNState.RECONNECTING:
            attempts += 1
            self.reconnect_count += 1

            if attempts > RECONNECT_MAX_RETRIES:
                logger.error("Max reconnect attempts (%d) reached — giving up",
                             RECONNECT_MAX_RETRIES)
                self._set_state(VPNState.ERROR)
                return False

            logger.info("Reconnecting (attempt %d/%d, delay %ds)",
                        attempts, RECONNECT_MAX_RETRIES, delay)

            self._cleanup()
            self._teardown_routing()

            time.sleep(delay)

            if self.start():
                return True

            delay = min(delay * 2, RECONNECT_MAX_DELAY)

        return False

    def get_status(self) -> dict:
        """Get VPN status for web UI / state file."""
        uptime = None
        if self.connected_since:
            elapsed = int(time.time() - self.connected_since)
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime = f"{hours}:{minutes:02d}:{seconds:02d}"

        return {
            'state': self.state.value,
            'connected': self.state == VPNState.CONNECTED,
            'server': self.config.gateway_host,
            'port': self.config.gateway_port,
            'protocol': 'HTP (HookProbe Transport Protocol)',
            'encryption': 'ChaCha20-Poly1305 AEAD',
            'tun_device': self.config.tun_device,
            'tun_ip': self.config.tun_local_ip,
            'kill_switch': self.config.kill_switch,
            'wan_interface': self.config.wan_interface,
            'uptime': uptime,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'reconnect_count': self.reconnect_count,
            'ts': time.time(),
        }

    def set_kill_switch(self, mode: str):
        """Change kill switch mode at runtime."""
        try:
            KillSwitchMode(mode)
        except ValueError:
            logger.error("Invalid kill switch mode: %s", mode)
            return

        self.config.kill_switch = mode
        if self.state == VPNState.CONNECTED:
            self._apply_traffic_marks()
        logger.info("Kill switch mode changed to: %s", mode)
        self._write_state_file()


# =============================================================================
# STANDALONE DAEMON
# =============================================================================

COMMAND_FILE = Path('/etc/hookprobe/vpn_command')


def _check_command(client: FortressVPNClient) -> Optional[str]:
    """Read and consume command file written by web UI."""
    try:
        if not COMMAND_FILE.exists():
            return None
        data = json.loads(COMMAND_FILE.read_text())
        COMMAND_FILE.unlink(missing_ok=True)
        # Only process fresh commands (< 60s old)
        if time.time() - data.get('ts', 0) > 60:
            return None
        return data.get('command')
    except (json.JSONDecodeError, OSError):
        return None


def _emergency_cleanup():
    """Last-resort cleanup: remove nftables VPN table and PBR rules.

    Registered via atexit to prevent kill switch from persisting
    after crashes, SIGKILL, or unhandled exceptions.
    """
    try:
        subprocess.run(
            ['nft', 'delete', 'table', 'inet', 'fortress_vpn'],
            capture_output=True, timeout=5
        )
    except Exception:
        pass
    try:
        subprocess.run(
            ['ip', 'rule', 'del', 'fwmark',
             f'{VPN_FWMARK}/{VPN_FWMASK}', 'table', str(VPN_ROUTING_TABLE)],
            capture_output=True, timeout=5
        )
    except Exception:
        pass
    try:
        subprocess.run(
            ['ip', 'route', 'flush', 'table', str(VPN_ROUTING_TABLE)],
            capture_output=True, timeout=5
        )
    except Exception:
        pass


def main():
    """Run Fortress VPN client as daemon."""
    import atexit

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
    )

    # Register emergency cleanup FIRST — before anything else.
    # This ensures nftables rules are removed even on unhandled exceptions.
    atexit.register(_emergency_cleanup)

    config = VPNConfig.load()

    import argparse
    parser = argparse.ArgumentParser(description='Fortress HTP VPN Client')
    parser.add_argument('--gateway', default=config.gateway_host, help='Gateway hostname')
    parser.add_argument('--port', type=int, default=config.gateway_port, help='Gateway port')
    parser.add_argument('--token', default=config.device_token, help='PSK/device token')
    parser.add_argument('--kill-switch', default=config.kill_switch,
                        choices=['off', 'host', 'full'], help='Kill switch mode')
    parser.add_argument('--wan', default=config.wan_interface, help='WAN interface')
    args = parser.parse_args()

    config.gateway_host = args.gateway
    config.gateway_port = args.port
    if args.token:
        config.device_token = args.token
    config.kill_switch = args.kill_switch
    if args.wan:
        config.wan_interface = args.wan

    if not config.device_token:
        logger.error("No device token/PSK configured. Set in %s or pass --token", CONFIG_FILE)
        sys.exit(1)

    client = FortressVPNClient(config)

    _shutdown_called = False

    def shutdown(sig, frame):
        nonlocal _shutdown_called
        if _shutdown_called:
            return  # Prevent double-shutdown from rapid signals
        _shutdown_called = True
        logger.info("Shutting down (signal %d)", sig)
        try:
            client.stop()
        except Exception as e:
            logger.error("Cleanup error during shutdown: %s", e)
        finally:
            sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Auto-start if enabled in config
    if config.enabled:
        if not client.start():
            logger.error("Failed to connect VPN on startup")
    else:
        logger.info("VPN not enabled in config — waiting for connect command")

    # Main loop: handle reconnection + web UI commands
    try:
        while True:
            time.sleep(5)

            # Check for commands from web UI
            cmd = _check_command(client)
            if cmd == 'connect' and client.state != VPNState.CONNECTED:
                # Reload config in case it was updated
                client.config = VPNConfig.load()
                if client.config.device_token:
                    client.start()
            elif cmd == 'disconnect' and client.state != VPNState.STOPPED:
                client.stop()

            # Auto-reconnect if connected but tunnel died
            if client.state not in (VPNState.STOPPED, VPNState.CONNECTED,
                                     VPNState.CONNECTING):
                client.reconnect()

    except KeyboardInterrupt:
        client.stop()


if __name__ == '__main__':
    main()
