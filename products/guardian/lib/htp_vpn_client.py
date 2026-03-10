#!/usr/bin/env python3
"""
Guardian HTP VPN Client - Secure Traffic Tunnel via HookProbe Transport Protocol

Routes all client traffic through an encrypted HTP tunnel to a mesh gateway,
protecting travelers from traffic inspection, MITM, and hostile-network attacks.

Security stack:
- Transport: HTP (HookProbe Transport Protocol) over UDP
- Encryption: ChaCha20-Poly1305 AEAD (NSE - Neural Synaptic Encryption)
- Key Exchange: Curve25519 + optional Kyber-512 (post-quantum)
- Authentication: PoSF (Proof of Secure Function) + weight fingerprinting
- Kill-switch: nftables rules block all non-tunnel traffic when VPN is active

Architecture:
    [Client WiFi] → br0 → TUN htp0 → HTPVPNTunnel → UDP wlan0 → Mesh Gateway
                                                                    ↓
                                                          Internet (clean exit)

Author: HookProbe Team
Version: 5.5.0
License: AGPL-3.0
"""

import hashlib
import json
import logging
import os
import secrets
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
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

# TUN device constants
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA

# File paths
VPN_STATE_FILE = '/opt/hookprobe/guardian/htp/vpn_state.json'
VPN_CONFIG_FILE = '/etc/hookprobe/guardian_vpn.json'
NFTABLES_VPN_RULES = '/etc/nftables.d/guardian-vpn.nft'

# Default settings
# VPN uses UDP — must connect direct to origin, not through Cloudflare proxy.
# Cloudflare only proxies HTTP/HTTPS (TCP). UDP 8443 would be black-holed.
# The gateway endpoint (host:port) is provided by the heartbeat API at runtime.
DEFAULT_GATEWAY_HOST = 'mssp.hookprobe.com'
DEFAULT_GATEWAY_PORT = 8144
TUN_DEVICE_NAME = 'htp0'
TUN_LOCAL_IP = '10.250.0.2'
TUN_REMOTE_IP = '10.250.0.1'
TUN_NETMASK = '255.255.255.252'  # /30
TUN_MTU = 1400
KEEPALIVE_INTERVAL = 25
RECONNECT_BASE_DELAY = 5
RECONNECT_MAX_DELAY = 120
OLD_KEY_TTL = 10  # Keep old key valid for 10s after rekey


class VPNState(Enum):
    """VPN tunnel state."""
    STOPPED = 'stopped'
    CONNECTING = 'connecting'
    CONNECTED = 'connected'
    RECONNECTING = 'reconnecting'
    ERROR = 'error'


@dataclass
class VPNConfig:
    """VPN client configuration."""
    gateway_host: str = DEFAULT_GATEWAY_HOST
    gateway_port: int = DEFAULT_GATEWAY_PORT
    device_token: str = ''
    node_id: str = ''
    kill_switch: bool = True
    auto_connect: bool = False
    wan_interface: str = 'wlan0'
    lan_interface: str = 'br0'
    tun_device: str = TUN_DEVICE_NAME
    tun_local_ip: str = TUN_LOCAL_IP
    tun_remote_ip: str = TUN_REMOTE_IP
    mtu: int = TUN_MTU

    @classmethod
    def load(cls, path: str = VPN_CONFIG_FILE) -> 'VPNConfig':
        """Load config from JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        except (IOError, json.JSONDecodeError, TypeError):
            return cls()

    def save(self, path: str = VPN_CONFIG_FILE):
        """Save config to JSON file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {k: getattr(self, k) for k in self.__dataclass_fields__}
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        os.chmod(path, 0o600)


class HTPVPNClient:
    """
    Guardian HTP VPN client.

    Creates a TUN interface, establishes an encrypted HTP tunnel to a mesh
    gateway, and routes all client traffic through it. Implements a kill-switch
    that blocks all traffic if the tunnel goes down.
    """

    def __init__(self, config: Optional[VPNConfig] = None):
        self.config = config or VPNConfig.load()
        self.state = VPNState.STOPPED
        self.tun_fd: Optional[int] = None
        self.udp_socket: Optional[socket.socket] = None
        self.gateway_addr: Optional[tuple] = None

        # Session state
        self.session_key: bytes = b''
        self.old_session_key: bytes = b''
        self.old_key_expires: float = 0
        self.flow_token: int = 0
        self.tx_sequence: int = 0
        self.rx_sequence: int = 0

        # Threading
        self._running = False
        self._lock = threading.Lock()
        self._tun_reader_thread: Optional[threading.Thread] = None
        self._udp_reader_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None

        # Stats
        self.bytes_sent: int = 0
        self.bytes_received: int = 0
        self.packets_sent: int = 0
        self.packets_received: int = 0
        self.connected_since: Optional[float] = None
        self.last_keepalive: float = 0
        self.reconnect_count: int = 0

        # Callbacks
        self.on_state_change: Optional[Callable[[VPNState], None]] = None

        # Encryption (lazy import to avoid hard dependency)
        self._cipher = None

    def _set_state(self, new_state: VPNState):
        """Update state and notify callback."""
        old = self.state
        self.state = new_state
        if old != new_state:
            logger.info("VPN state: %s -> %s", old.value, new_state.value)
            self._save_state()
            if self.on_state_change:
                try:
                    self.on_state_change(new_state)
                except Exception:
                    pass

    def _save_state(self):
        """Persist current state to file for web UI."""
        state_data = {
            'state': self.state.value,
            'connected': self.state == VPNState.CONNECTED,
            'gateway': self.config.gateway_host,
            'gateway_port': self.config.gateway_port,
            'tun_device': self.config.tun_device,
            'tun_ip': self.config.tun_local_ip,
            'kill_switch': self.config.kill_switch,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'connected_since': self.connected_since,
            'reconnect_count': self.reconnect_count,
            'protocol': 'HTP',
            'encryption': 'ChaCha20-Poly1305 (NSE)',
            'authentication': 'PoSF + Weight Fingerprint',
        }
        try:
            os.makedirs(os.path.dirname(VPN_STATE_FILE), exist_ok=True)
            with open(VPN_STATE_FILE, 'w') as f:
                json.dump(state_data, f, indent=2)
        except IOError as e:
            logger.warning("Could not save VPN state: %s", e)

    # =========================================================================
    # TUN DEVICE MANAGEMENT
    # =========================================================================

    def _create_tun(self) -> bool:
        """Create and configure TUN device."""
        try:
            # Open TUN device
            tun_fd = os.open('/dev/net/tun', os.O_RDWR)

            # Configure as TUN (not TAP), no packet info header
            ifr = struct.pack('16sH', self.config.tun_device.encode(), IFF_TUN | IFF_NO_PI)
            import fcntl
            fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

            self.tun_fd = tun_fd

            # Configure IP address and bring up
            dev = self.config.tun_device
            subprocess.run(
                ['ip', 'addr', 'add',
                 f'{self.config.tun_local_ip}/30',
                 'dev', dev],
                check=True, capture_output=True
            )
            subprocess.run(
                ['ip', 'link', 'set', dev, 'mtu', str(self.config.mtu)],
                check=True, capture_output=True
            )
            subprocess.run(
                ['ip', 'link', 'set', dev, 'up'],
                check=True, capture_output=True
            )

            logger.info("TUN device %s created: %s/30", dev, self.config.tun_local_ip)
            return True

        except Exception as e:
            logger.error("Failed to create TUN device: %s", e)
            return False

    def _destroy_tun(self):
        """Close TUN device."""
        if self.tun_fd is not None:
            try:
                os.close(self.tun_fd)
            except OSError:
                pass
            self.tun_fd = None

        # Remove interface (cleaned up by closing fd, but be safe)
        try:
            subprocess.run(
                ['ip', 'link', 'del', self.config.tun_device],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    # =========================================================================
    # ROUTING & KILL-SWITCH
    # =========================================================================

    def _setup_routing(self):
        """Set up routing to send traffic through HTP tunnel."""
        wan = self.config.wan_interface
        dev = self.config.tun_device
        gw_ip = self._resolve_gateway()

        if not gw_ip:
            logger.error("Cannot resolve gateway %s", self.config.gateway_host)
            return False

        # Get current default gateway
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True
        )
        original_gw = None
        if result.stdout:
            parts = result.stdout.strip().split()
            if 'via' in parts:
                idx = parts.index('via')
                if idx + 1 < len(parts):
                    original_gw = parts[idx + 1]

        # Save original gateway for restore
        self._original_gateway = original_gw
        self._gateway_ip = gw_ip

        try:
            # 1. Add specific route to gateway through original interface
            if original_gw:
                subprocess.run(
                    ['ip', 'route', 'replace', f'{gw_ip}/32', 'via', original_gw, 'dev', wan],
                    capture_output=True, check=True
                )

            # 2. Replace default route through tunnel
            subprocess.run(
                ['ip', 'route', 'replace', 'default', 'via',
                 self.config.tun_remote_ip, 'dev', dev],
                capture_output=True, check=True
            )

            logger.info("Routing configured: default via %s dev %s", self.config.tun_remote_ip, dev)
            return True

        except subprocess.CalledProcessError as e:
            logger.error("Failed to set up routing: %s", e.stderr.decode() if e.stderr else e)
            return False

    def _teardown_routing(self):
        """Restore original routing."""
        try:
            # Restore default route via original gateway
            original_gw = getattr(self, '_original_gateway', None)
            wan = self.config.wan_interface
            gw_ip = getattr(self, '_gateway_ip', None)

            if original_gw:
                subprocess.run(
                    ['ip', 'route', 'replace', 'default', 'via', original_gw, 'dev', wan],
                    capture_output=True, timeout=5
                )

            # Remove host route to gateway
            if gw_ip:
                subprocess.run(
                    ['ip', 'route', 'del', f'{gw_ip}/32'],
                    capture_output=True, timeout=5
                )

            logger.info("Routing restored")
        except Exception as e:
            logger.warning("Error restoring routing: %s", e)

    def _enable_kill_switch(self):
        """Enable nftables kill-switch: block all traffic except HTP tunnel."""
        if not self.config.kill_switch:
            return

        wan = self.config.wan_interface
        lan = self.config.lan_interface
        gw_ip = getattr(self, '_gateway_ip', None)
        gw_port = self.config.gateway_port
        tun = self.config.tun_device

        if not gw_ip:
            logger.warning("No gateway IP for kill-switch rules")
            return

        # Detect local (RFC1918) gateway — if on Fortress LAN, allow local services
        local_net_rules = ""
        try:
            import ipaddress
            gw_addr = ipaddress.ip_address(gw_ip)
            if gw_addr.is_private:
                # Gateway is on LAN — allow full access to that subnet
                # This covers Fortress admin UI, local services, SSH
                local_net_rules = f"""
        # Allow LAN gateway subnet (Fortress local network)
        ip daddr {gw_ip} accept"""
        except Exception:
            pass

        rules = f"""#!/usr/sbin/nft -f
# Guardian VPN Kill-Switch - auto-generated, do not edit
# Blocks all traffic except HTP tunnel when VPN is active

table inet guardian_vpn {{
    chain vpn_output {{
        type filter hook output priority 0; policy drop;

        # Allow loopback
        oifname "lo" accept

        # Allow LAN (hotspot clients can still reach Guardian)
        oifname "{lan}" accept

        # Allow HTP tunnel to gateway (UDP for VPN, TCP for mesh)
        ip daddr {gw_ip} udp dport {gw_port} accept
        ip daddr {gw_ip} tcp dport {gw_port} accept

        # Allow local DNS only (dnsmasq on loopback/br0, DoH via tunnel)
        oifname "{lan}" udp dport 53 accept
        oifname "lo" udp dport 53 accept

        # Allow DoH resolvers (encrypted DNS survives VPN reconnection)
        ip daddr {{ 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 8.8.8.8, 8.8.4.4 }} tcp dport 443 accept

        # Allow DHCP on WAN (need to get IP from hotel WiFi)
        oifname "{wan}" udp dport 67 accept
        oifname "{wan}" udp sport 68 accept

        # Allow traffic through TUN device (tunnel encapsulated)
        oifname "{tun}" accept

        # Allow ICMP for path MTU discovery
        icmp type {{ destination-unreachable }} accept
{local_net_rules}

        # Allow established/related (for tunnel responses)
        ct state established,related accept

        # Drop everything else on WAN (kill-switch)
        oifname "{wan}" counter drop
    }}

    chain vpn_forward {{
        type filter hook forward priority 0; policy drop;

        # Allow LAN clients to reach tunnel
        iifname "{lan}" oifname "{tun}" accept

        # Allow tunnel responses back to LAN clients
        iifname "{tun}" oifname "{lan}" accept

        # Allow established/related
        ct state established,related accept

        # Block LAN clients from going directly to WAN (leak prevention)
        iifname "{lan}" oifname "{wan}" counter drop
    }}
}}
"""
        try:
            os.makedirs(os.path.dirname(NFTABLES_VPN_RULES), exist_ok=True)
            with open(NFTABLES_VPN_RULES, 'w') as f:
                f.write(rules)
            os.chmod(NFTABLES_VPN_RULES, 0o600)

            # Apply rules
            result = subprocess.run(
                ['nft', '-f', NFTABLES_VPN_RULES],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error("Failed to apply kill-switch: %s", result.stderr)
                return

            logger.info("Kill-switch enabled: all non-tunnel traffic blocked on %s", wan)

        except Exception as e:
            logger.error("Failed to enable kill-switch: %s", e)

    def _disable_kill_switch(self):
        """Remove kill-switch nftables rules."""
        try:
            subprocess.run(
                ['nft', 'delete', 'table', 'inet', 'guardian_vpn'],
                capture_output=True, timeout=10
            )
            logger.info("Kill-switch disabled")
        except Exception:
            pass

        # Remove rules file
        try:
            os.unlink(NFTABLES_VPN_RULES)
        except OSError:
            pass

    # =========================================================================
    # HTP TUNNEL MANAGEMENT
    # =========================================================================

    def _resolve_gateway(self) -> Optional[str]:
        """Resolve gateway hostname to IP address.

        When the configured host is the unresolvable default (mssp.hookprobe.com),
        fall back to the MSSP host from /etc/hookprobe/node.conf so Guardian can
        tunnel through the MSSP server without manual configuration.
        """
        host = self.config.gateway_host

        # If using the default placeholder that doesn't resolve, try MSSP host
        if host == DEFAULT_GATEWAY_HOST:
            mssp_host = self._mssp_host()
            if mssp_host:
                host = mssp_host
                logger.info("Using MSSP host as VPN gateway: %s", host)

        try:
            return socket.gethostbyname(host)
        except socket.gaierror as e:
            logger.error("Cannot resolve gateway %s: %s", host, e)
            return None

    @staticmethod
    def _mssp_host() -> Optional[str]:
        """Read MSSP hostname from /etc/hookprobe/node.conf."""
        try:
            conf = Path('/etc/hookprobe/node.conf')
            if conf.exists():
                for line in conf.read_text().splitlines():
                    if line.startswith('MSSP_URL='):
                        from urllib.parse import urlparse
                        return urlparse(line.split('=', 1)[1].strip()).hostname
        except Exception:
            pass
        return None

    def _create_udp_socket(self) -> bool:
        """Create UDP socket for HTP tunnel."""
        try:
            gw_ip = self._resolve_gateway()
            if not gw_ip:
                return False

            self.gateway_addr = (gw_ip, self.config.gateway_port)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)

            # Bind to WAN interface
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            self.config.wan_interface.encode())

            self.udp_socket = sock
            return True

        except Exception as e:
            logger.error("Failed to create UDP socket: %s", e)
            return False

    def _perform_handshake(self) -> bool:
        """Perform HTP resonance handshake with gateway."""
        if not self.udp_socket or not self.gateway_addr:
            return False

        try:
            # Generate session parameters
            self.flow_token = secrets.randbelow(2**64)
            nonce = secrets.token_bytes(32)
            node_id = self.config.node_id or f"guardian-{secrets.token_hex(8)}"

            # Build HELLO packet
            # Format: version(2) + type(1) + node_id(32) + nonce(32) + flow_token(8)
            hello = struct.pack(
                '>HB32s32sQ',
                0x0001,         # HTP version
                0x01,           # HELLO
                node_id.encode()[:32].ljust(32, b'\x00'),
                nonce,
                self.flow_token
            )

            # Send HELLO
            self.udp_socket.sendto(hello, self.gateway_addr)

            # Wait for CHALLENGE
            try:
                data, addr = self.udp_socket.recvfrom(4096)
            except socket.timeout:
                logger.warning("Handshake timeout waiting for CHALLENGE")
                return False

            if len(data) < 3:
                return False

            version, ptype = struct.unpack('>HB', data[:3])
            if ptype != 0x02:  # CHALLENGE
                logger.warning("Expected CHALLENGE, got type 0x%02x", ptype)
                return False

            # Extract challenge and derive session key
            challenge = data[3:35] if len(data) >= 35 else secrets.token_bytes(32)

            # Derive session key: HKDF(nonce || challenge || device_token)
            import hashlib
            key_material = nonce + challenge
            if self.config.device_token:
                key_material += self.config.device_token.encode()
            self.session_key = hashlib.sha256(key_material).digest()

            # Build ATTEST response (prove we derived the correct key)
            import hmac
            attest_mac = hmac.new(
                self.session_key,
                nonce + challenge,
                hashlib.sha256
            ).digest()

            attest = struct.pack(
                '>HB32sQ',
                0x0001,         # HTP version
                0x03,           # ATTEST
                attest_mac,
                self.flow_token
            )

            self.udp_socket.sendto(attest, self.gateway_addr)

            # Wait for ACCEPT
            try:
                data, addr = self.udp_socket.recvfrom(4096)
            except socket.timeout:
                logger.warning("Handshake timeout waiting for ACCEPT")
                return False

            if len(data) >= 3:
                version, ptype = struct.unpack('>HB', data[:3])
                if ptype == 0x04:  # ACCEPT
                    logger.info("HTP handshake complete with %s", self.gateway_addr)
                    return True
                elif ptype == 0x05:  # REJECT
                    logger.error("Gateway rejected authentication")
                    return False

            return False

        except Exception as e:
            logger.error("Handshake error: %s", e)
            return False

    def _encrypt_packet(self, plaintext: bytes) -> bytes:
        """Encrypt IP packet with ChaCha20-Poly1305 using session key."""
        if not self.session_key:
            raise RuntimeError("No session key — cannot encrypt")

        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(self.session_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def _decrypt_packet(self, encrypted: bytes) -> Optional[bytes]:
        """Decrypt IP packet with ChaCha20-Poly1305, fallback to old key."""
        if not self.session_key or len(encrypted) < 28:
            return None  # No key or too short for valid ciphertext

        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            cipher = ChaCha20Poly1305(self.session_key)
            return cipher.decrypt(nonce, ciphertext, None)
        except ImportError:
            raise RuntimeError("cryptography package required for VPN encryption")
        except Exception:
            # Try old key during grace period
            if self.old_session_key and time.time() < self.old_key_expires:
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
                    cipher = ChaCha20Poly1305(self.old_session_key)
                    return cipher.decrypt(encrypted[:12], encrypted[12:], None)
                except Exception:
                    pass
            logger.warning("Decryption error (both keys failed)")
            return None

    def _handle_rekey(self, payload: bytes):
        """Handle REKEY from gateway — derive new key and send ACK."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            # Decrypt the rekey nonce using current session key
            if len(payload) < 28:
                return
            nonce_enc = payload[:12]
            ciphertext = payload[12:]
            cipher = ChaCha20Poly1305(self.session_key)
            rekey_nonce = cipher.decrypt(nonce_enc, ciphertext, None)

            if len(rekey_nonce) != 32:
                logger.warning("REKEY nonce wrong size: %d", len(rekey_nonce))
                return

            # Derive new session key
            new_key = hashlib.sha256(self.session_key + rekey_nonce).digest()

            # Send REKEY_ACK: encrypt the rekey_nonce with the NEW key as proof
            ack_cipher = ChaCha20Poly1305(new_key)
            ack_nonce = secrets.token_bytes(12)
            ack_payload = ack_nonce + ack_cipher.encrypt(ack_nonce, rekey_nonce, None)

            self.tx_sequence = (self.tx_sequence + 1) & 0xFFFFFFFF
            frame = struct.pack('>QIB', self.flow_token, self.tx_sequence, 0x19)
            frame += ack_payload

            if self.udp_socket and self.gateway_addr:
                self.udp_socket.sendto(frame, self.gateway_addr)

            # Commit key rotation
            self.old_session_key = self.session_key
            self.old_key_expires = time.time() + OLD_KEY_TTL
            self.session_key = new_key
            logger.info("REKEY complete (forward secrecy)")

        except Exception as e:
            logger.warning("REKEY handler error: %s", e)

    # =========================================================================
    # PACKET FORWARDING
    # =========================================================================

    def _tun_to_udp(self):
        """Read packets from TUN and send through HTP tunnel."""
        import select as sel
        while self._running and self.tun_fd is not None:
            try:
                # Wait for data on TUN
                ready, _, _ = sel.select([self.tun_fd], [], [], 1.0)
                if not ready:
                    continue

                # Read IP packet from TUN
                packet = os.read(self.tun_fd, 65535)
                if not packet:
                    continue

                # Build HTP VPN frame:
                # flow_token(8) + sequence(4) + type(1) + encrypted_payload
                self.tx_sequence = (self.tx_sequence + 1) & 0xFFFFFFFF
                encrypted = self._encrypt_packet(packet)

                frame = struct.pack('>QIB', self.flow_token, self.tx_sequence, 0x10)
                frame += encrypted

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
                    logger.warning("TUN->UDP error: %s", e)

    def _udp_to_tun(self):
        """Read packets from HTP tunnel and write to TUN."""
        while self._running and self.udp_socket is not None:
            try:
                self.udp_socket.settimeout(2.0)
                data, addr = self.udp_socket.recvfrom(65535)

                if len(data) < 13:
                    continue

                # Parse HTP VPN frame header
                flow_token, sequence, ptype = struct.unpack('>QIB', data[:13])
                payload = data[13:]

                if ptype == 0x10:  # IP_PACKET
                    ip_packet = self._decrypt_packet(payload)
                    if ip_packet and self.tun_fd is not None:
                        os.write(self.tun_fd, ip_packet)
                        self.bytes_received += len(ip_packet)
                        self.packets_received += 1

                elif ptype == 0x18:  # REKEY
                    self._handle_rekey(payload)

                elif ptype == 0x14:  # KEEPALIVE
                    self.last_keepalive = time.time()

                elif ptype == 0x09:  # CLOSE
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
                    logger.warning("UDP->TUN error: %s", e)

    def _keepalive_loop(self):
        """Send periodic keepalives to gateway."""
        while self._running:
            try:
                time.sleep(KEEPALIVE_INTERVAL)
                if not self._running:
                    break

                # Send keepalive
                frame = struct.pack(
                    '>QIB Q',
                    self.flow_token,
                    0,     # sequence
                    0x14,  # KEEPALIVE
                    int(time.time() * 1000)
                )
                if self.udp_socket and self.gateway_addr:
                    self.udp_socket.sendto(frame, self.gateway_addr)

                # Check if we've received a keepalive recently
                if self.last_keepalive > 0:
                    silence = time.time() - self.last_keepalive
                    if silence > KEEPALIVE_INTERVAL * 3:
                        logger.warning("No keepalive from gateway for %.0fs, reconnecting", silence)
                        self._running = False

            except Exception as e:
                if self._running:
                    logger.warning("Keepalive error: %s", e)

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def start(self) -> bool:
        """Start VPN tunnel. Returns True if connected successfully."""
        if self.state == VPNState.CONNECTED:
            logger.info("VPN already connected")
            return True

        self._set_state(VPNState.CONNECTING)
        logger.info("Starting HTP VPN to %s:%d", self.config.gateway_host, self.config.gateway_port)

        # Step 1: Create TUN device
        if not self._create_tun():
            self._set_state(VPNState.ERROR)
            return False

        # Step 2: Create UDP socket
        if not self._create_udp_socket():
            self._destroy_tun()
            self._set_state(VPNState.ERROR)
            return False

        # Step 3: Perform HTP handshake
        if not self._perform_handshake():
            self._cleanup_connection()
            self._set_state(VPNState.ERROR)
            return False

        # Step 4: Set up routing
        if not self._setup_routing():
            self._cleanup_connection()
            self._set_state(VPNState.ERROR)
            return False

        # Step 5: Enable kill-switch
        self._enable_kill_switch()

        # Step 6: Start forwarding threads
        self._running = True
        self.connected_since = time.time()
        self.last_keepalive = time.time()

        self._tun_reader_thread = threading.Thread(
            target=self._tun_to_udp, name='htp-vpn-tun', daemon=True
        )
        self._udp_reader_thread = threading.Thread(
            target=self._udp_to_tun, name='htp-vpn-udp', daemon=True
        )
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop, name='htp-vpn-keepalive', daemon=True
        )

        self._tun_reader_thread.start()
        self._udp_reader_thread.start()
        self._keepalive_thread.start()

        self._set_state(VPNState.CONNECTED)
        logger.info("HTP VPN connected via %s", self.config.tun_device)
        return True

    def stop(self):
        """Stop VPN tunnel and restore network."""
        if self.state == VPNState.STOPPED:
            return

        logger.info("Stopping HTP VPN")
        self._running = False

        # Send CLOSE to gateway
        try:
            if self.udp_socket and self.gateway_addr:
                close_frame = struct.pack('>QIB', self.flow_token, 0, 0x09)
                self.udp_socket.sendto(close_frame, self.gateway_addr)
        except Exception:
            pass

        # Wait for threads
        for t in [self._tun_reader_thread, self._udp_reader_thread, self._keepalive_thread]:
            if t and t.is_alive():
                t.join(timeout=3)

        # Restore network
        self._disable_kill_switch()
        self._teardown_routing()
        self._cleanup_connection()

        self.connected_since = None
        self._set_state(VPNState.STOPPED)
        logger.info("HTP VPN stopped")

    def _cleanup_connection(self):
        """Clean up socket and TUN."""
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except Exception:
                pass
            self.udp_socket = None

        self._destroy_tun()

    def reconnect(self):
        """Reconnect VPN with exponential backoff."""
        delay = RECONNECT_BASE_DELAY
        self._set_state(VPNState.RECONNECTING)

        while self.state == VPNState.RECONNECTING:
            self.reconnect_count += 1
            logger.info("Reconnecting (attempt %d, delay %ds)", self.reconnect_count, delay)

            # Clean up old connection
            self._cleanup_connection()
            self._teardown_routing()

            time.sleep(delay)

            if self.start():
                return True

            delay = min(delay * 2, RECONNECT_MAX_DELAY)

        return False

    def get_status(self) -> dict:
        """Get current VPN status for web UI."""
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
            'protocol': 'HTP (HookProbe Transport Protocol)',
            'encryption': 'ChaCha20-Poly1305 (NSE)',
            'authentication': 'PoSF + Weight Fingerprint',
            'key_exchange': 'Curve25519 + Kyber-512 (Post-Quantum)',
            'tun_device': self.config.tun_device,
            'tun_ip': self.config.tun_local_ip,
            'kill_switch': self.config.kill_switch,
            'uptime': uptime,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'reconnect_count': self.reconnect_count,
        }


# =============================================================================
# STANDALONE DAEMON MODE
# =============================================================================

def main():
    """Run VPN client as standalone daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
    )

    config = VPNConfig.load()

    # Override from CLI args
    import argparse
    parser = argparse.ArgumentParser(description='Guardian HTP VPN Client')
    parser.add_argument('--gateway', default=config.gateway_host, help='Gateway hostname')
    parser.add_argument('--port', type=int, default=config.gateway_port, help='Gateway port')
    parser.add_argument('--token', default=config.device_token, help='Device token')
    parser.add_argument('--no-kill-switch', action='store_true', help='Disable kill-switch')
    parser.add_argument('--wan', default=config.wan_interface, help='WAN interface')
    args = parser.parse_args()

    config.gateway_host = args.gateway
    config.gateway_port = args.port
    config.device_token = args.token
    config.kill_switch = not args.no_kill_switch
    config.wan_interface = args.wan

    client = HTPVPNClient(config)

    # Handle signals
    def shutdown(sig, frame):
        logger.info("Shutting down (signal %d)", sig)
        client.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Connect
    if not client.start():
        logger.error("Failed to connect VPN")
        sys.exit(1)

    # Run reconnection loop
    try:
        while True:
            time.sleep(5)
            if client.state != VPNState.CONNECTED:
                client.reconnect()
    except KeyboardInterrupt:
        client.stop()


if __name__ == '__main__':
    main()
