"""
VPN Profile Generator

Generates platform-specific VPN profiles:
- iOS: .mobileconfig (Configuration Profile)
- Android: VPN connection JSON / strongSwan profile
- macOS: .mobileconfig
- Windows: PowerShell script or VPN connection

All profiles use IKEv2 with EAP-TLS authentication via Nexus gateway.
"""

import os
import uuid
import base64
import plistlib
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from django.conf import settings

from .certificate_manager import CertificateManager


class VPNProfileGenerator:
    """
    Generates VPN connection profiles for various platforms.

    Profiles connect via IKEv2 to Nexus, which then routes to
    Guardian/Fortress devices over HTP.
    """

    def __init__(self):
        """Initialize profile generator."""
        self.cert_manager = CertificateManager()

        # Nexus VPN gateway settings
        self.vpn_server = os.getenv('VPN_SERVER_HOST', 'vpn.hookprobe.com')
        self.vpn_server_id = os.getenv('VPN_SERVER_ID', 'vpn.hookprobe.com')
        self.organization = os.getenv('VPN_ORGANIZATION', 'HookProbe')

    def generate_ios_profile(
        self,
        profile_name: str,
        user_identifier: str,
        cert_pem: bytes,
        encrypted_private_key: bytes,
        key_iv: bytes,
        device_name: str = "",
        route_all_traffic: bool = False,
        split_tunnel_routes: Optional[List[str]] = None,
        dns_servers: Optional[List[str]] = None,
        on_demand_enabled: bool = True,
    ) -> bytes:
        """
        Generate iOS/macOS .mobileconfig profile.

        This creates a Configuration Profile that can be installed on
        iOS/iPadOS/macOS devices for automatic VPN configuration.

        Args:
            profile_name: User-friendly profile name
            user_identifier: User's email or UUID for IKEv2 local ID
            cert_pem: User certificate in PEM format
            encrypted_private_key: Encrypted private key
            key_iv: IV for key decryption
            device_name: Target device name (for display)
            route_all_traffic: Route all traffic through VPN
            split_tunnel_routes: CIDR ranges for split tunneling
            dns_servers: DNS servers when VPN is active
            on_demand_enabled: Enable on-demand VPN connection

        Returns:
            Signed .mobileconfig bytes
        """
        # Generate unique identifiers
        profile_uuid = str(uuid.uuid4()).upper()
        vpn_uuid = str(uuid.uuid4()).upper()
        cert_uuid = str(uuid.uuid4()).upper()
        ca_uuid = str(uuid.uuid4()).upper()

        # Create PKCS#12 from certificate and key
        p12_password = base64.urlsafe_b64encode(os.urandom(24)).decode()
        p12_data = self.cert_manager.create_pkcs12(
            cert_pem, encrypted_private_key, key_iv, p12_password
        )

        # Build on-demand rules
        on_demand_rules = []
        if on_demand_enabled:
            on_demand_rules = [
                # Connect on cellular
                {
                    'InterfaceTypeMatch': 'Cellular',
                    'Action': 'Connect',
                },
                # Connect on WiFi (except trusted networks)
                {
                    'InterfaceTypeMatch': 'WiFi',
                    'Action': 'Connect',
                },
                # Disconnect on Ethernet (assumed trusted)
                {
                    'InterfaceTypeMatch': 'Ethernet',
                    'Action': 'Disconnect',
                },
                # Default: Connect
                {
                    'Action': 'Connect',
                },
            ]

        # Build VPN payload
        vpn_payload = {
            'PayloadType': 'com.apple.vpn.managed',
            'PayloadUUID': vpn_uuid,
            'PayloadIdentifier': f'com.hookprobe.vpn.{vpn_uuid}',
            'PayloadDisplayName': f'HookProbe VPN - {device_name or profile_name}',
            'PayloadDescription': f'VPN connection to {device_name or "your HookProbe network"}',
            'PayloadVersion': 1,

            # VPN Type
            'VPNType': 'IKEv2',
            'VPNSubType': '',

            # IKEv2 Configuration
            'IKEv2': {
                # Server
                'RemoteAddress': self.vpn_server,
                'RemoteIdentifier': self.vpn_server_id,

                # Client authentication
                'LocalIdentifier': user_identifier,
                'AuthenticationMethod': 'Certificate',
                'PayloadCertificateUUID': cert_uuid,

                # IKE SA
                'IKESecurityAssociationParameters': {
                    'EncryptionAlgorithm': 'AES-256-GCM',
                    'IntegrityAlgorithm': 'SHA2-256',
                    'DiffieHellmanGroup': 20,  # ECP_384
                    'LifeTimeInMinutes': 1440,  # 24 hours
                },

                # Child SA (ESP)
                'ChildSecurityAssociationParameters': {
                    'EncryptionAlgorithm': 'AES-256-GCM',
                    'IntegrityAlgorithm': 'SHA2-256',
                    'DiffieHellmanGroup': 20,
                    'LifeTimeInMinutes': 480,  # 8 hours
                },

                # Options
                'EnablePFS': True,
                'DisableMOBIKE': False,  # Enable MOBIKE for network switching
                'DisableRedirect': False,
                'NATKeepAliveInterval': 20,  # Keep NAT mapping alive
                'UseConfigurationAttributeInternalIPSubnet': False,

                # Certificate-based auth
                'CertificateType': 'ECDSA256',

                # Dead Peer Detection
                'DeadPeerDetectionRate': 'Medium',  # Low/Medium/High/None

                # Extended Authentication (EAP)
                'ExtendedAuthEnabled': False,
            },

            # On-Demand
            'OnDemandEnabled': 1 if on_demand_enabled else 0,
            'OnDemandRules': on_demand_rules,

            # VPN On Demand Match
            'VPNOnDemandRules': on_demand_rules,
        }

        # Add DNS configuration if specified
        if dns_servers:
            vpn_payload['DNS'] = {
                'ServerAddresses': dns_servers,
            }

        # Add split tunnel routes if not routing all traffic
        if not route_all_traffic and split_tunnel_routes:
            # iOS uses IncludedRoutes for split tunneling
            vpn_payload['IKEv2']['IncludedRoutes'] = [
                {'Address': route.split('/')[0], 'PrefixLength': int(route.split('/')[1])}
                for route in split_tunnel_routes
            ]
        elif route_all_traffic:
            # Route all traffic through VPN
            vpn_payload['IKEv2']['IncludedRoutes'] = [
                {'Address': '0.0.0.0', 'PrefixLength': 0}
            ]

        # User certificate payload (PKCS#12)
        cert_payload = {
            'PayloadType': 'com.apple.security.pkcs12',
            'PayloadUUID': cert_uuid,
            'PayloadIdentifier': f'com.hookprobe.vpn.cert.{cert_uuid}',
            'PayloadDisplayName': 'HookProbe VPN Certificate',
            'PayloadDescription': 'Your personal VPN authentication certificate',
            'PayloadVersion': 1,
            'PayloadContent': p12_data,
            'Password': p12_password,
        }

        # CA certificate payload
        ca_cert_pem = self.cert_manager.get_ca_certificate_pem()
        # Convert PEM to DER for the payload
        from cryptography import x509
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)

        ca_payload = {
            'PayloadType': 'com.apple.security.root',
            'PayloadUUID': ca_uuid,
            'PayloadIdentifier': f'com.hookprobe.vpn.ca.{ca_uuid}',
            'PayloadDisplayName': 'HookProbe VPN CA',
            'PayloadDescription': 'HookProbe Nexus VPN Certificate Authority',
            'PayloadVersion': 1,
            'PayloadContent': ca_cert_der,
        }

        # Build complete profile
        profile = {
            'PayloadType': 'Configuration',
            'PayloadUUID': profile_uuid,
            'PayloadIdentifier': f'com.hookprobe.vpn.profile.{profile_uuid}',
            'PayloadDisplayName': f'HookProbe VPN - {profile_name}',
            'PayloadDescription': f'Secure VPN connection to your {device_name or "HookProbe"} network. '
                                  f'This profile enables encrypted access to your home or business network.',
            'PayloadOrganization': self.organization,
            'PayloadVersion': 1,
            'PayloadRemovalDisallowed': False,

            # Nested payloads
            'PayloadContent': [
                ca_payload,
                cert_payload,
                vpn_payload,
            ],
        }

        # Serialize to plist
        return plistlib.dumps(profile)

    def generate_android_profile(
        self,
        profile_name: str,
        user_identifier: str,
        cert_pem: bytes,
        encrypted_private_key: bytes,
        key_iv: bytes,
        device_name: str = "",
        route_all_traffic: bool = False,
        split_tunnel_routes: Optional[List[str]] = None,
        dns_servers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate Android VPN profile (strongSwan compatible).

        This creates a JSON profile that can be imported into the
        strongSwan VPN Client app on Android.

        Args:
            profile_name: User-friendly profile name
            user_identifier: User's email or UUID for IKEv2 local ID
            cert_pem: User certificate in PEM format
            encrypted_private_key: Encrypted private key
            key_iv: IV for key decryption
            device_name: Target device name
            route_all_traffic: Route all traffic through VPN
            split_tunnel_routes: CIDR ranges for split tunneling
            dns_servers: DNS servers when VPN is active

        Returns:
            Dict containing profile data and certificate files
        """
        # Create PKCS#12 for import
        p12_password = base64.urlsafe_b64encode(os.urandom(24)).decode()
        p12_data = self.cert_manager.create_pkcs12(
            cert_pem, encrypted_private_key, key_iv, p12_password
        )

        # strongSwan profile format
        profile = {
            'uuid': str(uuid.uuid4()),
            'name': f'HookProbe - {device_name or profile_name}',
            'type': 'ikev2-cert',

            # Server
            'remote': {
                'addr': self.vpn_server,
                'id': self.vpn_server_id,
            },

            # Client
            'local': {
                'id': user_identifier,
                # Certificate will be imported separately
            },

            # IKE proposal
            'ike-proposal': 'aes256gcm16-sha384-ecp384',

            # ESP proposal
            'esp-proposal': 'aes256gcm16-sha384',

            # Options
            'options': {
                'mobike': True,
                'cert-req': True,
                'ocsp': False,  # Skip OCSP for offline scenarios
            },

            # Split tunneling
            'split-tunneling': not route_all_traffic,
            'included-subnets': split_tunnel_routes or [],
            'excluded-subnets': [],

            # DNS
            'dns-servers': dns_servers or [],
        }

        # Return profile and certificate data
        return {
            'profile': profile,
            'certificate': {
                'p12_data': base64.b64encode(p12_data).decode(),
                'p12_password': p12_password,
                'filename': f'hookprobe_vpn_{user_identifier.replace("@", "_")}.p12',
            },
            'ca_certificate': {
                'pem_data': self.cert_manager.get_ca_certificate_pem().decode(),
                'filename': 'hookprobe_ca.crt',
            },
        }

    def generate_windows_profile(
        self,
        profile_name: str,
        user_identifier: str,
        cert_pem: bytes,
        encrypted_private_key: bytes,
        key_iv: bytes,
        device_name: str = "",
        route_all_traffic: bool = False,
        split_tunnel_routes: Optional[List[str]] = None,
        dns_servers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate Windows VPN profile (PowerShell script).

        Creates a PowerShell script that configures IKEv2 VPN
        and imports the required certificates.

        Args:
            Same as generate_ios_profile

        Returns:
            Dict containing PowerShell script and certificate files
        """
        # Create PKCS#12 for import
        p12_password = base64.urlsafe_b64encode(os.urandom(24)).decode()
        p12_data = self.cert_manager.create_pkcs12(
            cert_pem, encrypted_private_key, key_iv, p12_password
        )

        # Build PowerShell script
        ps_script = f'''# HookProbe VPN Setup Script
# Run as Administrator

$ErrorActionPreference = "Stop"

# Configuration
$VpnName = "HookProbe - {device_name or profile_name}"
$ServerAddress = "{self.vpn_server}"
$CertPassword = ConvertTo-SecureString -String "{p12_password}" -AsPlainText -Force

Write-Host "Installing HookProbe VPN..." -ForegroundColor Cyan

# Import CA certificate
$CaCertPath = Join-Path $PSScriptRoot "hookprobe_ca.crt"
if (Test-Path $CaCertPath) {{
    Import-Certificate -FilePath $CaCertPath -CertStoreLocation Cert:\\LocalMachine\\Root
    Write-Host "  CA certificate imported" -ForegroundColor Green
}}

# Import user certificate
$UserCertPath = Join-Path $PSScriptRoot "hookprobe_user.p12"
if (Test-Path $UserCertPath) {{
    Import-PfxCertificate -FilePath $UserCertPath -CertStoreLocation Cert:\\CurrentUser\\My -Password $CertPassword
    Write-Host "  User certificate imported" -ForegroundColor Green
}}

# Remove existing VPN if present
$existingVpn = Get-VpnConnection -Name $VpnName -ErrorAction SilentlyContinue
if ($existingVpn) {{
    Remove-VpnConnection -Name $VpnName -Force
    Write-Host "  Removed existing VPN connection" -ForegroundColor Yellow
}}

# Create IKEv2 VPN connection
Add-VpnConnection `
    -Name $VpnName `
    -ServerAddress $ServerAddress `
    -TunnelType Ikev2 `
    -AuthenticationMethod MachineCertificate `
    -EncryptionLevel Required `
    -RememberCredential `
    -SplitTunneling:${str(not route_all_traffic).lower()}

Write-Host "  VPN connection created" -ForegroundColor Green

# Configure IKEv2 security
Set-VpnConnectionIPsecConfiguration `
    -ConnectionName $VpnName `
    -AuthenticationTransformConstants GCMAES256 `
    -CipherTransformConstants GCMAES256 `
    -EncryptionMethod GCMAES256 `
    -IntegrityCheckMethod SHA384 `
    -DHGroup ECP384 `
    -PfsGroup ECP384 `
    -Force

Write-Host "  Security settings configured" -ForegroundColor Green
'''

        # Add split tunnel routes if configured
        if split_tunnel_routes and not route_all_traffic:
            routes_script = '\n# Configure split tunnel routes\n'
            for route in split_tunnel_routes:
                addr, prefix = route.split('/')
                routes_script += f'Add-VpnConnectionRoute -ConnectionName $VpnName -DestinationPrefix "{route}"\n'
            ps_script += routes_script

        # Add DNS configuration
        if dns_servers:
            dns_script = f'''
# Configure DNS
$adapter = Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -like "*{profile_name}*" }}
if ($adapter) {{
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses {",".join(dns_servers)}
}}
'''
            ps_script += dns_script

        ps_script += '''
Write-Host ""
Write-Host "VPN setup complete!" -ForegroundColor Green
Write-Host "Connect using: Settings > Network > VPN > $VpnName"
'''

        return {
            'script': ps_script,
            'filename': 'Install-HookProbeVPN.ps1',
            'certificate': {
                'p12_data': base64.b64encode(p12_data).decode(),
                'p12_password': p12_password,
                'filename': 'hookprobe_user.p12',
            },
            'ca_certificate': {
                'pem_data': self.cert_manager.get_ca_certificate_pem().decode(),
                'filename': 'hookprobe_ca.crt',
            },
        }

    def generate_universal_bundle(
        self,
        profile_name: str,
        user_identifier: str,
        cert_pem: bytes,
        encrypted_private_key: bytes,
        key_iv: bytes,
        device_name: str = "",
        route_all_traffic: bool = False,
        split_tunnel_routes: Optional[List[str]] = None,
        dns_servers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a universal bundle with all platform profiles.

        Returns a dict containing profiles for all supported platforms.

        Args:
            Same as generate_ios_profile

        Returns:
            Dict with profiles for each platform
        """
        return {
            'ios': {
                'data': self.generate_ios_profile(
                    profile_name, user_identifier, cert_pem,
                    encrypted_private_key, key_iv, device_name,
                    route_all_traffic, split_tunnel_routes, dns_servers
                ),
                'filename': f'hookprobe_vpn_{profile_name}.mobileconfig',
                'content_type': 'application/x-apple-aspen-config',
            },
            'android': self.generate_android_profile(
                profile_name, user_identifier, cert_pem,
                encrypted_private_key, key_iv, device_name,
                route_all_traffic, split_tunnel_routes, dns_servers
            ),
            'windows': self.generate_windows_profile(
                profile_name, user_identifier, cert_pem,
                encrypted_private_key, key_iv, device_name,
                route_all_traffic, split_tunnel_routes, dns_servers
            ),
        }


# Import for Windows profile generation
from cryptography.hazmat.primitives import serialization
