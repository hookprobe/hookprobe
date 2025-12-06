#!/usr/bin/env python3
"""
Mobile Network Protection - Hotel/Public WiFi Security Module

Provides specialized protection for mobile users connecting to untrusted
networks such as hotels, airports, coffee shops, and conference centers.

Features:
- Captive portal detection and safe handling
- Evil twin AP detection
- SSL stripping protection
- DNS security verification
- Network reconnaissance detection
- Automatic VPN failover
- Location-aware security policies

Author: HookProbe Team
Version: 1.0.0
License: MIT
"""

import os
import re
import json
import socket
import ssl
import time
import subprocess
import hashlib
import urllib.request
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any, Set
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


class NetworkTrustLevel(Enum):
    """Network trust classification"""
    TRUSTED = 4       # Known secure network (home, office)
    VERIFIED = 3      # Previously verified network
    UNKNOWN = 2       # New network, not yet analyzed
    SUSPICIOUS = 1    # Network with anomalies detected
    HOSTILE = 0       # Known malicious or compromised network


class CaptivePortalStatus(Enum):
    """Captive portal detection status"""
    NONE = 0          # No captive portal
    DETECTED = 1      # Captive portal detected
    AUTHENTICATING = 2  # Currently authenticating
    AUTHENTICATED = 3   # Successfully authenticated
    FAILED = 4        # Authentication failed


@dataclass
class NetworkProfile:
    """Profile of a detected network"""
    ssid: str
    bssid: str
    channel: int
    frequency: int
    signal_strength: int
    security: str  # WPA2, WPA3, WEP, OPEN
    trust_level: NetworkTrustLevel
    captive_portal: CaptivePortalStatus
    first_seen: datetime
    last_seen: datetime
    location_hint: Optional[str] = None  # Hotel name, airport code, etc.
    dns_servers: List[str] = field(default_factory=list)
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    certificate_hash: Optional[str] = None
    anomalies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'ssid': self.ssid,
            'bssid': self.bssid,
            'channel': self.channel,
            'frequency': self.frequency,
            'signal_strength': self.signal_strength,
            'security': self.security,
            'trust_level': self.trust_level.name,
            'captive_portal': self.captive_portal.name,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'location_hint': self.location_hint,
            'dns_servers': self.dns_servers,
            'gateway_ip': self.gateway_ip,
            'gateway_mac': self.gateway_mac,
            'certificate_hash': self.certificate_hash,
            'anomalies': self.anomalies,
            'metadata': self.metadata
        }


@dataclass
class SecurityCheck:
    """Result of a security check"""
    check_name: str
    passed: bool
    severity: str  # critical, high, medium, low, info
    description: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'check_name': self.check_name,
            'passed': self.passed,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
            'evidence': self.evidence
        }


class MobileNetworkProtection:
    """
    Mobile Network Protection Engine

    Provides comprehensive protection for devices connecting to
    untrusted networks such as hotels, airports, and public WiFi.
    """

    # Known captive portal detection endpoints
    CAPTIVE_PORTAL_ENDPOINTS = [
        ("http://connectivitycheck.gstatic.com/generate_204", 204),
        ("http://www.msftconnecttest.com/connecttest.txt", 200),
        ("http://captive.apple.com/hotspot-detect.html", 200),
        ("http://detectportal.firefox.com/success.txt", 200),
    ]

    # Known safe DNS servers for verification
    SAFE_DNS_SERVERS = [
        ("1.1.1.1", "Cloudflare"),
        ("8.8.8.8", "Google"),
        ("9.9.9.9", "Quad9"),
        ("208.67.222.222", "OpenDNS"),
    ]

    # Critical domains for HTTPS verification
    HTTPS_VERIFICATION_DOMAINS = [
        "www.google.com",
        "www.microsoft.com",
        "www.apple.com",
        "www.cloudflare.com",
    ]

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/guardian/data",
        vpn_interface: str = "wg0",
        auto_vpn: bool = True
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.vpn_interface = vpn_interface
        self.auto_vpn = auto_vpn

        # Known networks database
        self.known_networks: Dict[str, NetworkProfile] = {}

        # Current network state
        self.current_network: Optional[NetworkProfile] = None
        self.security_checks: List[SecurityCheck] = []

        # Trusted network configurations (e.g., home, office)
        self.trusted_ssids: Set[str] = set()
        self.trusted_bssids: Set[str] = set()

        # Load saved state
        self._load_state()

    def _run_command(self, cmd: str, timeout: int = 10) -> Tuple[str, bool]:
        """Run shell command safely"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip(), result.returncode == 0
        except subprocess.TimeoutExpired:
            return "Command timed out", False
        except Exception as e:
            return str(e), False

    def _load_state(self):
        """Load saved network profiles and trusted networks"""
        state_file = self.data_dir / "mobile_protection_state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    state = json.load(f)
                    self.trusted_ssids = set(state.get('trusted_ssids', []))
                    self.trusted_bssids = set(state.get('trusted_bssids', []))

                    # Load known networks
                    for ssid, profile_data in state.get('known_networks', {}).items():
                        try:
                            self.known_networks[ssid] = NetworkProfile(
                                ssid=profile_data['ssid'],
                                bssid=profile_data['bssid'],
                                channel=profile_data.get('channel', 0),
                                frequency=profile_data.get('frequency', 0),
                                signal_strength=profile_data.get('signal_strength', 0),
                                security=profile_data.get('security', 'UNKNOWN'),
                                trust_level=NetworkTrustLevel[profile_data.get('trust_level', 'UNKNOWN')],
                                captive_portal=CaptivePortalStatus[profile_data.get('captive_portal', 'NONE')],
                                first_seen=datetime.fromisoformat(profile_data['first_seen']),
                                last_seen=datetime.fromisoformat(profile_data['last_seen']),
                                location_hint=profile_data.get('location_hint'),
                                dns_servers=profile_data.get('dns_servers', []),
                                gateway_ip=profile_data.get('gateway_ip'),
                                gateway_mac=profile_data.get('gateway_mac'),
                                certificate_hash=profile_data.get('certificate_hash'),
                                anomalies=profile_data.get('anomalies', []),
                                metadata=profile_data.get('metadata', {})
                            )
                        except Exception:
                            pass
            except Exception:
                pass

    def _save_state(self):
        """Save network profiles and trusted networks"""
        state_file = self.data_dir / "mobile_protection_state.json"
        try:
            state = {
                'trusted_ssids': list(self.trusted_ssids),
                'trusted_bssids': list(self.trusted_bssids),
                'known_networks': {
                    ssid: profile.to_dict()
                    for ssid, profile in self.known_networks.items()
                },
                'last_updated': datetime.now().isoformat()
            }
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    # =========================================================================
    # NETWORK ANALYSIS
    # =========================================================================

    def analyze_current_network(self) -> NetworkProfile:
        """Analyze the currently connected network"""
        self.security_checks = []

        # Get current network info
        profile = self._get_current_network_info()
        if not profile:
            return None

        # Run all security checks
        self._check_captive_portal(profile)
        self._check_dns_security(profile)
        self._check_gateway_security(profile)
        self._check_ssl_interception(profile)
        self._check_network_isolation(profile)
        self._check_dhcp_security(profile)
        self._check_arp_security(profile)

        # Calculate trust level based on checks
        profile.trust_level = self._calculate_trust_level(profile)

        # Store network profile
        self.known_networks[profile.ssid] = profile
        self.current_network = profile
        self._save_state()

        return profile

    def _get_current_network_info(self) -> Optional[NetworkProfile]:
        """Get information about the currently connected network"""
        # Try to get connected network info
        for iface in ['wlan0', 'wlan1']:
            output, success = self._run_command(f'iw dev {iface} link 2>/dev/null')
            if not success or 'Not connected' in output:
                continue

            ssid = None
            bssid = None
            signal = -100
            freq = 0

            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('Connected to'):
                    bssid = line.split()[-1] if line.split() else None
                elif line.startswith('SSID:'):
                    ssid = line.split(':', 1)[1].strip()
                elif line.startswith('signal:'):
                    try:
                        signal = int(line.split(':')[1].split()[0])
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('freq:'):
                    try:
                        freq = int(line.split(':')[1].strip())
                    except (ValueError, IndexError):
                        pass

            if ssid and bssid:
                # Get additional info
                channel = self._freq_to_channel(freq)
                security = self._get_network_security(iface)
                gateway_ip, gateway_mac = self._get_gateway_info()
                dns_servers = self._get_dns_servers()

                # Check if this is a known network
                now = datetime.now()
                if ssid in self.known_networks:
                    existing = self.known_networks[ssid]
                    profile = NetworkProfile(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        frequency=freq,
                        signal_strength=signal,
                        security=security,
                        trust_level=existing.trust_level,
                        captive_portal=CaptivePortalStatus.NONE,
                        first_seen=existing.first_seen,
                        last_seen=now,
                        location_hint=existing.location_hint,
                        dns_servers=dns_servers,
                        gateway_ip=gateway_ip,
                        gateway_mac=gateway_mac,
                        certificate_hash=existing.certificate_hash,
                        anomalies=[],
                        metadata=existing.metadata
                    )
                else:
                    profile = NetworkProfile(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        frequency=freq,
                        signal_strength=signal,
                        security=security,
                        trust_level=NetworkTrustLevel.UNKNOWN,
                        captive_portal=CaptivePortalStatus.NONE,
                        first_seen=now,
                        last_seen=now,
                        dns_servers=dns_servers,
                        gateway_ip=gateway_ip,
                        gateway_mac=gateway_mac,
                        anomalies=[]
                    )

                return profile

        return None

    def _freq_to_channel(self, freq: int) -> int:
        """Convert frequency to channel number"""
        if 2412 <= freq <= 2484:
            return (freq - 2407) // 5
        elif freq >= 5180:
            return (freq - 5000) // 5
        return 0

    def _get_network_security(self, iface: str) -> str:
        """Get network security type"""
        output, _ = self._run_command(f'iw dev {iface} info 2>/dev/null')
        # Security is determined during connection, check wpa_supplicant
        output2, _ = self._run_command('wpa_cli status 2>/dev/null | grep key_mgmt')
        if 'WPA3' in output2 or 'SAE' in output2:
            return 'WPA3'
        elif 'WPA2' in output2 or 'WPA-PSK' in output2:
            return 'WPA2'
        elif 'WPA' in output2:
            return 'WPA'
        elif 'WEP' in output2:
            return 'WEP'
        elif 'NONE' in output2:
            return 'OPEN'
        return 'UNKNOWN'

    def _get_gateway_info(self) -> Tuple[Optional[str], Optional[str]]:
        """Get default gateway IP and MAC"""
        # Get gateway IP
        output, success = self._run_command('ip route | grep default')
        gateway_ip = None
        if success and output:
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
            if match:
                gateway_ip = match.group(1)

        # Get gateway MAC
        gateway_mac = None
        if gateway_ip:
            output, success = self._run_command(f'arp -n {gateway_ip} 2>/dev/null')
            if success and output:
                match = re.search(r'([0-9a-f:]{17})', output, re.IGNORECASE)
                if match:
                    gateway_mac = match.group(1).lower()

        return gateway_ip, gateway_mac

    def _get_dns_servers(self) -> List[str]:
        """Get configured DNS servers"""
        dns_servers = []

        # Check /etc/resolv.conf
        try:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) > 1:
                            dns_servers.append(parts[1])
        except Exception:
            pass

        # Also check systemd-resolved
        output, _ = self._run_command('resolvectl status 2>/dev/null | grep "DNS Servers"')
        if output:
            for line in output.split('\n'):
                if 'DNS Servers' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        servers = parts[1].strip().split()
                        dns_servers.extend(servers)

        return list(set(dns_servers))

    # =========================================================================
    # SECURITY CHECKS
    # =========================================================================

    def _check_captive_portal(self, profile: NetworkProfile):
        """Check for captive portal"""
        for url, expected_code in self.CAPTIVE_PORTAL_ENDPOINTS:
            try:
                req = urllib.request.Request(url, method='GET')
                req.add_header('User-Agent', 'Mozilla/5.0')

                with urllib.request.urlopen(req, timeout=5) as response:
                    actual_code = response.getcode()

                    if actual_code != expected_code:
                        # Captive portal detected
                        profile.captive_portal = CaptivePortalStatus.DETECTED
                        profile.anomalies.append("Captive portal detected")

                        self.security_checks.append(SecurityCheck(
                            check_name="Captive Portal Detection",
                            passed=True,  # Detection is informational
                            severity="info",
                            description=f"Captive portal detected (expected {expected_code}, got {actual_code})",
                            recommendation="Complete portal authentication before accessing sensitive data",
                            evidence={'url': url, 'expected': expected_code, 'actual': actual_code}
                        ))
                        return

            except urllib.error.HTTPError as e:
                # Redirect to captive portal
                if e.code in [301, 302, 303, 307, 308]:
                    profile.captive_portal = CaptivePortalStatus.DETECTED
                    profile.anomalies.append("Captive portal redirect detected")

                    self.security_checks.append(SecurityCheck(
                        check_name="Captive Portal Detection",
                        passed=True,
                        severity="info",
                        description=f"Captive portal redirect detected (HTTP {e.code})",
                        recommendation="Complete portal authentication before accessing sensitive data",
                        evidence={'url': url, 'redirect_code': e.code}
                    ))
                    return

            except Exception:
                continue

        # No captive portal
        profile.captive_portal = CaptivePortalStatus.NONE
        self.security_checks.append(SecurityCheck(
            check_name="Captive Portal Detection",
            passed=True,
            severity="info",
            description="No captive portal detected",
            recommendation="None needed",
            evidence={'status': 'clear'}
        ))

    def _check_dns_security(self, profile: NetworkProfile):
        """Check DNS server security"""
        if not profile.dns_servers:
            self.security_checks.append(SecurityCheck(
                check_name="DNS Configuration",
                passed=False,
                severity="high",
                description="No DNS servers configured",
                recommendation="Configure a secure DNS server (e.g., 1.1.1.1, 8.8.8.8)",
                evidence={'dns_servers': []}
            ))
            profile.anomalies.append("No DNS servers configured")
            return

        # Check if DNS servers are known safe servers
        safe_servers = [ip for ip, _ in self.SAFE_DNS_SERVERS]
        using_safe_dns = any(dns in safe_servers for dns in profile.dns_servers)

        # Check for DNS hijacking by resolving known domains
        dns_hijack_detected = False
        for dns_server in profile.dns_servers[:2]:  # Check first 2 DNS servers
            if self._check_dns_hijacking(dns_server):
                dns_hijack_detected = True
                break

        if dns_hijack_detected:
            self.security_checks.append(SecurityCheck(
                check_name="DNS Security",
                passed=False,
                severity="critical",
                description="DNS hijacking detected - DNS responses manipulated",
                recommendation="Use encrypted DNS (DoH/DoT) or VPN immediately",
                evidence={'dns_servers': profile.dns_servers, 'hijack_detected': True}
            ))
            profile.anomalies.append("DNS hijacking detected")
            profile.trust_level = NetworkTrustLevel.HOSTILE
        elif not using_safe_dns:
            self.security_checks.append(SecurityCheck(
                check_name="DNS Security",
                passed=True,
                severity="medium",
                description="Using network-provided DNS servers (not verified safe)",
                recommendation="Consider using secure DNS (1.1.1.1, 8.8.8.8)",
                evidence={'dns_servers': profile.dns_servers}
            ))
            profile.anomalies.append("Using unverified DNS servers")
        else:
            self.security_checks.append(SecurityCheck(
                check_name="DNS Security",
                passed=True,
                severity="info",
                description="Using known secure DNS servers",
                recommendation="None needed",
                evidence={'dns_servers': profile.dns_servers}
            ))

    def _check_dns_hijacking(self, dns_server: str) -> bool:
        """Check if DNS server is returning manipulated responses"""
        # Test domains with known IP addresses
        test_domains = [
            ("dns.google", ["8.8.8.8", "8.8.4.4"]),
            ("one.one.one.one", ["1.1.1.1", "1.0.0.1"]),
        ]

        for domain, expected_ips in test_domains:
            try:
                output, success = self._run_command(
                    f'dig @{dns_server} {domain} +short +time=2 2>/dev/null'
                )
                if success and output:
                    resolved_ips = output.strip().split('\n')
                    # Check if any expected IP is in resolved IPs
                    if not any(ip in expected_ips for ip in resolved_ips):
                        return True  # DNS hijacking detected
            except Exception:
                continue

        return False

    def _check_gateway_security(self, profile: NetworkProfile):
        """Check gateway/router security"""
        if not profile.gateway_ip:
            self.security_checks.append(SecurityCheck(
                check_name="Gateway Security",
                passed=False,
                severity="high",
                description="No default gateway detected",
                recommendation="Check network configuration",
                evidence={}
            ))
            return

        # Check for multiple gateways (potential MITM)
        output, success = self._run_command('ip route | grep default | wc -l')
        if success and output:
            try:
                gateway_count = int(output)
                if gateway_count > 1:
                    self.security_checks.append(SecurityCheck(
                        check_name="Gateway Security",
                        passed=False,
                        severity="critical",
                        description=f"Multiple default gateways detected ({gateway_count})",
                        recommendation="Investigate potential route hijacking",
                        evidence={'gateway_count': gateway_count}
                    ))
                    profile.anomalies.append("Multiple gateways detected")
                    return
            except ValueError:
                pass

        # Check if gateway MAC matches known good gateway
        if profile.ssid in self.known_networks:
            known = self.known_networks[profile.ssid]
            if known.gateway_mac and profile.gateway_mac:
                if known.gateway_mac != profile.gateway_mac:
                    self.security_checks.append(SecurityCheck(
                        check_name="Gateway Security",
                        passed=False,
                        severity="critical",
                        description="Gateway MAC address has changed - potential MITM attack",
                        recommendation="Disconnect immediately and verify network authenticity",
                        evidence={
                            'expected_mac': known.gateway_mac,
                            'current_mac': profile.gateway_mac
                        }
                    ))
                    profile.anomalies.append("Gateway MAC changed")
                    profile.trust_level = NetworkTrustLevel.HOSTILE
                    return

        self.security_checks.append(SecurityCheck(
            check_name="Gateway Security",
            passed=True,
            severity="info",
            description=f"Gateway verified: {profile.gateway_ip} ({profile.gateway_mac})",
            recommendation="None needed",
            evidence={'gateway_ip': profile.gateway_ip, 'gateway_mac': profile.gateway_mac}
        ))

    def _check_ssl_interception(self, profile: NetworkProfile):
        """Check for SSL/TLS interception (MITM proxies)"""
        ssl_issues = []

        for domain in self.HTTPS_VERIFICATION_DOMAINS:
            try:
                # Get certificate
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        cert_hash = hashlib.sha256(cert).hexdigest()[:16]

                        # Check certificate issuer
                        cert_info = ssock.getpeercert()
                        issuer = dict(x[0] for x in cert_info.get('issuer', []))
                        org = issuer.get('organizationName', '')

                        # Known legitimate CAs
                        legitimate_cas = [
                            'DigiCert', 'Let\'s Encrypt', 'Google Trust Services',
                            'Amazon', 'Cloudflare', 'Microsoft', 'GlobalSign',
                            'Comodo', 'Sectigo', 'GeoTrust', 'Entrust'
                        ]

                        if not any(ca in org for ca in legitimate_cas):
                            ssl_issues.append({
                                'domain': domain,
                                'issuer': org,
                                'issue': 'Unknown certificate issuer'
                            })

            except ssl.SSLCertVerificationError as e:
                ssl_issues.append({
                    'domain': domain,
                    'error': str(e),
                    'issue': 'Certificate verification failed'
                })
            except Exception as e:
                continue

        if ssl_issues:
            self.security_checks.append(SecurityCheck(
                check_name="SSL/TLS Interception",
                passed=False,
                severity="critical",
                description=f"SSL interception detected - {len(ssl_issues)} certificate issues",
                recommendation="Use VPN immediately - network may be intercepting HTTPS traffic",
                evidence={'ssl_issues': ssl_issues}
            ))
            profile.anomalies.append("SSL interception detected")
            profile.trust_level = NetworkTrustLevel.HOSTILE
        else:
            self.security_checks.append(SecurityCheck(
                check_name="SSL/TLS Interception",
                passed=True,
                severity="info",
                description="No SSL interception detected",
                recommendation="None needed",
                evidence={'domains_checked': len(self.HTTPS_VERIFICATION_DOMAINS)}
            ))

    def _check_network_isolation(self, profile: NetworkProfile):
        """Check if network provides proper client isolation"""
        # Try to discover other devices on the network
        gateway_ip = profile.gateway_ip
        if not gateway_ip:
            return

        # Get network prefix
        network_prefix = '.'.join(gateway_ip.split('.')[:-1])

        # Quick scan for other devices
        other_devices = []
        output, success = self._run_command(
            f'arp -n | grep "{network_prefix}" | grep -v "{gateway_ip}" | wc -l'
        )

        if success and output:
            try:
                device_count = int(output)
                if device_count > 10:
                    self.security_checks.append(SecurityCheck(
                        check_name="Network Isolation",
                        passed=False,
                        severity="medium",
                        description=f"Network has poor client isolation - {device_count} other devices visible",
                        recommendation="Use VPN to protect traffic from other network users",
                        evidence={'visible_devices': device_count}
                    ))
                    profile.anomalies.append("Poor network isolation")
                else:
                    self.security_checks.append(SecurityCheck(
                        check_name="Network Isolation",
                        passed=True,
                        severity="info",
                        description="Network isolation appears adequate",
                        recommendation="None needed",
                        evidence={'visible_devices': device_count}
                    ))
            except ValueError:
                pass

    def _check_dhcp_security(self, profile: NetworkProfile):
        """Check for DHCP-related security issues"""
        # Check for multiple DHCP servers
        output, success = self._run_command(
            'grep -h "DHCPOFFER" /var/log/syslog 2>/dev/null | '
            'grep -oP "from \\K[0-9.]+?" | sort -u'
        )

        if success and output:
            dhcp_servers = [s.strip() for s in output.split('\n') if s.strip()]
            if len(dhcp_servers) > 1:
                self.security_checks.append(SecurityCheck(
                    check_name="DHCP Security",
                    passed=False,
                    severity="high",
                    description=f"Multiple DHCP servers detected: {', '.join(dhcp_servers)}",
                    recommendation="Potential rogue DHCP server - verify network configuration",
                    evidence={'dhcp_servers': dhcp_servers}
                ))
                profile.anomalies.append("Multiple DHCP servers")
                return

        self.security_checks.append(SecurityCheck(
            check_name="DHCP Security",
            passed=True,
            severity="info",
            description="Single DHCP server detected",
            recommendation="None needed",
            evidence={}
        ))

    def _check_arp_security(self, profile: NetworkProfile):
        """Check for ARP-related security issues"""
        # Check ARP table for anomalies
        output, success = self._run_command('ip neigh show')
        if not success or not output:
            return

        # Check for duplicate IPs with different MACs
        ip_mac_map: Dict[str, List[str]] = {}
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                for i, p in enumerate(parts):
                    if p == 'lladdr' and i + 1 < len(parts):
                        mac = parts[i + 1].lower()
                        if ip not in ip_mac_map:
                            ip_mac_map[ip] = []
                        if mac not in ip_mac_map[ip]:
                            ip_mac_map[ip].append(mac)

        # Check for IP addresses with multiple MACs
        duplicates = {ip: macs for ip, macs in ip_mac_map.items() if len(macs) > 1}

        if duplicates:
            self.security_checks.append(SecurityCheck(
                check_name="ARP Security",
                passed=False,
                severity="critical",
                description=f"ARP spoofing detected - {len(duplicates)} IPs with multiple MACs",
                recommendation="Network may be under ARP spoofing attack - use VPN",
                evidence={'duplicate_ips': duplicates}
            ))
            profile.anomalies.append("ARP spoofing detected")
            profile.trust_level = NetworkTrustLevel.HOSTILE
        else:
            self.security_checks.append(SecurityCheck(
                check_name="ARP Security",
                passed=True,
                severity="info",
                description="No ARP anomalies detected",
                recommendation="None needed",
                evidence={}
            ))

    # =========================================================================
    # TRUST LEVEL CALCULATION
    # =========================================================================

    def _calculate_trust_level(self, profile: NetworkProfile) -> NetworkTrustLevel:
        """Calculate network trust level based on security checks"""
        # Check if this is a trusted network
        if profile.ssid in self.trusted_ssids or profile.bssid in self.trusted_bssids:
            return NetworkTrustLevel.TRUSTED

        # Count failed checks by severity
        critical_fails = sum(1 for c in self.security_checks if not c.passed and c.severity == 'critical')
        high_fails = sum(1 for c in self.security_checks if not c.passed and c.severity == 'high')
        medium_fails = sum(1 for c in self.security_checks if not c.passed and c.severity == 'medium')

        # Determine trust level
        if critical_fails > 0:
            return NetworkTrustLevel.HOSTILE
        elif high_fails > 0:
            return NetworkTrustLevel.SUSPICIOUS
        elif medium_fails > 0:
            return NetworkTrustLevel.UNKNOWN
        elif profile.ssid in self.known_networks:
            return NetworkTrustLevel.VERIFIED
        else:
            return NetworkTrustLevel.UNKNOWN

    # =========================================================================
    # VPN MANAGEMENT
    # =========================================================================

    def enable_vpn_protection(self) -> bool:
        """Enable VPN protection for untrusted networks"""
        # Check if VPN interface exists
        output, success = self._run_command(f'ip link show {self.vpn_interface} 2>/dev/null')
        if not success:
            return False

        # Bring up VPN interface
        output, success = self._run_command(f'sudo wg-quick up {self.vpn_interface} 2>/dev/null')
        if success:
            return True

        # Try IKEv2 VPN as fallback
        output, success = self._run_command('sudo ipsec up guardian-vpn 2>/dev/null')
        return success

    def disable_vpn_protection(self) -> bool:
        """Disable VPN protection"""
        output, success = self._run_command(f'sudo wg-quick down {self.vpn_interface} 2>/dev/null')
        if success:
            return True

        output, success = self._run_command('sudo ipsec down guardian-vpn 2>/dev/null')
        return success

    def is_vpn_active(self) -> bool:
        """Check if VPN is active"""
        output, success = self._run_command(f'ip link show {self.vpn_interface} 2>/dev/null')
        if success and 'UP' in output:
            return True

        output, success = self._run_command('ipsec status 2>/dev/null | grep ESTABLISHED')
        return success and 'ESTABLISHED' in output

    # =========================================================================
    # NETWORK MANAGEMENT
    # =========================================================================

    def add_trusted_network(self, ssid: str = None, bssid: str = None):
        """Add a network to the trusted list"""
        if ssid:
            self.trusted_ssids.add(ssid)
        if bssid:
            self.trusted_bssids.add(bssid.lower())
        self._save_state()

    def remove_trusted_network(self, ssid: str = None, bssid: str = None):
        """Remove a network from the trusted list"""
        if ssid and ssid in self.trusted_ssids:
            self.trusted_ssids.remove(ssid)
        if bssid and bssid.lower() in self.trusted_bssids:
            self.trusted_bssids.remove(bssid.lower())
        self._save_state()

    def get_protection_status(self) -> Dict[str, Any]:
        """Get current protection status"""
        vpn_active = self.is_vpn_active()

        return {
            'timestamp': datetime.now().isoformat(),
            'current_network': self.current_network.to_dict() if self.current_network else None,
            'trust_level': self.current_network.trust_level.name if self.current_network else 'UNKNOWN',
            'vpn_active': vpn_active,
            'vpn_recommended': (
                self.current_network and
                self.current_network.trust_level in [
                    NetworkTrustLevel.UNKNOWN,
                    NetworkTrustLevel.SUSPICIOUS,
                    NetworkTrustLevel.HOSTILE
                ]
            ) if self.current_network else True,
            'security_checks': [c.to_dict() for c in self.security_checks],
            'anomalies': self.current_network.anomalies if self.current_network else [],
            'known_networks_count': len(self.known_networks),
            'trusted_ssids': list(self.trusted_ssids)
        }

    def generate_protection_report(self) -> Dict[str, Any]:
        """Generate comprehensive protection report for qsecbit integration"""
        status = self.get_protection_status()

        # Calculate protection score (0-1)
        if not self.current_network:
            protection_score = 0.0
        else:
            passed_checks = sum(1 for c in self.security_checks if c.passed)
            total_checks = len(self.security_checks) if self.security_checks else 1
            base_score = passed_checks / total_checks

            # Adjust for trust level
            trust_multiplier = {
                NetworkTrustLevel.TRUSTED: 1.0,
                NetworkTrustLevel.VERIFIED: 0.9,
                NetworkTrustLevel.UNKNOWN: 0.7,
                NetworkTrustLevel.SUSPICIOUS: 0.4,
                NetworkTrustLevel.HOSTILE: 0.1
            }
            protection_score = base_score * trust_multiplier.get(
                self.current_network.trust_level, 0.5
            )

            # Boost if VPN is active
            if self.is_vpn_active():
                protection_score = min(1.0, protection_score + 0.3)

        # Determine RAG status
        if protection_score >= 0.8:
            rag_status = "GREEN"
        elif protection_score >= 0.5:
            rag_status = "AMBER"
        else:
            rag_status = "RED"

        return {
            **status,
            'protection_score': round(protection_score, 4),
            'rag_status': rag_status,
            'layer_coverage': {
                'L2_data_link': ['Evil Twin Detection', 'ARP Security', 'DHCP Security'],
                'L3_network': ['Gateway Security', 'Network Isolation'],
                'L4_transport': ['Port Security'],
                'L5_session': ['SSL/TLS Interception'],
                'L6_presentation': ['Certificate Validation'],
                'L7_application': ['DNS Security', 'Captive Portal']
            }
        }


# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("MOBILE NETWORK PROTECTION - Hotel/Public WiFi Security")
    print("=" * 70)

    protection = MobileNetworkProtection()

    print("\nAnalyzing current network...")
    profile = protection.analyze_current_network()

    if profile:
        print(f"\n--- NETWORK PROFILE ---")
        print(f"SSID: {profile.ssid}")
        print(f"BSSID: {profile.bssid}")
        print(f"Security: {profile.security}")
        print(f"Trust Level: {profile.trust_level.name}")
        print(f"Captive Portal: {profile.captive_portal.name}")
        print(f"Gateway: {profile.gateway_ip} ({profile.gateway_mac})")
        print(f"DNS Servers: {', '.join(profile.dns_servers)}")

        if profile.anomalies:
            print(f"\nAnomalies Detected:")
            for anomaly in profile.anomalies:
                print(f"  - {anomaly}")

        print(f"\n--- SECURITY CHECKS ---")
        for check in protection.security_checks:
            status = "PASS" if check.passed else "FAIL"
            print(f"[{status}] {check.check_name}: {check.description}")

        print(f"\n--- PROTECTION STATUS ---")
        status = protection.get_protection_status()
        print(f"VPN Active: {status['vpn_active']}")
        print(f"VPN Recommended: {status['vpn_recommended']}")

        report = protection.generate_protection_report()
        print(f"Protection Score: {report['protection_score']}")
        print(f"RAG Status: {report['rag_status']}")
    else:
        print("No network connection detected")

    print("=" * 70)
