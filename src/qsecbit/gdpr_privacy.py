"""
GDPR Privacy Module for Qsecbit

Implements privacy-preserving data processing for Qsecbit analysis:
- IP address anonymization (GDPR Article 32)
- MAC address anonymization
- PII detection and masking
- Data minimization
- Pseudonymization

Author: HookProbe Team
License: MIT
Version: 5.0
"""

import hashlib
import ipaddress
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class AnonymizationMethod(Enum):
    """Anonymization methods for personal data"""
    MASK = "mask"           # Partial masking (e.g., 192.168.1.0)
    HASH = "hash"           # Cryptographic hash (irreversible)
    TRUNCATE = "truncate"   # Remove last part
    NONE = "none"           # No anonymization


@dataclass
class GDPRConfig:
    """GDPR configuration for privacy-preserving analysis"""
    # Master switches
    gdpr_enabled: bool = True
    strict_mode: bool = False

    # IP/MAC anonymization
    anonymize_ip: bool = True
    anonymize_ipv6: bool = True
    anonymize_mac: bool = True
    ip_method: AnonymizationMethod = AnonymizationMethod.MASK
    mac_method: AnonymizationMethod = AnonymizationMethod.MASK

    # Data minimization
    collect_full_payload: bool = False
    collect_packet_headers: bool = True
    anonymize_http_params: bool = True

    # Pseudonymization
    pseudonymize_user_ids: bool = False
    pseudonymization_salt: str = ""  # Set via environment variable

    # Retention
    retention_days: int = 90

    @classmethod
    def from_env(cls) -> 'GDPRConfig':
        """Load GDPR config from environment variables"""
        import os

        return cls(
            gdpr_enabled=os.getenv('GDPR_ENABLED', 'true').lower() == 'true',
            strict_mode=os.getenv('GDPR_STRICT_MODE', 'false').lower() == 'true',
            anonymize_ip=os.getenv('ANONYMIZE_IP_ADDRESSES', 'true').lower() == 'true',
            anonymize_ipv6=os.getenv('ANONYMIZE_IPV6_ADDRESSES', 'true').lower() == 'true',
            anonymize_mac=os.getenv('ANONYMIZE_MAC_ADDRESSES', 'true').lower() == 'true',
            ip_method=AnonymizationMethod(os.getenv('IP_ANONYMIZATION_METHOD', 'mask')),
            mac_method=AnonymizationMethod(os.getenv('MAC_ANONYMIZATION_METHOD', 'mask')),
            anonymize_http_params=os.getenv('ANONYMIZE_HTTP_QUERY_PARAMS', 'true').lower() == 'true',
            pseudonymize_user_ids=os.getenv('PSEUDONYMIZE_USER_IDS', 'false').lower() == 'true',
            pseudonymization_salt=os.getenv('PSEUDONYMIZATION_KEY', ''),
            retention_days=int(os.getenv('RETENTION_QSECBIT_SCORES_DAYS', '90')),
        )


class PrivacyPreserver:
    """Privacy-preserving data transformation for GDPR compliance"""

    def __init__(self, config: Optional[GDPRConfig] = None):
        self.config = config or GDPRConfig.from_env()

    def anonymize_ipv4(self, ip: str) -> str:
        """
        Anonymize IPv4 address according to GDPR requirements

        Examples:
            MASK: 192.168.1.123 -> 192.168.1.0
            HASH: 192.168.1.123 -> sha256(ip+salt)
            TRUNCATE: 192.168.1.123 -> 192.168.1
        """
        if not self.config.anonymize_ip or not self.config.gdpr_enabled:
            return ip

        try:
            # Validate IP
            ipaddress.IPv4Address(ip)

            method = self.config.ip_method

            if method == AnonymizationMethod.MASK:
                # Mask last octet: 192.168.1.123 -> 192.168.1.0
                parts = ip.split('.')
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0"

            elif method == AnonymizationMethod.HASH:
                # Cryptographic hash (irreversible)
                return self._hash_value(ip)

            elif method == AnonymizationMethod.TRUNCATE:
                # Keep only network portion
                parts = ip.split('.')
                return f"{parts[0]}.{parts[1]}.{parts[2]}"

            else:
                return ip

        except ValueError:
            # Invalid IP, return as-is
            return ip

    def anonymize_ipv6(self, ip: str) -> str:
        """
        Anonymize IPv6 address (GDPR requirement)

        Masks last 80 bits (keeps /48 prefix):
            2001:db8:1234:5678:9abc:def0:1234:5678 ->
            2001:db8:1234:0000:0000:0000:0000:0000
        """
        if not self.config.anonymize_ipv6 or not self.config.gdpr_enabled:
            return ip

        try:
            # Validate IPv6
            addr = ipaddress.IPv6Address(ip)

            method = self.config.ip_method

            if method == AnonymizationMethod.MASK:
                # Mask last 80 bits (keep /48 prefix)
                masked = int(addr) & (0xFFFFFFFF000000000000000000000000)
                return str(ipaddress.IPv6Address(masked))

            elif method == AnonymizationMethod.HASH:
                return self._hash_value(ip)

            else:
                return ip

        except ValueError:
            return ip

    def anonymize_ip(self, ip: str) -> str:
        """Auto-detect IP version and anonymize"""
        if ':' in ip:
            return self.anonymize_ipv6(ip)
        else:
            return self.anonymize_ipv4(ip)

    def anonymize_mac(self, mac: str) -> str:
        """
        Anonymize MAC address

        Examples:
            MASK: AA:BB:CC:11:22:33 -> AA:BB:CC:00:00:00 (keeps OUI)
            HASH: AA:BB:CC:11:22:33 -> sha256(mac+salt)
        """
        if not self.config.anonymize_mac or not self.config.gdpr_enabled:
            return mac

        method = self.config.mac_method

        if method == AnonymizationMethod.MASK:
            # Keep OUI (Organizationally Unique Identifier), mask device ID
            # AA:BB:CC:11:22:33 -> AA:BB:CC:00:00:00
            parts = mac.upper().replace('-', ':').split(':')
            if len(parts) == 6:
                return f"{parts[0]}:{parts[1]}:{parts[2]}:00:00:00"
            return mac

        elif method == AnonymizationMethod.HASH:
            return self._hash_value(mac)

        else:
            return mac

    def anonymize_url(self, url: str) -> str:
        """
        Remove query parameters from URL (may contain PII)

        Example:
            https://example.com/page?email=user@example.com&token=abc123
            -> https://example.com/page
        """
        if not self.config.anonymize_http_params or not self.config.gdpr_enabled:
            return url

        # Remove query parameters
        return url.split('?')[0]

    def pseudonymize_user_id(self, user_id: str) -> str:
        """
        Pseudonymize user ID (reversible with key)

        Uses HMAC-SHA256 for consistent pseudonyms
        """
        if not self.config.pseudonymize_user_ids or not self.config.gdpr_enabled:
            return user_id

        if not self.config.pseudonymization_salt:
            # No salt configured, return hashed version
            return hashlib.sha256(user_id.encode()).hexdigest()[:16]

        # HMAC for keyed pseudonymization
        import hmac
        return hmac.new(
            self.config.pseudonymization_salt.encode(),
            user_id.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

    def detect_pii(self, text: str) -> Dict[str, List[str]]:
        """
        Detect potential PII in text using regex patterns

        Returns:
            Dictionary with PII types and detected values
        """
        pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'phone': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
            'ssn': r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
            'credit_card': r'\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b',
        }

        detected: Dict[str, List[str]] = {}

        for pii_type, pattern in pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                detected[pii_type] = matches

        return detected

    def mask_pii(self, text: str) -> str:
        """
        Automatically mask detected PII in text

        Example:
            "Contact admin@example.com at 192.168.1.10"
            -> "Contact [EMAIL_MASKED] at [IP_MASKED]"
        """
        if not self.config.gdpr_enabled:
            return text

        # Mask emails
        text = re.sub(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            '[EMAIL_MASKED]',
            text
        )

        # Mask IPv4
        text = re.sub(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            lambda m: self.anonymize_ipv4(m.group(0)),
            text
        )

        # Mask phone numbers
        text = re.sub(
            r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
            '[PHONE_MASKED]',
            text
        )

        # Mask SSN
        text = re.sub(
            r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
            '[SSN_MASKED]',
            text
        )

        # Mask credit cards
        text = re.sub(
            r'\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b',
            '[CARD_MASKED]',
            text
        )

        return text

    def anonymize_network_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Anonymize network flow data for GDPR compliance

        Preserves security analysis capability while protecting privacy
        """
        if not self.config.gdpr_enabled:
            return flow

        anonymized = flow.copy()

        # Anonymize IP addresses
        if 'src_ip' in anonymized:
            anonymized['src_ip'] = self.anonymize_ip(anonymized['src_ip'])
        if 'dst_ip' in anonymized:
            anonymized['dst_ip'] = self.anonymize_ip(anonymized['dst_ip'])

        # Anonymize MAC addresses
        if 'src_mac' in anonymized:
            anonymized['src_mac'] = self.anonymize_mac(anonymized['src_mac'])
        if 'dst_mac' in anonymized:
            anonymized['dst_mac'] = self.anonymize_mac(anonymized['dst_mac'])

        # Anonymize URLs
        if 'url' in anonymized:
            anonymized['url'] = self.anonymize_url(anonymized['url'])
        if 'referer' in anonymized:
            anonymized['referer'] = self.anonymize_url(anonymized['referer'])

        # Remove payload data (privacy violation if collected)
        if 'payload' in anonymized:
            anonymized['payload'] = '[REMOVED_FOR_PRIVACY]'

        # Anonymize user agents (may contain unique identifiers)
        if self.config.strict_mode and 'user_agent' in anonymized:
            anonymized['user_agent'] = self._generalize_user_agent(
                anonymized['user_agent']
            )

        return anonymized

    def _hash_value(self, value: str) -> str:
        """Hash a value with optional salt"""
        if self.config.pseudonymization_salt:
            value_with_salt = value + self.config.pseudonymization_salt
        else:
            value_with_salt = value

        return hashlib.sha256(value_with_salt.encode()).hexdigest()[:16]

    def _generalize_user_agent(self, user_agent: str) -> str:
        """
        Generalize user agent to remove unique identifiers

        Example:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0"
            -> "Mozilla/5.0 (Windows) Chrome/119"
        """
        # Extract browser and major version
        browser_match = re.search(r'(Chrome|Firefox|Safari|Edge)/(\d+)', user_agent)
        if browser_match:
            browser, version = browser_match.groups()
            major_version = version.split('.')[0]
            return f"{browser}/{major_version}"

        # Extract OS
        if 'Windows' in user_agent:
            return "Mozilla/5.0 (Windows)"
        elif 'Mac' in user_agent:
            return "Mozilla/5.0 (Macintosh)"
        elif 'Linux' in user_agent:
            return "Mozilla/5.0 (Linux)"
        elif 'Android' in user_agent:
            return "Mozilla/5.0 (Android)"
        elif 'iOS' in user_agent:
            return "Mozilla/5.0 (iOS)"

        return "Mozilla/5.0 (Unknown)"

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal (RFC 1918, RFC 4193)"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    def should_anonymize(self, ip: str) -> bool:
        """
        Determine if IP should be anonymized

        Private IPs may not need anonymization (internal network)
        Public IPs always need anonymization under GDPR
        """
        if not self.config.gdpr_enabled:
            return False

        # In strict mode, anonymize everything
        if self.config.strict_mode:
            return True

        # Anonymize public IPs only
        return not self.is_private_ip(ip)


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

# Global instance
_privacy_preserver: Optional[PrivacyPreserver] = None


def get_privacy_preserver() -> PrivacyPreserver:
    """Get singleton privacy preserver instance"""
    global _privacy_preserver
    if _privacy_preserver is None:
        _privacy_preserver = PrivacyPreserver()
    return _privacy_preserver


def anonymize_ip(ip: str) -> str:
    """Convenience function to anonymize IP"""
    return get_privacy_preserver().anonymize_ip(ip)


def anonymize_mac(mac: str) -> str:
    """Convenience function to anonymize MAC"""
    return get_privacy_preserver().anonymize_mac(mac)


def anonymize_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to anonymize network flow"""
    return get_privacy_preserver().anonymize_network_flow(flow)


def mask_pii(text: str) -> str:
    """Convenience function to mask PII in text"""
    return get_privacy_preserver().mask_pii(text)


# ============================================================
# EXAMPLE USAGE
# ============================================================

if __name__ == "__main__":
    # Example usage
    preserver = PrivacyPreserver()

    # Test IP anonymization
    print("IP Anonymization:")
    print(f"  Original: 192.168.1.123")
    print(f"  Anonymized: {preserver.anonymize_ipv4('192.168.1.123')}")
    print()

    # Test MAC anonymization
    print("MAC Anonymization:")
    print(f"  Original: AA:BB:CC:11:22:33")
    print(f"  Anonymized: {preserver.anonymize_mac('AA:BB:CC:11:22:33')}")
    print()

    # Test URL anonymization
    print("URL Anonymization:")
    url = "https://example.com/search?q=user@email.com&token=abc123"
    print(f"  Original: {url}")
    print(f"  Anonymized: {preserver.anonymize_url(url)}")
    print()

    # Test PII detection
    print("PII Detection:")
    text = "Contact admin@example.com or call 555-123-4567"
    detected = preserver.detect_pii(text)
    print(f"  Original: {text}")
    print(f"  Detected: {detected}")
    print(f"  Masked: {preserver.mask_pii(text)}")
    print()

    # Test network flow anonymization
    print("Network Flow Anonymization:")
    flow = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_mac': 'AA:BB:CC:11:22:33',
        'url': 'https://example.com/page?user=john@doe.com',
        'payload': 'sensitive data here'
    }
    anonymized_flow = preserver.anonymize_network_flow(flow)
    print(f"  Original: {flow}")
    print(f"  Anonymized: {anonymized_flow}")
