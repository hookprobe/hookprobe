"""
Hostname Decoder for dnsmasq DHCP

Decodes octal-escaped hostnames from dnsmasq DHCP Option 12.
dnsmasq escapes special characters (including UTF-8 sequences) as \\DDD.

Example:
    "Andrei\\032toma\\226\\128\\153s\\032library" -> "Andrei toma's library"
    "My\\032Device" -> "My Device"
"""

import re
from typing import Optional


def decode_dnsmasq_hostname(hostname: Optional[str]) -> Optional[str]:
    """
    Decode octal escapes in dnsmasq hostnames.

    dnsmasq uses octal escape sequences (\\DDD) for special characters,
    including spaces (\\032) and UTF-8 multi-byte sequences.

    Args:
        hostname: Raw hostname from DHCP (may contain \\DDD octal escapes)

    Returns:
        Decoded hostname, or original if no escapes found, or None if input is None
    """
    if not hostname:
        return hostname

    # Quick check - if no backslash, return as-is
    if '\\' not in hostname:
        return hostname

    try:
        # Replace octal escapes with actual bytes
        result = b''
        i = 0

        while i < len(hostname):
            if hostname[i] == '\\' and i + 3 < len(hostname):
                octal_str = hostname[i+1:i+4]

                # Check if all 3 chars are octal digits (0-7)
                if all(c in '01234567' for c in octal_str):
                    byte_value = int(octal_str, 8)
                    result += bytes([byte_value])
                    i += 4
                    continue

            # Regular character - encode to UTF-8 bytes
            result += hostname[i].encode('utf-8', errors='replace')
            i += 1

        # Decode UTF-8 bytes back to string
        decoded = result.decode('utf-8', errors='replace').strip()
        return decoded if decoded else hostname

    except Exception:
        # Fallback to original hostname on any error
        return hostname


def is_escaped_hostname(hostname: Optional[str]) -> bool:
    """
    Check if hostname contains dnsmasq octal escapes.

    Args:
        hostname: Hostname string to check

    Returns:
        True if hostname contains \\DDD patterns
    """
    if not hostname:
        return False
    return '\\' in hostname and bool(re.search(r'\\\d{3}', hostname))


def clean_device_name(hostname: Optional[str], max_length: int = 32) -> str:
    """
    Clean and simplify device name for display.

    1. Decodes dnsmasq octal escapes
    2. Detects UUID-like strings (returns "Unknown Device")
    3. Removes hex prefixes (e.g., "F6574fcbe4474hookprobepro" -> "hookprobepro")
    4. Removes hex suffixes with various separators (_XXXX, -XXXX, or space XXXX)
    5. Truncates to max_length if needed

    Args:
        hostname: Raw hostname from DHCP/mDNS
        max_length: Maximum display length (default 32)

    Returns:
        Cleaned, human-readable device name
    """
    if not hostname:
        return "Unknown Device"

    # First decode any octal escapes
    name = decode_dnsmasq_hostname(hostname)

    if not name:
        return "Unknown Device"

    # Remove ".local" suffix from mDNS names first
    if name.endswith('.local'):
        name = name[:-6]

    # Detect UUID-like strings: "9bd3d706 9e8d 47d9 81a4 90feb..." or "9bd3d706-9e8d-47d9-..."
    # These are not useful as device names
    if re.match(r'^[0-9a-fA-F]{8}[-_ ][0-9a-fA-F]{4}[-_ ][0-9a-fA-F]{4}', name):
        return "Unknown Device"

    # Remove hex prefixes (e.g., "F6574fcbe4474hookprobepro" -> "hookprobepro")
    hex_prefix_match = re.match(r'^[0-9a-fA-F]{8,}[-_]?(.+)$', name)
    if hex_prefix_match:
        remaining = hex_prefix_match.group(1)
        # Only use if remaining part looks like a real name (has letters)
        if re.search(r'[a-zA-Z]{3,}', remaining):
            name = remaining

    # Remove hex identifier suffixes like "_fcdc2e6bffd5_1", "-abc123", or " 40edcf82626b"
    # Pattern: underscore/dash/space followed by 6+ hex chars, optionally followed by more
    # IMPORTANT: Include space (\s) to catch "Hooksound 40edcf82626b" -> "Hooksound"
    name = re.sub(r'[\s_-][0-9a-fA-F]{6,}(?:[_-]\d+)?$', '', name)

    # Remove pure 12-char MAC addresses if that's the entire remaining name
    if re.match(r'^[0-9a-fA-F]{12}$', name):
        return "Unknown Device"

    # Clean up multiple spaces
    name = re.sub(r'\s+', ' ', name).strip()

    # Truncate if needed
    if len(name) > max_length:
        name = name[:max_length-3] + '...'

    return name if name else "Unknown Device"


def is_randomized_mac(mac: Optional[str]) -> bool:
    """
    Check if a MAC address is locally administered (randomized/privacy mode).

    Modern devices (iOS 14+, Android 10+, Windows 10+) use randomized MAC addresses
    for privacy. These have the "locally administered" bit set (bit 1 of first octet).

    Format detection:
    - xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
    - First octet bit 1 = 1 means locally administered (randomized)
    - Examples: 46:xx, 4a:xx, 56:xx, 5a:xx, 6a:xx, 7e:xx are randomized
    - Examples: 00:xx, 08:xx, AC:xx are real OUI (not randomized)

    Args:
        mac: MAC address string (any common format)

    Returns:
        True if MAC is randomized/locally administered, False otherwise
    """
    if not mac:
        return False

    # Normalize MAC format - remove separators and convert to uppercase
    mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').upper()

    # Validate length
    if len(mac_clean) != 12:
        return False

    # Check if it's valid hex
    try:
        first_octet = int(mac_clean[:2], 16)
    except ValueError:
        return False

    # Check bit 1 (locally administered bit)
    # If set, this is a locally administered address (often randomized)
    return bool(first_octet & 0x02)


def get_mac_type_label(mac: Optional[str]) -> str:
    """
    Get a human-readable label for the MAC address type.

    Args:
        mac: MAC address string

    Returns:
        "Private Address" for randomized MACs, "" for normal MACs, or "" if invalid
    """
    if is_randomized_mac(mac):
        return "Private Address"
    return ""


# For convenience - define exports
__all__ = [
    'decode_dnsmasq_hostname',
    'is_escaped_hostname',
    'clean_device_name',
    'is_randomized_mac',
    'get_mac_type_label'
]
