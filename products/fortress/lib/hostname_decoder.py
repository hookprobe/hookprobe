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
    2. Removes common suffixes (_XXXX hex identifiers)
    3. Truncates to max_length if needed

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

    # Remove hex identifier suffixes like "_fcdc2e6bffd5_1" or "-abc123"
    # Pattern: underscore/dash followed by 6+ hex chars, optionally followed by more
    name = re.sub(r'[_-][0-9a-fA-F]{6,}(?:[_-]\d+)?$', '', name)

    # Remove ".local" suffix from mDNS names
    if name.endswith('.local'):
        name = name[:-6]

    # Clean up multiple spaces
    name = re.sub(r'\s+', ' ', name).strip()

    # Truncate if needed
    if len(name) > max_length:
        name = name[:max_length-3] + '...'

    return name if name else "Unknown Device"


# For convenience - define exports
__all__ = ['decode_dnsmasq_hostname', 'is_escaped_hostname', 'clean_device_name']
