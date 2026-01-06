"""
Security Utilities for Fortress Web

Provides helper functions for secure logging and error handling to address:
- CWE-532: Information Exposure Through Log Files
- CWE-209: Information Exposure Through an Error Message

These utilities help maintain operational visibility while protecting sensitive data.
"""

import re
from typing import Optional


def mask_mac(mac: str, show_prefix: bool = True, show_suffix: bool = True) -> str:
    """
    Mask a MAC address for secure logging (CWE-532 mitigation).

    For network device management, MAC addresses are needed for debugging
    but can be partially masked to reduce PII exposure in logs.

    Args:
        mac: MAC address to mask (e.g., "aa:bb:cc:dd:ee:ff")
        show_prefix: Show first 3 octets (vendor OUI)
        show_suffix: Show last octet (device identifier)

    Returns:
        Masked MAC like "aa:bb:cc:**:**:ff" or "**:**:**:**:**:ff"

    Examples:
        >>> mask_mac("aa:bb:cc:dd:ee:ff")
        'aa:bb:cc:**:**:ff'
        >>> mask_mac("aa:bb:cc:dd:ee:ff", show_prefix=False)
        '**:**:**:**:**:ff'
    """
    if not mac:
        return "**:**:**:**:**:**"

    # Normalize MAC format
    mac_clean = mac.upper().replace('-', ':')

    # Validate MAC format
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac_clean):
        return "**:**:**:**:**:**"

    parts = mac_clean.split(':')

    if show_prefix and show_suffix:
        # Show vendor OUI (first 3) and last octet: aa:bb:cc:**:**:ff
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:{parts[5]}"
    elif show_prefix:
        # Show only vendor OUI: aa:bb:cc:**:**:**
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:**"
    elif show_suffix:
        # Show only last octet: **:**:**:**:**:ff
        return f"**:**:**:**:**:{parts[5]}"
    else:
        return "**:**:**:**:**:**"


def mask_ip(ip: str) -> str:
    """
    Mask an IP address for secure logging (CWE-532 mitigation).

    Args:
        ip: IP address to mask

    Returns:
        Masked IP like "192.168.x.x" or "10.200.x.x"
    """
    if not ip:
        return "x.x.x.x"

    parts = ip.split('.')
    if len(parts) != 4:
        return "x.x.x.x"

    # Show network portion, mask host portion
    return f"{parts[0]}.{parts[1]}.x.x"


def safe_error_message(exception: Exception, include_type: bool = True) -> str:
    """
    Create a safe error message for API responses (CWE-209 mitigation).

    Prevents information exposure through error messages by:
    - Not including stack traces
    - Not including file paths
    - Not including internal implementation details

    Args:
        exception: The exception to process
        include_type: Whether to include the exception type name

    Returns:
        Sanitized error message safe for API responses
    """
    # Get the error message
    msg = str(exception) if exception else "An error occurred"

    # Remove potentially sensitive information
    # Remove file paths (Unix and Windows)
    msg = re.sub(r'(/[^\s:]+)+\.(py|sh|conf|json|yaml|yml)', '[path]', msg)
    msg = re.sub(r'[A-Za-z]:\\[^\s:]+', '[path]', msg)

    # Remove line numbers
    msg = re.sub(r'line \d+', 'line [N]', msg, flags=re.IGNORECASE)

    # Remove memory addresses
    msg = re.sub(r'0x[0-9a-fA-F]+', '[addr]', msg)

    # Remove stack trace indicators
    msg = re.sub(r'Traceback.*:', '', msg, flags=re.IGNORECASE | re.DOTALL)

    # Truncate long messages
    if len(msg) > 200:
        msg = msg[:197] + "..."

    if include_type and exception:
        return f"{type(exception).__name__}: {msg.strip()}"

    return msg.strip() or "An error occurred"


def sanitize_for_log(data: dict, sensitive_keys: Optional[set] = None) -> dict:
    """
    Sanitize a dictionary for logging by masking sensitive values.

    Args:
        data: Dictionary to sanitize
        sensitive_keys: Set of keys to mask (defaults to common sensitive keys)

    Returns:
        Sanitized copy of the dictionary
    """
    if sensitive_keys is None:
        sensitive_keys = {
            'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
            'auth', 'credential', 'private_key', 'privatekey', 'ssh_key',
            'wpa_passphrase', 'psk', 'ssid_password'
        }

    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            result[key] = '***REDACTED***'
        elif key_lower in ('mac', 'mac_address'):
            result[key] = mask_mac(str(value)) if value else value
        elif key_lower in ('ip', 'ip_address', 'ipaddr'):
            result[key] = mask_ip(str(value)) if value else value
        elif isinstance(value, dict):
            result[key] = sanitize_for_log(value, sensitive_keys)
        else:
            result[key] = value

    return result
