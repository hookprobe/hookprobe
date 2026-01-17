"""
Security Utilities for MSSP Web Apps

Provides helper functions for secure logging to address:
- CWE-532: Information Exposure Through Log Files
- CWE-209: Information Exposure Through an Error Message
"""

import re


def mask_mac(mac: str, show_prefix: bool = True, show_suffix: bool = True) -> str:
    """
    Mask a MAC address for secure logging (CWE-532 mitigation).

    Args:
        mac: MAC address to mask (e.g., "aa:bb:cc:dd:ee:ff")
        show_prefix: Show first 3 octets (vendor OUI)
        show_suffix: Show last octet (device identifier)

    Returns:
        Masked MAC like "aa:bb:cc:**:**:ff"
    """
    if not mac:
        return "**:**:**:**:**:**"

    mac_clean = mac.upper().replace('-', ':')

    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac_clean):
        return "**:**:**:**:**:**"

    parts = mac_clean.split(':')

    if show_prefix and show_suffix:
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:{parts[5]}"
    elif show_prefix:
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:**"
    elif show_suffix:
        return f"**:**:**:**:**:{parts[5]}"
    else:
        return "**:**:**:**:**:**"


def mask_ip(ip: str) -> str:
    """
    Mask an IP address for secure logging (CWE-532 mitigation).

    Args:
        ip: IP address to mask

    Returns:
        Masked IP like "192.168.x.x"
    """
    if not ip:
        return "x.x.x.x"

    parts = ip.split('.')
    if len(parts) != 4:
        return "x.x.x.x"

    return f"{parts[0]}.{parts[1]}.x.x"
