#!/usr/bin/env python3
"""
Security Utilities for Fortress Library Modules

Provides helper functions for secure logging and error handling to address:
- CWE-532: Information Exposure Through Log Files
- CWE-209: Information Exposure Through an Error Message

These utilities protect sensitive data (MAC addresses, IP addresses, PII)
while maintaining operational visibility for debugging and monitoring.

G.N.C. Security Protocol: Reviewed by Gemini (Architect) for industry best practices.
"""

import hashlib
import logging
import re
from typing import Optional

# Logger for internal error tracking
logger = logging.getLogger(__name__)


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
        'AA:BB:CC:**:**:FF'
        >>> mask_mac("aa:bb:cc:dd:ee:ff", show_prefix=False)
        '**:**:**:**:**:FF'
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
        # Show vendor OUI (first 3) and last octet: AA:BB:CC:**:**:FF
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:{parts[5]}"
    elif show_prefix:
        # Show only vendor OUI: AA:BB:CC:**:**:**
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:**"
    elif show_suffix:
        # Show only last octet: **:**:**:**:**:FF
        return f"**:**:**:**:**:{parts[5]}"
    else:
        return "**:**:**:**:**:**"


def mac_log_id(mac: str) -> str:
    """
    Generate a non-reversible log identifier from a MAC address (CWE-532 mitigation).

    Produces a short hash suitable for log correlation without exposing the
    actual MAC address. Unlike mask_mac(), this reveals zero octets.

    Args:
        mac: MAC address (e.g., "aa:bb:cc:dd:ee:ff")

    Returns:
        8-character hex hash, e.g., "dev_a1b2c3d4"
    """
    if not mac:
        return "dev_unknown"
    normalized = mac.upper().replace('-', ':').strip()
    return "dev_" + hashlib.sha256(normalized.encode()).hexdigest()[:8]


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


def mask_hostname(hostname: str) -> str:
    """
    Mask a hostname for secure logging (CWE-532 mitigation).

    Args:
        hostname: Hostname to mask

    Returns:
        Truncated hostname showing first 8 chars + "..."
    """
    if not hostname:
        return "[none]"
    if len(hostname) <= 8:
        return hostname
    return hostname[:8] + "..."


def safe_log_exception(
    logger_instance: logging.Logger,
    message: str,
    exc: Exception,
    level: str = 'error'
) -> None:
    """
    Log exception securely with only the type name, not the full message (CWE-532 mitigation).

    This prevents sensitive data that may be embedded in exception messages
    from being written to log files.

    Args:
        logger_instance: Logger to use
        message: Context message describing the operation that failed
        exc: The exception that was caught
        level: Log level ('debug', 'info', 'warning', 'error')

    Example:
        try:
            do_something()
        except Exception as e:
            safe_log_exception(logger, "Database operation failed", e)
        # Logs: "Database operation failed: ValueError"
    """
    log_fn = getattr(logger_instance, level, logger_instance.error)
    log_fn(f"{message}: {type(exc).__name__}")


def safe_error_message(exception: Exception, context: str = "operation") -> str:
    """
    Handle exceptions securely for API responses (CWE-209 mitigation).

    Security: Returns ONLY a generic, opaque error message to prevent
    information exposure. NO exception details are included in the response.

    The exception type is logged internally for debugging.

    Args:
        exception: The exception object that occurred
        context: A developer-controlled string describing the operation

    Returns:
        A generic, opaque error message safe for API responses.
    """
    # CWE-209 FIX: Log only exception type, not full stack trace
    logger.error(f"Error during {context}: {type(exception).__name__}")

    # Return generic, opaque message to client
    return f"An internal error occurred while processing the {context}"


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


# Convenience function for secure device logging
def log_device_event(
    logger_instance: logging.Logger,
    level: int,
    message: str,
    mac: Optional[str] = None,
    ip: Optional[str] = None,
    hostname: Optional[str] = None,
    **extra
) -> None:
    """
    Log a device event with automatic PII masking.

    This is the recommended way to log device-related events to ensure
    consistent PII protection across the codebase.

    Args:
        logger_instance: Logger to use
        level: Logging level (e.g., logging.INFO)
        message: Log message (should not contain raw PII)
        mac: MAC address to log (will be masked)
        ip: IP address to log (will be masked)
        hostname: Hostname to log (will be truncated)
        **extra: Additional key-value pairs for structured logging

    Example:
        log_device_event(logger, logging.INFO, "Device connected",
                        mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.100")
        # Logs: "Device connected [mac=AA:BB:CC:**:**:FF ip=192.168.x.x]"
    """
    parts = [message]
    details = []

    if mac:
        details.append(f"mac={mask_mac(mac)}")
    if ip:
        details.append(f"ip={mask_ip(ip)}")
    if hostname:
        details.append(f"host={mask_hostname(hostname)}")

    for key, value in extra.items():
        key_lower = key.lower()
        if 'mac' in key_lower:
            details.append(f"{key}={mask_mac(str(value))}")
        elif 'ip' in key_lower:
            details.append(f"{key}={mask_ip(str(value))}")
        else:
            details.append(f"{key}={value}")

    if details:
        parts.append(f"[{' '.join(details)}]")

    logger_instance.log(level, " ".join(parts))
