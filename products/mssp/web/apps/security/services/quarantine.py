"""
Quarantine Manager - IPS with nftables Integration

Provides autonomous threat response capabilities:
- Block malicious IPs via nftables dynamic sets
- Rate limiting for DDoS mitigation
- Automatic expiration and release
- Audit logging for compliance

Security Notes:
- Uses nftables named sets for O(1) lookups
- Commands executed via subprocess with strict validation
- No shell=True to prevent injection
- IP addresses validated before blocking
"""

from __future__ import annotations

import re
import uuid
import logging
import subprocess
from datetime import timedelta
from typing import TYPE_CHECKING, Optional, List

from django.utils import timezone
from django.conf import settings

from apps.common.security_utils import mask_ip

if TYPE_CHECKING:
    from apps.security.models import QuarantineAction

logger = logging.getLogger(__name__)


class QuarantineManager:
    """
    Manages IPS quarantine actions via nftables.

    Uses nftables dynamic sets for efficient IP blocking:
    - hp_quarantine_ipv4: Blocked IPv4 addresses
    - hp_quarantine_ipv6: Blocked IPv6 addresses
    - hp_ratelimit: Rate-limited addresses

    Example nftables setup (run once):
    ```
    nft add table inet hp_ips
    nft add set inet hp_ips quarantine_ipv4 { type ipv4_addr; flags timeout; }
    nft add set inet hp_ips quarantine_ipv6 { type ipv6_addr; flags timeout; }
    nft add chain inet hp_ips input { type filter hook input priority -100; }
    nft add rule inet hp_ips input ip saddr @quarantine_ipv4 drop
    nft add rule inet hp_ips input ip6 saddr @quarantine_ipv6 drop
    ```
    """

    NFT_TABLE = 'inet hp_ips'
    NFT_SET_IPV4 = 'quarantine_ipv4'
    NFT_SET_IPV6 = 'quarantine_ipv6'

    # IP validation patterns
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    IPV6_PATTERN = re.compile(
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|'
        r'^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
    )

    # Reserved IPs that should never be blocked
    RESERVED_IPS = {
        '127.0.0.1',
        '::1',
        '0.0.0.0',
        '255.255.255.255',
    }

    # Default quarantine duration
    DEFAULT_DURATION_MINUTES = 60

    def __init__(self, dry_run: bool = False):
        """
        Initialize quarantine manager.

        Args:
            dry_run: If True, log commands but don't execute them
        """
        self.dry_run = dry_run or getattr(settings, 'IPS_DRY_RUN', False)

    def quarantine_ip(
        self,
        ip_address: str,
        duration_minutes: int = None,
        reason: str = '',
        security_event=None,
        confidence_score: float = 0.9,
        classification_method: str = 'hybrid',
        signature_match: str = '',
    ) -> Optional['QuarantineAction']:
        """
        Add an IP to the quarantine set.

        Args:
            ip_address: IP to block
            duration_minutes: How long to block (default: 60)
            reason: Human-readable reason for blocking
            security_event: Related SecurityEvent model instance
            confidence_score: Classification confidence (0.0-1.0)
            classification_method: How the threat was detected
            signature_match: Matched signature ID if any

        Returns:
            QuarantineAction model instance, or None if failed
        """
        # Import here to avoid circular imports
        from apps.security.models import QuarantineAction

        # Validate IP
        if not self._validate_ip(ip_address):
            logger.warning(f"Invalid IP address for quarantine: {mask_ip(ip_address)}")
            return None

        # Check if reserved
        if ip_address in self.RESERVED_IPS:
            logger.warning(f"Attempted to quarantine reserved IP: {mask_ip(ip_address)}")
            return None

        # Check for private IP ranges (optional - might want to block)
        if self._is_private_ip(ip_address):
            logger.info(f"Quarantining private IP: {mask_ip(ip_address)}")

        duration = duration_minutes or self.DEFAULT_DURATION_MINUTES
        expires_at = timezone.now() + timedelta(minutes=duration)

        # Determine confidence level
        if confidence_score >= 0.95:
            confidence_level = 'critical'
        elif confidence_score >= 0.85:
            confidence_level = 'high'
        elif confidence_score >= 0.70:
            confidence_level = 'medium'
        else:
            confidence_level = 'low'

        # Generate action ID
        action_id = f"qa-{uuid.uuid4().hex[:12]}"

        # Execute nftables command
        nft_handle = self._add_to_nft_set(ip_address, duration)

        if nft_handle is None and not self.dry_run:
            logger.error(f"Failed to add {mask_ip(ip_address)} to nftables quarantine set")
            return None

        # Create database record
        try:
            action = QuarantineAction.objects.create(
                action_id=action_id,
                action_type='block_ip',
                target_ip=ip_address,
                confidence_level=confidence_level,
                confidence_score=confidence_score,
                classification_method=classification_method,
                signature_match=signature_match or '',
                security_event=security_event,
                expires_at=expires_at,
                reason=reason or f"Auto-quarantine: {classification_method} detection",
                nft_rule_handle=nft_handle or 'dry-run',
            )
            logger.info(f"Quarantined IP {mask_ip(ip_address)} until {expires_at} (action: {action_id})")
            return action
        except Exception as e:
            logger.error(f"Failed to create QuarantineAction: {e}")
            # Try to remove from nftables if DB failed
            if nft_handle:
                self._remove_from_nft_set(ip_address)
            return None

    def release_ip(
        self,
        ip_address: str,
        released_by: str = 'auto',
        reason: str = ''
    ) -> bool:
        """
        Remove an IP from quarantine.

        Args:
            ip_address: IP to release
            released_by: User or 'auto' for automatic expiry
            reason: Why the IP was released

        Returns:
            True if successful
        """
        from apps.security.models import QuarantineAction

        if not self._validate_ip(ip_address):
            return False

        # Remove from nftables
        success = self._remove_from_nft_set(ip_address)

        # Update database records
        actions = QuarantineAction.objects.filter(
            target_ip=ip_address,
            status='active'
        )

        for action in actions:
            action.release(by=released_by, reason=reason)

        if success or self.dry_run:
            logger.info(f"Released IP {mask_ip(ip_address)} from quarantine (by: {released_by})")
            return True

        return False

    def expire_quarantines(self) -> int:
        """
        Process expired quarantines.

        Call this periodically (e.g., via celery beat) to release
        IPs whose quarantine duration has passed.

        Returns:
            Number of quarantines released
        """
        from apps.security.models import QuarantineAction

        expired = QuarantineAction.objects.filter(
            status='active',
            expires_at__lt=timezone.now()
        )

        count = 0
        for action in expired:
            self.release_ip(
                action.target_ip,
                released_by='auto',
                reason='Quarantine expired'
            )
            count += 1

        if count > 0:
            logger.info(f"Released {count} expired quarantines")

        return count

    def get_active_quarantines(self) -> List[dict]:
        """Get list of currently quarantined IPs"""
        from apps.security.models import QuarantineAction

        actions = QuarantineAction.objects.filter(status='active').values(
            'action_id',
            'target_ip',
            'confidence_level',
            'reason',
            'created_at',
            'expires_at',
        )
        return list(actions)

    def is_quarantined(self, ip_address: str) -> bool:
        """Check if an IP is currently quarantined"""
        from apps.security.models import QuarantineAction

        return QuarantineAction.objects.filter(
            target_ip=ip_address,
            status='active'
        ).exists()

    def _add_to_nft_set(self, ip_address: str, duration_minutes: int) -> Optional[str]:
        """
        Add IP to nftables quarantine set with timeout.

        Returns:
            Handle string, or None if failed
        """
        is_ipv6 = ':' in ip_address
        nft_set = self.NFT_SET_IPV6 if is_ipv6 else self.NFT_SET_IPV4

        # nftables timeout format
        timeout = f"{duration_minutes}m"

        cmd = [
            'nft', 'add', 'element', self.NFT_TABLE.split()[0], self.NFT_TABLE.split()[1],
            nft_set, '{', ip_address, 'timeout', timeout, '}'
        ]

        return self._execute_nft_cmd(cmd)

    def _remove_from_nft_set(self, ip_address: str) -> bool:
        """Remove IP from nftables quarantine set"""
        is_ipv6 = ':' in ip_address
        nft_set = self.NFT_SET_IPV6 if is_ipv6 else self.NFT_SET_IPV4

        cmd = [
            'nft', 'delete', 'element', self.NFT_TABLE.split()[0], self.NFT_TABLE.split()[1],
            nft_set, '{', ip_address, '}'
        ]

        result = self._execute_nft_cmd(cmd)
        return result is not None

    def _execute_nft_cmd(self, cmd: List[str]) -> Optional[str]:
        """
        Execute an nftables command safely.

        Args:
            cmd: Command as list (no shell=True for security)

        Returns:
            'ok' on success, None on failure
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            return 'dry-run'

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return 'ok'
            else:
                logger.error(f"nft command failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("nft command timed out")
            return None
        except Exception as e:
            logger.error(f"nft command error: {e}")
            return None

    def _validate_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        if not ip_address:
            return False
        return bool(
            self.IPV4_PATTERN.match(ip_address) or
            self.IPV6_PATTERN.match(ip_address)
        )

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is in private range"""
        if ':' in ip_address:
            # IPv6 - simplified check
            return ip_address.startswith('fc') or ip_address.startswith('fd')

        # IPv4 private ranges
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

            return False
        except ValueError:
            return False

    def setup_nftables(self) -> bool:
        """
        Initialize nftables table and sets for IPS.

        Run this once during system setup, or add to setup-vrf.sh.

        Returns:
            True if successful
        """
        commands = [
            # Create table
            ['nft', 'add', 'table', 'inet', 'hp_ips'],

            # Create sets with timeout support
            ['nft', 'add', 'set', 'inet', 'hp_ips', 'quarantine_ipv4',
             '{', 'type', 'ipv4_addr;', 'flags', 'timeout;', '}'],
            ['nft', 'add', 'set', 'inet', 'hp_ips', 'quarantine_ipv6',
             '{', 'type', 'ipv6_addr;', 'flags', 'timeout;', '}'],

            # Create chain with high priority (processed early)
            ['nft', 'add', 'chain', 'inet', 'hp_ips', 'input',
             '{', 'type', 'filter', 'hook', 'input', 'priority', '-100;', '}'],

            # Add drop rules
            ['nft', 'add', 'rule', 'inet', 'hp_ips', 'input',
             'ip', 'saddr', '@quarantine_ipv4', 'counter', 'drop'],
            ['nft', 'add', 'rule', 'inet', 'hp_ips', 'input',
             'ip6', 'saddr', '@quarantine_ipv6', 'counter', 'drop'],
        ]

        success = True
        for cmd in commands:
            result = self._execute_nft_cmd(cmd)
            if result is None:
                success = False
                # Continue trying other commands

        return success


# Singleton instance for convenience
_manager = None


def get_quarantine_manager(dry_run: bool = False) -> QuarantineManager:
    """Get or create quarantine manager singleton"""
    global _manager
    if _manager is None:
        _manager = QuarantineManager(dry_run=dry_run)
    return _manager
