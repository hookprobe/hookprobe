"""
Qsecbit Unified - Response Orchestrator

Automated threat response system with XDP integration.
Coordinates responses across multiple mitigation systems.

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import json
import logging
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

from ..threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, ResponseAction,
    DEFAULT_RESPONSE_MAP
)


@dataclass
class ResponseResult:
    """Result of a response action."""
    action: ResponseAction
    success: bool
    timestamp: datetime
    details: str = ""
    target: str = ""  # IP, MAC, or session ID


@dataclass
class ResponsePolicy:
    """
    Response policy configuration.

    Defines how to respond to threats based on severity and type.
    """
    # Enable/disable response types
    enable_xdp_blocking: bool = True
    enable_firewall_rules: bool = True
    enable_rate_limiting: bool = True
    enable_session_termination: bool = False  # Dangerous, disabled by default
    enable_quarantine: bool = False           # Dangerous, disabled by default

    # Thresholds
    auto_block_severity: ThreatSeverity = ThreatSeverity.HIGH  # Auto-block HIGH+
    rate_limit_severity: ThreatSeverity = ThreatSeverity.MEDIUM  # Rate limit MEDIUM+

    # Limits
    max_blocked_ips: int = 10000
    block_duration_minutes: int = 60
    rate_limit_duration_minutes: int = 30

    # Whitelist
    whitelist_ips: Set[str] = field(default_factory=set)
    whitelist_macs: Set[str] = field(default_factory=set)


class ResponseOrchestrator:
    """
    Automated threat response orchestrator.

    Coordinates responses to detected threats including:
    - XDP-level IP blocking
    - Firewall rule management
    - Rate limiting
    - Session termination
    - Alert routing
    """

    def __init__(
        self,
        xdp_manager=None,
        policy: Optional[ResponsePolicy] = None,
        data_dir: str = "/opt/hookprobe/data"
    ):
        """
        Initialize response orchestrator.

        Args:
            xdp_manager: XDP manager instance for kernel-level blocking
            policy: Response policy configuration
            data_dir: Directory for persistent state
        """
        self.xdp_manager = xdp_manager
        self.policy = policy or ResponsePolicy()
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Tracking
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> block_time
        self.blocked_macs: Dict[str, datetime] = {}  # MAC -> block_time
        self.rate_limited: Dict[str, datetime] = {}  # IP -> limit_time
        self.response_history: List[ResponseResult] = []

        # Alert callbacks
        self.alert_callbacks: List[callable] = []

        # Load state
        self._load_state()

    def _load_state(self):
        """Load blocked IPs/MACs from disk."""
        state_file = self.data_dir / "response_state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    state = json.load(f)
                    # Parse timestamps and filter expired
                    now = datetime.now()
                    block_duration = timedelta(minutes=self.policy.block_duration_minutes)

                    for ip, ts in state.get('blocked_ips', {}).items():
                        block_time = datetime.fromisoformat(ts)
                        if now - block_time < block_duration:
                            self.blocked_ips[ip] = block_time

                    for mac, ts in state.get('blocked_macs', {}).items():
                        block_time = datetime.fromisoformat(ts)
                        if now - block_time < block_duration:
                            self.blocked_macs[mac] = block_time
            except Exception:
                pass

    def _save_state(self):
        """Save state to disk."""
        state_file = self.data_dir / "response_state.json"
        try:
            with open(state_file, 'w') as f:
                json.dump({
                    'blocked_ips': {ip: ts.isoformat() for ip, ts in self.blocked_ips.items()},
                    'blocked_macs': {mac: ts.isoformat() for mac, ts in self.blocked_macs.items()},
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save response state: {e}")

    @staticmethod
    def _validate_ipv4(ip: str) -> bool:
        """Validate IPv4 address with strict octet range checking (CWE-20)."""
        pattern = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
        return bool(re.match(pattern, ip))

    @staticmethod
    def _validate_mac(mac: str) -> bool:
        """Validate MAC address format (CWE-20)."""
        pattern = r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'
        return bool(re.match(pattern, mac))

    def _run_command(self, cmd_list: List[str], timeout: int = 10) -> tuple:
        """Run command safely using list form (CWE-78 fix)."""
        try:
            result = subprocess.run(
                cmd_list, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip(), result.returncode == 0
        except Exception as e:
            return str(e), False

    def register_alert_callback(self, callback: callable):
        """Register a callback for alert notifications."""
        self.alert_callbacks.append(callback)

    def _send_alert(self, threat: ThreatEvent, response_result: ResponseResult):
        """Send alert via registered callbacks."""
        for callback in self.alert_callbacks:
            try:
                callback(threat, response_result)
            except Exception:
                pass

    def respond(self, threat: ThreatEvent) -> List[ResponseResult]:
        """
        Execute appropriate response actions for a threat.

        Args:
            threat: ThreatEvent to respond to

        Returns:
            List of ResponseResult objects
        """
        results = []

        # Get response actions for this threat
        actions = threat.response_actions or DEFAULT_RESPONSE_MAP.get(
            threat.attack_type, [ResponseAction.MONITOR]
        )

        for action in actions:
            result = self._execute_action(action, threat)
            if result:
                results.append(result)
                self.response_history.append(result)

                # Mark threat as blocked if any blocking action succeeded
                if result.success and action in [ResponseAction.BLOCK_IP, ResponseAction.BLOCK_MAC]:
                    threat.blocked = True
                    threat.response_timestamp = result.timestamp

                # Send alert
                if action == ResponseAction.ALERT:
                    self._send_alert(threat, result)

        # Trim history
        if len(self.response_history) > 10000:
            self.response_history = self.response_history[-10000:]

        return results

    def _execute_action(
        self,
        action: ResponseAction,
        threat: ThreatEvent
    ) -> Optional[ResponseResult]:
        """Execute a single response action."""

        # Check if action is enabled
        if action == ResponseAction.BLOCK_IP and not self.policy.enable_xdp_blocking:
            return None
        if action == ResponseAction.TERMINATE_SESSION and not self.policy.enable_session_termination:
            return None
        if action == ResponseAction.QUARANTINE and not self.policy.enable_quarantine:
            return None

        # Check whitelist
        if threat.source_ip and threat.source_ip in self.policy.whitelist_ips:
            return ResponseResult(
                action=action,
                success=False,
                timestamp=datetime.now(),
                details="Source IP is whitelisted",
                target=threat.source_ip
            )

        if threat.source_mac and threat.source_mac.lower() in self.policy.whitelist_macs:
            return ResponseResult(
                action=action,
                success=False,
                timestamp=datetime.now(),
                details="Source MAC is whitelisted",
                target=threat.source_mac
            )

        # Execute action
        if action == ResponseAction.MONITOR:
            return self._action_monitor(threat)
        elif action == ResponseAction.ALERT:
            return self._action_alert(threat)
        elif action == ResponseAction.RATE_LIMIT:
            return self._action_rate_limit(threat)
        elif action == ResponseAction.BLOCK_IP:
            return self._action_block_ip(threat)
        elif action == ResponseAction.BLOCK_MAC:
            return self._action_block_mac(threat)
        elif action == ResponseAction.TERMINATE_SESSION:
            return self._action_terminate_session(threat)
        elif action == ResponseAction.QUARANTINE:
            return self._action_quarantine(threat)
        elif action == ResponseAction.CAPTIVE_PORTAL:
            return self._action_captive_portal(threat)

        return None

    def _action_monitor(self, threat: ThreatEvent) -> ResponseResult:
        """Log and monitor (no active response)."""
        return ResponseResult(
            action=ResponseAction.MONITOR,
            success=True,
            timestamp=datetime.now(),
            details=f"Monitoring threat: {threat.attack_type.name}",
            target=threat.source_ip or threat.source_mac or "unknown"
        )

    def _action_alert(self, threat: ThreatEvent) -> ResponseResult:
        """Send alert notification."""
        # Log to alerts file
        alerts_file = self.data_dir / "alerts.json"
        try:
            with open(alerts_file, 'a') as f:
                f.write(json.dumps({
                    'timestamp': datetime.now().isoformat(),
                    'threat_id': threat.id,
                    'attack_type': threat.attack_type.name,
                    'severity': threat.severity.name,
                    'source_ip': threat.source_ip,
                    'description': threat.description
                }) + '\n')
        except Exception:
            pass

        return ResponseResult(
            action=ResponseAction.ALERT,
            success=True,
            timestamp=datetime.now(),
            details=f"Alert sent: {threat.description[:100]}",
            target=threat.source_ip or "unknown"
        )

    def _action_rate_limit(self, threat: ThreatEvent) -> ResponseResult:
        """Apply rate limiting to source."""
        if not threat.source_ip:
            return ResponseResult(
                action=ResponseAction.RATE_LIMIT,
                success=False,
                timestamp=datetime.now(),
                details="No source IP to rate limit"
            )

        # Rate limiting is typically handled by XDP or firewall
        self.rate_limited[threat.source_ip] = datetime.now()

        # If XDP manager is available, it handles rate limiting automatically
        # For firewall, we could add tc/iptables rules

        return ResponseResult(
            action=ResponseAction.RATE_LIMIT,
            success=True,
            timestamp=datetime.now(),
            details=f"Rate limiting applied to {threat.source_ip}",
            target=threat.source_ip
        )

    def _action_block_ip(self, threat: ThreatEvent) -> ResponseResult:
        """Block source IP address."""
        if not threat.source_ip:
            return ResponseResult(
                action=ResponseAction.BLOCK_IP,
                success=False,
                timestamp=datetime.now(),
                details="No source IP to block"
            )

        # Check limit
        if len(self.blocked_ips) >= self.policy.max_blocked_ips:
            # Remove oldest block
            oldest_ip = min(self.blocked_ips, key=self.blocked_ips.get)
            self._unblock_ip(oldest_ip)

        # Try XDP blocking first (fastest)
        if self.xdp_manager and hasattr(self.xdp_manager, 'block_ip'):
            success = self.xdp_manager.block_ip(threat.source_ip)
            if success:
                self.blocked_ips[threat.source_ip] = datetime.now()
                self._save_state()
                return ResponseResult(
                    action=ResponseAction.BLOCK_IP,
                    success=True,
                    timestamp=datetime.now(),
                    details=f"Blocked {threat.source_ip} via XDP",
                    target=threat.source_ip
                )

        # Fallback to iptables/nftables
        if self.policy.enable_firewall_rules:
            ip = threat.source_ip
            if not self._validate_ipv4(ip):
                return ResponseResult(
                    action=ResponseAction.BLOCK_IP,
                    success=False,
                    timestamp=datetime.now(),
                    details=f"Invalid IP address format: {ip!r}",
                    target=ip
                )
            # Try nftables first (CWE-78 fix: list form)
            _, success = self._run_command(
                ['nft', 'add', 'element', 'inet', 'filter', 'blocked_ips', '{', ip, '}']
            )
            if not success:
                # Try iptables (CWE-78 fix: list form)
                _, success = self._run_command(
                    ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                )

            if success:
                self.blocked_ips[threat.source_ip] = datetime.now()
                self._save_state()
                return ResponseResult(
                    action=ResponseAction.BLOCK_IP,
                    success=True,
                    timestamp=datetime.now(),
                    details=f"Blocked {threat.source_ip} via firewall",
                    target=threat.source_ip
                )

        return ResponseResult(
            action=ResponseAction.BLOCK_IP,
            success=False,
            timestamp=datetime.now(),
            details=f"Failed to block {threat.source_ip}",
            target=threat.source_ip
        )

    def _action_block_mac(self, threat: ThreatEvent) -> ResponseResult:
        """Block source MAC address."""
        if not threat.source_mac:
            return ResponseResult(
                action=ResponseAction.BLOCK_MAC,
                success=False,
                timestamp=datetime.now(),
                details="No source MAC to block"
            )

        mac = threat.source_mac.lower()

        # CWE-20: Validate MAC format
        if not self._validate_mac(mac):
            return ResponseResult(
                action=ResponseAction.BLOCK_MAC,
                success=False,
                timestamp=datetime.now(),
                details=f"Invalid MAC address format: {mac!r}",
                target=mac
            )

        # MAC blocking via ebtables (CWE-78 fix: list form)
        _, success = self._run_command(
            ['ebtables', '-A', 'INPUT', '-s', mac, '-j', 'DROP']
        )

        if success:
            self.blocked_macs[mac] = datetime.now()
            self._save_state()
            return ResponseResult(
                action=ResponseAction.BLOCK_MAC,
                success=True,
                timestamp=datetime.now(),
                details=f"Blocked MAC {mac} via ebtables",
                target=mac
            )

        return ResponseResult(
            action=ResponseAction.BLOCK_MAC,
            success=False,
            timestamp=datetime.now(),
            details=f"Failed to block MAC {mac}",
            target=mac
        )

    def _action_terminate_session(self, threat: ThreatEvent) -> ResponseResult:
        """Terminate active session (dangerous)."""
        if not threat.source_ip:
            return ResponseResult(
                action=ResponseAction.TERMINATE_SESSION,
                success=False,
                timestamp=datetime.now(),
                details="No source IP for session termination"
            )

        ip = threat.source_ip
        if not self._validate_ipv4(ip):
            return ResponseResult(
                action=ResponseAction.TERMINATE_SESSION,
                success=False,
                timestamp=datetime.now(),
                details=f"Invalid IP address format: {ip!r}",
                target=ip
            )

        # Kill established connections (CWE-78 fix: list form)
        _, success = self._run_command(
            ['conntrack', '-D', '-s', ip]
        )

        return ResponseResult(
            action=ResponseAction.TERMINATE_SESSION,
            success=success,
            timestamp=datetime.now(),
            details=f"Session termination for {threat.source_ip}: {'success' if success else 'failed'}",
            target=threat.source_ip
        )

    def _action_quarantine(self, threat: ThreatEvent) -> ResponseResult:
        """Quarantine device (move to isolated VLAN)."""
        # This would require SDN/OpenFlow integration
        return ResponseResult(
            action=ResponseAction.QUARANTINE,
            success=False,
            timestamp=datetime.now(),
            details="Quarantine not implemented (requires SDN)",
            target=threat.source_ip or threat.source_mac or "unknown"
        )

    def _action_captive_portal(self, threat: ThreatEvent) -> ResponseResult:
        """Redirect to captive portal."""
        # This would require dnsmasq/hostapd configuration
        return ResponseResult(
            action=ResponseAction.CAPTIVE_PORTAL,
            success=False,
            timestamp=datetime.now(),
            details="Captive portal redirect not implemented",
            target=threat.source_ip or "unknown"
        )

    def _unblock_ip(self, ip: str):
        """Remove IP block."""
        if not self._validate_ipv4(ip):
            return

        if self.xdp_manager and hasattr(self.xdp_manager, 'unblock_ip'):
            self.xdp_manager.unblock_ip(ip)

        # CWE-78 fix: list form (stderr suppression handled by capture_output)
        self._run_command(['nft', 'delete', 'element', 'inet', 'filter', 'blocked_ips', '{', ip, '}'])
        self._run_command(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])

        if ip in self.blocked_ips:
            del self.blocked_ips[ip]

        self._save_state()

    def cleanup_expired_blocks(self):
        """Remove expired blocks."""
        now = datetime.now()
        block_duration = timedelta(minutes=self.policy.block_duration_minutes)
        rate_limit_duration = timedelta(minutes=self.policy.rate_limit_duration_minutes)

        # Clean expired IP blocks
        expired_ips = [
            ip for ip, block_time in self.blocked_ips.items()
            if now - block_time > block_duration
        ]
        for ip in expired_ips:
            self._unblock_ip(ip)

        # Clean expired rate limits
        expired_limits = [
            ip for ip, limit_time in self.rate_limited.items()
            if now - limit_time > rate_limit_duration
        ]
        for ip in expired_limits:
            del self.rate_limited[ip]

    def get_statistics(self) -> Dict[str, Any]:
        """Get response statistics."""
        action_counts = defaultdict(int)
        success_counts = defaultdict(int)

        for result in self.response_history:
            action_counts[result.action.name] += 1
            if result.success:
                success_counts[result.action.name] += 1

        return {
            'blocked_ips': len(self.blocked_ips),
            'blocked_macs': len(self.blocked_macs),
            'rate_limited': len(self.rate_limited),
            'total_responses': len(self.response_history),
            'action_counts': dict(action_counts),
            'success_counts': dict(success_counts),
            'policy': {
                'xdp_blocking': self.policy.enable_xdp_blocking,
                'firewall_rules': self.policy.enable_firewall_rules,
                'auto_block_severity': self.policy.auto_block_severity.name,
            }
        }
