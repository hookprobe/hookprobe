"""
AIOCHI Autonomous Quarantine System
Automated threat response: NAPSE detection → OVS isolation.

Philosophy: When a threat is detected, isolate first, investigate second.
A flower shop can't afford a 30-minute response time to ransomware.

Architecture:
1. Monitor NAPSE alerts (tail -F)
2. Score alerts using severity + confidence
3. Apply OVS drop rules for high-severity threats
4. Notify user via dashboard/webhook
5. Auto-release after investigation window

MITRE ATT&CK Coverage:
- T1486: Ransomware → Immediate quarantine
- T1566: Phishing → DNS block + device monitoring
- T1041: Exfiltration → Traffic drop + alert
- T1071: C2 Communication → Block destination + quarantine source
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class QuarantineReason(Enum):
    """Reason for quarantine action."""
    MALWARE_C2 = "malware_c2"           # Command & Control communication
    RANSOMWARE = "ransomware"           # Ransomware behavior detected
    DATA_EXFIL = "data_exfil"           # Data exfiltration attempt
    PORT_SCAN = "port_scan"             # Internal port scanning
    BRUTE_FORCE = "brute_force"         # Credential brute force
    LATERAL_MOVEMENT = "lateral_move"   # Lateral movement attempt
    POLICY_VIOLATION = "policy"         # Policy violation
    MANUAL = "manual"                   # Manual quarantine by admin


class QuarantineStatus(Enum):
    """Status of a quarantined device."""
    ACTIVE = "active"           # Currently quarantined
    RELEASED = "released"       # Released from quarantine
    EXPIRED = "expired"         # Auto-released after timeout
    OVERRIDDEN = "overridden"   # Admin override


@dataclass
class QuarantinedDevice:
    """A device in quarantine."""
    mac: str
    ip_address: str = ""
    hostname: str = ""
    reason: QuarantineReason = QuarantineReason.MANUAL
    trigger_alert_id: str = ""
    trigger_signature: str = ""
    trigger_severity: int = 3
    quarantine_time: datetime = field(default_factory=datetime.now)
    release_time: Optional[datetime] = None
    auto_release_at: Optional[datetime] = None
    status: QuarantineStatus = QuarantineStatus.ACTIVE
    notes: str = ""
    blocked_flows: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "reason": self.reason.value,
            "trigger_alert_id": self.trigger_alert_id,
            "trigger_signature": self.trigger_signature,
            "trigger_severity": self.trigger_severity,
            "quarantine_time": self.quarantine_time.isoformat(),
            "release_time": self.release_time.isoformat() if self.release_time else None,
            "auto_release_at": self.auto_release_at.isoformat() if self.auto_release_at else None,
            "status": self.status.value,
            "notes": self.notes,
            "blocked_flows": self.blocked_flows,
        }


@dataclass
class QuarantineAction:
    """Record of a quarantine action."""
    id: str
    timestamp: datetime
    action: str  # "quarantine", "release", "extend", "block_ip"
    target_mac: str
    target_ip: str = ""
    reason: str = ""
    trigger_alert: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "target_mac": self.target_mac,
            "target_ip": self.target_ip,
            "reason": self.reason,
            "trigger_alert": self.trigger_alert,
            "success": self.success,
            "error_message": self.error_message,
        }


# IDS alert severity mapping
ALERT_SEVERITY = {
    1: "critical",   # Most severe
    2: "high",
    3: "medium",
    4: "low",
}

# Alert signatures that trigger auto-quarantine
AUTO_QUARANTINE_SIGNATURES = {
    # Ransomware indicators (CRITICAL - immediate quarantine)
    r"ET MALWARE Ransomware": QuarantineReason.RANSOMWARE,
    r"ET TROJAN Ransomware": QuarantineReason.RANSOMWARE,
    r"ET MALWARE CryptoLocker": QuarantineReason.RANSOMWARE,
    r"ET MALWARE WannaCry": QuarantineReason.RANSOMWARE,

    # C2 Communication (HIGH - quarantine + block destination)
    r"ET MALWARE.*C2": QuarantineReason.MALWARE_C2,
    r"ET TROJAN.*C2": QuarantineReason.MALWARE_C2,
    r"ET CNC": QuarantineReason.MALWARE_C2,
    r"ETPRO TROJAN.*Beacon": QuarantineReason.MALWARE_C2,
    r"Cobalt Strike": QuarantineReason.MALWARE_C2,

    # Data Exfiltration (HIGH)
    r"ET POLICY.*Exfil": QuarantineReason.DATA_EXFIL,
    r"DNS Tunnel": QuarantineReason.DATA_EXFIL,
    r"Large DNS Query": QuarantineReason.DATA_EXFIL,

    # Lateral Movement (MEDIUM - quarantine source)
    r"ET SCAN.*Internal": QuarantineReason.LATERAL_MOVEMENT,
    r"ETPRO SCAN.*SMB": QuarantineReason.LATERAL_MOVEMENT,
    r"Pass.the.Hash": QuarantineReason.LATERAL_MOVEMENT,

    # Brute Force (MEDIUM - rate limit, then quarantine)
    r"ET SCAN.*Brute": QuarantineReason.BRUTE_FORCE,
    r"Multiple Failed SSH": QuarantineReason.BRUTE_FORCE,
    r"Multiple Failed Login": QuarantineReason.BRUTE_FORCE,
}

# Severity thresholds for auto-quarantine
QUARANTINE_THRESHOLDS = {
    QuarantineReason.RANSOMWARE: 1,      # Quarantine on ANY ransomware alert
    QuarantineReason.MALWARE_C2: 2,      # Quarantine on severity <= 2
    QuarantineReason.DATA_EXFIL: 2,
    QuarantineReason.LATERAL_MOVEMENT: 3,
    QuarantineReason.BRUTE_FORCE: 2,
    QuarantineReason.PORT_SCAN: 3,
}

# Default quarantine duration by reason (hours)
QUARANTINE_DURATION = {
    QuarantineReason.RANSOMWARE: 24,      # 24 hours for ransomware
    QuarantineReason.MALWARE_C2: 12,
    QuarantineReason.DATA_EXFIL: 12,
    QuarantineReason.LATERAL_MOVEMENT: 6,
    QuarantineReason.BRUTE_FORCE: 2,
    QuarantineReason.PORT_SCAN: 1,
    QuarantineReason.POLICY_VIOLATION: 1,
    QuarantineReason.MANUAL: 24,
}


class AutonomousQuarantineEngine:
    """
    Autonomous Quarantine Engine.

    Monitors NAPSE alerts and automatically quarantines
    devices showing malicious behavior.

    Features:
    - Real-time NAPSE alert monitoring
    - Signature-based auto-quarantine rules
    - OVS flow rule enforcement
    - Auto-release after investigation window
    - Webhook notifications
    - ClickHouse logging
    """

    OVS_BRIDGE = "FTS"
    QUARANTINE_VLAN = 99  # Quarantine VLAN
    QUARANTINE_PRIORITY = 1000  # High priority for drop rules

    def __init__(
        self,
        alert_source: str = "/var/log/napse/eve.json",
        state_path: str = "/run/fortress/quarantine-state.json",
        use_ovs: bool = True,
        webhook_url: Optional[str] = None,
        auto_release: bool = True,
    ):
        """
        Initialize the Autonomous Quarantine Engine.

        Args:
            alert_source: Path to NAPSE alert log
            state_path: Path to save quarantine state
            use_ovs: Enable OVS rule enforcement
            webhook_url: URL for notifications
            auto_release: Enable automatic release after timeout
        """
        self.alert_source = alert_source
        self.state_path = state_path
        self.use_ovs = use_ovs
        self.webhook_url = webhook_url
        self.auto_release = auto_release

        # Quarantined devices
        self._quarantined: Dict[str, QuarantinedDevice] = {}

        # IP to MAC mapping (for alert correlation)
        self._ip_mac_map: Dict[str, str] = {}

        # Blocked IPs (external threats)
        self._blocked_ips: Set[str] = set()

        # Action log
        self._actions: List[QuarantineAction] = []
        self._max_actions = 1000

        # Alert correlation (prevent duplicate quarantines)
        self._recent_alerts: Dict[str, datetime] = {}
        self._alert_cooldown = timedelta(minutes=5)

        # Monitoring thread
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_running = False

        # Callbacks for notifications
        self._callbacks: List[Callable[[QuarantineAction], None]] = []

        # Load saved state
        self._load_state()

    def start_monitoring(self) -> None:
        """Start monitoring NAPSE alert log."""
        if self._monitor_running:
            return

        self._monitor_running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_eve_log,
            daemon=True,
            name="aiochi-quarantine-monitor",
        )
        self._monitor_thread.start()

        # Start auto-release checker
        threading.Thread(
            target=self._auto_release_loop,
            daemon=True,
            name="aiochi-quarantine-release",
        ).start()

        logger.info(f"Started autonomous quarantine monitoring ({self.eve_log_path})")

    def stop_monitoring(self) -> None:
        """Stop monitoring."""
        self._monitor_running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        logger.info("Stopped quarantine monitoring")

    # =========================================================================
    # Quarantine Operations
    # =========================================================================

    def quarantine_device(
        self,
        mac: str,
        reason: QuarantineReason = QuarantineReason.MANUAL,
        ip_address: str = "",
        trigger_alert: Optional[Dict[str, Any]] = None,
        duration_hours: Optional[int] = None,
        notes: str = "",
    ) -> QuarantinedDevice:
        """
        Quarantine a device immediately.

        Args:
            mac: Device MAC address
            reason: Reason for quarantine
            ip_address: IP address if known
            trigger_alert: Alert that triggered quarantine
            duration_hours: Override default duration
            notes: Optional notes

        Returns:
            QuarantinedDevice object
        """
        mac = self._normalize_mac(mac)

        # Calculate auto-release time
        duration = duration_hours or QUARANTINE_DURATION.get(reason, 24)
        auto_release_at = datetime.now() + timedelta(hours=duration)

        device = QuarantinedDevice(
            mac=mac,
            ip_address=ip_address,
            reason=reason,
            trigger_alert_id=trigger_alert.get("flow_id", "") if trigger_alert else "",
            trigger_signature=trigger_alert.get("alert", {}).get("signature", "") if trigger_alert else "",
            trigger_severity=trigger_alert.get("alert", {}).get("severity", 3) if trigger_alert else 3,
            auto_release_at=auto_release_at if self.auto_release else None,
            notes=notes,
        )

        # Apply OVS rules
        success = self._apply_quarantine_rules(device)

        if success:
            self._quarantined[mac] = device
            self._save_state()

            # Log action
            action = self._create_action(
                action="quarantine",
                target_mac=mac,
                target_ip=ip_address,
                reason=reason.value,
                trigger_alert=trigger_alert or {},
                success=True,
            )
            self._notify_callbacks(action)

            logger.warning(f"QUARANTINED device {mac} - Reason: {reason.value}")
        else:
            device.status = QuarantineStatus.RELEASED
            device.notes = "Failed to apply OVS rules"

        return device

    def release_device(
        self,
        mac: str,
        reason: str = "Manual release",
    ) -> bool:
        """
        Release a device from quarantine.

        Args:
            mac: Device MAC address
            reason: Reason for release

        Returns:
            True if released successfully
        """
        mac = self._normalize_mac(mac)

        if mac not in self._quarantined:
            return False

        device = self._quarantined[mac]

        # Remove OVS rules
        success = self._remove_quarantine_rules(device)

        if success:
            device.status = QuarantineStatus.RELEASED
            device.release_time = datetime.now()
            device.notes = reason

            # Log action
            action = self._create_action(
                action="release",
                target_mac=mac,
                target_ip=device.ip_address,
                reason=reason,
                success=True,
            )
            self._notify_callbacks(action)

            # Keep in history but mark as released
            self._save_state()

            logger.info(f"Released device {mac} from quarantine: {reason}")
            return True

        return False

    def block_ip(
        self,
        ip: str,
        reason: str = "Malicious IP",
        trigger_alert: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Block an external IP address.

        Args:
            ip: IP address to block
            reason: Reason for blocking
            trigger_alert: Alert that triggered the block

        Returns:
            True if blocked successfully
        """
        if ip in self._blocked_ips:
            return True  # Already blocked

        if not self.use_ovs:
            logger.info(f"[DRY RUN] Would block IP: {ip}")
            self._blocked_ips.add(ip)
            return True

        try:
            # Add OVS rule to drop traffic to/from this IP
            cmd = [
                "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                f"priority={self.QUARANTINE_PRIORITY},ip,nw_src={ip},actions=drop"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            cmd = [
                "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                f"priority={self.QUARANTINE_PRIORITY},ip,nw_dst={ip},actions=drop"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            self._blocked_ips.add(ip)

            # Log action
            action = self._create_action(
                action="block_ip",
                target_mac="",
                target_ip=ip,
                reason=reason,
                trigger_alert=trigger_alert or {},
                success=True,
            )
            self._notify_callbacks(action)

            logger.warning(f"Blocked IP: {ip} - {reason}")
            return True

        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an external IP address."""
        if ip not in self._blocked_ips:
            return True

        if not self.use_ovs:
            self._blocked_ips.discard(ip)
            return True

        try:
            cmd = [
                "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                f"ip,nw_src={ip}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            cmd = [
                "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                f"ip,nw_dst={ip}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            self._blocked_ips.discard(ip)

            logger.info(f"Unblocked IP: {ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False

    def is_quarantined(self, mac: str) -> bool:
        """Check if a device is currently quarantined."""
        mac = self._normalize_mac(mac)
        device = self._quarantined.get(mac)
        return device is not None and device.status == QuarantineStatus.ACTIVE

    def get_quarantined_devices(self) -> List[QuarantinedDevice]:
        """Get all quarantined devices."""
        return [d for d in self._quarantined.values() if d.status == QuarantineStatus.ACTIVE]

    def get_device(self, mac: str) -> Optional[QuarantinedDevice]:
        """Get quarantine info for a device."""
        return self._quarantined.get(self._normalize_mac(mac))

    # =========================================================================
    # Alert Processing
    # =========================================================================

    def process_alert(self, alert: Dict[str, Any]) -> Optional[QuarantineAction]:
        """
        Process a NAPSE alert and determine if quarantine is needed.

        Args:
            alert: NAPSE alert

        Returns:
            QuarantineAction if action was taken, None otherwise
        """
        # Skip non-alert events
        if alert.get("event_type") != "alert":
            return None

        alert_data = alert.get("alert", {})
        signature = alert_data.get("signature", "")
        severity = alert_data.get("severity", 4)
        src_ip = alert.get("src_ip", "")
        dest_ip = alert.get("dest_ip", "")

        # Check if this is a local device (internal IP)
        src_is_local = self._is_local_ip(src_ip)
        dest_is_local = self._is_local_ip(dest_ip)

        # Determine quarantine reason
        reason = self._match_signature_to_reason(signature)
        if not reason:
            return None

        # Check severity threshold
        threshold = QUARANTINE_THRESHOLDS.get(reason, 2)
        if severity > threshold:
            logger.debug(f"Alert below threshold: {signature} (severity {severity} > {threshold})")
            return None

        # Check cooldown (prevent duplicate actions)
        alert_key = f"{src_ip}:{signature}"
        if alert_key in self._recent_alerts:
            last_time = self._recent_alerts[alert_key]
            if datetime.now() - last_time < self._alert_cooldown:
                return None
        self._recent_alerts[alert_key] = datetime.now()

        # Determine target
        if src_is_local:
            # Quarantine the internal source
            mac = self._resolve_ip_to_mac(src_ip)
            if mac:
                device = self.quarantine_device(
                    mac=mac,
                    reason=reason,
                    ip_address=src_ip,
                    trigger_alert=alert,
                )

                # Also block the external destination (C2, exfil target)
                if not dest_is_local and reason in [QuarantineReason.MALWARE_C2, QuarantineReason.DATA_EXFIL]:
                    self.block_ip(dest_ip, f"C2/Exfil destination ({signature})", alert)

                return self._actions[-1] if self._actions else None

        elif dest_is_local and reason == QuarantineReason.PORT_SCAN:
            # External scanner - just block the source IP
            self.block_ip(src_ip, f"External scanner ({signature})", alert)
            return self._actions[-1] if self._actions else None

        return None

    def _match_signature_to_reason(self, signature: str) -> Optional[QuarantineReason]:
        """Match alert signature to quarantine reason."""
        for pattern, reason in AUTO_QUARANTINE_SIGNATURES.items():
            if re.search(pattern, signature, re.IGNORECASE):
                return reason
        return None

    def _is_local_ip(self, ip: str) -> bool:
        """Check if an IP is local/internal."""
        if not ip:
            return False

        # RFC1918 private ranges
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            octets = ip.split(".")
            if len(octets) >= 2:
                second = int(octets[1])
                if 16 <= second <= 31:
                    return True
        return False

    def _resolve_ip_to_mac(self, ip: str) -> Optional[str]:
        """Resolve IP to MAC address."""
        # Check cache first
        if ip in self._ip_mac_map:
            return self._ip_mac_map[ip]

        # Try ARP table
        try:
            result = subprocess.run(
                ["ip", "neigh", "show", ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if "lladdr" in parts:
                    idx = parts.index("lladdr") + 1
                    if idx < len(parts):
                        mac = self._normalize_mac(parts[idx])
                        self._ip_mac_map[ip] = mac
                        return mac
        except Exception:
            pass

        return None

    # =========================================================================
    # OVS Rule Management
    # =========================================================================

    def _apply_quarantine_rules(self, device: QuarantinedDevice) -> bool:
        """Apply OVS quarantine rules for a device."""
        if not self.use_ovs:
            logger.info(f"[DRY RUN] Would quarantine: {device.mac}")
            return True

        try:
            # Drop all traffic FROM this MAC
            cmd = [
                "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                f"priority={self.QUARANTINE_PRIORITY},dl_src={device.mac},actions=drop"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                logger.error(f"Failed to add src drop rule: {result.stderr}")
                return False

            # Drop all traffic TO this MAC
            cmd = [
                "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                f"priority={self.QUARANTINE_PRIORITY},dl_dst={device.mac},actions=drop"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                logger.error(f"Failed to add dst drop rule: {result.stderr}")
                return False

            # If we have IP, also add IP-based rules (belt and suspenders)
            if device.ip_address:
                cmd = [
                    "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                    f"priority={self.QUARANTINE_PRIORITY},ip,nw_src={device.ip_address},actions=drop"
                ]
                subprocess.run(cmd, capture_output=True, timeout=5)

            logger.info(f"Applied quarantine rules for {device.mac}")
            return True

        except Exception as e:
            logger.error(f"Failed to apply quarantine rules: {e}")
            return False

    def _remove_quarantine_rules(self, device: QuarantinedDevice) -> bool:
        """Remove OVS quarantine rules for a device."""
        if not self.use_ovs:
            return True

        try:
            # Remove MAC-based rules
            cmd = [
                "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                f"dl_src={device.mac},priority={self.QUARANTINE_PRIORITY}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            cmd = [
                "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                f"dl_dst={device.mac},priority={self.QUARANTINE_PRIORITY}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=5)

            # Remove IP-based rules
            if device.ip_address:
                cmd = [
                    "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                    f"ip,nw_src={device.ip_address},priority={self.QUARANTINE_PRIORITY}"
                ]
                subprocess.run(cmd, capture_output=True, timeout=5)

            logger.info(f"Removed quarantine rules for {device.mac}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove quarantine rules: {e}")
            return False

    # =========================================================================
    # Monitoring
    # =========================================================================

    def _monitor_eve_log(self) -> None:
        """Monitor NAPSE alert log."""
        if not os.path.exists(self.eve_log_path):
            logger.warning(f"EVE log not found: {self.eve_log_path}")
            return

        try:
            # Open file and seek to end
            with open(self.eve_log_path, 'r') as f:
                f.seek(0, 2)  # Seek to end

                while self._monitor_running:
                    line = f.readline()
                    if line:
                        try:
                            alert = json.loads(line)
                            self.process_alert(alert)
                        except json.JSONDecodeError:
                            pass
                    else:
                        time.sleep(0.1)

        except Exception as e:
            logger.error(f"EVE monitoring error: {e}")
            self._monitor_running = False

    def _auto_release_loop(self) -> None:
        """Check for devices that should be auto-released."""
        while self._monitor_running:
            now = datetime.now()

            for mac, device in list(self._quarantined.items()):
                if (
                    device.status == QuarantineStatus.ACTIVE
                    and device.auto_release_at
                    and now > device.auto_release_at
                ):
                    logger.info(f"Auto-releasing {mac} (quarantine expired)")
                    device.status = QuarantineStatus.EXPIRED
                    device.release_time = now
                    self._remove_quarantine_rules(device)

                    action = self._create_action(
                        action="auto_release",
                        target_mac=mac,
                        target_ip=device.ip_address,
                        reason="Quarantine period expired",
                        success=True,
                    )
                    self._notify_callbacks(action)

            self._save_state()
            time.sleep(60)  # Check every minute

    # =========================================================================
    # Utilities
    # =========================================================================

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format."""
        return mac.upper().replace("-", ":")

    def _create_action(
        self,
        action: str,
        target_mac: str,
        target_ip: str,
        reason: str,
        trigger_alert: Dict[str, Any] = None,
        success: bool = True,
        error_message: str = "",
    ) -> QuarantineAction:
        """Create and log a quarantine action."""
        import uuid

        action_obj = QuarantineAction(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            action=action,
            target_mac=target_mac,
            target_ip=target_ip,
            reason=reason,
            trigger_alert=trigger_alert or {},
            success=success,
            error_message=error_message,
        )

        self._actions.append(action_obj)
        if len(self._actions) > self._max_actions:
            self._actions.pop(0)

        return action_obj

    def _notify_callbacks(self, action: QuarantineAction) -> None:
        """Notify registered callbacks of an action."""
        for callback in self._callbacks:
            try:
                callback(action)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        # Send webhook if configured
        if self.webhook_url:
            self._send_webhook(action)

    def _send_webhook(self, action: QuarantineAction) -> None:
        """Send webhook notification."""
        try:
            import requests
            requests.post(
                self.webhook_url,
                json={
                    "event": "quarantine_action",
                    "data": action.to_dict(),
                },
                timeout=5,
            )
        except Exception as e:
            logger.debug(f"Webhook failed: {e}")

    def add_callback(self, callback: Callable[[QuarantineAction], None]) -> None:
        """Add a callback for quarantine events."""
        self._callbacks.append(callback)

    def _load_state(self) -> None:
        """Load saved quarantine state."""
        if not os.path.exists(self.state_path):
            return

        try:
            with open(self.state_path, 'r') as f:
                data = json.load(f)

            for device_data in data.get("quarantined", []):
                mac = device_data.get("mac")
                if mac:
                    device = QuarantinedDevice(
                        mac=mac,
                        ip_address=device_data.get("ip_address", ""),
                        hostname=device_data.get("hostname", ""),
                        reason=QuarantineReason(device_data.get("reason", "manual")),
                        trigger_signature=device_data.get("trigger_signature", ""),
                        status=QuarantineStatus(device_data.get("status", "active")),
                        notes=device_data.get("notes", ""),
                    )

                    # Reapply rules if still active
                    if device.status == QuarantineStatus.ACTIVE:
                        self._apply_quarantine_rules(device)

                    self._quarantined[mac] = device

            self._blocked_ips = set(data.get("blocked_ips", []))

            logger.info(f"Loaded state: {len(self._quarantined)} quarantined, {len(self._blocked_ips)} blocked IPs")

        except Exception as e:
            logger.error(f"Failed to load state: {e}")

    def _save_state(self) -> None:
        """Save quarantine state."""
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)

            data = {
                "version": "1.0",
                "updated": datetime.now().isoformat(),
                "quarantined": [d.to_dict() for d in self._quarantined.values()],
                "blocked_ips": list(self._blocked_ips),
            }

            with open(self.state_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """Get quarantine summary for dashboard."""
        active = [d for d in self._quarantined.values() if d.status == QuarantineStatus.ACTIVE]

        return {
            "enabled": True,
            "monitoring": self._monitor_running,
            "quarantined_count": len(active),
            "blocked_ips_count": len(self._blocked_ips),
            "recent_actions": [a.to_dict() for a in self._actions[-10:]],
            "quarantined_devices": [d.to_dict() for d in active],
        }

    def get_actions(self, limit: int = 50) -> List[QuarantineAction]:
        """Get recent quarantine actions."""
        return list(reversed(self._actions[-limit:]))


# Singleton instance
_quarantine_engine: Optional[AutonomousQuarantineEngine] = None


def get_quarantine_engine(use_ovs: bool = True) -> AutonomousQuarantineEngine:
    """Get or create the singleton quarantine engine."""
    global _quarantine_engine

    if _quarantine_engine is None:
        _quarantine_engine = AutonomousQuarantineEngine(use_ovs=use_ovs)

    return _quarantine_engine


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    engine = AutonomousQuarantineEngine(use_ovs=False)

    # Manual quarantine test
    print("Testing manual quarantine...")
    device = engine.quarantine_device(
        mac="AA:BB:CC:DD:EE:FF",
        reason=QuarantineReason.MALWARE_C2,
        ip_address="10.200.0.100",
        notes="Test quarantine",
    )

    print(f"Quarantined: {device.mac}")
    print(f"  Reason: {device.reason.value}")
    print(f"  Auto-release: {device.auto_release_at}")

    # Process test alert
    print("\nProcessing test alert...")
    test_alert = {
        "event_type": "alert",
        "src_ip": "10.200.0.50",
        "dest_ip": "185.220.101.1",
        "alert": {
            "signature": "ET MALWARE CryptoLocker Ransomware Traffic",
            "severity": 1,
        }
    }

    # Simulate IP-MAC mapping
    engine._ip_mac_map["10.200.0.50"] = "11:22:33:44:55:66"

    action = engine.process_alert(test_alert)
    if action:
        print(f"Action taken: {action.action}")
        print(f"  Target: {action.target_mac}")
        print(f"  Reason: {action.reason}")

    # Summary
    print(f"\nSummary: {engine.get_summary()}")
