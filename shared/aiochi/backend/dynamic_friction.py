"""
AIOCHI Dynamic Friction Engine
QSecBit-driven network friction using tc/netem to stall attackers.

Philosophy: Instead of binary block/allow, apply graduated "friction" to
suspicious devices. This stalls automated attack tools without alerting
the attacker that they've been detected.

MITRE Coverage: T1046, T1499, T1071, T1027
- Slows reconnaissance (T1046)
- Disrupts C2 beaconing intervals (T1071)
- Frustrates automated exfiltration (T1027)

Innovation: QSecBit score (0-1) drives friction level:
- 0.0-0.3 (GREEN): No friction
- 0.3-0.5 (AMBER-LOW): 50ms latency (imperceptible to humans)
- 0.5-0.7 (AMBER-HIGH): 200ms latency (frustrating to humans)
- 0.7-0.9 (RED): 500ms + 5% packet loss (breaks most automation)
- 0.9-1.0 (CRITICAL): 1000ms + 20% packet loss (nearly unusable)

Usage:
    from dynamic_friction import DynamicFrictionEngine
    engine = DynamicFrictionEngine()
    engine.apply_friction("10.200.0.50", qsecbit_score=0.65)  # 200ms delay
"""

import ipaddress
import logging
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Security: Strict validation patterns
MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
INTERFACE_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,14}$')


def validate_ip(ip_str: str) -> bool:
    """Validate IP address to prevent command injection."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_mac(mac_str: str) -> bool:
    """Validate MAC address format."""
    return bool(MAC_PATTERN.match(mac_str))


def validate_interface(iface: str) -> bool:
    """Validate network interface name."""
    return bool(INTERFACE_PATTERN.match(iface))


class FrictionLevel(Enum):
    """Friction levels mapped to network degradation."""
    NONE = "none"           # No friction - clean traffic
    SUBTLE = "subtle"       # 50ms - imperceptible to humans
    NOTICEABLE = "notice"   # 200ms - frustrating but usable
    DEGRADED = "degraded"   # 500ms + 5% loss - breaks automation
    SEVERE = "severe"       # 1000ms + 20% loss - nearly unusable


@dataclass
class FrictionConfig:
    """Configuration for a friction level."""
    level: FrictionLevel
    latency_ms: int = 0
    jitter_ms: int = 0      # Random variation in latency
    packet_loss_pct: float = 0.0
    bandwidth_kbit: Optional[int] = None  # Optional bandwidth limit
    description: str = ""

    def to_tc_params(self) -> str:
        """Convert to tc netem parameters."""
        params = []
        if self.latency_ms > 0:
            params.append(f"delay {self.latency_ms}ms")
            if self.jitter_ms > 0:
                params.append(f"{self.jitter_ms}ms")
        if self.packet_loss_pct > 0:
            params.append(f"loss {self.packet_loss_pct}%")
        return " ".join(params)


# Default friction configurations
FRICTION_CONFIGS: Dict[FrictionLevel, FrictionConfig] = {
    FrictionLevel.NONE: FrictionConfig(
        level=FrictionLevel.NONE,
        description="No friction applied"
    ),
    FrictionLevel.SUBTLE: FrictionConfig(
        level=FrictionLevel.SUBTLE,
        latency_ms=50,
        jitter_ms=10,
        description="50ms latency - imperceptible to humans"
    ),
    FrictionLevel.NOTICEABLE: FrictionConfig(
        level=FrictionLevel.NOTICEABLE,
        latency_ms=200,
        jitter_ms=50,
        description="200ms latency - frustrating but usable"
    ),
    FrictionLevel.DEGRADED: FrictionConfig(
        level=FrictionLevel.DEGRADED,
        latency_ms=500,
        jitter_ms=100,
        packet_loss_pct=5.0,
        description="500ms + 5% loss - breaks most automation"
    ),
    FrictionLevel.SEVERE: FrictionConfig(
        level=FrictionLevel.SEVERE,
        latency_ms=1000,
        jitter_ms=200,
        packet_loss_pct=20.0,
        description="1s + 20% loss - nearly unusable"
    ),
}


@dataclass
class FrictionRecord:
    """Record of friction applied to a device."""
    device_ip: str
    device_mac: Optional[str] = None
    level: FrictionLevel = FrictionLevel.NONE
    qsecbit_score: float = 0.0
    applied_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    reason: str = ""
    mitre_ids: List[str] = field(default_factory=list)
    auto_escalate: bool = True  # Auto-increase friction if threats continue


class DynamicFrictionEngine:
    """
    Dynamic Friction Engine for AIOCHI.

    Applies graduated network friction based on QSecBit scores,
    slowing attackers without alerting them to detection.
    """

    # QSecBit score thresholds -> Friction levels
    SCORE_THRESHOLDS: List[Tuple[float, float, FrictionLevel]] = [
        (0.0, 0.3, FrictionLevel.NONE),
        (0.3, 0.5, FrictionLevel.SUBTLE),
        (0.5, 0.7, FrictionLevel.NOTICEABLE),
        (0.7, 0.9, FrictionLevel.DEGRADED),
        (0.9, 1.0, FrictionLevel.SEVERE),
    ]

    # OVS bridge and interface settings
    OVS_BRIDGE = "FTS"
    LAN_INTERFACE = "eth0"  # Will be detected dynamically

    def __init__(
        self,
        lan_interface: Optional[str] = None,
        dry_run: bool = False,
        auto_escalate: bool = True,
        default_duration_minutes: int = 30,
    ):
        """
        Initialize the Dynamic Friction Engine.

        Args:
            lan_interface: Network interface to apply tc rules
            dry_run: Log commands instead of executing
            auto_escalate: Auto-increase friction if threats continue
            default_duration_minutes: Default friction duration
        """
        self.lan_interface = lan_interface or self._detect_lan_interface()
        self.dry_run = dry_run
        self.auto_escalate = auto_escalate
        self.default_duration_minutes = default_duration_minutes

        # Active friction records (ip -> FrictionRecord)
        self._active_friction: Dict[str, FrictionRecord] = {}

        # HTB class IDs for per-IP traffic shaping
        self._class_ids: Dict[str, int] = {}
        self._next_class_id = 10

        # Lock for thread safety
        self._lock = threading.Lock()

        # Callbacks for friction events
        self._callbacks: List[Callable[[FrictionRecord, str], None]] = []

        # Statistics
        self._stats = {
            "friction_applied": 0,
            "friction_escalated": 0,
            "friction_cleared": 0,
            "total_latency_injected_ms": 0,
        }

        # Initialize tc qdisc if not dry run
        if not dry_run:
            self._initialize_tc_qdisc()

        logger.info(f"Dynamic Friction Engine initialized (interface: {self.lan_interface})")

    def _detect_lan_interface(self) -> str:
        """Detect the LAN interface attached to OVS bridge."""
        try:
            # Try to find interface on OVS bridge
            result = subprocess.run(
                ["ovs-vsctl", "list-ports", self.OVS_BRIDGE],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ports = result.stdout.strip().split("\n")
                for port in ports:
                    if port and not port.startswith("veth"):
                        return port
        except Exception as e:
            logger.debug(f"OVS detection failed: {e}")

        # Fallback to default
        return "eth0"

    def _initialize_tc_qdisc(self) -> bool:
        """Initialize tc qdisc hierarchy on the interface."""
        try:
            # Clear existing qdiscs
            self._run_tc(f"qdisc del dev {self.lan_interface} root", ignore_errors=True)

            # Create HTB root qdisc with default class
            self._run_tc(f"qdisc add dev {self.lan_interface} root handle 1: htb default 1")

            # Create default class (no friction)
            self._run_tc(
                f"class add dev {self.lan_interface} parent 1: classid 1:1 "
                f"htb rate 1000mbit ceil 1000mbit"
            )

            logger.info("TC qdisc hierarchy initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize tc qdisc: {e}")
            return False

    def _run_tc(self, cmd: str, ignore_errors: bool = False) -> bool:
        """Run a tc command safely without shell=True."""
        full_cmd = f"tc {cmd}"

        if self.dry_run:
            logger.info(f"[DRY RUN] {full_cmd}")
            return True

        try:
            # Security: Use shlex.split() to safely tokenize, avoid shell=True
            cmd_list = ["tc"] + shlex.split(cmd)
            result = subprocess.run(
                cmd_list, capture_output=True,
                text=True, timeout=10
            )
            if result.returncode != 0 and not ignore_errors:
                logger.warning(f"tc command failed: {result.stderr}")
                return False
            return True
        except Exception as e:
            if not ignore_errors:
                logger.error(f"tc command error: {e}")
            return False

    def _run_iptables(self, cmd: str, ignore_errors: bool = False) -> bool:
        """Run an iptables command safely without shell=True."""
        full_cmd = f"iptables {cmd}"

        if self.dry_run:
            logger.info(f"[DRY RUN] {full_cmd}")
            return True

        try:
            # Security: Use shlex.split() to safely tokenize, avoid shell=True
            cmd_list = ["iptables"] + shlex.split(cmd)
            result = subprocess.run(
                cmd_list, capture_output=True,
                text=True, timeout=10
            )
            if result.returncode != 0 and not ignore_errors:
                logger.warning(f"iptables command failed: {result.stderr}")
                return False
            return True
        except Exception as e:
            if not ignore_errors:
                logger.error(f"iptables command error: {e}")
            return False

    # =========================================================================
    # Core Friction Application
    # =========================================================================

    def get_friction_level(self, qsecbit_score: float) -> FrictionLevel:
        """Get friction level for a QSecBit score."""
        for lower, upper, level in self.SCORE_THRESHOLDS:
            if lower <= qsecbit_score < upper:
                return level
        return FrictionLevel.SEVERE  # Default to severe for score >= 1.0

    def apply_friction(
        self,
        device_ip: str,
        qsecbit_score: float,
        device_mac: Optional[str] = None,
        reason: str = "",
        mitre_ids: Optional[List[str]] = None,
        duration_minutes: Optional[int] = None,
    ) -> FrictionRecord:
        """
        Apply friction to a device based on QSecBit score.

        Args:
            device_ip: Target device IP address
            qsecbit_score: QSecBit resilience score (0-1, higher = more suspicious)
            device_mac: Optional MAC address for identification
            reason: Human-readable reason for friction
            mitre_ids: List of MITRE ATT&CK technique IDs
            duration_minutes: How long friction should last

        Returns:
            FrictionRecord with applied friction details

        Raises:
            ValueError: If device_ip is not a valid IP address
        """
        # Security: Validate IP address before any operations
        if not validate_ip(device_ip):
            raise ValueError(f"Invalid IP address: {device_ip}")
        if device_mac and not validate_mac(device_mac):
            logger.warning(f"Invalid MAC address format: {device_mac}")
            device_mac = None  # Clear invalid MAC but continue

        with self._lock:
            level = self.get_friction_level(qsecbit_score)
            duration = duration_minutes or self.default_duration_minutes

            # Check if already has friction and should escalate
            existing = self._active_friction.get(device_ip)
            if existing and self.auto_escalate:
                # Escalate if new score is higher
                if qsecbit_score > existing.qsecbit_score:
                    level = self._escalate_level(existing.level)
                    self._stats["friction_escalated"] += 1
                    reason = f"ESCALATED: {reason}"

            # Create friction record
            record = FrictionRecord(
                device_ip=device_ip,
                device_mac=device_mac,
                level=level,
                qsecbit_score=qsecbit_score,
                expires_at=datetime.now() + timedelta(minutes=duration),
                reason=reason,
                mitre_ids=mitre_ids or [],
                auto_escalate=self.auto_escalate,
            )

            # Apply tc rules
            success = self._apply_tc_friction(device_ip, level)

            if success:
                self._active_friction[device_ip] = record
                self._stats["friction_applied"] += 1

                config = FRICTION_CONFIGS[level]
                self._stats["total_latency_injected_ms"] += config.latency_ms

                # Notify callbacks
                for callback in self._callbacks:
                    try:
                        callback(record, "applied")
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                logger.info(
                    f"Applied {level.value} friction to {device_ip} "
                    f"(QSecBit: {qsecbit_score:.2f}, reason: {reason})"
                )
            else:
                logger.error(f"Failed to apply friction to {device_ip}")

            return record

    def _apply_tc_friction(self, device_ip: str, level: FrictionLevel) -> bool:
        """Apply tc rules for friction level."""
        config = FRICTION_CONFIGS[level]

        if level == FrictionLevel.NONE:
            return self._clear_tc_friction(device_ip)

        # Get or create class ID for this IP
        class_id = self._get_class_id(device_ip)

        try:
            # Create HTB class for this IP
            self._run_tc(
                f"class add dev {self.lan_interface} parent 1: classid 1:{class_id} "
                f"htb rate 100mbit ceil 100mbit",
                ignore_errors=True  # May already exist
            )

            # Delete existing netem qdisc if present
            self._run_tc(
                f"qdisc del dev {self.lan_interface} parent 1:{class_id} handle {class_id}:",
                ignore_errors=True
            )

            # Add netem qdisc with latency/loss
            tc_params = config.to_tc_params()
            if tc_params:
                self._run_tc(
                    f"qdisc add dev {self.lan_interface} parent 1:{class_id} "
                    f"handle {class_id}: netem {tc_params}"
                )

            # Add iptables MARK rule to classify traffic from this IP
            mark = class_id
            self._run_iptables(
                f"-t mangle -A PREROUTING -s {device_ip} -j MARK --set-mark {mark}",
                ignore_errors=True
            )

            # Add tc filter to route marked traffic to the class
            self._run_tc(
                f"filter add dev {self.lan_interface} parent 1: protocol ip prio 1 "
                f"handle {mark} fw classid 1:{class_id}",
                ignore_errors=True
            )

            return True

        except Exception as e:
            logger.error(f"Failed to apply tc friction: {e}")
            return False

    def _clear_tc_friction(self, device_ip: str) -> bool:
        """Clear tc rules for a device."""
        class_id = self._class_ids.get(device_ip)
        if not class_id:
            return True  # Nothing to clear

        try:
            # Remove iptables mark rule
            self._run_iptables(
                f"-t mangle -D PREROUTING -s {device_ip} -j MARK --set-mark {class_id}",
                ignore_errors=True
            )

            # Remove netem qdisc
            self._run_tc(
                f"qdisc del dev {self.lan_interface} parent 1:{class_id}",
                ignore_errors=True
            )

            # Remove class
            self._run_tc(
                f"class del dev {self.lan_interface} classid 1:{class_id}",
                ignore_errors=True
            )

            return True

        except Exception as e:
            logger.error(f"Failed to clear tc friction: {e}")
            return False

    def _get_class_id(self, device_ip: str) -> int:
        """Get or create a tc class ID for an IP."""
        if device_ip not in self._class_ids:
            self._class_ids[device_ip] = self._next_class_id
            self._next_class_id += 1
        return self._class_ids[device_ip]

    def _escalate_level(self, current: FrictionLevel) -> FrictionLevel:
        """Escalate to the next friction level."""
        levels = list(FrictionLevel)
        current_idx = levels.index(current)
        if current_idx < len(levels) - 1:
            return levels[current_idx + 1]
        return current

    # =========================================================================
    # Friction Management
    # =========================================================================

    def clear_friction(self, device_ip: str) -> bool:
        """
        Clear friction for a device.

        Args:
            device_ip: Device IP to clear

        Returns:
            True if successful

        Raises:
            ValueError: If device_ip is not a valid IP address
        """
        # Security: Validate IP address
        if not validate_ip(device_ip):
            raise ValueError(f"Invalid IP address: {device_ip}")

        with self._lock:
            if device_ip not in self._active_friction:
                return True

            record = self._active_friction[device_ip]
            success = self._clear_tc_friction(device_ip)

            if success:
                del self._active_friction[device_ip]
                self._stats["friction_cleared"] += 1

                # Notify callbacks
                for callback in self._callbacks:
                    try:
                        callback(record, "cleared")
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                logger.info(f"Cleared friction for {device_ip}")

            return success

    def clear_all_friction(self) -> int:
        """Clear friction for all devices."""
        with self._lock:
            cleared = 0
            for ip in list(self._active_friction.keys()):
                if self._clear_tc_friction(ip):
                    del self._active_friction[ip]
                    cleared += 1
            self._stats["friction_cleared"] += cleared
            return cleared

    def expire_old_friction(self) -> int:
        """Expire friction records past their expiration time."""
        with self._lock:
            now = datetime.now()
            expired = 0

            for ip in list(self._active_friction.keys()):
                record = self._active_friction[ip]
                if record.expires_at and record.expires_at < now:
                    if self._clear_tc_friction(ip):
                        del self._active_friction[ip]
                        expired += 1
                        logger.info(f"Friction expired for {ip}")

            return expired

    def update_qsecbit_score(self, device_ip: str, new_score: float) -> Optional[FrictionRecord]:
        """
        Update friction based on new QSecBit score.

        Args:
            device_ip: Device IP address
            new_score: Updated QSecBit score

        Returns:
            Updated FrictionRecord or None

        Raises:
            ValueError: If device_ip is not a valid IP address
        """
        # Security: Validate IP address
        if not validate_ip(device_ip):
            raise ValueError(f"Invalid IP address: {device_ip}")

        with self._lock:
            existing = self._active_friction.get(device_ip)
            new_level = self.get_friction_level(new_score)

            # If no existing friction and score warrants it, apply
            if not existing and new_level != FrictionLevel.NONE:
                return self.apply_friction(
                    device_ip, new_score,
                    reason="QSecBit score update"
                )

            # If existing and level changed, update
            if existing and existing.level != new_level:
                if new_level == FrictionLevel.NONE:
                    self.clear_friction(device_ip)
                    return None
                else:
                    # Re-apply with new level
                    return self.apply_friction(
                        device_ip, new_score,
                        device_mac=existing.device_mac,
                        reason=existing.reason,
                        mitre_ids=existing.mitre_ids,
                    )

            return existing

    # =========================================================================
    # Query & Stats
    # =========================================================================

    def get_friction(self, device_ip: str) -> Optional[FrictionRecord]:
        """Get current friction record for a device."""
        return self._active_friction.get(device_ip)

    def get_all_friction(self) -> Dict[str, FrictionRecord]:
        """Get all active friction records."""
        return dict(self._active_friction)

    def get_friction_by_level(self, level: FrictionLevel) -> List[FrictionRecord]:
        """Get all friction records at a specific level."""
        return [
            r for r in self._active_friction.values()
            if r.level == level
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        level_counts = {}
        for level in FrictionLevel:
            level_counts[level.value] = len(self.get_friction_by_level(level))

        return {
            **self._stats,
            "active_friction_count": len(self._active_friction),
            "level_distribution": level_counts,
            "lan_interface": self.lan_interface,
            "dry_run": self.dry_run,
        }

    def add_callback(self, callback: Callable[[FrictionRecord, str], None]) -> None:
        """Add callback for friction events."""
        self._callbacks.append(callback)

    # =========================================================================
    # Integration with Playbook Engine
    # =========================================================================

    def handle_suricata_alert(self, alert: Dict[str, Any]) -> Optional[FrictionRecord]:
        """
        Handle a Suricata alert and apply appropriate friction.

        Args:
            alert: Suricata EVE JSON alert

        Returns:
            FrictionRecord if friction was applied
        """
        src_ip = alert.get("src_ip", "")
        if not src_ip:
            return None

        # Get MITRE info if available
        try:
            from .mitre_mapping import get_mitre_mapper
            mapper = get_mitre_mapper()
            sid = alert.get("alert", {}).get("signature_id", 0)
            mitre_info = mapper.get_by_sid(sid) if sid else None
        except ImportError:
            mitre_info = None

        # Calculate QSecBit adjustment based on alert severity
        alert_severity = alert.get("alert", {}).get("severity", 3)
        severity_scores = {1: 0.9, 2: 0.7, 3: 0.5, 4: 0.3}
        base_score = severity_scores.get(alert_severity, 0.5)

        signature = alert.get("alert", {}).get("signature", "Unknown")
        mitre_ids = [mitre_info["mitre_id"]] if mitre_info else []

        return self.apply_friction(
            device_ip=src_ip,
            qsecbit_score=base_score,
            reason=f"Suricata: {signature}",
            mitre_ids=mitre_ids,
        )


# Singleton instance
_engine: Optional[DynamicFrictionEngine] = None


def get_friction_engine(dry_run: bool = False) -> DynamicFrictionEngine:
    """Get or create the singleton friction engine."""
    global _engine

    if _engine is None:
        _engine = DynamicFrictionEngine(dry_run=dry_run)

    return _engine


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    engine = DynamicFrictionEngine(dry_run=True)

    print("Dynamic Friction Engine Demo")
    print("=" * 60)

    # Test friction levels
    test_scores = [0.1, 0.4, 0.6, 0.8, 0.95]
    for score in test_scores:
        level = engine.get_friction_level(score)
        config = FRICTION_CONFIGS[level]
        print(f"\nQSecBit {score:.2f} -> {level.value}")
        print(f"  Latency: {config.latency_ms}ms, Loss: {config.packet_loss_pct}%")
        print(f"  Description: {config.description}")

    # Test applying friction
    print("\n" + "=" * 60)
    print("Applying friction to test IPs...")

    record = engine.apply_friction(
        device_ip="10.200.0.50",
        qsecbit_score=0.65,
        reason="Internal port scan detected",
        mitre_ids=["T1046"],
    )

    print(f"\nApplied to {record.device_ip}:")
    print(f"  Level: {record.level.value}")
    print(f"  QSecBit: {record.qsecbit_score}")
    print(f"  Reason: {record.reason}")
    print(f"  Expires: {record.expires_at}")

    # Show stats
    print("\n" + "=" * 60)
    stats = engine.get_stats()
    print(f"Statistics:")
    for k, v in stats.items():
        print(f"  {k}: {v}")
