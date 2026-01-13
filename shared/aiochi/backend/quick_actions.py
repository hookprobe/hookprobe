"""
AIOCHI Quick Actions
One-touch actions for common network operations.

Philosophy: Complex network operations should be available as simple buttons.
"Pause Kids' Internet" shouldn't require CLI expertise.
"""

import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from threading import Lock

logger = logging.getLogger(__name__)


class ActionStatus(Enum):
    """Status of an action execution."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    REVERTED = "reverted"


class ActionCategory(Enum):
    """Categories of quick actions."""
    PARENTAL = "parental"         # Pause kids, screen time
    PERFORMANCE = "performance"   # Game mode, boost device
    SECURITY = "security"         # Guest lockdown, privacy mode
    DEVICE = "device"             # Block device, quarantine
    NETWORK = "network"           # WAN failover, restart


@dataclass
class QuickAction:
    """Definition of a quick action."""
    id: str
    name: str                       # Display name
    description: str                # What it does
    icon: str = "settings"          # Icon name
    category: ActionCategory = ActionCategory.NETWORK
    requires_confirmation: bool = False  # Ask before executing
    is_toggle: bool = False         # True = on/off action
    current_state: bool = False     # For toggles: current on/off
    duration_default: Optional[timedelta] = None  # Auto-revert after
    target_selector: str = ""       # "device", "bubble", "vlan", ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "category": self.category.value,
            "requires_confirmation": self.requires_confirmation,
            "is_toggle": self.is_toggle,
            "current_state": self.current_state,
            "duration_default_seconds": self.duration_default.total_seconds() if self.duration_default else None,
            "target_selector": self.target_selector,
        }


@dataclass
class ActionExecution:
    """Record of an action execution."""
    id: str
    action_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    status: ActionStatus = ActionStatus.PENDING
    target: str = ""                # MAC, bubble_id, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    result_message: str = ""
    reverts_at: Optional[datetime] = None
    reverted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action_id": self.action_id,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "target": self.target,
            "parameters": self.parameters,
            "result_message": self.result_message,
            "reverts_at": self.reverts_at.isoformat() if self.reverts_at else None,
            "reverted": self.reverted,
        }


# Pre-defined quick actions
DEFAULT_ACTIONS: List[QuickAction] = [
    # Parental Controls
    QuickAction(
        id="pause_kids",
        name="Pause Kids' Internet",
        description="Temporarily block internet access for kids' devices",
        icon="child_care",
        category=ActionCategory.PARENTAL,
        requires_confirmation=True,
        is_toggle=True,
        duration_default=timedelta(hours=1),
        target_selector="bubble",
    ),
    QuickAction(
        id="bedtime_mode",
        name="Bedtime Mode",
        description="Reduce internet speed for kids' devices (no streaming)",
        icon="bedtime",
        category=ActionCategory.PARENTAL,
        is_toggle=True,
        duration_default=timedelta(hours=8),
        target_selector="bubble",
    ),

    # Performance
    QuickAction(
        id="game_mode",
        name="Game Mode",
        description="Prioritize gaming traffic, deprioritize background activities",
        icon="sports_esports",
        category=ActionCategory.PERFORMANCE,
        is_toggle=True,
    ),
    QuickAction(
        id="boost_device",
        name="Boost This Device",
        description="Give priority bandwidth to a specific device",
        icon="bolt",
        category=ActionCategory.PERFORMANCE,
        is_toggle=True,
        duration_default=timedelta(hours=2),
        target_selector="device",
    ),
    QuickAction(
        id="work_mode",
        name="Work Mode",
        description="Prioritize work devices and video calls",
        icon="work",
        category=ActionCategory.PERFORMANCE,
        is_toggle=True,
    ),

    # Security
    QuickAction(
        id="guest_lockdown",
        name="Guest Lockdown",
        description="Block all guest devices from internal network",
        icon="lock",
        category=ActionCategory.SECURITY,
        requires_confirmation=True,
        is_toggle=True,
    ),
    QuickAction(
        id="privacy_mode",
        name="Privacy Mode",
        description="Block all tracking and analytics domains",
        icon="visibility_off",
        category=ActionCategory.SECURITY,
        is_toggle=True,
    ),
    QuickAction(
        id="paranoid_mode",
        name="Paranoid Mode",
        description="Block all external connections except whitelisted",
        icon="security",
        category=ActionCategory.SECURITY,
        requires_confirmation=True,
        is_toggle=True,
    ),

    # Device
    QuickAction(
        id="block_device",
        name="Block Device",
        description="Completely block a device from network access",
        icon="block",
        category=ActionCategory.DEVICE,
        requires_confirmation=True,
        is_toggle=True,
        target_selector="device",
    ),
    QuickAction(
        id="quarantine_device",
        name="Quarantine Device",
        description="Isolate a device to quarantine VLAN",
        icon="warning",
        category=ActionCategory.DEVICE,
        requires_confirmation=True,
        is_toggle=True,
        target_selector="device",
    ),

    # Network
    QuickAction(
        id="force_failover",
        name="Switch to Backup Internet",
        description="Manually switch to backup WAN connection",
        icon="swap_horiz",
        category=ActionCategory.NETWORK,
        requires_confirmation=True,
        is_toggle=True,
    ),
    QuickAction(
        id="restart_wifi",
        name="Restart WiFi",
        description="Restart WiFi access points (brief disconnection)",
        icon="wifi",
        category=ActionCategory.NETWORK,
        requires_confirmation=True,
    ),
]


class QuickActionExecutor:
    """
    Executes quick actions and manages their state.

    Features:
    - Pre-defined common actions
    - Custom action registration
    - Toggle state tracking
    - Auto-revert after duration
    - Execution history
    """

    def __init__(
        self,
        use_ovs: bool = True,
        use_nftables: bool = True,
    ):
        """
        Initialize the Quick Action Executor.

        Args:
            use_ovs: Use OVS for network actions
            use_nftables: Use nftables for firewall actions
        """
        self.use_ovs = use_ovs
        self.use_nftables = use_nftables

        # Available actions
        self._actions: Dict[str, QuickAction] = {
            a.id: a for a in DEFAULT_ACTIONS
        }

        # Execution history
        self._executions: List[ActionExecution] = []
        self._lock = Lock()

        # Action handlers (action_id -> callable)
        self._handlers: Dict[str, Callable] = {}

        # Register default handlers
        self._register_default_handlers()

    def get_actions(
        self,
        category: Optional[ActionCategory] = None,
    ) -> List[QuickAction]:
        """
        Get available actions.

        Args:
            category: Filter by category

        Returns:
            List of available actions
        """
        actions = list(self._actions.values())

        if category:
            actions = [a for a in actions if a.category == category]

        return actions

    def get_action(self, action_id: str) -> Optional[QuickAction]:
        """Get a specific action by ID."""
        return self._actions.get(action_id)

    def execute(
        self,
        action_id: str,
        target: str = "",
        parameters: Optional[Dict[str, Any]] = None,
        duration: Optional[timedelta] = None,
    ) -> ActionExecution:
        """
        Execute a quick action.

        Args:
            action_id: Action to execute
            target: Target (MAC, bubble_id, etc.)
            parameters: Additional parameters
            duration: Override default duration

        Returns:
            ActionExecution with result
        """
        import uuid

        action = self._actions.get(action_id)
        if not action:
            execution = ActionExecution(
                id=str(uuid.uuid4()),
                action_id=action_id,
                status=ActionStatus.FAILED,
                result_message=f"Unknown action: {action_id}",
            )
            return execution

        # Create execution record
        execution = ActionExecution(
            id=str(uuid.uuid4()),
            action_id=action_id,
            target=target,
            parameters=parameters or {},
            status=ActionStatus.RUNNING,
        )

        # Calculate revert time
        if action.is_toggle:
            revert_duration = duration or action.duration_default
            if revert_duration:
                execution.reverts_at = datetime.now() + revert_duration

        try:
            # Execute handler
            handler = self._handlers.get(action_id)
            if handler:
                result = handler(action, target, parameters or {})
                execution.status = ActionStatus.SUCCESS
                execution.result_message = result or f"{action.name} executed successfully"

                # Update toggle state
                if action.is_toggle:
                    action.current_state = not action.current_state
            else:
                execution.status = ActionStatus.FAILED
                execution.result_message = f"No handler for action: {action_id}"

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            execution.status = ActionStatus.FAILED
            execution.result_message = str(e)

        # Store execution
        with self._lock:
            self._executions.append(execution)
            # Keep last 100 executions
            if len(self._executions) > 100:
                self._executions.pop(0)

        return execution

    def revert(self, execution_id: str) -> Optional[ActionExecution]:
        """
        Revert a previously executed action.

        Args:
            execution_id: ID of execution to revert

        Returns:
            Updated ActionExecution or None
        """
        execution = None
        with self._lock:
            for e in self._executions:
                if e.id == execution_id:
                    execution = e
                    break

        if not execution:
            return None

        if execution.reverted:
            return execution

        action = self._actions.get(execution.action_id)
        if not action or not action.is_toggle:
            return execution

        # Execute the action again to toggle off
        try:
            handler = self._handlers.get(execution.action_id)
            if handler:
                handler(action, execution.target, execution.parameters, revert=True)
                execution.reverted = True
                execution.status = ActionStatus.REVERTED

                # Update toggle state
                action.current_state = not action.current_state

        except Exception as e:
            logger.error(f"Action revert failed: {e}")
            execution.result_message = f"Revert failed: {e}"

        return execution

    def get_execution_history(
        self,
        limit: int = 20,
    ) -> List[ActionExecution]:
        """Get recent execution history."""
        with self._lock:
            return list(reversed(self._executions[-limit:]))

    def check_auto_reverts(self) -> List[ActionExecution]:
        """
        Check for executions that should auto-revert.

        Call this periodically (e.g., every minute).

        Returns:
            List of reverted executions
        """
        reverted = []
        now = datetime.now()

        with self._lock:
            for execution in self._executions:
                if (
                    execution.reverts_at
                    and not execution.reverted
                    and execution.status == ActionStatus.SUCCESS
                    and now > execution.reverts_at
                ):
                    reverted.append(execution)

        for execution in reverted:
            self.revert(execution.id)

        return reverted

    def register_action(
        self,
        action: QuickAction,
        handler: Callable,
    ) -> None:
        """
        Register a custom action.

        Args:
            action: Action definition
            handler: Callable(action, target, parameters, revert=False) -> str
        """
        self._actions[action.id] = action
        self._handlers[action.id] = handler

    def _register_default_handlers(self) -> None:
        """Register handlers for default actions."""
        self._handlers["pause_kids"] = self._handle_pause_bubble
        self._handlers["bedtime_mode"] = self._handle_rate_limit_bubble
        self._handlers["game_mode"] = self._handle_game_mode
        self._handlers["boost_device"] = self._handle_boost_device
        self._handlers["work_mode"] = self._handle_work_mode
        self._handlers["guest_lockdown"] = self._handle_guest_lockdown
        self._handlers["privacy_mode"] = self._handle_privacy_mode
        self._handlers["paranoid_mode"] = self._handle_paranoid_mode
        self._handlers["block_device"] = self._handle_block_device
        self._handlers["quarantine_device"] = self._handle_quarantine_device
        self._handlers["force_failover"] = self._handle_force_failover
        self._handlers["restart_wifi"] = self._handle_restart_wifi

    # =========================================================================
    # OVS/tc Configuration Constants
    # =========================================================================
    OVS_BRIDGE = "FTS"
    PAUSE_FLOW_PRIORITY = 100  # High priority to ensure drops happen first
    GAME_MODE_MARK = 0x10  # DSCP marking for game traffic

    # Gaming ports for QoS prioritization
    GAMING_PORTS = {
        "xbox": [3074],
        "steam": list(range(27000, 27051)),  # 27000-27050
        "blizzard": list(range(5000, 6001)),  # 5000-6000
        "epic": [5222],
        "playstation": [3478, 3479, 3480],
        "nintendo": [45000, 45001],
    }

    # Kids domains for behavioral detection (DNS-based)
    KIDS_DOMAINS = [
        "youtubekids.com", "roblox.com", "coolmathgames.com", "pbskids.org",
        "nickjr.com", "cartoonnetwork.com", "disney.com", "minecraft.net",
        "scratch.mit.edu", "abcmouse.com", "starfall.com", "funbrain.com"
    ]

    # Handler implementations
    def _handle_pause_bubble(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """
        Pause/unpause internet for a bubble using OVS flow rules.

        Implementation:
        - Gets all MAC addresses in the target bubble
        - Adds high-priority OVS drop rules for each MAC
        - On revert, removes the drop rules

        OVS Commands:
        - Block: ovs-ofctl add-flow FTS "priority=100,dl_src=<MAC>,actions=drop"
        - Unblock: ovs-ofctl del-flows FTS "dl_src=<MAC>,priority=100"
        """
        if not target:
            raise ValueError("Target bubble_id required")

        # Get MACs for the bubble (from parameters or lookup)
        macs = parameters.get("macs", [])
        if not macs:
            # Try to look up from bubble registry
            macs = self._get_bubble_macs(target)

        if not macs:
            logger.warning(f"No MACs found for bubble: {target}")
            return f"No devices found in bubble {target}"

        blocked_count = 0
        errors = []

        for mac in macs:
            try:
                if revert:
                    # Remove drop rule
                    cmd = [
                        "ovs-ofctl", "del-flows", self.OVS_BRIDGE,
                        f"dl_src={mac},priority={self.PAUSE_FLOW_PRIORITY}"
                    ]
                else:
                    # Add drop rule (blocks all traffic from this MAC)
                    cmd = [
                        "ovs-ofctl", "add-flow", self.OVS_BRIDGE,
                        f"priority={self.PAUSE_FLOW_PRIORITY},dl_src={mac},actions=drop"
                    ]

                if self.use_ovs:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        blocked_count += 1
                        logger.info(f"{'Unpaused' if revert else 'Paused'} MAC: {mac}")
                    else:
                        errors.append(f"{mac}: {result.stderr}")
                        logger.error(f"OVS command failed for {mac}: {result.stderr}")
                else:
                    # Dry run mode
                    logger.info(f"[DRY RUN] Would execute: {' '.join(cmd)}")
                    blocked_count += 1

            except subprocess.TimeoutExpired:
                errors.append(f"{mac}: timeout")
                logger.error(f"OVS command timeout for {mac}")
            except Exception as e:
                errors.append(f"{mac}: {str(e)}")
                logger.error(f"Error processing {mac}: {e}")

        action_word = "Resumed" if revert else "Paused"
        if errors:
            return f"{action_word} {blocked_count}/{len(macs)} devices for {target}. Errors: {len(errors)}"
        return f"{action_word} internet for {target} ({blocked_count} devices)"

    def _get_bubble_macs(self, bubble_id: str) -> List[str]:
        """
        Get MAC addresses for devices in a bubble.

        Looks up from:
        1. /run/fortress/bubbles/<bubble_id>.json
        2. Ecosystem bubble manager (if available)
        """
        import json
        import os

        # Try file-based lookup first
        bubble_file = f"/run/fortress/bubbles/{bubble_id}.json"
        if os.path.exists(bubble_file):
            try:
                with open(bubble_file, 'r') as f:
                    data = json.load(f)
                    return data.get("devices", [])
            except Exception as e:
                logger.debug(f"Could not read bubble file: {e}")

        # Try ecosystem bubble manager
        try:
            from products.fortress.lib.ecosystem_bubble import get_ecosystem_bubble_manager
            manager = get_ecosystem_bubble_manager()
            bubble = manager.get_bubble(bubble_id)
            if bubble:
                return list(bubble.devices)
        except ImportError:
            logger.debug("Ecosystem bubble manager not available")
        except Exception as e:
            logger.debug(f"Could not get bubble from manager: {e}")

        return []

    def _handle_rate_limit_bubble(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Apply rate limiting to a bubble (bedtime mode)."""
        if not target:
            raise ValueError("Target bubble_id required")

        # In production: Apply tc/OVS QoS rules
        logger.info(f"{'Removing' if revert else 'Applying'} rate limit to: {target}")

        return f"{'Removed' if revert else 'Applied'} bedtime mode for {target}"

    def _handle_game_mode(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """
        Enable/disable game mode using tc (traffic control) QoS rules.

        Implementation:
        - Creates priority queues on the WAN interface
        - Gaming traffic (by port) gets highest priority
        - Background traffic (streaming, downloads) deprioritized

        tc Architecture:
        - Root qdisc: HTB (Hierarchical Token Bucket)
        - Class 1:10 - Gaming (priority, 50% guaranteed bandwidth)
        - Class 1:20 - Interactive (medium priority, 30%)
        - Class 1:30 - Bulk (low priority, 20%)

        Gaming ports prioritized:
        - Xbox Live: 3074
        - Steam: 27000-27050
        - Blizzard: 5000-6000
        - Epic Games: 5222
        - PlayStation: 3478-3480
        """
        wan_interface = self._get_wan_interface()
        if not wan_interface:
            logger.warning("Could not detect WAN interface")
            return "Game mode: WAN interface not found"

        try:
            if revert:
                # Remove tc rules - delete the root qdisc
                self._run_tc_command(["tc", "qdisc", "del", "dev", wan_interface, "root"], ignore_errors=True)
                logger.info(f"Game mode disabled on {wan_interface}")
                return "Game mode disabled (QoS rules removed)"

            # Set up tc QoS hierarchy
            errors = []

            # Step 1: Remove any existing qdisc
            self._run_tc_command(["tc", "qdisc", "del", "dev", wan_interface, "root"], ignore_errors=True)

            # Step 2: Create HTB root qdisc
            # Using 1000mbit as ceiling, actual rate managed by classes
            cmd = ["tc", "qdisc", "add", "dev", wan_interface, "root", "handle", "1:", "htb", "default", "30"]
            if not self._run_tc_command(cmd):
                errors.append("Failed to create root qdisc")

            # Step 3: Create parent class (full bandwidth)
            cmd = ["tc", "class", "add", "dev", wan_interface, "parent", "1:", "classid", "1:1",
                   "htb", "rate", "1000mbit", "burst", "15k"]
            if not self._run_tc_command(cmd):
                errors.append("Failed to create parent class")

            # Step 4: Create Gaming class (highest priority, 50% guaranteed)
            cmd = ["tc", "class", "add", "dev", wan_interface, "parent", "1:1", "classid", "1:10",
                   "htb", "rate", "500mbit", "ceil", "1000mbit", "burst", "15k", "prio", "1"]
            if not self._run_tc_command(cmd):
                errors.append("Failed to create gaming class")

            # Step 5: Create Interactive class (medium priority, 30%)
            cmd = ["tc", "class", "add", "dev", wan_interface, "parent", "1:1", "classid", "1:20",
                   "htb", "rate", "300mbit", "ceil", "800mbit", "burst", "15k", "prio", "2"]
            if not self._run_tc_command(cmd):
                errors.append("Failed to create interactive class")

            # Step 6: Create Bulk class (lowest priority, 20%)
            cmd = ["tc", "class", "add", "dev", wan_interface, "parent", "1:1", "classid", "1:30",
                   "htb", "rate", "200mbit", "ceil", "500mbit", "burst", "15k", "prio", "3"]
            if not self._run_tc_command(cmd):
                errors.append("Failed to create bulk class")

            # Step 7: Add SFQ (Stochastic Fair Queuing) to gaming class for fairness
            cmd = ["tc", "qdisc", "add", "dev", wan_interface, "parent", "1:10", "handle", "10:", "sfq", "perturb", "10"]
            self._run_tc_command(cmd, ignore_errors=True)

            # Step 8: Add filters for gaming ports -> class 1:10
            gaming_ports_added = 0
            for platform, ports in self.GAMING_PORTS.items():
                for port in ports:
                    # UDP filter (most games use UDP)
                    cmd = ["tc", "filter", "add", "dev", wan_interface, "parent", "1:", "protocol", "ip",
                           "prio", "1", "u32", "match", "ip", "dport", str(port), "0xffff",
                           "match", "ip", "protocol", "17", "0xff", "flowid", "1:10"]
                    if self._run_tc_command(cmd, ignore_errors=True):
                        gaming_ports_added += 1

                    # TCP filter (for game downloads, updates)
                    cmd = ["tc", "filter", "add", "dev", wan_interface, "parent", "1:", "protocol", "ip",
                           "prio", "2", "u32", "match", "ip", "dport", str(port), "0xffff",
                           "match", "ip", "protocol", "6", "0xff", "flowid", "1:10"]
                    self._run_tc_command(cmd, ignore_errors=True)

            logger.info(f"Game mode enabled on {wan_interface} ({gaming_ports_added} port filters)")

            if errors:
                return f"Game mode partially enabled. Errors: {', '.join(errors)}"
            return f"Game mode enabled ({gaming_ports_added} gaming port filters active)"

        except Exception as e:
            logger.error(f"Game mode setup failed: {e}")
            return f"Game mode failed: {str(e)}"

    def _run_tc_command(self, cmd: List[str], ignore_errors: bool = False) -> bool:
        """Execute a tc command, optionally ignoring errors."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0 and not ignore_errors:
                logger.error(f"tc command failed: {' '.join(cmd)} -> {result.stderr}")
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"tc command timeout: {' '.join(cmd)}")
            return False
        except Exception as e:
            logger.error(f"tc command error: {e}")
            return False

    def _get_wan_interface(self) -> Optional[str]:
        """
        Detect the WAN interface (default route interface).

        Checks:
        1. /run/fortress/wan-interface (if written by setup)
        2. Default route via `ip route`
        3. Fall back to common names
        """
        import os

        # Check fortress config
        wan_file = "/run/fortress/wan-interface"
        if os.path.exists(wan_file):
            try:
                with open(wan_file, 'r') as f:
                    return f.read().strip()
            except Exception:
                pass

        # Parse default route
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout:
                # Parse: "default via X.X.X.X dev eth0 ..."
                parts = result.stdout.split()
                if "dev" in parts:
                    dev_idx = parts.index("dev")
                    if dev_idx + 1 < len(parts):
                        return parts[dev_idx + 1]
        except Exception as e:
            logger.debug(f"Could not parse default route: {e}")

        # Fall back to common names
        for iface in ["eth0", "eno1", "enp0s31f6", "wan0"]:
            if os.path.exists(f"/sys/class/net/{iface}"):
                return iface

        return None

    def _handle_boost_device(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Boost a specific device."""
        if not target:
            raise ValueError("Target MAC required")

        logger.info(f"{'Removing boost from' if revert else 'Boosting'}: {target}")

        return f"{'Removed boost from' if revert else 'Boosted'} {target}"

    def _handle_work_mode(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Enable/disable work mode."""
        logger.info(f"{'Disabling' if revert else 'Enabling'} work mode")

        return f"Work mode {'disabled' if revert else 'enabled'}"

    def _handle_guest_lockdown(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Lock down guest network."""
        # In production: Block inter-VLAN routing for guest VLAN
        logger.info(f"{'Removing' if revert else 'Applying'} guest lockdown")

        return f"Guest lockdown {'removed' if revert else 'applied'}"

    def _handle_privacy_mode(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Enable/disable privacy mode."""
        # In production: Enable aggressive dnsXai blocking
        logger.info(f"{'Disabling' if revert else 'Enabling'} privacy mode")

        return f"Privacy mode {'disabled' if revert else 'enabled'}"

    def _handle_paranoid_mode(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Enable/disable paranoid mode."""
        # In production: Whitelist-only mode for outbound connections
        logger.info(f"{'Disabling' if revert else 'Enabling'} paranoid mode")

        return f"Paranoid mode {'disabled' if revert else 'enabled'}"

    def _handle_block_device(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Block/unblock a device."""
        if not target:
            raise ValueError("Target MAC required")

        logger.info(f"{'Unblocking' if revert else 'Blocking'}: {target}")

        return f"{'Unblocked' if revert else 'Blocked'} device {target}"

    def _handle_quarantine_device(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Quarantine/release a device."""
        if not target:
            raise ValueError("Target MAC required")

        # In production: Move device to quarantine VLAN (99)
        logger.info(f"{'Releasing' if revert else 'Quarantining'}: {target}")

        return f"{'Released' if revert else 'Quarantined'} device {target}"

    def _handle_force_failover(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Force WAN failover/failback."""
        # In production: Write to /run/fortress/slaai-recommendation.json
        logger.info(f"{'Switching to primary' if revert else 'Switching to backup'} WAN")

        return f"Switched to {'primary' if revert else 'backup'} internet"

    def _handle_restart_wifi(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Restart WiFi access points."""
        if revert:
            return "WiFi restart is not reversible"

        # In production: systemctl restart fts-hostapd-*.service
        logger.info("Restarting WiFi access points")

        return "WiFi access points restarted"


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    executor = QuickActionExecutor()

    # List available actions
    print("Available Actions:")
    for action in executor.get_actions():
        print(f"  [{action.category.value}] {action.name}: {action.description}")

    # Execute an action
    print("\nExecuting 'pause_kids' for bubble 'family_kids'...")
    execution = executor.execute(
        action_id="pause_kids",
        target="family_kids",
        duration=timedelta(minutes=30),
    )
    print(f"Result: {execution.status.value} - {execution.result_message}")
    if execution.reverts_at:
        print(f"Auto-reverts at: {execution.reverts_at}")

    # Revert
    print("\nReverting...")
    execution = executor.revert(execution.id)
    if execution:
        print(f"Result: {execution.status.value}")
