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

    # Handler implementations
    def _handle_pause_bubble(
        self,
        action: QuickAction,
        target: str,
        parameters: Dict[str, Any],
        revert: bool = False,
    ) -> str:
        """Pause/unpause internet for a bubble."""
        if not target:
            raise ValueError("Target bubble_id required")

        # In production, this would:
        # 1. Get all MACs in the bubble
        # 2. Add/remove OVS flow rules to drop traffic
        logger.info(f"{'Unpausing' if revert else 'Pausing'} bubble: {target}")

        # Example OVS command (would be executed in production)
        # ovs-ofctl add-flow FTS "priority=100,dl_src=XX:XX:XX:XX:XX:XX,actions=drop"

        return f"{'Resumed' if revert else 'Paused'} internet for {target}"

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
        """Enable/disable game mode."""
        # In production: Apply QoS rules for gaming traffic
        logger.info(f"{'Disabling' if revert else 'Enabling'} game mode")

        return f"Game mode {'disabled' if revert else 'enabled'}"

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
