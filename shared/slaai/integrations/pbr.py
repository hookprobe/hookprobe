"""
SLA AI PBR Integration

Integrates SLA AI decisions with Fortress Policy-Based Routing.

Responsibilities:
    - Read SLA AI recommendations from state file
    - Execute route table changes via ip/nft commands
    - Coordinate with wan-failover-pbr.sh
    - Manage firewall marks and routing rules
"""

import asyncio
import json
import os
import subprocess
import logging
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, Optional, Callable
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class PBRAction(Enum):
    """PBR actions that can be taken."""
    SWITCH_TO_PRIMARY = "switch_primary"
    SWITCH_TO_BACKUP = "switch_backup"
    HOLD = "hold"
    REFRESH = "refresh"


@dataclass
class RouteConfig:
    """Route configuration for an interface."""
    interface: str
    gateway: str
    table_id: int
    fwmark: int
    priority: int


class PBRIntegration:
    """
    Integration layer between SLA AI and Fortress PBR.

    Reads SLA AI recommendations and executes route changes.
    Works alongside wan-failover-pbr.sh for compatibility.
    """

    # Default paths
    STATE_FILE = "/run/fortress/slaai-recommendation.json"
    PBR_SCRIPT = "/opt/hookprobe/fortress/devices/common/wan-failover-pbr.sh"
    ROUTE_STATE_FILE = "/run/fortress/pbr-state.json"

    # Route table IDs (must match wan-failover-pbr.sh)
    TABLE_PRIMARY = 100
    TABLE_BACKUP = 200

    # Firewall marks
    FWMARK_PRIMARY = 0x100
    FWMARK_BACKUP = 0x200

    def __init__(
        self,
        primary_interface: str = "eth0",
        backup_interface: str = "wwan0",
        primary_gateway: Optional[str] = None,
        backup_gateway: Optional[str] = None,
        use_pbr_script: bool = True,
    ):
        """
        Initialize PBR integration.

        Args:
            primary_interface: Primary WAN interface
            backup_interface: Backup WAN interface
            primary_gateway: Primary gateway IP (auto-detected if None)
            backup_gateway: Backup gateway IP (auto-detected if None)
            use_pbr_script: Use wan-failover-pbr.sh for actions
        """
        self.primary_interface = primary_interface
        self.backup_interface = backup_interface
        self.primary_gateway = primary_gateway or self._detect_gateway(primary_interface)
        self.backup_gateway = backup_gateway or self._detect_gateway(backup_interface)
        self.use_pbr_script = use_pbr_script

        # Current state
        self._active_interface = primary_interface
        self._last_action: Optional[PBRAction] = None
        self._last_action_time: Optional[datetime] = None

        # Route configs
        self._routes = {
            primary_interface: RouteConfig(
                interface=primary_interface,
                gateway=self.primary_gateway or "",
                table_id=self.TABLE_PRIMARY,
                fwmark=self.FWMARK_PRIMARY,
                priority=100,
            ),
            backup_interface: RouteConfig(
                interface=backup_interface,
                gateway=self.backup_gateway or "",
                table_id=self.TABLE_BACKUP,
                fwmark=self.FWMARK_BACKUP,
                priority=200,
            ),
        }

        logger.info(
            f"PBR Integration initialized: "
            f"primary={primary_interface} (gw={self.primary_gateway}), "
            f"backup={backup_interface} (gw={self.backup_gateway})"
        )

    def _detect_gateway(self, interface: str) -> Optional[str]:
        """Detect gateway for an interface."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "dev", interface, "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and result.stdout:
                # Parse: default via X.X.X.X dev eth0
                parts = result.stdout.strip().split()
                if "via" in parts:
                    idx = parts.index("via")
                    return parts[idx + 1]

        except Exception as e:
            logger.warning(f"Failed to detect gateway for {interface}: {e}")

        return None

    def read_recommendation(self) -> Optional[Dict]:
        """
        Read SLA AI recommendation from state file.

        Returns:
            Recommendation dict or None if unavailable
        """
        try:
            if os.path.exists(self.STATE_FILE):
                with open(self.STATE_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read recommendation: {e}")

        return None

    def get_recommended_action(self) -> PBRAction:
        """
        Get recommended action from SLA AI.

        Returns:
            PBRAction to take
        """
        rec = self.read_recommendation()

        if not rec:
            return PBRAction.HOLD

        recommendation = rec.get("recommendation", "hold")

        if recommendation == "failover":
            if self._active_interface != self.backup_interface:
                return PBRAction.SWITCH_TO_BACKUP
        elif recommendation == "failback":
            if self._active_interface != self.primary_interface:
                return PBRAction.SWITCH_TO_PRIMARY

        return PBRAction.HOLD

    async def execute_action(self, action: PBRAction) -> bool:
        """
        Execute a PBR action.

        Args:
            action: PBRAction to execute

        Returns:
            True if successful
        """
        if action == PBRAction.HOLD:
            return True

        logger.info(f"Executing PBR action: {action.value}")

        success = False

        if self.use_pbr_script and os.path.exists(self.PBR_SCRIPT):
            # Use wan-failover-pbr.sh
            success = await self._execute_via_script(action)
        else:
            # Direct execution
            success = await self._execute_direct(action)

        if success:
            self._last_action = action
            self._last_action_time = datetime.now()

            if action == PBRAction.SWITCH_TO_PRIMARY:
                self._active_interface = self.primary_interface
            elif action == PBRAction.SWITCH_TO_BACKUP:
                self._active_interface = self.backup_interface

            # Save state
            self._save_state()

        return success

    async def _execute_via_script(self, action: PBRAction) -> bool:
        """Execute action using wan-failover-pbr.sh."""
        try:
            if action == PBRAction.SWITCH_TO_BACKUP:
                cmd = [self.PBR_SCRIPT, "failover"]
            elif action == PBRAction.SWITCH_TO_PRIMARY:
                cmd = [self.PBR_SCRIPT, "failback"]
            elif action == PBRAction.REFRESH:
                cmd = [self.PBR_SCRIPT, "refresh"]
            else:
                return True

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.error(f"PBR script failed: {result.stderr}")
                return False

            logger.info(f"PBR script executed: {action.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to execute PBR script: {e}")
            return False

    async def _execute_direct(self, action: PBRAction) -> bool:
        """Execute action directly with ip/nft commands."""
        try:
            if action == PBRAction.SWITCH_TO_BACKUP:
                return await self._switch_to_interface(
                    self.backup_interface,
                    self._routes[self.backup_interface],
                )
            elif action == PBRAction.SWITCH_TO_PRIMARY:
                return await self._switch_to_interface(
                    self.primary_interface,
                    self._routes[self.primary_interface],
                )
            elif action == PBRAction.REFRESH:
                return await self._refresh_routes()

            return True

        except Exception as e:
            logger.error(f"Direct PBR execution failed: {e}")
            return False

    async def _switch_to_interface(self, interface: str, config: RouteConfig) -> bool:
        """Switch default route to specified interface."""
        if not config.gateway:
            logger.error(f"No gateway for {interface}")
            return False

        commands = [
            # Remove current default route
            ["ip", "route", "del", "default"],
            # Add new default route via interface
            ["ip", "route", "add", "default", "via", config.gateway, "dev", interface],
            # Update main table priority
            ["ip", "route", "change", "default", "via", config.gateway,
             "dev", interface, "metric", str(config.priority)],
        ]

        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                # Ignore errors on route del (might not exist)
                if "del" not in cmd and result.returncode != 0:
                    logger.warning(f"Command failed: {' '.join(cmd)}: {result.stderr}")
            except Exception as e:
                logger.warning(f"Command error: {' '.join(cmd)}: {e}")

        logger.info(f"Switched to {interface} via {config.gateway}")
        return True

    async def _refresh_routes(self) -> bool:
        """Refresh routing tables."""
        for interface, config in self._routes.items():
            if not config.gateway:
                config.gateway = self._detect_gateway(interface) or ""

            if config.gateway:
                try:
                    # Ensure per-interface route table exists
                    subprocess.run(
                        ["ip", "route", "replace", "default",
                         "via", config.gateway, "dev", interface,
                         "table", str(config.table_id)],
                        capture_output=True,
                        timeout=10,
                    )
                except Exception as e:
                    logger.warning(f"Failed to refresh route for {interface}: {e}")

        return True

    def _save_state(self) -> None:
        """Save current PBR state."""
        state = {
            "active_interface": self._active_interface,
            "last_action": self._last_action.value if self._last_action else None,
            "last_action_time": self._last_action_time.isoformat() if self._last_action_time else None,
            "primary": {
                "interface": self.primary_interface,
                "gateway": self.primary_gateway,
            },
            "backup": {
                "interface": self.backup_interface,
                "gateway": self.backup_gateway,
            },
        }

        try:
            os.makedirs(os.path.dirname(self.ROUTE_STATE_FILE), exist_ok=True)
            with open(self.ROUTE_STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save PBR state: {e}")

    def get_active_interface(self) -> str:
        """Get currently active interface."""
        return self._active_interface

    async def monitor_and_act(
        self,
        check_interval_s: int = 5,
        on_switch: Optional[Callable] = None,
    ) -> None:
        """
        Monitor SLA AI recommendations and act on them.

        Args:
            check_interval_s: Check interval in seconds
            on_switch: Callback when interface switches
        """
        logger.info("Starting PBR monitor loop")

        while True:
            try:
                action = self.get_recommended_action()

                if action != PBRAction.HOLD:
                    old_interface = self._active_interface
                    success = await self.execute_action(action)

                    if success and on_switch and old_interface != self._active_interface:
                        if asyncio.iscoroutinefunction(on_switch):
                            await on_switch(old_interface, self._active_interface)
                        else:
                            on_switch(old_interface, self._active_interface)

            except Exception as e:
                logger.error(f"PBR monitor error: {e}")

            await asyncio.sleep(check_interval_s)

    def setup_source_routing(self) -> bool:
        """
        Setup source-based routing rules.

        Ensures traffic from each interface returns via same interface
        (prevents asymmetric routing).
        """
        try:
            for interface, config in self._routes.items():
                if not config.gateway:
                    continue

                # Get interface IP
                result = subprocess.run(
                    ["ip", "-4", "addr", "show", interface],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode != 0:
                    continue

                # Parse IP address
                import re
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if not match:
                    continue

                ip_addr = match.group(1)

                # Add source-based routing rule
                subprocess.run(
                    ["ip", "rule", "add", "from", ip_addr,
                     "lookup", str(config.table_id), "priority", str(config.priority)],
                    capture_output=True,
                    timeout=5,
                )

                logger.debug(f"Source routing rule added for {interface} ({ip_addr})")

            return True

        except Exception as e:
            logger.error(f"Failed to setup source routing: {e}")
            return False

    def setup_fwmark_routing(self) -> bool:
        """
        Setup fwmark-based routing rules.

        Allows marking packets to use specific route tables.
        """
        try:
            for interface, config in self._routes.items():
                # Add fwmark rule
                subprocess.run(
                    ["ip", "rule", "add", "fwmark", hex(config.fwmark),
                     "lookup", str(config.table_id), "priority", str(config.priority + 10)],
                    capture_output=True,
                    timeout=5,
                )

                logger.debug(f"Fwmark routing rule added for {interface} (mark={hex(config.fwmark)})")

            return True

        except Exception as e:
            logger.error(f"Failed to setup fwmark routing: {e}")
            return False


async def main():
    """Test PBR integration."""
    import argparse

    parser = argparse.ArgumentParser(description="SLA AI PBR Integration")
    parser.add_argument("--primary", default="eth0", help="Primary interface")
    parser.add_argument("--backup", default="wwan0", help="Backup interface")
    parser.add_argument("--monitor", action="store_true", help="Start monitor loop")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    pbr = PBRIntegration(
        primary_interface=args.primary,
        backup_interface=args.backup,
    )

    if args.monitor:
        def on_switch(old, new):
            print(f"Switched: {old} -> {new}")

        await pbr.monitor_and_act(on_switch=on_switch)
    else:
        # Show current recommendation
        rec = pbr.read_recommendation()
        if rec:
            print(json.dumps(rec, indent=2))
        else:
            print("No recommendation available")


if __name__ == "__main__":
    asyncio.run(main())
