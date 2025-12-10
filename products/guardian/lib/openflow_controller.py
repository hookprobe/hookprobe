"""
Guardian-specific OpenFlow Extensions

Provides Guardian-specific SDN components built on the shared OpenFlow
infrastructure. Includes VLAN definitions and OVS management utilities.

Author: HookProbe Team
Version: 5.0.0 Cortex
License: AGPL-3.0 - see LICENSE in this directory
"""

import asyncio
import json
import logging
from enum import IntEnum
from typing import Dict, List, Any, Optional

# Import base classes from shared SDN module
from shared.network.sdn import (
    OpenFlowController,
    FlowEntry,
    FlowMatch,
    FlowAction,
    SwitchFeatures,
    OVSBridge,
    VLANRange,
    OFP_CONSTANTS,
    OFPType,
    OFPActionType,
    OFPFlowModCommand,
    OFPPort,
    OFP_VERSION,
    OFP_HEADER_SIZE
)

logger = logging.getLogger(__name__)


# =============================================================================
# GUARDIAN-SPECIFIC VLAN ASSIGNMENTS
# =============================================================================

class GuardianVLAN(IntEnum):
    """Guardian-specific VLAN assignments for network segmentation"""
    MANAGEMENT = 10
    TRUSTED = 100
    GUEST = 200
    IOT = 300
    QUARANTINE = 666
    HOSTILE = 999


# =============================================================================
# OVS MANAGEMENT INTERFACE
# =============================================================================

class OVSManager:
    """
    Open vSwitch management interface

    Provides high-level OVS configuration through ovs-vsctl and ovs-ofctl.
    Guardian-specific implementation for travel router deployments.
    """

    def __init__(self, bridge_name: str = 'br-guardian'):
        self.bridge_name = bridge_name
        self._ovs_available = None

    async def _check_ovs(self) -> bool:
        """Check if OVS is available"""
        if self._ovs_available is not None:
            return self._ovs_available

        try:
            proc = await asyncio.create_subprocess_exec(
                'ovs-vsctl', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            self._ovs_available = proc.returncode == 0
        except FileNotFoundError:
            self._ovs_available = False

        return self._ovs_available

    async def create_bridge(self) -> bool:
        """Create OVS bridge"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--may-exist', 'add-br', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error(f"Failed to create bridge: {stderr.decode()}")
            return False

        return True

    async def delete_bridge(self) -> bool:
        """Delete OVS bridge"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--if-exists', 'del-br', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def add_port(self, port_name: str, vlan: Optional[int] = None) -> bool:
        """Add port to bridge"""
        if not await self._check_ovs():
            return False

        cmd = ['ovs-vsctl', '--may-exist', 'add-port', self.bridge_name, port_name]

        if vlan:
            cmd.extend(['tag=' + str(vlan)])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def del_port(self, port_name: str) -> bool:
        """Remove port from bridge"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--if-exists', 'del-port', self.bridge_name, port_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def set_controller(self, controller_addr: str) -> bool:
        """Set OpenFlow controller"""
        if not await self._check_ovs():
            return False

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', 'set-controller', self.bridge_name, controller_addr,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def set_protocols(self, protocols: List[str]) -> bool:
        """Set supported OpenFlow protocols"""
        if not await self._check_ovs():
            return False

        proto_str = ','.join(protocols)
        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', 'set', 'bridge', self.bridge_name,
            f'protocols={proto_str}',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def get_ports(self) -> List[str]:
        """Get list of ports on bridge"""
        if not await self._check_ovs():
            return []

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', 'list-ports', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0:
            return []

        return stdout.decode().strip().split('\n') if stdout.strip() else []

    async def get_bridge_info(self) -> Dict[str, Any]:
        """Get bridge information"""
        if not await self._check_ovs():
            return {}

        proc = await asyncio.create_subprocess_exec(
            'ovs-vsctl', '--format=json', 'list', 'bridge', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0:
            return {}

        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError:
            return {}

    async def add_flow(
        self,
        priority: int,
        match: str,
        actions: str,
        table: int = 0
    ) -> bool:
        """Add flow using ovs-ofctl"""
        if not await self._check_ovs():
            return False

        flow_spec = f"table={table},priority={priority},{match},actions={actions}"

        proc = await asyncio.create_subprocess_exec(
            'ovs-ofctl', '-O', 'OpenFlow13', 'add-flow', self.bridge_name, flow_spec,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def del_flows(self, match: str = '') -> bool:
        """Delete flows matching criteria"""
        if not await self._check_ovs():
            return False

        cmd = ['ovs-ofctl', '-O', 'OpenFlow13', 'del-flows', self.bridge_name]
        if match:
            cmd.append(match)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        return proc.returncode == 0

    async def dump_flows(self) -> List[str]:
        """Dump all flows"""
        if not await self._check_ovs():
            return []

        proc = await asyncio.create_subprocess_exec(
            'ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', self.bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0:
            return []

        return stdout.decode().strip().split('\n')


# Re-export shared classes for backwards compatibility
__all__ = [
    # Guardian-specific
    'OVSManager',
    'GuardianVLAN',
    # Re-exported from shared for convenience
    'OFPType',
    'OFPActionType',
    'OFPFlowModCommand',
    'OFPPort',
]
