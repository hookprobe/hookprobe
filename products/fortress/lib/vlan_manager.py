#!/usr/bin/env python3
"""
Fortress VLAN Manager

Manages VLAN configuration, device assignment, and traffic policies.
Integrates with Open vSwitch and provides API for web UI.
"""

import logging
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

from .config import get_config, VLANConfig
from .database import get_db

logger = logging.getLogger(__name__)


class DNSPolicy(Enum):
    """DNS protection policy levels."""
    MINIMAL = "minimal"      # Malware only
    STANDARD = "standard"    # Malware + Ads
    STRICT = "strict"        # Malware + Ads + Trackers
    MAXIMUM = "maximum"      # All categories blocked


@dataclass
class VLANStatus:
    """Runtime VLAN status."""
    vlan_id: int
    name: str
    subnet: str
    gateway: str
    device_count: int
    active_count: int
    interface_up: bool
    dhcp_running: bool
    dns_policy: str
    bandwidth_used_mbps: float


class VLANManager:
    """
    Manages VLANs for network segmentation.

    Responsibilities:
    - Create/delete VLAN interfaces on OVS bridge
    - Configure DHCP per VLAN
    - Assign devices to VLANs
    - Apply DNS policies per VLAN
    - Monitor VLAN traffic
    """

    def __init__(self):
        self.config = get_config()
        self.db = get_db()
        self.ovs_bridge = self.config.ovs_bridge

    def _run_cmd(self, cmd: List[str], check: bool = False) -> tuple:
        """Run a shell command safely."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            if check and result.returncode != 0:
                logger.error(f"Command failed: {' '.join(cmd)}: {result.stderr}")
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Command error: {e}")
            return False, "", str(e)

    # ========================================
    # VLAN Interface Management
    # ========================================

    def create_vlan_interface(self, vlan_id: int, subnet: str, gateway: str) -> bool:
        """Create VLAN interface on OVS bridge."""
        interface_name = f"vlan{vlan_id}"

        # Check if already exists
        success, _, _ = self._run_cmd(['ip', 'link', 'show', interface_name])
        if success:
            logger.info(f"VLAN interface {interface_name} already exists")
            return True

        # Add internal port to OVS bridge
        success, _, err = self._run_cmd([
            'ovs-vsctl', '--may-exist', 'add-port', self.ovs_bridge, interface_name,
            '--', 'set', 'interface', interface_name, 'type=internal',
            '--', 'set', 'port', interface_name, f'tag={vlan_id}'
        ])

        if not success:
            logger.error(f"Failed to create VLAN port: {err}")
            return False

        # Bring interface up
        self._run_cmd(['ip', 'link', 'set', interface_name, 'up'])

        # Assign gateway IP
        self._run_cmd(['ip', 'addr', 'add', gateway + '/24', 'dev', interface_name])

        logger.info(f"Created VLAN interface {interface_name} ({subnet})")
        return True

    def delete_vlan_interface(self, vlan_id: int) -> bool:
        """Delete VLAN interface."""
        interface_name = f"vlan{vlan_id}"

        # Remove from OVS
        success, _, _ = self._run_cmd([
            'ovs-vsctl', '--if-exists', 'del-port', self.ovs_bridge, interface_name
        ])

        if success:
            logger.info(f"Deleted VLAN interface {interface_name}")

        return success

    def setup_all_vlans(self) -> Dict[int, bool]:
        """Set up all configured VLANs."""
        results = {}
        for name, vlan_config in self.config.vlans.items():
            success = self.create_vlan_interface(
                vlan_config.id,
                vlan_config.subnet,
                vlan_config.gateway
            )
            results[vlan_config.id] = success
        return results

    # ========================================
    # Device Assignment
    # ========================================

    def assign_device_to_vlan(self, mac_address: str, vlan_id: int, reason: str = None) -> bool:
        """
        Assign a device to a VLAN.

        This updates the database and configures OVS flow rules to tag
        traffic from this MAC address with the appropriate VLAN.
        """
        mac = mac_address.upper()

        # Validate VLAN exists
        vlan = self.db.get_vlan(vlan_id)
        if not vlan:
            logger.error(f"VLAN {vlan_id} does not exist")
            return False

        # Update database
        success = self.db.update_device_vlan(mac, vlan_id)
        if not success:
            logger.error(f"Failed to update device {mac} VLAN in database")
            return False

        # Add OVS flow rule for MAC-to-VLAN mapping
        self._add_mac_vlan_flow(mac, vlan_id)

        # Update FreeRADIUS if available
        self._update_radius_vlan(mac, vlan_id)

        logger.info(f"Assigned device {mac} to VLAN {vlan_id} ({vlan['name']})")

        # Audit log
        self.db.audit_log(
            user_id="system",
            action="device_vlan_assign",
            resource_type="device",
            resource_id=mac,
            details={"vlan_id": vlan_id, "reason": reason}
        )

        return True

    def _add_mac_vlan_flow(self, mac: str, vlan_id: int):
        """Add OVS flow rule for MAC-to-VLAN mapping."""
        # Priority 200 for MAC-based VLAN assignment
        self._run_cmd([
            'ovs-ofctl', 'add-flow', self.ovs_bridge,
            f'priority=200,dl_src={mac},actions=mod_vlan_vid:{vlan_id},normal'
        ])

    def _update_radius_vlan(self, mac: str, vlan_id: int):
        """Update FreeRADIUS users file for VLAN assignment."""
        radius_users = Path('/etc/freeradius/3.0/mods-config/files/authorize')
        if not radius_users.exists():
            return

        # Read existing content
        content = radius_users.read_text()

        # Remove existing entry for this MAC
        mac_normalized = mac.replace(':', '-')
        lines = [l for l in content.split('\n') if mac_normalized not in l and mac not in l]

        # Add new entry
        entry = f'''
{mac} Cleartext-Password := "{mac}"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = {vlan_id}
'''
        lines.append(entry)

        # Write back
        radius_users.write_text('\n'.join(lines))

    def auto_assign_device(self, mac_address: str, device_type: str = None) -> int:
        """
        Automatically assign device to appropriate VLAN based on type.

        Returns the assigned VLAN ID.
        """
        mac = mac_address.upper()

        # Check if device is already known
        device = self.db.get_device(mac)
        if device and device.get('is_known'):
            return device['vlan_id']

        # Default VLAN assignments by device type
        vlan_map = {
            'pos_terminal': 20,      # POS VLAN
            'payment': 20,
            'staff_laptop': 30,      # Staff VLAN
            'staff_phone': 30,
            'camera': 99,            # IoT VLAN
            'sensor': 99,
            'smart_device': 99,
            'printer': 30,           # Staff (shared resource)
        }

        # Determine VLAN
        vlan_id = vlan_map.get(device_type, 40)  # Default to Guest

        # Assign
        self.assign_device_to_vlan(mac, vlan_id, reason="auto_assignment")

        return vlan_id

    def quarantine_device(self, mac_address: str, reason: str = "security_threat") -> bool:
        """Move device to quarantine VLAN."""
        return self.assign_device_to_vlan(mac_address, 99, reason=f"quarantine:{reason}")

    # ========================================
    # VLAN Configuration
    # ========================================

    def get_vlans(self) -> List[Dict]:
        """Get all VLANs with their configuration."""
        return self.db.get_vlans()

    def get_vlan_status(self, vlan_id: int) -> Optional[VLANStatus]:
        """Get runtime status of a VLAN."""
        vlan = self.db.get_vlan(vlan_id)
        if not vlan:
            return None

        interface_name = f"vlan{vlan_id}"

        # Check interface status
        success, output, _ = self._run_cmd(['ip', 'link', 'show', interface_name])
        interface_up = success and 'UP' in output

        # Get device counts
        devices = self.db.get_devices(vlan_id=vlan_id)
        active = [d for d in devices if d.get('last_seen')]  # Would check timestamp properly

        # Check DHCP status
        dhcp_running = self._check_dhcp_running(vlan_id)

        return VLANStatus(
            vlan_id=vlan_id,
            name=vlan['name'],
            subnet=str(vlan['subnet']),
            gateway=str(vlan['gateway']) if vlan['gateway'] else '',
            device_count=len(devices),
            active_count=len(active),
            interface_up=interface_up,
            dhcp_running=dhcp_running,
            dns_policy=vlan.get('dns_policy', 'standard'),
            bandwidth_used_mbps=0.0  # Would get from OVS stats
        )

    def _check_dhcp_running(self, vlan_id: int) -> bool:
        """Check if DHCP is running for this VLAN."""
        success, output, _ = self._run_cmd(['pgrep', '-f', f'dnsmasq.*vlan{vlan_id}'])
        return success

    def update_vlan_config(self, vlan_id: int, **kwargs) -> bool:
        """Update VLAN configuration."""
        return self.db.update_vlan(vlan_id, **kwargs)

    def set_dns_policy(self, vlan_id: int, policy: str) -> bool:
        """Set DNS protection policy for a VLAN."""
        if policy not in [p.value for p in DNSPolicy]:
            logger.error(f"Invalid DNS policy: {policy}")
            return False

        success = self.db.update_vlan(vlan_id, dns_policy=policy)

        if success:
            # Restart dnsmasq to apply new policy
            self._run_cmd(['systemctl', 'restart', f'dnsmasq@vlan{vlan_id}'])
            logger.info(f"Set DNS policy for VLAN {vlan_id} to {policy}")

        return success

    def set_bandwidth_limit(self, vlan_id: int, limit_mbps: int) -> bool:
        """Set bandwidth limit for a VLAN."""
        interface_name = f"vlan{vlan_id}"

        # Remove existing qdisc
        self._run_cmd(['tc', 'qdisc', 'del', 'dev', interface_name, 'root'], check=False)

        if limit_mbps > 0:
            # Add HTB qdisc with rate limit
            rate = f"{limit_mbps}mbit"
            self._run_cmd([
                'tc', 'qdisc', 'add', 'dev', interface_name, 'root', 'handle', '1:',
                'htb', 'default', '10'
            ])
            self._run_cmd([
                'tc', 'class', 'add', 'dev', interface_name, 'parent', '1:',
                'classid', '1:10', 'htb', 'rate', rate, 'ceil', rate
            ])

            logger.info(f"Set bandwidth limit for VLAN {vlan_id} to {limit_mbps} Mbps")

        return self.db.update_vlan(vlan_id, bandwidth_limit_mbps=limit_mbps)

    # ========================================
    # Inter-VLAN Routing
    # ========================================

    def allow_inter_vlan(self, src_vlan: int, dst_vlan: int) -> bool:
        """Allow traffic between two VLANs."""
        # Add OVS flow to allow inter-VLAN routing
        self._run_cmd([
            'ovs-ofctl', 'add-flow', self.ovs_bridge,
            f'priority=150,dl_vlan={src_vlan},actions=strip_vlan,mod_vlan_vid:{dst_vlan},normal'
        ])
        logger.info(f"Allowed inter-VLAN routing: VLAN {src_vlan} -> VLAN {dst_vlan}")
        return True

    def block_inter_vlan(self, src_vlan: int, dst_vlan: int) -> bool:
        """Block traffic between two VLANs."""
        self._run_cmd([
            'ovs-ofctl', 'del-flows', self.ovs_bridge,
            f'dl_vlan={src_vlan},actions=*mod_vlan_vid:{dst_vlan}*'
        ])
        logger.info(f"Blocked inter-VLAN routing: VLAN {src_vlan} -> VLAN {dst_vlan}")
        return True

    # ========================================
    # Statistics
    # ========================================

    def get_vlan_stats(self, vlan_id: int) -> Dict[str, Any]:
        """Get traffic statistics for a VLAN."""
        interface_name = f"vlan{vlan_id}"

        # Get OVS port stats
        success, output, _ = self._run_cmd([
            'ovs-ofctl', 'dump-ports', self.ovs_bridge, interface_name
        ])

        stats = {
            'rx_packets': 0,
            'tx_packets': 0,
            'rx_bytes': 0,
            'tx_bytes': 0,
            'device_count': 0,
        }

        if success:
            # Parse OVS output (simplified)
            for line in output.split('\n'):
                if 'rx pkts=' in line:
                    try:
                        stats['rx_packets'] = int(line.split('rx pkts=')[1].split(',')[0])
                        stats['tx_packets'] = int(line.split('tx pkts=')[1].split(',')[0])
                    except (IndexError, ValueError):
                        pass

        # Get device count
        stats['device_count'] = len(self.db.get_devices(vlan_id=vlan_id))

        return stats

    def get_all_vlan_stats(self) -> Dict[int, Dict]:
        """Get statistics for all VLANs."""
        vlans = self.get_vlans()
        return {v['vlan_id']: self.get_vlan_stats(v['vlan_id']) for v in vlans}


# Singleton instance
_vlan_manager: Optional[VLANManager] = None


def get_vlan_manager() -> VLANManager:
    """Get the VLAN manager singleton."""
    global _vlan_manager
    if _vlan_manager is None:
        _vlan_manager = VLANManager()
    return _vlan_manager
