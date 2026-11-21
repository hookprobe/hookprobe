"""
AIOCHI Policy Resolver
Maps bubbles and devices to OpenFlow network policies.

The Policy Resolution Chain:
1. Device-specific policy override (highest priority)
2. Bubble default policy (from bubble type)
3. Quarantine (unknown devices not in any bubble)

OpenFlow Priority Mapping:
- Priority 900: Device-specific override rules
- Priority 600: Bubble default policy rules
- Priority 500: Base allow rules (fallback)
- Priority 450: D2D bubble rules
- Priority 100: Default isolation

Example:
    Family Bubble (type=FAMILY) has default_policy=SMART_HOME
    - Dad's iPhone: policy_override=FULL_ACCESS -> Priority 900
    - Mom's iPhone: no override -> SMART_HOME (bubble default) -> Priority 600
    - Kids' iPad: policy_override=LAN_ONLY -> Priority 900 (grounded!)
"""

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .types import (
    Bubble,
    BubbleType,
    NetworkPolicy,
    BUBBLE_TYPE_TO_POLICY,
    POLICY_INFO,
)

logger = logging.getLogger(__name__)

# Database paths
BUBBLE_DB = Path('/var/lib/hookprobe/bubbles.db')
AUTOPILOT_DB = Path('/var/lib/hookprobe/autopilot.db')

# Trigger file for NAC policy sync (container -> host communication)
POLICY_TRIGGER_FILE = Path('/opt/hookprobe/fortress/data/.nac_policy_sync')

# OpenFlow priorities
OFP_DEVICE_OVERRIDE_PRIORITY = 900   # Device-specific overrides
OFP_BUBBLE_DEFAULT_PRIORITY = 600    # Bubble default policy
OFP_BASE_ALLOW_PRIORITY = 500        # Base allow (normal traffic)
OFP_D2D_PRIORITY = 450               # Bubble D2D rules
OFP_ISOLATION_PRIORITY = 100         # Default isolation

# Database timeout
DB_TIMEOUT_SECONDS = 5.0


@dataclass
class PolicyResolution:
    """Result of policy resolution for a device."""
    mac: str
    effective_policy: NetworkPolicy
    policy_source: str  # 'device_override', 'bubble_default', 'quarantine'
    bubble_id: Optional[str] = None
    bubble_type: Optional[BubbleType] = None
    openflow_priority: int = OFP_BUBBLE_DEFAULT_PRIORITY
    confidence: float = 1.0

    def to_dict(self) -> Dict:
        return {
            'mac': self.mac,
            'effective_policy': self.effective_policy.value,
            'policy_source': self.policy_source,
            'bubble_id': self.bubble_id,
            'bubble_type': self.bubble_type.value if self.bubble_type else None,
            'openflow_priority': self.openflow_priority,
            'confidence': self.confidence,
        }


class PolicyResolver:
    """
    Resolves effective network policies for devices.

    Policy resolution flow:
    1. Check for device-specific policy override
    2. If in bubble, use bubble's default policy
    3. Otherwise, quarantine (unknown device)

    This resolver integrates with:
    - EcosystemBubbleManager: For bubble membership
    - NAC Policy Sync: For OpenFlow rule application
    - AIOCHI Identity Engine: For device trust levels
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._cache: Dict[str, PolicyResolution] = {}
        self._bubbles: Dict[str, Bubble] = {}  # bubble_id -> Bubble
        self._device_bubble_map: Dict[str, str] = {}  # MAC -> bubble_id
        self._device_overrides: Dict[str, NetworkPolicy] = {}  # MAC -> override

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize/migrate database schema for policy overrides."""
        try:
            if AUTOPILOT_DB.exists():
                with sqlite3.connect(str(AUTOPILOT_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                    # Add policy_override column if it doesn't exist
                    try:
                        conn.execute('''
                            ALTER TABLE device_identity
                            ADD COLUMN policy_override TEXT
                        ''')
                        conn.commit()
                        logger.info("Added policy_override column to device_identity")
                    except sqlite3.OperationalError:
                        pass  # Column already exists

                    # Create policy resolution table for caching
                    conn.execute('''
                        CREATE TABLE IF NOT EXISTS policy_resolutions (
                            mac TEXT PRIMARY KEY,
                            effective_policy TEXT,
                            policy_source TEXT,
                            bubble_id TEXT,
                            openflow_priority INTEGER,
                            updated_at TEXT
                        )
                    ''')
                    conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize policy database: {e}")

    def resolve(self, mac: str, bubble: Optional[Bubble] = None) -> PolicyResolution:
        """
        Resolve the effective network policy for a device.

        Args:
            mac: Device MAC address
            bubble: Optional bubble object (if already known)

        Returns:
            PolicyResolution with effective policy and metadata
        """
        mac = mac.upper()

        with self._lock:
            # 1. Check for device-specific override
            if mac in self._device_overrides:
                override = self._device_overrides[mac]
                return PolicyResolution(
                    mac=mac,
                    effective_policy=override,
                    policy_source='device_override',
                    bubble_id=self._device_bubble_map.get(mac),
                    openflow_priority=OFP_DEVICE_OVERRIDE_PRIORITY,
                )

            # 2. Check bubble for override or default
            if bubble is None:
                bubble_id = self._device_bubble_map.get(mac)
                if bubble_id:
                    bubble = self._bubbles.get(bubble_id)

            if bubble:
                # Check for device override in bubble
                device_override = bubble.device_policy_overrides.get(mac)
                if device_override:
                    return PolicyResolution(
                        mac=mac,
                        effective_policy=device_override,
                        policy_source='device_override',
                        bubble_id=bubble.bubble_id,
                        bubble_type=bubble.bubble_type,
                        openflow_priority=OFP_DEVICE_OVERRIDE_PRIORITY,
                        confidence=bubble.confidence,
                    )

                # Use bubble default
                default_policy = bubble.get_default_network_policy()
                return PolicyResolution(
                    mac=mac,
                    effective_policy=default_policy,
                    policy_source='bubble_default',
                    bubble_id=bubble.bubble_id,
                    bubble_type=bubble.bubble_type,
                    openflow_priority=OFP_BUBBLE_DEFAULT_PRIORITY,
                    confidence=bubble.confidence,
                )

            # 3. Unknown device - quarantine
            return PolicyResolution(
                mac=mac,
                effective_policy=NetworkPolicy.QUARANTINE,
                policy_source='quarantine',
                openflow_priority=OFP_DEVICE_OVERRIDE_PRIORITY,  # High priority for quarantine
            )

    def set_device_override(
        self,
        mac: str,
        policy: NetworkPolicy,
        apply_openflow: bool = True
    ) -> PolicyResolution:
        """
        Set a device-specific policy override.

        Args:
            mac: Device MAC address
            policy: Network policy to apply
            apply_openflow: If True, trigger OpenFlow rule application

        Returns:
            Updated PolicyResolution
        """
        mac = mac.upper()

        with self._lock:
            self._device_overrides[mac] = policy

            # Also update bubble if device is in one
            bubble_id = self._device_bubble_map.get(mac)
            if bubble_id and bubble_id in self._bubbles:
                self._bubbles[bubble_id].set_device_policy(mac, policy)

            # Persist to database
            self._persist_override(mac, policy)

            # Resolve and return
            resolution = self.resolve(mac)

            # Trigger OpenFlow update
            if apply_openflow:
                self._trigger_openflow_update(mac, policy)

            logger.info(f"Set policy override for {mac}: {policy.value}")
            return resolution

    def clear_device_override(
        self,
        mac: str,
        apply_openflow: bool = True
    ) -> PolicyResolution:
        """
        Clear a device-specific policy override (use bubble default).

        Args:
            mac: Device MAC address
            apply_openflow: If True, trigger OpenFlow rule application

        Returns:
            Updated PolicyResolution (now using bubble default)
        """
        mac = mac.upper()

        with self._lock:
            if mac in self._device_overrides:
                del self._device_overrides[mac]

            # Also clear from bubble
            bubble_id = self._device_bubble_map.get(mac)
            if bubble_id and bubble_id in self._bubbles:
                self._bubbles[bubble_id].clear_device_policy(mac)

            # Persist to database
            self._persist_override(mac, None)

            # Resolve and return
            resolution = self.resolve(mac)

            # Trigger OpenFlow update
            if apply_openflow:
                self._trigger_openflow_update(mac, resolution.effective_policy)

            logger.info(f"Cleared policy override for {mac}, using: {resolution.effective_policy.value}")
            return resolution

    def update_bubble(self, bubble: Bubble):
        """
        Update bubble in resolver cache.

        Args:
            bubble: Bubble object to cache
        """
        with self._lock:
            self._bubbles[bubble.bubble_id] = bubble

            # Update device-to-bubble mapping
            for mac in bubble.devices:
                self._device_bubble_map[mac.upper()] = bubble.bubble_id

    def remove_device_from_bubble(self, mac: str, bubble_id: str):
        """Remove device from bubble mapping."""
        mac = mac.upper()
        with self._lock:
            if self._device_bubble_map.get(mac) == bubble_id:
                del self._device_bubble_map[mac]

    def get_all_resolutions(self) -> List[PolicyResolution]:
        """Get policy resolutions for all known devices."""
        resolutions = []
        with self._lock:
            # All devices in bubbles
            for mac in self._device_bubble_map.keys():
                resolutions.append(self.resolve(mac))

            # All devices with overrides not in bubbles
            for mac in self._device_overrides.keys():
                if mac not in self._device_bubble_map:
                    resolutions.append(self.resolve(mac))

        return resolutions

    def generate_openflow_rules(self) -> List[Dict]:
        """
        Generate OpenFlow rules for all devices.

        Returns:
            List of rule dictionaries for NAC policy sync
        """
        rules = []

        for resolution in self.get_all_resolutions():
            rule = {
                'mac': resolution.mac,
                'policy': resolution.effective_policy.value,
                'priority': resolution.openflow_priority,
                'source': resolution.policy_source,
                'bubble_id': resolution.bubble_id,
            }
            rules.append(rule)

        return rules

    def _persist_override(self, mac: str, policy: Optional[NetworkPolicy]):
        """Persist policy override to database."""
        try:
            if AUTOPILOT_DB.exists():
                with sqlite3.connect(str(AUTOPILOT_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                    if policy:
                        conn.execute('''
                            INSERT OR REPLACE INTO policy_resolutions
                            (mac, effective_policy, policy_source, openflow_priority, updated_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (mac, policy.value, 'device_override', OFP_DEVICE_OVERRIDE_PRIORITY,
                              datetime.now().isoformat()))

                        # Also update device_identity if it exists
                        conn.execute('''
                            UPDATE device_identity SET policy_override = ? WHERE mac = ?
                        ''', (policy.value, mac))
                    else:
                        conn.execute('''
                            DELETE FROM policy_resolutions WHERE mac = ?
                        ''', (mac,))
                        conn.execute('''
                            UPDATE device_identity SET policy_override = NULL WHERE mac = ?
                        ''', (mac,))
                    conn.commit()
        except Exception as e:
            logger.warning(f"Could not persist policy override: {e}")

    def _trigger_openflow_update(self, mac: str, policy: NetworkPolicy):
        """Trigger OpenFlow rule update via trigger file."""
        try:
            POLICY_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)

            trigger_data = {
                'mac': mac,
                'policy': policy.value,
                'timestamp': datetime.now().isoformat(),
            }

            with open(POLICY_TRIGGER_FILE, 'w') as f:
                json.dump(trigger_data, f)

            logger.debug(f"Triggered OpenFlow update for {mac}: {policy.value}")
        except Exception as e:
            logger.warning(f"Could not trigger OpenFlow update: {e}")

    def load_from_database(self):
        """Load persisted resolutions from database."""
        try:
            if AUTOPILOT_DB.exists():
                with sqlite3.connect(str(AUTOPILOT_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute('''
                        SELECT mac, effective_policy, policy_source
                        FROM policy_resolutions
                        WHERE policy_source = 'device_override'
                    ''')

                    for row in cursor:
                        try:
                            mac = row['mac'].upper()
                            policy = NetworkPolicy(row['effective_policy'])
                            self._device_overrides[mac] = policy
                        except (ValueError, KeyError):
                            pass

                    logger.info(f"Loaded {len(self._device_overrides)} device policy overrides")
        except Exception as e:
            logger.warning(f"Could not load from database: {e}")

    def get_policy_info(self, policy: NetworkPolicy) -> Dict:
        """Get display info for a policy."""
        return POLICY_INFO.get(policy, POLICY_INFO[NetworkPolicy.QUARANTINE])


# Singleton instance
_resolver_instance: Optional[PolicyResolver] = None
_resolver_lock = threading.Lock()


def get_policy_resolver() -> PolicyResolver:
    """Get singleton policy resolver instance."""
    global _resolver_instance

    with _resolver_lock:
        if _resolver_instance is None:
            _resolver_instance = PolicyResolver()
            _resolver_instance.load_from_database()
        return _resolver_instance
