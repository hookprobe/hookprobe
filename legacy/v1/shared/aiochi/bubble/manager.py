"""
AIOCHI Ecosystem Bubble Manager
Unified bubble management with policy resolution integration.

This module provides a high-level API for bubble management that integrates
with the PolicyResolver for OpenFlow policy enforcement.

Usage:
    from shared.aiochi.bubble import get_bubble_manager

    manager = get_bubble_manager()
    bubble = manager.create_bubble("Dad", BubbleType.FAMILY)
    manager.add_device(bubble.bubble_id, "AA:BB:CC:DD:EE:FF")
    manager.set_device_policy("AA:BB:CC:DD:EE:FF", NetworkPolicy.FULL_ACCESS)
"""

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from .types import (
    Bubble,
    BubbleEvent,
    BubbleState,
    BubbleType,
    NetworkPolicy,
    BUBBLE_TYPE_TO_POLICY,
    BUBBLE_TYPE_POLICIES,
)
from .policy_resolver import PolicyResolver, get_policy_resolver

logger = logging.getLogger(__name__)

# Database paths
BUBBLE_DB = Path('/var/lib/hookprobe/bubbles.db')

# SDN Trigger file for D2D rules
SDN_TRIGGER_FILE = Path('/opt/hookprobe/fortress/data/.bubble_sdn_sync')

# OpenFlow priorities
OFP_D2D_PRIORITY = 450

# Database timeout
DB_TIMEOUT_SECONDS = 5.0


class EcosystemBubbleManager:
    """
    Manages ecosystem bubbles with integrated policy resolution.

    This manager handles:
    - Bubble CRUD operations
    - Device-to-bubble assignments
    - Policy resolution and OpenFlow integration
    - D2D rule generation for intra-bubble traffic
    """

    def __init__(self):
        self._bubbles: Dict[str, Bubble] = {}
        self._device_bubble_map: Dict[str, str] = {}  # MAC -> bubble_id
        self._events: List[BubbleEvent] = []
        self._lock = threading.RLock()

        # Policy resolver integration
        self._policy_resolver = get_policy_resolver()

        # SDN dirty flag for D2D rule sync
        self._sdn_dirty = False

        # Initialize database
        self._init_database()
        self._load_bubbles()

    def _init_database(self):
        """Initialize bubble database with new schema."""
        try:
            BUBBLE_DB.parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS bubbles (
                        bubble_id TEXT PRIMARY KEY,
                        name TEXT,
                        ecosystem TEXT,
                        bubble_type TEXT DEFAULT 'family',
                        devices_json TEXT,
                        state TEXT DEFAULT 'active',
                        confidence REAL DEFAULT 1.0,
                        policies_json TEXT,
                        device_overrides_json TEXT,
                        pinned INTEGER DEFAULT 0,
                        is_manual INTEGER DEFAULT 1,
                        color TEXT DEFAULT '#2196F3',
                        icon TEXT DEFAULT 'fa-layer-group',
                        owner_hint TEXT,
                        created_at TEXT,
                        last_activity TEXT,
                        manually_assigned_json TEXT
                    )
                ''')

                # Migration: add new columns
                for col, default in [
                    ('device_overrides_json', 'TEXT'),
                    ('color', "TEXT DEFAULT '#2196F3'"),
                    ('icon', "TEXT DEFAULT 'fa-layer-group'"),
                ]:
                    try:
                        conn.execute(f'ALTER TABLE bubbles ADD COLUMN {col} {default}')
                    except sqlite3.OperationalError:
                        pass

                conn.execute('''
                    CREATE TABLE IF NOT EXISTS bubble_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT,
                        bubble_id TEXT,
                        mac TEXT,
                        timestamp TEXT,
                        details_json TEXT
                    )
                ''')
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize bubble database: {e}")

    def _load_bubbles(self):
        """Load bubbles from database."""
        try:
            if not BUBBLE_DB.exists():
                return

            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('SELECT * FROM bubbles WHERE state != "dissolved"')

                for row in cursor:
                    try:
                        devices = set(json.loads(row['devices_json'] or '[]'))
                        policies = json.loads(row['policies_json'] or '{}')
                        device_overrides = json.loads(row['device_overrides_json'] or '{}')
                        manually_assigned = set(json.loads(row['manually_assigned_json'] or '[]'))

                        bubble = Bubble(
                            bubble_id=row['bubble_id'],
                            name=row['name'] or '',
                            ecosystem=row['ecosystem'] or 'mixed',
                            bubble_type=BubbleType(row['bubble_type'] or 'family'),
                            devices=devices,
                            state=BubbleState(row['state'] or 'active'),
                            confidence=row['confidence'] or 1.0,
                            policies=policies,
                            pinned=bool(row['pinned']),
                            is_manual=bool(row['is_manual']),
                            color=row['color'] or '#2196F3',
                            icon=row['icon'] or 'fa-layer-group',
                            owner_hint=row['owner_hint'],
                            created_at=row['created_at'] or datetime.now().isoformat(),
                            last_activity=row['last_activity'] or datetime.now().isoformat(),
                            manually_assigned_devices=manually_assigned,
                        )

                        # Restore device policy overrides
                        for mac, policy_str in device_overrides.items():
                            try:
                                bubble.device_policy_overrides[mac.upper()] = NetworkPolicy(policy_str)
                            except ValueError:
                                pass

                        self._bubbles[bubble.bubble_id] = bubble

                        # Update device-to-bubble map
                        for mac in devices:
                            self._device_bubble_map[mac.upper()] = bubble.bubble_id

                        # Sync to policy resolver
                        self._policy_resolver.update_bubble(bubble)

                    except Exception as e:
                        logger.warning(f"Could not load bubble: {e}")

                logger.info(f"Loaded {len(self._bubbles)} bubbles from database")
        except Exception as e:
            logger.warning(f"Could not load bubbles: {e}")

    def _persist_bubble(self, bubble: Bubble):
        """Persist bubble to database."""
        try:
            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                device_overrides = {
                    mac: policy.value
                    for mac, policy in bubble.device_policy_overrides.items()
                }

                conn.execute('''
                    INSERT OR REPLACE INTO bubbles
                    (bubble_id, name, ecosystem, bubble_type, devices_json, state,
                     confidence, policies_json, device_overrides_json, pinned, is_manual,
                     color, icon, owner_hint, created_at, last_activity, manually_assigned_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    bubble.bubble_id,
                    bubble.name,
                    bubble.ecosystem,
                    bubble.bubble_type.value,
                    json.dumps(list(bubble.devices)),
                    bubble.state.value,
                    bubble.confidence,
                    json.dumps(bubble.policies),
                    json.dumps(device_overrides),
                    1 if bubble.pinned else 0,
                    1 if bubble.is_manual else 0,
                    bubble.color,
                    bubble.icon,
                    bubble.owner_hint,
                    bubble.created_at,
                    bubble.last_activity,
                    json.dumps(list(bubble.manually_assigned_devices)),
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Could not persist bubble: {e}")

    def _record_event(self, event: BubbleEvent):
        """Record a bubble event."""
        self._events.append(event)
        try:
            with sqlite3.connect(str(BUBBLE_DB), timeout=DB_TIMEOUT_SECONDS) as conn:
                conn.execute('''
                    INSERT INTO bubble_events
                    (event_type, bubble_id, mac, timestamp, details_json)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    event.event_type,
                    event.bubble_id,
                    event.mac,
                    event.timestamp,
                    json.dumps(event.details),
                ))
                conn.commit()
        except Exception as e:
            logger.debug(f"Could not persist event: {e}")

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def create_bubble(
        self,
        name: str,
        bubble_type: BubbleType = BubbleType.FAMILY,
        devices: Optional[List[str]] = None,
        color: str = "#2196F3",
        icon: str = "fa-layer-group",
    ) -> Bubble:
        """
        Create a new bubble.

        Args:
            name: Human-readable name (e.g., "Dad", "Mom", "Kids")
            bubble_type: Type determining default policy
            devices: Initial devices (MAC addresses)
            color: UI color hex code
            icon: FontAwesome icon class

        Returns:
            Created Bubble object
        """
        bubble_id = f"bubble-{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"

        with self._lock:
            bubble = Bubble(
                bubble_id=bubble_id,
                name=name,
                bubble_type=bubble_type,
                devices=set(),
                state=BubbleState.ACTIVE,
                confidence=1.0,
                pinned=True,
                is_manual=True,
                color=color,
                icon=icon,
            )

            self._bubbles[bubble_id] = bubble

            # Add initial devices
            if devices:
                for mac in devices:
                    self._add_device_internal(bubble, mac.upper())

            self._persist_bubble(bubble)
            self._policy_resolver.update_bubble(bubble)

            self._record_event(BubbleEvent(
                event_type='created',
                bubble_id=bubble_id,
                details={'name': name, 'type': bubble_type.value},
            ))

            logger.info(f"Created bubble: {name} ({bubble_id})")
            return bubble

    def get_bubble(self, bubble_id: str) -> Optional[Bubble]:
        """Get bubble by ID."""
        with self._lock:
            return self._bubbles.get(bubble_id)

    def get_all_bubbles(self) -> List[Bubble]:
        """Get all active bubbles."""
        with self._lock:
            return [b for b in self._bubbles.values() if b.state == BubbleState.ACTIVE]

    def get_device_bubble(self, mac: str) -> Optional[Bubble]:
        """Get the bubble for a device."""
        mac = mac.upper()
        with self._lock:
            bubble_id = self._device_bubble_map.get(mac)
            if bubble_id:
                return self._bubbles.get(bubble_id)
            return None

    def update_bubble(
        self,
        bubble_id: str,
        name: Optional[str] = None,
        bubble_type: Optional[BubbleType] = None,
        color: Optional[str] = None,
        icon: Optional[str] = None,
    ) -> Optional[Bubble]:
        """Update bubble properties."""
        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble:
                return None

            if name is not None:
                bubble.name = name
            if bubble_type is not None:
                bubble.bubble_type = bubble_type
            if color is not None:
                bubble.color = color
            if icon is not None:
                bubble.icon = icon

            bubble.last_activity = datetime.now().isoformat()

            self._persist_bubble(bubble)
            self._policy_resolver.update_bubble(bubble)

            self._record_event(BubbleEvent(
                event_type='updated',
                bubble_id=bubble_id,
                details={'name': bubble.name, 'type': bubble.bubble_type.value},
            ))

            return bubble

    def delete_bubble(self, bubble_id: str) -> bool:
        """Delete a bubble."""
        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble:
                return False

            # Clear device mappings
            for mac in bubble.devices:
                if self._device_bubble_map.get(mac) == bubble_id:
                    del self._device_bubble_map[mac]
                    self._policy_resolver.remove_device_from_bubble(mac, bubble_id)

            # Mark as dissolved
            bubble.state = BubbleState.DISSOLVED
            self._persist_bubble(bubble)

            # Remove from cache
            del self._bubbles[bubble_id]

            self._record_event(BubbleEvent(
                event_type='deleted',
                bubble_id=bubble_id,
            ))

            self._sdn_dirty = True
            logger.info(f"Deleted bubble: {bubble_id}")
            return True

    def add_device(self, bubble_id: str, mac: str, pin: bool = True) -> bool:
        """
        Add a device to a bubble.

        Args:
            bubble_id: Target bubble
            mac: Device MAC address
            pin: If True, mark as manually assigned

        Returns:
            True if successful
        """
        mac = mac.upper()

        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble:
                return False

            # Remove from old bubble if any
            old_bubble_id = self._device_bubble_map.get(mac)
            if old_bubble_id and old_bubble_id != bubble_id:
                old_bubble = self._bubbles.get(old_bubble_id)
                if old_bubble:
                    old_bubble.devices.discard(mac)
                    old_bubble.manually_assigned_devices.discard(mac)
                    self._persist_bubble(old_bubble)
                    self._policy_resolver.remove_device_from_bubble(mac, old_bubble_id)

            self._add_device_internal(bubble, mac, pin)
            self._persist_bubble(bubble)
            self._policy_resolver.update_bubble(bubble)

            self._record_event(BubbleEvent(
                event_type='device_added',
                bubble_id=bubble_id,
                mac=mac,
                details={'pinned': pin, 'old_bubble': old_bubble_id},
            ))

            self._sdn_dirty = True
            return True

    def _add_device_internal(self, bubble: Bubble, mac: str, pin: bool = True):
        """Internal helper to add device to bubble."""
        mac = mac.upper()
        bubble.devices.add(mac)
        if pin:
            bubble.manually_assigned_devices.add(mac)
        self._device_bubble_map[mac] = bubble.bubble_id
        bubble.last_activity = datetime.now().isoformat()

    def remove_device(self, bubble_id: str, mac: str) -> bool:
        """Remove a device from a bubble."""
        mac = mac.upper()

        with self._lock:
            bubble = self._bubbles.get(bubble_id)
            if not bubble or mac not in bubble.devices:
                return False

            bubble.devices.discard(mac)
            bubble.manually_assigned_devices.discard(mac)
            bubble.device_policy_overrides.pop(mac, None)

            if self._device_bubble_map.get(mac) == bubble_id:
                del self._device_bubble_map[mac]

            self._persist_bubble(bubble)
            self._policy_resolver.remove_device_from_bubble(mac, bubble_id)

            self._record_event(BubbleEvent(
                event_type='device_removed',
                bubble_id=bubble_id,
                mac=mac,
            ))

            self._sdn_dirty = True
            return True

    def move_device(self, mac: str, to_bubble_id: str, pin: bool = True) -> bool:
        """Move a device to a different bubble."""
        return self.add_device(to_bubble_id, mac, pin)

    # =========================================================================
    # POLICY MANAGEMENT
    # =========================================================================

    def set_device_policy(
        self,
        mac: str,
        policy: NetworkPolicy,
        apply_openflow: bool = True
    ) -> bool:
        """
        Set a device-specific policy override.

        Args:
            mac: Device MAC address
            policy: Network policy to apply
            apply_openflow: If True, trigger OpenFlow rule application

        Returns:
            True if successful
        """
        mac = mac.upper()

        with self._lock:
            # Update in bubble if device is in one
            bubble_id = self._device_bubble_map.get(mac)
            if bubble_id and bubble_id in self._bubbles:
                bubble = self._bubbles[bubble_id]
                bubble.set_device_policy(mac, policy)
                self._persist_bubble(bubble)
                self._policy_resolver.update_bubble(bubble)

            # Use policy resolver to apply
            self._policy_resolver.set_device_override(mac, policy, apply_openflow)

            self._record_event(BubbleEvent(
                event_type='policy_changed',
                bubble_id=bubble_id or '',
                mac=mac,
                details={'policy': policy.value},
            ))

            logger.info(f"Set device policy: {mac} -> {policy.value}")
            return True

    def clear_device_policy(self, mac: str, apply_openflow: bool = True) -> bool:
        """
        Clear device-specific policy override (use bubble default).

        Args:
            mac: Device MAC address
            apply_openflow: If True, trigger OpenFlow rule application

        Returns:
            True if successful
        """
        mac = mac.upper()

        with self._lock:
            # Update in bubble
            bubble_id = self._device_bubble_map.get(mac)
            if bubble_id and bubble_id in self._bubbles:
                bubble = self._bubbles[bubble_id]
                bubble.clear_device_policy(mac)
                self._persist_bubble(bubble)
                self._policy_resolver.update_bubble(bubble)

            # Use policy resolver
            resolution = self._policy_resolver.clear_device_override(mac, apply_openflow)

            self._record_event(BubbleEvent(
                event_type='policy_cleared',
                bubble_id=bubble_id or '',
                mac=mac,
                details={'effective_policy': resolution.effective_policy.value},
            ))

            return True

    def get_device_policy(self, mac: str) -> NetworkPolicy:
        """Get effective policy for a device."""
        mac = mac.upper()
        resolution = self._policy_resolver.resolve(mac)
        return resolution.effective_policy

    # =========================================================================
    # SDN INTEGRATION
    # =========================================================================

    def sync_sdn_rules(self):
        """Sync SDN rules for D2D traffic between bubble devices."""
        rules = []

        with self._lock:
            for bubble in self._bubbles.values():
                if bubble.state != BubbleState.ACTIVE:
                    continue

                devices = list(bubble.devices)
                for i in range(len(devices)):
                    for j in range(i + 1, len(devices)):
                        mac_a = devices[i]
                        mac_b = devices[j]

                        # Bidirectional D2D rules
                        rules.append({
                            'type': 'allow',
                            'priority': OFP_D2D_PRIORITY,
                            'match': {'eth_src': mac_a, 'eth_dst': mac_b},
                            'actions': ['normal'],
                            'bubble_id': bubble.bubble_id,
                        })
                        rules.append({
                            'type': 'allow',
                            'priority': OFP_D2D_PRIORITY,
                            'match': {'eth_src': mac_b, 'eth_dst': mac_a},
                            'actions': ['normal'],
                            'bubble_id': bubble.bubble_id,
                        })

        # Write trigger file for host-side application
        try:
            SDN_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
            trigger_data = {
                'timestamp': datetime.now().isoformat(),
                'rules': rules,
                'bubble_count': len([b for b in self._bubbles.values() if b.state == BubbleState.ACTIVE]),
            }
            with open(SDN_TRIGGER_FILE, 'w') as f:
                json.dump(trigger_data, f, indent=2)
            logger.debug(f"SDN trigger written: {len(rules)} D2D rules")
        except Exception as e:
            logger.error(f"Could not write SDN trigger: {e}")

        self._sdn_dirty = False

    def get_stats(self) -> Dict:
        """Get bubble manager statistics."""
        with self._lock:
            active = [b for b in self._bubbles.values() if b.state == BubbleState.ACTIVE]
            return {
                'total_bubbles': len(self._bubbles),
                'active_bubbles': len(active),
                'total_devices': len(self._device_bubble_map),
                'devices_with_overrides': sum(
                    len(b.device_policy_overrides) for b in self._bubbles.values()
                ),
            }


# Singleton instance
_manager_instance: Optional[EcosystemBubbleManager] = None
_manager_lock = threading.Lock()


def get_bubble_manager() -> EcosystemBubbleManager:
    """Get singleton bubble manager instance."""
    global _manager_instance

    with _manager_lock:
        if _manager_instance is None:
            _manager_instance = EcosystemBubbleManager()
        return _manager_instance
