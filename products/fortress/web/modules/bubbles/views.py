"""
Fortress Bubble Management Views

REST API and Web UI for managing device bubbles.

Bubble Types:
- FAMILY: Full smart home access, mDNS D2D, shared components
- GUEST: Internet only, isolated from family/corporate
- CORPORATE: Work devices, separate from family
- SMART_HOME: IoT hub, shared by all family bubbles

Manual Override Features:
- Create custom bubbles (e.g., "Dad's Bubble", "Mom's Bubble")
- Move devices between bubbles
- Pin bubble assignments (prevent AI changes)
- Rename and customize bubbles
"""

import json
import logging
import re
import sqlite3
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from flask import jsonify, request, render_template
from flask_login import login_required, current_user

from . import bubbles_bp
from ..auth.decorators import admin_required
from ...security_utils import safe_error_message, mask_mac

logger = logging.getLogger(__name__)

# MAC address validation pattern
MAC_PATTERN = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

# Bubble database
BUBBLE_DB = Path('/var/lib/hookprobe/bubbles.db')


# =============================================================================
# BUBBLE TYPES & POLICIES
# =============================================================================

class BubbleType(str, Enum):
    """Types of bubbles with default policies."""
    FAMILY = 'family'         # Full smart home access
    GUEST = 'guest'           # Internet only
    CORPORATE = 'corporate'   # Isolated, internet access
    SMART_HOME = 'smart_home' # IoT devices
    LAN_ONLY = 'lan_only'     # LAN access only, no internet
    CUSTOM = 'custom'         # User-defined


# Default policies for bubble types
BUBBLE_TYPE_POLICIES = {
    BubbleType.FAMILY: {
        'internet_access': True,
        'lan_access': True,
        'smart_home_access': True,
        'd2d_allowed': True,        # mDNS device-to-device
        'shared_devices': True,     # Can use shared printers, NAS
        'vlan': 100,                # Family VLAN
        'icon': 'fa-users',
        'color': '#4CAF50',         # Green
        'description': 'Full network access with smart home integration',
    },
    BubbleType.GUEST: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'vlan': 40,                 # Guest VLAN
        'icon': 'fa-user-friends',
        'color': '#9E9E9E',         # Gray
        'description': 'Internet only, isolated from home network',
    },
    BubbleType.CORPORATE: {
        'internet_access': True,
        'lan_access': False,
        'smart_home_access': False,
        'd2d_allowed': False,
        'shared_devices': False,
        'vlan': 50,                 # Corporate VLAN
        'icon': 'fa-briefcase',
        'color': '#2196F3',         # Blue
        'description': 'Work devices, isolated from family',
    },
    BubbleType.SMART_HOME: {
        'internet_access': True,
        'lan_access': True,
        'smart_home_access': True,
        'd2d_allowed': True,
        'shared_devices': True,
        'vlan': 30,                 # IoT VLAN
        'icon': 'fa-home',
        'color': '#FF9800',         # Orange
        'description': 'Smart home devices shared by family',
    },
    BubbleType.LAN_ONLY: {
        'internet_access': False,
        'lan_access': True,
        'smart_home_access': False,
        'd2d_allowed': True,
        'shared_devices': True,
        'vlan': 60,                 # LAN-only VLAN
        'icon': 'fa-network-wired',
        'color': '#795548',         # Brown
        'description': 'Local network only, no internet access (printers, NAS)',
    },
    BubbleType.CUSTOM: {
        'internet_access': True,
        'lan_access': True,
        'smart_home_access': False,
        'd2d_allowed': True,
        'shared_devices': False,
        'vlan': 100,
        'icon': 'fa-layer-group',
        'color': '#9C27B0',         # Purple
        'description': 'Custom user-defined bubble',
    },
}

# Preset family bubble templates
FAMILY_PRESETS = {
    'dad': {'name': "Dad's Bubble", 'icon': 'fa-user-tie', 'color': '#1976D2'},
    'mom': {'name': "Mom's Bubble", 'icon': 'fa-user', 'color': '#E91E63'},
    'kids': {'name': "Kids' Bubble", 'icon': 'fa-child', 'color': '#FF5722'},
    'guest': {'name': 'Guests', 'icon': 'fa-user-friends', 'color': '#607D8B'},
    'work': {'name': 'Work Devices', 'icon': 'fa-laptop', 'color': '#455A64'},
}


# =============================================================================
# DATABASE HELPERS
# =============================================================================

def get_db_connection():
    """Get database connection with row factory."""
    BUBBLE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(BUBBLE_DB), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema():
    """Ensure database schema includes manual bubble fields."""
    with get_db_connection() as conn:
        # Add new columns for manual management
        migrations = [
            'ALTER TABLE bubbles ADD COLUMN bubble_type TEXT DEFAULT "custom"',
            'ALTER TABLE bubbles ADD COLUMN display_name TEXT',
            'ALTER TABLE bubbles ADD COLUMN icon TEXT DEFAULT "fa-layer-group"',
            'ALTER TABLE bubbles ADD COLUMN color TEXT DEFAULT "#9C27B0"',
            'ALTER TABLE bubbles ADD COLUMN is_manual INTEGER DEFAULT 0',
            'ALTER TABLE bubbles ADD COLUMN is_pinned INTEGER DEFAULT 0',
            'ALTER TABLE bubbles ADD COLUMN created_by TEXT',
            'ALTER TABLE bubbles ADD COLUMN policy_json TEXT',
        ]
        for migration in migrations:
            try:
                conn.execute(migration)
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Create manual_assignments table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS manual_assignments (
                mac TEXT PRIMARY KEY,
                bubble_id TEXT NOT NULL,
                assigned_by TEXT,
                assigned_at TEXT,
                is_pinned INTEGER DEFAULT 0,
                notes TEXT
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_assignments_bubble
            ON manual_assignments(bubble_id)
        ''')

        # Create device_names table for custom device naming
        # This allows users to assign friendly names to devices
        # e.g., "013_aio-nap" -> "Living Room Light"
        conn.execute('''
            CREATE TABLE IF NOT EXISTS device_names (
                mac TEXT PRIMARY KEY,
                custom_name TEXT NOT NULL,
                original_hostname TEXT,
                updated_by TEXT,
                updated_at TEXT
            )
        ''')
        conn.commit()


# Initialize schema on module load
try:
    ensure_schema()
except Exception as e:
    logger.warning(f"Could not initialize bubble schema: {e}")


# =============================================================================
# API ENDPOINTS
# =============================================================================

@bubbles_bp.route('/api/types')
@login_required
def get_bubble_types():
    """Get available bubble types with their default policies."""
    types = []
    for bt in BubbleType:
        policy = BUBBLE_TYPE_POLICIES[bt]
        types.append({
            'type': bt.value,
            'name': bt.value.replace('_', ' ').title(),
            'policy': policy,
        })
    return jsonify({'types': types, 'presets': FAMILY_PRESETS})


@bubbles_bp.route('/api/list')
@login_required
def list_bubbles():
    """
    List all bubbles (AI-detected and manual).

    Returns bubbles with their devices, policies, and metadata.
    """
    bubbles = []

    try:
        with get_db_connection() as conn:
            # Get all bubbles
            rows = conn.execute('''
                SELECT * FROM bubbles
                WHERE state != 'dissolved'
                ORDER BY is_manual DESC, last_activity DESC
            ''').fetchall()

            for row in rows:
                bubble_id = row['bubble_id']

                # Get devices in bubble
                devices = []
                device_rows = conn.execute('''
                    SELECT mac FROM manual_assignments WHERE bubble_id = ?
                ''', (bubble_id,)).fetchall()
                devices.extend([r['mac'] for r in device_rows])

                # Also check devices field in bubbles table
                if row['devices']:
                    try:
                        stored_devices = json.loads(row['devices'])
                        devices.extend(stored_devices)
                    except (json.JSONDecodeError, TypeError):
                        pass

                devices = list(set(devices))  # Deduplicate

                # Parse policy
                policy = BUBBLE_TYPE_POLICIES.get(
                    BubbleType(row['bubble_type'] or 'custom'),
                    BUBBLE_TYPE_POLICIES[BubbleType.CUSTOM]
                )
                if row['policy_json']:
                    try:
                        policy.update(json.loads(row['policy_json']))
                    except (json.JSONDecodeError, TypeError):
                        pass

                bubbles.append({
                    'bubble_id': bubble_id,
                    'display_name': row['display_name'] or f"Bubble {bubble_id[:8]}",
                    'bubble_type': row['bubble_type'] or 'custom',
                    'ecosystem': row['ecosystem'],
                    'state': row['state'],
                    'confidence': row['confidence'] or 0.0,
                    'devices': devices,
                    'device_count': len(devices),
                    'icon': row['icon'] or 'fa-layer-group',
                    'color': row['color'] or '#9C27B0',
                    'is_manual': bool(row['is_manual']),
                    'is_pinned': bool(row['is_pinned']),
                    'policy': policy,
                    'created_at': row['created_at'],
                    'last_activity': row['last_activity'],
                })

    except Exception as e:
        logger.error(f"Failed to list bubbles: {e}")
        return jsonify({'error': safe_error_message(e)}), 500

    return jsonify({'bubbles': bubbles, 'count': len(bubbles)})


@bubbles_bp.route('/api/create', methods=['POST'])
@login_required
@admin_required
def create_bubble():
    """
    Create a new manual bubble.

    Request body:
    {
        "name": "Dad's Bubble",
        "bubble_type": "family",
        "devices": ["AA:BB:CC:DD:EE:FF"],
        "icon": "fa-user-tie",
        "color": "#1976D2"
    }
    """
    data = request.get_json() or {}

    name = data.get('name', 'New Bubble')
    bubble_type = data.get('bubble_type', 'custom')
    devices = data.get('devices', [])
    icon = data.get('icon', 'fa-layer-group')
    color = data.get('color', '#9C27B0')

    # Validate bubble type
    try:
        bt = BubbleType(bubble_type)
    except ValueError:
        bt = BubbleType.CUSTOM

    # Generate bubble ID
    import hashlib
    bubble_id = f"MANUAL-{hashlib.sha256(f'{name}{datetime.now().isoformat()}'.encode()).hexdigest()[:12]}"

    # Get default policy for type
    policy = BUBBLE_TYPE_POLICIES[bt].copy()

    try:
        with get_db_connection() as conn:
            now = datetime.now().isoformat()

            # Create bubble
            conn.execute('''
                INSERT INTO bubbles
                (bubble_id, ecosystem, state, confidence, devices,
                 bubble_type, display_name, icon, color, is_manual, is_pinned,
                 created_by, policy_json, created_at, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                bubble_id, 'mixed', 'active', 1.0, json.dumps(devices),
                bt.value, name, icon, color, 1, 0,
                current_user.username, json.dumps(policy),
                now, now
            ))

            # Assign devices
            for mac in devices:
                conn.execute('''
                    INSERT OR REPLACE INTO manual_assignments
                    (mac, bubble_id, assigned_by, assigned_at, is_pinned)
                    VALUES (?, ?, ?, ?, 0)
                ''', (mac.upper(), bubble_id, current_user.username, now))

            conn.commit()

        logger.info(f"Created manual bubble {bubble_id} ({name}) with {len(devices)} devices")

        return jsonify({
            'success': True,
            'bubble_id': bubble_id,
            'message': f"Bubble '{name}' created successfully"
        })

    except Exception as e:
        logger.error(f"Failed to create bubble: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/<bubble_id>', methods=['GET'])
@login_required
def get_bubble(bubble_id):
    """Get details for a specific bubble."""
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                'SELECT * FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if not row:
                return jsonify({'error': 'Bubble not found'}), 404

            # Get assigned devices
            device_rows = conn.execute('''
                SELECT * FROM manual_assignments WHERE bubble_id = ?
            ''', (bubble_id,)).fetchall()

            devices = []
            for dr in device_rows:
                devices.append({
                    'mac': dr['mac'],
                    'is_pinned': bool(dr['is_pinned']),
                    'assigned_by': dr['assigned_by'],
                    'assigned_at': dr['assigned_at'],
                    'notes': dr['notes'],
                })

            return jsonify({
                'bubble_id': bubble_id,
                'display_name': row['display_name'],
                'bubble_type': row['bubble_type'],
                'ecosystem': row['ecosystem'],
                'state': row['state'],
                'confidence': row['confidence'],
                'devices': devices,
                'icon': row['icon'],
                'color': row['color'],
                'is_manual': bool(row['is_manual']),
                'is_pinned': bool(row['is_pinned']),
            })

    except Exception as e:
        logger.error(f"Failed to get bubble {bubble_id}: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/<bubble_id>', methods=['PUT'])
@login_required
@admin_required
def update_bubble(bubble_id):
    """
    Update a bubble's properties.

    Request body (all optional):
    {
        "display_name": "New Name",
        "bubble_type": "family",
        "icon": "fa-users",
        "color": "#4CAF50",
        "is_pinned": true
    }
    """
    data = request.get_json() or {}

    try:
        with get_db_connection() as conn:
            # Check bubble exists
            row = conn.execute(
                'SELECT bubble_id FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if not row:
                return jsonify({'error': 'Bubble not found'}), 404

            # Build update query
            updates = []
            values = []

            if 'display_name' in data:
                updates.append('display_name = ?')
                values.append(data['display_name'])

            if 'bubble_type' in data:
                updates.append('bubble_type = ?')
                values.append(data['bubble_type'])
                # Update policy based on type
                try:
                    bt = BubbleType(data['bubble_type'])
                    updates.append('policy_json = ?')
                    values.append(json.dumps(BUBBLE_TYPE_POLICIES[bt]))
                except ValueError:
                    pass

            if 'icon' in data:
                updates.append('icon = ?')
                values.append(data['icon'])

            if 'color' in data:
                updates.append('color = ?')
                values.append(data['color'])

            if 'is_pinned' in data:
                updates.append('is_pinned = ?')
                values.append(1 if data['is_pinned'] else 0)

            if updates:
                updates.append('last_activity = ?')
                values.append(datetime.now().isoformat())
                values.append(bubble_id)

                conn.execute(
                    f'UPDATE bubbles SET {", ".join(updates)} WHERE bubble_id = ?',
                    values
                )
                conn.commit()

        return jsonify({'success': True, 'message': 'Bubble updated'})

    except Exception as e:
        logger.error(f"Failed to update bubble {bubble_id}: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/<bubble_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_bubble(bubble_id):
    """Delete a bubble (manual only, AI bubbles are dissolved)."""
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                'SELECT is_manual FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if not row:
                return jsonify({'error': 'Bubble not found'}), 404

            if row['is_manual']:
                # Delete manual bubble
                conn.execute('DELETE FROM bubbles WHERE bubble_id = ?', (bubble_id,))
                conn.execute('DELETE FROM manual_assignments WHERE bubble_id = ?', (bubble_id,))
            else:
                # Mark AI bubble as dissolved
                conn.execute(
                    'UPDATE bubbles SET state = "dissolved" WHERE bubble_id = ?',
                    (bubble_id,)
                )

            conn.commit()

        return jsonify({'success': True, 'message': 'Bubble deleted'})

    except Exception as e:
        logger.error(f"Failed to delete bubble {bubble_id}: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/<bubble_id>/devices', methods=['POST'])
@login_required
@admin_required
def add_device_to_bubble(bubble_id):
    """
    Add a device to a bubble.

    Request body:
    {
        "mac": "AA:BB:CC:DD:EE:FF",
        "pin": true  // Optional: prevent AI from moving device
    }
    """
    data = request.get_json() or {}
    mac = data.get('mac', '').upper()
    pin = data.get('pin', False)

    if not mac:
        return jsonify({'error': 'MAC address required'}), 400

    try:
        with get_db_connection() as conn:
            # Check bubble exists
            row = conn.execute(
                'SELECT bubble_id FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if not row:
                return jsonify({'error': 'Bubble not found'}), 404

            now = datetime.now().isoformat()

            # Add assignment
            conn.execute('''
                INSERT OR REPLACE INTO manual_assignments
                (mac, bubble_id, assigned_by, assigned_at, is_pinned)
                VALUES (?, ?, ?, ?, ?)
            ''', (mac, bubble_id, current_user.username, now, 1 if pin else 0))

            # Update bubble devices list
            existing = conn.execute(
                'SELECT devices FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            devices = []
            if existing and existing['devices']:
                try:
                    devices = json.loads(existing['devices'])
                except (json.JSONDecodeError, TypeError):
                    pass

            if mac not in devices:
                devices.append(mac)
                conn.execute(
                    'UPDATE bubbles SET devices = ?, last_activity = ? WHERE bubble_id = ?',
                    (json.dumps(devices), now, bubble_id)
                )

            conn.commit()

        logger.info(f"Added device {mac} to bubble {bubble_id}")
        return jsonify({'success': True, 'message': f'Device {mac} added to bubble'})

    except Exception as e:
        logger.error(f"Failed to add device to bubble: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/<bubble_id>/devices/<mac>', methods=['DELETE'])
@login_required
@admin_required
def remove_device_from_bubble(bubble_id, mac):
    """Remove a device from a bubble."""
    mac = mac.upper()

    try:
        with get_db_connection() as conn:
            # Remove assignment
            conn.execute(
                'DELETE FROM manual_assignments WHERE mac = ? AND bubble_id = ?',
                (mac, bubble_id)
            )

            # Update bubble devices list
            existing = conn.execute(
                'SELECT devices FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if existing and existing['devices']:
                try:
                    devices = json.loads(existing['devices'])
                    if mac in devices:
                        devices.remove(mac)
                        conn.execute(
                            'UPDATE bubbles SET devices = ?, last_activity = ? WHERE bubble_id = ?',
                            (json.dumps(devices), datetime.now().isoformat(), bubble_id)
                        )
                except (json.JSONDecodeError, TypeError):
                    pass

            conn.commit()

        logger.info(f"Removed device {mac} from bubble {bubble_id}")
        return jsonify({'success': True, 'message': f'Device {mac} removed from bubble'})

    except Exception as e:
        logger.error(f"Failed to remove device from bubble: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/move-device', methods=['POST'])
@login_required
@admin_required
def move_device():
    """
    Move a device from one bubble to another.

    This is the main "drag and drop" API endpoint.

    Request body:
    {
        "mac": "AA:BB:CC:DD:EE:FF",
        "from_bubble": "old_bubble_id",  // Optional
        "to_bubble": "new_bubble_id",
        "pin": true  // Optional: prevent AI from moving device back
    }
    """
    data = request.get_json() or {}
    mac = data.get('mac', '').upper()
    from_bubble = data.get('from_bubble')
    to_bubble = data.get('to_bubble')
    pin = data.get('pin', False)

    if not mac or not to_bubble:
        return jsonify({'error': 'MAC and to_bubble required'}), 400

    try:
        with get_db_connection() as conn:
            now = datetime.now().isoformat()

            # Remove from old bubble if specified
            if from_bubble:
                conn.execute(
                    'DELETE FROM manual_assignments WHERE mac = ? AND bubble_id = ?',
                    (mac, from_bubble)
                )

                # Update old bubble devices list
                existing = conn.execute(
                    'SELECT devices FROM bubbles WHERE bubble_id = ?',
                    (from_bubble,)
                ).fetchone()
                if existing and existing['devices']:
                    try:
                        devices = json.loads(existing['devices'])
                        if mac in devices:
                            devices.remove(mac)
                            conn.execute(
                                'UPDATE bubbles SET devices = ? WHERE bubble_id = ?',
                                (json.dumps(devices), from_bubble)
                            )
                    except (json.JSONDecodeError, TypeError):
                        pass

            # Add to new bubble
            conn.execute('''
                INSERT OR REPLACE INTO manual_assignments
                (mac, bubble_id, assigned_by, assigned_at, is_pinned)
                VALUES (?, ?, ?, ?, ?)
            ''', (mac, to_bubble, current_user.username, now, 1 if pin else 0))

            # Update new bubble devices list
            existing = conn.execute(
                'SELECT devices FROM bubbles WHERE bubble_id = ?',
                (to_bubble,)
            ).fetchone()

            devices = []
            if existing and existing['devices']:
                try:
                    devices = json.loads(existing['devices'])
                except (json.JSONDecodeError, TypeError):
                    pass

            if mac not in devices:
                devices.append(mac)
                conn.execute(
                    'UPDATE bubbles SET devices = ?, last_activity = ? WHERE bubble_id = ?',
                    (json.dumps(devices), now, to_bubble)
                )

            conn.commit()

        logger.info(f"Moved device {mac} to bubble {to_bubble}")
        return jsonify({
            'success': True,
            'message': f'Device moved to bubble',
            'device': mac,
            'bubble': to_bubble
        })

    except Exception as e:
        logger.error(f"Failed to move device: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/<bubble_id>/pin', methods=['POST'])
@login_required
@admin_required
def pin_bubble(bubble_id):
    """Pin a bubble to prevent AI from modifying it."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                'UPDATE bubbles SET is_pinned = 1 WHERE bubble_id = ?',
                (bubble_id,)
            )
            # Also pin all device assignments
            conn.execute(
                'UPDATE manual_assignments SET is_pinned = 1 WHERE bubble_id = ?',
                (bubble_id,)
            )
            conn.commit()

        return jsonify({'success': True, 'message': 'Bubble pinned'})

    except Exception as e:
        logger.error(f"Failed to pin bubble: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/<bubble_id>/unpin', methods=['POST'])
@login_required
@admin_required
def unpin_bubble(bubble_id):
    """Unpin a bubble to allow AI modifications."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                'UPDATE bubbles SET is_pinned = 0 WHERE bubble_id = ?',
                (bubble_id,)
            )
            conn.commit()

        return jsonify({'success': True, 'message': 'Bubble unpinned'})

    except Exception as e:
        logger.error(f"Failed to unpin bubble: {e}")
        return jsonify({'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/presets')
@login_required
def get_presets():
    """Get family bubble presets for quick setup."""
    return jsonify({
        'presets': FAMILY_PRESETS,
        'types': {bt.value: BUBBLE_TYPE_POLICIES[bt] for bt in BubbleType}
    })


@bubbles_bp.route('/api/suggestions')
@login_required
def get_suggestions():
    """
    Get AI suggestions for bubble improvements.

    Returns suggestions like:
    - "Mom's iPhone is frequently communicating with a new Huawei Watch. Add to Mom's Bubble?"
    - "Guest iPad has been on network for 30 minutes. Should it stay in Guest bubble?"
    """
    suggestions = []

    try:
        # Import connection graph analyzer
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
            from connection_graph import get_connection_analyzer
            analyzer = get_connection_analyzer()
        except ImportError:
            return jsonify({'suggestions': [], 'message': 'D2D analyzer not available'})

        # Find high-affinity device pairs not in same bubble
        with get_db_connection() as conn:
            # Get all device→bubble mappings
            assignments = {}
            rows = conn.execute('SELECT mac, bubble_id FROM manual_assignments').fetchall()
            for row in rows:
                assignments[row['mac']] = row['bubble_id']

            # Check relationships
            for (mac_a, mac_b), rel in analyzer.relationships.items():
                affinity = rel.calculate_affinity_score()

                if affinity >= 0.5:  # High affinity
                    bubble_a = assignments.get(mac_a)
                    bubble_b = assignments.get(mac_b)

                    if bubble_a and bubble_b and bubble_a != bubble_b:
                        suggestions.append({
                            'type': 'merge_suggestion',
                            'message': f'Devices {mac_a[:8]} and {mac_b[:8]} communicate frequently. Consider merging bubbles?',
                            'devices': [mac_a, mac_b],
                            'affinity': affinity,
                            'action': {
                                'type': 'move_device',
                                'mac': mac_b,
                                'from_bubble': bubble_b,
                                'to_bubble': bubble_a,
                            }
                        })
                    elif bubble_a and not bubble_b:
                        suggestions.append({
                            'type': 'add_suggestion',
                            'message': f'Device {mac_b[:8]} communicates with devices in bubble. Add it?',
                            'devices': [mac_b],
                            'affinity': affinity,
                            'action': {
                                'type': 'add_device',
                                'mac': mac_b,
                                'bubble_id': bubble_a,
                            }
                        })

    except Exception as e:
        logger.error(f"Failed to get suggestions: {e}")

    return jsonify({'suggestions': suggestions[:10]})  # Limit to 10


# =============================================================================
# DEVICE NAMES API
# =============================================================================

def get_device_custom_name(mac):
    """Get custom name for a device by MAC address."""
    masked = mask_mac(mac)  # CWE-532: Pre-mask for safe logging
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                'SELECT custom_name FROM device_names WHERE mac = ?',
                (mac.upper(),)
            ).fetchone()
            return row['custom_name'] if row else None
    except Exception as e:
        logger.debug(f"Failed to get device name for {masked}: {safe_error_message(e)}")
        return None


def get_all_device_names():
    """Get all custom device names as a dict mapping MAC -> name."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute('SELECT mac, custom_name FROM device_names').fetchall()
            return {row['mac']: row['custom_name'] for row in rows}
    except Exception as e:
        logger.debug(f"Failed to get device names: {safe_error_message(e)}")
        return {}


@bubbles_bp.route('/api/device-names')
@login_required
def list_device_names():
    """List all custom device names."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute('''
                SELECT mac, custom_name, original_hostname, updated_by, updated_at
                FROM device_names
                ORDER BY updated_at DESC
            ''').fetchall()
            return jsonify({
                'success': True,
                'names': [dict(row) for row in rows]
            })
    except Exception as e:
        logger.error(f"Failed to list device names: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/device-names/<mac>', methods=['GET'])
@login_required
def get_device_name(mac):
    """Get custom name for a specific device."""
    if not MAC_PATTERN.match(mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    try:
        with get_db_connection() as conn:
            row = conn.execute('''
                SELECT mac, custom_name, original_hostname, updated_by, updated_at
                FROM device_names WHERE mac = ?
            ''', (mac.upper(),)).fetchone()

            if row:
                return jsonify({'success': True, 'name': dict(row)})
            else:
                return jsonify({'success': True, 'name': None})
    except Exception as e:
        logger.error(f"Failed to get device name: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/device-names/<mac>', methods=['PUT', 'POST'])
@login_required
def set_device_name(mac):
    """Set custom name for a device."""
    if not MAC_PATTERN.match(mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    data = request.get_json() or {}
    custom_name = data.get('name', '').strip()

    if not custom_name:
        return jsonify({'success': False, 'error': 'Name is required'}), 400

    if len(custom_name) > 64:
        return jsonify({'success': False, 'error': 'Name too long (max 64 chars)'}), 400

    # Sanitize name - only allow safe characters
    import re
    if not re.match(r'^[\w\s\-\'\.]+$', custom_name):
        return jsonify({
            'success': False,
            'error': 'Name contains invalid characters (only letters, numbers, spaces, hyphens, apostrophes, periods allowed)'
        }), 400

    try:
        from flask_login import current_user
        from datetime import datetime

        with get_db_connection() as conn:
            # Get original hostname for reference
            original_hostname = data.get('original_hostname', '')

            conn.execute('''
                INSERT OR REPLACE INTO device_names
                (mac, custom_name, original_hostname, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                mac.upper(),
                custom_name,
                original_hostname,
                current_user.username if hasattr(current_user, 'username') else 'system',
                datetime.now().isoformat()
            ))
            conn.commit()

        logger.info(f"Device {mask_mac(mac)} renamed to '{custom_name}'")
        return jsonify({'success': True, 'message': f'Device renamed to {custom_name}'})
    except Exception as e:
        logger.error(f"Failed to set device name: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@bubbles_bp.route('/api/device-names/<mac>', methods=['DELETE'])
@login_required
def delete_device_name(mac):
    """Remove custom name for a device (revert to hostname)."""
    if not MAC_PATTERN.match(mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    try:
        with get_db_connection() as conn:
            conn.execute('DELETE FROM device_names WHERE mac = ?', (mac.upper(),))
            conn.commit()

        logger.info(f"Device {mask_mac(mac)} name reset to default")
        return jsonify({'success': True, 'message': 'Device name reset to default'})
    except Exception as e:
        logger.error(f"Failed to delete device name: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# =============================================================================
# WEB UI ROUTES
# =============================================================================

@bubbles_bp.route('/')
@login_required
def index():
    """Bubble management page."""
    return render_template('bubbles/index.html')
