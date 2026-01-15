"""
AIOCHI Views - AI Eyes Dashboard
Flask views for the Cognitive Network Layer.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta
from flask import render_template, jsonify, request
from flask_login import login_required

from . import aiochi_bp
from ...security_utils import safe_error_message
from ..auth.decorators import admin_required

# Import D2D Connection Graph for device color visualization
# Uses absolute import since lib/ is at /app/lib (sibling to web/)
try:
    from lib.connection_graph import (
        get_connection_analyzer,
        get_user_bubble_color,
        DEVICE_TYPE_COLORS,
        USER_BUBBLE_COLORS,
        DeviceType,
    )
    D2D_CONNECTION_AVAILABLE = True
except ImportError as e:
    D2D_CONNECTION_AVAILABLE = False
    logging.getLogger(__name__).debug(f"D2D connection graph not available: {e}")

# Import AIOCHI Bubble Client for D2D cluster colors from container
# This is the primary source for D2D communication tracking
try:
    from lib.aiochi_bubble_client import (
        get_d2d_client,
        get_device_colors as get_d2d_device_colors,
        is_aiochi_available,
    )
    AIOCHI_D2D_AVAILABLE = True
except ImportError as e:
    AIOCHI_D2D_AVAILABLE = False
    logging.getLogger(__name__).debug(f"AIOCHI D2D client not available: {e}")

    # Stub functions
    def get_d2d_client():
        return None

    def get_d2d_device_colors():
        return {}

    def is_aiochi_available():
        return False

# Import real data integration module
try:
    from .real_data import (
        get_dnsxai_stats,
        get_recent_blocked_domains,
        get_suricata_alerts,
        get_device_events,
        get_system_performance,
        get_ambient_state,
        generate_privacy_feed,
        get_quick_actions_state,
        get_color_palette,
        get_icon_palette,
    )
    REAL_DATA_AVAILABLE = True
except ImportError as e:
    import traceback
    _import_logger = logging.getLogger(__name__)
    _import_logger.warning(f"Real data module not available: {e}")
    _import_logger.debug(f"Import traceback: {traceback.format_exc()}")
    REAL_DATA_AVAILABLE = False
except Exception as e:
    import traceback
    _import_logger = logging.getLogger(__name__)
    _import_logger.error(f"Real data module failed to load: {type(e).__name__}: {e}")
    _import_logger.debug(f"Import traceback: {traceback.format_exc()}")
    REAL_DATA_AVAILABLE = False

# Security: MAC address validation pattern
MAC_PATTERN = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


def _validate_mac_address(mac: str) -> bool:
    """Validate MAC address format to prevent command injection (CWE-78)."""
    if not mac or not isinstance(mac, str):
        return False
    return bool(MAC_PATTERN.match(mac))


def _sanitize_notes(notes: str, max_length: int = 200) -> str:
    """Sanitize notes field to prevent command injection (CWE-78).

    Only allows alphanumeric characters, spaces, and basic punctuation.
    """
    if not notes or not isinstance(notes, str):
        return ''
    # Only allow safe characters: alphanumeric, spaces, and basic punctuation
    sanitized = re.sub(r'[^a-zA-Z0-9\s.,!?\-_\']', '', notes)
    return sanitized[:max_length]


# =============================================================================
# BUBBLE TYPE TO NETWORK POLICY MAPPING
# =============================================================================
# Maps bubble/group types to their corresponding network policies
# These policy names match NetworkPolicy enum in device_policies.py
BUBBLE_TYPE_TO_POLICY = {
    'family': 'smart_home',       # Full access with smart home (home-friendly)
    'guest': 'internet_only',     # Internet only, no LAN
    'corporate': 'internet_only', # Work devices: Internet only, isolated from home
    'work': 'internet_only',      # Alias for corporate
    'smart_home': 'smart_home',   # IoT devices with full smart home access
    'iot': 'smart_home',          # Alias for smart_home
    'lan_only': 'lan_only',       # LAN only, no internet
    'quarantine': 'quarantine',   # Fully isolated
    'custom': 'smart_home',       # Default to smart_home for custom groups
}


def _apply_bubble_network_policy(mac: str, bubble_type: str):
    """
    Apply network policy for a device based on its bubble/group type.

    This function syncs ALL THREE databases and applies OpenFlow rules:
    1. autopilot.db (device_identity table) - Dashboard reads FIRST
    2. devices.db (devices table) - device_policies module, SDN fallback
    3. OpenFlow rules via host agent for actual network enforcement

    Args:
        mac: Device MAC address
        bubble_type: The bubble type (family, guest, corporate, smart_home, lan_only, quarantine, custom)
    """
    _logger = logging.getLogger(__name__)
    mac_upper = mac.upper().replace('-', ':')

    # Map bubble type to network policy
    bubble_type_lower = (bubble_type or 'custom').lower()
    policy_name = BUBBLE_TYPE_TO_POLICY.get(bubble_type_lower, 'smart_home')

    _logger.info(f"Applying bubble policy: {mac_upper} -> bubble_type={bubble_type_lower} -> policy={policy_name}")

    # Step 1: Update autopilot.db (PRIMARY source for Dashboard)
    try:
        from lib.sdn_autopilot import get_autopilot
        autopilot = get_autopilot()
        if autopilot:
            result = autopilot.set_policy(mac_upper, policy_name)
            if result:
                _logger.info(f"Updated autopilot.db: {mac_upper} -> {policy_name}")
            else:
                _logger.warning(f"Failed to update autopilot.db for {mac_upper}")
    except ImportError as e:
        _logger.warning(f"sdn_autopilot module not available: {e}")
    except Exception as e:
        _logger.error(f"Failed to update autopilot.db for {mac_upper}: {e}")

    # Step 2: Update device policy in devices.db
    try:
        from lib.device_policies import set_device_policy
        result = set_device_policy(mac_upper, policy_name)
        if result:
            _logger.info(f"Updated devices.db: {mac_upper} -> {policy_name}")
        else:
            _logger.warning(f"Failed to update devices.db for {mac_upper}")
    except ImportError as e:
        _logger.warning(f"device_policies module not available: {e}")
    except Exception as e:
        _logger.error(f"Failed to update devices.db for {mac_upper}: {e}")

    # Step 3: Apply OpenFlow rules via host agent
    try:
        from lib.host_agent_client import apply_policy, is_host_agent_available

        if not is_host_agent_available():
            _logger.warning(f"Host agent not available, cannot apply OpenFlow policy for {mac_upper}")
            return

        result = apply_policy(mac_upper, policy_name)
        if result.get('success'):
            _logger.info(f"Applied {policy_name} OpenFlow policy to device {mac_upper}")
        else:
            _logger.error(f"Failed to apply {policy_name} OpenFlow policy: {result.get('error')}")
    except ImportError as e:
        _logger.warning(f"host_agent_client not available, skipping OpenFlow policy: {e}")
    except Exception as e:
        _logger.error(f"Failed to apply OpenFlow policy for {mac_upper}: {e}")


def _apply_quarantine_network_policy(mac: str, quarantine: bool = True):
    """
    Apply or remove quarantine network policy for a device.

    This is a convenience wrapper around _apply_bubble_network_policy for quarantine.

    Args:
        mac: Device MAC address
        quarantine: True to apply quarantine (block all), False to remove (smart_home)
    """
    bubble_type = 'quarantine' if quarantine else 'smart_home'
    _apply_bubble_network_policy(mac, bubble_type)


logger = logging.getLogger(__name__)

# AIOCHI API configuration
# When AIOCHI is enabled, fts-web calls the AIOCHI containers via REST APIs
# NOTE: fts-web and aiochi-identity are on different podman networks (fts-internal vs aiochi-internal)
# so we use localhost:8060 which is port-mapped from aiochi-identity container
AIOCHI_IDENTITY_URL = 'http://127.0.0.1:8060'
AIOCHI_ENABLED = False

def check_aiochi_available(check_full_stack: bool = False) -> bool:
    """
    Check if AIOCHI services are available.

    Args:
        check_full_stack: If True, also check real_data and bubble manager availability

    Returns:
        True if AIOCHI is available and functional
    """
    import requests
    try:
        # Check identity engine health
        resp = requests.get(f'{AIOCHI_IDENTITY_URL}/health', timeout=2)
        identity_ok = resp.status_code == 200

        if not identity_ok:
            logger.debug("AIOCHI identity engine health check failed")
            return False

        if check_full_stack:
            # Verify real_data module is available
            if not REAL_DATA_AVAILABLE:
                logger.debug("AIOCHI full stack check: real_data module not available")
                return False

            # Verify bubble manager is available
            if not LOCAL_BUBBLE_AVAILABLE:
                logger.debug("AIOCHI full stack check: bubble manager not available")
                return False

        return True
    except requests.exceptions.RequestException as e:
        logger.debug(f"AIOCHI health check failed: {e}")
        return False
    except Exception as e:
        logger.debug(f"AIOCHI check error: {type(e).__name__}: {e}")
        return False


def get_aiochi_status() -> dict:
    """Get detailed AIOCHI status for debugging/dashboard."""
    import requests
    status = {
        'identity_engine': False,
        'real_data_available': REAL_DATA_AVAILABLE,
        'bubble_manager_available': LOCAL_BUBBLE_AVAILABLE,
        'sdn_autopilot_available': SDN_AUTOPILOT_AVAILABLE,
        'overall': False,
    }

    try:
        resp = requests.get(f'{AIOCHI_IDENTITY_URL}/health', timeout=2)
        status['identity_engine'] = resp.status_code == 200
    except Exception:
        pass

    # Overall is true if we have at least real_data OR identity_engine
    status['overall'] = status['identity_engine'] or status['real_data_available']
    return status


# Check on module load (but don't fail startup)
try:
    import requests
    AIOCHI_ENABLED = check_aiochi_available()
    if AIOCHI_ENABLED:
        logger.info("AIOCHI Identity Engine available at %s", AIOCHI_IDENTITY_URL)
    else:
        # Even if identity engine is down, check if real_data is available
        if REAL_DATA_AVAILABLE:
            logger.info("AIOCHI Identity Engine not reachable, but real_data module available")
        else:
            logger.info("AIOCHI Identity Engine not reachable and real_data unavailable, using demo mode")
except ImportError:
    logger.warning("requests module not available, AIOCHI integration disabled")


# ============================================================================
# Local Bubble Manager Integration (Fallback when AIOCHI container unavailable)
# ============================================================================
LOCAL_BUBBLE_MANAGER = None
LOCAL_BUBBLE_AVAILABLE = False

try:
    import sys
    import os
    from pathlib import Path
    # Add shared/aiochi to path using environment variable or fallback to known paths
    aiochi_path = None
    # 1. Check HOOKPROBE_ROOT environment variable (preferred)
    hookprobe_root = os.environ.get('HOOKPROBE_ROOT', '/opt/hookprobe')
    aiochi_env_path = Path(hookprobe_root) / 'shared' / 'aiochi'
    if aiochi_env_path.exists():
        aiochi_path = aiochi_env_path
    else:
        # 2. Fallback to relative path from this file (for development)
        aiochi_relative = Path(__file__).parent.parent.parent.parent.parent.parent / 'shared' / 'aiochi'
        if aiochi_relative.exists():
            aiochi_path = aiochi_relative

    if aiochi_path and str(aiochi_path.parent) not in sys.path:
        sys.path.insert(0, str(aiochi_path.parent))
        logger.debug(f"Added aiochi path to sys.path: {aiochi_path.parent}")

    from aiochi.bubble import get_bubble_manager, BubbleType, NetworkPolicy
    LOCAL_BUBBLE_AVAILABLE = True
    logger.info(f"Local bubble manager available (path: {aiochi_path})")
except ImportError as e:
    logger.warning(f"Local bubble manager not available: {e}")

# Import SDN autopilot for device data
SDN_AUTOPILOT_AVAILABLE = False
try:
    lib_path = Path(__file__).parent.parent.parent.parent / 'lib'
    if lib_path.exists() and str(lib_path) not in sys.path:
        sys.path.insert(0, str(lib_path))

    from sdn_autopilot import get_autopilot as get_sdn_autopilot
    SDN_AUTOPILOT_AVAILABLE = True
    logger.info("SDN Autopilot available for device data")
except ImportError as e:
    logger.warning(f"SDN Autopilot not available: {e}")

# DHCP leases file path (fallback when SDN Autopilot unavailable)
DHCP_LEASES_PATH = Path('/var/lib/misc/dnsmasq.leases')

# Import hostname decoder
try:
    from hostname_decoder import clean_device_name
except ImportError:
    def clean_device_name(name, max_length=32):
        return name if name else "Unknown Device"


def get_local_bubble_manager():
    """Get or create the local bubble manager instance."""
    global LOCAL_BUBBLE_MANAGER
    if LOCAL_BUBBLE_MANAGER is None and LOCAL_BUBBLE_AVAILABLE:
        LOCAL_BUBBLE_MANAGER = get_bubble_manager()
    return LOCAL_BUBBLE_MANAGER


# =============================================================================
# BUBBLES MODULE FALLBACK (SQLite-based bubble storage)
# =============================================================================
BUBBLES_MODULE_AVAILABLE = False
DEVICE_NAMES_AVAILABLE = False
try:
    from ..bubbles.views import (
        get_db_connection as get_bubbles_db,
        BUBBLE_TYPE_POLICIES,
        BubbleType as BubbleTypeEnum,
        get_all_device_names,
        get_device_custom_name,
    )
    BUBBLES_MODULE_AVAILABLE = True
    DEVICE_NAMES_AVAILABLE = True
    logger.info("Bubbles module database available for fallback storage")
except ImportError as e:
    logger.warning(f"Bubbles module not available: {e}")
    # Fallback stub functions
    def get_all_device_names():
        return {}
    def get_device_custom_name(mac):
        return None


def get_bubbles_from_module():
    """
    Get bubbles from the bubbles module SQLite database.
    Returns data in the same format as the AIOCHI API.
    """
    if not BUBBLES_MODULE_AVAILABLE:
        return None

    try:
        import json
        with get_bubbles_db() as conn:
            # Get all bubbles
            rows = conn.execute('''
                SELECT * FROM bubbles
                WHERE state != 'dissolved' OR state IS NULL
                ORDER BY is_manual DESC, last_activity DESC NULLS LAST
            ''').fetchall()

            bubbles = []
            all_devices = get_sdn_devices()  # Get real device info
            all_devices_map = {d['mac'].upper(): d for d in all_devices}
            assigned_macs = set()

            for row in rows:
                bubble_id = row['bubble_id']

                # Get devices in bubble from manual_assignments
                device_rows = conn.execute('''
                    SELECT mac FROM manual_assignments WHERE bubble_id = ?
                ''', (bubble_id,)).fetchall()

                devices = [r['mac'] for r in device_rows]

                # Also check devices_json field in bubbles table
                if row['devices_json']:
                    try:
                        stored_devices = json.loads(row['devices_json'])
                        devices.extend(stored_devices)
                    except (json.JSONDecodeError, TypeError):
                        pass

                devices = list(set(devices))  # Deduplicate
                for mac in devices:
                    assigned_macs.add(mac.upper())

                # Enrich device data with real info
                devices_with_info = []
                for mac in devices:
                    mac_upper = mac.upper()
                    device_info = all_devices_map.get(mac_upper, {})
                    devices_with_info.append({
                        'mac': mac_upper,
                        'label': device_info.get('label', mac_upper[:8]),
                        'vendor': device_info.get('vendor', 'Unknown'),
                        'online': device_info.get('online', False),
                        'ip': device_info.get('ip', ''),
                    })

                # Get policy - normalize key names for frontend
                bubble_type = row['bubble_type'] or 'custom'
                # Map common type aliases
                type_aliases = {'work': 'corporate', 'iot': 'smart_home', 'lan': 'lan_only'}
                mapped_type = type_aliases.get(bubble_type.lower(), bubble_type.lower())
                try:
                    raw_policy = BUBBLE_TYPE_POLICIES.get(
                        BubbleTypeEnum(mapped_type),
                        BUBBLE_TYPE_POLICIES[BubbleTypeEnum.CUSTOM]
                    ).copy()
                    # Normalize policy keys for frontend compatibility
                    policy = {
                        'internet': raw_policy.get('internet_access', True),
                        'lan': raw_policy.get('lan_access', True),
                        'd2d': raw_policy.get('d2d_allowed', True),
                        'vlan': raw_policy.get('vlan', 100),
                        'smart_home': raw_policy.get('smart_home_access', False),
                        'shared_devices': raw_policy.get('shared_devices', False),
                    }
                except (ValueError, KeyError):
                    policy = {'internet': True, 'lan': True, 'd2d': True, 'vlan': 100, 'smart_home': False, 'shared_devices': False}

                bubbles.append({
                    'bubble_id': bubble_id,
                    'name': row['name'] or row['display_name'] or f"Bubble {bubble_id[:8]}",
                    'bubble_type': bubble_type.upper(),
                    'icon': row['icon'] or 'fa-layer-group',
                    'color': row['color'] or '#2196F3',
                    'devices': devices_with_info,
                    'policy': policy,
                    'is_manual': bool(row['is_manual']),
                    'is_pinned': bool(row['is_pinned']),
                    'confidence': float(row['confidence'] or 1.0),
                })

            # Unassigned devices - devices not in any bubble
            unassigned = []
            for device in all_devices:
                if device['mac'].upper() not in assigned_macs:
                    unassigned.append({
                        'mac': device['mac'],
                        'label': device.get('label', device['mac'][:8]),
                        'vendor': device.get('vendor', 'Unknown'),
                        'online': device.get('online', False),
                        'ip': device.get('ip', ''),
                    })

            return {
                'bubbles': bubbles,
                'unassigned_devices': unassigned,
            }

    except Exception as e:
        logger.error(f"Failed to get bubbles from module: {e}")
        import traceback
        traceback.print_exc()
        return None


def create_bubble_in_module(name, bubble_type, devices, icon, color):
    """
    Create a bubble in the bubbles module SQLite database.
    """
    if not BUBBLES_MODULE_AVAILABLE:
        return None

    try:
        import json
        import hashlib
        from flask_login import current_user

        with get_bubbles_db() as conn:
            now = datetime.now().isoformat()

            # Generate bubble ID - sanitize to alphanumeric and hyphens only
            import re
            sanitized_name = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
            bubble_id = f"bubble-{sanitized_name}-{hashlib.sha256(f'{name}{now}'.encode()).hexdigest()[:8]}"

            # Get default policy for type
            try:
                bt = BubbleTypeEnum(bubble_type.lower())
                policy = BUBBLE_TYPE_POLICIES.get(bt, BUBBLE_TYPE_POLICIES[BubbleTypeEnum.CUSTOM])
            except (ValueError, KeyError):
                policy = {'internet': True, 'lan': True, 'd2d': True, 'vlan': 100}

            # Create bubble
            conn.execute('''
                INSERT INTO bubbles
                (bubble_id, ecosystem, state, confidence, devices_json,
                 bubble_type, name, display_name, icon, color, is_manual, is_pinned,
                 created_by, policies_json, created_at, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                bubble_id, 'mixed', 'active', 1.0, json.dumps(devices),
                bubble_type.lower(), name, name, icon, color, 1, 0,
                current_user.username if hasattr(current_user, 'username') else 'system',
                json.dumps(policy), now, now
            ))

            # Assign devices
            for mac in devices:
                conn.execute('''
                    INSERT OR REPLACE INTO manual_assignments
                    (mac, bubble_id, assigned_by, assigned_at, is_pinned)
                    VALUES (?, ?, ?, ?, 0)
                ''', (mac.upper(), bubble_id,
                      current_user.username if hasattr(current_user, 'username') else 'system',
                      now))

            conn.commit()

        logger.info(f"Created bubble {bubble_id} ({name}) via bubbles module")
        return bubble_id

    except Exception as e:
        logger.error(f"Failed to create bubble in module: {e}")
        import traceback
        traceback.print_exc()
        return None


def add_device_to_bubble_in_module(bubble_id, mac):
    """
    Add a device to a bubble in the bubbles module SQLite database.

    Applies the bubble's network policy to the device across all databases:
    - quarantine -> quarantine policy (fully isolated)
    - guest/corporate/work -> internet_only policy
    - family/smart_home/iot -> smart_home policy
    - lan_only -> lan_only policy
    """
    if not BUBBLES_MODULE_AVAILABLE:
        return False

    try:
        import json
        from flask_login import current_user

        bubble_type = None

        with get_bubbles_db() as conn:
            now = datetime.now().isoformat()

            # Check bubble exists and get bubble_type
            row = conn.execute(
                'SELECT bubble_id, devices_json, bubble_type FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if not row:
                logger.warning(f"Bubble {bubble_id} not found in module database")
                return False

            # Get the bubble type for policy mapping
            bubble_type = row['bubble_type'] or 'custom'

            # Add to manual_assignments (removes from any other bubble first)
            conn.execute(
                'DELETE FROM manual_assignments WHERE mac = ?',
                (mac.upper(),)
            )
            conn.execute('''
                INSERT INTO manual_assignments
                (mac, bubble_id, assigned_by, assigned_at, is_pinned)
                VALUES (?, ?, ?, ?, 0)
            ''', (mac.upper(), bubble_id,
                  current_user.username if hasattr(current_user, 'username') else 'system',
                  now))

            # Update bubble devices list
            devices = []
            if row['devices_json']:
                try:
                    devices = json.loads(row['devices_json'])
                except (json.JSONDecodeError, TypeError):
                    pass

            if mac.upper() not in [d.upper() for d in devices]:
                devices.append(mac.upper())
                conn.execute(
                    'UPDATE bubbles SET devices_json = ?, last_activity = ? WHERE bubble_id = ?',
                    (json.dumps(devices), now, bubble_id)
                )

            conn.commit()

        # Apply the bubble's network policy to the device (syncs all 3 databases)
        _apply_bubble_network_policy(mac.upper(), bubble_type)

        logger.info(f"Added device {mac} to bubble {bubble_id} (type={bubble_type}) via bubbles module")
        return True

    except Exception as e:
        logger.error(f"Failed to add device to bubble in module: {e}")
        import traceback
        traceback.print_exc()
        return False


def remove_device_from_bubble_in_module(bubble_id, mac):
    """
    Remove a device from a bubble in the bubbles module SQLite database.

    If removing from quarantine (SYSTEM-QUARANTINE), also removes the ISOLATED
    network policy to unblock the device.
    """
    if not BUBBLES_MODULE_AVAILABLE:
        return False

    try:
        import json

        # Check if this is quarantine before removing
        is_quarantine = bubble_id == 'SYSTEM-QUARANTINE'

        with get_bubbles_db() as conn:
            now = datetime.now().isoformat()

            # Also check bubble_type in case bubble_id doesn't match
            if not is_quarantine:
                row = conn.execute(
                    'SELECT bubble_type FROM bubbles WHERE bubble_id = ?',
                    (bubble_id,)
                ).fetchone()
                if row and row['bubble_type'] == 'quarantine':
                    is_quarantine = True

            # Remove from manual_assignments
            conn.execute(
                'DELETE FROM manual_assignments WHERE mac = ? AND bubble_id = ?',
                (mac.upper(), bubble_id)
            )

            # Update bubble devices list
            row = conn.execute(
                'SELECT devices_json FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if row and row['devices_json']:
                try:
                    devices = json.loads(row['devices_json'])
                    devices = [d for d in devices if d.upper() != mac.upper()]
                    conn.execute(
                        'UPDATE bubbles SET devices_json = ?, last_activity = ? WHERE bubble_id = ?',
                        (json.dumps(devices), now, bubble_id)
                    )
                except (json.JSONDecodeError, TypeError):
                    pass

            conn.commit()

        # Remove quarantine network policy if removing from quarantine
        if is_quarantine:
            _apply_quarantine_network_policy(mac.upper(), quarantine=False)

        logger.info(f"Removed device {mac} from bubble {bubble_id} via bubbles module")
        return True

    except Exception as e:
        logger.error(f"Failed to remove device from bubble in module: {e}")
        import traceback
        traceback.print_exc()
        return False


def move_device_in_module(mac, from_bubble, to_bubble):
    """
    Move a device between bubbles in the bubbles module SQLite database.

    Applies the TARGET bubble's network policy to the device:
    - quarantine -> quarantine policy (fully isolated)
    - guest/corporate/work -> internet_only policy
    - family/smart_home/iot -> smart_home policy
    - lan_only -> lan_only policy
    """
    if not BUBBLES_MODULE_AVAILABLE:
        return False

    try:
        import json
        from flask_login import current_user

        to_bubble_type = None

        with get_bubbles_db() as conn:
            now = datetime.now().isoformat()

            # Check target bubble exists and get bubble_type
            to_row = conn.execute(
                'SELECT bubble_id, bubble_type FROM bubbles WHERE bubble_id = ?',
                (to_bubble,)
            ).fetchone()

            if not to_row:
                logger.warning(f"Target bubble {to_bubble} not found in module database")
                return False

            to_bubble_type = to_row['bubble_type'] or 'custom'

            # Remove device from source bubble's devices_json
            if from_bubble:
                from_row = conn.execute(
                    'SELECT devices_json FROM bubbles WHERE bubble_id = ?',
                    (from_bubble,)
                ).fetchone()
                if from_row and from_row['devices_json']:
                    try:
                        devices = json.loads(from_row['devices_json'])
                        devices = [d for d in devices if d.upper() != mac.upper()]
                        conn.execute(
                            'UPDATE bubbles SET devices_json = ? WHERE bubble_id = ?',
                            (json.dumps(devices), from_bubble)
                        )
                    except (json.JSONDecodeError, TypeError):
                        pass

            # Remove from any existing assignment
            conn.execute('DELETE FROM manual_assignments WHERE mac = ?', (mac.upper(),))

            # Add to new bubble
            conn.execute('''
                INSERT INTO manual_assignments
                (mac, bubble_id, assigned_by, assigned_at, is_pinned)
                VALUES (?, ?, ?, ?, 0)
            ''', (mac.upper(), to_bubble,
                  current_user.username if hasattr(current_user, 'username') else 'system',
                  now))

            # Update target bubble devices list
            devices = []
            to_devices_row = conn.execute(
                'SELECT devices_json FROM bubbles WHERE bubble_id = ?',
                (to_bubble,)
            ).fetchone()
            if to_devices_row and to_devices_row['devices_json']:
                try:
                    devices = json.loads(to_devices_row['devices_json'])
                except (json.JSONDecodeError, TypeError):
                    pass

            if mac.upper() not in [d.upper() for d in devices]:
                devices.append(mac.upper())
                conn.execute(
                    'UPDATE bubbles SET devices_json = ?, last_activity = ? WHERE bubble_id = ?',
                    (json.dumps(devices), now, to_bubble)
                )

            conn.commit()

        # Apply the TARGET bubble's network policy (syncs all 3 databases)
        _apply_bubble_network_policy(mac.upper(), to_bubble_type)

        logger.info(f"Moved device {mac} from {from_bubble} to {to_bubble} (type={to_bubble_type}) via bubbles module")
        return True

    except Exception as e:
        logger.error(f"Failed to move device in module: {e}")
        import traceback
        traceback.print_exc()
        return False


def update_bubble_in_module(bubble_id, name=None, bubble_type=None, icon=None, color=None):
    """
    Update a bubble in the bubbles module SQLite database.
    """
    if not BUBBLES_MODULE_AVAILABLE:
        return False

    try:
        import json

        with get_bubbles_db() as conn:
            now = datetime.now().isoformat()

            # Check bubble exists
            row = conn.execute(
                'SELECT bubble_id FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            ).fetchone()

            if not row:
                logger.warning(f"Bubble {bubble_id} not found in module database")
                return False

            # Build update query dynamically
            updates = []
            params = []

            if name is not None:
                updates.append('name = ?')
                updates.append('display_name = ?')
                params.extend([name, name])

            if bubble_type is not None:
                updates.append('bubble_type = ?')
                params.append(bubble_type.lower() if isinstance(bubble_type, str) else bubble_type.value)

                # Update policy when type changes
                try:
                    bt = BubbleTypeEnum(bubble_type.lower() if isinstance(bubble_type, str) else bubble_type.value)
                    policy = BUBBLE_TYPE_POLICIES.get(bt, BUBBLE_TYPE_POLICIES[BubbleTypeEnum.CUSTOM])
                    updates.append('policies_json = ?')
                    params.append(json.dumps(policy))
                except (ValueError, KeyError):
                    pass

            if icon is not None:
                updates.append('icon = ?')
                params.append(icon)

            if color is not None:
                updates.append('color = ?')
                params.append(color)

            if updates:
                updates.append('last_activity = ?')
                params.append(now)
                params.append(bubble_id)

                query = f"UPDATE bubbles SET {', '.join(updates)} WHERE bubble_id = ?"
                conn.execute(query, params)
                conn.commit()

        logger.info(f"Updated bubble {bubble_id} via bubbles module")
        return True

    except Exception as e:
        logger.error(f"Failed to update bubble in module: {e}")
        import traceback
        traceback.print_exc()
        return False


def delete_bubble_in_module(bubble_id):
    """
    Delete a bubble from the bubbles module SQLite database.
    """
    if not BUBBLES_MODULE_AVAILABLE:
        return False

    try:
        with get_bubbles_db() as conn:
            # Remove all device assignments
            conn.execute(
                'DELETE FROM manual_assignments WHERE bubble_id = ?',
                (bubble_id,)
            )

            # Delete the bubble
            cursor = conn.execute(
                'DELETE FROM bubbles WHERE bubble_id = ?',
                (bubble_id,)
            )

            conn.commit()

            if cursor.rowcount > 0:
                logger.info(f"Deleted bubble {bubble_id} via bubbles module")
                return True
            else:
                logger.warning(f"Bubble {bubble_id} not found for deletion")
                return False

    except Exception as e:
        logger.error(f"Failed to delete bubble in module: {e}")
        import traceback
        traceback.print_exc()
        return False


ARP_STATUS_FILE = Path('/var/lib/hookprobe/arp-status.json')

def get_arp_online_status():
    """
    Get real-time online status from ARP table.

    Reads from /var/lib/hookprobe/arp-status.json which is updated
    every 5 seconds by the fts-arp-export.timer systemd service.

    ARP states:
    - REACHABLE: Device actively communicating (definitely online)
    - STALE: Device was seen recently (likely online, within ~30-60s)
    - DELAY/PROBE: Device being checked (transitional)
    - FAILED: Device not reachable (offline)

    Returns:
        Dict mapping MAC address (uppercase) to online status dict:
        {'online': bool, 'state': str, 'ip': str}
    """
    arp_status = {}
    try:
        if ARP_STATUS_FILE.exists():
            import json
            import time
            # Check file age - if older than 30 seconds, data may be stale
            file_age = time.time() - ARP_STATUS_FILE.stat().st_mtime
            if file_age > 30:
                logger.warning(f"ARP status file is {file_age:.0f}s old, data may be stale")

            with open(ARP_STATUS_FILE, 'r') as f:
                arp_status = json.load(f)

            online_count = sum(1 for s in arp_status.values() if s.get('online', False))
            logger.debug(f"ARP status: {len(arp_status)} devices, {online_count} online (file age: {file_age:.1f}s)")
        else:
            logger.debug(f"ARP status file not found: {ARP_STATUS_FILE}")

    except Exception as e:
        logger.warning(f"Failed to read ARP status: {e}")

    return arp_status


def get_dhcp_devices():
    """
    Get devices from DHCP leases file (fallback when SDN Autopilot unavailable).

    Reads /var/lib/misc/dnsmasq.leases which has format:
    <expiry_timestamp> <mac> <ip> <hostname> <client_id>

    Returns:
        List of device dicts with mac, label, ip, online, vendor, device_type
    """
    devices = []
    try:
        if not DHCP_LEASES_PATH.exists():
            logger.debug(f"DHCP leases file not found: {DHCP_LEASES_PATH}")
            return []

        import time
        current_time = int(time.time())

        # Get real-time ARP status for accurate online detection
        arp_status = get_arp_online_status()

        with open(DHCP_LEASES_PATH, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    try:
                        expiry = int(parts[0])
                        mac = parts[1].upper()
                        ip = parts[2]
                        hostname = parts[3] if parts[3] != '*' else ''

                        # Validate MAC format
                        if not _validate_mac_address(mac):
                            continue

                        # Use ARP for real-time online status (primary)
                        # Fall back to DHCP lease expiry if not in ARP table
                        arp_info = arp_status.get(mac)
                        if arp_info:
                            is_online = arp_info['online']
                            arp_state = arp_info['state']
                        else:
                            # Device not in ARP table - check if lease is recent
                            is_online = expiry > current_time
                            arp_state = 'UNKNOWN'

                        # Try to detect device type from hostname
                        device_type = 'unknown'
                        hostname_lower = hostname.lower()
                        if any(x in hostname_lower for x in ['iphone', 'ipad', 'macbook', 'mac', 'apple']):
                            device_type = 'apple'
                        elif any(x in hostname_lower for x in ['android', 'galaxy', 'samsung', 'pixel']):
                            device_type = 'android'
                        elif any(x in hostname_lower for x in ['tv', 'roku', 'firestick', 'chromecast']):
                            device_type = 'tv'
                        elif any(x in hostname_lower for x in ['hooksound', 'speaker', 'echo', 'alexa']):
                            device_type = 'speaker'
                        elif any(x in hostname_lower for x in ['windows', 'desktop', 'laptop', 'pc']):
                            device_type = 'computer'

                        devices.append({
                            'mac': mac,
                            'label': clean_device_name(hostname) if hostname else f"Device ({mac[-8:]})",
                            'vendor': 'Unknown',  # Would need OUI lookup
                            'ip': ip,
                            'online': is_online,
                            'arp_state': arp_state,
                            'device_type': device_type,
                        })
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse DHCP lease line: {line.strip()}: {e}")
                        continue

        online_count = sum(1 for d in devices if d['online'])
        logger.debug(f"Found {len(devices)} devices from DHCP leases, {online_count} online (ARP-based)")
        return devices

    except Exception as e:
        logger.warning(f"Failed to read DHCP leases: {e}")
        return []


def get_sdn_devices():
    """Get all devices from SDN Autopilot or DHCP leases fallback."""
    # Get real-time ARP status for accurate online detection
    arp_status = get_arp_online_status()

    # Get custom device names (user-defined names take priority)
    custom_names = get_all_device_names()

    # Try SDN Autopilot first
    if SDN_AUTOPILOT_AVAILABLE:
        try:
            autopilot = get_sdn_autopilot()
            if autopilot:
                devices = autopilot.get_all_devices()
                result = []
                for d in devices:
                    if not d.get('mac'):
                        continue
                    mac = d.get('mac', '').upper()
                    # Use ARP status for real-time online detection
                    arp_info = arp_status.get(mac, {})
                    is_online = arp_info.get('online', d.get('is_online', False))
                    # Custom name (user-defined) takes priority over hostname
                    hostname = d.get('friendly_name') or d.get('hostname', '')
                    label = custom_names.get(mac) or clean_device_name(hostname) or d.get('device_type', 'Unknown')
                    result.append({
                        'mac': mac,
                        'label': label,
                        'hostname': hostname,  # Keep original for reference
                        'vendor': d.get('vendor', 'Unknown'),
                        'ip': arp_info.get('ip', '') or d.get('ip', ''),
                        'online': is_online,
                        'device_type': d.get('device_type', 'unknown'),
                        'arp_state': arp_info.get('state', 'UNKNOWN'),
                    })
                if result:
                    return result
        except Exception as e:
            logger.warning(f"Failed to get SDN devices: {e}")

    # Fallback to DHCP leases
    dhcp_devices = get_dhcp_devices()
    if dhcp_devices:
        # Apply custom names to DHCP devices too
        for device in dhcp_devices:
            mac = device['mac']
            if mac in custom_names:
                device['hostname'] = device.get('label', '')  # Keep original as hostname
                device['label'] = custom_names[mac]
        logger.info(f"Using DHCP fallback: found {len(dhcp_devices)} devices")
        return dhcp_devices

    return []


def fetch_aiochi_devices():
    """Fetch devices from AIOCHI Identity Engine."""
    import requests
    try:
        resp = requests.get(f'{AIOCHI_IDENTITY_URL}/api/devices', timeout=3)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch AIOCHI devices: {e}")
        return None


def fetch_aiochi_ecosystems():
    """Fetch ecosystem bubbles from AIOCHI Identity Engine."""
    import requests
    try:
        resp = requests.get(f'{AIOCHI_IDENTITY_URL}/api/ecosystems', timeout=3)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch AIOCHI ecosystems: {e}")
        return None


def get_demo_presence():
    """Generate demo presence data for the Three Pillars."""
    return {
        'bubbles': [
            {
                'id': 'dad',
                'label': "Dad's Bubble",
                'icon': 'fa-user',
                'color': '#4fc3f7',
                'devices': [
                    {'name': 'iPhone 15 Pro', 'type': 'phone', 'online': True, 'last_seen': 'Now'},
                    {'name': 'MacBook Pro', 'type': 'laptop', 'online': True, 'last_seen': 'Now'},
                    {'name': 'Apple Watch', 'type': 'watch', 'online': True, 'last_seen': 'Now'},
                ],
                'ecosystem': 'apple',
                'trust_level': 'CORE'
            },
            {
                'id': 'mom',
                'label': "Mom's Bubble",
                'icon': 'fa-user',
                'color': '#f48fb1',
                'devices': [
                    {'name': 'Galaxy S24', 'type': 'phone', 'online': True, 'last_seen': 'Now'},
                    {'name': 'Galaxy Tab', 'type': 'tablet', 'online': False, 'last_seen': '2h ago'},
                ],
                'ecosystem': 'samsung',
                'trust_level': 'CORE'
            },
            {
                'id': 'kids',
                'label': "Kids' Bubble",
                'icon': 'fa-child',
                'color': '#81c784',
                'devices': [
                    {'name': 'iPad', 'type': 'tablet', 'online': True, 'last_seen': 'Now'},
                    {'name': 'Nintendo Switch', 'type': 'gaming', 'online': True, 'last_seen': 'Now'},
                    {'name': 'Chromebook', 'type': 'laptop', 'online': False, 'last_seen': '5h ago'},
                ],
                'ecosystem': 'mixed',
                'trust_level': 'TRUSTED'
            },
            {
                'id': 'iot',
                'label': 'Smart Home',
                'icon': 'fa-home',
                'color': '#ffb74d',
                'devices': [
                    {'name': 'HomePod Mini', 'type': 'speaker', 'online': True, 'last_seen': 'Now'},
                    {'name': 'Nest Thermostat', 'type': 'thermostat', 'online': True, 'last_seen': 'Now'},
                    {'name': 'Ring Doorbell', 'type': 'camera', 'online': True, 'last_seen': 'Now'},
                    {'name': 'Philips Hue Bridge', 'type': 'hub', 'online': True, 'last_seen': 'Now'},
                ],
                'ecosystem': 'iot',
                'trust_level': 'KNOWN'
            }
        ],
        'total_devices': 12,
        'online_devices': 10,
        'ecosystems': {
            'apple': 4,
            'samsung': 2,
            'google': 1,
            'other': 5
        }
    }


def get_demo_privacy_feed():
    """Generate demo privacy feed (narrative events)."""
    now = datetime.now()
    return {
        'events': [
            {
                'id': 1,
                'time': (now - timedelta(minutes=2)).strftime('%I:%M %p'),
                'icon': 'fa-shield-check',
                'color': 'success',
                'title': 'All Clear',
                'narrative': "Your network is running smoothly. No threats detected in the last hour.",
                'category': 'status'
            },
            {
                'id': 2,
                'time': (now - timedelta(minutes=15)).strftime('%I:%M %p'),
                'icon': 'fa-download',
                'color': 'info',
                'title': 'Software Update',
                'narrative': "The HomePod Mini updated its software successfully. Everything looks good!",
                'category': 'update'
            },
            {
                'id': 3,
                'time': (now - timedelta(minutes=32)).strftime('%I:%M %p'),
                'icon': 'fa-lock',
                'color': 'warning',
                'title': 'Blocked Connection',
                'narrative': "I blocked a suspicious connection attempt from an unknown server. Your Ring Doorbell is protected.",
                'category': 'security'
            },
            {
                'id': 4,
                'time': (now - timedelta(hours=1, minutes=5)).strftime('%I:%M %p'),
                'icon': 'fa-wifi',
                'color': 'info',
                'title': 'New Device',
                'narrative': "A new device 'Guest_Laptop' joined the Guest WiFi. I'm keeping an eye on it.",
                'category': 'device'
            },
            {
                'id': 5,
                'time': (now - timedelta(hours=2)).strftime('%I:%M %p'),
                'icon': 'fa-ban',
                'color': 'success',
                'title': 'Ads Blocked',
                'narrative': "Blocked 247 tracking attempts and 89 ads in the last hour. Your privacy is protected.",
                'category': 'privacy'
            },
            {
                'id': 6,
                'time': (now - timedelta(hours=3, minutes=20)).strftime('%I:%M %p'),
                'icon': 'fa-clock',
                'color': 'info',
                'title': 'Pattern Learned',
                'narrative': "I noticed Dad usually arrives home around 6:30 PM. I'll let you know if something seems unusual.",
                'category': 'learning'
            }
        ],
        'unread_count': 2,
        'categories': {
            'security': 1,
            'privacy': 1,
            'device': 1,
            'update': 1,
            'status': 1,
            'learning': 1
        }
    }


def get_demo_performance():
    """Generate demo performance data."""
    return {
        'health_score': 87,
        'health_trend': 'stable',  # improving, stable, degrading
        'insight': "Your network is performing well. The microwave in the kitchen occasionally causes brief WiFi interference with the HomePod.",
        'metrics': {
            'latency_ms': 12,
            'latency_trend': 'good',
            'bandwidth_used_pct': 34,
            'bandwidth_trend': 'normal',
            'devices_active': 10,
            'devices_total': 12,
            'uptime_pct': 99.8,
            'threats_blocked_24h': 156
        },
        'recommendations': [
            {
                'priority': 'low',
                'icon': 'fa-wifi',
                'text': "Consider moving the HomePod away from the microwave for better connectivity."
            }
        ]
    }


def get_demo_ambient_state():
    """Get demo ambient state (CALM/CURIOUS/ALERT)."""
    return {
        'state': 'CALM',
        'color': '#81c784',
        'icon': 'fa-shield-check',
        'message': "Everything is peaceful. Your network is protected.",
        'last_alert': None,
        'whisper': {
            'phase': '🌙',
            'phase_name': 'Dreaming',
            'message': "Learning your network patterns while you sleep..."
        }
    }


def get_demo_quick_actions():
    """Get available quick actions."""
    return {
        'actions': [
            {
                'id': 'pause_kids',
                'label': "Pause Kids' Internet",
                'icon': 'fa-pause-circle',
                'color': 'warning',
                'active': False,
                'description': "Temporarily block internet for kids' devices"
            },
            {
                'id': 'game_mode',
                'label': 'Game Mode',
                'icon': 'fa-gamepad',
                'color': 'info',
                'active': False,
                'description': "Prioritize gaming traffic for low latency"
            },
            {
                'id': 'privacy_mode',
                'label': 'Privacy Mode',
                'icon': 'fa-user-secret',
                'color': 'primary',
                'active': True,
                'description': "Block all tracking and analytics domains"
            },
            {
                'id': 'guest_lockdown',
                'label': 'Guest Lockdown',
                'icon': 'fa-lock',
                'color': 'danger',
                'active': False,
                'description': "Isolate guest network from main network"
            }
        ]
    }


@aiochi_bp.route('/')
@login_required
def index():
    """AIOCHI main dashboard - The Three Pillars."""
    return render_template('aiochi/index.html')


@aiochi_bp.route('/cortex')
@login_required
def cortex():
    """Cortex - Neural Command Center 3D Globe Visualization."""
    return render_template('aiochi/cortex.html')


@aiochi_bp.route('/api/status')
@login_required
def api_status():
    """Get full AIOCHI status for dashboard."""
    try:
        # Use real data if available
        if REAL_DATA_AVAILABLE:
            return jsonify({
                'success': True,
                'demo_mode': False,
                'real_data': True,
                'timestamp': datetime.now().isoformat(),
                'ambient': get_ambient_state(),
                'presence': _get_real_presence(),
                'privacy': generate_privacy_feed(),
                'performance': _get_real_performance(),
                'quick_actions': get_quick_actions_state()
            })

        # Fallback to demo mode
        return jsonify({
            'success': True,
            'demo_mode': True,
            'real_data': False,
            'timestamp': datetime.now().isoformat(),
            'ambient': get_demo_ambient_state(),
            'presence': get_demo_presence(),
            'privacy': get_demo_privacy_feed(),
            'performance': get_demo_performance(),
            'quick_actions': get_demo_quick_actions()
        })
    except Exception as e:
        logger.error(f"AIOCHI status API error: {e}")
        return jsonify({
            'success': False,
            'error': safe_error_message(e)
        }), 500


def _get_real_presence():
    """Get real presence data from bubble manager and SDN devices."""
    try:
        # Try local bubble manager first
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                bubbles_list = manager.get_all_bubbles()
                all_devices = get_sdn_devices()
                all_devices_map = {d['mac'].upper(): d for d in all_devices}

                bubbles_data = []
                total_devices = 0
                online_devices = 0
                ecosystems = {}

                for bubble in bubbles_list:
                    devices_in_bubble = []
                    for mac in bubble.devices:
                        mac_upper = mac.upper()
                        device_info = all_devices_map.get(mac_upper, {})
                        is_online = device_info.get('online', False)
                        devices_in_bubble.append({
                            'name': device_info.get('label', mac_upper[:8]),
                            'type': device_info.get('device_type', 'unknown'),
                            'online': is_online,
                            'last_seen': 'Now' if is_online else 'Unknown',
                        })
                        total_devices += 1
                        if is_online:
                            online_devices += 1

                    # Detect ecosystem based on vendor
                    ecosystem = 'mixed'
                    vendor = bubble.ecosystem or 'mixed'
                    if 'apple' in vendor.lower():
                        ecosystem = 'apple'
                    elif 'samsung' in vendor.lower() or 'galaxy' in vendor.lower():
                        ecosystem = 'samsung'
                    elif 'google' in vendor.lower():
                        ecosystem = 'google'

                    ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + len(devices_in_bubble)

                    bubbles_data.append({
                        'id': bubble.bubble_id,
                        'label': bubble.name,
                        'icon': bubble.icon or 'fa-layer-group',
                        'color': bubble.color or '#2196F3',
                        'devices': devices_in_bubble,
                        'ecosystem': ecosystem,
                        'trust_level': 'CORE' if bubble.bubble_type.value in ('family', 'FAMILY') else 'KNOWN',
                    })

                return {
                    'bubbles': bubbles_data,
                    'total_devices': total_devices,
                    'online_devices': online_devices,
                    'ecosystems': ecosystems,
                }

        # Try bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            module_data = get_bubbles_from_module()
            if module_data and module_data.get('bubbles'):
                all_devices = get_sdn_devices()
                all_devices_map = {d['mac'].upper(): d for d in all_devices}

                bubbles_data = []
                total_devices = 0
                online_devices = 0
                ecosystems = {}

                for bubble in module_data['bubbles']:
                    devices_in_bubble = []
                    for device in bubble.get('devices', []):
                        mac = device.get('mac', '').upper()
                        device_info = all_devices_map.get(mac, {})
                        is_online = device.get('online', device_info.get('online', False))
                        devices_in_bubble.append({
                            'name': device.get('label', mac[:8]),
                            'type': device_info.get('device_type', 'unknown'),
                            'online': is_online,
                            'last_seen': 'Now' if is_online else 'Unknown',
                        })
                        total_devices += 1
                        if is_online:
                            online_devices += 1

                    ecosystem = 'mixed'
                    ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + len(devices_in_bubble)

                    bubbles_data.append({
                        'id': bubble['bubble_id'],
                        'label': bubble['name'],
                        'icon': bubble.get('icon', 'fa-layer-group'),
                        'color': bubble.get('color', '#2196F3'),
                        'devices': devices_in_bubble,
                        'ecosystem': ecosystem,
                        'trust_level': 'CORE' if bubble.get('bubble_type', '').upper() == 'FAMILY' else 'KNOWN',
                    })

                if bubbles_data:
                    return {
                        'bubbles': bubbles_data,
                        'total_devices': total_devices,
                        'online_devices': online_devices,
                        'ecosystems': ecosystems,
                    }

        # Try DHCP devices only (no bubbles, just show who's online)
        dhcp_devices = get_sdn_devices()
        if dhcp_devices:
            online_count = sum(1 for d in dhcp_devices if d.get('online', False))
            return {
                'bubbles': [{
                    'id': 'unassigned',
                    'label': 'All Devices',
                    'icon': 'fa-network-wired',
                    'color': '#607D8B',
                    'devices': [
                        {
                            'name': d.get('label', d.get('mac', 'Unknown')[:8]),
                            'type': d.get('device_type', 'unknown'),
                            'online': d.get('online', False),
                            'last_seen': 'Now' if d.get('online', False) else 'Unknown',
                        }
                        for d in dhcp_devices
                    ],
                    'ecosystem': 'mixed',
                    'trust_level': 'KNOWN',
                }],
                'total_devices': len(dhcp_devices),
                'online_devices': online_count,
                'ecosystems': {'mixed': len(dhcp_devices)},
            }

        # Fallback to demo only if nothing else available
        return get_demo_presence()
    except Exception as e:
        logger.warning(f"Could not get real presence: {e}")
        return get_demo_presence()


def _get_real_performance():
    """Get real performance metrics."""
    try:
        if REAL_DATA_AVAILABLE:
            system_perf = get_system_performance()
            dns_stats = get_dnsxai_stats()

            # Count devices from SDN
            devices = get_sdn_devices()
            devices_active = sum(1 for d in devices if d.get('online', False))
            devices_total = len(devices)

            return {
                'health_score': system_perf.get('health_score', 85),
                'health_trend': system_perf.get('health_trend', 'stable'),
                'insight': _generate_performance_insight(system_perf, dns_stats),
                'metrics': {
                    'latency_ms': system_perf.get('latency_ms', 10),
                    'latency_trend': system_perf.get('latency_trend', 'good'),
                    'bandwidth_used_pct': system_perf.get('bandwidth_used_pct', 25),
                    'bandwidth_trend': system_perf.get('bandwidth_trend', 'normal'),
                    'devices_active': devices_active,
                    'devices_total': devices_total,
                    'uptime_pct': system_perf.get('uptime_pct', 99.9),
                    'threats_blocked_24h': dns_stats.get('blocked_today', 0),
                },
                'recommendations': _generate_recommendations(system_perf, dns_stats),
            }
    except Exception as e:
        logger.warning(f"Could not get real performance: {e}")

    return get_demo_performance()


def _generate_performance_insight(system_perf: dict, dns_stats: dict) -> str:
    """Generate a human-readable performance insight."""
    health_score = system_perf.get('health_score', 85)
    blocked = dns_stats.get('blocked_today', 0)

    if health_score >= 90:
        return f"Excellent network health! Protected from {blocked} threats today."
    elif health_score >= 75:
        return f"Your network is performing well. Blocked {blocked} tracking attempts."
    elif health_score >= 60:
        return "Network performance is acceptable. Consider checking for interference."
    else:
        return "Network health needs attention. High load detected."


def _generate_recommendations(system_perf: dict, dns_stats: dict) -> list:
    """Generate performance recommendations."""
    recommendations = []

    if system_perf.get('latency_ms', 0) > 50:
        recommendations.append({
            'priority': 'medium',
            'icon': 'fa-gauge-high',
            'text': "High latency detected. Check your internet connection."
        })

    if system_perf.get('health_trend') == 'degrading':
        recommendations.append({
            'priority': 'high',
            'icon': 'fa-triangle-exclamation',
            'text': "System load is increasing. Consider restarting services."
        })

    if not recommendations:
        recommendations.append({
            'priority': 'low',
            'icon': 'fa-check-circle',
            'text': "Everything looks good! No actions needed."
        })

    return recommendations


@aiochi_bp.route('/api/presence')
@login_required
def api_presence():
    """Get presence data (device bubbles)."""
    try:
        # Try to fetch real data from AIOCHI containers
        if AIOCHI_ENABLED:
            ecosystems = fetch_aiochi_ecosystems()
            if ecosystems:
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'data': ecosystems
                })

        # Fallback to demo data
        return jsonify({
            'success': True,
            'demo_mode': True,
            'data': get_demo_presence()
        })
    except Exception as e:
        logger.error(f"AIOCHI presence API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/feed')
@login_required
def api_feed():
    """Get privacy feed (narrative events)."""
    try:
        # Use real data if available
        if REAL_DATA_AVAILABLE:
            return jsonify({
                'success': True,
                'demo_mode': False,
                'real_data': True,
                'data': generate_privacy_feed()
            })

        return jsonify({
            'success': True,
            'demo_mode': True,
            'real_data': False,
            'data': get_demo_privacy_feed()
        })
    except Exception as e:
        logger.error(f"AIOCHI feed API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/performance')
@login_required
def api_performance():
    """Get performance metrics."""
    try:
        # Use real data if available
        if REAL_DATA_AVAILABLE:
            return jsonify({
                'success': True,
                'demo_mode': False,
                'real_data': True,
                'data': _get_real_performance()
            })

        return jsonify({
            'success': True,
            'demo_mode': True,
            'real_data': False,
            'data': get_demo_performance()
        })
    except Exception as e:
        logger.error(f"AIOCHI performance API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/action/<action_id>', methods=['POST'])
@login_required
def api_action(action_id):
    """Execute a quick action."""
    try:
        # Validate action
        valid_actions = ['pause_kids', 'game_mode', 'privacy_mode', 'guest_lockdown']
        if action_id not in valid_actions:
            return jsonify({
                'success': False,
                'error': f'Unknown action: {action_id}'
            }), 400

        # Get desired state from request
        data = request.get_json() or {}
        activate = data.get('activate', True)

        logger.info(f"AIOCHI action: {action_id} -> {'activate' if activate else 'deactivate'}")

        # Use real action executor if available
        if REAL_DATA_AVAILABLE:
            try:
                from .real_data import execute_quick_action
                result = execute_quick_action(action_id, activate)
                return jsonify({
                    'success': result.get('success', False),
                    'demo_mode': False,
                    'action': action_id,
                    'activated': activate if result.get('success') else not activate,
                    'message': result.get('message', f"Action '{action_id}' processed"),
                    'details': result
                })
            except Exception as e:
                # CWE-209: Don't expose exception details in logs
                logger.error(f"Quick action executor failed: {type(e).__name__}")
                # Fall through to demo mode

        # Demo mode fallback
        return jsonify({
            'success': True,
            'demo_mode': True,
            'action': action_id,
            'activated': activate,
            'message': f"Action '{action_id}' {'activated' if activate else 'deactivated'} (demo mode)"
        })
    except Exception as e:
        logger.error(f"AIOCHI action API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# Push notification storage (in production, use database)
_push_subscriptions = {}


@aiochi_bp.route('/api/push/subscribe', methods=['POST'])
@login_required
def api_push_subscribe():
    """Subscribe to push notifications."""
    try:
        data = request.get_json() or {}
        subscription = data.get('subscription', {})
        preferences = data.get('preferences', {})

        if not subscription or not subscription.get('endpoint'):
            return jsonify({
                'success': False,
                'error': 'Invalid subscription data'
            }), 400

        # Store subscription (keyed by endpoint)
        endpoint = subscription.get('endpoint')
        _push_subscriptions[endpoint] = {
            'subscription': subscription,
            'preferences': preferences,
            'created_at': datetime.now().isoformat()
        }

        logger.info(f"Push subscription added: {endpoint[:50]}...")
        return jsonify({
            'success': True,
            'message': 'Subscription saved successfully'
        })
    except Exception as e:
        logger.error(f"Push subscribe error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def api_push_unsubscribe():
    """Unsubscribe from push notifications."""
    try:
        data = request.get_json() or {}
        endpoint = data.get('endpoint')

        if endpoint and endpoint in _push_subscriptions:
            del _push_subscriptions[endpoint]
            logger.info(f"Push subscription removed: {endpoint[:50]}...")

        return jsonify({
            'success': True,
            'message': 'Subscription removed successfully'
        })
    except Exception as e:
        logger.error(f"Push unsubscribe error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/push/test', methods=['POST'])
@login_required
def api_push_test():
    """Send a test push notification."""
    try:
        # In production, this would use pywebpush to send actual notifications
        logger.info("Test push notification requested")
        return jsonify({
            'success': True,
            'message': 'Test notification queued',
            'subscriptions_count': len(_push_subscriptions)
        })
    except Exception as e:
        logger.error(f"Push test error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# Family Profiles API
# ============================================================================

# Demo family profiles
_demo_profiles = {
    'admin': {
        'id': 'admin',
        'name': 'Admin',
        'persona': 'tech',
        'avatar_emoji': '🔧',
        'theme': 'default',
        'is_admin': True,
        'assigned_bubbles': ['dad', 'mom', 'kids', 'iot'],
    },
    'parent': {
        'id': 'parent',
        'name': 'Parent',
        'persona': 'parent',
        'avatar_emoji': '👨‍👩‍👧‍👦',
        'theme': 'green',
        'is_admin': False,
        'assigned_bubbles': ['dad', 'mom', 'kids'],
    },
    'gamer': {
        'id': 'gamer',
        'name': 'Gamer',
        'persona': 'gamer',
        'avatar_emoji': '🎮',
        'theme': 'purple',
        'is_admin': False,
        'assigned_bubbles': ['kids'],
    },
    'kid': {
        'id': 'kid',
        'name': 'Kid',
        'persona': 'kid',
        'avatar_emoji': '🧒',
        'theme': 'orange',
        'is_admin': False,
        'assigned_bubbles': ['kids'],
        'pin_required': True,
    },
}


@aiochi_bp.route('/api/profiles')
@login_required
def api_profiles():
    """Get all family profiles."""
    try:
        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'profiles': list(_demo_profiles.values())
        })
    except Exception as e:
        logger.error(f"Profiles API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/profiles/<profile_id>')
@login_required
def api_profile_get(profile_id):
    """Get a specific family profile."""
    try:
        profile = _demo_profiles.get(profile_id)
        if not profile:
            return jsonify({'success': False, 'error': 'Profile not found'}), 404

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'profile': profile
        })
    except Exception as e:
        logger.error(f"Profile get error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/profiles/<profile_id>', methods=['PUT'])
@login_required
def api_profile_update(profile_id):
    """Update a family profile."""
    try:
        if profile_id not in _demo_profiles:
            return jsonify({'success': False, 'error': 'Profile not found'}), 404

        data = request.get_json() or {}
        profile = _demo_profiles[profile_id]

        # Update allowed fields
        allowed_fields = ['name', 'persona', 'avatar_emoji', 'theme', 'assigned_bubbles']
        for fld in allowed_fields:
            if fld in data:
                profile[fld] = data[fld]

        logger.info(f"Profile updated: {profile_id}")
        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'profile': profile
        })
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/profiles', methods=['POST'])
@login_required
def api_profile_create():
    """Create a new family profile."""
    try:
        data = request.get_json() or {}

        if not data.get('id') or not data.get('name'):
            return jsonify({
                'success': False,
                'error': 'Profile ID and name are required'
            }), 400

        if data['id'] in _demo_profiles:
            return jsonify({
                'success': False,
                'error': 'Profile ID already exists'
            }), 400

        # Create profile with defaults
        profile = {
            'id': data['id'],
            'name': data['name'],
            'persona': data.get('persona', 'parent'),
            'avatar_emoji': data.get('avatar_emoji', '👤'),
            'theme': data.get('theme', 'default'),
            'is_admin': False,
            'assigned_bubbles': data.get('assigned_bubbles', []),
        }

        _demo_profiles[data['id']] = profile
        logger.info(f"Profile created: {data['id']}")

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'profile': profile
        })
    except Exception as e:
        logger.error(f"Profile create error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/profiles/<profile_id>', methods=['DELETE'])
@login_required
def api_profile_delete(profile_id):
    """Delete a family profile."""
    try:
        if profile_id not in _demo_profiles:
            return jsonify({'success': False, 'error': 'Profile not found'}), 404

        if _demo_profiles[profile_id].get('is_admin'):
            return jsonify({
                'success': False,
                'error': 'Cannot delete admin profile'
            }), 400

        del _demo_profiles[profile_id]
        logger.info(f"Profile deleted: {profile_id}")

        return jsonify({
            'success': True,
            'message': 'Profile deleted successfully'
        })
    except Exception as e:
        logger.error(f"Profile delete error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/profiles/<profile_id>/switch', methods=['POST'])
@login_required
def api_profile_switch(profile_id):
    """Switch to a different family profile."""
    try:
        if profile_id not in _demo_profiles:
            return jsonify({'success': False, 'error': 'Profile not found'}), 404

        profile = _demo_profiles[profile_id]

        # Check PIN if required
        if profile.get('pin_required'):
            data = request.get_json() or {}
            pin = data.get('pin')
            if pin != '0000':  # Demo PIN
                return jsonify({
                    'success': False,
                    'error': 'Invalid PIN'
                }), 401

        logger.info(f"Switched to profile: {profile_id}")

        # Return profile with narrative config
        narrative_configs = {
            'parent': {'tone': 'reassuring', 'detail_level': 'simple', 'emoji_enabled': True},
            'gamer': {'tone': 'energetic', 'detail_level': 'medium', 'emoji_enabled': True},
            'tech': {'tone': 'technical', 'detail_level': 'full', 'emoji_enabled': False},
            'kid': {'tone': 'fun', 'detail_level': 'minimal', 'emoji_enabled': True},
        }

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'profile': profile,
            'narrative_config': narrative_configs.get(profile.get('persona', 'parent'))
        })
    except Exception as e:
        logger.error(f"Profile switch error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# AI Agent Feedback API (Human-in-the-Loop)
# ============================================================================

import subprocess
import uuid

# Storage for pending feedback requests (in production, use database)
_pending_feedback = {}

# Storage for recent agent actions (in production, use ClickHouse)
_agent_actions = []


@aiochi_bp.route('/api/agent/status')
@login_required
def api_agent_status():
    """Get AI Agent status and recent actions."""
    try:
        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'agent': {
                'status': 'active',
                'model': 'llama3.2:3b',
                'mode': 'agentic',  # 'agentic' or 'template'
                'memory_window': 10,  # Last N events remembered
                'tools_available': ['BLOCK', 'MIGRATE', 'THROTTLE', 'MONITOR', 'TRUST'],
            },
            'stats': {
                'actions_today': 7,
                'deterministic_pct': 60,  # % of decisions that were instant (no LLM)
                'avg_response_ms': 850,
                'feedback_pending': len(_pending_feedback),
            },
            'recent_actions': _agent_actions[-10:]  # Last 10 actions
        })
    except Exception as e:
        logger.error(f"Agent status API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/feed', methods=['POST'])
def api_feed_post():
    """Receive narrative events from n8n workflow (internal API)."""
    try:
        data = request.get_json() or {}
        narrative = data.get('narrative', {})

        if not narrative:
            return jsonify({'success': False, 'error': 'No narrative data'}), 400

        # Store the narrative event
        event_id = narrative.get('id', str(uuid.uuid4()))
        narrative['id'] = event_id
        narrative['received_at'] = datetime.now().isoformat()

        # Add to agent actions if it's an AI action
        if narrative.get('category') == 'ai-agent':
            _agent_actions.append(narrative)
            # Keep only last 100 actions
            if len(_agent_actions) > 100:
                _agent_actions.pop(0)

        logger.info(f"Narrative received: {narrative.get('title', 'Unknown')}")

        return jsonify({
            'success': True,
            'event_id': event_id
        })
    except Exception as e:
        logger.error(f"Feed POST error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/feedback-request', methods=['POST'])
def api_feedback_request():
    """Receive feedback request from n8n workflow (internal API)."""
    try:
        data = request.get_json() or {}

        action_id = data.get('action_id')
        message = data.get('message')
        options = data.get('options', [
            {'label': 'Approve', 'action': 'approve'},
            {'label': 'Reject', 'action': 'reject'}
        ])

        if not action_id or not message:
            return jsonify({
                'success': False,
                'error': 'action_id and message are required'
            }), 400

        # Store the feedback request
        feedback_req = {
            'id': action_id,
            'message': message,
            'options': options,
            'created_at': datetime.now().isoformat(),
            'status': 'pending',
            'mac_address': data.get('mac_address'),
            'action_type': data.get('action_type'),
            'device_label': data.get('device_label'),
        }
        _pending_feedback[action_id] = feedback_req

        logger.info(f"Feedback request created: {action_id}")

        # TODO: Send push notification to subscribed clients
        # In production, use pywebpush to send to all _push_subscriptions

        return jsonify({
            'success': True,
            'feedback_id': action_id
        })
    except Exception as e:
        logger.error(f"Feedback request error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/feedback/pending')
@login_required
def api_feedback_pending():
    """Get all pending feedback requests."""
    try:
        pending = [
            fb for fb in _pending_feedback.values()
            if fb.get('status') == 'pending'
        ]
        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'pending': pending,
            'count': len(pending)
        })
    except Exception as e:
        logger.error(f"Feedback pending API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/feedback/<action_id>', methods=['POST'])
@login_required
def api_feedback_submit(action_id):
    """Submit feedback for an AI action."""
    try:
        if action_id not in _pending_feedback:
            return jsonify({
                'success': False,
                'error': 'Feedback request not found'
            }), 404

        data = request.get_json() or {}
        response = data.get('response')  # 'approve', 'reject', 'trust', 'block_permanent'
        notes = data.get('notes', '')

        if not response:
            return jsonify({
                'success': False,
                'error': 'Response is required (approve, reject, trust, block_permanent)'
            }), 400

        feedback_req = _pending_feedback[action_id]
        mac_address = feedback_req.get('mac_address')
        action_type = feedback_req.get('action_type')

        # Security: Validate MAC address format to prevent command injection (CWE-78)
        if mac_address and not _validate_mac_address(mac_address):
            logger.warning(f"Invalid MAC address format rejected: {mac_address[:50]}")
            return jsonify({
                'success': False,
                'error': 'Invalid MAC address format'
            }), 400

        # Security: Sanitize notes field to prevent command injection (CWE-78)
        sanitized_notes = _sanitize_notes(notes)

        # Update feedback status
        feedback_req['status'] = 'responded'
        feedback_req['response'] = response
        feedback_req['notes'] = sanitized_notes
        feedback_req['responded_at'] = datetime.now().isoformat()

        # Execute action based on feedback
        result = {'action_taken': None}

        if response == 'trust' and mac_address:
            # User trusts this device - remove block and add to trusted
            result = _execute_tool('trust-device.sh', [mac_address, 'user', sanitized_notes or 'User approved'])

        elif response == 'block_permanent' and mac_address:
            # User wants permanent block
            result = _execute_tool('block-device.sh', [mac_address, sanitized_notes or 'User requested permanent block'])

        elif response == 'reject' and mac_address and action_type == 'BLOCK':
            # User rejects the block - unblock the device
            result = _execute_tool('unblock-device.sh', [mac_address, sanitized_notes or 'User rejected AI block decision'])

        elif response == 'reject' and mac_address and action_type == 'MIGRATE':
            # User rejects migration - move back to trusted VLAN
            result = _execute_tool('migrate-device.sh', [mac_address, 'trusted', sanitized_notes or 'User rejected migration'])

        elif response == 'approve':
            # User approves - no action needed, AI decision stands
            result = {'action_taken': 'none', 'message': 'User approved AI decision'}

        logger.info(f"Feedback submitted for {action_id}: {response}")

        return jsonify({
            'success': True,
            'feedback_id': action_id,
            'response': response,
            'result': result
        })
    except Exception as e:
        # CWE-532 SECURITY FIX: Log only exception type, not full message which may contain sensitive data
        logger.error(f"Feedback submit error: {type(e).__name__}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# Security: Allowed tool names (whitelist approach - CWE-78 prevention)
ALLOWED_TOOLS = {
    'trust-device.sh',
    'block-device.sh',
    'unblock-device.sh',
    'migrate-device.sh',
}

# Security: Tool name validation pattern (alphanumeric, hyphen, underscore, dot only)
TOOL_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')

# Security: Base directory for tools (prevent path traversal)
TOOLS_BASE_DIR = '/opt/hookprobe/shared/aiochi/tools'


def _validate_tool_arg(arg: str) -> bool:
    """
    Validate a single tool argument for security (CWE-78 prevention).

    Only allows:
    - MAC addresses (validated by _validate_mac_address)
    - Simple alphanumeric strings with limited punctuation
    - Short text descriptions (sanitized elsewhere)
    """
    if not arg or not isinstance(arg, str):
        return False

    # Length limit
    if len(arg) > 500:
        return False

    # Check if it's a valid MAC address
    if _validate_mac_address(arg):
        return True

    # Check if it's a safe simple string (alphanumeric + limited punctuation)
    # Allows: a-z, A-Z, 0-9, space, hyphen, underscore, period, comma
    # CWE-78 SECURITY FIX: Reject arguments starting with '-' to prevent argument injection
    # (except MAC addresses which are already validated above)
    if arg.startswith('-'):
        return False
    safe_pattern = re.compile(r'^[a-zA-Z0-9\s\-_\.,]+$')
    return bool(safe_pattern.match(arg))


def _execute_tool(tool_name: str, args: list):
    """
    Execute an AIOCHI tool script with security validation.

    Security measures (CWE-78 prevention):
    - Tool name whitelist validation
    - Path traversal prevention (realpath check)
    - Argument sanitization
    - Subprocess without shell=True
    """
    try:
        # Security: Validate tool name format
        if not tool_name or not isinstance(tool_name, str):
            logger.warning("Tool execution rejected: invalid tool name")
            return {'action_taken': None, 'error': 'Invalid tool name'}

        if not TOOL_NAME_PATTERN.match(tool_name):
            logger.warning(f"Tool execution rejected: invalid tool name format: {tool_name[:50]}")
            return {'action_taken': None, 'error': 'Invalid tool name format'}

        # Security: Whitelist check
        if tool_name not in ALLOWED_TOOLS:
            logger.warning(f"Tool execution rejected: tool not in whitelist: {tool_name}")
            return {'action_taken': None, 'error': f'Tool not allowed: {tool_name}'}

        # Security: Build and validate path (prevent path traversal)
        tool_path = os.path.join(TOOLS_BASE_DIR, tool_name)
        real_path = os.path.realpath(tool_path)

        # Ensure the resolved path is still within the tools directory
        if not real_path.startswith(os.path.realpath(TOOLS_BASE_DIR)):
            logger.warning(f"Tool execution rejected: path traversal attempt: {tool_name}")
            return {'action_taken': None, 'error': 'Invalid tool path'}

        # Security: Validate all arguments
        if not isinstance(args, list):
            args = []

        validated_args = []
        for arg in args:
            if not _validate_tool_arg(str(arg)):
                logger.warning(f"Tool execution rejected: invalid argument: {str(arg)[:50]}")
                return {'action_taken': tool_name, 'error': 'Invalid argument format'}
            validated_args.append(str(arg))

        # Build command (using list - no shell injection possible)
        cmd = [real_path] + validated_args

        # Execute with strict controls
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=TOOLS_BASE_DIR,  # Restrict working directory
            env={  # Minimal environment
                'PATH': '/usr/bin:/bin',
                'HOME': '/tmp',
            }
        )

        if result.returncode == 0:
            # Parse JSON output
            try:
                output = json.loads(result.stdout)
                return output
            except json.JSONDecodeError:
                return {'action_taken': tool_name, 'raw_output': result.stdout}
        else:
            logger.error(f"Tool {tool_name} failed: {result.stderr}")
            return {'action_taken': tool_name, 'error': result.stderr}

    except subprocess.TimeoutExpired:
        logger.error(f"Tool {tool_name} timed out")
        return {'action_taken': tool_name, 'error': 'Timeout'}
    except FileNotFoundError:
        logger.warning(f"Tool {tool_name} not found (demo mode)")
        return {'action_taken': tool_name, 'demo_mode': True, 'message': 'Tool not available in demo mode'}
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return {'action_taken': tool_name, 'error': safe_error_message(e)}


@aiochi_bp.route('/api/agent/actions')
@login_required
def api_agent_actions():
    """Get AI agent action history."""
    try:
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)

        # In demo mode, generate sample actions
        if not AIOCHI_ENABLED or not _agent_actions:
            demo_actions = [
                {
                    'id': 'action-1',
                    'timestamp': (datetime.now() - timedelta(minutes=15)).isoformat(),
                    'action': 'BLOCK',
                    'mac_address': 'aa:bb:cc:dd:ee:ff',
                    'device_label': 'Unknown Device',
                    'reason': 'Detected connection to known C2 server',
                    'narrative': "I blocked an unknown device that was trying to communicate with a server associated with malware. Better safe than sorry!",
                    'deterministic': True,
                    'trust_score_before': 30,
                    'trust_score_after': 10,
                    'feedback_status': 'pending',
                },
                {
                    'id': 'action-2',
                    'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                    'action': 'MIGRATE',
                    'mac_address': '11:22:33:44:55:66',
                    'device_label': 'New Smart Bulb',
                    'reason': 'New IoT device detected',
                    'narrative': "A new smart device joined your network. I moved it to the IoT zone for safety until I learn more about it.",
                    'deterministic': False,
                    'trust_score_before': 50,
                    'trust_score_after': 50,
                    'feedback_status': 'approved',
                },
                {
                    'id': 'action-3',
                    'timestamp': (datetime.now() - timedelta(hours=5)).isoformat(),
                    'action': 'MONITOR',
                    'mac_address': '77:88:99:aa:bb:cc',
                    'device_label': "Kids' Tablet",
                    'reason': 'Unusual browsing pattern at late hour',
                    'narrative': "The kids' tablet was active at 2 AM, which is unusual. I'm keeping an eye on it but no action needed yet.",
                    'deterministic': False,
                    'trust_score_before': 85,
                    'trust_score_after': 85,
                    'feedback_status': 'none',
                },
            ]
            actions = demo_actions
        else:
            actions = _agent_actions

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'actions': actions[offset:offset + limit],
            'total': len(actions),
            'offset': offset,
            'limit': limit
        })
    except Exception as e:
        logger.error(f"Agent actions API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/agent/trust/<mac_address>', methods=['GET'])
@login_required
def api_agent_trust_get(mac_address):
    """Get trust score for a device."""
    try:
        # In production, query ClickHouse device_trust table
        # For demo, return sample data
        trust_data = {
            'mac_address': mac_address,
            'trust_score': 75,
            'ecosystem': 'apple',
            'action_count': 3,
            'is_known': True,
            'last_action': 'MONITOR',
            'last_seen': datetime.now().isoformat()
        }
        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'trust': trust_data
        })
    except Exception as e:
        logger.error(f"Trust get API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/agent/trust/<mac_address>', methods=['PUT'])
@login_required
def api_agent_trust_set(mac_address):
    """Manually set trust score for a device."""
    try:
        data = request.get_json() or {}
        trust_score = data.get('trust_score')
        notes = data.get('notes', '')

        if trust_score is None or not (0 <= trust_score <= 100):
            return jsonify({
                'success': False,
                'error': 'trust_score must be between 0 and 100'
            }), 400

        logger.info(f"Trust score set for {mac_address}: {trust_score}")

        # In production, update ClickHouse device_trust table
        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'mac_address': mac_address,
            'trust_score': trust_score,
            'message': 'Trust score updated'
        })
    except Exception as e:
        logger.error(f"Trust set API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# L1 SOC API - Physical Layer Security Operations Center
# ============================================================================
# These endpoints provide L1 (cellular/radio) security status for the dashboard.
# When AIOCHI is enabled, these proxy to the L1 SOC backend. When disabled,
# they return demo data.

# In-memory state for demo/fallback
_l1_state = {
    'available': False,
    'survival_mode': False,
    'survival_trigger': None,
    'survival_since': None,
    'trust_score': 85,
    'trust_components': {
        'tower_identity': 100,
        'snr_score': 75,
        'signal_stability': 90,
        'temporal_consistency': 95,
        'handover_score': 100
    },
    'current_cell': {
        'cell_id': '12345678',
        'pci': 42,
        'tac': 1234,
        'mcc_mnc': '310-260',
        'band': 'n78',
        'rsrp': -85,
        'sinr': 22,
        'snr': 20.5,
        'ta': 15,
        'carrier': 'Verizon',
        'network_type': '5G SA',
        'status': 'trusted'
    }
}


@aiochi_bp.route('/api/l1/status')
@login_required
def api_l1_status():
    """Get L1 SOC status including trust score and survival mode state.

    Uses fts-host-agent to read modem data via mmcli on the host.
    """
    try:
        # Try to get L1 data from host agent
        # Uses absolute import since lib/ is at /app/lib (sibling to web/)
        from lib.host_agent_client import get_l1_status
        l1_data = get_l1_status()

        if l1_data.get('success') and not l1_data.get('socket_missing'):
            # Real L1 data from host modem
            # Use network_type_detail if available (more accurate from mbimcli)
            network_type = l1_data.get('network_type_detail') or l1_data.get('network_type')
            return jsonify({
                'success': True,
                'available': True,
                'demo_mode': False,
                'network_type': network_type,
                'carrier': l1_data.get('carrier'),
                'cell_id': l1_data.get('cell_id'),
                'pci': l1_data.get('pci'),
                'tac': l1_data.get('tac'),
                'band': l1_data.get('band'),
                'mcc_mnc': l1_data.get('mcc_mnc'),
                'rsrp': l1_data.get('rsrp'),
                'sinr': l1_data.get('sinr'),
                'snr': l1_data.get('snr'),
                # Additional detailed signal info from mbimcli
                'rsrp_5g': l1_data.get('rsrp_5g'),
                'rsrp_lte': l1_data.get('rsrp_lte'),
                'snr_5g': l1_data.get('snr_5g'),
                'snr_lte': l1_data.get('snr_lte'),
                'distance_km': l1_data.get('distance_km'),
                'handovers_1h': l1_data.get('handovers_1h', 0),
                'tower_status': l1_data.get('tower_status', 'unknown'),
                'trust_score': l1_data.get('trust_score', 50),
                'trust_components': l1_data.get('trust_components', {}),
                'survival_mode': l1_data.get('survival_mode', False),
                'vpn_ready': l1_data.get('vpn_ready', False),
                # Extended fields from qmicli
                'earfcn': l1_data.get('earfcn'),
                'neighbors': l1_data.get('neighbors'),
                'nr_arfcn': l1_data.get('nr_arfcn'),
                # Security gauge fields
                'rrc_state': l1_data.get('rrc_state'),
                'neighbor_count': l1_data.get('neighbor_count'),
                'earfcn_valid': l1_data.get('earfcn_valid'),
                'expected_band': l1_data.get('expected_band'),
                'error': l1_data.get('error')
            })
        else:
            # No modem available - return minimal response so UI hides the section
            return jsonify({
                'success': True,
                'available': False,
                'reason': l1_data.get('error', 'No modem detected')
            })
    except Exception as e:
        logger.error(f"L1 status API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/l1/survival/enter', methods=['POST'])
@login_required
def api_l1_survival_enter():
    """Manually enter survival mode."""
    try:
        data = request.get_json() or {}
        trigger = data.get('trigger', 'manual')

        if AIOCHI_ENABLED:
            try:
                import requests
                resp = requests.post(
                    'http://localhost:8061/api/l1/survival/enter',
                    json={'trigger': trigger},
                    timeout=5
                )
                if resp.status_code == 200:
                    return jsonify(resp.json())
            except Exception as e:
                logger.warning(f"Failed to contact L1 SOC for survival mode: {e}")

        # Fallback: update local state
        _l1_state['survival_mode'] = True
        _l1_state['survival_trigger'] = trigger
        _l1_state['survival_since'] = datetime.utcnow().isoformat()

        logger.warning(f"Survival mode entered manually: {trigger}")

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'survival_mode': True,
            'trigger': trigger,
            'message': 'Survival mode activated'
        })
    except Exception as e:
        logger.error(f"Survival enter API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/l1/survival/exit', methods=['POST'])
@login_required
def api_l1_survival_exit():
    """Exit survival mode."""
    try:
        if AIOCHI_ENABLED:
            try:
                import requests
                resp = requests.post(
                    'http://localhost:8061/api/l1/survival/exit',
                    timeout=5
                )
                if resp.status_code == 200:
                    return jsonify(resp.json())
            except Exception as e:
                logger.warning(f"Failed to contact L1 SOC to exit survival mode: {e}")

        # Fallback: update local state
        _l1_state['survival_mode'] = False
        _l1_state['survival_trigger'] = None
        _l1_state['survival_since'] = None

        logger.info("Survival mode exited")

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'survival_mode': False,
            'message': 'Survival mode deactivated'
        })
    except Exception as e:
        logger.error(f"Survival exit API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# AI Agent Activity & Prompts API
# ============================================================================
# These endpoints provide AI activity feed and user prompt management for
# the "Less is More" UX approach.

# In-memory storage for pending prompts and decisions
_pending_prompts = []
_ai_decisions = []


@aiochi_bp.route('/api/agent/activity')
@login_required
def api_agent_activity():
    """Get recent AI activity for the activity feed."""
    try:
        # Try to get from autonomous agent if available
        activity_items = []

        if AIOCHI_ENABLED:
            try:
                import requests
                resp = requests.get('http://localhost:8060/api/agent/decisions', timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    activity_items = data.get('decisions', [])[:10]  # Last 10
            except Exception:
                pass

        if not activity_items:
            # Return demo/empty state
            activity_items = []

        # Format for frontend
        formatted = []
        for item in activity_items:
            formatted.append({
                'id': item.get('id', ''),
                'type': item.get('type', 'action'),
                'narrative': item.get('narrative', item.get('description', '')),
                'icon': item.get('icon', 'fa-robot'),
                'color': _get_decision_color(item.get('confidence', 1.0)),
                'confidence': item.get('confidence', 1.0),
                'auto_execute': item.get('auto_execute', False),
                'countdown': item.get('countdown', 0),
                'timestamp': item.get('timestamp', datetime.utcnow().isoformat())
            })

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'activity': formatted,
            'pending_count': len([i for i in formatted if i.get('auto_execute')])
        })
    except Exception as e:
        logger.error(f"Agent activity API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


def _get_decision_color(confidence):
    """Map confidence to UI color class."""
    if confidence >= 0.85:
        return 'success'
    elif confidence >= 0.60:
        return 'info'
    elif confidence >= 0.30:
        return 'warning'
    else:
        return 'danger'


@aiochi_bp.route('/api/agent/prompts')
@login_required
def api_agent_prompts():
    """Get pending user prompts (confidence < 30%)."""
    try:
        prompts = []

        if AIOCHI_ENABLED:
            try:
                import requests
                resp = requests.get('http://localhost:8060/api/agent/prompts', timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    prompts = data.get('prompts', [])
            except Exception:
                pass

        # Filter to only low-confidence prompts that need user input
        user_prompts = [p for p in prompts if p.get('confidence', 1.0) < 0.30]

        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'prompts': user_prompts
        })
    except Exception as e:
        logger.error(f"Agent prompts API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/agent/decision/<decision_id>', methods=['POST'])
@login_required
def api_agent_decision_respond(decision_id):
    """Submit user response to an AI decision prompt."""
    from flask_login import current_user
    try:
        data = request.get_json() or {}
        action = data.get('action', 'dismiss')
        user_decision = data.get('user_decision', True)

        username = current_user.username if hasattr(current_user, 'username') else 'unknown'
        logger.info(f"User decision for {decision_id}: {action} by {username}")

        if AIOCHI_ENABLED:
            try:
                import requests
                resp = requests.post(
                    f'http://localhost:8060/api/agent/decisions/{decision_id}/respond',
                    json={
                        'action': action,
                        'user_decision': user_decision,
                        'user': username
                    },
                    timeout=5
                )
                if resp.status_code == 200:
                    return jsonify(resp.json())
            except Exception as e:
                logger.warning(f"Failed to submit decision to agent: {e}")

        # Fallback: acknowledge locally
        return jsonify({
            'success': True,
            'demo_mode': not AIOCHI_ENABLED,
            'decision_id': decision_id,
            'action': action,
            'message': 'Decision recorded'
        })
    except Exception as e:
        logger.error(f"Agent decision API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# Bubble Management API (AIOCHI Identity Engine Integration)
# ============================================================================
# These endpoints proxy to the AIOCHI Identity Engine for unified bubble
# management. AIOCHI is the single source of truth for device-to-bubble
# relationships.

def fetch_aiochi_bubbles():
    """Fetch all bubbles from AIOCHI Identity Engine."""
    import requests
    try:
        resp = requests.get(f'{AIOCHI_IDENTITY_URL}/api/bubbles', timeout=5)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch AIOCHI bubbles: {e}")
        return None


def fetch_d2d_clusters_from_container(ip_to_mac_map=None):
    """Fetch D2D communication clusters from aiochi-bubble container.

    Returns a dict mapping MAC address -> d2d_cluster info for UI rendering.
    Format matches what the AIOCHI dashboard JS expects.

    Args:
        ip_to_mac_map: Optional dict mapping IP -> MAC for device resolution.
                       If not provided, will try to build from SDN devices.
    """
    if not AIOCHI_D2D_AVAILABLE:
        return {}

    try:
        client = get_d2d_client()
        if not client:
            return {}

        clusters = client.get_communication_clusters()
        if not clusters:
            return {}

        # Build IP-to-MAC map if not provided
        if ip_to_mac_map is None:
            ip_to_mac_map = {}
            try:
                # Try to get from SDN devices
                sdn_devices = get_sdn_devices()
                for d in sdn_devices:
                    ip = d.get('ip', '')
                    mac = d.get('mac', '').upper()
                    if ip and mac:
                        ip_to_mac_map[ip] = mac
            except Exception as e:
                logger.debug(f"Could not build IP-to-MAC map: {e}")

        d2d_device_clusters = {}
        for cluster in clusters:
            cluster_id = cluster.get('cluster_id', '')
            color = cluster.get('color', '#6B7280')
            device_count = cluster.get('device_count', 0)
            devices = cluster.get('devices', [])

            # Calculate average affinity from cluster data if available
            avg_connections = cluster.get('avg_connections', 0)
            # Normalize to 0-1 range (assume 10+ connections = 1.0 affinity)
            avg_affinity = min(avg_connections / 10.0, 1.0) if avg_connections else 0.5

            cluster_info = {
                'cluster_id': cluster_id,
                'cluster_color': color,
                'device_count': device_count,
                'avg_affinity': round(avg_affinity, 2),
            }

            for device in devices:
                device_id = device.get('mac', '').upper()
                device_ip = device.get('ip', '')

                # Handle IP-based device IDs from aiochi-bubble (e.g., "IP:10.200.0.9")
                if device_id.startswith('IP:'):
                    ip_addr = device_id[3:]  # Remove "IP:" prefix
                    # Try to resolve to MAC
                    if ip_addr in ip_to_mac_map:
                        mac = ip_to_mac_map[ip_addr]
                        d2d_device_clusters[mac] = cluster_info
                    # Also store by IP for devices we couldn't resolve
                    if ip_addr:
                        d2d_device_clusters[f"IP:{ip_addr}"] = cluster_info
                elif device_id:
                    # Real MAC address
                    d2d_device_clusters[device_id] = cluster_info

                # Also try matching by IP field
                if device_ip and device_ip in ip_to_mac_map:
                    mac = ip_to_mac_map[device_ip]
                    d2d_device_clusters[mac] = cluster_info

        if d2d_device_clusters:
            resolved_macs = [k for k in d2d_device_clusters.keys() if not k.startswith('IP:')]
            logger.info(f"AIOCHI D2D: {len(clusters)} clusters, {len(d2d_device_clusters)} entries, {len(resolved_macs)} MAC-resolved")

        return d2d_device_clusters

    except Exception as e:
        logger.debug(f"Failed to fetch D2D clusters from container: {e}")
        return {}


def get_demo_bubbles():
    """Generate demo bubbles data."""
    return {
        'bubbles': [
            {
                'bubble_id': 'bubble-dad',
                'name': "Dad's Bubble",
                'bubble_type': 'FAMILY',
                'icon': 'fa-user-tie',
                'color': '#1976D2',
                'devices': [
                    {'mac': 'AA:BB:CC:DD:EE:01', 'label': 'iPhone 15 Pro', 'online': True},
                    {'mac': 'AA:BB:CC:DD:EE:02', 'label': 'MacBook Pro', 'online': True},
                    {'mac': 'AA:BB:CC:DD:EE:03', 'label': 'Apple Watch', 'online': True},
                ],
                'policy': {'internet': True, 'lan': True, 'd2d': True, 'vlan': 110},
                'is_manual': False,
                'is_pinned': False,
            },
            {
                'bubble_id': 'bubble-mom',
                'name': "Mom's Bubble",
                'bubble_type': 'FAMILY',
                'icon': 'fa-user',
                'color': '#E91E63',
                'devices': [
                    {'mac': 'BB:CC:DD:EE:FF:01', 'label': 'Galaxy S24', 'online': True},
                    {'mac': 'BB:CC:DD:EE:FF:02', 'label': 'Galaxy Tab', 'online': False},
                ],
                'policy': {'internet': True, 'lan': True, 'd2d': True, 'vlan': 110},
                'is_manual': False,
                'is_pinned': False,
            },
            {
                'bubble_id': 'bubble-kids',
                'name': "Kids' Bubble",
                'bubble_type': 'FAMILY',
                'icon': 'fa-child',
                'color': '#FF5722',
                'devices': [
                    {'mac': 'CC:DD:EE:FF:00:01', 'label': 'iPad', 'online': True},
                    {'mac': 'CC:DD:EE:FF:00:02', 'label': 'Nintendo Switch', 'online': True},
                ],
                'policy': {'internet': True, 'lan': True, 'd2d': True, 'vlan': 110},
                'is_manual': True,
                'is_pinned': False,
            },
            {
                'bubble_id': 'bubble-iot',
                'name': 'Smart Home',
                'bubble_type': 'IOT',
                'icon': 'fa-home',
                'color': '#FF9800',
                'devices': [
                    {'mac': 'DD:EE:FF:00:11:01', 'label': 'HomePod Mini', 'online': True},
                    {'mac': 'DD:EE:FF:00:11:02', 'label': 'Nest Thermostat', 'online': True},
                    {'mac': 'DD:EE:FF:00:11:03', 'label': 'Ring Doorbell', 'online': True},
                ],
                'policy': {'internet': True, 'lan': False, 'd2d': True, 'vlan': 130},
                'is_manual': False,
                'is_pinned': False,
            },
            {
                'bubble_id': 'bubble-guest',
                'name': 'Guests',
                'bubble_type': 'GUEST',
                'icon': 'fa-user-friends',
                'color': '#607D8B',
                'devices': [],
                'policy': {'internet': True, 'lan': False, 'd2d': False, 'vlan': 150},
                'is_manual': True,
                'is_pinned': True,
            },
        ],
        'unassigned_devices': [
            {'mac': 'EE:FF:00:11:22:01', 'label': 'Unknown Device', 'vendor': 'Unknown'},
            {'mac': 'EE:FF:00:11:22:02', 'label': 'Guest Laptop', 'vendor': 'Dell'},
        ]
    }


@aiochi_bp.route('/api/bubbles')
@login_required
def api_bubbles_list():
    """Get all bubbles with real device data.

    Priority:
    1. AIOCHI Identity Engine (container) - if available
    2. Local bubble manager (SQLite) - real data fallback
    3. Demo data - only if nothing else works
    """
    try:
        # Try AIOCHI container first
        if AIOCHI_ENABLED:
            data = fetch_aiochi_bubbles()
            if data:
                # Enrich devices with D2D cluster colors
                # Priority: 1. aiochi-bubble container, 2. local connection_graph
                d2d_device_clusters = {}

                # Try aiochi-bubble container first (primary source)
                if AIOCHI_D2D_AVAILABLE:
                    d2d_device_clusters = fetch_d2d_clusters_from_container()

                # Fallback to local connection analyzer if container didn't have data
                if not d2d_device_clusters and D2D_CONNECTION_AVAILABLE:
                    try:
                        analyzer = get_connection_analyzer()
                        cluster_colors = analyzer.assign_bubble_colors()
                        clusters = analyzer.find_d2d_clusters()
                        for i, cluster in enumerate(clusters):
                            color = cluster_colors.get(i, get_user_bubble_color(i))
                            for mac in cluster.devices:
                                d2d_device_clusters[mac.upper()] = {
                                    'cluster_id': i,
                                    'cluster_color': color,
                                    'device_count': len(cluster.devices),
                                    'avg_affinity': round(cluster.avg_affinity, 2),
                                }
                    except Exception as e:
                        logger.debug(f"Local D2D enrichment failed: {e}")

                # Add D2D info to devices in bubbles
                if d2d_device_clusters:
                    for bubble in data.get('bubbles', []):
                        for device in bubble.get('devices', []):
                            mac_upper = device.get('mac', '').upper()
                            ip = device.get('ip', '')
                            if mac_upper in d2d_device_clusters:
                                device['d2d_cluster'] = d2d_device_clusters[mac_upper]
                            elif ip and f"IP:{ip}" in d2d_device_clusters:
                                device['d2d_cluster'] = d2d_device_clusters[f"IP:{ip}"]

                    # Add D2D info to unassigned devices
                    for device in data.get('unassigned_devices', []):
                        mac_upper = device.get('mac', '').upper()
                        ip = device.get('ip', '')
                        if mac_upper in d2d_device_clusters:
                            device['d2d_cluster'] = d2d_device_clusters[mac_upper]
                        elif ip and f"IP:{ip}" in d2d_device_clusters:
                            device['d2d_cluster'] = d2d_device_clusters[f"IP:{ip}"]

                    logger.info(f"AIOCHI enriched with D2D: {len(d2d_device_clusters)} devices with cluster colors")

                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    **data
                })

        # Try local bubble manager (real data)
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                # Get all bubbles from local database
                bubbles_list = manager.get_all_bubbles()

                # Get all devices from SDN
                all_devices = get_sdn_devices()
                all_devices_map = {d['mac'].upper(): d for d in all_devices}

                # Get D2D colors for devices that communicate
                # Priority: 1. aiochi-bubble container, 2. local connection_graph
                d2d_device_colors = {}
                d2d_device_clusters = {}

                # Try aiochi-bubble container first (primary source)
                if AIOCHI_D2D_AVAILABLE:
                    d2d_device_clusters = fetch_d2d_clusters_from_container()

                # Fallback to local connection analyzer if container didn't have data
                if not d2d_device_clusters and D2D_CONNECTION_AVAILABLE:
                    try:
                        analyzer = get_connection_analyzer()
                        d2d_device_colors = {k.upper(): v for k, v in analyzer.get_device_colors().items()}
                        cluster_colors = analyzer.assign_bubble_colors()
                        clusters = analyzer.find_d2d_clusters()
                        for i, cluster in enumerate(clusters):
                            color = cluster_colors.get(i, get_user_bubble_color(i))
                            for mac in cluster.devices:
                                d2d_device_clusters[mac.upper()] = {
                                    'cluster_id': i,
                                    'cluster_color': color,
                                    'device_count': len(cluster.devices),
                                    'avg_affinity': round(cluster.avg_affinity, 2),
                                }
                    except Exception as e:
                        logger.debug(f"Local D2D colors unavailable: {e}")

                # Track which devices are already assigned
                assigned_macs = set()

                # Format bubbles for API response
                bubbles_data = []
                for bubble in bubbles_list:
                    # Get device details for devices in this bubble
                    devices_in_bubble = []
                    for mac in bubble.devices:
                        mac_upper = mac.upper()
                        assigned_macs.add(mac_upper)
                        device_info = all_devices_map.get(mac_upper, {})
                        device_entry = {
                            'mac': mac_upper,
                            'label': device_info.get('label', mac_upper[:8]),
                            'vendor': device_info.get('vendor', 'Unknown'),
                            'online': device_info.get('online', False),
                            'ip': device_info.get('ip', ''),
                        }
                        # Add D2D color info if available
                        if mac_upper in d2d_device_colors:
                            device_entry['d2d_type_color'] = d2d_device_colors[mac_upper]
                        # D2D cluster - try MAC first, then IP fallback
                        ip = device_entry.get('ip', '')
                        if mac_upper in d2d_device_clusters:
                            device_entry['d2d_cluster'] = d2d_device_clusters[mac_upper]
                        elif ip and f"IP:{ip}" in d2d_device_clusters:
                            device_entry['d2d_cluster'] = d2d_device_clusters[f"IP:{ip}"]
                        devices_in_bubble.append(device_entry)

                    # Get policy info based on bubble type
                    from .types_helper import get_bubble_type_policy
                    policy = get_bubble_type_policy(bubble.bubble_type.value if hasattr(bubble.bubble_type, 'value') else str(bubble.bubble_type))

                    bubbles_data.append({
                        'bubble_id': bubble.bubble_id,
                        'name': bubble.name,
                        'bubble_type': bubble.bubble_type.value if hasattr(bubble.bubble_type, 'value') else str(bubble.bubble_type),
                        'icon': bubble.icon or 'fa-layer-group',
                        'color': bubble.color or '#2196F3',
                        'devices': devices_in_bubble,
                        'policy': policy,
                        'is_manual': bubble.is_manual,
                        'is_pinned': bubble.pinned,
                        'confidence': bubble.confidence,
                    })

                # Calculate unassigned devices (in SDN but not in any bubble)
                unassigned = []
                for mac, device in all_devices_map.items():
                    if mac not in assigned_macs:
                        device_entry = {
                            'mac': mac,
                            'label': device.get('label', 'Unknown'),
                            'vendor': device.get('vendor', 'Unknown'),
                            'online': device.get('online', False),
                            'ip': device.get('ip', ''),
                            'device_type': device.get('device_type', 'unknown'),
                        }
                        # Add D2D color info if available
                        if mac in d2d_device_colors:
                            device_entry['d2d_type_color'] = d2d_device_colors[mac]
                        # D2D cluster - try MAC first, then IP fallback
                        ip = device_entry.get('ip', '')
                        if mac in d2d_device_clusters:
                            device_entry['d2d_cluster'] = d2d_device_clusters[mac]
                        elif ip and f"IP:{ip}" in d2d_device_clusters:
                            device_entry['d2d_cluster'] = d2d_device_clusters[f"IP:{ip}"]
                        unassigned.append(device_entry)

                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'local_mode': True,
                    'bubbles': bubbles_data,
                    'unassigned_devices': unassigned,
                })

        # Try bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            module_data = get_bubbles_from_module()
            if module_data:
                logger.info(f"Returning {len(module_data.get('bubbles', []))} bubbles from bubbles module")

                # Enrich devices with D2D cluster colors
                # Priority: 1. AIOCHI container API, 2. Local connection_graph
                d2d_clusters = {}

                # Try AIOCHI container API first (primary source)
                if AIOCHI_D2D_AVAILABLE:
                    try:
                        # Build IP-to-MAC map from module_data devices
                        ip_to_mac_map = {}
                        for bubble in module_data.get('bubbles', []):
                            for d in bubble.get('devices', []):
                                ip = d.get('ip', '')
                                mac = d.get('mac', '').upper()
                                if ip and mac:
                                    ip_to_mac_map[ip] = mac
                        for d in module_data.get('unassigned_devices', []):
                            ip = d.get('ip', '')
                            mac = d.get('mac', '').upper()
                            if ip and mac:
                                ip_to_mac_map[ip] = mac

                        d2d_clusters = fetch_d2d_clusters_from_container(ip_to_mac_map)
                        if d2d_clusters:
                            logger.info(f"Module data: Fetched {len(d2d_clusters)} D2D clusters from AIOCHI container")
                    except Exception as e:
                        logger.debug(f"AIOCHI D2D unavailable for module data: {e}")

                # Fallback to local connection_graph if container didn't have data
                d2d_colors = {}
                if not d2d_clusters and D2D_CONNECTION_AVAILABLE:
                    try:
                        analyzer = get_connection_analyzer()
                        d2d_colors = {k.upper(): v for k, v in analyzer.get_device_colors().items()}
                        cluster_colors = analyzer.assign_bubble_colors()
                        clusters = analyzer.find_d2d_clusters()
                        for i, cluster in enumerate(clusters):
                            color = cluster_colors.get(i, get_user_bubble_color(i))
                            for mac in cluster.devices:
                                d2d_clusters[mac.upper()] = {
                                    'cluster_id': i,
                                    'cluster_color': color,
                                    'device_count': len(cluster.devices),
                                    'avg_affinity': round(cluster.avg_affinity, 2),
                                }
                        logger.info(f"Module data: Using local D2D: {len(clusters)} clusters, {len(d2d_clusters)} devices")
                    except Exception as e:
                        logger.warning(f"Local D2D connection_graph failed: {e}")

                # Always enrich devices with D2D cluster colors if we have data
                if d2d_clusters:
                    try:
                        enriched_count = 0
                        # Add D2D info to devices in bubbles
                        for bubble in module_data.get('bubbles', []):
                            for device in bubble.get('devices', []):
                                mac_upper = device.get('mac', '').upper()
                                device_ip = device.get('ip', '')
                                if mac_upper in d2d_colors:
                                    device['d2d_type_color'] = d2d_colors[mac_upper]
                                # Try MAC first, then IP fallback for aiochi-bubble
                                if mac_upper in d2d_clusters:
                                    device['d2d_cluster'] = d2d_clusters[mac_upper]
                                    enriched_count += 1
                                elif device_ip and f"IP:{device_ip}" in d2d_clusters:
                                    device['d2d_cluster'] = d2d_clusters[f"IP:{device_ip}"]
                                    enriched_count += 1

                        # Add D2D info to unassigned devices
                        for device in module_data.get('unassigned_devices', []):
                            mac_upper = device.get('mac', '').upper()
                            device_ip = device.get('ip', '')
                            if mac_upper in d2d_colors:
                                device['d2d_type_color'] = d2d_colors[mac_upper]
                            # Try MAC first, then IP fallback for aiochi-bubble
                            if mac_upper in d2d_clusters:
                                device['d2d_cluster'] = d2d_clusters[mac_upper]
                                enriched_count += 1
                            elif device_ip and f"IP:{device_ip}" in d2d_clusters:
                                device['d2d_cluster'] = d2d_clusters[f"IP:{device_ip}"]
                                enriched_count += 1

                        logger.info(f"D2D enrichment complete: {len(d2d_clusters)} clusters, {enriched_count} devices enriched")
                    except Exception as e:
                        logger.warning(f"D2D enrichment failed for module data: {e}")

                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'module_mode': True,
                    **module_data
                })

        # Try DHCP devices even if bubble manager unavailable
        # This gives real device visibility without full bubble management
        logger.info(f"D2D Debug: AIOCHI_ENABLED={AIOCHI_ENABLED}, LOCAL_BUBBLE={LOCAL_BUBBLE_AVAILABLE}, AIOCHI_D2D={AIOCHI_D2D_AVAILABLE}")
        dhcp_devices = get_sdn_devices()  # Uses DHCP fallback when SDN unavailable
        logger.info(f"D2D Debug: dhcp_devices={len(dhcp_devices) if dhcp_devices else 0}")
        if dhcp_devices:
            logger.info(f"Returning {len(dhcp_devices)} devices from DHCP (no bubble manager)")

            # Build IP-to-MAC map for D2D resolution
            ip_to_mac_map = {}
            for d in dhcp_devices:
                ip = d.get('ip', '')
                mac = d.get('mac', '').upper()
                if ip and mac:
                    ip_to_mac_map[ip] = mac

            # Add D2D colors to DHCP-only devices
            # Priority: 1. AIOCHI container API, 2. Local connection_graph
            d2d_clusters = {}

            # Try AIOCHI container API first (primary source)
            if AIOCHI_D2D_AVAILABLE:
                try:
                    d2d_clusters = fetch_d2d_clusters_from_container(ip_to_mac_map)
                    if d2d_clusters:
                        logger.info(f"DHCP devices: Fetched {len(d2d_clusters)} D2D clusters from AIOCHI container")
                except Exception as e:
                    logger.debug(f"AIOCHI D2D unavailable for DHCP devices: {e}")

            # Fallback to local connection_graph if container didn't have data
            if not d2d_clusters and D2D_CONNECTION_AVAILABLE:
                try:
                    analyzer = get_connection_analyzer()
                    d2d_colors = {k.upper(): v for k, v in analyzer.get_device_colors().items()}
                    cluster_colors = analyzer.assign_bubble_colors()
                    clusters = analyzer.find_d2d_clusters()
                    for i, cluster in enumerate(clusters):
                        color = cluster_colors.get(i, get_user_bubble_color(i))
                        for mac in cluster.devices:
                            d2d_clusters[mac.upper()] = {
                                'cluster_id': i,
                                'cluster_color': color,
                                'device_count': len(cluster.devices),
                                'avg_affinity': round(cluster.avg_affinity, 2),
                            }
                    # Also add d2d_colors
                    for device in dhcp_devices:
                        mac = device.get('mac', '').upper()
                        if mac in d2d_colors:
                            device['d2d_type_color'] = d2d_colors[mac]
                except Exception as e:
                    logger.debug(f"Local D2D unavailable for DHCP devices: {e}")

            # Enrich devices with D2D cluster colors
            # Match by MAC first, then try IP as fallback
            if d2d_clusters:
                for device in dhcp_devices:
                    mac = device.get('mac', '').upper()
                    ip = device.get('ip', '')
                    # Try MAC first
                    if mac in d2d_clusters:
                        device['d2d_cluster'] = d2d_clusters[mac]
                    # Fallback to IP-based lookup (for aiochi-bubble which uses IP:x.x.x.x)
                    elif ip and f"IP:{ip}" in d2d_clusters:
                        device['d2d_cluster'] = d2d_clusters[f"IP:{ip}"]

            return jsonify({
                'success': True,
                'demo_mode': False,
                'dhcp_only_mode': True,
                'bubbles': [],  # No bubbles without manager
                'unassigned_devices': dhcp_devices,
            })

        # Fallback to demo data only if no DHCP devices found
        return jsonify({
            'success': True,
            'demo_mode': True,
            **get_demo_bubbles()
        })
    except Exception as e:
        logger.error(f"Bubbles list API error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/<bubble_id>')
@login_required
def api_bubble_get(bubble_id):
    """Get a specific bubble from AIOCHI Identity Engine."""
    import requests
    try:
        if AIOCHI_ENABLED:
            resp = requests.get(f'{AIOCHI_IDENTITY_URL}/api/bubble/{bubble_id}', timeout=5)
            if resp.status_code == 200:
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'bubble': resp.json()
                })
            elif resp.status_code == 404:
                return jsonify({'success': False, 'error': 'Bubble not found'}), 404

        # Demo mode: find in demo bubbles
        demo = get_demo_bubbles()
        for b in demo['bubbles']:
            if b['bubble_id'] == bubble_id:
                return jsonify({
                    'success': True,
                    'demo_mode': True,
                    'bubble': b
                })

        return jsonify({'success': False, 'error': 'Bubble not found'}), 404
    except Exception as e:
        logger.error(f"Bubble get API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles', methods=['POST'])
@login_required
def api_bubble_create():
    """Create a new bubble.

    Priority:
    1. AIOCHI Identity Engine (container) - if available
    2. Local bubble manager (SQLite) - real data fallback
    """
    import requests
    try:
        data = request.get_json() or {}

        name = data.get('name', 'New Bubble')
        bubble_type = data.get('bubble_type', 'CUSTOM')
        devices = data.get('devices', [])
        icon = data.get('icon', 'fa-layer-group')
        color = data.get('color', '#9C27B0')

        if AIOCHI_ENABLED:
            # Generate bubble_id from name (required by identity engine)
            import hashlib
            import uuid
            bubble_id = f"bubble-{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"

            # Map bubble_type to default policy
            from .types_helper import get_bubble_type_policy
            policy = get_bubble_type_policy(bubble_type)

            # Forward to AIOCHI Identity Engine
            resp = requests.post(
                f'{AIOCHI_IDENTITY_URL}/api/bubble',
                json={
                    'bubble_id': bubble_id,
                    'name': name,
                    'bubble_type': bubble_type,
                    'devices': devices,
                    'policy': policy,
                },
                timeout=5
            )
            if resp.status_code in (200, 201):
                result = resp.json()
                logger.info(f"Created bubble via AIOCHI: {result.get('bubble_id')}")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    **result
                })
            else:
                return jsonify({
                    'success': False,
                    'error': resp.json().get('error', 'Failed to create bubble')
                }), resp.status_code

        # Use local bubble manager
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                # Map string bubble_type to enum
                type_map = {
                    'FAMILY': BubbleType.FAMILY,
                    'GUEST': BubbleType.GUEST,
                    'IOT': BubbleType.IOT,
                    'WORK': BubbleType.CORPORATE,
                    'CUSTOM': BubbleType.CUSTOM,
                    'family': BubbleType.FAMILY,
                    'guest': BubbleType.GUEST,
                    'iot': BubbleType.IOT,
                    'smart_home': BubbleType.IOT,
                    'corporate': BubbleType.CORPORATE,
                    'custom': BubbleType.CUSTOM,
                }
                bt = type_map.get(bubble_type, BubbleType.CUSTOM)

                bubble = manager.create_bubble(
                    name=name,
                    bubble_type=bt,
                    color=color,
                    icon=icon,
                )

                # Add devices to the bubble
                for mac in devices:
                    manager.add_device(bubble.bubble_id, mac)

                logger.info(f"Created bubble via local manager: {bubble.bubble_id}")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'local_mode': True,
                    'bubble_id': bubble.bubble_id,
                    'message': f"Bubble '{name}' created"
                })

        # Use bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            bubble_id = create_bubble_in_module(name, bubble_type, devices, icon, color)
            if bubble_id:
                logger.info(f"Created bubble via bubbles module: {bubble_id}")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'module_mode': True,
                    'bubble_id': bubble_id,
                    'message': f"Bubble '{name}' created"
                })

        # Demo mode fallback - should rarely happen now
        import hashlib
        bubble_id = f"DEMO-{hashlib.sha256(f'{name}{datetime.now().isoformat()}'.encode()).hexdigest()[:12]}"
        logger.info(f"Created demo bubble: {bubble_id}")

        return jsonify({
            'success': True,
            'demo_mode': True,
            'bubble_id': bubble_id,
            'message': f"Bubble '{name}' created (demo mode - no storage available)"
        })
    except Exception as e:
        logger.error(f"Bubble create API error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/<bubble_id>', methods=['PUT'])
@login_required
def api_bubble_update(bubble_id):
    """Update a bubble (name, type, color, icon).

    Note: Quarantine (SYSTEM-QUARANTINE) is a system-managed group
    and cannot be modified.
    """
    # Protect system groups (like Quarantine)
    if bubble_id == 'SYSTEM-QUARANTINE':
        return jsonify({
            'success': False,
            'error': 'Quarantine is a system-managed group and cannot be modified.',
            'is_system': True
        }), 403

    import requests
    try:
        data = request.get_json() or {}

        if AIOCHI_ENABLED:
            resp = requests.put(
                f'{AIOCHI_IDENTITY_URL}/api/bubble/{bubble_id}',
                json=data,
                timeout=5
            )
            if resp.status_code == 200:
                logger.info(f"Updated bubble via AIOCHI: {bubble_id}")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'message': 'Bubble updated'
                })
            elif resp.status_code == 404:
                return jsonify({'success': False, 'error': 'Bubble not found'}), 404
            else:
                return jsonify({
                    'success': False,
                    'error': resp.json().get('error', 'Failed to update bubble')
                }), resp.status_code

        # Use local bubble manager
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                # Map bubble_type if provided
                bubble_type = None
                if 'bubble_type' in data:
                    type_map = {
                        'FAMILY': BubbleType.FAMILY,
                        'GUEST': BubbleType.GUEST,
                        'IOT': BubbleType.IOT,
                        'WORK': BubbleType.CORPORATE,
                        'CUSTOM': BubbleType.CUSTOM,
                    }
                    bubble_type = type_map.get(data['bubble_type'].upper(), BubbleType.CUSTOM)

                result = manager.update_bubble(
                    bubble_id=bubble_id,
                    name=data.get('name'),
                    bubble_type=bubble_type,
                    color=data.get('color'),
                    icon=data.get('icon'),
                )

                if result:
                    logger.info(f"Updated bubble via local manager: {bubble_id}")
                    return jsonify({
                        'success': True,
                        'demo_mode': False,
                        'local_mode': True,
                        'message': 'Bubble updated'
                    })
                else:
                    return jsonify({'success': False, 'error': 'Bubble not found'}), 404

        # Use bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            result = update_bubble_in_module(
                bubble_id=bubble_id,
                name=data.get('name'),
                bubble_type=data.get('bubble_type'),
                icon=data.get('icon'),
                color=data.get('color'),
            )
            if result:
                logger.info(f"Updated bubble via bubbles module: {bubble_id}")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'module_mode': True,
                    'message': 'Bubble updated'
                })
            else:
                return jsonify({'success': False, 'error': 'Bubble not found'}), 404

        # Demo mode
        logger.info(f"Updated demo bubble: {bubble_id}")
        return jsonify({
            'success': True,
            'demo_mode': True,
            'message': 'Bubble updated (demo mode)'
        })
    except Exception as e:
        logger.error(f"Bubble update API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/<bubble_id>', methods=['DELETE'])
@admin_required
def api_bubble_delete(bubble_id):
    """Delete a bubble. Devices become unassigned. Requires admin privileges.

    Note: Quarantine (SYSTEM-QUARANTINE) is a system-managed group
    and cannot be deleted.
    """
    # Protect system groups (like Quarantine)
    if bubble_id == 'SYSTEM-QUARANTINE':
        return jsonify({
            'success': False,
            'error': 'Quarantine is a system-managed group and cannot be deleted. Move devices out of Quarantine instead.',
            'is_system': True
        }), 403

    import requests
    try:
        if AIOCHI_ENABLED:
            resp = requests.delete(
                f'{AIOCHI_IDENTITY_URL}/api/bubble/{bubble_id}',
                timeout=5
            )
            if resp.status_code == 200:
                logger.info(f"Deleted bubble via AIOCHI: {bubble_id}")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'message': 'Bubble deleted'
                })
            elif resp.status_code == 404:
                return jsonify({'success': False, 'error': 'Bubble not found'}), 404
            else:
                return jsonify({
                    'success': False,
                    'error': resp.json().get('error', 'Failed to delete bubble')
                }), resp.status_code

        # Use local bubble manager
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                result = manager.delete_bubble(bubble_id)
                if result:
                    logger.info(f"Deleted bubble via local manager: {bubble_id}")
                    return jsonify({
                        'success': True,
                        'demo_mode': False,
                        'local_mode': True,
                        'message': 'Bubble deleted'
                    })
                else:
                    return jsonify({'success': False, 'error': 'Bubble not found'}), 404

        # Use bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            result = delete_bubble_in_module(bubble_id)
            if result:
                logger.info(f"Deleted bubble via bubbles module: {bubble_id}")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'module_mode': True,
                    'message': 'Bubble deleted'
                })
            else:
                return jsonify({'success': False, 'error': 'Bubble not found'}), 404

        # Demo mode
        logger.info(f"Deleted demo bubble: {bubble_id}")
        return jsonify({
            'success': True,
            'demo_mode': True,
            'message': 'Bubble deleted (demo mode)'
        })
    except Exception as e:
        logger.error(f"Bubble delete API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/<bubble_id>/devices', methods=['POST'])
@login_required
def api_bubble_add_device(bubble_id):
    """Add a device to a bubble. Device can only belong to one bubble."""
    import requests
    try:
        data = request.get_json() or {}
        mac = data.get('mac', '').upper()
        confidence = data.get('confidence', 1.0)
        reason = data.get('reason', 'Manual assignment via UI')

        if not mac:
            return jsonify({'success': False, 'error': 'MAC address required'}), 400

        if AIOCHI_ENABLED:
            resp = requests.post(
                f'{AIOCHI_IDENTITY_URL}/api/device/{mac}/assign',
                json={
                    'bubble_id': bubble_id,
                    'confidence': confidence,
                    'reason': reason,
                },
                timeout=5
            )
            if resp.status_code == 200:
                logger.info(f"Assigned device {mac} to bubble {bubble_id} via AIOCHI")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'message': f'Device {mac} added to bubble'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': resp.json().get('error', 'Failed to assign device')
                }), resp.status_code

        # Use local bubble manager
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                result = manager.add_device(bubble_id, mac)
                if result:
                    logger.info(f"Assigned device {mac} to bubble {bubble_id} via local manager")
                    return jsonify({
                        'success': True,
                        'demo_mode': False,
                        'local_mode': True,
                        'message': f'Device {mac} added to bubble'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Failed to add device (bubble not found or device already assigned)'
                    }), 400

        # Use bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            result = add_device_to_bubble_in_module(bubble_id, mac)
            if result:
                logger.info(f"Assigned device {mac} to bubble {bubble_id} via bubbles module")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'module_mode': True,
                    'message': f'Device {mac} added to bubble'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Failed to add device (bubble not found)'
                }), 400

        # Demo mode - only if no storage available
        logger.info(f"Assigned device {mac} to demo bubble {bubble_id}")
        return jsonify({
            'success': True,
            'demo_mode': True,
            'message': f'Device {mac} added to bubble (demo mode - not persisted)'
        })
    except Exception as e:
        logger.error(f"Bubble add device API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/<bubble_id>/devices/<mac>', methods=['DELETE'])
@login_required
def api_bubble_remove_device(bubble_id, mac):
    """Remove a device from a bubble. Device becomes unassigned."""
    import requests
    mac = mac.upper()
    try:
        if AIOCHI_ENABLED:
            # Assign to "unassigned" by setting bubble_id to None
            resp = requests.post(
                f'{AIOCHI_IDENTITY_URL}/api/device/{mac}/assign',
                json={
                    'bubble_id': None,
                    'confidence': 0.0,
                    'reason': 'Removed from bubble via UI',
                },
                timeout=5
            )
            if resp.status_code == 200:
                logger.info(f"Removed device {mac} from bubble {bubble_id} via AIOCHI")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'message': f'Device {mac} removed from bubble'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': resp.json().get('error', 'Failed to remove device')
                }), resp.status_code

        # Use local bubble manager
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                result = manager.remove_device(bubble_id, mac)
                if result:
                    logger.info(f"Removed device {mac} from bubble {bubble_id} via local manager")
                    return jsonify({
                        'success': True,
                        'demo_mode': False,
                        'local_mode': True,
                        'message': f'Device {mac} removed from bubble'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Failed to remove device (bubble or device not found)'
                    }), 400

        # Use bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            result = remove_device_from_bubble_in_module(bubble_id, mac)
            if result:
                logger.info(f"Removed device {mac} from bubble {bubble_id} via bubbles module")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'module_mode': True,
                    'message': f'Device {mac} removed from bubble'
                })

        # Demo mode - only if no storage available
        logger.info(f"Removed device {mac} from demo bubble {bubble_id}")
        return jsonify({
            'success': True,
            'demo_mode': True,
            'message': f'Device {mac} removed from bubble (demo mode - not persisted)'
        })
    except Exception as e:
        logger.error(f"Bubble remove device API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/move-device', methods=['POST'])
@login_required
def api_bubble_move_device():
    """Move a device between bubbles (or from unassigned to bubble).

    Used by drag-and-drop in the UI. A device can only belong to one bubble.
    """
    import requests
    try:
        data = request.get_json() or {}
        mac = data.get('mac', '').upper()
        from_bubble = data.get('from_bubble')  # Can be None/null for unassigned
        to_bubble = data.get('to_bubble')
        reason = data.get('reason', 'Moved via drag-and-drop')

        if not mac:
            return jsonify({'success': False, 'error': 'MAC address required'}), 400

        # Handle moving to unassigned (to_bubble is None, empty, or "unassigned")
        is_unassign = not to_bubble or to_bubble == 'unassigned'

        if is_unassign:
            # Moving to unassigned = remove from current bubble
            if not from_bubble:
                return jsonify({'success': False, 'error': 'from_bubble required when unassigning'}), 400

            # Use bubbles module to remove device from bubble
            if BUBBLES_MODULE_AVAILABLE:
                result = remove_device_from_bubble_in_module(from_bubble, mac)
                if result:
                    logger.info(f"Unassigned device {mac} from bubble {from_bubble} via bubbles module")
                    return jsonify({
                        'success': True,
                        'demo_mode': False,
                        'module_mode': True,
                        'message': 'Device unassigned from bubble',
                        'device': mac,
                        'from_bubble': from_bubble,
                        'to_bubble': None,
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Failed to unassign device'
                    }), 400

            # Demo mode fallback
            logger.info(f"Unassigned device {mac} from demo bubble {from_bubble}")
            return jsonify({
                'success': True,
                'demo_mode': True,
                'message': 'Device unassigned (demo mode - not persisted)',
                'device': mac,
                'from_bubble': from_bubble,
                'to_bubble': None,
            })

        if AIOCHI_ENABLED:
            resp = requests.post(
                f'{AIOCHI_IDENTITY_URL}/api/device/{mac}/assign',
                json={
                    'bubble_id': to_bubble,
                    'confidence': 1.0,
                    'reason': reason,
                },
                timeout=5
            )
            if resp.status_code == 200:
                logger.info(f"Moved device {mac} from {from_bubble} to {to_bubble} via AIOCHI")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'message': f'Device moved to bubble',
                    'device': mac,
                    'from_bubble': from_bubble,
                    'to_bubble': to_bubble,
                })
            else:
                return jsonify({
                    'success': False,
                    'error': resp.json().get('error', 'Failed to move device')
                }), resp.status_code

        # Use local bubble manager
        if LOCAL_BUBBLE_AVAILABLE:
            manager = get_local_bubble_manager()
            if manager:
                result = manager.move_device(mac, to_bubble)
                if result:
                    logger.info(f"Moved device {mac} from {from_bubble} to {to_bubble} via local manager")
                    return jsonify({
                        'success': True,
                        'demo_mode': False,
                        'local_mode': True,
                        'message': 'Device moved to bubble',
                        'device': mac,
                        'from_bubble': from_bubble,
                        'to_bubble': to_bubble,
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Failed to move device (target bubble not found)'
                    }), 400

        # Use bubbles module database (SQLite fallback)
        if BUBBLES_MODULE_AVAILABLE:
            result = move_device_in_module(mac, from_bubble, to_bubble)
            if result:
                logger.info(f"Moved device {mac} from {from_bubble} to {to_bubble} via bubbles module")
                return jsonify({
                    'success': True,
                    'demo_mode': False,
                    'module_mode': True,
                    'message': 'Device moved to bubble',
                    'device': mac,
                    'from_bubble': from_bubble,
                    'to_bubble': to_bubble,
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Failed to move device (target bubble not found)'
                }), 400

        # Demo mode - only if no storage available
        logger.info(f"Moved device {mac} in demo mode")
        return jsonify({
            'success': True,
            'demo_mode': True,
            'message': 'Device moved (demo mode - not persisted)',
            'device': mac,
            'from_bubble': from_bubble,
            'to_bubble': to_bubble,
        })
    except Exception as e:
        logger.error(f"Bubble move device API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# D2D Bubble Suggestions API (Trio+ Enhanced)
# ============================================================================

@aiochi_bp.route('/api/bubbles/suggestions')
@login_required
def api_bubble_suggestions():
    """
    Get D2D-based bubble suggestions for the dashboard.

    Uses Zeek conn.log analysis to identify devices that communicate
    and should be grouped into the same user bubble.

    Enhanced with Trio+ recommended algorithm:
    - IoT vs Personal device classification
    - D2D affinity scoring (frequency, bytes, recency, symmetry, overlap)
    - Color assignments for visualization

    Returns:
        JSON with suggestions, device colors, and stats
    """
    try:
        from lib.connection_graph import get_connection_analyzer
        from lib.behavior_clustering import get_clustering_engine

        # Get the connection analyzer
        analyzer = get_connection_analyzer()

        # Get bubble suggestions from D2D analysis
        suggestions = analyzer.get_bubble_suggestions(min_affinity=0.4)

        # Get device color assignments
        device_colors = analyzer.get_device_colors()

        # Get D2D stats
        d2d_stats = analyzer.get_stats()

        # Get clustering stats
        engine = get_clustering_engine()
        clustering_stats = engine.get_stats()

        # Get clustering suggestions (if available)
        cluster_suggestions = engine.get_bubble_suggestions()

        return jsonify({
            'success': True,
            'd2d_suggestions': suggestions[:20],  # Top 20 suggestions
            'cluster_suggestions': cluster_suggestions[:10],  # Top 10 from clustering
            'device_colors': device_colors,
            'd2d_stats': d2d_stats,
            'clustering_stats': clustering_stats,
            'summary': {
                'total_suggestions': len(suggestions),
                'personal_device_pairs': sum(1 for s in suggestions if s.get('bubble_type') == 'user'),
                'iot_device_pairs': sum(1 for s in suggestions if s.get('bubble_type') == 'iot'),
                'high_confidence': sum(1 for s in suggestions if s.get('confidence', 0) >= 0.7),
            }
        })

    except ImportError as e:
        logger.warning(f"D2D modules not available: {e}")
        return jsonify({
            'success': True,
            'd2d_suggestions': [],
            'cluster_suggestions': [],
            'device_colors': {},
            'd2d_stats': {'available': False},
            'clustering_stats': {'available': False},
            'summary': {
                'total_suggestions': 0,
                'personal_device_pairs': 0,
                'iot_device_pairs': 0,
                'high_confidence': 0,
            },
            'note': 'D2D analysis modules not available - Zeek data collection in progress'
        })

    except Exception as e:
        logger.error(f"Bubble suggestions API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/device/<mac>/classification')
@login_required
def api_device_classification(mac):
    """
    Get device classification (Personal vs IoT) for a specific device.

    Uses D2D communication patterns and OUI lookup to classify.

    Args:
        mac: Device MAC address

    Returns:
        JSON with device type, confidence, and supporting evidence
    """
    try:
        # Validate MAC address
        if not _validate_mac_address(mac):
            return jsonify({
                'success': False,
                'error': 'Invalid MAC address format'
            }), 400

        from lib.connection_graph import (
            get_connection_analyzer,
            get_oui,
            IOT_VENDOR_OUIS,
            PERSONAL_VENDOR_OUIS,
        )

        analyzer = get_connection_analyzer()

        # Classify the device
        device_type, confidence = analyzer.classify_device(mac)

        # Get additional evidence
        oui = get_oui(mac)
        vendor_type = None
        vendor_name = None

        if oui in IOT_VENDOR_OUIS:
            vendor_type = 'iot'
            vendor_name = IOT_VENDOR_OUIS[oui]
        elif oui in PERSONAL_VENDOR_OUIS:
            vendor_type = 'personal'
            vendor_name = PERSONAL_VENDOR_OUIS[oui]

        # Get D2D peers
        peers = analyzer.get_device_peers(mac)

        return jsonify({
            'success': True,
            'mac': mac.upper(),
            'device_type': device_type.value,
            'confidence': round(confidence, 2),
            'color': device_type.color,
            'oui': oui,
            'vendor_type': vendor_type,
            'vendor_name': vendor_name,
            'd2d_peers': len(peers),
            'top_peers': [
                {'mac': peer, 'affinity': round(aff, 2)}
                for peer, aff in peers[:5]
            ],
        })

    except ImportError as e:
        logger.warning(f"D2D modules not available: {e}")
        return jsonify({
            'success': True,
            'mac': mac.upper(),
            'device_type': 'unknown',
            'confidence': 0.0,
            'note': 'D2D classification not available'
        })

    except Exception as e:
        logger.error(f"Device classification API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/types')
@login_required
def api_bubble_types():
    """Get available bubble types and their policies."""
    types = [
        {
            'type': 'FAMILY',
            'name': 'Family',
            'icon': 'fa-users',
            'color': '#4CAF50',
            'policy': {'internet': True, 'lan': True, 'd2d': True, 'vlan': 110},
            'description': 'Full network access with smart home integration',
        },
        {
            'type': 'GUEST',
            'name': 'Guest',
            'icon': 'fa-user-friends',
            'color': '#607D8B',
            'policy': {'internet': True, 'lan': False, 'd2d': False, 'vlan': 150},
            'description': 'Internet only, isolated from home network',
        },
        {
            'type': 'IOT',
            'name': 'IoT / Smart Home',
            'icon': 'fa-home',
            'color': '#FF9800',
            'policy': {'internet': True, 'lan': False, 'd2d': True, 'vlan': 130},
            'description': 'Smart home devices with D2D but no LAN access',
        },
        {
            'type': 'WORK',
            'name': 'Work',
            'icon': 'fa-briefcase',
            'color': '#2196F3',
            'policy': {'internet': True, 'lan': False, 'd2d': False, 'vlan': 120},
            'description': 'Work devices, isolated from family',
        },
        {
            'type': 'CUSTOM',
            'name': 'Custom',
            'icon': 'fa-layer-group',
            'color': '#9C27B0',
            'policy': {'internet': True, 'lan': True, 'd2d': True, 'vlan': 110},
            'description': 'Custom user-defined bubble',
        },
    ]

    presets = {
        'dad': {'name': "Dad's Bubble", 'icon': 'fa-user-tie', 'color': '#1976D2'},
        'mom': {'name': "Mom's Bubble", 'icon': 'fa-user', 'color': '#E91E63'},
        'kids': {'name': "Kids' Bubble", 'icon': 'fa-child', 'color': '#FF5722'},
        'guest': {'name': 'Guests', 'icon': 'fa-user-friends', 'color': '#607D8B'},
        'work': {'name': 'Work Devices', 'icon': 'fa-laptop', 'color': '#455A64'},
    }

    return jsonify({
        'success': True,
        'types': types,
        'presets': presets
    })


# ============================================================================
# Color and Icon Palette API
# ============================================================================

@aiochi_bp.route('/api/bubbles/colors')
@login_required
def api_bubble_colors():
    """Get available colors for bubble customization."""
    try:
        if REAL_DATA_AVAILABLE:
            colors = get_color_palette()
        else:
            colors = [
                {'name': 'Blue', 'value': '#2196F3', 'class': 'primary'},
                {'name': 'Green', 'value': '#4CAF50', 'class': 'success'},
                {'name': 'Orange', 'value': '#FF9800', 'class': 'warning'},
                {'name': 'Red', 'value': '#f44336', 'class': 'danger'},
                {'name': 'Purple', 'value': '#9C27B0', 'class': 'purple'},
                {'name': 'Pink', 'value': '#E91E63', 'class': 'pink'},
                {'name': 'Cyan', 'value': '#00BCD4', 'class': 'info'},
                {'name': 'Grey', 'value': '#607D8B', 'class': 'secondary'},
            ]

        return jsonify({
            'success': True,
            'colors': colors
        })
    except Exception as e:
        logger.error(f"Bubble colors API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/bubbles/icons')
@login_required
def api_bubble_icons():
    """Get available icons for bubble customization."""
    try:
        if REAL_DATA_AVAILABLE:
            icons = get_icon_palette()
        else:
            icons = [
                {'name': 'Users', 'value': 'fa-users', 'label': 'Family'},
                {'name': 'User', 'value': 'fa-user', 'label': 'Person'},
                {'name': 'Child', 'value': 'fa-child', 'label': 'Kids'},
                {'name': 'Home', 'value': 'fa-home', 'label': 'Smart Home'},
                {'name': 'Laptop', 'value': 'fa-laptop', 'label': 'Work'},
                {'name': 'Layer Group', 'value': 'fa-layer-group', 'label': 'Custom'},
            ]

        return jsonify({
            'success': True,
            'icons': icons
        })
    except Exception as e:
        logger.error(f"Bubble icons API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# Device Names API
# ============================================================================

@aiochi_bp.route('/api/device/<mac>/name', methods=['GET'])
@login_required
def api_get_device_name(mac):
    """Get custom name for a device."""
    if not MAC_PATTERN.match(mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    try:
        custom_name = get_device_custom_name(mac)
        return jsonify({
            'success': True,
            'mac': mac.upper(),
            'custom_name': custom_name
        })
    except Exception as e:
        logger.error(f"Get device name error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/device/<mac>/name', methods=['PUT', 'POST'])
@login_required
def api_set_device_name(mac):
    """Set custom name for a device.

    Body: {"name": "Living Room Light", "original_hostname": "013_aio-nap"}
    """
    if not MAC_PATTERN.match(mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    if not BUBBLES_MODULE_AVAILABLE:
        return jsonify({'success': False, 'error': 'Device naming not available'}), 503

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
            'error': 'Name contains invalid characters'
        }), 400

    try:
        from flask_login import current_user

        with get_bubbles_db() as conn:
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

        logger.info(f"Device {mac} renamed to '{custom_name}'")
        return jsonify({
            'success': True,
            'message': f'Device renamed to {custom_name}',
            'mac': mac.upper(),
            'custom_name': custom_name
        })
    except Exception as e:
        logger.error(f"Set device name error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/device/<mac>/name', methods=['DELETE'])
@login_required
def api_delete_device_name(mac):
    """Remove custom name for a device (revert to hostname)."""
    if not MAC_PATTERN.match(mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address'}), 400

    if not BUBBLES_MODULE_AVAILABLE:
        return jsonify({'success': False, 'error': 'Device naming not available'}), 503

    try:
        with get_bubbles_db() as conn:
            conn.execute('DELETE FROM device_names WHERE mac = ?', (mac.upper(),))
            conn.commit()

        logger.info(f"Device {mac} name reset to default")
        return jsonify({'success': True, 'message': 'Device name reset to default'})
    except Exception as e:
        logger.error(f"Delete device name error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


@aiochi_bp.route('/api/device-names')
@login_required
def api_list_device_names():
    """List all custom device names."""
    if not BUBBLES_MODULE_AVAILABLE:
        return jsonify({'success': True, 'names': {}})

    try:
        names = get_all_device_names()
        return jsonify({'success': True, 'names': names})
    except Exception as e:
        logger.error(f"List device names error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(e)}), 500


# ============================================================================
# SSE Endpoint for Real-time Updates
# ============================================================================

@aiochi_bp.route('/api/events/stream')
@login_required
def api_events_stream():
    """Server-Sent Events endpoint for real-time dashboard updates.

    Streams:
    - Security events (Suricata alerts)
    - DNS blocking events
    - Device events (join/leave)
    - Bubble changes
    """
    from flask import Response, stream_with_context
    import time

    def generate():
        """Generate SSE events."""
        last_event_time = datetime.now()
        event_id = 0

        while True:
            try:
                # Check for new events every 5 seconds
                time.sleep(5)

                events_to_send = []

                # Get recent Suricata alerts
                if REAL_DATA_AVAILABLE:
                    alerts = get_suricata_alerts(limit=5)
                    for alert in alerts:
                        try:
                            alert_time = datetime.fromisoformat(alert.get('timestamp', '').replace('Z', '+00:00'))
                            if alert_time > last_event_time:
                                event_id += 1
                                events_to_send.append({
                                    'type': 'security',
                                    'id': event_id,
                                    'data': {
                                        'severity': alert.get('severity', 3),
                                        'message': alert.get('signature', 'Security event'),
                                        'timestamp': alert.get('timestamp'),
                                    }
                                })
                        except (ValueError, TypeError):
                            pass

                    # Get recent blocked domains
                    blocked = get_recent_blocked_domains(limit=5)
                    for domain_event in blocked:
                        event_id += 1
                        events_to_send.append({
                            'type': 'dns_block',
                            'id': event_id,
                            'data': {
                                'domain': domain_event.get('domain', ''),
                                'category': domain_event.get('category', 'tracking'),
                            }
                        })

                # Send heartbeat if no events
                if not events_to_send:
                    event_id += 1
                    events_to_send.append({
                        'type': 'heartbeat',
                        'id': event_id,
                        'data': {'timestamp': datetime.now().isoformat()}
                    })

                # Send events
                for event in events_to_send:
                    yield f"event: {event['type']}\n"
                    yield f"id: {event['id']}\n"
                    yield f"data: {json.dumps(event['data'])}\n\n"

                last_event_time = datetime.now()

            except GeneratorExit:
                break
            except Exception as e:
                logger.error(f"SSE error: {e}")
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                break

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )


# ============================================================================
# Active Defenses API - 5 HookProbe Innovations
# ============================================================================

# Try to import the defense backend modules
try:
    from shared.aiochi.backend.dynamic_friction import DynamicFrictionEngine, FrictionLevel
    FRICTION_ENGINE_AVAILABLE = True
except ImportError:
    FRICTION_ENGINE_AVAILABLE = False

try:
    from shared.aiochi.backend.nse_ghost_probe import NSEGhostProbe
    GHOST_PROBE_AVAILABLE = True
except ImportError:
    GHOST_PROBE_AVAILABLE = False

try:
    from shared.aiochi.backend.attack_chain_predictor import AttackChainPredictor
    CHAIN_PREDICTOR_AVAILABLE = True
except ImportError:
    CHAIN_PREDICTOR_AVAILABLE = False

try:
    from shared.aiochi.backend.honeypot_mesh import HoneypotMesh
    HONEYPOT_MESH_AVAILABLE = True
except ImportError:
    HONEYPOT_MESH_AVAILABLE = False

try:
    from shared.aiochi.backend.data_gravity_monitor import DataGravityMonitor
    GRAVITY_MONITOR_AVAILABLE = True
except ImportError:
    GRAVITY_MONITOR_AVAILABLE = False


# Lazy-load singleton instances
_friction_engine = None
_ghost_probe = None
_chain_predictor = None
_honeypot_mesh = None
_gravity_monitor = None


def get_friction_engine():
    """Get or create friction engine singleton."""
    global _friction_engine
    if _friction_engine is None and FRICTION_ENGINE_AVAILABLE:
        _friction_engine = DynamicFrictionEngine()
    return _friction_engine


def get_ghost_probe():
    """Get or create ghost probe singleton."""
    global _ghost_probe
    if _ghost_probe is None and GHOST_PROBE_AVAILABLE:
        _ghost_probe = NSEGhostProbe()
    return _ghost_probe


def get_chain_predictor():
    """Get or create chain predictor singleton."""
    global _chain_predictor
    if _chain_predictor is None and CHAIN_PREDICTOR_AVAILABLE:
        _chain_predictor = AttackChainPredictor()
    return _chain_predictor


def get_honeypot_mesh():
    """Get or create honeypot mesh singleton."""
    global _honeypot_mesh
    if _honeypot_mesh is None and HONEYPOT_MESH_AVAILABLE:
        _honeypot_mesh = HoneypotMesh()
    return _honeypot_mesh


def get_gravity_monitor():
    """Get or create gravity monitor singleton."""
    global _gravity_monitor
    if _gravity_monitor is None and GRAVITY_MONITOR_AVAILABLE:
        _gravity_monitor = DataGravityMonitor()
    return _gravity_monitor


@aiochi_bp.route('/api/defenses/friction')
@login_required
def api_defense_friction():
    """Get Dynamic Friction Control status.

    Returns devices with applied friction and statistics.
    """
    engine = get_friction_engine()

    # Demo mode if engine not available
    if not engine:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'stats': {
                'active': 2,
                'subtle': 1,
                'degraded': 1,
                'severe': 0,
            },
            'devices': [
                {
                    'mac': 'AA:BB:CC:DD:EE:01',
                    'label': 'Suspicious IoT Camera',
                    'level': 'subtle',
                    'delay_ms': 50,
                    'qsecbit': 0.42,
                    'reason': 'Unusual outbound traffic pattern detected',
                },
                {
                    'mac': 'AA:BB:CC:DD:EE:02',
                    'label': 'Guest Laptop',
                    'level': 'degraded',
                    'delay_ms': 500,
                    'qsecbit': 0.28,
                    'reason': 'Port scanning activity detected',
                },
            ],
        })

    try:
        # Get friction statistics and active frictions from engine
        engine_stats = engine.get_stats()
        all_friction = engine.get_all_friction()

        # Count by level
        stats = {
            'active': engine_stats.get('active_friction_count', 0),
            'subtle': engine_stats.get('level_distribution', {}).get('subtle', 0),
            'degraded': engine_stats.get('level_distribution', {}).get('degraded', 0),
            'severe': engine_stats.get('level_distribution', {}).get('severe', 0),
        }

        devices = []
        for key, friction_record in all_friction.items():
            # FrictionRecord is a dataclass
            level_name = friction_record.level.value if hasattr(friction_record.level, 'value') else str(friction_record.level).lower()
            delay_ms = 50 if level_name == 'subtle' else 500 if level_name == 'degraded' else 2000

            devices.append({
                'mac': friction_record.device_mac or key,
                'label': friction_record.device_ip,
                'level': level_name,
                'delay_ms': delay_ms,
                'qsecbit': friction_record.qsecbit_score,
                'reason': friction_record.reason or 'Security policy',
            })

        return jsonify({
            'success': True,
            'demo_mode': False,
            'stats': stats,
            'devices': devices,
        })
    except Exception as e:
        logger.error(f"Friction API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))})


@aiochi_bp.route('/api/defenses/ghost')
@login_required
def api_defense_ghost():
    """Get NSE Ghost Probe status.

    Returns recent probe results and statistics.
    """
    probe = get_ghost_probe()

    # Demo mode if probe not available
    if not probe:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'stats': {
                'probes_24h': 15,
                'clean': 12,
                'suspicious': 2,
                'masquerading': 1,
            },
            'probes': [
                {
                    'mac': 'AA:BB:CC:DD:EE:03',
                    'claimed_vendor': 'Apple, Inc.',
                    'actual_vendor': 'Apple, Inc.',
                    'verdict': 'clean',
                    'confidence': 0.95,
                    'action': 'none',
                    'label': 'iPhone 15 Pro',
                },
                {
                    'mac': 'AA:BB:CC:DD:EE:04',
                    'claimed_vendor': 'Samsung',
                    'actual_vendor': 'Unknown (Chinese OEM)',
                    'verdict': 'suspicious',
                    'confidence': 0.72,
                    'action': 'friction_applied',
                    'label': 'Smart Bulb',
                },
                {
                    'mac': 'AA:BB:CC:DD:EE:05',
                    'claimed_vendor': 'Apple, Inc.',
                    'actual_vendor': 'Raspberry Pi Foundation',
                    'verdict': 'masquerading',
                    'confidence': 0.88,
                    'action': 'quarantined',
                    'label': 'Unknown Device',
                },
            ],
        })

    try:
        # Get probe statistics from engine
        probe_stats = probe.get_stats()

        stats = {
            'probes_24h': probe_stats.get('probes_completed', 0),
            'clean': probe_stats.get('probes_completed', 0) - probe_stats.get('masquerading_detected', 0) - probe_stats.get('compromised_detected', 0),
            'suspicious': probe_stats.get('compromised_detected', 0),
            'masquerading': probe_stats.get('masquerading_detected', 0),
        }

        # Probe results come from cache (recent probes only)
        probes = []
        if hasattr(probe, '_cache') and probe._cache:
            for ip, result in list(probe._cache.items())[:20]:
                probes.append({
                    'mac': getattr(result, 'target_mac', '') or '',
                    'claimed_vendor': getattr(result, 'dhcp_hostname', 'Unknown'),
                    'actual_vendor': getattr(result, 'oui_vendor', 'Unknown'),
                    'verdict': result.verdict.value if hasattr(result.verdict, 'value') else str(result.verdict),
                    'confidence': getattr(result, 'confidence', 0),
                    'action': 'none',
                    'label': getattr(result, 'dhcp_hostname', ip),
                })

        return jsonify({
            'success': True,
            'demo_mode': False,
            'stats': stats,
            'probes': probes,
        })
    except Exception as e:
        logger.error(f"Ghost Probe API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))})


@aiochi_bp.route('/api/defenses/ghost/probe-all', methods=['POST'])
@login_required
def api_defense_ghost_probe_all():
    """Trigger probing of all connected devices."""
    probe = get_ghost_probe()

    if not probe:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'message': 'Demo mode - would probe all devices',
            'devices_queued': 5,
        })

    try:
        result = probe.probe_all_devices()
        return jsonify({
            'success': True,
            'message': 'Probe initiated for all devices',
            'devices_queued': result.get('queued_count', 0),
        })
    except Exception as e:
        logger.error(f"Probe All error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))})


@aiochi_bp.route('/api/defenses/chain')
@login_required
def api_defense_chain():
    """Get Attack Chain Predictor status.

    Returns active attack chains and predictions.
    """
    predictor = get_chain_predictor()

    # Demo mode if predictor not available
    if not predictor:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'stats': {
                'predictions_24h': 8,
                'hardened': 5,
                'prevented': 3,
                'active_chains': 1,
            },
            'chains': [
                {
                    'chain_id': 'chain-abc12345',
                    'device_mac': 'AA:BB:CC:DD:EE:06',
                    'techniques': ['T1595.001', 'T1046', 'T1110.003'],
                    'current_stage': 3,
                    'total_stages': 5,
                    'confidence': 0.78,
                    'predicted_next': [
                        {'technique': 'T1021.001', 'probability': 0.65},
                        {'technique': 'T1078', 'probability': 0.45},
                    ],
                    'status': 'monitoring',
                },
            ],
        })

    try:
        # Get all tracked chains from predictor
        all_chains = predictor.get_all_chains()
        stats = predictor.get_stats()

        chains = []
        for chain_id, chain_data in list(all_chains.items())[:10]:
            # chain_data is an AttackChain object
            techniques = getattr(chain_data, 'observed_techniques', [])
            if hasattr(chain_data, 'events'):
                techniques = [e.mitre_id for e in chain_data.events if hasattr(e, 'mitre_id')]

            chains.append({
                'chain_id': chain_id,
                'device_mac': getattr(chain_data, 'source_ip', 'Unknown'),
                'techniques': techniques,
                'current_stage': len(techniques),
                'total_stages': max(len(techniques) + 2, 5),
                'confidence': getattr(chain_data, 'confidence', 0),
                'predicted_next': getattr(chain_data, 'predicted_next', []),
                'status': 'monitoring' if getattr(chain_data, 'is_active', True) else 'completed',
            })

        return jsonify({
            'success': True,
            'demo_mode': False,
            'stats': {
                'predictions_24h': stats.get('predictions_made', 0),
                'hardened': stats.get('hardenings_triggered', 0),
                'prevented': stats.get('hardenings_triggered', 0),
                'active_chains': len(all_chains),
            },
            'chains': chains,
        })
    except Exception as e:
        logger.error(f"Chain Predictor API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))})


@aiochi_bp.route('/api/defenses/honeypot')
@login_required
def api_defense_honeypot():
    """Get Honeypot Mesh status.

    Returns attacker profiles and touch statistics.
    """
    mesh = get_honeypot_mesh()

    # Demo mode if mesh not available
    if not mesh:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'stats': {
                'touches_24h': 47,
                'dark_ports': 12,
                'unique_attackers': 8,
                'critical_threats': 2,
            },
            'attackers': [
                {
                    'source_ip': '185.234.219.xxx',
                    'threat_level': 'critical',
                    'ports_touched': [22, 3389, 445, 23],
                    'ttp_count': 5,
                    'reputation': 'Known Scanner',
                    'country': 'RU',
                    'action': 'blocked',
                    'last_seen': '2 min ago',
                },
                {
                    'source_ip': '103.152.xxx.xxx',
                    'threat_level': 'high',
                    'ports_touched': [80, 8080, 443],
                    'ttp_count': 3,
                    'reputation': 'Bot Network',
                    'country': 'CN',
                    'action': 'tarpitted',
                    'last_seen': '15 min ago',
                },
                {
                    'source_ip': '192.168.1.xxx',
                    'threat_level': 'low',
                    'ports_touched': [8888],
                    'ttp_count': 1,
                    'reputation': 'Internal',
                    'country': 'Local',
                    'action': 'logged',
                    'last_seen': '1 hour ago',
                },
            ],
        })

    try:
        # Get honeypot data from mesh (using synchronous get_stats)
        mesh_stats = mesh.get_stats()

        # Access attacker profiles directly (they're stored as dict)
        attacker_profiles_dict = getattr(mesh, 'attacker_profiles', {})
        touches_list = getattr(mesh, 'touches', [])
        dark_ports_dict = getattr(mesh, 'dark_ports', {})

        # Count 24h touches
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(hours=24)
        recent_touches = [t for t in touches_list if hasattr(t, 'timestamp') and t.timestamp > cutoff]

        stats = {
            'touches_24h': len(recent_touches),
            'dark_ports': mesh_stats.get('dark_ports', 0),
            'unique_attackers': mesh_stats.get('attacker_profiles', 0),
            'critical_threats': mesh_stats.get('active_threats', 0),
        }

        attackers = []
        for ip, profile in list(attacker_profiles_dict.items())[:15]:
            # AttackerProfile is a dataclass
            threat_level = profile.threat_level.value if hasattr(profile.threat_level, 'value') else str(profile.threat_level)
            touched_ports = getattr(profile, 'touched_ports', [])
            ports_list = [p.port for p in touched_ports] if touched_ports else []

            attackers.append({
                'source_ip': ip,
                'threat_level': threat_level,
                'ports_touched': ports_list,
                'ttp_count': len(getattr(profile, 'observed_ttps', [])),
                'reputation': getattr(profile, 'reputation', 'Unknown'),
                'country': getattr(profile, 'country_code', '??'),
                'action': 'logged',
                'last_seen': str(getattr(profile, 'last_seen', 'Unknown')),
            })

        return jsonify({
            'success': True,
            'demo_mode': False,
            'stats': stats,
            'attackers': attackers,
        })
    except Exception as e:
        logger.error(f"Honeypot API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))})


@aiochi_bp.route('/api/defenses/gravity')
@login_required
def api_defense_gravity():
    """Get Data Gravity Monitor status.

    Returns exfiltration events and sensitive file movements.
    """
    monitor = get_gravity_monitor()

    # Demo mode if monitor not available
    if not monitor:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'stats': {
                'events_24h': 23,
                'blocked': 5,
                'sensitive_files': 18,
                'high_risk_sources': 2,
            },
            'events': [
                {
                    'filename': 'customer_db_backup.sql',
                    'size_bytes': 52428800,
                    'source_device': 'Server-01',
                    'dest_ip': '203.0.113.xxx (DigitalOcean)',
                    'risk_level': 'critical',
                    'risk_score': 0.92,
                    'mitre_techniques': ['T1048.002', 'T1567'],
                    'action': 'blocked',
                    'timestamp': '5 min ago',
                },
                {
                    'filename': 'quarterly_report.xlsx',
                    'size_bytes': 2097152,
                    'source_device': 'Finance-PC',
                    'dest_ip': 'OneDrive (Microsoft)',
                    'risk_level': 'medium',
                    'risk_score': 0.45,
                    'mitre_techniques': ['T1567.002'],
                    'action': 'allowed',
                    'timestamp': '20 min ago',
                },
                {
                    'filename': 'photo_001.jpg',
                    'size_bytes': 4194304,
                    'source_device': 'iPhone-Sarah',
                    'dest_ip': 'iCloud (Apple)',
                    'risk_level': 'low',
                    'risk_score': 0.12,
                    'mitre_techniques': [],
                    'action': 'allowed',
                    'timestamp': '1 hour ago',
                },
            ],
        })

    try:
        # Get gravity data from monitor (using synchronous methods)
        stats = monitor.get_stats()

        # Access events directly from the monitor
        from datetime import datetime, timedelta
        exfil_events = getattr(monitor, 'exfil_events', [])
        cutoff = datetime.now() - timedelta(hours=24)
        recent_events = [e for e in exfil_events if hasattr(e, 'timestamp') and e.timestamp > cutoff]

        formatted_events = []
        for e in recent_events[:20]:
            # ExfilEvent is a dataclass
            risk_level = 'critical' if e.risk_score >= 0.8 else 'high' if e.risk_score >= 0.6 else 'medium' if e.risk_score >= 0.4 else 'low'
            sensitivity = getattr(e.sensitivity, 'value', str(e.sensitivity)) if hasattr(e, 'sensitivity') else 'unknown'

            formatted_events.append({
                'filename': getattr(e, 'filename', 'Unknown'),
                'size_bytes': getattr(e, 'file_size', 0),
                'source_device': getattr(e, 'source_ip', 'Unknown'),
                'dest_ip': getattr(e, 'dest_ip', 'Unknown'),
                'risk_level': risk_level,
                'risk_score': e.risk_score,
                'mitre_techniques': getattr(e, 'mitre_techniques', []),
                'action': 'blocked' if getattr(e, 'blocked', False) else 'allowed',
                'timestamp': str(e.timestamp) if hasattr(e, 'timestamp') else 'Unknown',
            })

        return jsonify({
            'success': True,
            'demo_mode': False,
            'stats': {
                'events_24h': len(recent_events),
                'blocked': stats.get('blocked_transfers', 0),
                'sensitive_files': stats.get('total_events', 0),
                'high_risk_sources': len([e for e in recent_events if e.risk_score >= 0.7]),
            },
            'events': formatted_events,
        })
    except Exception as e:
        logger.error(f"Gravity Monitor API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))})


# =============================================================================
# D2D (DEVICE-TO-DEVICE) COMMUNICATION COLOR APIs
# =============================================================================
# These endpoints expose the D2D connection graph analysis to the frontend,
# enabling visualization of device relationships with color coding.

@aiochi_bp.route('/api/d2d/colors')
@login_required
def api_d2d_colors():
    """Get device colors based on D2D communication clusters.

    Returns a mapping of MAC addresses to hex colors based on:
    1. Device type (Personal=green, IoT=orange, Infra=blue, Unknown=gray)
    2. D2D cluster membership (devices that communicate get same color)

    This enables the UI to color-code devices by their relationships.
    """
    if not D2D_CONNECTION_AVAILABLE:
        # Return demo colors based on common device types
        return jsonify({
            'success': True,
            'demo_mode': True,
            'device_colors': {},
            'cluster_colors': {},
            'palette': {
                'device_types': {
                    'personal': '#4CAF50',
                    'iot': '#FF9800',
                    'infrastructure': '#2196F3',
                    'unknown': '#9E9E9E',
                },
                'user_bubbles': USER_BUBBLE_COLORS if 'USER_BUBBLE_COLORS' in dir() else [
                    '#E91E63', '#3F51B5', '#009688', '#FF5722',
                    '#673AB7', '#00BCD4', '#795548', '#607D8B',
                ],
            },
        })

    try:
        analyzer = get_connection_analyzer()

        # Get device type colors (based on classification)
        device_colors = analyzer.get_device_colors()

        # Assign and get cluster colors (based on D2D communication)
        cluster_colors = analyzer.assign_bubble_colors()

        # Build device-to-cluster mapping
        clusters = analyzer.find_d2d_clusters()
        device_to_cluster = {}
        for i, cluster in enumerate(clusters):
            color = cluster_colors.get(i, get_user_bubble_color(i))
            for mac in cluster.devices:
                device_to_cluster[mac.upper()] = {
                    'cluster_id': i,
                    'cluster_color': color,
                    'type_color': device_colors.get(mac, '#9E9E9E'),
                    'device_count': len(cluster.devices),
                    'avg_affinity': round(cluster.avg_affinity, 2),
                }

        return jsonify({
            'success': True,
            'demo_mode': False,
            'device_colors': {k.upper(): v for k, v in device_colors.items()},
            'device_clusters': device_to_cluster,
            'cluster_colors': cluster_colors,
            'cluster_count': len(clusters),
            'palette': {
                'device_types': {
                    'personal': DEVICE_TYPE_COLORS[DeviceType.PERSONAL],
                    'iot': DEVICE_TYPE_COLORS[DeviceType.IOT],
                    'infrastructure': DEVICE_TYPE_COLORS[DeviceType.INFRASTRUCTURE],
                    'unknown': DEVICE_TYPE_COLORS[DeviceType.UNKNOWN],
                },
                'user_bubbles': USER_BUBBLE_COLORS,
            },
        })
    except Exception as e:
        logger.error(f"D2D colors API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))}), 500


@aiochi_bp.route('/api/d2d/clusters')
@login_required
def api_d2d_clusters():
    """Get D2D communication clusters.

    Returns groups of devices that communicate with each other,
    with color assignments for visualization.
    """
    if not D2D_CONNECTION_AVAILABLE:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'clusters': [
                {
                    'cluster_id': 0,
                    'color': '#E91E63',
                    'devices': ['AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02'],
                    'device_count': 2,
                    'avg_affinity': 0.85,
                    'services': ['airplay', 'mdns'],
                    'label': 'Dad\'s Devices',
                },
                {
                    'cluster_id': 1,
                    'color': '#3F51B5',
                    'devices': ['BB:CC:DD:EE:FF:01', 'BB:CC:DD:EE:FF:02', 'BB:CC:DD:EE:FF:03'],
                    'device_count': 3,
                    'avg_affinity': 0.72,
                    'services': ['smb', 'mdns', 'spotify'],
                    'label': 'Mom\'s Devices',
                },
            ],
        })

    try:
        analyzer = get_connection_analyzer()
        clusters = analyzer.find_d2d_clusters()
        cluster_colors = analyzer.assign_bubble_colors()

        formatted_clusters = []
        for i, cluster in enumerate(clusters):
            color = cluster_colors.get(i, get_user_bubble_color(i))

            # Get device details for each MAC
            devices_with_info = []
            for mac in cluster.devices:
                device_type, confidence = analyzer.classify_device(mac)
                devices_with_info.append({
                    'mac': mac.upper(),
                    'device_type': device_type.value,
                    'type_confidence': round(confidence, 2),
                    'type_color': device_type.color,
                })

            formatted_clusters.append({
                'cluster_id': i,
                'color': color,
                'devices': [mac.upper() for mac in cluster.devices],
                'devices_detailed': devices_with_info,
                'device_count': len(cluster.devices),
                'avg_affinity': round(cluster.avg_affinity, 2),
                'services': cluster.primary_services,
            })

        return jsonify({
            'success': True,
            'demo_mode': False,
            'clusters': formatted_clusters,
            'total_clusters': len(formatted_clusters),
        })
    except Exception as e:
        logger.error(f"D2D clusters API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))}), 500


@aiochi_bp.route('/api/d2d/relationships')
@login_required
def api_d2d_relationships():
    """Get all D2D relationships with colors and affinity scores.

    Returns edges between devices that communicate, with:
    - Affinity score (0.0-1.0)
    - Connection count
    - Services used
    - Assigned bubble color
    """
    if not D2D_CONNECTION_AVAILABLE:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'relationships': [
                {
                    'device_a': 'AA:BB:CC:DD:EE:01',
                    'device_b': 'AA:BB:CC:DD:EE:02',
                    'affinity': 0.85,
                    'connection_count': 150,
                    'services': ['airplay', 'mdns'],
                    'bubble_color': '#E91E63',
                    'should_suggest': True,
                },
            ],
            'stats': {
                'total_relationships': 1,
                'high_affinity_pairs': 1,
            },
        })

    try:
        analyzer = get_connection_analyzer()

        # Ensure colors are assigned
        analyzer.assign_bubble_colors()

        relationships = []
        for key, rel in analyzer.relationships.items():
            mac_a, mac_b = key
            affinity = rel.calculate_affinity_score()
            suggestion = rel.get_suggestion_details()

            relationships.append({
                'device_a': mac_a.upper(),
                'device_b': mac_b.upper(),
                'affinity': round(affinity, 3),
                'connection_count': rel.connection_count,
                'services': rel.services,
                'bubble_color': rel.bubble_color or '#9E9E9E',
                'temporal_sync': round(rel.temporal_sync_score, 2),
                'discovery_hits': rel.discovery_hits,
                'device_type_a': rel.device_type_a,
                'device_type_b': rel.device_type_b,
                'should_suggest': suggestion.get('should_suggest', False),
                'suggestion_reason': suggestion.get('reason', ''),
            })

        # Sort by affinity (highest first)
        relationships.sort(key=lambda x: x['affinity'], reverse=True)

        stats = analyzer.get_stats()

        return jsonify({
            'success': True,
            'demo_mode': False,
            'relationships': relationships,
            'stats': stats,
        })
    except Exception as e:
        logger.error(f"D2D relationships API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))}), 500


@aiochi_bp.route('/api/d2d/peers/<mac>')
@login_required
def api_d2d_peers(mac):
    """Get communication peers for a specific device.

    Returns devices that the specified device communicates with,
    sorted by affinity score.
    """
    # Validate MAC address
    if not _validate_mac_address(mac):
        return jsonify({'success': False, 'error': 'Invalid MAC address format'}), 400

    mac_normalized = mac.upper()

    if not D2D_CONNECTION_AVAILABLE:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'device': mac_normalized,
            'peers': [],
            'device_type': 'unknown',
            'type_color': '#9E9E9E',
        })

    try:
        analyzer = get_connection_analyzer()

        # Get device classification
        device_type, type_confidence = analyzer.classify_device(mac_normalized)

        # Get high-affinity peers
        peers = analyzer.get_high_affinity_peers(mac_normalized)

        # Format peer data with colors
        peer_data = []
        for peer_mac, affinity in peers:
            peer_type, peer_confidence = analyzer.classify_device(peer_mac)

            # Get relationship details
            key = analyzer._normalize_mac_pair(mac_normalized, peer_mac)
            rel = analyzer.relationships.get(key)

            peer_data.append({
                'mac': peer_mac.upper(),
                'affinity': round(affinity, 3),
                'device_type': peer_type.value,
                'type_color': peer_type.color,
                'type_confidence': round(peer_confidence, 2),
                'bubble_color': rel.bubble_color if rel else '#9E9E9E',
                'services': rel.services if rel else [],
                'connection_count': rel.connection_count if rel else 0,
            })

        return jsonify({
            'success': True,
            'demo_mode': False,
            'device': mac_normalized,
            'device_type': device_type.value,
            'type_color': device_type.color,
            'type_confidence': round(type_confidence, 2),
            'peers': peer_data,
            'peer_count': len(peer_data),
        })
    except Exception as e:
        logger.error(f"D2D peers API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))}), 500


@aiochi_bp.route('/api/d2d/stats')
@login_required
def api_d2d_stats():
    """Get D2D connection graph statistics.

    Returns overview stats about device relationships and clusters.
    """
    if not D2D_CONNECTION_AVAILABLE:
        return jsonify({
            'success': True,
            'demo_mode': True,
            'stats': {
                'total_relationships': 0,
                'total_connections': 0,
                'high_affinity_pairs': 0,
                'unique_devices': 0,
                'device_types': {'personal': 0, 'iot': 0, 'unknown': 0},
                'bubble_suggestions': 0,
            },
        })

    try:
        analyzer = get_connection_analyzer()
        stats = analyzer.get_stats()

        # Add cluster info
        clusters = analyzer.find_d2d_clusters()

        return jsonify({
            'success': True,
            'demo_mode': False,
            'stats': stats,
            'cluster_count': len(clusters),
            'palette': {
                'device_types': {
                    'personal': DEVICE_TYPE_COLORS[DeviceType.PERSONAL],
                    'iot': DEVICE_TYPE_COLORS[DeviceType.IOT],
                    'infrastructure': DEVICE_TYPE_COLORS[DeviceType.INFRASTRUCTURE],
                    'unknown': DEVICE_TYPE_COLORS[DeviceType.UNKNOWN],
                },
                'user_bubbles': USER_BUBBLE_COLORS,
            },
        })
    except Exception as e:
        logger.error(f"D2D stats API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))}), 500


@aiochi_bp.route('/api/d2d/analyze', methods=['POST'])
@login_required
@admin_required
def api_d2d_analyze():
    """Trigger D2D connection analysis.

    Parses Zeek logs and updates device relationships.
    Admin only as this can be resource-intensive.
    """
    if not D2D_CONNECTION_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'D2D connection graph module not available',
        }), 503

    try:
        analyzer = get_connection_analyzer()
        analyzer.update_relationships()
        stats = analyzer.get_stats()

        return jsonify({
            'success': True,
            'message': 'D2D analysis completed',
            'stats': stats,
        })
    except Exception as e:
        logger.error(f"D2D analyze API error: {e}")
        return jsonify({'success': False, 'error': safe_error_message(str(e))}), 500
