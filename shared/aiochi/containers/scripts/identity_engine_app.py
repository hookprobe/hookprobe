"""AIOCHI Identity Engine REST API

Provides bidirectional sync between Fortress SDN Autopilot and AIOCHI:
- Fortress sends bubble/device data via POST /api/bubble/sync
- Fortress queries enriched identities via GET /api/enrichment/<mac>
- Both systems share trust scores via GET /api/trust/<mac>
"""
# NOTE: Using __import__ to avoid 'from' keyword which confuses buildah heredoc parsing
Flask = __import__('flask').Flask
jsonify = __import__('flask').jsonify
request = __import__('flask').request
import os
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

# In-memory storage for bubble sync data (in production: ClickHouse)
_bubble_registry = {}  # bubble_id -> bubble_data
_device_bubble_map = {}  # mac -> bubble_id
_sync_timestamp = None


def create_app():
    """Create Flask application."""
    app = Flask(__name__)

    # Singleton engine instance (avoid re-creating on each request)
    _engine = None

    def get_engine():
        nonlocal _engine
        if _engine is None:
            identity_engine = __import__('backend.identity_engine', fromlist=['IdentityEngine'])
            _engine = identity_engine.IdentityEngine()
        return _engine

    @app.route('/health')
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'identity-engine',
            'sync_timestamp': _sync_timestamp.isoformat() if _sync_timestamp else None,
            'bubbles_synced': len(_bubble_registry),
            'devices_mapped': len(_device_bubble_map),
        })

    @app.route('/api/device/<mac>')
    def get_device(mac):
        """Get device identity by MAC address."""
        engine = get_engine()
        # Use enrich() which is the correct method name in IdentityEngine
        identity = engine.enrich(mac)
        if identity:
            return jsonify(identity.to_dict())
        return jsonify({'error': 'Device not found'}), 404

    @app.route('/api/devices')
    def list_devices():
        """List all known devices."""
        engine = get_engine()
        # Use get_all_devices() which is the correct method name
        devices = engine.get_all_devices()
        return jsonify([d.to_dict() for d in devices])

    @app.route('/api/ecosystems')
    def list_ecosystems():
        """List detected ecosystem bubbles grouped by ecosystem type."""
        engine = get_engine()
        devices = engine.get_all_devices()
        # Group devices by ecosystem
        ecosystems = defaultdict(list)
        for device in devices:
            eco_name = device.ecosystem.value if hasattr(device.ecosystem, 'value') else str(device.ecosystem)
            ecosystems[eco_name].append(device.to_dict())
        return jsonify(dict(ecosystems))

    @app.route('/api/feed', methods=['POST'])
    def post_feed():
        """Receive narrative events for the privacy feed."""
        data = request.get_json() or {}
        # Store/forward to narrative engine - placeholder for now
        return jsonify({'status': 'received', 'event': data.get('narrative', {}).get('id', 'unknown')})

    @app.route('/api/performance', methods=['POST'])
    def post_performance():
        """Receive performance metrics."""
        data = request.get_json() or {}
        # Store performance data - placeholder for now
        return jsonify({'status': 'received'})

    @app.route('/api/alert', methods=['POST'])
    def post_alert():
        """Receive security alerts."""
        data = request.get_json() or {}
        # Store/forward alerts - placeholder for now
        return jsonify({'status': 'received', 'alert_type': data.get('type', 'unknown')})

    @app.route('/api/presence', methods=['POST'])
    def post_presence():
        """Receive device presence updates."""
        data = request.get_json() or {}
        # Update presence tracking - placeholder for now
        return jsonify({'status': 'received'})

    @app.route('/api/feedback-request', methods=['POST'])
    def post_feedback_request():
        """Request human feedback on AI decisions."""
        data = request.get_json() or {}
        # Queue feedback request - placeholder for now
        return jsonify({'status': 'queued', 'action_id': data.get('action_id', 'unknown')})

    # =========================================================================
    # BUBBLE MANAGEMENT ENDPOINTS (Single Source of Truth)
    # Fortress SDN Autopilot queries these for NAC policy enforcement
    # =========================================================================

    @app.route('/api/bubbles', methods=['GET'])
    def list_bubbles():
        """List all bubbles with their devices and policies.

        Used by Fortress SDN to get current bubble state for NAC enforcement.
        """
        global _bubble_registry
        return jsonify({
            'bubbles': list(_bubble_registry.values()),
            'total': len(_bubble_registry),
            'sync_timestamp': _sync_timestamp.isoformat() if _sync_timestamp else None,
        })

    @app.route('/api/bubble/<bubble_id>', methods=['GET'])
    def get_bubble(bubble_id):
        """Get a specific bubble by ID."""
        global _bubble_registry
        if bubble_id in _bubble_registry:
            return jsonify(_bubble_registry[bubble_id])
        return jsonify({'error': 'Bubble not found'}), 404

    @app.route('/api/bubble', methods=['POST'])
    def create_bubble():
        """Create a new bubble.

        Request body:
        {
            "bubble_id": "family-dad",
            "name": "Dad's Devices",
            "bubble_type": "FAMILY",  # FAMILY, GUEST, IOT, WORK
            "devices": ["AA:BB:CC:DD:EE:01"],
            "policy": {
                "internet": true,
                "lan": true,
                "d2d": true,
                "vlan": 110
            }
        }
        """
        global _bubble_registry, _device_bubble_map, _sync_timestamp
        data = request.get_json() or {}

        bubble_id = data.get('bubble_id')
        if not bubble_id:
            return jsonify({'error': 'bubble_id required'}), 400

        bubble = {
            'bubble_id': bubble_id,
            'name': data.get('name', f'Bubble {bubble_id}'),
            'bubble_type': data.get('bubble_type', 'GUEST'),
            'devices': data.get('devices', []),
            'policy': data.get('policy', {
                'internet': True,
                'lan': False,
                'd2d': False,
                'vlan': 150,
            }),
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
        }

        _bubble_registry[bubble_id] = bubble

        # Update device-to-bubble mapping
        for mac in bubble['devices']:
            _device_bubble_map[mac.upper()] = bubble_id

        _sync_timestamp = datetime.now()
        logger.info(f"Created bubble: {bubble_id} with {len(bubble['devices'])} devices")

        return jsonify({'status': 'created', 'bubble': bubble}), 201

    @app.route('/api/bubble/<bubble_id>', methods=['PUT'])
    def update_bubble(bubble_id):
        """Update an existing bubble."""
        global _bubble_registry, _device_bubble_map, _sync_timestamp
        data = request.get_json() or {}

        if bubble_id not in _bubble_registry:
            return jsonify({'error': 'Bubble not found'}), 404

        bubble = _bubble_registry[bubble_id]

        # Update fields
        if 'name' in data:
            bubble['name'] = data['name']
        if 'bubble_type' in data:
            bubble['bubble_type'] = data['bubble_type']
        if 'policy' in data:
            bubble['policy'].update(data['policy'])
        if 'devices' in data:
            # Remove old device mappings
            for mac in bubble['devices']:
                if _device_bubble_map.get(mac.upper()) == bubble_id:
                    del _device_bubble_map[mac.upper()]
            # Set new devices
            bubble['devices'] = data['devices']
            for mac in bubble['devices']:
                _device_bubble_map[mac.upper()] = bubble_id

        bubble['updated_at'] = datetime.now().isoformat()
        _sync_timestamp = datetime.now()

        return jsonify({'status': 'updated', 'bubble': bubble})

    @app.route('/api/bubble/<bubble_id>', methods=['DELETE'])
    def delete_bubble(bubble_id):
        """Delete a bubble."""
        global _bubble_registry, _device_bubble_map, _sync_timestamp

        if bubble_id not in _bubble_registry:
            return jsonify({'error': 'Bubble not found'}), 404

        bubble = _bubble_registry[bubble_id]

        # Remove device mappings
        for mac in bubble['devices']:
            if _device_bubble_map.get(mac.upper()) == bubble_id:
                del _device_bubble_map[mac.upper()]

        del _bubble_registry[bubble_id]
        _sync_timestamp = datetime.now()

        return jsonify({'status': 'deleted', 'bubble_id': bubble_id})

    @app.route('/api/device/<mac>/bubble', methods=['GET'])
    def get_device_bubble(mac):
        """Get the bubble assignment for a device.

        Used by Fortress SDN to determine NAC policy for a device.
        """
        global _device_bubble_map, _bubble_registry
        mac = mac.upper().replace('-', ':')

        bubble_id = _device_bubble_map.get(mac)
        if bubble_id and bubble_id in _bubble_registry:
            bubble = _bubble_registry[bubble_id]
            return jsonify({
                'mac': mac,
                'bubble_id': bubble_id,
                'bubble_name': bubble['name'],
                'bubble_type': bubble['bubble_type'],
                'policy': bubble['policy'],
            })

        # Device not in any bubble - return guest policy
        return jsonify({
            'mac': mac,
            'bubble_id': None,
            'bubble_name': 'Unassigned',
            'bubble_type': 'GUEST',
            'policy': {
                'internet': True,
                'lan': False,
                'd2d': False,
                'vlan': 150,
            },
        })

    @app.route('/api/device/<mac>/assign', methods=['POST'])
    def assign_device_to_bubble(mac):
        """Assign a device to a bubble.

        Request body:
        {
            "bubble_id": "family-dad",
            "confidence": 0.85,
            "reason": "Same ecosystem as existing devices"
        }
        """
        global _bubble_registry, _device_bubble_map, _sync_timestamp
        data = request.get_json() or {}
        mac = mac.upper().replace('-', ':')

        bubble_id = data.get('bubble_id')
        if not bubble_id:
            return jsonify({'error': 'bubble_id required'}), 400

        if bubble_id not in _bubble_registry:
            return jsonify({'error': 'Bubble not found'}), 404

        # Remove from old bubble if any
        old_bubble_id = _device_bubble_map.get(mac)
        if old_bubble_id and old_bubble_id in _bubble_registry:
            old_bubble = _bubble_registry[old_bubble_id]
            if mac in old_bubble['devices']:
                old_bubble['devices'].remove(mac)

        # Add to new bubble
        bubble = _bubble_registry[bubble_id]
        if mac not in bubble['devices']:
            bubble['devices'].append(mac)

        _device_bubble_map[mac] = bubble_id
        bubble['updated_at'] = datetime.now().isoformat()
        _sync_timestamp = datetime.now()

        logger.info(f"Assigned {mac} to bubble {bubble_id} (confidence: {data.get('confidence', 0)})")

        return jsonify({
            'status': 'assigned',
            'mac': mac,
            'bubble_id': bubble_id,
            'confidence': data.get('confidence', 0),
        })

    @app.route('/api/trust/<mac>', methods=['GET'])
    def get_trust_score(mac):
        """Get trust score for a device.

        Used by Fortress SDN for policy decisions.
        """
        engine = get_engine()
        mac = mac.upper().replace('-', ':')

        identity = engine.get_identity(mac)
        if identity:
            return jsonify({
                'mac': mac,
                'trust_level': identity.trust_level.value,
                'trust_name': identity.trust_level.name,
                'confidence': identity.confidence,
                'ecosystem': identity.ecosystem.value,
            })

        # Unknown device - untrusted
        return jsonify({
            'mac': mac,
            'trust_level': 0,
            'trust_name': 'L0_UNTRUSTED',
            'confidence': 0.0,
            'ecosystem': 'unknown',
        })

    @app.route('/api/enrichment/<mac>', methods=['GET'])
    def get_enrichment(mac):
        """Get full enrichment data for a device.

        Returns identity, bubble assignment, and trust score.
        Used by Fortress SDN for comprehensive device info.
        """
        engine = get_engine()
        mac = mac.upper().replace('-', ':')

        # Get identity
        identity = engine.get_identity(mac)
        identity_data = identity.to_dict() if identity else {
            'mac': mac,
            'human_label': f'Unknown ({mac[-8:]})',
            'device_type': '',
            'vendor': '',
            'ecosystem': 'unknown',
            'trust_level': 0,
            'confidence': 0.0,
        }

        # Get bubble assignment
        bubble_id = _device_bubble_map.get(mac)
        bubble_data = None
        if bubble_id and bubble_id in _bubble_registry:
            bubble_data = _bubble_registry[bubble_id]

        return jsonify({
            'identity': identity_data,
            'bubble': {
                'bubble_id': bubble_id,
                'name': bubble_data['name'] if bubble_data else 'Unassigned',
                'type': bubble_data['bubble_type'] if bubble_data else 'GUEST',
                'policy': bubble_data['policy'] if bubble_data else {
                    'internet': True, 'lan': False, 'd2d': False, 'vlan': 150
                },
            },
            'sync_timestamp': _sync_timestamp.isoformat() if _sync_timestamp else None,
        })

    @app.route('/api/sync/bulk', methods=['POST'])
    def bulk_sync():
        """Bulk sync bubbles and devices from Fortress SDN.

        Request body:
        {
            "bubbles": [...],
            "devices": [{"mac": "...", "bubble_id": "..."}]
        }

        Used for initial sync or full refresh.
        """
        global _bubble_registry, _device_bubble_map, _sync_timestamp
        data = request.get_json() or {}

        bubbles_synced = 0
        devices_synced = 0

        # Sync bubbles
        for bubble in data.get('bubbles', []):
            bubble_id = bubble.get('bubble_id')
            if bubble_id:
                bubble['updated_at'] = datetime.now().isoformat()
                _bubble_registry[bubble_id] = bubble
                bubbles_synced += 1

                # Update device mappings from bubble
                for mac in bubble.get('devices', []):
                    _device_bubble_map[mac.upper()] = bubble_id
                    devices_synced += 1

        # Sync individual device mappings
        for device in data.get('devices', []):
            mac = device.get('mac', '').upper()
            bubble_id = device.get('bubble_id')
            if mac and bubble_id:
                _device_bubble_map[mac] = bubble_id
                devices_synced += 1

        _sync_timestamp = datetime.now()
        logger.info(f"Bulk sync: {bubbles_synced} bubbles, {devices_synced} devices")

        return jsonify({
            'status': 'synced',
            'bubbles_synced': bubbles_synced,
            'devices_synced': devices_synced,
            'timestamp': _sync_timestamp.isoformat(),
        })

    @app.route('/api/policies', methods=['GET'])
    def get_policies():
        """Get all NAC policies by bubble type.

        Used by Fortress SDN to understand policy matrix.
        """
        # Default policies by bubble type
        policies = {
            'FAMILY': {'internet': True, 'lan': True, 'd2d': True, 'vlan': 110},
            'WORK': {'internet': True, 'lan': False, 'd2d': True, 'vlan': 120},
            'IOT': {'internet': True, 'lan': False, 'd2d': True, 'vlan': 130},
            'GUEST': {'internet': True, 'lan': False, 'd2d': False, 'vlan': 150},
        }

        return jsonify({
            'policies': policies,
            'active_bubbles': len(_bubble_registry),
            'active_devices': len(_device_bubble_map),
        })

    return app
