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

    # =========================================================================
    # PURPLE TEAM FEEDBACK ENDPOINTS
    # Receive feedback from SDN Autopilot and Nexus Purple Team for learning
    # =========================================================================

    # In-memory storage for feedback data (in production: ClickHouse)
    _sdn_decisions = []  # SDN enforcement decisions
    _trust_adjustments = []  # Trust score adjustments
    _defense_outcomes = []  # Real defense outcomes
    _vulnerabilities = []  # Reported vulnerabilities
    _optimizations_applied = []  # Applied optimizations
    _bubble_violations = []  # Policy violations

    @app.route('/api/device/<mac>/feedback', methods=['POST'])
    def receive_sdn_feedback(mac):
        """Receive SDN Autopilot enforcement decision feedback.

        This enables AIOCHI to learn from actual SDN enforcement outcomes.
        Called by Fortress SDN Autopilot after enforcement actions.

        Request body:
        {
            "decision": "ALLOW|BLOCK|QUARANTINE|RATE_LIMIT",
            "reason": "Why this decision was made",
            "details": {
                "attack_type": "optional attack type",
                "rule_id": "OVS flow rule ID",
                "confidence": 0.85
            }
        }
        """
        mac = mac.upper().replace('-', ':')
        data = request.get_json() or {}

        decision = data.get('decision')
        if not decision:
            return jsonify({'error': 'decision required'}), 400

        feedback = {
            'mac': mac,
            'decision': decision,
            'reason': data.get('reason', ''),
            'details': data.get('details', {}),
            'timestamp': datetime.now().isoformat(),
            'bubble_id': _device_bubble_map.get(mac),
        }

        _sdn_decisions.append(feedback)
        logger.info(f"SDN feedback: {mac} - {decision} ({data.get('reason', 'no reason')})")

        # Update device trust based on decision outcome
        engine = get_engine()
        identity = engine.get_identity(mac)
        if identity:
            # Positive decisions can increase trust over time
            if decision in ('ALLOW',) and identity.trust_level.value < 3:
                # Gradual trust increase (in production: use RL engine)
                logger.debug(f"Device {mac} building trust through positive decisions")

        return jsonify({
            'status': 'received',
            'mac': mac,
            'decision': decision,
            'feedback_id': len(_sdn_decisions),
        })

    @app.route('/api/device/<mac>/trust-adjust', methods=['POST'])
    def receive_trust_adjustment(mac):
        """Receive trust score adjustment from SDN Autopilot.

        Called when SDN Autopilot detects attacks or positive behavior
        that should adjust device trust.

        Request body:
        {
            "adjustment": 0.15,  # -1.0 to 1.0
            "reason": "Blocked port scan attempt",
            "attack_type": "PORT_SCAN",
            "evidence": {...}
        }
        """
        mac = mac.upper().replace('-', ':')
        data = request.get_json() or {}

        adjustment = data.get('adjustment', 0.0)
        if not isinstance(adjustment, (int, float)):
            return jsonify({'error': 'adjustment must be a number'}), 400

        # Clamp adjustment to valid range
        adjustment = max(-1.0, min(1.0, adjustment))

        record = {
            'mac': mac,
            'adjustment': adjustment,
            'reason': data.get('reason', ''),
            'attack_type': data.get('attack_type'),
            'evidence': data.get('evidence', {}),
            'timestamp': datetime.now().isoformat(),
            'bubble_id': _device_bubble_map.get(mac),
        }

        _trust_adjustments.append(record)
        logger.info(f"Trust adjustment: {mac} += {adjustment} ({data.get('reason', 'no reason')})")

        # Apply adjustment to device trust
        engine = get_engine()
        identity = engine.get_identity(mac)
        new_trust_level = None

        if identity:
            current = identity.trust_level.value
            # Map adjustment to trust level change
            if adjustment < -0.5:
                # Severe negative - drop trust significantly
                new_level = max(0, current - 2)
            elif adjustment < -0.2:
                # Moderate negative - drop trust one level
                new_level = max(0, current - 1)
            elif adjustment > 0.5:
                # Strong positive - increase trust
                new_level = min(4, current + 1)
            else:
                new_level = current

            if new_level != current:
                # Note: In production, this would update the identity engine's internal state
                new_trust_level = new_level
                logger.info(f"Device {mac} trust level: {current} -> {new_level}")

        return jsonify({
            'status': 'received',
            'mac': mac,
            'adjustment': adjustment,
            'previous_trust': identity.trust_level.value if identity else 0,
            'new_trust': new_trust_level,
        })

    @app.route('/api/defense-outcome', methods=['POST'])
    def receive_defense_outcome():
        """Receive actual defense outcome from SDN Autopilot.

        Enables comparison of simulated vs real attack outcomes
        for Purple Team meta-learning.

        Request body:
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "attack_type": "TER_REPLAY",
            "detected": true,
            "blocked": true,
            "detection_time_ms": 45,
            "mitigation_method": "OVS_FLOW_BLOCK",
            "confidence": 0.92,
            "false_positive": false,
            "evidence": {...}
        }
        """
        data = request.get_json() or {}

        required = ['mac', 'attack_type', 'detected', 'blocked']
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({'error': f'Missing required fields: {missing}'}), 400

        mac = data['mac'].upper().replace('-', ':')

        outcome = {
            'mac': mac,
            'attack_type': data['attack_type'],
            'detected': data['detected'],
            'blocked': data['blocked'],
            'detection_time_ms': data.get('detection_time_ms', 0),
            'mitigation_method': data.get('mitigation_method', 'UNKNOWN'),
            'confidence': data.get('confidence', 0.0),
            'false_positive': data.get('false_positive', False),
            'evidence': data.get('evidence', {}),
            'timestamp': datetime.now().isoformat(),
            'bubble_id': _device_bubble_map.get(mac),
        }

        _defense_outcomes.append(outcome)
        logger.info(f"Defense outcome: {mac} - {data['attack_type']} - "
                    f"detected={data['detected']}, blocked={data['blocked']}")

        # Calculate outcome score for meta-learning
        outcome_score = 0
        if outcome['detected'] and outcome['blocked']:
            outcome_score = 100  # Perfect defense
        elif outcome['detected'] and not outcome['blocked']:
            outcome_score = 50  # Detected but not blocked
        elif not outcome['detected'] and not outcome['blocked']:
            outcome_score = 0  # Missed attack
        elif not outcome['detected'] and outcome['blocked']:
            outcome_score = 75  # Blocked by other means (e.g., baseline rules)

        # Penalize false positives
        if outcome['false_positive']:
            outcome_score = max(0, outcome_score - 25)

        return jsonify({
            'status': 'received',
            'outcome_id': len(_defense_outcomes),
            'outcome_score': outcome_score,
            'message': 'Defense outcome recorded for meta-learning',
        })

    @app.route('/api/vulnerability', methods=['POST'])
    def receive_vulnerability():
        """Receive vulnerability report from Nexus Purple Team.

        Called when Purple Team discovers a vulnerability during simulation.

        Request body:
        {
            "simulation_id": "sim-uuid",
            "attack_class": "TERReplayBubbleAttack",
            "affected_bubble": "family-dad",
            "affected_devices": ["AA:BB:CC:DD:EE:FF"],
            "severity": "HIGH",
            "mitre_attack_id": "T1557",
            "description": "TER replay attack bypassed bubble boundary",
            "recommended_fix": "Increase TER replay window strictness",
            "evidence": {...}
        }
        """
        data = request.get_json() or {}

        required = ['attack_class', 'affected_bubble', 'severity']
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({'error': f'Missing required fields: {missing}'}), 400

        valid_severities = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        if data['severity'] not in valid_severities:
            return jsonify({'error': f'severity must be one of {valid_severities}'}), 400

        vuln = {
            'simulation_id': data.get('simulation_id', 'manual'),
            'attack_class': data['attack_class'],
            'affected_bubble': data['affected_bubble'],
            'affected_devices': data.get('affected_devices', []),
            'severity': data['severity'],
            'mitre_attack_id': data.get('mitre_attack_id', ''),
            'description': data.get('description', ''),
            'recommended_fix': data.get('recommended_fix', ''),
            'evidence': data.get('evidence', {}),
            'timestamp': datetime.now().isoformat(),
            'status': 'NEW',
        }

        _vulnerabilities.append(vuln)
        logger.warning(f"Vulnerability reported: {data['attack_class']} - "
                       f"{data['severity']} - bubble: {data['affected_bubble']}")

        # For CRITICAL vulnerabilities, trigger immediate alert
        if vuln['severity'] == 'CRITICAL':
            logger.critical(f"CRITICAL vulnerability discovered: {vuln['description']}")
            # In production: trigger n8n webhook for immediate notification

        return jsonify({
            'status': 'received',
            'vulnerability_id': len(_vulnerabilities),
            'severity': vuln['severity'],
            'message': f"Vulnerability {vuln['attack_class']} recorded",
        })

    @app.route('/api/optimization-applied', methods=['POST'])
    def receive_optimization_applied():
        """Receive notification that optimization was applied by SDN Autopilot.

        Tracks which Nexus recommendations were actually applied.

        Request body:
        {
            "simulation_id": "sim-uuid",
            "optimization_id": "opt-uuid",
            "parameter": "temporal_sync_weight",
            "old_value": 0.5,
            "new_value": 0.7,
            "applied_by": "sdn_autopilot",
            "result": "SUCCESS"
        }
        """
        data = request.get_json() or {}

        required = ['parameter', 'old_value', 'new_value']
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({'error': f'Missing required fields: {missing}'}), 400

        optimization = {
            'simulation_id': data.get('simulation_id', 'manual'),
            'optimization_id': data.get('optimization_id', f'opt-{len(_optimizations_applied) + 1}'),
            'parameter': data['parameter'],
            'old_value': data['old_value'],
            'new_value': data['new_value'],
            'applied_by': data.get('applied_by', 'unknown'),
            'result': data.get('result', 'UNKNOWN'),
            'timestamp': datetime.now().isoformat(),
        }

        _optimizations_applied.append(optimization)
        logger.info(f"Optimization applied: {data['parameter']} = {data['new_value']} "
                    f"(was {data['old_value']})")

        return jsonify({
            'status': 'received',
            'optimization_id': optimization['optimization_id'],
            'message': f"Optimization for {data['parameter']} recorded",
        })

    @app.route('/api/bubble-violation', methods=['POST'])
    def receive_bubble_violation():
        """Receive bubble policy violation report.

        Called when SDN Autopilot detects a device violating its bubble policy.

        Request body:
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "violation_type": "UNAUTHORIZED_D2D|CROSS_BUBBLE|VLAN_ESCAPE|INTERNET_BLOCKED",
            "bubble_id": "family-dad",
            "target_mac": "BB:CC:DD:EE:FF:00",
            "target_bubble_id": "guest-visitors",
            "details": {...}
        }
        """
        data = request.get_json() or {}

        required = ['mac', 'violation_type', 'bubble_id']
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({'error': f'Missing required fields: {missing}'}), 400

        valid_violations = ('UNAUTHORIZED_D2D', 'CROSS_BUBBLE', 'VLAN_ESCAPE', 'INTERNET_BLOCKED')
        if data['violation_type'] not in valid_violations:
            return jsonify({'error': f'violation_type must be one of {valid_violations}'}), 400

        mac = data['mac'].upper().replace('-', ':')

        violation = {
            'mac': mac,
            'violation_type': data['violation_type'],
            'bubble_id': data['bubble_id'],
            'target_mac': data.get('target_mac', '').upper().replace('-', ':') if data.get('target_mac') else None,
            'target_bubble_id': data.get('target_bubble_id'),
            'details': data.get('details', {}),
            'timestamp': datetime.now().isoformat(),
            'action_taken': 'LOGGED',  # In production: BLOCKED, QUARANTINED, etc.
        }

        _bubble_violations.append(violation)
        logger.warning(f"Bubble violation: {mac} - {data['violation_type']} in bubble {data['bubble_id']}")

        # Cross-bubble violations are more severe
        if violation['violation_type'] == 'CROSS_BUBBLE':
            logger.warning(f"Cross-bubble communication attempt: {mac} -> {violation['target_mac']}")

        return jsonify({
            'status': 'received',
            'violation_id': len(_bubble_violations),
            'violation_type': violation['violation_type'],
            'action_taken': violation['action_taken'],
        })

    # =========================================================================
    # PURPLE TEAM QUERY ENDPOINTS
    # Allow Nexus to query feedback data for meta-learning
    # =========================================================================

    @app.route('/api/defense-outcomes', methods=['GET'])
    def list_defense_outcomes():
        """List defense outcomes for meta-learning analysis.

        Query params:
            - attack_type: Filter by attack type
            - since: ISO timestamp, return outcomes after this time
            - limit: Max results (default 100)
        """
        attack_type = request.args.get('attack_type')
        since = request.args.get('since')
        limit = int(request.args.get('limit', 100))

        results = _defense_outcomes.copy()

        if attack_type:
            results = [r for r in results if r['attack_type'] == attack_type]

        if since:
            results = [r for r in results if r['timestamp'] >= since]

        results = results[-limit:]

        return jsonify({
            'outcomes': results,
            'total': len(results),
        })

    @app.route('/api/vulnerabilities', methods=['GET'])
    def list_vulnerabilities():
        """List discovered vulnerabilities.

        Query params:
            - severity: Filter by severity
            - status: Filter by status (NEW, ACKNOWLEDGED, FIXED)
            - limit: Max results (default 50)
        """
        severity = request.args.get('severity')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 50))

        results = _vulnerabilities.copy()

        if severity:
            results = [r for r in results if r['severity'] == severity]

        if status:
            results = [r for r in results if r['status'] == status]

        results = results[-limit:]

        return jsonify({
            'vulnerabilities': results,
            'total': len(results),
            'by_severity': {
                'CRITICAL': sum(1 for v in _vulnerabilities if v['severity'] == 'CRITICAL'),
                'HIGH': sum(1 for v in _vulnerabilities if v['severity'] == 'HIGH'),
                'MEDIUM': sum(1 for v in _vulnerabilities if v['severity'] == 'MEDIUM'),
                'LOW': sum(1 for v in _vulnerabilities if v['severity'] == 'LOW'),
            },
        })

    @app.route('/api/feedback-stats', methods=['GET'])
    def get_feedback_stats():
        """Get statistics on feedback data for monitoring.

        Returns counts and recent activity summary.
        """
        return jsonify({
            'sdn_decisions': {
                'total': len(_sdn_decisions),
                'recent_24h': sum(1 for d in _sdn_decisions
                                  if datetime.fromisoformat(d['timestamp']) > datetime.now().replace(hour=0, minute=0)),
            },
            'trust_adjustments': {
                'total': len(_trust_adjustments),
                'positive': sum(1 for t in _trust_adjustments if t['adjustment'] > 0),
                'negative': sum(1 for t in _trust_adjustments if t['adjustment'] < 0),
            },
            'defense_outcomes': {
                'total': len(_defense_outcomes),
                'detected': sum(1 for o in _defense_outcomes if o['detected']),
                'blocked': sum(1 for o in _defense_outcomes if o['blocked']),
                'false_positives': sum(1 for o in _defense_outcomes if o['false_positive']),
            },
            'vulnerabilities': {
                'total': len(_vulnerabilities),
                'open': sum(1 for v in _vulnerabilities if v['status'] == 'NEW'),
                'critical': sum(1 for v in _vulnerabilities if v['severity'] == 'CRITICAL'),
            },
            'optimizations_applied': {
                'total': len(_optimizations_applied),
                'successful': sum(1 for o in _optimizations_applied if o['result'] == 'SUCCESS'),
            },
            'bubble_violations': {
                'total': len(_bubble_violations),
                'cross_bubble': sum(1 for v in _bubble_violations if v['violation_type'] == 'CROSS_BUBBLE'),
            },
        })

    return app
