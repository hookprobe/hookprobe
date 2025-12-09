"""
Cortex Module Views - Neural Command Center Integration

Provides:
- /cortex: Full-page Cortex visualization iframe
- /api/cortex/node: Guardian node status for Cortex digital twin
- /api/cortex/events: Recent events for Cortex visualization
"""
import os
import socket
import json
from datetime import datetime
from flask import render_template, jsonify, current_app, request
from . import cortex_bp
from utils import load_json_file, get_system_info


# Default Cortex server URL (can be configured via environment)
CORTEX_SERVER_URL = os.environ.get('CORTEX_SERVER_URL', 'http://localhost:8765')


@cortex_bp.route('/cortex')
def cortex_view():
    """
    Full-page Cortex visualization.
    Embeds the Cortex 3D globe as an iframe or redirects to standalone.
    """
    cortex_url = request.args.get('url', CORTEX_SERVER_URL)
    mode = request.args.get('mode', 'demo')  # demo or live

    return render_template('cortex/index.html',
                           cortex_url=cortex_url,
                           mode=mode,
                           node_id=get_node_id())


@cortex_bp.route('/api/cortex/node')
def api_cortex_node():
    """
    Get Guardian node status for Cortex digital twin.

    This endpoint is called by the Cortex GuardianConnector to:
    - Register this Guardian as a node on the globe
    - Get real-time Qsecbit status and health
    - Report events to the mesh visualization

    Response format matches Cortex NodeTwin requirements.
    """
    try:
        system = get_system_info()
        threat_data = get_threat_summary()
        qsecbit = get_qsecbit_status()

        # Get geographic coordinates (would be configured or detected)
        geo = get_node_location()

        return jsonify({
            'node_id': get_node_id(),
            'tier': 'guardian',
            'lat': geo['lat'],
            'lng': geo['lng'],
            'label': geo['label'],

            # Qsecbit status
            'qsecbit_score': qsecbit['score'],
            'qsecbit_status': qsecbit['status'],  # green, amber, red

            # Health metrics
            'online': True,
            'last_heartbeat': datetime.utcnow().isoformat() + 'Z',
            'uptime': system.get('uptime', 'unknown'),
            'load': system.get('load', [0, 0, 0]),
            'memory_percent': system.get('memory', {}).get('percent', 0),

            # Threat summary
            'threats': {
                'total': threat_data.get('total', 0),
                'blocked': threat_data.get('blocked', 0),
                'active': threat_data.get('high', 0) + threat_data.get('medium', 0)
            },

            # Mesh connectivity
            'mesh': {
                'connected': True,
                'peers': 0,  # TODO: Get from mesh module
                'mode': 'guardian'
            }
        })
    except Exception as e:
        current_app.logger.error(f"Cortex node API error: {e}")
        return jsonify({'error': str(e)}), 500


@cortex_bp.route('/api/cortex/events')
def api_cortex_events():
    """
    Get recent security events for Cortex visualization.

    Returns events in Cortex-compatible format for attack arcs and effects.
    """
    try:
        # Get recent events from threat log
        events = get_recent_events(limit=50)

        return jsonify({
            'node_id': get_node_id(),
            'events': events,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    except Exception as e:
        current_app.logger.error(f"Cortex events API error: {e}")
        return jsonify({'error': str(e)}), 500


@cortex_bp.route('/api/cortex/heartbeat', methods=['POST'])
def api_cortex_heartbeat():
    """
    Receive heartbeat from Cortex server.
    Used for bidirectional health checks and event streaming.
    """
    try:
        data = request.get_json() or {}
        cortex_id = data.get('cortex_id', 'unknown')

        return jsonify({
            'node_id': get_node_id(),
            'ack': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'cortex_id': cortex_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_node_id():
    """Generate unique node ID for this Guardian."""
    hostname = socket.gethostname()
    return f"guardian-{hostname}"


def get_node_location():
    """
    Get geographic location for this node.
    Reads from configuration or uses default.
    """
    config_path = '/opt/hookprobe/guardian/config/location.json'
    default = {'lat': 0.0, 'lng': 0.0, 'label': socket.gethostname()}

    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
    except Exception:
        pass

    # Try to get from environment
    return {
        'lat': float(os.environ.get('HOOKPROBE_LAT', 0.0)),
        'lng': float(os.environ.get('HOOKPROBE_LNG', 0.0)),
        'label': os.environ.get('HOOKPROBE_LABEL', default['label'])
    }


def get_qsecbit_status():
    """Get current Qsecbit score and status."""
    qsecbit_file = current_app.config.get(
        'QSECBIT_FILE',
        '/var/log/hookprobe/qsecbit/current.json'
    )

    try:
        if os.path.exists(qsecbit_file):
            with open(qsecbit_file, 'r') as f:
                data = json.load(f)
                score = data.get('score', 0.0)
                if score < 0.45:
                    status = 'green'
                elif score < 0.70:
                    status = 'amber'
                else:
                    status = 'red'
                return {'score': score, 'status': status}
    except Exception:
        pass

    return {'score': 0.0, 'status': 'green'}


def get_threat_summary():
    """Get summary of current threats."""
    threat_file = current_app.config.get(
        'THREAT_FILE',
        '/var/log/hookprobe/threats/aggregated.json'
    )

    data = load_json_file(threat_file, {
        'stats': {
            'total': 0,
            'blocked': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    })

    return data.get('stats', {})


def get_recent_events(limit=50):
    """
    Get recent security events in Cortex format.

    Event types:
    - attack_detected: Incoming attack
    - attack_repelled: Attack blocked
    - qsecbit_threshold: Status change
    """
    events = []
    event_log = '/var/log/hookprobe/events/recent.json'

    try:
        if os.path.exists(event_log):
            with open(event_log, 'r') as f:
                raw_events = json.load(f)
                for event in raw_events[-limit:]:
                    events.append({
                        'type': event.get('type', 'unknown'),
                        'source': event.get('source', {}),
                        'target': {
                            'node_id': get_node_id(),
                            **get_node_location()
                        },
                        'timestamp': event.get('timestamp'),
                        'severity': event.get('severity', 'low'),
                        'details': event.get('details', {})
                    })
    except Exception:
        pass

    return events
