"""
Cortex Module Views - Neural Command Center Integration

Provides:
- /cortex: Full-page Cortex visualization (iframe mode)
- /cortex/embedded: Embedded tab view for Guardian UI
- /api/cortex/node: Guardian node status for Cortex digital twin
- /api/cortex/location: Get Guardian's geographic location from WAN IP
- /api/cortex/events: Recent events for Cortex visualization
- /api/cortex/demo: Demo mode data for mesh visualization
"""
import os
import sys
import socket
import json
import random
from datetime import datetime, timedelta
from flask import render_template, jsonify, current_app, request
from . import cortex_bp
from utils import load_json_file, get_system_info, _safe_error

# Add shared directory to path for cortex imports
# Check multiple possible locations (installed vs development)
_possible_shared_paths = [
    # Installed location
    '/opt/hookprobe/shared',
    # Development location (relative to this file)
    os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', 'shared')),
    # Alternative dev location
    os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', '..', 'shared')),
]

_shared_path = None
for path in _possible_shared_paths:
    if os.path.isdir(path) and os.path.exists(os.path.join(path, 'cortex', 'backend', 'demo_data.py')):
        _shared_path = path
        break

if _shared_path:
    print(f"[Cortex] Shared path found: {_shared_path}")
    if _shared_path not in sys.path:
        sys.path.insert(0, _shared_path)
        print(f"[Cortex] Added to sys.path")
else:
    print(f"[Cortex] Shared path not found in: {_possible_shared_paths}")

# Import shared Cortex demo data generator
SHARED_DEMO_AVAILABLE = False
_demo_generator = None
HOOKPROBE_NODES = []

try:
    from cortex.backend.demo_data import DemoDataGenerator, HOOKPROBE_NODES, THREAT_SOURCES
    SHARED_DEMO_AVAILABLE = True
    _demo_generator = DemoDataGenerator()
    print(f"[Cortex] Shared demo data loaded: {len(HOOKPROBE_NODES)} nodes, {len(_demo_generator.organizations)} orgs")
except ImportError as e:
    print(f"[Cortex] Failed to load shared demo data: {e}")
    # Will use fallback local demo data

# Try to import requests for IP geolocation
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Default Cortex server URL (can be configured via environment)
CORTEX_SERVER_URL = os.environ.get('CORTEX_SERVER_URL', 'http://localhost:8765')

# Demo mode state (in-memory, resets on restart)
_demo_mode = True  # Default to demo mode for initial experience


# =============================================================================
# PAGE ROUTES
# =============================================================================

@cortex_bp.route('/cortex')
def cortex_view():
    """
    Full-page Cortex visualization (iframe mode).
    Embeds the Cortex 3D globe as an iframe or redirects to standalone.
    """
    cortex_url = request.args.get('url', CORTEX_SERVER_URL)
    mode = request.args.get('mode', 'demo')

    return render_template('cortex/index.html',
                           cortex_url=cortex_url,
                           mode=mode,
                           node_id=get_node_id())


@cortex_bp.route('/cortex/embedded')
def cortex_embedded():
    """
    Embedded Cortex view for Guardian tab integration.
    Returns the embedded globe template for the Cortex tab.
    """
    return render_template('cortex/embedded.html',
                           node_id=get_node_id(),
                           demo_mode=_demo_mode)


# =============================================================================
# API ROUTES
# =============================================================================

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

        # Get geographic coordinates (auto-detect or from config)
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
        return jsonify({'error': 'Internal server error'}), 500


@cortex_bp.route('/api/cortex/location')
def api_cortex_location():
    """
    Get Guardian's geographic location from WAN IP.

    Attempts to:
    1. Read from local configuration
    2. Detect from WAN IP using external geolocation service
    3. Return default/estimated location

    Returns:
        JSON with lat, lng, label, city, country, source
    """
    try:
        # First check for manual configuration
        config_location = get_configured_location()
        if config_location and config_location.get('lat') != 0:
            config_location['source'] = 'config'
            return jsonify(config_location)

        # Try to detect from WAN IP
        wan_location = detect_location_from_wan()
        if wan_location:
            # Cache the detected location
            cache_location(wan_location)
            return jsonify(wan_location)

        # Return default
        return jsonify({
            'lat': 0.0,
            'lng': 0.0,
            'label': get_node_id(),
            'city': 'Unknown',
            'country': 'Unknown',
            'source': 'default'
        })
    except Exception as e:
        current_app.logger.error(f"Location API error: {e}")
        return jsonify({'error': _safe_error(e)}), 500


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
        return jsonify({'error': _safe_error(e)}), 500


@cortex_bp.route('/api/cortex/demo', methods=['GET'])
def api_cortex_demo_status():
    """Get current demo mode status."""
    return jsonify({
        'demo_mode': _demo_mode,
        'node_id': get_node_id(),
        'shared_data_available': SHARED_DEMO_AVAILABLE,
        'demo_node_count': len(_demo_generator.nodes) if _demo_generator else 12,
        'demo_organizations': len(_demo_generator.organizations) if _demo_generator else 0
    })


@cortex_bp.route('/api/cortex/debug', methods=['GET'])
def api_cortex_debug():
    """Debug endpoint showing all Cortex configuration and state."""
    return jsonify({
        'shared_path': _shared_path,
        'shared_path_exists': os.path.isdir(_shared_path),
        'shared_demo_available': SHARED_DEMO_AVAILABLE,
        'demo_mode': _demo_mode,
        'demo_generator': _demo_generator is not None,
        'demo_node_count': len(_demo_generator.nodes) if _demo_generator else 0,
        'demo_org_count': len(_demo_generator.organizations) if _demo_generator else 0,
        'requests_available': REQUESTS_AVAILABLE,
        'cortex_server_url': CORTEX_SERVER_URL,
        'node_id': get_node_id(),
        'sample_nodes': _demo_generator.nodes[:3] if _demo_generator else []
    })


@cortex_bp.route('/api/cortex/demo/toggle', methods=['POST'])
def api_cortex_demo_toggle():
    """Toggle demo mode on/off."""
    global _demo_mode
    _demo_mode = not _demo_mode

    return jsonify({
        'demo_mode': _demo_mode,
        'message': f"Demo mode {'enabled' if _demo_mode else 'disabled'}"
    })


@cortex_bp.route('/api/cortex/demo/data')
def api_cortex_demo_data():
    """
    Get demo mesh data for visualization.

    In demo mode, returns simulated mesh with multiple nodes and events
    from the shared Cortex demo data generator (75+ enterprise nodes).
    In live mode, returns only this Guardian's data.
    """
    guardian_location = get_node_location()
    guardian_node = {
        'id': get_node_id(),
        'tier': 'guardian',
        'lat': guardian_location['lat'],
        'lng': guardian_location['lng'],
        'label': guardian_location['label'],
        'qsecbit': get_qsecbit_status()['score'],
        'status': get_qsecbit_status()['status'],
        'online': True
    }

    if not _demo_mode:
        # Live mode - only this Guardian
        return jsonify({
            'mode': 'live',
            'nodes': [guardian_node],
            'events': [],
            'stats': {
                'total_nodes': 1,
                'by_tier': {'guardian': 1, 'sentinel': 0, 'fortress': 0, 'nexus': 0}
            }
        })

    # Demo mode - use shared Cortex demo data generator if available
    if SHARED_DEMO_AVAILABLE and _demo_generator:
        # Get enterprise fleet data from shared generator (75+ nodes)
        fleet_data = _demo_generator.get_fleet_data()
        demo_nodes = [guardian_node]  # Always include real Guardian first

        # Add shared demo nodes (avoiding duplicates near Guardian location)
        for device in fleet_data.get('devices', []):
            # Skip nodes too close to real Guardian (within 5 degrees)
            if abs(device['lat'] - guardian_node['lat']) < 5 and \
               abs(device['lng'] - guardian_node['lng']) < 5:
                continue
            demo_nodes.append({
                'id': device['id'],
                'tier': device['tier'],
                'lat': device['lat'],
                'lng': device['lng'],
                'label': device['label'],
                'qsecbit': device.get('qsecbit', 0.2),
                'status': device.get('status', 'green'),
                'online': device.get('online', True),
                'customer_id': device.get('customer_id', ''),
                'department': device.get('department', '')
            })

        # Generate events using shared generator
        demo_events = []
        for _ in range(random.randint(3, 8)):
            event = _demo_generator.generate_event()
            if event['type'] in ['attack_detected', 'attack_repelled']:
                demo_events.append({
                    'id': event.get('id', f"evt-{random.randint(1000, 9999)}"),
                    'type': event['type'],
                    'source': event.get('source', {}),
                    'target': event.get('target', {}),
                    'timestamp': event.get('timestamp'),
                    'severity': event.get('severity', 'medium'),
                    'attack_type': event.get('attack_type', 'unknown'),
                    'category': event.get('category', 'unknown')
                })

        stats = fleet_data.get('stats', {})
        return jsonify({
            'mode': 'demo',
            'nodes': demo_nodes,
            'events': demo_events,
            'stats': {
                'total_nodes': len(demo_nodes),
                'by_tier': stats.get('by_tier', count_by_tier(demo_nodes)),
                'by_status': stats.get('by_status', {}),
                'organizations': len(_demo_generator.organizations) if _demo_generator else 0
            }
        })

    # Fallback to local demo data if shared not available
    demo_nodes = generate_demo_nodes(guardian_node)
    demo_events = generate_demo_events(demo_nodes)

    return jsonify({
        'mode': 'demo',
        'nodes': demo_nodes,
        'events': demo_events,
        'stats': {
            'total_nodes': len(demo_nodes),
            'by_tier': count_by_tier(demo_nodes)
        }
    })


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
        return jsonify({'error': _safe_error(e)}), 500


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_node_id():
    """Generate unique node ID for this Guardian."""
    hostname = socket.gethostname()
    return f"guardian-{hostname}"


def get_node_location():
    """
    Get geographic location for this node.
    Reads from configuration or detects from WAN IP.
    """
    # Try configured location first
    config_location = get_configured_location()
    if config_location and config_location.get('lat') != 0:
        return config_location

    # Try cached detected location
    cached = get_cached_location()
    if cached:
        return cached

    # Try to detect (but don't block on it)
    detected = detect_location_from_wan()
    if detected:
        cache_location(detected)
        return detected

    # Default
    return {
        'lat': 0.0,
        'lng': 0.0,
        'label': socket.gethostname()
    }


def get_configured_location():
    """Read manually configured location."""
    config_path = '/opt/hookprobe/guardian/config/location.json'
    default = {'lat': 0.0, 'lng': 0.0, 'label': socket.gethostname()}

    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
    except Exception:
        pass

    # Try environment variables
    env_lat = os.environ.get('HOOKPROBE_LAT')
    env_lng = os.environ.get('HOOKPROBE_LNG')
    if env_lat and env_lng:
        return {
            'lat': float(env_lat),
            'lng': float(env_lng),
            'label': os.environ.get('HOOKPROBE_LABEL', default['label'])
        }

    return default


def get_cached_location():
    """Read cached detected location."""
    cache_path = '/tmp/guardian_location_cache.json'
    try:
        if os.path.exists(cache_path):
            with open(cache_path, 'r') as f:
                data = json.load(f)
                # Check if cache is less than 24 hours old
                cached_time = datetime.fromisoformat(data.get('timestamp', '2000-01-01'))
                if datetime.utcnow() - cached_time < timedelta(hours=24):
                    return data
    except Exception:
        pass
    return None


def cache_location(location):
    """Cache detected location."""
    cache_path = '/tmp/guardian_location_cache.json'
    try:
        location['timestamp'] = datetime.utcnow().isoformat()
        with open(cache_path, 'w') as f:
            json.dump(location, f)
    except Exception:
        pass


def detect_location_from_wan():
    """
    Detect geographic location from WAN IP address.

    Uses free IP geolocation services (no API key required).
    """
    if not REQUESTS_AVAILABLE:
        return None

    try:
        # Get public IP
        ip_response = requests.get('https://api.ipify.org?format=json', timeout=5)
        if ip_response.status_code != 200:
            return None

        public_ip = ip_response.json().get('ip')
        if not public_ip:
            return None

        # Get geolocation for IP (using ip-api.com - free, no key required)
        geo_response = requests.get(
            f'http://ip-api.com/json/{public_ip}?fields=status,country,city,lat,lon',
            timeout=5
        )
        if geo_response.status_code != 200:
            return None

        geo_data = geo_response.json()
        if geo_data.get('status') != 'success':
            return None

        return {
            'lat': geo_data.get('lat', 0.0),
            'lng': geo_data.get('lon', 0.0),
            'label': f"{geo_data.get('city', 'Unknown')} Guardian",
            'city': geo_data.get('city', 'Unknown'),
            'country': geo_data.get('country', 'Unknown'),
            'source': 'wan_ip'
        }
    except Exception as e:
        current_app.logger.debug(f"WAN location detection failed: {e}")
        return None


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


# =============================================================================
# DEMO DATA GENERATION
# =============================================================================

# Demo node locations (major cities worldwide)
DEMO_LOCATIONS = [
    {'lat': 40.7128, 'lng': -74.0060, 'city': 'New York', 'country': 'USA'},
    {'lat': 51.5074, 'lng': -0.1278, 'city': 'London', 'country': 'UK'},
    {'lat': 35.6762, 'lng': 139.6503, 'city': 'Tokyo', 'country': 'Japan'},
    {'lat': 48.8566, 'lng': 2.3522, 'city': 'Paris', 'country': 'France'},
    {'lat': -33.8688, 'lng': 151.2093, 'city': 'Sydney', 'country': 'Australia'},
    {'lat': 52.5200, 'lng': 13.4050, 'city': 'Berlin', 'country': 'Germany'},
    {'lat': 37.5665, 'lng': 126.9780, 'city': 'Seoul', 'country': 'S. Korea'},
    {'lat': 55.7558, 'lng': 37.6173, 'city': 'Moscow', 'country': 'Russia'},
    {'lat': -23.5505, 'lng': -46.6333, 'city': 'Sao Paulo', 'country': 'Brazil'},
    {'lat': 19.4326, 'lng': -99.1332, 'city': 'Mexico City', 'country': 'Mexico'},
    {'lat': 1.3521, 'lng': 103.8198, 'city': 'Singapore', 'country': 'Singapore'},
    {'lat': 22.3193, 'lng': 114.1694, 'city': 'Hong Kong', 'country': 'China'},
]

# Attack source locations (for demo attacks)
DEMO_ATTACK_SOURCES = [
    {'lat': 39.9042, 'lng': 116.4074, 'label': 'Beijing Botnet'},
    {'lat': 55.7558, 'lng': 37.6173, 'label': 'Moscow Scanner'},
    {'lat': 9.0820, 'lng': 8.6753, 'label': 'Nigeria Phish'},
    {'lat': 51.1657, 'lng': 10.4515, 'label': 'DE Scan Cluster'},
    {'lat': 35.8617, 'lng': 104.1954, 'label': 'CN DDoS Origin'},
]


def generate_demo_nodes(guardian_node):
    """Generate demo mesh nodes including the real Guardian."""
    nodes = [guardian_node]  # Always include the real Guardian

    # Add demo nodes
    tiers = ['sentinel', 'guardian', 'fortress', 'nexus']
    tier_weights = [0.4, 0.3, 0.2, 0.1]  # More sentinels, fewer nexuses

    for loc in DEMO_LOCATIONS:
        # Don't add node too close to real Guardian
        if abs(loc['lat'] - guardian_node['lat']) < 5 and abs(loc['lng'] - guardian_node['lng']) < 5:
            continue

        tier = random.choices(tiers, weights=tier_weights)[0]
        status = random.choices(['green', 'amber', 'red'], weights=[0.7, 0.2, 0.1])[0]
        qsecbit = random.uniform(0.1, 0.4) if status == 'green' else \
                  random.uniform(0.45, 0.65) if status == 'amber' else \
                  random.uniform(0.7, 0.9)

        nodes.append({
            'id': f"demo-{tier}-{loc['city'].lower().replace(' ', '-')}",
            'tier': tier,
            'lat': loc['lat'] + random.uniform(-0.5, 0.5),
            'lng': loc['lng'] + random.uniform(-0.5, 0.5),
            'label': f"{loc['city']} {tier.capitalize()}",
            'qsecbit': round(qsecbit, 3),
            'status': status,
            'online': random.random() > 0.05  # 95% online
        })

    return nodes


def generate_demo_events(nodes):
    """Generate demo attack/repelled events."""
    events = []
    now = datetime.utcnow()

    # Generate a few recent events
    num_events = random.randint(3, 8)
    for i in range(num_events):
        source = random.choice(DEMO_ATTACK_SOURCES)
        target = random.choice([n for n in nodes if n.get('online', True)])
        is_repelled = random.random() > 0.3  # 70% repelled

        events.append({
            'id': f"demo-event-{i}",
            'type': 'attack_repelled' if is_repelled else 'attack_detected',
            'source': {
                'lat': source['lat'],
                'lng': source['lng'],
                'label': source['label']
            },
            'target': {
                'node_id': target['id'],
                'lat': target['lat'],
                'lng': target['lng'],
                'label': target['label']
            },
            'timestamp': (now - timedelta(seconds=random.randint(1, 60))).isoformat() + 'Z',
            'severity': random.choice(['low', 'medium', 'high']),
            'attack_type': random.choice(['ddos', 'scan', 'bruteforce', 'malware', 'phishing'])
        })

    return events


def count_by_tier(nodes):
    """Count nodes by tier."""
    counts = {'sentinel': 0, 'guardian': 0, 'fortress': 0, 'nexus': 0}
    for node in nodes:
        tier = node.get('tier', 'sentinel').lower()
        if tier in counts:
            counts[tier] += 1
    return counts
