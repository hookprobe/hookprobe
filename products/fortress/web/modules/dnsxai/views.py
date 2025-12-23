"""
Fortress dnsXai Views - DNS Protection with Privacy Controls

Communicates with the dnsXai container API for real-time statistics
and control. Privacy settings are stored locally for web container access.

Features:
- Protection level slider (0-5)
- Kill switch / pause protection
- Privacy settings (enable/disable tracking)
- ML/LSTM threat detection status
- Whitelist/blocklist management
"""
import os
import json
import time
import logging
import requests
from pathlib import Path
from flask import render_template, jsonify, request, current_app
from flask_login import login_required
from . import dnsxai_bp

logger = logging.getLogger(__name__)

# Configuration paths (local to web container)
CONFIG_DIR = Path('/etc/hookprobe')
PRIVACY_CONFIG = CONFIG_DIR / 'dnsxai' / 'privacy.json'

# dnsXai API endpoint (container network)
DNSXAI_API_URL = os.environ.get('DNSXAI_API_URL', 'http://fts-dnsxai:8080')
API_TIMEOUT = 5  # seconds


def _api_call(method: str, endpoint: str, data: dict = None, timeout: int = API_TIMEOUT):
    """Make API call to dnsXai container."""
    url = f"{DNSXAI_API_URL}{endpoint}"
    try:
        if method.upper() == 'GET':
            resp = requests.get(url, timeout=timeout)
        elif method.upper() == 'POST':
            resp = requests.post(url, json=data, timeout=timeout)
        elif method.upper() == 'DELETE':
            resp = requests.delete(url, json=data, timeout=timeout)
        else:
            return None, f"Unknown method: {method}"

        if resp.status_code == 200:
            return resp.json(), None
        else:
            return None, f"API error: {resp.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "dnsXai service unavailable"
    except requests.exceptions.Timeout:
        return None, "dnsXai service timeout"
    except Exception as e:
        logger.warning(f"API call failed: {e}")
        return None, str(e)


def load_json_file(path: Path, default=None):
    """Load JSON file with fallback."""
    try:
        if path.exists():
            with open(path, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load {path}: {e}")
    return default if default is not None else {}


def save_json_file(path: Path, data: dict) -> bool:
    """Save JSON file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save {path}: {e}")
        return False


@dnsxai_bp.route('/')
@login_required
def index():
    """dnsXai main page."""
    return render_template('dnsxai/index.html')


# =============================================================================
# PRIVACY SETTINGS API (stored locally)
# =============================================================================

@dnsxai_bp.route('/api/privacy', methods=['GET'])
@login_required
def api_get_privacy():
    """Get privacy settings."""
    config = load_json_file(PRIVACY_CONFIG, {
        'settings': {
            'enable_query_logging': False,
            'enable_domain_tracking': False,
            'enable_ad_blocking_stats': True,
            'enable_threat_detection': True,
            'enable_ml_training_data': False,
            'anonymize_client_ips': True,
            'retention_days': 7,
            'export_allowed': False
        }
    })
    return jsonify({
        'success': True,
        **config
    })


@dnsxai_bp.route('/api/privacy', methods=['POST'])
@login_required
def api_set_privacy():
    """Update privacy settings."""
    data = request.get_json()
    setting = data.get('setting')
    value = data.get('value')

    if not setting:
        return jsonify({'success': False, 'error': 'Setting name required'}), 400

    config = load_json_file(PRIVACY_CONFIG, {'settings': {}})
    if 'settings' not in config:
        config['settings'] = {}

    config['settings'][setting] = value

    if save_json_file(PRIVACY_CONFIG, config):
        return jsonify({'success': True, 'setting': setting, 'value': value})
    return jsonify({'success': False, 'error': 'Failed to save'}), 500


@dnsxai_bp.route('/api/privacy/preset', methods=['POST'])
@login_required
def api_privacy_preset():
    """Apply privacy preset."""
    data = request.get_json()
    preset = data.get('preset', 'balanced')

    presets = {
        'maximum': {
            'enable_query_logging': False,
            'enable_domain_tracking': False,
            'enable_ad_blocking_stats': False,
            'enable_threat_detection': True,
            'enable_ml_training_data': False,
            'anonymize_client_ips': True,
            'retention_days': 1,
            'export_allowed': False
        },
        'balanced': {
            'enable_query_logging': False,
            'enable_domain_tracking': False,
            'enable_ad_blocking_stats': True,
            'enable_threat_detection': True,
            'enable_ml_training_data': False,
            'anonymize_client_ips': True,
            'retention_days': 7,
            'export_allowed': False
        },
        'full': {
            'enable_query_logging': True,
            'enable_domain_tracking': True,
            'enable_ad_blocking_stats': True,
            'enable_threat_detection': True,
            'enable_ml_training_data': True,
            'anonymize_client_ips': True,
            'retention_days': 30,
            'export_allowed': False
        }
    }

    if preset not in presets:
        return jsonify({'success': False, 'error': 'Invalid preset'}), 400

    config = load_json_file(PRIVACY_CONFIG, {})
    config['settings'] = presets[preset]

    if save_json_file(PRIVACY_CONFIG, config):
        return jsonify({'success': True, 'preset': preset})
    return jsonify({'success': False, 'error': 'Failed to save'}), 500


# =============================================================================
# PROTECTION STATUS API (from dnsXai container)
# =============================================================================

@dnsxai_bp.route('/api/stats')
@login_required
def api_stats():
    """Get dnsXai statistics from container."""
    # Call dnsXai API
    data, error = _api_call('GET', '/api/stats')

    if error:
        # Return default stats with error indicator
        return jsonify({
            'total_queries': 0,
            'blocked': 0,
            'allowed': 0,
            'block_rate': 0.0,
            'blocklist_domains': 0,
            'level': 3,
            'status': 'offline',
            'ml_available': False,
            'ml_threats': 0,
            'error': error
        })

    # Map API response to expected format
    return jsonify({
        'total_queries': data.get('total_queries', 0),
        'blocked': data.get('blocked_queries', 0),
        'allowed': data.get('allowed_queries', 0),
        'block_rate': data.get('block_rate', 0.0),
        'blocklist_domains': data.get('blocklist_domains', 0),
        'level': data.get('protection_level', 3),
        'status': 'active' if data.get('protection_enabled', True) else 'paused',
        'paused': data.get('paused', False),
        'pause_until': data.get('pause_until'),
        'ml_available': data.get('ml_classifications', 0) > 0,
        'ml_threats': data.get('ml_blocks', 0),
        'cache_hits': data.get('cache_hits', 0),
        'cache_misses': data.get('cache_misses', 0),
        'uptime_start': data.get('uptime_start'),
        'last_updated': data.get('last_updated')
    })


@dnsxai_bp.route('/api/level', methods=['POST'])
@login_required
def api_set_level():
    """Set protection level."""
    data = request.get_json()
    level = data.get('level', 3)

    if not isinstance(level, int) or level < 0 or level > 5:
        return jsonify({'success': False, 'error': 'Invalid level (0-5)'}), 400

    result, error = _api_call('POST', '/api/level', {'level': level})

    if error:
        return jsonify({'success': False, 'error': error}), 503

    return jsonify({'success': True, 'level': level})


@dnsxai_bp.route('/api/pause', methods=['GET', 'POST'])
@login_required
def api_pause():
    """Pause/resume protection."""
    if request.method == 'GET':
        data, error = _api_call('GET', '/api/stats')
        if error:
            return jsonify({'status': 'unknown', 'error': error})

        return jsonify({
            'status': 'paused' if data.get('paused') else 'active',
            'pause_until': data.get('pause_until'),
            'remaining_seconds': 0  # Calculated on frontend
        })

    # POST - toggle pause
    data = request.get_json() or {}
    action = data.get('action', 'toggle')
    minutes = data.get('minutes', 0)

    if action == 'pause':
        result, error = _api_call('POST', '/api/pause', {'minutes': minutes})
    elif action == 'resume':
        result, error = _api_call('POST', '/api/resume', {})
    else:
        # Toggle
        stats, _ = _api_call('GET', '/api/stats')
        if stats and stats.get('paused'):
            result, error = _api_call('POST', '/api/resume', {})
        else:
            result, error = _api_call('POST', '/api/pause', {'minutes': minutes})

    if error:
        return jsonify({'success': False, 'error': error}), 503

    return jsonify({'success': True, **result})


@dnsxai_bp.route('/api/kill', methods=['POST'])
@login_required
def api_kill_switch():
    """Kill switch - disable protection immediately."""
    data = request.get_json() or {}
    action = data.get('action', 'toggle')

    # Kill = pause indefinitely (0 minutes)
    if action == 'kill':
        result, error = _api_call('POST', '/api/pause', {'minutes': 0})
    else:
        result, error = _api_call('POST', '/api/resume', {})

    if error:
        return jsonify({'success': False, 'error': error}), 503

    return jsonify({'success': True, **result})


# =============================================================================
# WHITELIST API (from dnsXai container)
# =============================================================================

@dnsxai_bp.route('/api/whitelist', methods=['GET'])
@login_required
def api_get_whitelist():
    """Get whitelist entries."""
    data, error = _api_call('GET', '/api/whitelist')

    if error:
        return jsonify({'whitelist': [], 'error': error})

    return jsonify({
        'whitelist': data.get('whitelist', []),
        'count': data.get('count', 0)
    })


@dnsxai_bp.route('/api/whitelist', methods=['POST'])
@login_required
def api_add_whitelist():
    """Add domain to whitelist."""
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()

    if not domain:
        return jsonify({'success': False, 'error': 'Domain required'}), 400

    result, error = _api_call('POST', '/api/whitelist', {'domain': domain})

    if error:
        return jsonify({'success': False, 'error': error}), 503

    return jsonify(result)


@dnsxai_bp.route('/api/whitelist', methods=['DELETE'])
@login_required
def api_remove_whitelist():
    """Remove domain from whitelist."""
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()

    if not domain:
        return jsonify({'success': False, 'error': 'Domain required'}), 400

    result, error = _api_call('DELETE', '/api/whitelist', {'domain': domain})

    if error:
        return jsonify({'success': False, 'error': error}), 503

    return jsonify(result)


# =============================================================================
# BLOCKLIST SOURCES API (stored locally for now)
# =============================================================================

@dnsxai_bp.route('/api/sources', methods=['GET'])
@login_required
def api_get_sources():
    """Get blocklist sources."""
    sources_file = CONFIG_DIR / 'dnsxai' / 'sources.json'
    sources = load_json_file(sources_file, {
        'sources': [
            {
                'id': 'stevenblack',
                'name': 'Steven Black Unified',
                'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                'enabled': True,
                'category': 'ads_malware'
            },
            {
                'id': 'adaway',
                'name': 'AdAway Default',
                'url': 'https://adaway.org/hosts.txt',
                'enabled': True,
                'category': 'ads'
            },
            {
                'id': 'malwaredomains',
                'name': 'Malware Domains',
                'url': 'https://mirror1.malwaredomains.com/files/justdomains',
                'enabled': True,
                'category': 'malware'
            }
        ]
    })
    return jsonify(sources)


@dnsxai_bp.route('/api/sources', methods=['POST'])
@login_required
def api_add_source():
    """Add blocklist source."""
    data = request.get_json()
    url = data.get('url', '').strip()
    name = data.get('name', url)
    category = data.get('category', 'custom')

    if not url:
        return jsonify({'success': False, 'error': 'URL required'}), 400

    sources_file = CONFIG_DIR / 'dnsxai' / 'sources.json'
    sources = load_json_file(sources_file, {'sources': []})

    # Generate ID from name
    source_id = name.lower().replace(' ', '_')[:20]

    new_source = {
        'id': source_id,
        'name': name,
        'url': url,
        'enabled': True,
        'category': category
    }

    sources['sources'].append(new_source)

    if save_json_file(sources_file, sources):
        return jsonify({'success': True, 'source': new_source})
    return jsonify({'success': False, 'error': 'Failed to save'}), 500


@dnsxai_bp.route('/api/sources', methods=['DELETE'])
@login_required
def api_remove_source():
    """Remove blocklist source."""
    data = request.get_json()
    source_id = data.get('id', '').strip()

    if not source_id:
        return jsonify({'success': False, 'error': 'Source ID required'}), 400

    sources_file = CONFIG_DIR / 'dnsxai' / 'sources.json'
    sources = load_json_file(sources_file, {'sources': []})

    sources['sources'] = [s for s in sources['sources'] if s.get('id') != source_id]

    if save_json_file(sources_file, sources):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Failed to save'}), 500


# =============================================================================
# ML/LSTM API (from dnsXai container)
# =============================================================================

@dnsxai_bp.route('/api/ml/status')
@login_required
def api_ml_status():
    """Get ML training status."""
    data, error = _api_call('GET', '/api/ml/status')

    if error:
        return jsonify({
            'model_trained': False,
            'training_samples': 0,
            'training_in_progress': False,
            'ready_for_training': False,
            'error': error
        })

    return jsonify(data)


@dnsxai_bp.route('/api/ml/train', methods=['POST'])
@login_required
def api_ml_train():
    """Trigger ML training."""
    result, error = _api_call('POST', '/api/ml/train', {}, timeout=10)

    if error:
        return jsonify({'success': False, 'error': error}), 503

    return jsonify(result)


# =============================================================================
# BLOCKED DOMAINS API (from dnsXai container)
# =============================================================================

@dnsxai_bp.route('/api/blocked')
@login_required
def api_blocked():
    """Get recently blocked domains."""
    limit = request.args.get('limit', 100, type=int)

    data, error = _api_call('GET', f'/api/blocked?limit={limit}')

    if error:
        return jsonify({'blocked': [], 'error': error})

    return jsonify({
        'blocked': data.get('blocked', []),
        'count': data.get('count', 0)
    })


# =============================================================================
# HEALTH CHECK
# =============================================================================

@dnsxai_bp.route('/api/health')
@login_required
def api_health():
    """Check dnsXai service health."""
    data, error = _api_call('GET', '/health', timeout=2)

    if error:
        return jsonify({
            'healthy': False,
            'service': 'dnsxai',
            'error': error
        }), 503

    return jsonify({
        'healthy': True,
        'service': 'dnsxai',
        **data
    })
