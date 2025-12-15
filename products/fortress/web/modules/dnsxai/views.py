"""
Fortress dnsXai Views - DNS Protection with Privacy Controls

Features:
- Protection level slider (0-5)
- Kill switch / pause protection
- Privacy settings (enable/disable tracking)
- ML/LSTM threat detection status
- Per-VLAN DNS policies
- Whitelist/blocklist management
"""
import os
import json
import time
import logging
from pathlib import Path
from flask import render_template, jsonify, request
from flask_login import login_required
from . import dnsxai_bp

# Configuration paths
PRIVACY_CONFIG = Path('/etc/hookprobe/dnsxai/privacy.json')
DNS_SHIELD_DIR = Path('/opt/hookprobe/fortress/dns-shield')
DNS_SHIELD_CONFIG = DNS_SHIELD_DIR / 'shield.conf'
DNS_SHIELD_WHITELIST = DNS_SHIELD_DIR / 'whitelist.txt'
DNS_SHIELD_BLOCKLIST = DNS_SHIELD_DIR / 'blocked-hosts'
DNS_SHIELD_SOURCES = DNS_SHIELD_DIR / 'sources.json'
DNS_SHIELD_PAUSE = DNS_SHIELD_DIR / 'pause_state.json'
DNSMASQ_QUERY_LOG = Path('/var/log/hookprobe/dnsmasq-queries.log')
DNSMASQ_SHIELD_CONF = Path('/etc/dnsmasq.d/fortress-shield.conf')
ML_STATS_FILE = Path('/opt/hookprobe/fortress/data/threat-intel/aggregated.json')


def load_json_file(path: Path, default=None):
    """Load JSON file with fallback."""
    try:
        if path.exists():
            with open(path, 'r') as f:
                return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to load {path}: {e}")
    return default if default is not None else {}


def save_json_file(path: Path, data: dict) -> bool:
    """Save JSON file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Failed to save {path}: {e}")
        return False


def load_text_file(path: Path, default=None):
    """Load text file as list of lines."""
    try:
        if path.exists():
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
    except Exception:
        pass
    return default if default is not None else []


def save_text_file(path: Path, lines: list) -> bool:
    """Save text file from list."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        return True
    except Exception:
        return False


@dnsxai_bp.route('/')
@login_required
def index():
    """dnsXai main page."""
    return render_template('dnsxai/index.html')


# =============================================================================
# PRIVACY SETTINGS API
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
# PROTECTION STATUS API
# =============================================================================

@dnsxai_bp.route('/api/stats')
@login_required
def api_stats():
    """Get dnsXai statistics."""
    stats = {
        'total_queries': 0,
        'blocked': 0,
        'allowed': 0,
        'block_rate': 0.0,
        'blocklist_domains': 0,
        'level': 3,
        'status': 'active',
        'ml_available': False,
        'ml_threats': 0
    }

    # Get query stats from dnsmasq log
    try:
        if DNSMASQ_QUERY_LOG.exists():
            file_size = DNSMASQ_QUERY_LOG.stat().st_size
            read_size = min(file_size, 1024 * 1024)

            with open(DNSMASQ_QUERY_LOG, 'r') as f:
                if file_size > read_size:
                    f.seek(file_size - read_size)
                    f.readline()

                for line in f:
                    if ' query[' in line:
                        stats['total_queries'] += 1
                    if ' is 0.0.0.0' in line or '/0.0.0.0' in line:
                        stats['blocked'] += 1

        stats['allowed'] = max(0, stats['total_queries'] - stats['blocked'])
        if stats['total_queries'] > 0:
            stats['block_rate'] = (stats['blocked'] / stats['total_queries']) * 100
    except Exception as e:
        logging.warning(f"Failed to read query log: {e}")

    # Get blocklist count
    try:
        if DNS_SHIELD_BLOCKLIST.exists():
            with open(DNS_SHIELD_BLOCKLIST, 'r') as f:
                stats['blocklist_domains'] = sum(1 for line in f if line.strip() and not line.startswith('#'))
    except Exception:
        pass

    # Get protection level
    try:
        if DNS_SHIELD_CONFIG.exists():
            with open(DNS_SHIELD_CONFIG, 'r') as f:
                for line in f:
                    if line.strip().startswith('SHIELD_LEVEL='):
                        stats['level'] = int(line.strip().split('=')[1])
                        break
    except Exception:
        pass

    # Get pause state
    pause_state = load_json_file(DNS_SHIELD_PAUSE, {'status': 'active'})
    stats['status'] = pause_state.get('status', 'active')

    # Check if protection is active
    if not DNSMASQ_SHIELD_CONF.exists():
        stats['status'] = 'disabled'

    # Get ML stats
    ml_stats = load_json_file(ML_STATS_FILE, {})
    if ml_stats:
        stats['ml_available'] = True
        stats['ml_threats'] = ml_stats.get('stats', {}).get('attack_sequences', 0)

    return jsonify(stats)


@dnsxai_bp.route('/api/level', methods=['POST'])
@login_required
def api_set_level():
    """Set protection level."""
    data = request.get_json()
    level = data.get('level', 3)

    if not isinstance(level, int) or level < 0 or level > 5:
        return jsonify({'success': False, 'error': 'Invalid level (0-5)'}), 400

    try:
        DNS_SHIELD_DIR.mkdir(parents=True, exist_ok=True)
        config_content = f"SHIELD_LEVEL={level}\n"
        with open(DNS_SHIELD_CONFIG, 'w') as f:
            f.write(config_content)
        return jsonify({'success': True, 'level': level})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/api/pause', methods=['GET', 'POST'])
@login_required
def api_pause():
    """Pause/resume protection."""
    disabled_conf = DNSMASQ_SHIELD_CONF.with_suffix('.conf.disabled')

    if request.method == 'GET':
        state = load_json_file(DNS_SHIELD_PAUSE, {'status': 'active', 'pause_until': 0})
        now = time.time()

        if state['status'] == 'paused':
            remaining = state.get('pause_until', 0) - now
            if remaining <= 0:
                state = {'status': 'active', 'pause_until': 0}
                save_json_file(DNS_SHIELD_PAUSE, state)
                return jsonify({'status': 'active', 'remaining_seconds': 0})
            return jsonify({'status': 'paused', 'remaining_seconds': int(remaining)})
        elif state['status'] == 'disabled' or not DNSMASQ_SHIELD_CONF.exists():
            return jsonify({'status': 'disabled', 'remaining_seconds': 0})
        return jsonify({'status': 'active', 'remaining_seconds': 0})

    data = request.get_json()
    action = data.get('action', '')
    now = time.time()

    if action == 'pause':
        minutes = data.get('minutes', 5)
        state = {'status': 'paused', 'pause_until': now + (minutes * 60)}
        save_json_file(DNS_SHIELD_PAUSE, state)
        return jsonify({'success': True, 'status': 'paused', 'minutes': minutes})

    elif action == 'resume':
        state = {'status': 'active', 'pause_until': 0}
        save_json_file(DNS_SHIELD_PAUSE, state)
        return jsonify({'success': True, 'status': 'active'})

    elif action == 'disable':
        state = {'status': 'disabled', 'pause_until': 0}
        save_json_file(DNS_SHIELD_PAUSE, state)
        return jsonify({'success': True, 'status': 'disabled'})

    elif action == 'enable':
        state = {'status': 'active', 'pause_until': 0}
        save_json_file(DNS_SHIELD_PAUSE, state)
        return jsonify({'success': True, 'status': 'active'})

    return jsonify({'success': False, 'error': 'Invalid action'}), 400


# =============================================================================
# WHITELIST API
# =============================================================================

@dnsxai_bp.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
@login_required
def api_whitelist():
    """Manage whitelisted domains."""
    if request.method == 'GET':
        whitelist = load_text_file(DNS_SHIELD_WHITELIST, [])
        whitelist = [d for d in whitelist if not d.startswith('#')]
        return jsonify({'whitelist': whitelist})

    data = request.get_json()
    domain = data.get('domain', '').strip().lower()

    if not domain:
        return jsonify({'success': False, 'error': 'Domain required'}), 400

    whitelist = load_text_file(DNS_SHIELD_WHITELIST, [])
    working = [d.lower() for d in whitelist if not d.startswith('#')]

    if request.method == 'POST':
        if domain not in working:
            whitelist.append(domain)
            if save_text_file(DNS_SHIELD_WHITELIST, whitelist):
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Already whitelisted'}), 400

    if request.method == 'DELETE':
        if domain in working:
            whitelist = [d for d in whitelist if d.lower() != domain]
            if save_text_file(DNS_SHIELD_WHITELIST, whitelist):
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Not found'}), 404

    return jsonify({'success': False}), 405


# =============================================================================
# BLOCKLIST SOURCES API
# =============================================================================

@dnsxai_bp.route('/api/sources', methods=['GET', 'POST', 'DELETE'])
@login_required
def api_sources():
    """Manage blocklist sources."""
    default_sources = [
        {
            'name': 'StevenBlack Unified Hosts',
            'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
            'builtin': True,
            'enabled': True
        }
    ]

    sources = load_json_file(DNS_SHIELD_SOURCES, {'sources': default_sources})

    if request.method == 'GET':
        return jsonify({'sources': sources.get('sources', default_sources)})

    data = request.get_json()

    if request.method == 'POST':
        url = data.get('url', '').strip()
        name = data.get('name', 'Custom Source').strip()

        if not url:
            return jsonify({'success': False, 'error': 'URL required'}), 400

        source_list = sources.get('sources', default_sources.copy())
        if any(s['url'] == url for s in source_list):
            return jsonify({'success': False, 'error': 'Source exists'}), 400

        source_list.append({'name': name, 'url': url, 'builtin': False, 'enabled': True})
        sources['sources'] = source_list

        if save_json_file(DNS_SHIELD_SOURCES, sources):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Failed to save'}), 500

    if request.method == 'DELETE':
        url = data.get('url', '').strip()
        source_list = sources.get('sources', [])
        source_list = [s for s in source_list if s['url'] != url or s.get('builtin', False)]
        sources['sources'] = source_list

        if save_json_file(DNS_SHIELD_SOURCES, sources):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Failed to save'}), 500


# =============================================================================
# ML/LSTM STATUS API
# =============================================================================

@dnsxai_bp.route('/api/ml/status')
@login_required
def api_ml_status():
    """Get ML/LSTM threat detection status."""
    ml_stats = load_json_file(ML_STATS_FILE, {})

    result = {
        'available': bool(ml_stats),
        'timestamp': ml_stats.get('timestamp', ''),
        'stats': ml_stats.get('stats', {}),
        'pattern_distribution': ml_stats.get('pattern_distribution', {}),
        'training_ready': ml_stats.get('training_ready', False)
    }

    # Check LSTM model status
    model_path = Path('/opt/hookprobe/fortress/data/ml-models/trained/threat_lstm.pt')
    result['lstm_model_exists'] = model_path.exists()

    # Get training history
    history_path = Path('/opt/hookprobe/fortress/data/ml-models/trained/training_history.json')
    if history_path.exists():
        history = load_json_file(history_path, [])
        if history:
            result['last_training'] = history[-1] if isinstance(history, list) else history

    return jsonify(result)


@dnsxai_bp.route('/api/ml/train', methods=['POST'])
@login_required
def api_ml_train():
    """Trigger ML/LSTM training."""
    import subprocess

    try:
        # Run LSTM training script
        result = subprocess.run(
            ['python3', '/opt/hookprobe/fortress/lib/lstm_threat_detector.py', '--train', '--epochs', '50'],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0:
            return jsonify({'success': True, 'output': result.stdout})
        else:
            return jsonify({'success': False, 'error': result.stderr}), 500

    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Training timeout'}), 500
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'LSTM trainer not found'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# BLOCKED DOMAINS API
# =============================================================================

@dnsxai_bp.route('/api/blocked')
@login_required
def api_blocked_domains():
    """Get recently blocked domains."""
    from collections import OrderedDict

    limit = request.args.get('limit', 50, type=int)
    blocked_domains = OrderedDict()
    total_blocks = 0

    try:
        if not DNSMASQ_QUERY_LOG.exists():
            return jsonify({'success': True, 'domains': [], 'total_blocks': 0})

        file_size = DNSMASQ_QUERY_LOG.stat().st_size
        read_size = min(file_size, 2 * 1024 * 1024)

        with open(DNSMASQ_QUERY_LOG, 'r') as f:
            if file_size > read_size:
                f.seek(file_size - read_size)
                f.readline()

            for line in f:
                if ' is 0.0.0.0' in line or '/0.0.0.0' in line:
                    domain = None

                    if ' config ' in line:
                        parts = line.split(' config ')[1].split(' is ')[0]
                        domain = parts.strip()
                    elif '/0.0.0.0 ' in line:
                        parts = line.split('/0.0.0.0 ')[1].split(' is ')[0]
                        domain = parts.strip()
                    elif ' reply ' in line:
                        parts = line.split(' reply ')[1].split(' is ')[0]
                        domain = parts.strip()

                    if domain:
                        total_blocks += 1
                        if domain in blocked_domains:
                            blocked_domains[domain]['block_count'] += 1
                        else:
                            blocked_domains[domain] = {
                                'domain': domain,
                                'block_count': 1,
                                'time': int(time.time())
                            }

        domains_list = list(blocked_domains.values())
        domains_list.sort(key=lambda x: x.get('block_count', 1), reverse=True)

        return jsonify({
            'success': True,
            'domains': domains_list[:limit],
            'total_blocks': total_blocks
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'domains': []}), 500
