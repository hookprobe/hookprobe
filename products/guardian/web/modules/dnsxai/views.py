"""
dnsXai Module Views - AI-powered DNS Protection
"""
import os
import json
import time
from flask import jsonify, request, current_app
from . import dnsxai_bp
from utils import load_json_file, save_json_file, load_text_file, save_text_file, run_command


def get_dnsxai_config():
    """Load dnsXai configuration."""
    config_file = current_app.config.get('DNSXAI_CONFIG', '/opt/hookprobe/guardian/dnsxai/config.json')
    return load_json_file(config_file, {
        'enabled': True,
        'level': 3,
        'ml_enabled': True,
        'cname_uncloaking': True,
        'federated_learning': False,
        'confidence_threshold': 0.7,
        'blocklist_sources': []
    })


def save_dnsxai_config(config):
    """Save dnsXai configuration."""
    config_file = current_app.config.get('DNSXAI_CONFIG', '/opt/hookprobe/guardian/dnsxai/config.json')
    return save_json_file(config_file, config)


@dnsxai_bp.route('/api/stats')
def api_stats():
    """Get dnsXai statistics."""
    stats_file = current_app.config.get('DNSXAI_STATS', '/opt/hookprobe/guardian/dnsxai/stats.json')
    stats = load_json_file(stats_file, {
        'total_queries': 0,
        'blocked': 0,
        'allowed': 0,
        'block_rate': 0.0,
        'blocklist_domains': 0,
        'ml_blocks': 0,
        'cname_uncloaked': 0
    })

    # Calculate block rate
    if stats['total_queries'] > 0:
        stats['block_rate'] = (stats['blocked'] / stats['total_queries']) * 100

    # Get current level
    config = get_dnsxai_config()
    stats['level'] = config.get('level', 3)

    return jsonify(stats)


@dnsxai_bp.route('/api/level', methods=['POST'])
def api_set_level():
    """Set protection level."""
    data = request.get_json()
    level = data.get('level', 3)

    if not isinstance(level, int) or level < 0 or level > 5:
        return jsonify({'success': False, 'error': 'Invalid level (0-5)'}), 400

    config = get_dnsxai_config()
    config['level'] = level
    config['enabled'] = level > 0

    if save_dnsxai_config(config):
        # Apply changes
        run_command('sudo systemctl restart dnsxai 2>/dev/null || true')
        return jsonify({'success': True, 'level': level})
    return jsonify({'success': False, 'error': 'Failed to save config'}), 500


@dnsxai_bp.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def api_whitelist():
    """Manage whitelisted domains."""
    whitelist_file = current_app.config.get('DNSXAI_WHITELIST', '/opt/hookprobe/guardian/dnsxai/whitelist.txt')

    if request.method == 'GET':
        whitelist = load_text_file(whitelist_file, [])
        return jsonify({'whitelist': whitelist})

    data = request.get_json()
    domain = data.get('domain', '').strip().lower()

    if not domain:
        return jsonify({'success': False, 'error': 'Domain required'}), 400

    whitelist = load_text_file(whitelist_file, [])

    if request.method == 'POST':
        if domain not in whitelist:
            whitelist.append(domain)
            if save_text_file(whitelist_file, whitelist):
                run_command('sudo systemctl restart dnsmasq')
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Domain already whitelisted'}), 400

    if request.method == 'DELETE':
        if domain in whitelist:
            whitelist.remove(domain)
            if save_text_file(whitelist_file, whitelist):
                run_command('sudo systemctl restart dnsmasq')
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Domain not found'}), 404

    return jsonify({'success': False, 'error': 'Invalid method'}), 405


@dnsxai_bp.route('/api/sources', methods=['GET', 'POST', 'DELETE'])
def api_sources():
    """Manage blocklist sources."""
    config = get_dnsxai_config()

    if request.method == 'GET':
        return jsonify({'sources': config.get('blocklist_sources', [])})

    data = request.get_json()

    if request.method == 'POST':
        url = data.get('url', '').strip()
        name = data.get('name', '').strip() or 'Custom Source'

        if not url:
            return jsonify({'success': False, 'error': 'URL required'}), 400

        sources = config.get('blocklist_sources', [])
        if any(s['url'] == url for s in sources):
            return jsonify({'success': False, 'error': 'Source already exists'}), 400

        sources.append({'name': name, 'url': url})
        config['blocklist_sources'] = sources

        if save_dnsxai_config(config):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Failed to save config'}), 500

    if request.method == 'DELETE':
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'URL required'}), 400

        sources = config.get('blocklist_sources', [])
        sources = [s for s in sources if s['url'] != url]
        config['blocklist_sources'] = sources

        if save_dnsxai_config(config):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Failed to save config'}), 500


@dnsxai_bp.route('/api/pause', methods=['GET', 'POST'])
def api_pause():
    """Pause/resume dnsXai protection."""
    pause_file = current_app.config.get('DNSXAI_PAUSE', '/opt/hookprobe/guardian/dnsxai/pause_state.json')

    def get_state():
        return load_json_file(pause_file, {'status': 'active', 'pause_until': 0})

    def save_state(state):
        return save_json_file(pause_file, state)

    def apply_state(enabled):
        if enabled:
            run_command('sudo systemctl start dnsxai 2>/dev/null || true')
            run_command('sudo systemctl restart dnsmasq')
        else:
            run_command('sudo systemctl stop dnsxai 2>/dev/null || true')
            run_command('sudo systemctl restart dnsmasq')

    if request.method == 'GET':
        state = get_state()
        now = time.time()

        if state['status'] == 'paused':
            remaining = state.get('pause_until', 0) - now
            if remaining <= 0:
                state = {'status': 'active', 'pause_until': 0}
                save_state(state)
                apply_state(True)
                return jsonify({'status': 'active', 'remaining_seconds': 0})
            return jsonify({'status': 'paused', 'remaining_seconds': int(remaining)})
        elif state['status'] == 'disabled':
            return jsonify({'status': 'disabled', 'remaining_seconds': 0})
        return jsonify({'status': 'active', 'remaining_seconds': 0})

    # POST
    data = request.get_json()
    action = data.get('action', '')
    now = time.time()

    if action == 'pause':
        minutes = data.get('minutes', 5)
        if not isinstance(minutes, int) or minutes < 1 or minutes > 1440:
            return jsonify({'success': False, 'error': 'Invalid minutes'}), 400

        state = {'status': 'paused', 'pause_until': now + (minutes * 60)}
        save_state(state)
        apply_state(False)
        return jsonify({'success': True, 'status': 'paused', 'minutes': minutes})

    elif action == 'resume':
        state = {'status': 'active', 'pause_until': 0}
        save_state(state)
        apply_state(True)
        return jsonify({'success': True, 'status': 'active'})

    elif action == 'disable':
        state = {'status': 'disabled', 'pause_until': 0}
        save_state(state)
        apply_state(False)
        return jsonify({'success': True, 'status': 'disabled'})

    elif action == 'enable':
        state = {'status': 'active', 'pause_until': 0}
        save_state(state)
        apply_state(True)
        return jsonify({'success': True, 'status': 'active'})

    return jsonify({'success': False, 'error': 'Invalid action'}), 400


@dnsxai_bp.route('/api/update', methods=['POST'])
def api_update():
    """Trigger blocklist update."""
    try:
        output, success = run_command('/opt/hookprobe/shared/dnsXai/update-blocklist.sh --force', timeout=120)
        if success:
            return jsonify({'success': True, 'message': 'Blocklists updated'})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
