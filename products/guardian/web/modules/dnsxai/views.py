"""
dnsXai Module Views - AI-powered DNS Protection
Integrates with Guardian DNS Shield (dnsmasq blocklist)
"""
import os
import re
import time
from flask import jsonify, request
from . import dnsxai_bp
from utils import load_json_file, save_json_file, load_text_file, save_text_file, run_command


# DNS Shield paths (actual system paths)
DNS_SHIELD_DIR = '/opt/hookprobe/guardian/dns-shield'
DNS_SHIELD_CONFIG = f'{DNS_SHIELD_DIR}/shield.conf'
DNS_SHIELD_STATS = f'{DNS_SHIELD_DIR}/stats.json'
DNS_SHIELD_WHITELIST = f'{DNS_SHIELD_DIR}/whitelist.txt'
DNS_SHIELD_BLOCKLIST = f'{DNS_SHIELD_DIR}/blocked-hosts'
DNS_SHIELD_SOURCES = f'{DNS_SHIELD_DIR}/sources.json'
DNS_SHIELD_PAUSE = f'{DNS_SHIELD_DIR}/pause_state.json'
DNSMASQ_QUERY_LOG = '/var/log/hookprobe/dnsmasq-queries.log'
DNSMASQ_SHIELD_CONF = '/etc/dnsmasq.d/dns-shield.conf'


def get_shield_level():
    """Read shield level from config file."""
    try:
        if os.path.exists(DNS_SHIELD_CONFIG):
            with open(DNS_SHIELD_CONFIG, 'r') as f:
                for line in f:
                    if line.strip().startswith('SHIELD_LEVEL='):
                        return int(line.strip().split('=')[1])
    except Exception:
        pass
    return 3  # Default


def set_shield_level(level):
    """Update shield level in config file."""
    try:
        if not os.path.exists(DNS_SHIELD_CONFIG):
            return False

        with open(DNS_SHIELD_CONFIG, 'r') as f:
            content = f.read()

        # Replace the SHIELD_LEVEL line
        new_content = re.sub(r'SHIELD_LEVEL=\d+', f'SHIELD_LEVEL={level}', content)

        with open(DNS_SHIELD_CONFIG, 'w') as f:
            f.write(new_content)
        return True
    except Exception:
        return False


def get_blocklist_count():
    """Count domains in the blocklist file."""
    try:
        if os.path.exists(DNS_SHIELD_BLOCKLIST):
            with open(DNS_SHIELD_BLOCKLIST, 'r') as f:
                count = sum(1 for line in f if line.strip() and not line.startswith('#'))
                return count
    except Exception:
        pass
    return 0


def get_dns_stats():
    """Parse dnsmasq query log for real-time statistics."""
    stats = {
        'total_queries': 0,
        'blocked': 0,
        'allowed': 0,
        'block_rate': 0.0
    }

    try:
        if not os.path.exists(DNSMASQ_QUERY_LOG):
            return stats

        # Get file size and only read last 1MB for performance
        file_size = os.path.getsize(DNSMASQ_QUERY_LOG)
        read_size = min(file_size, 1024 * 1024)  # 1MB max

        with open(DNSMASQ_QUERY_LOG, 'r') as f:
            if file_size > read_size:
                f.seek(file_size - read_size)
                f.readline()  # Skip partial line

            for line in f:
                if ' query[' in line:
                    stats['total_queries'] += 1
                # Blocked queries return 0.0.0.0
                if ' is 0.0.0.0' in line or '/0.0.0.0' in line:
                    stats['blocked'] += 1

        stats['allowed'] = max(0, stats['total_queries'] - stats['blocked'])

        if stats['total_queries'] > 0:
            stats['block_rate'] = (stats['blocked'] / stats['total_queries']) * 100
    except Exception:
        pass

    return stats


def is_protection_active():
    """Check if DNS Shield protection is currently active."""
    # Check if dnsmasq shield config exists (not disabled)
    return os.path.exists(DNSMASQ_SHIELD_CONF)


@dnsxai_bp.route('/stats')
def api_stats():
    """Get dnsXai statistics from DNS Shield."""
    # Get real-time stats from dnsmasq log
    stats = get_dns_stats()

    # Get blocklist size
    stats['blocklist_domains'] = get_blocklist_count()

    # Get current level
    stats['level'] = get_shield_level()

    # Load persisted stats for ML and CNAME (future features)
    persisted = load_json_file(DNS_SHIELD_STATS, {})
    stats['ml_blocks'] = persisted.get('ml_blocks', 0)
    stats['cname_uncloaked'] = persisted.get('cname_uncloaked', 0)

    # Get pause state to determine if active
    pause_state = load_json_file(DNS_SHIELD_PAUSE, {'status': 'active', 'pause_until': 0})

    # Check actual state
    if not is_protection_active():
        if pause_state.get('status') != 'disabled':
            stats['status'] = 'disabled'
        else:
            stats['status'] = pause_state.get('status', 'disabled')
    else:
        stats['status'] = pause_state.get('status', 'active')

    return jsonify(stats)


@dnsxai_bp.route('/level', methods=['POST'])
def api_set_level():
    """Set protection level."""
    data = request.get_json()
    level = data.get('level', 3)

    if not isinstance(level, int) or level < 0 or level > 5:
        return jsonify({'success': False, 'error': 'Invalid level (0-5)'}), 400

    if set_shield_level(level):
        # Trigger blocklist update with new level in background
        run_command('/opt/hookprobe/guardian/scripts/update-blocklists.sh --silent &')
        return jsonify({'success': True, 'level': level})

    return jsonify({'success': False, 'error': 'Failed to save config'}), 500


@dnsxai_bp.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def api_whitelist():
    """Manage whitelisted domains."""
    if request.method == 'GET':
        whitelist = load_text_file(DNS_SHIELD_WHITELIST, [])
        # Filter out comments and empty lines
        whitelist = [d for d in whitelist if d.strip() and not d.startswith('#')]
        return jsonify({'whitelist': whitelist})

    data = request.get_json()
    domain = data.get('domain', '').strip().lower()

    if not domain:
        return jsonify({'success': False, 'error': 'Domain required'}), 400

    whitelist = load_text_file(DNS_SHIELD_WHITELIST, [])
    # Keep all lines, filter for working comparison
    working = [d.strip().lower() for d in whitelist if d.strip() and not d.startswith('#')]

    if request.method == 'POST':
        if domain not in working:
            whitelist.append(domain)
            if save_text_file(DNS_SHIELD_WHITELIST, whitelist):
                # Restart dnsmasq to apply whitelist
                run_command('sudo systemctl restart dnsmasq')
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Domain already whitelisted'}), 400

    if request.method == 'DELETE':
        if domain in working:
            whitelist = [d for d in whitelist if d.strip().lower() != domain]
            if save_text_file(DNS_SHIELD_WHITELIST, whitelist):
                run_command('sudo systemctl restart dnsmasq')
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Domain not found'}), 404

    return jsonify({'success': False, 'error': 'Invalid method'}), 405


@dnsxai_bp.route('/sources', methods=['GET', 'POST', 'DELETE'])
def api_sources():
    """Manage blocklist sources."""
    # Default source
    default_sources = [
        {
            'name': 'StevenBlack Unified Hosts',
            'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
            'builtin': True
        }
    ]

    sources = load_json_file(DNS_SHIELD_SOURCES, {'sources': default_sources})

    if request.method == 'GET':
        return jsonify({'sources': sources.get('sources', default_sources)})

    data = request.get_json()

    if request.method == 'POST':
        url = data.get('url', '').strip()
        name = data.get('name', '').strip() or 'Custom Source'

        if not url:
            return jsonify({'success': False, 'error': 'URL required'}), 400

        source_list = sources.get('sources', default_sources.copy())
        if any(s['url'] == url for s in source_list):
            return jsonify({'success': False, 'error': 'Source already exists'}), 400

        source_list.append({'name': name, 'url': url, 'builtin': False})
        sources['sources'] = source_list

        if save_json_file(DNS_SHIELD_SOURCES, sources):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Failed to save config'}), 500

    if request.method == 'DELETE':
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'URL required'}), 400

        source_list = sources.get('sources', [])
        # Don't allow deleting builtin sources
        source_list = [s for s in source_list if s['url'] != url or s.get('builtin', False)]
        sources['sources'] = source_list

        if save_json_file(DNS_SHIELD_SOURCES, sources):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Failed to save config'}), 500


@dnsxai_bp.route('/pause', methods=['GET', 'POST'])
def api_pause():
    """Pause/resume dnsXai protection."""
    disabled_conf = f'{DNSMASQ_SHIELD_CONF}.disabled'

    def apply_state(enabled):
        """Apply DNS blocking state by modifying dnsmasq config."""
        if enabled:
            # Re-enable by restoring config
            if os.path.exists(disabled_conf) and not os.path.exists(DNSMASQ_SHIELD_CONF):
                run_command(f'sudo mv {disabled_conf} {DNSMASQ_SHIELD_CONF}')
            run_command('sudo systemctl restart dnsmasq')
        else:
            # Disable by moving config away
            if os.path.exists(DNSMASQ_SHIELD_CONF):
                run_command(f'sudo mv {DNSMASQ_SHIELD_CONF} {disabled_conf}')
            run_command('sudo systemctl restart dnsmasq')

    if request.method == 'GET':
        state = load_json_file(DNS_SHIELD_PAUSE, {'status': 'active', 'pause_until': 0})
        now = time.time()

        # Check if protection is actually active
        protection_active = is_protection_active()

        if state['status'] == 'paused':
            remaining = state.get('pause_until', 0) - now
            if remaining <= 0:
                state = {'status': 'active', 'pause_until': 0}
                save_json_file(DNS_SHIELD_PAUSE, state)
                apply_state(True)
                return jsonify({'status': 'active', 'remaining_seconds': 0})
            return jsonify({'status': 'paused', 'remaining_seconds': int(remaining)})
        elif state['status'] == 'disabled' or not protection_active:
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
        save_json_file(DNS_SHIELD_PAUSE, state)
        apply_state(False)
        return jsonify({'success': True, 'status': 'paused', 'minutes': minutes})

    elif action == 'resume':
        state = {'status': 'active', 'pause_until': 0}
        save_json_file(DNS_SHIELD_PAUSE, state)
        apply_state(True)
        return jsonify({'success': True, 'status': 'active'})

    elif action == 'disable':
        state = {'status': 'disabled', 'pause_until': 0}
        save_json_file(DNS_SHIELD_PAUSE, state)
        apply_state(False)
        return jsonify({'success': True, 'status': 'disabled'})

    elif action == 'enable':
        state = {'status': 'active', 'pause_until': 0}
        save_json_file(DNS_SHIELD_PAUSE, state)
        apply_state(True)
        return jsonify({'success': True, 'status': 'active'})

    return jsonify({'success': False, 'error': 'Invalid action'}), 400


@dnsxai_bp.route('/update', methods=['POST'])
def api_update():
    """Trigger blocklist update."""
    try:
        update_script = '/opt/hookprobe/guardian/scripts/update-blocklists.sh'
        if not os.path.exists(update_script):
            return jsonify({'success': False, 'error': 'Update script not found'}), 500

        output, success = run_command(f'{update_script} --force', timeout=120)
        if success:
            return jsonify({'success': True, 'message': 'Blocklists updated'})
        return jsonify({'success': False, 'error': output or 'Update failed'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
