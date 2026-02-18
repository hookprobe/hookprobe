"""
dnsXai Module Views - AI-powered DNS Protection
Integrates with Guardian DNS Shield (dnsmasq blocklist)
Features: ML classification, CNAME uncloaking, federated learning, real-time detection
"""
import os
import re
import time
import logging
from flask import jsonify, request
from . import dnsxai_bp
from utils import load_json_file, save_json_file, load_text_file, save_text_file, run_command

# ML Engine imports
try:
    from .ml_engine import (
        get_classifier, get_uncloaker, get_federated, get_detector,
        DomainFeatureExtractor, check_ml_libraries, HAS_NUMPY, HAS_SKLEARN
    )
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    check_ml_libraries = None
    HAS_NUMPY = False
    HAS_SKLEARN = False
    logging.warning(f"ML engine not available: {e}")

# Packet Inspector imports
try:
    from .packet_inspector import (
        get_packet_detector, get_dns_analyzer,
        PacketAdDetector, DNSResponseAnalyzer
    )
    PACKET_INSPECTOR_AVAILABLE = True
except ImportError as e:
    PACKET_INSPECTOR_AVAILABLE = False
    logging.warning(f"Packet inspector not available: {e}")

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


def _check_ml_ready():
    """Check if ML libraries are available. Returns (ready, error_response)."""
    if not ML_AVAILABLE:
        return False, jsonify({
            'success': False,
            'error': 'ML engine not available'
        }), 400

    if check_ml_libraries:
        has_numpy, has_sklearn = check_ml_libraries()
        if not has_sklearn:
            missing = []
            if not has_numpy:
                missing.append('numpy')
            if not has_sklearn:
                missing.append('scikit-learn')
            return False, jsonify({
                'success': False,
                'error': f'ML libraries not installed ({", ".join(missing)} required)',
                'hint': 'Run: pip3 install numpy scikit-learn joblib'
            }), 400

    return True, None


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
    """Get dnsXai statistics from DNS Shield with ML metrics."""
    # Get real-time stats from dnsmasq log
    stats = get_dns_stats()

    # Get blocklist size
    stats['blocklist_domains'] = get_blocklist_count()

    # Get current level
    stats['level'] = get_shield_level()

    # Get ML stats if available
    if ML_AVAILABLE:
        try:
            detector = get_detector()
            ml_stats = detector.get_stats()
            stats['ml_blocks'] = ml_stats.get('ml_detections', 0)
            stats['cname_uncloaked'] = ml_stats.get('cname_uncloaked', 0)
            stats['ml_available'] = True
            stats['ml_trained'] = ml_stats.get('classifier_status', {}).get('is_trained', False)
            stats['ml_training_samples'] = ml_stats.get('classifier_status', {}).get('training_samples', 0)
            stats['threats_detected'] = ml_stats.get('threats_detected', 0)
        except Exception as e:
            stats['ml_blocks'] = 0
            stats['cname_uncloaked'] = 0
            stats['ml_available'] = False
            stats['ml_error'] = str(e)
    else:
        # Fallback to persisted stats
        persisted = load_json_file(DNS_SHIELD_STATS, {})
        stats['ml_blocks'] = persisted.get('ml_blocks', 0)
        stats['cname_uncloaked'] = persisted.get('cname_uncloaked', 0)
        stats['ml_available'] = False

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
        import subprocess as _sp
        _sp.Popen(
            ['/opt/hookprobe/guardian/scripts/update-blocklists.sh', '--silent'],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL
        )
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
                run_command(['sudo', 'systemctl', 'restart', 'dnsmasq'])
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Domain already whitelisted'}), 400

    if request.method == 'DELETE':
        if domain in working:
            whitelist = [d for d in whitelist if d.strip().lower() != domain]
            if save_text_file(DNS_SHIELD_WHITELIST, whitelist):
                run_command(['sudo', 'systemctl', 'restart', 'dnsmasq'])
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
                run_command(['sudo', 'mv', disabled_conf, DNSMASQ_SHIELD_CONF])
            run_command(['sudo', 'systemctl', 'restart', 'dnsmasq'])
        else:
            # Disable by moving config away
            if os.path.exists(DNSMASQ_SHIELD_CONF):
                run_command(['sudo', 'mv', DNSMASQ_SHIELD_CONF, disabled_conf])
            run_command(['sudo', 'systemctl', 'restart', 'dnsmasq'])

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

        output, success = run_command([update_script, '--force'], timeout=120)
        if success:
            return jsonify({'success': True, 'message': 'Blocklists updated'})
        return jsonify({'success': False, 'error': output or 'Update failed'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# ML/AI ENDPOINTS
# =============================================================================

@dnsxai_bp.route('/ml/status')
def api_ml_status():
    """Get ML engine status and capabilities."""
    # Dynamic check - allows detection after package installation
    force_recheck = request.args.get('recheck', 'false').lower() == 'true'

    if check_ml_libraries:
        has_numpy, has_sklearn = check_ml_libraries(force_recheck=force_recheck)
    else:
        has_numpy, has_sklearn = False, False

    if not ML_AVAILABLE or not has_sklearn:
        missing = []
        if not has_numpy:
            missing.append('numpy')
        if not has_sklearn:
            missing.append('scikit-learn')
        return jsonify({
            'available': False,
            'has_numpy': has_numpy,
            'has_sklearn': has_sklearn,
            'error': f'ML libraries not installed ({", ".join(missing)} required)',
            'hint': 'Run: pip3 install numpy scikit-learn joblib'
        })

    try:
        classifier = get_classifier()
        uncloaker = get_uncloaker()
        federated = get_federated()
        detector = get_detector()

        return jsonify({
            'available': True,
            'has_numpy': True,
            'has_sklearn': True,
            'classifier': classifier.get_status(),
            'uncloaker': uncloaker.get_stats(),
            'federated': federated.get_stats(),
            'detector': detector.get_stats()
        })
    except Exception as e:
        return jsonify({'available': False, 'error': str(e)}), 500


@dnsxai_bp.route('/ml/train', methods=['POST'])
def api_ml_train():
    """Train ML model on browsing history with seed data for ad detection."""
    ready, error_response = _check_ml_ready()
    if not ready:
        return error_response

    try:
        data = request.get_json() or {}
        source = data.get('source', 'auto')  # 'auto', 'history', 'custom'
        use_seed_data = data.get('use_seed_data', True)  # Include known ad/safe domains

        domains = []

        if source == 'custom':
            # Use provided domains
            domains = data.get('domains', [])
        else:
            # Parse browsing history from dnsmasq log
            domains = _parse_browsing_history(
                hours=data.get('hours', 24),
                limit=data.get('limit', 5000)
            )

        # Note: Even with 0 browsing domains, training can work with seed data
        # The classifier will use known ad/safe domains as baseline

        # Train the classifier
        classifier = get_classifier()
        result = classifier.train(domains, use_seed_data=use_seed_data)

        # Enhance result message
        if result.get('success'):
            user_count = result.get('user_domains', 0)
            seed_count = result.get('seed_domains', 0)
            if user_count > 0:
                result['message'] = f'Trained on {user_count} browsing domains + {seed_count} known patterns'
            else:
                result['message'] = f'Trained on {seed_count} known ad/safe patterns. Browse websites to improve accuracy.'

        return jsonify(result)

    except Exception as e:
        logging.error(f"ML training error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/ml/classify', methods=['POST'])
def api_ml_classify():
    """Classify a domain using ML."""
    ready, error_response = _check_ml_ready()
    if not ready:
        return error_response

    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()

        if not domain:
            return jsonify({'success': False, 'error': 'Domain required'}), 400

        classifier = get_classifier()
        result = classifier.predict(domain)

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/ml/analyze', methods=['POST'])
def api_ml_analyze():
    """Real-time threat analysis for a domain."""
    ready, error_response = _check_ml_ready()
    if not ready:
        return error_response

    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        cname_chain = data.get('cname_chain', [])

        if not domain:
            return jsonify({'success': False, 'error': 'Domain required'}), 400

        detector = get_detector()
        result = detector.analyze_query(domain, cname_chain=cname_chain)

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/ml/history')
def api_ml_history():
    """Get browsing history for ML training."""
    try:
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 1000, type=int)

        domains = _parse_browsing_history(hours=hours, limit=limit)

        # Get unique domains with counts
        from collections import Counter
        domain_counts = Counter(domains)

        return jsonify({
            'success': True,
            'total_queries': len(domains),
            'unique_domains': len(domain_counts),
            'top_domains': domain_counts.most_common(50),
            'hours': hours
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/ml/threats')
def api_ml_threats():
    """Get recent ML-detected threats."""
    if not ML_AVAILABLE:
        return jsonify({'threats': [], 'error': 'ML not available'})

    try:
        detector = get_detector()
        stats = detector.get_stats()

        return jsonify({
            'success': True,
            'threats': stats.get('recent_threats', []),
            'total_detected': stats.get('threats_detected', 0),
            'ml_detections': stats.get('ml_detections', 0),
            'cname_uncloaked': stats.get('cname_uncloaked', 0)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/blocked')
def api_blocked_domains():
    """Get recently blocked domains from dnsmasq log with block counts."""
    import time
    from collections import OrderedDict

    limit = request.args.get('limit', 50, type=int)
    blocked_domains = OrderedDict()
    total_blocks = 0  # Total number of blocked requests

    try:
        if not os.path.exists(DNSMASQ_QUERY_LOG):
            return jsonify({'success': True, 'domains': [], 'count': 0, 'total_blocks': 0})

        # Read last portion of log file for performance
        file_size = os.path.getsize(DNSMASQ_QUERY_LOG)
        read_size = min(file_size, 2 * 1024 * 1024)  # 2MB max

        with open(DNSMASQ_QUERY_LOG, 'r') as f:
            if file_size > read_size:
                f.seek(file_size - read_size)
                f.readline()  # Skip partial line

            # Parse blocked queries (return 0.0.0.0)
            # Format: "Dec 8 10:30:45 dnsmasq[123]: /0.0.0.0 example.com is 0.0.0.0"
            # Or: "Dec 8 10:30:45 dnsmasq[123]: config example.com is 0.0.0.0"
            for line in f:
                if ' is 0.0.0.0' in line or '/0.0.0.0' in line:
                    try:
                        # Extract domain from different log formats
                        domain = None

                        # Format 1: "config domain.com is 0.0.0.0"
                        if ' config ' in line:
                            parts = line.split(' config ')[1].split(' is ')[0]
                            domain = parts.strip()

                        # Format 2: "/0.0.0.0 domain.com is 0.0.0.0"
                        elif '/0.0.0.0 ' in line:
                            parts = line.split('/0.0.0.0 ')[1].split(' is ')[0]
                            domain = parts.strip()

                        # Format 3: "reply domain.com is 0.0.0.0"
                        elif ' reply ' in line and ' is 0.0.0.0' in line:
                            parts = line.split(' reply ')[1].split(' is ')[0]
                            domain = parts.strip()

                        if domain:
                            total_blocks += 1

                            if domain in blocked_domains:
                                # Increment block count for existing domain
                                blocked_domains[domain]['block_count'] += 1
                            else:
                                # Extract timestamp if possible
                                timestamp = None
                                try:
                                    # Get month day time from beginning of line
                                    ts_parts = line.split()[:3]
                                    if len(ts_parts) >= 3:
                                        timestamp = ' '.join(ts_parts)
                                except Exception:
                                    pass

                                blocked_domains[domain] = {
                                    'domain': domain,
                                    'type': 'blocklist',
                                    'typeBadge': 'BLOCKED',
                                    'timestamp': timestamp,
                                    'time': int(time.time()),
                                    'block_count': 1
                                }
                    except Exception:
                        continue

        # Convert to list and sort by block count (most blocked first)
        domains_list = list(blocked_domains.values())
        domains_list.sort(key=lambda x: x.get('block_count', 1), reverse=True)

        return jsonify({
            'success': True,
            'domains': domains_list[:limit],
            'count': len(domains_list),
            'total_blocks': total_blocks
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'domains': [], 'total_blocks': 0}), 500


# =============================================================================
# CNAME UNCLOAKING ENDPOINTS
# =============================================================================

@dnsxai_bp.route('/cname/check', methods=['POST'])
def api_cname_check():
    """Check if a CNAME is hiding a tracker."""
    ready, error_response = _check_ml_ready()
    if not ready:
        return error_response

    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        cname_target = data.get('cname_target', '').strip().lower()

        if not domain or not cname_target:
            return jsonify({'success': False, 'error': 'Domain and cname_target required'}), 400

        uncloaker = get_uncloaker()
        result = uncloaker.check_cname(domain, cname_target)

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/cname/stats')
def api_cname_stats():
    """Get CNAME uncloaking statistics."""
    if not ML_AVAILABLE:
        return jsonify({'success': False, 'stats': {}})

    try:
        uncloaker = get_uncloaker()
        return jsonify({
            'success': True,
            **uncloaker.get_stats()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# FEDERATED LEARNING ENDPOINTS
# =============================================================================

@dnsxai_bp.route('/federated/status')
def api_federated_status():
    """Get federated learning status."""
    if not ML_AVAILABLE:
        return jsonify({'available': False})

    try:
        federated = get_federated()
        return jsonify({
            'success': True,
            **federated.get_stats()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/federated/export')
def api_federated_export():
    """Export local updates for federation."""
    if not ML_AVAILABLE:
        return jsonify({'updates': []})

    try:
        federated = get_federated()
        return jsonify({
            'success': True,
            'updates': federated.get_exportable_updates()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/federated/import', methods=['POST'])
def api_federated_import():
    """Import updates from other nodes."""
    ready, error_response = _check_ml_ready()
    if not ready:
        return error_response

    try:
        data = request.get_json()
        updates = data.get('updates', [])

        federated = get_federated()
        imported = 0

        for update in updates:
            if federated.apply_update(update):
                imported += 1

        return jsonify({
            'success': True,
            'imported': imported,
            'total': len(updates)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _parse_browsing_history(hours: int = 24, limit: int = 5000) -> list:
    """
    Parse browsing history from dnsmasq query log.
    Returns list of domains queried in the past N hours.
    """
    domains = []

    try:
        if not os.path.exists(DNSMASQ_QUERY_LOG):
            return domains

        import datetime
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)

        # Read log file (limit to last 10MB for performance)
        file_size = os.path.getsize(DNSMASQ_QUERY_LOG)
        read_size = min(file_size, 10 * 1024 * 1024)

        with open(DNSMASQ_QUERY_LOG, 'r') as f:
            if file_size > read_size:
                f.seek(file_size - read_size)
                f.readline()  # Skip partial line

            # Parse log entries
            # Format: "Dec  7 10:30:45 dnsmasq[123]: query[A] example.com from 192.168.1.100"
            domain_pattern = re.compile(r'query\[[A-Z]+\]\s+(\S+)\s+from')

            for line in f:
                if len(domains) >= limit:
                    break

                match = domain_pattern.search(line)
                if match:
                    domain = match.group(1).lower().strip('.')

                    # Skip internal/local domains
                    if not domain or domain.endswith('.local') or domain.endswith('.lan'):
                        continue
                    if domain in ('localhost', 'broadcasthost'):
                        continue

                    domains.append(domain)

    except Exception as e:
        logging.error(f"Failed to parse browsing history: {e}")

    return domains


# =============================================================================
# PACKET-LEVEL AD DETECTION ENDPOINTS
# =============================================================================

@dnsxai_bp.route('/packet/status')
def api_packet_status():
    """Get packet-level ad detection status and statistics."""
    if not PACKET_INSPECTOR_AVAILABLE:
        return jsonify({
            'success': False,
            'available': False,
            'error': 'Packet inspector not available'
        })

    try:
        detector = get_packet_detector()
        stats = detector.get_stats()

        return jsonify({
            'success': True,
            'available': True,
            **stats
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/packet/check/domain', methods=['POST'])
def api_packet_check_domain():
    """
    Check if a domain matches known ad/tracker patterns.
    Uses SNI pattern matching against known ad networks.
    """
    if not PACKET_INSPECTOR_AVAILABLE:
        return jsonify({'success': False, 'error': 'Packet inspector not available'}), 400

    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()

        if not domain:
            return jsonify({'success': False, 'error': 'Domain required'}), 400

        detector = get_packet_detector()
        result = detector.check_sni(domain)

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/packet/check/ip', methods=['POST'])
def api_packet_check_ip():
    """
    Check if an IP belongs to a known ad network.
    Uses IP reputation database with known ad network CIDR ranges.
    """
    if not PACKET_INSPECTOR_AVAILABLE:
        return jsonify({'success': False, 'error': 'Packet inspector not available'}), 400

    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        detector = get_packet_detector()
        result = detector.check_ip(ip)

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/packet/analyze/dns', methods=['POST'])
def api_packet_analyze_dns():
    """
    Analyze a DNS response for ad indicators.
    Checks domain patterns, resolved IPs, and CNAME chains.
    """
    if not PACKET_INSPECTOR_AVAILABLE:
        return jsonify({'success': False, 'error': 'Packet inspector not available'}), 400

    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        ip_addresses = data.get('ips', [])
        cnames = data.get('cnames', [])
        ttl = data.get('ttl', 0)

        if not domain:
            return jsonify({'success': False, 'error': 'Domain required'}), 400

        analyzer = get_dns_analyzer()
        result = analyzer.analyze_dns_response(
            domain=domain,
            ip_addresses=ip_addresses,
            cnames=cnames,
            ttl=ttl
        )

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/packet/analyze/connection', methods=['POST'])
def api_packet_analyze_connection():
    """
    Analyze a network connection for ad/tracking activity.
    Full analysis including IP reputation, SNI, and traffic patterns.
    """
    if not PACKET_INSPECTOR_AVAILABLE:
        return jsonify({'success': False, 'error': 'Packet inspector not available'}), 400

    try:
        data = request.get_json()
        dst_ip = data.get('dst_ip', '').strip()
        dst_port = data.get('dst_port', 443)
        payload_size = data.get('payload_size', 0)
        content_type = data.get('content_type')

        if not dst_ip:
            return jsonify({'success': False, 'error': 'Destination IP required'}), 400

        detector = get_packet_detector()
        result = detector.analyze_connection(
            dst_ip=dst_ip,
            dst_port=dst_port,
            payload_size=payload_size,
            content_type=content_type
        )

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/packet/detections')
def api_packet_detections():
    """Get recent packet-level ad detections."""
    if not PACKET_INSPECTOR_AVAILABLE:
        return jsonify({'success': False, 'detections': [], 'error': 'Packet inspector not available'})

    try:
        limit = request.args.get('limit', 50, type=int)

        detector = get_packet_detector()
        detections = detector.get_recent_detections(limit)

        return jsonify({
            'success': True,
            'detections': detections,
            'count': len(detections)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/packet/ip/block', methods=['POST'])
def api_packet_block_ip():
    """Add an IP to the blocked ad network list."""
    if not PACKET_INSPECTOR_AVAILABLE:
        return jsonify({'success': False, 'error': 'Packet inspector not available'}), 400

    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        reason = data.get('reason', 'User blocked')

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        detector = get_packet_detector()
        detector.ip_db.add_blocked_ip(ip, reason)

        return jsonify({
            'success': True,
            'message': f'IP {ip} added to blocked list'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dnsxai_bp.route('/packet/combined/check', methods=['POST'])
def api_combined_ad_check():
    """
    Combined ML + Packet analysis for comprehensive ad detection.
    Uses both domain classification and packet-level analysis.
    """
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        ip = data.get('ip', '').strip()

        if not domain and not ip:
            return jsonify({'success': False, 'error': 'Domain or IP required'}), 400

        result = {
            'domain': domain,
            'ip': ip,
            'is_ad': False,
            'confidence': 0.0,
            'methods_used': [],
            'details': {}
        }

        total_score = 0.0
        method_count = 0

        # ML classification (if available and domain provided)
        if ML_AVAILABLE and domain:
            try:
                classifier = get_classifier()
                ml_result = classifier.predict(domain)
                result['details']['ml_classification'] = ml_result
                result['methods_used'].append('ml_classification')

                if ml_result.get('is_suspicious'):
                    total_score += ml_result.get('threat_score', 0) * 0.4
                    method_count += 1
            except Exception as e:
                logging.warning(f"ML classification failed: {e}")

        # Packet-level analysis (if available)
        if PACKET_INSPECTOR_AVAILABLE:
            detector = get_packet_detector()

            # Check domain against SNI patterns
            if domain:
                sni_result = detector.check_sni(domain)
                result['details']['sni_check'] = sni_result
                result['methods_used'].append('sni_pattern')

                if sni_result.get('is_ad'):
                    total_score += 0.6
                    method_count += 1

            # Check IP reputation
            if ip:
                ip_result = detector.check_ip(ip)
                result['details']['ip_check'] = ip_result
                result['methods_used'].append('ip_reputation')

                if ip_result.get('is_ad'):
                    total_score += 0.5
                    method_count += 1

        # Calculate final score
        if method_count > 0:
            result['confidence'] = min(total_score, 1.0)
            result['is_ad'] = result['confidence'] > 0.4

        return jsonify({
            'success': True,
            **result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
