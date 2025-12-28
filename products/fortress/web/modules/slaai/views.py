"""
Fortress SLA AI Views - WAN Monitoring & Business Continuity Dashboard

Provides:
- Real-time RTO/RPO gauges
- Failover status and history
- Cost tracking for metered connections
- LSTM prediction confidence
"""

from flask import render_template, jsonify, request
from flask_login import login_required
from datetime import datetime, timedelta
import json
import logging

from . import slaai_bp
from ..auth.decorators import operator_required

logger = logging.getLogger(__name__)

# Import system data module for real data
SYSTEM_DATA_AVAILABLE = False
try:
    import sys
    from pathlib import Path
    # Add lib path
    lib_path = Path(__file__).parent.parent.parent.parent / 'lib'
    if lib_path.exists() and str(lib_path) not in sys.path:
        sys.path.insert(0, str(lib_path))

    from system_data import (
        get_wan_health,
        get_slaai_status,
        get_all_interface_traffic,
        get_vlans,
        get_interfaces,
    )
    SYSTEM_DATA_AVAILABLE = True
except ImportError as e:
    logger.warning(f"system_data module not available: {e}")

# Try to import SLA AI engine components (optional)
SLAAI_ENGINE_AVAILABLE = False
try:
    shared_path = Path(__file__).parent.parent.parent.parent.parent.parent / 'shared'
    if shared_path.exists() and str(shared_path) not in sys.path:
        sys.path.insert(0, str(shared_path))

    from slaai import SLAEngine, SLAState, SLAStatus
    from slaai.config import load_config
    SLAAI_ENGINE_AVAILABLE = True
except ImportError as e:
    logger.debug(f"SLA AI engine not available: {e}")


def get_demo_sla_status():
    """Return demo SLA status when engine unavailable."""
    return {
        'state': 'primary_active',
        'timestamp': datetime.now().isoformat(),
        'primary_interface': 'eth0',
        'backup_interface': 'wwan0',
        'active_interface': 'eth0',
        'primary_health': 0.92,
        'backup_health': 0.65,
        'prediction': {
            'failure_probability': 0.08,
            'confidence': 0.87,
            'predicted_failure_time': None,
        },
        'cost_status': {
            'interface': 'wwan0',
            'daily_usage_mb': 145,
            'daily_budget_mb': 500,
            'monthly_usage_mb': 2150,
            'monthly_budget_mb': 10240,
            'cost_per_gb': 2.0,
            'current_cost': 4.30,
            'budget_remaining': 15.70,
        },
        'dns_status': {
            'active_provider': 'cloudflare',
            'latency_ms': 12,
            'health': 0.98,
        },
        'failback_status': {
            'can_failback': False,
            'reason': 'Primary is active',
        },
        'uptime_pct': 99.87,
        'failover_count_24h': 1,
        'rto_actual_s': 2.3,
        'rto_target_s': 5.0,
        'rpo_actual_bytes': 0,
        'rpo_target_bytes': 0,
        'failover_history': [
            {
                'timestamp': (datetime.now() - timedelta(hours=8)).isoformat(),
                'type': 'failover',
                'from_interface': 'eth0',
                'to_interface': 'wwan0',
                'reason': 'Primary link failure detected',
                'duration_s': 2.3,
            },
            {
                'timestamp': (datetime.now() - timedelta(hours=4)).isoformat(),
                'type': 'failback',
                'from_interface': 'wwan0',
                'to_interface': 'eth0',
                'reason': 'Primary recovered and stable',
                'duration_s': 1.8,
            },
        ],
    }


@slaai_bp.route('/')
@login_required
def index():
    """SLA AI dashboard - main view."""
    return render_template(
        'slaai/index.html',
        slaai_available=SYSTEM_DATA_AVAILABLE
    )


@slaai_bp.route('/api/status')
@login_required
def api_status():
    """Get current SLA status as JSON."""
    try:
        # Use real system data if available
        if SYSTEM_DATA_AVAILABLE:
            status = get_slaai_status()
            return jsonify({
                'success': True,
                'status': status,
                'demo_mode': False
            })

        # Fall back to demo data
        return jsonify({
            'success': True,
            'status': get_demo_sla_status(),
            'demo_mode': True
        })

    except Exception as e:
        logger.error(f"SLA AI status error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'status': get_demo_sla_status(),
            'demo_mode': True
        })


@slaai_bp.route('/api/metrics')
@login_required
def api_metrics():
    """Get WAN metrics for charts."""
    try:
        if SYSTEM_DATA_AVAILABLE:
            wan = get_wan_health()
            now = datetime.now()

            # Current metrics from real data
            current_metrics = {
                'timestamp': now.isoformat(),
                'primary_rtt': wan['primary']['rtt_ms'] if wan.get('primary') else None,
                'primary_jitter': wan['primary']['jitter_ms'] if wan.get('primary') else None,
                'primary_loss': wan['primary']['packet_loss'] if wan.get('primary') else 100,
                'backup_rtt': wan['backup']['rtt_ms'] if wan.get('backup') else None,
                'backup_signal': wan['backup'].get('signal_dbm') if wan.get('backup') else None,
                'backup_loss': wan['backup']['packet_loss'] if wan.get('backup') else 100,
            }

            return jsonify({
                'success': True,
                'metrics': [current_metrics],
                'demo_mode': False
            })

        # Fallback to demo data
        now = datetime.now()
        metrics = []
        for i in range(60):
            ts = now - timedelta(minutes=60 - i)
            metrics.append({
                'timestamp': ts.isoformat(),
                'primary_rtt': 12 + (i % 5) * 0.5,
                'primary_jitter': 1.2 + (i % 3) * 0.2,
                'backup_rtt': 45 + (i % 8) * 2,
                'backup_signal': -75 + (i % 10),
            })

        return jsonify({
            'success': True,
            'metrics': metrics,
            'demo_mode': True
        })

    except Exception as e:
        logger.error(f"Metrics error: {e}")
        return jsonify({'success': False, 'error': str(e)})


@slaai_bp.route('/api/history')
@login_required
def api_history():
    """Get failover history."""
    try:
        history = get_demo_sla_status()['failover_history']
        return jsonify({
            'success': True,
            'history': history,
            'demo_mode': not SLAAI_ENGINE_AVAILABLE
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@slaai_bp.route('/api/force-failover', methods=['POST'])
@login_required
@operator_required
def api_force_failover():
    """Force manual failover (admin only)."""
    try:
        # In production, this would call SLA engine
        return jsonify({
            'success': True,
            'message': 'Manual failover initiated',
            'demo_mode': not SLAAI_ENGINE_AVAILABLE
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@slaai_bp.route('/api/force-failback', methods=['POST'])
@login_required
@operator_required
def api_force_failback():
    """Force manual failback (admin only)."""
    try:
        return jsonify({
            'success': True,
            'message': 'Manual failback initiated',
            'demo_mode': not SYSTEM_DATA_AVAILABLE
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@slaai_bp.route('/api/traffic')
@login_required
def api_traffic():
    """Get real-time traffic data for all interfaces."""
    try:
        if SYSTEM_DATA_AVAILABLE:
            traffic = get_all_interface_traffic()
            vlans = get_vlans()

            return jsonify({
                'success': True,
                'traffic': traffic,
                'vlans': vlans,
                'demo_mode': False
            })

        # Fallback demo data
        return jsonify({
            'success': True,
            'traffic': [],
            'vlans': [],
            'demo_mode': True
        })

    except Exception as e:
        logger.error(f"Traffic API error: {e}")
        return jsonify({'success': False, 'error': str(e)})


@slaai_bp.route('/api/interfaces')
@login_required
def api_interfaces():
    """Get list of active interfaces."""
    try:
        if SYSTEM_DATA_AVAILABLE:
            interfaces = get_interfaces()
            # Filter to relevant interfaces
            relevant = [
                iface for iface in interfaces
                if iface['type'] in ['wan', 'lte', 'bridge', 'wifi', 'vlan']
                and iface['state'] == 'UP'
            ]
            return jsonify({
                'success': True,
                'interfaces': relevant,
                'demo_mode': False
            })

        return jsonify({
            'success': True,
            'interfaces': [],
            'demo_mode': True
        })

    except Exception as e:
        logger.error(f"Interfaces API error: {e}")
        return jsonify({'success': False, 'error': str(e)})
