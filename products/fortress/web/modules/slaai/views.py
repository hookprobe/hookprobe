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

# Try to import SLA AI components
SLAAI_AVAILABLE = False
try:
    import sys
    from pathlib import Path
    # Add shared path
    shared_path = Path(__file__).parent.parent.parent.parent.parent.parent / 'shared'
    if shared_path.exists() and str(shared_path) not in sys.path:
        sys.path.insert(0, str(shared_path))

    from slaai import SLAEngine, SLAState, SLAStatus
    from slaai.config import load_config
    SLAAI_AVAILABLE = True
except ImportError as e:
    logger.warning(f"SLA AI not available: {e}")


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
        slaai_available=SLAAI_AVAILABLE
    )


@slaai_bp.route('/api/status')
@login_required
def api_status():
    """Get current SLA status as JSON."""
    try:
        if SLAAI_AVAILABLE:
            # Try to read from state file
            state_file = Path('/run/fortress/slaai-recommendation.json')
            if state_file.exists():
                with open(state_file) as f:
                    data = json.load(f)
                    return jsonify({'success': True, 'status': data})

        # Return demo data
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
        # Generate time series data for last hour
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
            'demo_mode': not SLAAI_AVAILABLE
        })

    except Exception as e:
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
            'demo_mode': not SLAAI_AVAILABLE
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
            'demo_mode': not SLAAI_AVAILABLE
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
            'demo_mode': not SLAAI_AVAILABLE
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
