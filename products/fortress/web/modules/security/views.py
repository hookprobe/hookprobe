"""
Fortress Security Views - QSecBit, threats, and security metrics.

Provides real-time security monitoring and threat visualization.
Uses system_data.py for real-time QSecBit scores from the agent.
"""

from flask import render_template, request, jsonify
from flask_login import login_required
from datetime import datetime, timedelta
import logging

from . import security_bp

logger = logging.getLogger(__name__)

# Import lib modules (with fallback for development)
DB_AVAILABLE = False
SYSTEM_DATA_AVAILABLE = False

try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from database import get_db
    DB_AVAILABLE = True
except ImportError:
    pass

try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from system_data import get_qsecbit_stats
    SYSTEM_DATA_AVAILABLE = True
except ImportError:
    pass


def get_real_qsecbit():
    """Get real QSecBit data from system_data.py (reads from agent stats file)."""
    if not SYSTEM_DATA_AVAILABLE:
        return None

    try:
        stats = get_qsecbit_stats()
        if not stats:
            return None

        # Calculate RAG status from score
        score = stats.get('score', 0.85)
        if score < 0.45:
            rag_status = 'GREEN'
        elif score < 0.70:
            rag_status = 'AMBER'
        else:
            rag_status = 'RED'

        return {
            'score': score,
            'rag_status': stats.get('rag_status', rag_status),
            'recorded_at': stats.get('last_updated', datetime.now().isoformat()),
            'container_running': stats.get('container_running', False),
            'threats_detected': stats.get('threats_detected', 0),
            'components': stats.get('components', {
                'network': 0.0,
                'threats': 0.0,
                'dns': 0.0,
                'ids': 0.0,
                'behavioral': 0.0,
            })
        }
    except Exception as e:
        logger.warning(f"Failed to get QSecBit stats: {e}")
        return None


def get_default_qsecbit():
    """Return default QSecBit data when no data available."""
    return {
        'score': 0.0,
        'rag_status': 'GREEN',
        'recorded_at': datetime.now().isoformat(),
        'components': {
            'network': 0.0,
            'threats': 0.0,
            'dns': 0.0,
            'ids': 0.0,
            'behavioral': 0.0,
        },
        'no_data': True  # Flag to indicate no real data
    }


def get_empty_threats():
    """Return empty threat list."""
    return []


def get_empty_dns_stats():
    """Return empty DNS statistics."""
    return {
        'total_queries': 0,
        'blocked_queries': 0,
        'block_rate': 0.0,
        'top_blocked': []
    }


def get_default_layer_stats():
    """Return default layer statistics (no threats detected)."""
    return {
        'L2': {'score': 1.0, 'threats': 0, 'status': 'GREEN'},
        'L3': {'score': 1.0, 'threats': 0, 'status': 'GREEN'},
        'L4': {'score': 1.0, 'threats': 0, 'status': 'GREEN'},
        'L5': {'score': 1.0, 'threats': 0, 'status': 'GREEN'},
        'L7': {'score': 1.0, 'threats': 0, 'status': 'GREEN'},
    }


@security_bp.route('/')
@login_required
def index():
    """Security dashboard with QSecBit metrics."""
    # Try to get real QSecBit data from system_data.py (file-based)
    qsecbit = get_real_qsecbit()
    if not qsecbit:
        qsecbit = get_default_qsecbit()

    # Start with empty data (no demo data)
    threats = get_empty_threats()
    dns_stats = get_empty_dns_stats()
    layer_stats = get_default_layer_stats()
    threat_summary = {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0}

    # Try to get real data from database if available
    if DB_AVAILABLE:
        try:
            db = get_db()

            # If DB has QSecBit data, use it (takes precedence over file)
            qsecbit_data = db.get_latest_qsecbit()
            if qsecbit_data:
                qsecbit = qsecbit_data
                qsecbit['score'] = float(qsecbit['score'])
                if qsecbit.get('recorded_at'):
                    qsecbit['recorded_at'] = str(qsecbit['recorded_at'])

            # Get real threat data
            threats = db.get_recent_threats(hours=24, limit=10)
            for threat in threats:
                if threat.get('detected_at'):
                    threat['detected_at'] = str(threat['detected_at'])
                if threat.get('source_ip'):
                    threat['source_ip'] = str(threat['source_ip'])

            # Get threat summary
            summary = db.get_threat_summary(hours=24)
            if summary:
                threat_summary = summary

            # Get DNS stats
            dns = db.get_dns_stats(hours=24)
            if dns:
                dns_stats = dns

        except Exception as e:
            logger.warning(f"Database access failed: {e}")
            # Keep default empty data, don't fall back to demo

    # Determine data availability flags
    data_available = not qsecbit.get('no_data', False) or DB_AVAILABLE

    return render_template(
        'security/index.html',
        qsecbit=qsecbit,
        threats=threats,
        dns_stats=dns_stats,
        layer_stats=layer_stats,
        threat_summary=threat_summary,
        db_available=DB_AVAILABLE,
        data_available=data_available
    )


@security_bp.route('/threats')
@login_required
def threats():
    """Detailed threat log page."""
    hours = request.args.get('hours', 24, type=int)
    threats = get_empty_threats()

    if DB_AVAILABLE:
        try:
            db = get_db()
            threats = db.get_recent_threats(hours=hours, limit=100)
            for threat in threats:
                if threat.get('detected_at'):
                    threat['detected_at'] = str(threat['detected_at'])
                if threat.get('source_ip'):
                    threat['source_ip'] = str(threat['source_ip'])
        except Exception as e:
            logger.warning(f"Failed to get threats: {e}")

    return render_template(
        'security/threats.html',
        threats=threats,
        hours=hours,
        db_available=DB_AVAILABLE
    )


@security_bp.route('/api/qsecbit')
@login_required
def api_qsecbit():
    """Get current QSecBit score for AJAX updates."""
    # Try file-based data first (from qsecbit_stats.json)
    qsecbit = get_real_qsecbit()
    if not qsecbit:
        qsecbit = get_default_qsecbit()

    # Check DB for more recent data
    if DB_AVAILABLE:
        try:
            db = get_db()
            qsecbit_data = db.get_latest_qsecbit()
            if qsecbit_data:
                qsecbit = qsecbit_data
                qsecbit['score'] = float(qsecbit['score'])
                if qsecbit.get('recorded_at'):
                    qsecbit['recorded_at'] = str(qsecbit['recorded_at'])
        except Exception as e:
            logger.warning(f"DB access failed: {e}")
            # Continue with file-based data

    return jsonify(qsecbit)


@security_bp.route('/api/history')
@login_required
def api_history():
    """Get QSecBit score history for charts."""
    hours = request.args.get('hours', 24, type=int)

    if not DB_AVAILABLE:
        # Return empty history (no demo data)
        return jsonify({'history': [], 'no_data': True})

    try:
        db = get_db()
        history = db.get_qsecbit_history(hours=hours)
        for item in history:
            item['score'] = float(item['score'])
            if item.get('recorded_at'):
                item['timestamp'] = str(item['recorded_at'])
        return jsonify({'history': history})
    except Exception as e:
        logger.exception("Failed to get security history")
        return jsonify({'history': [], 'error': 'An internal error occurred while fetching history'})


@security_bp.route('/api/threats/summary')
@login_required
def api_threat_summary():
    """Get threat summary for dashboard widgets."""
    summary = {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0}

    if DB_AVAILABLE:
        try:
            db = get_db()
            db_summary = db.get_threat_summary(hours=24)
            if db_summary:
                summary = db_summary
        except Exception as e:
            logger.warning(f"Failed to get threat summary: {e}")

    return jsonify(summary)
