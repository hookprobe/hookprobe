"""
Fortress Security Views - QSecBit, threats, and security metrics.

Provides real-time security monitoring and threat visualization.
"""

from flask import render_template, request, jsonify
from flask_login import login_required
from datetime import datetime, timedelta

from . import security_bp

# Import lib modules (with fallback for development)
DB_AVAILABLE = False
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from database import get_db
    DB_AVAILABLE = True
except ImportError:
    pass


def get_demo_qsecbit():
    """Return demo QSecBit data."""
    return {
        'score': 0.32,
        'rag_status': 'GREEN',
        'recorded_at': datetime.now().isoformat(),
        'components': {
            'network': 0.25,
            'threats': 0.15,
            'dns': 0.10,
            'ids': 0.20,
            'behavioral': 0.08,
        }
    }


def get_demo_threats():
    """Return demo threat data."""
    return [
        {
            'threat_type': 'port_scan',
            'severity': 'LOW',
            'source_ip': '192.168.1.100',
            'detected_at': (datetime.now() - timedelta(hours=2)).isoformat(),
            'blocked': True,
            'details': {'ports_scanned': 15}
        },
        {
            'threat_type': 'dns_tunnel',
            'severity': 'MEDIUM',
            'source_ip': '192.168.1.105',
            'detected_at': (datetime.now() - timedelta(hours=5)).isoformat(),
            'blocked': True,
            'details': {'domain': 'suspicious.example.com'}
        },
        {
            'threat_type': 'arp_spoof',
            'severity': 'HIGH',
            'source_ip': '192.168.1.200',
            'detected_at': (datetime.now() - timedelta(hours=12)).isoformat(),
            'blocked': True,
            'details': {'target_mac': 'AA:BB:CC:DD:EE:FF'}
        },
    ]


def get_demo_dns_stats():
    """Return demo DNS statistics."""
    return {
        'total_queries': 15420,
        'blocked_queries': 842,
        'block_rate': 5.46,
        'top_blocked': [
            {'domain': 'ads.doubleclick.net', 'count': 156},
            {'domain': 'tracker.example.com', 'count': 98},
            {'domain': 'analytics.badsite.com', 'count': 75},
        ]
    }


def get_demo_layer_stats():
    """Return demo layer statistics."""
    return {
        'L2': {'score': 0.95, 'threats': 1, 'status': 'GREEN'},
        'L3': {'score': 0.92, 'threats': 2, 'status': 'GREEN'},
        'L4': {'score': 0.88, 'threats': 5, 'status': 'GREEN'},
        'L5': {'score': 0.90, 'threats': 0, 'status': 'GREEN'},
        'L7': {'score': 0.85, 'threats': 3, 'status': 'AMBER'},
    }


@security_bp.route('/')
@login_required
def index():
    """Security dashboard with QSecBit metrics."""
    qsecbit = get_demo_qsecbit()
    threats = get_demo_threats()
    dns_stats = get_demo_dns_stats()
    layer_stats = get_demo_layer_stats()
    threat_summary = {'total': 3, 'high': 1, 'medium': 1, 'low': 1, 'blocked': 3}

    if DB_AVAILABLE:
        try:
            db = get_db()

            # Get QSecBit data
            qsecbit_data = db.get_latest_qsecbit()
            if qsecbit_data:
                qsecbit = qsecbit_data
                qsecbit['score'] = float(qsecbit['score'])
                if qsecbit.get('recorded_at'):
                    qsecbit['recorded_at'] = str(qsecbit['recorded_at'])

            # Get threat data
            threats = db.get_recent_threats(hours=24, limit=10)
            for threat in threats:
                if threat.get('detected_at'):
                    threat['detected_at'] = str(threat['detected_at'])
                if threat.get('source_ip'):
                    threat['source_ip'] = str(threat['source_ip'])

            # Get threat summary
            threat_summary = db.get_threat_summary(hours=24)

            # Get DNS stats
            dns_stats = db.get_dns_stats(hours=24)

        except Exception as e:
            # Fall back to demo data on error
            pass

    return render_template(
        'security/index.html',
        qsecbit=qsecbit,
        threats=threats,
        dns_stats=dns_stats,
        layer_stats=layer_stats,
        threat_summary=threat_summary,
        db_available=DB_AVAILABLE
    )


@security_bp.route('/threats')
@login_required
def threats():
    """Detailed threat log page."""
    hours = request.args.get('hours', 24, type=int)
    threats = get_demo_threats()

    if DB_AVAILABLE:
        try:
            db = get_db()
            threats = db.get_recent_threats(hours=hours, limit=100)
            for threat in threats:
                if threat.get('detected_at'):
                    threat['detected_at'] = str(threat['detected_at'])
                if threat.get('source_ip'):
                    threat['source_ip'] = str(threat['source_ip'])
        except Exception:
            pass

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
    qsecbit = get_demo_qsecbit()

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
            return jsonify({'error': str(e)}), 500

    return jsonify(qsecbit)


@security_bp.route('/api/history')
@login_required
def api_history():
    """Get QSecBit score history for charts."""
    hours = request.args.get('hours', 24, type=int)

    if not DB_AVAILABLE:
        # Generate demo history
        history = []
        now = datetime.now()
        for i in range(hours):
            timestamp = now - timedelta(hours=hours - i)
            score = 0.30 + (i % 10) * 0.02  # Vary between 0.30 and 0.50
            history.append({
                'timestamp': timestamp.isoformat(),
                'score': round(score, 3)
            })
        return jsonify({'history': history})

    try:
        db = get_db()
        history = db.get_qsecbit_history(hours=hours)
        for item in history:
            item['score'] = float(item['score'])
            if item.get('recorded_at'):
                item['timestamp'] = str(item['recorded_at'])
        return jsonify({'history': history})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/api/threats/summary')
@login_required
def api_threat_summary():
    """Get threat summary for dashboard widgets."""
    summary = {'total': 3, 'high': 1, 'medium': 1, 'low': 1, 'blocked': 3}

    if DB_AVAILABLE:
        try:
            db = get_db()
            summary = db.get_threat_summary(hours=24)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify(summary)
