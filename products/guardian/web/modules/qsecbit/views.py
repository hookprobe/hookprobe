"""
Qsecbit Live Views - Real-time Unified Unified Engine Integration

Provides simple API endpoints for real-time Qsecbit score display
optimized for Raspberry Pi.
"""
import sys
import logging
from pathlib import Path
from datetime import datetime
from flask import render_template, jsonify, current_app
from . import qsecbit_bp
from utils import _safe_error

logger = logging.getLogger(__name__)

# Try to import Qsecbit Unified UnifiedThreatEngine
UNIFIED_ENGINE_AVAILABLE = False
_unified_engine = None

try:
    # Add core path
    core_path = Path(__file__).parent.parent.parent.parent.parent.parent / 'core'
    sys.path.insert(0, str(core_path))

    from qsecbit import (
        UnifiedThreatEngine,
        UnifiedEngineConfig,
        DeploymentType,
    )
    UNIFIED_ENGINE_AVAILABLE = True
    logger.info("Qsecbit Unified UnifiedThreatEngine available")
except ImportError as e:
    logger.warning(f"Qsecbit Unified not available: {e}")


def get_unified_engine():
    """Get or create the UnifiedThreatEngine singleton."""
    global _unified_engine

    if not UNIFIED_ENGINE_AVAILABLE:
        return None

    if _unified_engine is None:
        try:
            config = UnifiedEngineConfig(
                deployment_type=DeploymentType.GUARDIAN,
                enable_ml_classification=True,
                enable_response_orchestration=False,  # View only
            )
            data_dir = current_app.config.get('DATA_DIR', '/opt/hookprobe/guardian/data')
            _unified_engine = UnifiedThreatEngine(
                config=config,
                data_dir=data_dir
            )
            logger.info("UnifiedThreatEngine initialized for Qsecbit Live view")
        except Exception as e:
            logger.error(f"Failed to initialize UnifiedThreatEngine: {e}")
            return None

    return _unified_engine


@qsecbit_bp.route('/')
def qsecbit_index():
    """Redirect to the simple dashboard."""
    return render_template('qsecbit/dashboard.html')


@qsecbit_bp.route('/live')
def qsecbit_live():
    """Render the embedded Qsecbit Live view."""
    return render_template('qsecbit/live.html')


@qsecbit_bp.route('/dashboard')
def qsecbit_dashboard():
    """Render the simple Qsecbit dashboard - clean standalone view."""
    return render_template('qsecbit/dashboard.html')


@qsecbit_bp.route('/api/score')
def api_qsecbit_score():
    """
    Get current Qsecbit Unified score - optimized for frequent polling.

    Returns a lightweight JSON response with score, status, and layer breakdown.
    """
    try:
        engine = get_unified_engine()

        if engine:
            # Run Unified detection
            result = engine.detect()

            # Build lightweight response
            response = {
                'score': round(result.unified_score, 3),
                'status': _get_rag_status(result.unified_score),
                'timestamp': datetime.now().isoformat(),
                'v6': True,
                'layers': {},
                'threats_active': len(result.threats),
                'attack_chains': len(result.attack_chains) if result.attack_chains else 0,
            }

            # Add layer scores
            for layer_score in result.layer_scores:
                layer_name = layer_score.layer.name.replace('_', '')
                response['layers'][layer_name] = {
                    'score': round(layer_score.score, 3),
                    'threats': layer_score.threat_count,
                    'status': _get_rag_status(layer_score.score)
                }

            # Add energy anomaly if significant
            if hasattr(result, 'energy_anomaly_score') and result.energy_anomaly_score > 0.1:
                response['energy_anomaly'] = round(result.energy_anomaly_score, 3)

            return jsonify(response)

        # Fallback: Read from file if engine not available
        return _get_fallback_score()

    except Exception as e:
        logger.error(f"Error getting Qsecbit score: {e}")
        return jsonify({
            'score': 0.0,
            'status': 'UNKNOWN',
            'error': _safe_error(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@qsecbit_bp.route('/api/threats')
def api_active_threats():
    """Get list of active threats (lightweight)."""
    try:
        engine = get_unified_engine()

        if engine:
            result = engine.detect()
            threats = []

            for threat in result.threats[-10:]:  # Last 10 threats
                threats.append({
                    'type': threat.attack_type.name if threat.attack_type else 'UNKNOWN',
                    'layer': threat.layer.name if threat.layer else 'UNKNOWN',
                    'severity': threat.severity.name if threat.severity else 'MEDIUM',
                    'source': threat.source_ip or 'N/A',
                    'mitre': threat.mitre_attack_id or '',
                    'blocked': bool(threat.response_actions),
                })

            return jsonify({
                'count': len(result.threats),
                'threats': threats,
                'timestamp': datetime.now().isoformat()
            })

        return jsonify({'count': 0, 'threats': [], 'timestamp': datetime.now().isoformat()})

    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        return jsonify({'count': 0, 'threats': [], 'error': _safe_error(e)}), 500


def _get_rag_status(score: float) -> str:
    """Convert score to RAG status."""
    if score >= 0.70:
        return 'RED'
    elif score >= 0.45:
        return 'AMBER'
    return 'GREEN'


def _get_fallback_score():
    """Get score from file when engine not available."""
    import json

    try:
        qsecbit_file = '/var/log/hookprobe/qsecbit/current.json'
        with open(qsecbit_file, 'r') as f:
            data = json.load(f)

        score = data.get('score', 0.0)
        return jsonify({
            'score': score,
            'status': _get_rag_status(score),
            'timestamp': datetime.now().isoformat(),
            'v6': False,
            'layers': data.get('layers', {}),
            'threats_active': data.get('threats', 0),
        })
    except Exception:
        return jsonify({
            'score': 0.0,
            'status': 'GREEN',
            'timestamp': datetime.now().isoformat(),
            'v6': False,
            'layers': {},
            'threats_active': 0,
        })
