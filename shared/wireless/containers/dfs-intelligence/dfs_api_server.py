#!/usr/bin/env python3
"""
HookProbe DFS Intelligence API Server
=====================================

REST API for DFS intelligence service, enabling bash scripts to
communicate with the containerized ML engine.

Endpoints:
  GET  /health              Health check
  GET  /status              ML system status
  POST /score               Score a channel
  POST /best                Get best channel recommendation
  GET  /rank                Rank all channels
  POST /radar               Log radar event
  POST /train               Train ML model
  GET  /nop                 Get NOP channels
  GET  /history             Get radar history

Author: HookProbe Team
License: AGPL-3.0
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify

# Import DFS intelligence module
# Module is at shared/wireless/dfs_intelligence.py, PYTHONPATH includes /opt/hookprobe
from shared.wireless.dfs_intelligence import (
    DFSDatabase,
    ChannelScorer,
    DFSMLTrainer,
    CHANNEL_INFO,
    DEFAULT_WEIGHTS,
    HAS_SKLEARN,
    HAS_NUMPY
)

# Configuration
API_HOST = os.environ.get("DFS_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("DFS_API_PORT", "8767"))
DB_PATH = os.environ.get("DFS_DB_PATH", "/var/lib/hookprobe/dfs_intelligence.db")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize database and scorer
db = DFSDatabase(DB_PATH)
scorer = ChannelScorer(db)
trainer = DFSMLTrainer(db)


# ============================================================
# Health & Status Endpoints
# ============================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "dfs-intelligence"
    })


@app.route('/status', methods=['GET'])
def status():
    """Get ML system status."""
    model_path = os.environ.get("DFS_MODEL_PATH", "/var/lib/hookprobe/dfs_model.json")
    model_trained = os.path.exists(model_path)
    model_info = {}

    if model_trained:
        try:
            with open(model_path, 'r') as f:
                model_info = json.load(f)
        except Exception:
            pass

    return jsonify({
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "ml_available": HAS_SKLEARN and HAS_NUMPY,
        "sklearn_installed": HAS_SKLEARN,
        "numpy_installed": HAS_NUMPY,
        "model_trained": model_trained,
        "model_info": model_info,
        "database_path": DB_PATH,
        "weights": DEFAULT_WEIGHTS
    })


# ============================================================
# Channel Scoring Endpoints
# ============================================================

@app.route('/score', methods=['POST'])
def score_channel():
    """
    Score a specific channel.

    Request body:
        {"channel": 52, "hour": 14}

    Response:
        {"channel": 52, "score": 0.75, "recommendation": "...", ...}
    """
    data = request.get_json() or {}
    channel = data.get('channel')
    hour = data.get('hour')

    if channel is None:
        return jsonify({"error": "channel required"}), 400

    if channel not in CHANNEL_INFO:
        return jsonify({"error": f"invalid channel: {channel}"}), 400

    try:
        result = scorer.score_channel(int(channel), hour)
        return jsonify({
            "channel": result.channel,
            "score": round(result.total_score, 4),
            "confidence": round(result.confidence, 4),
            "is_in_nop": result.is_in_nop,
            "nop_remaining_sec": result.nop_remaining_sec,
            "recommendation": result.recommendation,
            "component_scores": {
                k: round(v, 4) for k, v in result.component_scores.items()
            }
        })
    except Exception as e:
        logger.error(f"Error scoring channel {channel}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/best', methods=['POST'])
def best_channel():
    """
    Get best channel recommendation.

    Request body:
        {
            "prefer_dfs": true,
            "min_bandwidth": 80,
            "exclude": [100, 104]
        }

    Response:
        {"channel": 52, "score": 0.85, ...}
    """
    data = request.get_json() or {}
    prefer_dfs = data.get('prefer_dfs', False)
    min_bandwidth = data.get('min_bandwidth', 20)
    exclude = data.get('exclude', [])

    try:
        result = scorer.choose_best_channel(
            prefer_dfs=prefer_dfs,
            min_bandwidth=min_bandwidth,
            exclude_channels=exclude
        )
        info = CHANNEL_INFO.get(result.channel, {})

        return jsonify({
            "channel": result.channel,
            "score": round(result.total_score, 4),
            "confidence": round(result.confidence, 4),
            "recommendation": result.recommendation,
            "band": info.get("band", "unknown"),
            "max_bandwidth": info.get("max_bw", 20),
            "is_dfs": info.get("dfs", False),
            "cac_time": info.get("cac", 0)
        })
    except Exception as e:
        logger.error(f"Error getting best channel: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/rank', methods=['GET'])
def rank_channels():
    """
    Rank all channels.

    Query params:
        include_dfs: true/false (default: true)
        include_unii3: true/false (default: false)
        limit: number of results (default: all)

    Response:
        {"rankings": [{"channel": 36, "score": 0.95, ...}, ...]}
    """
    include_dfs = request.args.get('include_dfs', 'true').lower() == 'true'
    include_unii3 = request.args.get('include_unii3', 'false').lower() == 'true'
    limit = request.args.get('limit', type=int)

    try:
        rankings = scorer.rank_all_channels(
            include_dfs=include_dfs,
            include_unii3=include_unii3
        )

        if limit:
            rankings = rankings[:limit]

        results = []
        for score in rankings:
            info = CHANNEL_INFO.get(score.channel, {})
            results.append({
                "channel": score.channel,
                "score": round(score.total_score, 4),
                "band": info.get("band", "unknown"),
                "is_in_nop": score.is_in_nop,
                "nop_remaining_sec": score.nop_remaining_sec,
                "recommendation": score.recommendation
            })

        return jsonify({"rankings": results})
    except Exception as e:
        logger.error(f"Error ranking channels: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================
# Radar Event Endpoints
# ============================================================

@app.route('/radar', methods=['POST'])
def log_radar():
    """
    Log a radar detection event.

    Request body:
        {
            "channel": 100,
            "frequency": 5500,
            "event_type": "RADAR_DETECTED",
            "raw_payload": "..."
        }

    Response:
        {"event_id": 123, "channel": 100, "nop_added": true}
    """
    data = request.get_json() or {}
    channel = data.get('channel')
    frequency = data.get('frequency')
    event_type = data.get('event_type', 'RADAR_DETECTED')
    raw_payload = data.get('raw_payload')

    if channel is None:
        return jsonify({"error": "channel required"}), 400

    # Get frequency from channel if not provided
    if frequency is None:
        info = CHANNEL_INFO.get(int(channel), {})
        frequency = info.get("freq", 5180)

    try:
        event_id = db.log_radar_event(
            channel=int(channel),
            frequency=int(frequency),
            event_type=event_type,
            raw_payload=raw_payload
        )

        # Add to NOP
        db.add_nop(int(channel), int(frequency), event_id)

        return jsonify({
            "event_id": event_id,
            "channel": channel,
            "frequency": frequency,
            "nop_added": True,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error logging radar event: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/nop', methods=['GET'])
def get_nop():
    """
    Get channels currently in NOP.

    Response:
        {"nop_channels": {"100": 1234, "104": 890}, "count": 2}
    """
    try:
        nop = db.get_nop_channels()
        return jsonify({
            "nop_channels": {str(k): v for k, v in nop.items()},
            "count": len(nop)
        })
    except Exception as e:
        logger.error(f"Error getting NOP channels: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/history', methods=['GET'])
def get_history():
    """
    Get radar event history.

    Query params:
        channel: filter by channel
        limit: max events (default: 50)

    Response:
        {"events": [...], "count": 50}
    """
    channel = request.args.get('channel', type=int)
    limit = request.args.get('limit', 50, type=int)

    try:
        events = db.get_radar_events(channel=channel, limit=limit)
        results = []
        for event in events:
            results.append({
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "channel": event.channel,
                "frequency": event.frequency,
                "event_type": event.event_type
            })

        return jsonify({
            "events": results,
            "count": len(results)
        })
    except Exception as e:
        logger.error(f"Error getting radar history: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================
# ML Training Endpoints
# ============================================================

@app.route('/train', methods=['POST'])
def train_model():
    """
    Train the ML model.

    Request body:
        {"min_samples": 50}

    Response:
        {"success": true, "message": "..."}
    """
    if not HAS_SKLEARN:
        return jsonify({
            "success": False,
            "error": "sklearn not available"
        }), 503

    data = request.get_json() or {}
    min_samples = data.get('min_samples', 50)

    try:
        success = trainer.train(min_samples=min_samples)
        if success:
            return jsonify({
                "success": True,
                "message": "ML model trained successfully",
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "success": False,
                "message": "Training failed (insufficient data or error)"
            }), 400
    except Exception as e:
        logger.error(f"Error training model: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/predict', methods=['POST'])
def predict():
    """
    Get ML prediction for radar probability.

    Request body:
        {"channel": 100, "hour": 14}

    Response:
        {"channel": 100, "probability": 0.23, "risk": "low"}
    """
    if not HAS_SKLEARN:
        return jsonify({
            "error": "sklearn not available",
            "fallback": True,
            "probability": 0.5,
            "risk": "unknown"
        }), 200

    data = request.get_json() or {}
    channel = data.get('channel')
    hour = data.get('hour', datetime.now().hour)

    if channel is None:
        return jsonify({"error": "channel required"}), 400

    try:
        prob = trainer.predict_radar_probability(int(channel), int(hour))

        # Classify risk
        if prob < 0.3:
            risk = "low"
        elif prob < 0.6:
            risk = "medium"
        else:
            risk = "high"

        return jsonify({
            "channel": channel,
            "hour": hour,
            "probability": round(prob, 4),
            "risk": risk
        })
    except Exception as e:
        logger.error(f"Error predicting: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================
# Channel Information Endpoints
# ============================================================

@app.route('/channels', methods=['GET'])
def get_channels():
    """
    Get channel information.

    Query params:
        band: filter by band (UNII-1, UNII-2A, etc.)
        dfs: filter DFS only (true/false)

    Response:
        {"channels": {...}}
    """
    band = request.args.get('band')
    dfs_only = request.args.get('dfs', '').lower() == 'true'

    channels = {}
    for ch, info in CHANNEL_INFO.items():
        if band and info.get("band") != band:
            continue
        if dfs_only and not info.get("dfs"):
            continue
        channels[str(ch)] = info

    return jsonify({"channels": channels})


@app.route('/stats/<int:channel>', methods=['GET'])
def get_channel_stats(channel):
    """
    Get statistics for a specific channel.

    Response:
        {"channel": 100, "stats": {...}, "hourly_pattern": {...}}
    """
    if channel not in CHANNEL_INFO:
        return jsonify({"error": f"invalid channel: {channel}"}), 400

    try:
        stats = db.get_channel_stats(channel)
        pattern = db.get_hourly_pattern(channel)

        return jsonify({
            "channel": channel,
            "info": CHANNEL_INFO.get(channel, {}),
            "stats": stats or {"total_events": 0},
            "hourly_pattern": pattern
        })
    except Exception as e:
        logger.error(f"Error getting channel stats: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================
# Main Entry Point
# ============================================================

def main():
    """Run the API server."""
    logger.info(f"Starting DFS Intelligence API server on {API_HOST}:{API_PORT}")
    logger.info(f"Database: {DB_PATH}")
    logger.info(f"sklearn available: {HAS_SKLEARN}")
    logger.info(f"numpy available: {HAS_NUMPY}")

    # Run with gunicorn in production, Flask dev server for debugging
    if os.environ.get("DFS_DEBUG", "").lower() == "true":
        app.run(host=API_HOST, port=API_PORT, debug=True)
    else:
        # In container, use gunicorn via entrypoint
        app.run(host=API_HOST, port=API_PORT)


if __name__ == "__main__":
    main()
