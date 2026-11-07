#!/usr/bin/env python3
"""
AIOCHI Bubble Manager Entrypoint

This is the main entry point for the aiochi-bubble container.
It runs the D2D communication tracking using the NAPSE event bus.

Key features:
- Reads mDNS from NAPSE event bus (ecosystem detection)
- Reads connection events from NAPSE for D2D communication patterns
- Exposes REST API for fts-web to get device communication colors
- Bubbles are MANUAL (created by users in fts-web)
- D2D data helps users see which devices communicate (for bubble decisions)

Usage:
    python3 bubble_entrypoint.py
"""

import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Flask for health endpoint
from flask import Flask, jsonify, request

# Configure logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("aiochi-bubble")

# Health check app
app = Flask(__name__)
_health_status = {
    "status": "starting",
    "started_at": datetime.now().isoformat(),
    "ids_engine": "napse",
    "mdns_events": 0,
    "d2d_connections": 0,
    "last_event": None,
}


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify(_health_status)


@app.route("/status")
def status():
    """Detailed status endpoint."""
    return jsonify({
        **_health_status,
        "engine": "napse",
    })


# ==============================================================================
# D2D Tracker for FTS Web Integration
# ==============================================================================
_d2d_tracker = None


def get_d2d_tracker():
    """Get or create the D2D tracker singleton."""
    global _d2d_tracker
    if _d2d_tracker is None:
        try:
            from d2d_tracker import get_d2d_tracker as _get_tracker
            _d2d_tracker = _get_tracker()
            logger.info("D2D tracker initialized")
        except Exception as e:
            logger.warning(f"Could not initialize D2D tracker: {e}")
    return _d2d_tracker


# ==============================================================================
# REST API for FTS Web Integration
# ==============================================================================

@app.route("/api/devices", methods=["GET"])
def list_devices():
    """List all known devices with ecosystem colors."""
    try:
        tracker = get_d2d_tracker()
        if not tracker:
            return jsonify({"error": "D2D tracker not available", "devices": []}), 503

        devices = tracker.get_all_devices()
        return jsonify({
            "devices": [d.to_dict() for d in devices],
            "count": len(devices)
        })
    except Exception as e:
        logger.exception("Error listing devices")
        return jsonify({"error": "Failed to list devices", "devices": []}), 500


@app.route("/api/devices/<mac>", methods=["GET"])
def get_device(mac):
    """Get device info with communication colors."""
    try:
        tracker = get_d2d_tracker()
        if not tracker:
            return jsonify({"error": "D2D tracker not available"}), 503

        # Get device with full communication info for coloring
        info = tracker.get_device_communication_color(mac)
        return jsonify(info)
    except Exception as e:
        logger.exception("Error getting device info")
        return jsonify({"error": "Failed to get device info"}), 500


@app.route("/api/communication/graph", methods=["GET"])
def get_communication_graph():
    """Get full communication graph (nodes and edges) for visualization."""
    try:
        tracker = get_d2d_tracker()
        if not tracker:
            return jsonify({"error": "D2D tracker not available"}), 503

        graph = tracker.get_communication_graph()
        return jsonify(graph)
    except Exception as e:
        logger.exception("Error getting communication graph")
        return jsonify({"error": "Failed to get communication graph"}), 500


@app.route("/api/communication/clusters", methods=["GET"])
def get_communication_clusters():
    """Get clusters of devices that communicate with each other."""
    try:
        tracker = get_d2d_tracker()
        if not tracker:
            return jsonify({"error": "D2D tracker not available"}), 503

        clusters = tracker.get_communication_clusters()
        return jsonify({
            "clusters": clusters,
            "count": len(clusters)
        })
    except Exception as e:
        logger.exception("Error getting communication clusters")
        return jsonify({"error": "Failed to get communication clusters"}), 500


@app.route("/api/communication/<mac1>/<mac2>", methods=["GET"])
def get_communication_strength(mac1, mac2):
    """Get communication strength between two devices."""
    try:
        tracker = get_d2d_tracker()
        if not tracker:
            return jsonify({"error": "D2D tracker not available"}), 503

        strength = tracker.get_communication_strength(mac1, mac2)
        return jsonify({
            "mac1": mac1,
            "mac2": mac2,
            "strength": strength.value,
        })
    except Exception as e:
        logger.exception("Error getting communication strength")
        return jsonify({"error": "Failed to get communication strength"}), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get D2D tracker statistics."""
    try:
        tracker = get_d2d_tracker()
        if not tracker:
            return jsonify({"error": "D2D tracker not available"}), 503

        stats = tracker.get_stats()
        stats.update(_health_status)
        return jsonify(stats)
    except Exception as e:
        logger.exception("Error getting stats")
        return jsonify({"error": "Failed to get stats"}), 500


def run_health_server():
    """Run Flask health server in background thread."""
    app.run(host="0.0.0.0", port=8070, threaded=True, use_reloader=False)


def watch_napse_mdns():
    """Watch NAPSE event bus for mDNS events (ecosystem detection)."""
    from core.napse.synthesis.bubble_feed import BubbleFeed
    from shared.aiochi.bubble.mdns_parser import MDNSParser

    logger.info("Starting mDNS watcher via NAPSE event bus")

    parser = MDNSParser()
    tracker = get_d2d_tracker()
    _health_status["status"] = "running"

    def handle_mdns(record):
        """Callback for NAPSE MDNSRecord events."""
        event = parser.process_napse_mdns(record)
        if not event:
            return

        _health_status["mdns_events"] += 1
        _health_status["last_event"] = event.to_dict()

        logger.debug(
            f"mDNS: [{event.ecosystem}] {event.source_ip} -> {event.query}"
        )

        # Feed to D2D tracker for ecosystem detection
        if tracker:
            try:
                tracker.record_mdns_event(
                    source_mac=event.source_mac,
                    source_ip=event.source_ip,
                    query=event.query,
                    ecosystem=event.ecosystem,
                    hostname=getattr(event, 'hostname', ''),
                )
            except Exception as e:
                logger.debug(f"Could not record mDNS event: {e}")

    return handle_mdns


def watch_napse_connections():
    """Watch NAPSE event bus for D2D connection events."""
    from shared.aiochi.bubble.connection_graph import ConnectionGraphAnalyzer

    logger.info("Starting connection watcher via NAPSE event bus")

    # Local network prefixes for D2D detection
    LOCAL_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                      '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                      '172.30.', '172.31.', '192.168.')

    tracker = get_d2d_tracker()

    def handle_connection(record):
        """Callback for NAPSE ConnectionRecord events."""
        src_ip = getattr(record, 'id_orig_h', '')
        dst_ip = getattr(record, 'id_resp_h', '')

        # Only track D2D connections (both IPs are local)
        if not (src_ip and any(src_ip.startswith(p) for p in LOCAL_PREFIXES)):
            return
        if not (dst_ip and any(dst_ip.startswith(p) for p in LOCAL_PREFIXES)):
            return

        _health_status['d2d_connections'] += 1

        service = getattr(record, 'service', '') or ''
        proto = getattr(record, 'proto', '') or ''
        logger.debug(f"D2D: {src_ip} -> {dst_ip} ({service or proto})")

        # Feed to D2D tracker
        if tracker:
            try:
                tracker.record_d2d_connection(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    service=service or proto,
                )
            except Exception as e:
                logger.debug(f"Could not record D2D: {e}")

    return handle_connection


def run_napse_event_loop():
    """
    Connect to NAPSE event bus and run the event loop.

    Registers BubbleFeed with callbacks for mDNS and connection events.
    """
    from core.napse.synthesis.event_bus import NapseEventBus
    from core.napse.synthesis.bubble_feed import BubbleFeed

    logger.info("Connecting to NAPSE event bus...")

    # Create callbacks
    mdns_handler = watch_napse_mdns()
    conn_handler = watch_napse_connections()

    # Create BubbleFeed and register with event bus
    feed = BubbleFeed(
        connection_callback=conn_handler,
        mdns_callback=mdns_handler,
    )

    # Get or create event bus instance
    event_bus = NapseEventBus.get_instance()
    feed.register(event_bus)

    logger.info("BubbleFeed registered with NAPSE event bus")
    _health_status["status"] = "running"

    # Keep the thread alive — events arrive via callbacks
    while True:
        time.sleep(60)

        # Periodic state save
        tracker = get_d2d_tracker()
        if tracker:
            try:
                tracker.save_state()
            except Exception as e:
                logger.debug(f"Could not save state: {e}")


def main():
    """Main entry point."""
    logger.info("=" * 60)
    logger.info("AIOCHI Bubble Manager Starting")
    logger.info("=" * 60)
    logger.info("IDS Engine: NAPSE (event bus)")
    logger.info("=" * 60)

    # Handle shutdown
    shutdown_event = threading.Event()

    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Start health server in background
    health_thread = threading.Thread(target=run_health_server, daemon=True)
    health_thread.start()
    logger.info("Health endpoint available at http://0.0.0.0:8070/health")

    # Start NAPSE event loop
    with ThreadPoolExecutor(max_workers=1) as executor:
        napse_future = executor.submit(run_napse_event_loop)

        # Wait for shutdown
        while not shutdown_event.is_set():
            time.sleep(1)

            # Check if event loop died
            if napse_future.done():
                exc = napse_future.exception()
                if exc:
                    logger.error(f"NAPSE event loop died: {exc}")
                    _health_status["status"] = f"error: {exc}"
                    napse_future = executor.submit(run_napse_event_loop)

    logger.info("AIOCHI Bubble Manager stopped")


if __name__ == "__main__":
    main()
