#!/usr/bin/env python3
"""
AIOCHI Bubble Manager Entrypoint

This is the main entry point for the aiochi-bubble container.
It runs the D2D communication tracking using Zeek logs.

Key features:
- Reads mDNS from Zeek dns.log (ecosystem detection)
- Reads conn.log for D2D communication patterns
- Exposes REST API for fts-web to get device communication colors
- Bubbles are MANUAL (created by users in fts-web)
- D2D data helps users see which devices communicate (for bubble decisions)

Usage:
    python3 bubble_entrypoint.py
"""

import asyncio
import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

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
        "zeek_dns_log": os.environ.get("ZEEK_DNS_LOG", "/opt/zeek/logs/dns.log"),
        "zeek_conn_log": os.environ.get("ZEEK_CONN_LOG", "/opt/zeek/logs/conn.log"),
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
        logger.error(f"Error listing devices: {e}")
        return jsonify({"error": str(e), "devices": []}), 500


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
        logger.error(f"Error getting device {mac}: {e}")
        return jsonify({"error": str(e)}), 500


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
        logger.error(f"Error getting communication graph: {e}")
        return jsonify({"error": str(e)}), 500


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
        logger.error(f"Error getting communication clusters: {e}")
        return jsonify({"error": str(e)}), 500


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
        logger.error(f"Error getting communication strength: {e}")
        return jsonify({"error": str(e)}), 500


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
        logger.error(f"Error getting stats: {e}")
        return jsonify({"error": str(e)}), 500


def run_health_server():
    """Run Flask health server in background thread."""
    app.run(host="0.0.0.0", port=8070, threaded=True, use_reloader=False)


def watch_zeek_logs():
    """Watch Zeek logs for mDNS events (ecosystem detection)."""
    # Import parser
    try:
        from shared.aiochi.bubble.zeek_mdns_parser import ZeekMDNSParser
    except ImportError:
        # Fallback to direct import
        sys.path.insert(0, "/opt/hookprobe/shared/aiochi/bubble")
        from zeek_mdns_parser import ZeekMDNSParser

    dns_log = os.environ.get("ZEEK_DNS_LOG", "/opt/zeek/logs/current/dns.log")
    logger.info(f"Starting mDNS watcher on: {dns_log}")

    parser = ZeekMDNSParser(dns_log)
    _health_status["status"] = "running"

    # Get D2D tracker
    tracker = get_d2d_tracker()

    # Check if Zeek logs exist
    if not Path(dns_log).exists():
        logger.warning(f"Zeek dns.log not found at {dns_log} - waiting for Zeek to start")
        _health_status["status"] = "waiting_for_zeek"

    try:
        for event in parser.watch(poll_interval=2.0):
            _health_status["mdns_events"] += 1
            _health_status["last_event"] = event.to_dict()
            _health_status["status"] = "running"

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

    except Exception as e:
        logger.error(f"Error in mDNS watcher: {e}")
        _health_status["status"] = f"error: {e}"


def watch_connections():
    """Watch Zeek conn.log for device-to-device connections."""
    import json

    conn_log = Path(os.environ.get("ZEEK_CONN_LOG", "/opt/zeek/logs/current/conn.log"))
    logger.info(f"Starting connection watcher on: {conn_log}")

    # Get D2D tracker
    tracker = get_d2d_tracker()
    if tracker:
        logger.info("D2D tracker ready for connection tracking")
    else:
        logger.warning("D2D tracker not available - connection counts only")

    # Track file position and inode for rotation handling
    position = 0
    last_inode = None
    conn_fields = None  # TSV field names
    save_interval = 60  # Save state every 60 seconds
    last_save = time.time()

    # Local network prefixes for D2D detection
    LOCAL_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                      '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                      '172.30.', '172.31.', '192.168.')

    def is_local_ip(ip: str) -> bool:
        """Check if IP is in local network range."""
        return ip and any(ip.startswith(p) for p in LOCAL_PREFIXES)

    def parse_conn_line(line: str, fields: list) -> dict:
        """Parse TSV conn.log line into dict."""
        if not fields:
            return {}
        values = line.split('\t')
        if len(values) != len(fields):
            return {}
        return {fields[i]: values[i] for i in range(len(fields))}

    while True:
        try:
            if not conn_log.exists():
                time.sleep(5)
                continue

            # Check for log rotation (inode change)
            current_inode = conn_log.stat().st_ino
            if last_inode is not None and current_inode != last_inode:
                logger.info("conn.log rotated, resetting position")
                position = 0
                conn_fields = None
            last_inode = current_inode

            with open(conn_log) as f:
                f.seek(position)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Parse TSV header
                    if line.startswith('#fields'):
                        conn_fields = line.split('\t')[1:]  # Skip '#fields'
                        logger.info(f"conn.log fields: {len(conn_fields)} columns")
                        continue
                    elif line.startswith('#'):
                        continue

                    # Parse record (JSON or TSV)
                    conn = {}
                    if line.startswith('{'):
                        try:
                            conn = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                    else:
                        conn = parse_conn_line(line, conn_fields)
                        if not conn:
                            continue

                    # Handle both field name formats
                    src_ip = conn.get('id.orig_h', '')
                    dst_ip = conn.get('id.resp_h', '')
                    proto = conn.get('proto', '')
                    service = conn.get('service', '')

                    # Handle Zeek unset values
                    if service == '-':
                        service = ''

                    # Detect D2D connections (both IPs are local)
                    if is_local_ip(src_ip) and is_local_ip(dst_ip):
                        _health_status['d2d_connections'] += 1

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

                position = f.tell()

            # Periodically save state
            if tracker and time.time() - last_save > save_interval:
                tracker.save_state()
                last_save = time.time()

        except Exception as e:
            logger.error(f"Error in connection watcher: {e}")

        time.sleep(2)


def main():
    """Main entry point."""
    logger.info("=" * 60)
    logger.info("AIOCHI Bubble Manager Starting")
    logger.info("=" * 60)
    logger.info(f"Zeek DNS log: {os.environ.get('ZEEK_DNS_LOG')}")
    logger.info(f"Zeek Conn log: {os.environ.get('ZEEK_CONN_LOG')}")
    logger.info("Using Zeek logs (no host network required)")
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

    # Start watchers
    with ThreadPoolExecutor(max_workers=2) as executor:
        mdns_future = executor.submit(watch_zeek_logs)
        conn_future = executor.submit(watch_connections)

        # Wait for shutdown
        while not shutdown_event.is_set():
            time.sleep(1)

            # Check if watchers died
            if mdns_future.done():
                exc = mdns_future.exception()
                if exc:
                    logger.error(f"mDNS watcher died: {exc}")
                    mdns_future = executor.submit(watch_zeek_logs)

    logger.info("AIOCHI Bubble Manager stopped")


if __name__ == "__main__":
    main()
