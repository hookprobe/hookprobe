#!/usr/bin/env python3
"""
AIOCHI Bubble Manager Entrypoint

This is the main entry point for the aiochi-bubble container.
It runs the bubble detection engine using Zeek logs instead of live mDNS capture.

Key differences from Fortress fts-bubble-manager:
- Reads mDNS from Zeek dns.log (no port 5353 binding)
- Uses bridge network (no host network blocking)
- Provides REST API for health checks

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
from flask import Flask, jsonify

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
    "bubbles_detected": 0,
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
        "zeek_dns_log": os.environ.get("ZEEK_DNS_LOG", "/opt/zeek/logs/current/dns.log"),
        "zeek_conn_log": os.environ.get("ZEEK_CONN_LOG", "/opt/zeek/logs/current/conn.log"),
    })


def run_health_server():
    """Run Flask health server in background thread."""
    app.run(host="0.0.0.0", port=8070, threaded=True, use_reloader=False)


def watch_zeek_logs():
    """Watch Zeek logs for mDNS and connection events."""
    # Note: We modify _health_status dict in-place, no global needed

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

            # Record discovery for affinity calculation
            parser.record_discovery(event.source_mac, event.query)

            # TODO: Feed to bubble manager for clustering
            # This will be integrated with the shared/aiochi/bubble/manager.py

    except Exception as e:
        logger.error(f"Error in mDNS watcher: {e}")
        _health_status["status"] = f"error: {e}"


def watch_connections():
    """Watch Zeek conn.log for device-to-device connections."""
    # Note: We modify _health_status dict in-place, no global needed
    import json

    conn_log = Path(os.environ.get("ZEEK_CONN_LOG", "/opt/zeek/logs/current/conn.log"))
    logger.info(f"Starting connection watcher on: {conn_log}")

    # Import connection graph analyzer if available
    manager = None
    try:
        from shared.aiochi.bubble.manager import get_bubble_manager
        manager = get_bubble_manager()
        logger.info("Bubble manager loaded successfully")
    except ImportError:
        logger.warning("Bubble manager not available - connection analysis only")

    # Track file position and inode for rotation handling
    position = 0
    last_inode = None
    connections_processed = 0

    # Local network prefixes for D2D detection
    LOCAL_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                      '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                      '172.30.', '172.31.', '192.168.')

    def is_local_ip(ip: str) -> bool:
        """Check if IP is in local network range."""
        return ip and any(ip.startswith(p) for p in LOCAL_PREFIXES)

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
            last_inode = current_inode

            with open(conn_log) as f:
                f.seek(position)
                for line in f:
                    # Bug fix: was just 'pass' - now actually parse connections
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    try:
                        # Parse Zeek conn.log JSON format
                        conn = json.loads(line)
                        src_ip = conn.get('id.orig_h', '')
                        dst_ip = conn.get('id.resp_h', '')
                        proto = conn.get('proto', '')
                        service = conn.get('service', '')

                        # Detect D2D connections (both IPs are local)
                        if is_local_ip(src_ip) and is_local_ip(dst_ip):
                            connections_processed += 1

                            # Update health status
                            if 'd2d_connections' not in _health_status:
                                _health_status['d2d_connections'] = 0
                            _health_status['d2d_connections'] += 1

                            logger.debug(f"D2D: {src_ip} -> {dst_ip} ({service or proto})")

                            # Feed to bubble manager if available
                            if manager:
                                try:
                                    manager.record_d2d_connection(src_ip, dst_ip, service or proto)
                                except Exception as e:
                                    logger.debug(f"Could not record D2D: {e}")

                    except json.JSONDecodeError:
                        # Skip non-JSON lines (comments, etc.)
                        pass
                    except Exception as e:
                        logger.debug(f"Error parsing conn line: {e}")

                position = f.tell()

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
