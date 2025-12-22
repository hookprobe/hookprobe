#!/usr/bin/env python3
"""
XDP/eBPF DDoS Protection Daemon for Fortress

Provides high-performance packet filtering at the kernel level.
Exposes metrics via Prometheus and HTTP API for IP blocking.

Author: Andrei Toma
License: AGPL-3.0
Version: 5.4.0
"""

import os
import sys
import json
import signal
import time
import logging
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Optional, Dict, Any

# Add parent to path for imports
sys.path.insert(0, '/opt/hookprobe')

from core.qsecbit.xdp_manager import XDPManager, XDPStats

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('xdp-daemon')

# Global XDP manager instance
xdp_manager: Optional[XDPManager] = None


class XDPAPIHandler(BaseHTTPRequestHandler):
    """HTTP API handler for XDP management"""

    def log_message(self, format: str, *args) -> None:
        """Override to use our logger"""
        logger.debug(f"HTTP: {args}")

    def _send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self) -> None:
        """Handle GET requests"""
        global xdp_manager

        if self.path == '/health':
            self._send_json({
                'status': 'healthy',
                'enabled': xdp_manager.enabled if xdp_manager else False,
                'interface': xdp_manager.interface if xdp_manager else None
            })

        elif self.path == '/stats':
            if xdp_manager and xdp_manager.enabled:
                stats = xdp_manager.get_stats()
                if stats:
                    self._send_json({
                        'total_packets': stats.total_packets,
                        'dropped_blocked': stats.dropped_blocked,
                        'dropped_rate_limit': stats.dropped_rate_limit,
                        'dropped_malformed': stats.dropped_malformed,
                        'passed': stats.passed,
                        'tcp_syn_flood': stats.tcp_syn_flood,
                        'udp_flood': stats.udp_flood,
                        'icmp_flood': stats.icmp_flood,
                        'timestamp': stats.timestamp.isoformat()
                    })
                else:
                    self._send_json({'error': 'Could not get stats'}, 500)
            else:
                self._send_json({'error': 'XDP not enabled'}, 503)

        elif self.path == '/metrics':
            # Prometheus metrics format
            if xdp_manager and xdp_manager.enabled:
                stats = xdp_manager.get_stats()
                if stats:
                    metrics = [
                        f'# HELP xdp_packets_total Total packets processed',
                        f'# TYPE xdp_packets_total counter',
                        f'xdp_packets_total {stats.total_packets}',
                        f'# HELP xdp_packets_dropped_blocked Packets dropped (blocked IP)',
                        f'# TYPE xdp_packets_dropped_blocked counter',
                        f'xdp_packets_dropped_blocked {stats.dropped_blocked}',
                        f'# HELP xdp_packets_dropped_ratelimit Packets dropped (rate limit)',
                        f'# TYPE xdp_packets_dropped_ratelimit counter',
                        f'xdp_packets_dropped_ratelimit {stats.dropped_rate_limit}',
                        f'# HELP xdp_packets_dropped_malformed Packets dropped (malformed)',
                        f'# TYPE xdp_packets_dropped_malformed counter',
                        f'xdp_packets_dropped_malformed {stats.dropped_malformed}',
                        f'# HELP xdp_packets_passed Packets passed',
                        f'# TYPE xdp_packets_passed counter',
                        f'xdp_packets_passed {stats.passed}',
                        f'# HELP xdp_syn_flood_detected SYN flood packets detected',
                        f'# TYPE xdp_syn_flood_detected counter',
                        f'xdp_syn_flood_detected {stats.tcp_syn_flood}',
                        f'# HELP xdp_udp_flood_detected UDP flood packets detected',
                        f'# TYPE xdp_udp_flood_detected counter',
                        f'xdp_udp_flood_detected {stats.udp_flood}',
                        f'# HELP xdp_icmp_flood_detected ICMP flood packets detected',
                        f'# TYPE xdp_icmp_flood_detected counter',
                        f'xdp_icmp_flood_detected {stats.icmp_flood}',
                    ]
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; version=0.0.4')
                    self.end_headers()
                    self.wfile.write('\n'.join(metrics).encode())
                else:
                    self._send_json({'error': 'Could not get stats'}, 500)
            else:
                self._send_json({'error': 'XDP not enabled'}, 503)

        else:
            self._send_json({'error': 'Not found'}, 404)

    def do_POST(self) -> None:
        """Handle POST requests"""
        global xdp_manager

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else '{}'

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json({'error': 'Invalid JSON'}, 400)
            return

        if self.path == '/block':
            ip = data.get('ip')
            if not ip:
                self._send_json({'error': 'Missing ip parameter'}, 400)
                return

            if xdp_manager and xdp_manager.enabled:
                if xdp_manager.block_ip(ip):
                    logger.info(f"Blocked IP: {ip}")
                    self._send_json({'status': 'blocked', 'ip': ip})
                else:
                    self._send_json({'error': f'Failed to block {ip}'}, 500)
            else:
                self._send_json({'error': 'XDP not enabled'}, 503)

        elif self.path == '/unblock':
            ip = data.get('ip')
            if not ip:
                self._send_json({'error': 'Missing ip parameter'}, 400)
                return

            if xdp_manager and xdp_manager.enabled:
                if xdp_manager.unblock_ip(ip):
                    logger.info(f"Unblocked IP: {ip}")
                    self._send_json({'status': 'unblocked', 'ip': ip})
                else:
                    self._send_json({'error': f'Failed to unblock {ip}'}, 500)
            else:
                self._send_json({'error': 'XDP not enabled'}, 503)

        else:
            self._send_json({'error': 'Not found'}, 404)


def run_http_server(port: int = 9091) -> None:
    """Run HTTP API server"""
    server = HTTPServer(('0.0.0.0', port), XDPAPIHandler)
    logger.info(f"HTTP API server listening on port {port}")
    server.serve_forever()


def signal_handler(signum, frame) -> None:
    """Handle shutdown signals"""
    global xdp_manager
    logger.info(f"Received signal {signum}, shutting down...")
    if xdp_manager:
        xdp_manager.unload_program()
    sys.exit(0)


def main() -> None:
    """Main entry point"""
    global xdp_manager

    parser = argparse.ArgumentParser(description='XDP DDoS Protection Daemon')
    parser.add_argument('--interface', '-i',
                       default=os.environ.get('XDP_INTERFACE', 'FTS'),
                       help='Network interface to attach XDP program')
    parser.add_argument('--port', '-p', type=int,
                       default=int(os.environ.get('XDP_API_PORT', '9091')),
                       help='HTTP API port')
    parser.add_argument('--stats-interval', '-s', type=int,
                       default=int(os.environ.get('XDP_STATS_INTERVAL', '30')),
                       help='Stats logging interval in seconds')

    args = parser.parse_args()

    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logger.info(f"Starting XDP DDoS Protection Daemon")
    logger.info(f"Interface: {args.interface}")
    logger.info(f"API Port: {args.port}")

    # Initialize XDP manager
    xdp_manager = XDPManager(interface=args.interface, auto_detect=True)

    # Load XDP program
    if not xdp_manager.load_program():
        logger.error("Failed to load XDP program")
        sys.exit(1)

    logger.info("XDP program loaded successfully")

    # Start HTTP API server in background thread
    api_thread = Thread(target=run_http_server, args=(args.port,), daemon=True)
    api_thread.start()

    # Main loop - log stats periodically
    try:
        while True:
            time.sleep(args.stats_interval)

            stats = xdp_manager.get_stats()
            if stats:
                logger.info(
                    f"Stats: total={stats.total_packets} passed={stats.passed} "
                    f"blocked={stats.dropped_blocked} ratelimit={stats.dropped_rate_limit} "
                    f"syn_flood={stats.tcp_syn_flood} udp_flood={stats.udp_flood}"
                )
    except KeyboardInterrupt:
        logger.info("Interrupted, shutting down...")
    finally:
        if xdp_manager:
            xdp_manager.unload_program()


if __name__ == '__main__':
    main()
