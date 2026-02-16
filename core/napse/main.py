"""
NAPSE Main - Neural Adaptive Packet Synthesis Engine Entry Point

Orchestrates the 3-layer NAPSE architecture:
    Layer 0: eBPF/XDP kernel fast path (loaded via BCC)
    Layer 1: Rust protocol engine (via PyO3 napse_engine module)
    Layer 2: Python event synthesis (event bus, ClickHouse, metrics)

Usage:
    PYTHONPATH=/opt python -m napse --config /opt/napse/config/napse.yaml

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional

import yaml

from . import TIER_SENTINEL, TIER_GUARDIAN, TIER_FORTRESS, TIER_NEXUS

logger = logging.getLogger('napse')


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    'tier': 'fortress',
    'interface': 'eth0',
    'clickhouse': {
        'host': 'localhost',
        'port': 8123,
        'database': 'hookprobe_ids',
    },
    'signatures': {
        'paths': [],
    },
    'metrics': {
        'port': 9092,
    },
    'event_bus': {
        'queue_size': 10000,
    },
    'engine': {
        'poll_interval_ms': 10,
        'conn_expiry_interval_s': 30,
    },
}


def load_config(path: Optional[str]) -> Dict[str, Any]:
    """Load YAML config, falling back to defaults."""
    config = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path) as f:
            user_config = yaml.safe_load(f) or {}
        _deep_merge(config, user_config)
        logger.info("Loaded config from %s", path)
    else:
        logger.info("Using default configuration")

    # Environment overrides
    config['tier'] = os.getenv('NAPSE_TIER', config['tier'])
    config['interface'] = os.getenv('NAPSE_INTERFACE', config['interface'])
    ch_host = os.getenv('CLICKHOUSE_HOST')
    if ch_host:
        config['clickhouse']['host'] = ch_host
    ch_port = os.getenv('CLICKHOUSE_PORT')
    if ch_port:
        config['clickhouse']['port'] = int(ch_port)
    ch_db = os.getenv('CLICKHOUSE_DATABASE')
    if ch_db:
        config['clickhouse']['database'] = ch_db

    return config


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


# ---------------------------------------------------------------------------
# Metrics HTTP server
# ---------------------------------------------------------------------------

class MetricsHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for /metrics and /health endpoints."""

    metrics_ref = None  # Set by NapseOrchestrator
    engine_ref = None

    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            health = {
                'status': 'ok',
                'engine': 'napse',
                'version': '1.0.0',
                'uptime_s': int(time.time() - self.server.start_time),
            }
            self.wfile.write(json.dumps(health).encode())
        elif self.path == '/metrics':
            if self.metrics_ref:
                body = self.metrics_ref.to_prometheus()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; version=0.0.4')
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(503)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default access logs


# ---------------------------------------------------------------------------
# Packet capture via raw socket
# ---------------------------------------------------------------------------

def open_raw_socket(interface: str) -> socket.socket:
    """Open a raw AF_PACKET socket on the given interface."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    sock.settimeout(0.1)
    return sock


# ---------------------------------------------------------------------------
# NapseOrchestrator
# ---------------------------------------------------------------------------

class NapseOrchestrator:
    """
    Main orchestrator wiring all NAPSE subsystems together.

    Lifecycle:
        1. __init__: Parse config, create event bus
        2. setup(): Import and wire Rust engine + Python synthesis modules
        3. run(): Start metrics server, packet capture loop
        4. shutdown(): Graceful stop
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tier = config['tier']
        self._running = False
        self._engine = None
        self._event_bus = None
        self._ch_shipper = None
        self._metrics = None
        self._metrics_server = None
        self._metrics_thread = None

    def setup(self) -> None:
        """Initialize all subsystems."""
        logger.info("NAPSE %s tier initializing...", self.tier.upper())

        # Layer 2: Event bus
        from .synthesis.event_bus import NapseEventBus
        self._event_bus = NapseEventBus(
            max_queue_size=self.config['event_bus']['queue_size']
        )

        # Layer 1: Rust protocol engine
        try:
            from napse_engine import NapseEngine
            self._engine = NapseEngine()
            logger.info("Rust NapseEngine loaded")
        except ImportError:
            logger.warning(
                "napse_engine not available — running in synthesis-only mode. "
                "Build with: cd engine && maturin develop --release"
            )
            self._engine = None

        # Synthesis modules — ClickHouse shipper
        ch_cfg = self.config['clickhouse']
        from .synthesis.clickhouse_shipper import ClickHouseShipper
        self._ch_shipper = ClickHouseShipper(
            host=ch_cfg['host'],
            port=ch_cfg['port'],
            database=ch_cfg['database'],
        )
        self._ch_shipper.register(self._event_bus)

        # Metrics collector
        from .synthesis.metrics import NapseMetrics
        self._metrics = NapseMetrics()
        self._metrics.register(self._event_bus)

        # Load signatures if engine is available
        if self._engine:
            for sig_path in self.config['signatures'].get('paths', []):
                if os.path.exists(sig_path):
                    count = self._engine.load_signatures(sig_path)
                    logger.info("Loaded %d signatures from %s", count, sig_path)

            self._engine.start()

        logger.info("NAPSE setup complete (tier=%s, engine=%s)",
                     self.tier, 'rust' if self._engine else 'synthesis-only')

    def run(self) -> None:
        """Start the main processing loop."""
        self._running = True

        # Start metrics HTTP server
        self._start_metrics_server()

        # Main packet processing loop
        if self._engine:
            self._run_capture_loop()
        else:
            self._run_synthesis_only()

    def _start_metrics_server(self) -> None:
        """Start the metrics/health HTTP server in a background thread."""
        port = self.config['metrics']['port']
        MetricsHandler.metrics_ref = self._metrics
        MetricsHandler.engine_ref = self._engine

        try:
            server = HTTPServer(('0.0.0.0', port), MetricsHandler)
            server.start_time = time.time()
            self._metrics_server = server

            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            self._metrics_thread = t
            logger.info("Metrics server listening on :%d", port)
        except OSError as e:
            logger.warning("Could not start metrics server on :%d: %s", port, e)

    def _run_capture_loop(self) -> None:
        """Capture packets from raw socket and feed to Rust engine."""
        interface = self.config['interface']
        poll_ms = self.config['engine']['poll_interval_ms']

        logger.info("Starting packet capture on %s", interface)
        try:
            sock = open_raw_socket(interface)
        except PermissionError:
            logger.error(
                "Cannot open raw socket on %s — need CAP_NET_RAW. "
                "Run with: --cap-add NET_RAW", interface
            )
            self._run_synthesis_only()
            return
        except OSError as e:
            logger.error("Cannot bind to %s: %s", interface, e)
            self._run_synthesis_only()
            return

        try:
            while self._running:
                try:
                    data, _addr = sock.recvfrom(65535)
                except socket.timeout:
                    # Periodic maintenance
                    self._drain_engine_events()
                    self._ch_shipper.flush()
                    continue

                ts = time.time()

                # Skip ethernet header (14 bytes) to get IP header
                if len(data) > 14:
                    self._engine.process_packet(data[14:], ts)

                # Drain events from engine periodically
                self._drain_engine_events()

        except KeyboardInterrupt:
            logger.info("Capture interrupted")
        finally:
            sock.close()

    def _drain_engine_events(self) -> None:
        """Drain all pending events from Rust engine into the event bus."""
        if not self._engine or not self._event_bus:
            return

        from .synthesis.event_bus import EventType

        # Drain connection records
        for rec in self._engine.drain_connection_records():
            self._event_bus.emit(EventType.CONNECTION, rec)

        # Drain DNS records
        for rec in self._engine.drain_dns_records():
            self._event_bus.emit(EventType.DNS, rec)

        # Drain HTTP records
        for rec in self._engine.drain_http_records():
            self._event_bus.emit(EventType.HTTP, rec)

        # Drain TLS records
        for rec in self._engine.drain_tls_records():
            self._event_bus.emit(EventType.TLS, rec)

        # Drain DHCP records
        for rec in self._engine.drain_dhcp_records():
            self._event_bus.emit(EventType.DHCP, rec)

        # Drain alerts
        for alert in self._engine.drain_alerts():
            self._event_bus.emit(EventType.ALERT, alert)

        # Drain notices
        for notice in self._engine.drain_notices():
            self._event_bus.emit(EventType.NOTICE, notice)

        # Update engine stats in metrics
        if self._metrics:
            stats = self._engine.get_stats()
            self._metrics.update_engine_stats(
                active_connections=stats.get('connections_tracked', 0),
                signature_matches=stats.get('alerts_generated', 0),
            )

    def _run_synthesis_only(self) -> None:
        """Run in synthesis-only mode (no Rust engine).

        Useful for development or when running alongside an external
        IDS that writes EVE JSON logs.
        """
        logger.info("Running in synthesis-only mode — waiting for events")
        try:
            while self._running:
                time.sleep(1.0)
                if self._ch_shipper:
                    self._ch_shipper.flush()
        except KeyboardInterrupt:
            logger.info("Synthesis-only mode interrupted")

    def shutdown(self) -> None:
        """Graceful shutdown of all subsystems."""
        logger.info("NAPSE shutting down...")
        self._running = False

        # Stop Rust engine
        if self._engine:
            try:
                self._engine.stop()
            except Exception:
                pass

        # Final flush
        if self._ch_shipper:
            self._ch_shipper.flush()

        # Stop metrics server
        if self._metrics_server:
            self._metrics_server.shutdown()

        # Log final stats
        if self._metrics:
            logger.info("Final stats: %s", json.dumps(self._metrics.get_stats(), default=str))
        if self._ch_shipper:
            logger.info("Shipper stats: %s", json.dumps(self._ch_shipper.get_stats(), default=str))

        logger.info("NAPSE shutdown complete")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='NAPSE - Neural Adaptive Packet Synthesis Engine'
    )
    parser.add_argument(
        '--config', '-c',
        default='/opt/napse/config/napse.yaml',
        help='Path to NAPSE YAML configuration file',
    )
    parser.add_argument(
        '--log-level',
        default=os.getenv('NAPSE_LOG_LEVEL', 'INFO'),
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level',
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s %(name)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )

    logger.info("NAPSE v1.0.0 starting")

    # Load configuration
    config = load_config(args.config)
    logger.info("Tier: %s | Interface: %s | ClickHouse: %s:%d/%s",
                config['tier'],
                config['interface'],
                config['clickhouse']['host'],
                config['clickhouse']['port'],
                config['clickhouse']['database'])

    # Create orchestrator
    orchestrator = NapseOrchestrator(config)

    # Signal handling
    def handle_signal(signum, frame):
        logger.info("Received signal %d", signum)
        orchestrator.shutdown()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Setup and run
    try:
        orchestrator.setup()
        orchestrator.run()
    except Exception:
        logger.exception("Fatal error in NAPSE")
        orchestrator.shutdown()
        sys.exit(1)


if __name__ == '__main__':
    main()
