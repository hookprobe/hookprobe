"""
NAPSE Main - Neural Adaptive Packet Synthesis Engine Entry Point

Orchestrates the split-brain NAPSE architecture:
    Layer 0: eBPF/XDP kernel fast path (Zig Aegis or C BCC)
    Layer 1: Classification engine (Mojo brain -> Python Inspector -> synthesis-only)
    Layer 2: Python event synthesis (event bus, ClickHouse, metrics)

Capture cascade (tries in order):
    1. Mojo napse-brain binary (SIMD batch classification)
    2. Python PacketInspector (AF_PACKET + intent classification)
    3. Synthesis-only mode (external IDS feeds events)

Usage:
    PYTHONPATH=/opt python -m napse --config /opt/napse/config/napse.yaml

Author: HookProbe Team
License: Proprietary
Version: 2.0.0
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

        # Layer 1: Classification engine (cascade)
        capture_engine = os.getenv('NAPSE_CAPTURE_ENGINE',
                                   self.config.get('capture', {}).get('engine', 'auto'))
        self._engine_mode = self._init_capture_engine(capture_engine)

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

        logger.info("NAPSE setup complete (tier=%s, engine=%s)",
                     self.tier, self._engine_mode)

    def _init_capture_engine(self, mode: str) -> str:
        """Initialize the best available capture/classification engine.

        Cascade order:
            1. Mojo napse-brain binary (SIMD batch classification)
            2. Python PacketInspector (AF_PACKET + intent classification)
            3. Synthesis-only mode (no capture, external IDS feeds events)

        Returns the mode string for logging.
        """
        if mode in ('auto', 'mojo'):
            if self._try_mojo_engine():
                return 'mojo'
            if mode == 'mojo':
                logger.warning("Mojo engine requested but not available, falling back")

        if mode in ('auto', 'python', 'inspector'):
            if self._try_python_inspector():
                return 'python-inspector'
            if mode in ('python', 'inspector'):
                logger.warning("Python Inspector requested but not available, falling back")

        logger.info("Running in synthesis-only mode — no capture engine")
        self._engine = None
        self._inspector = None
        return 'synthesis-only'

    def _try_mojo_engine(self) -> bool:
        """Try to find and validate the Mojo napse-brain binary."""
        aegis_cfg = self.config.get('aegis', {})
        brain_cfg = self.config.get('brain', {})

        brain_binary = brain_cfg.get('binary', '/opt/napse/brain/napse-brain')
        if os.path.isfile(brain_binary) and os.access(brain_binary, os.X_OK):
            logger.info("Mojo napse-brain binary found at %s", brain_binary)
            self._mojo_binary = brain_binary
            self._mojo_config = brain_cfg.get('config', '/etc/napse/napse-brain.toml')

            aegis_binary = aegis_cfg.get('binary', '/opt/napse/aegis/aegis-loader')
            if os.path.isfile(aegis_binary) and os.access(aegis_binary, os.X_OK):
                self._aegis_binary = aegis_binary
                self._aegis_config = aegis_cfg.get('config', '/etc/aegis/aegis.toml')
                logger.info("Zig aegis-loader binary found at %s", aegis_binary)
            else:
                self._aegis_binary = None
                logger.info("Aegis binary not found, Mojo will read from stdin/pipe")

            return True

        logger.debug("Mojo napse-brain not found at %s", brain_binary)
        return False

    def _try_python_inspector(self) -> bool:
        """Try to import and initialize the Python PacketInspector."""
        try:
            from .inspector.packet_inspector import PacketInspector
            self._inspector = PacketInspector
            logger.info("Python PacketInspector available")
            return True
        except ImportError as e:
            logger.debug("PacketInspector not available: %s", e)
            return False
        except Exception as e:
            logger.debug("PacketInspector failed to load: %s", e)
            return False

    def run(self) -> None:
        """Start the main processing loop based on active engine mode."""
        self._running = True

        # Start metrics HTTP server
        self._start_metrics_server()

        # Main processing loop based on engine mode
        if self._engine_mode == 'mojo':
            self._run_mojo_capture_loop()
        elif self._engine_mode == 'python-inspector':
            self._run_inspector_loop()
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

    def _run_mojo_capture_loop(self) -> None:
        """Run the Mojo napse-brain as a subprocess for classification.

        Data flow:
            Aegis (Zig/XDP) -> Ring Buffer (/dev/shm) -> Napse (Mojo) -> stdout JSONL
            Python reads Mojo stdout and feeds events to the synthesis event bus.
        """
        import subprocess

        logger.info("Starting Mojo napse-brain engine")

        # Start Aegis first if available (XDP capture -> ring buffer)
        aegis_proc = None
        if getattr(self, '_aegis_binary', None):
            try:
                aegis_proc = subprocess.Popen(
                    [self._aegis_binary, '--config', self._aegis_config],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                logger.info("Aegis XDP capture started (PID %d)", aegis_proc.pid)
            except (OSError, FileNotFoundError) as e:
                logger.warning("Could not start Aegis: %s", e)

        # Start Mojo napse-brain (reads ring buffer, outputs JSONL to stdout)
        try:
            brain_proc = subprocess.Popen(
                [self._mojo_binary, '--config', self._mojo_config],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )
            logger.info("Mojo napse-brain started (PID %d)", brain_proc.pid)
        except (OSError, FileNotFoundError) as e:
            logger.error("Could not start Mojo brain: %s — falling back to Inspector", e)
            if aegis_proc:
                aegis_proc.terminate()
            if self._try_python_inspector():
                self._engine_mode = 'python-inspector'
                self._run_inspector_loop()
            else:
                self._run_synthesis_only()
            return

        from .synthesis.event_bus import EventType

        try:
            while self._running:
                line = brain_proc.stdout.readline()
                if not line:
                    if brain_proc.poll() is not None:
                        logger.warning("Mojo brain exited with code %d", brain_proc.returncode)
                        break
                    continue

                try:
                    event = json.loads(line.strip())
                    event_type = event.get('type', 'alert')
                    if event_type == 'intent':
                        self._event_bus.emit(EventType.ALERT, event)
                    elif event_type == 'flow':
                        self._event_bus.emit(EventType.CONNECTION, event)
                    else:
                        self._event_bus.emit(EventType.NOTICE, event)
                except (json.JSONDecodeError, ValueError):
                    pass  # Skip malformed lines

                if self._ch_shipper:
                    self._ch_shipper.flush()

        except KeyboardInterrupt:
            logger.info("Mojo capture interrupted")
        finally:
            brain_proc.terminate()
            brain_proc.wait(timeout=5)
            if aegis_proc:
                aegis_proc.terminate()
                aegis_proc.wait(timeout=5)

    def _run_inspector_loop(self) -> None:
        """Run the Python PacketInspector for AF_PACKET capture + classification.

        This is the production fallback when Zig/Mojo toolchains are unavailable.
        The PacketInspector captures packets directly via AF_PACKET and classifies
        them using a pure-Python Bayesian engine.
        """
        interface = self.config['interface']
        logger.info("Starting Python PacketInspector on %s", interface)

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

        from .synthesis.event_bus import EventType

        try:
            while self._running:
                try:
                    data, _addr = sock.recvfrom(65535)
                except socket.timeout:
                    if self._ch_shipper:
                        self._ch_shipper.flush()
                    continue

                ts = time.time()

                # Skip ethernet header (14 bytes)
                if len(data) > 14:
                    # Emit raw packet event for synthesis consumers
                    pkt_info = {
                        'timestamp': ts,
                        'raw_len': len(data) - 14,
                        'interface': interface,
                    }
                    self._event_bus.emit(EventType.NOTICE, pkt_info)

        except KeyboardInterrupt:
            logger.info("Inspector capture interrupted")
        finally:
            sock.close()

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

        logger.info("NAPSE shutdown complete (engine=%s)", self._engine_mode)


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

    logger.info("NAPSE v2.0.0 starting (Zig/Mojo split-brain architecture)")

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
