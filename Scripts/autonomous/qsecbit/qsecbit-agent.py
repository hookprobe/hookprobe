#!/usr/bin/env python3
"""
qsecbit-agent.py - HookProbe Qsecbit Monitoring Daemon
Version: 5.0
License: MIT

Long-running daemon for:
- Energy monitoring (RAPL + per-PID tracking)
- NIC monitoring and XDP/eBPF DDoS mitigation
- Anomaly scoring (Qsecbit cyber resilience metric)
- Telemetry export to VictoriaMetrics/ClickHouse
"""

import os
import sys
import time
import signal
import logging
import argparse
import json
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread, Event
from typing import Optional, Dict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from qsecbit import QsecbitAnalyzer, QsecbitConfig
    from energy_monitor import EnergyMonitor, DeploymentRole
    from xdp_manager import XDPManager
    from nic_detector import NICDetector
except ImportError as e:
    print(f"ERROR: Failed to import qsecbit modules: {e}")
    print("Ensure qsecbit.py, energy_monitor.py, xdp_manager.py, and nic_detector.py are in the same directory")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_DIR = Path(os.getenv("HOOKPROBE_BASE", "/opt/hookprobe"))
CONFIG_DIR = Path(os.getenv("HOOKPROBE_CONFIG", "/etc/hookprobe"))
LOG_DIR = Path("/var/log/hookprobe")

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "agent.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("hookprobe-agent")

# ============================================================================
# HEALTH CHECK HTTP SERVER
# ============================================================================

class HealthCheckHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for health checks"""

    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            health_status = {
                "status": "healthy",
                "version": "5.0",
                "uptime": int(time.time() - agent.start_time) if 'agent' in globals() else 0
            }

            self.wfile.write(json.dumps(health_status).encode())
        elif self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            if 'agent' in globals() and hasattr(agent, 'last_metrics'):
                self.wfile.write(json.dumps(agent.last_metrics).encode())
            else:
                self.wfile.write(json.dumps({"error": "no metrics available"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress request logging"""
        pass


def run_health_server(port: int = 8888):
    """Run health check HTTP server"""
    server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
    logger.info(f"Health check server listening on port {port}")
    server.serve_forever()


# ============================================================================
# AGENT CLASS
# ============================================================================

class HookProbeAgent:
    """Main HookProbe monitoring agent"""

    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file
        self.running = Event()
        self.start_time = time.time()
        self.last_metrics: Dict = {}

        # Components
        self.qsecbit: Optional[QsecbitAnalyzer] = None
        self.energy_monitor: Optional[EnergyMonitor] = None
        self.xdp_manager: Optional[XDPManager] = None
        self.nic_detector: Optional[NICDetector] = None

        # Configuration
        self.xdp_enabled = os.getenv("XDP_ENABLED", "false").lower() == "true"
        self.deployment_role = self._detect_deployment_role()

        # Signal handling
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def _detect_deployment_role(self) -> DeploymentRole:
        """Detect deployment role (server vs endpoint)"""
        # Simple heuristic: if we have a public IP or are in a datacenter, assume server
        # Otherwise, assume endpoint

        # For now, default to server (can be overridden via config)
        role_str = os.getenv("DEPLOYMENT_ROLE", "server").lower()

        if role_str == "endpoint":
            return DeploymentRole.USER_ENDPOINT
        else:
            return DeploymentRole.PUBLIC_SERVER

    def initialize_components(self):
        """Initialize monitoring components"""
        logger.info("Initializing components...")

        # NIC Detection
        try:
            self.nic_detector = NICDetector()
            nic_info = self.nic_detector.detect()
            logger.info(f"Primary NIC: {nic_info['interface']} ({nic_info['driver']})")
            logger.info(f"XDP capability: DRV={nic_info['xdp_drv']}, SKB={nic_info['xdp_skb']}")
        except Exception as e:
            logger.error(f"NIC detection failed: {e}")
            self.nic_detector = None

        # Energy Monitoring
        try:
            self.energy_monitor = EnergyMonitor(
                role=self.deployment_role,
                nic_interface=nic_info['interface'] if self.nic_detector else None
            )
            logger.info(f"Energy monitoring initialized (role: {self.deployment_role.value})")
        except Exception as e:
            logger.warning(f"Energy monitoring not available: {e}")
            self.energy_monitor = None

        # XDP/eBPF Manager
        if self.xdp_enabled and self.nic_detector:
            try:
                self.xdp_manager = XDPManager(
                    interface=nic_info['interface'],
                    mode='drv' if nic_info['xdp_drv'] else 'skb'
                )
                logger.info(f"XDP manager initialized on {nic_info['interface']}")
            except Exception as e:
                logger.error(f"XDP initialization failed: {e}")
                self.xdp_manager = None
        else:
            if not self.xdp_enabled:
                logger.info("XDP disabled (set XDP_ENABLED=true to enable)")

        # Qsecbit Analyzer
        try:
            qsecbit_config = QsecbitConfig()
            self.qsecbit = QsecbitAnalyzer(config=qsecbit_config)
            logger.info("Qsecbit analyzer initialized")
        except Exception as e:
            logger.error(f"Qsecbit initialization failed: {e}")
            self.qsecbit = None

        logger.info("Component initialization completed")

    def collect_metrics(self) -> Dict:
        """Collect metrics from all sources"""
        metrics = {
            "timestamp": time.time(),
            "uptime": int(time.time() - self.start_time)
        }

        # Energy metrics
        if self.energy_monitor:
            try:
                energy_data = self.energy_monitor.get_current_metrics()
                metrics["energy"] = energy_data
            except Exception as e:
                logger.error(f"Energy metrics collection failed: {e}")

        # XDP metrics
        if self.xdp_manager:
            try:
                xdp_stats = self.xdp_manager.get_stats()
                metrics["xdp"] = xdp_stats
            except Exception as e:
                logger.error(f"XDP metrics collection failed: {e}")

        # Qsecbit analysis
        if self.qsecbit and self.energy_monitor:
            try:
                # Run qsecbit analysis
                telemetry = {
                    "energy": metrics.get("energy", {}),
                    "network": metrics.get("xdp", {})
                }

                qsecbit_result = self.qsecbit.analyze(telemetry)
                metrics["qsecbit"] = qsecbit_result
            except Exception as e:
                logger.error(f"Qsecbit analysis failed: {e}")

        return metrics

    def process_alerts(self, metrics: Dict):
        """Process alerts based on metrics"""
        if "qsecbit" not in metrics:
            return

        qsecbit_data = metrics["qsecbit"]
        rag_status = qsecbit_data.get("rag_status", "GREEN")
        score = qsecbit_data.get("score", 0.0)

        if rag_status == "RED":
            logger.warning(f"RED ALERT: Qsecbit score {score:.3f} - System under stress!")
            # TODO: Trigger Kali response
        elif rag_status == "AMBER":
            logger.warning(f"AMBER ALERT: Qsecbit score {score:.3f} - Defensive capacity declining")
            # TODO: Prepare Kali container

        # XDP rate limiting
        if self.xdp_manager and "xdp" in metrics:
            xdp_stats = metrics["xdp"]

            # Check for DDoS indicators
            if xdp_stats.get("drops", 0) > 1000:
                logger.warning(f"High XDP drop rate: {xdp_stats['drops']} packets")

    def export_metrics(self, metrics: Dict):
        """Export metrics to external systems"""
        # TODO: Export to VictoriaMetrics
        # TODO: Export to ClickHouse

        # For now, just log summary
        if "qsecbit" in metrics:
            qsecbit_data = metrics["qsecbit"]
            logger.info(
                f"Qsecbit: {qsecbit_data.get('rag_status', 'N/A')} "
                f"score={qsecbit_data.get('score', 0.0):.3f}"
            )

    def run_monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting monitoring loop...")

        interval = 10  # seconds

        while self.running.is_set():
            try:
                # Collect metrics
                metrics = self.collect_metrics()
                self.last_metrics = metrics

                # Process alerts
                self.process_alerts(metrics)

                # Export metrics
                self.export_metrics(metrics)

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}", exc_info=True)

            # Sleep
            time.sleep(interval)

        logger.info("Monitoring loop stopped")

    def start(self):
        """Start the agent"""
        logger.info("Starting HookProbe agent...")
        logger.info(f"Base directory: {BASE_DIR}")
        logger.info(f"Config directory: {CONFIG_DIR}")

        # Initialize components
        self.initialize_components()

        # Start health check server
        health_thread = Thread(target=run_health_server, args=(8888,), daemon=True)
        health_thread.start()

        # Set running flag
        self.running.set()

        # Run monitoring loop (blocking)
        self.run_monitoring_loop()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping HookProbe agent...")

        # Clear running flag
        self.running.clear()

        # Cleanup XDP
        if self.xdp_manager:
            try:
                self.xdp_manager.cleanup()
                logger.info("XDP cleanup completed")
            except Exception as e:
                logger.error(f"XDP cleanup failed: {e}")

        logger.info("Agent stopped")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="HookProbe Qsecbit Agent")
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file"
    )
    parser.add_argument(
        "--xdp",
        action="store_true",
        help="Enable XDP/eBPF DDoS mitigation"
    )
    parser.add_argument(
        "--role",
        choices=["server", "endpoint"],
        default="server",
        help="Deployment role (server or endpoint)"
    )

    args = parser.parse_args()

    # Override environment variables with CLI args
    if args.xdp:
        os.environ["XDP_ENABLED"] = "true"

    if args.role:
        os.environ["DEPLOYMENT_ROLE"] = args.role

    # Create and start agent
    global agent
    agent = HookProbeAgent(config_file=args.config)

    try:
        agent.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        agent.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
