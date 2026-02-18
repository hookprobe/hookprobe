#!/usr/bin/env python3
"""
qsecbit-agent.py - HookProbe Qsecbit Monitoring Daemon
Version: 5.0.0
License: Proprietary - see LICENSE in this directory

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
from typing import Optional, Dict, List
from collections import deque
from datetime import datetime

import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from qsecbit import QsecbitAnalyzer, QsecbitConfig
    from energy_monitor import EnergyMonitor, DeploymentRole
    from xdp_manager import XDPManager
    from nic_detector import NICDetector
except ImportError as e:
    print(f"ERROR: Failed to import qsecbit modules: {e}")
    print("Ensure qsecbit.py, energy_monitor.py, xdp_manager.py, and nic_detector.py are in the same directory")
    sys.exit(1)

# Optional imports for E2E integration
try:
    from response.orchestrator import ResponseOrchestrator, ResponsePolicy
    RESPONSE_AVAILABLE = True
except ImportError:
    RESPONSE_AVAILABLE = False

try:
    from mesh_bridge import QsecbitMeshBridge, MeshBridgeConfig
    MESH_BRIDGE_AVAILABLE = True
except ImportError:
    MESH_BRIDGE_AVAILABLE = False

try:
    from shared.dsm.node import DSMNode
    from shared.dsm.gossip import GossipProtocol
    DSM_AVAILABLE = True
except ImportError:
    DSM_AVAILABLE = False

try:
    from threat_types import ThreatEvent, AttackType, ThreatSeverity, OSILayer
    THREAT_TYPES_AVAILABLE = True
except ImportError:
    THREAT_TYPES_AVAILABLE = False

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
    server = HTTPServer(('127.0.0.1', port), HealthCheckHandler)
    logger.info(f"Health check server listening on port {port}")
    server.serve_forever()


# ============================================================================
# AGENT CLASS
# ============================================================================

class HookProbeAgent:
    """Main HookProbe monitoring agent with E2E integration"""

    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file
        self.running = Event()
        self.start_time = time.time()
        self.last_metrics: Dict = {}

        # Core Components
        self.qsecbit: Optional[QsecbitAnalyzer] = None
        self.energy_monitor: Optional[EnergyMonitor] = None
        self.xdp_manager: Optional[XDPManager] = None
        self.nic_detector: Optional[NICDetector] = None

        # E2E Integration Components
        self.response_orchestrator: Optional['ResponseOrchestrator'] = None
        self.mesh_bridge: Optional['QsecbitMeshBridge'] = None
        self.dsm_node: Optional['DSMNode'] = None
        self.gossip: Optional['GossipProtocol'] = None

        # Threat tracking
        self.active_threats: List['ThreatEvent'] = []
        self.rag_history: deque = deque(maxlen=100)  # Track RAG status changes

        # Configuration
        self.xdp_enabled = os.getenv("XDP_ENABLED", "false").lower() == "true"
        self.dsm_enabled = os.getenv("DSM_ENABLED", "false").lower() == "true"
        self.mesh_enabled = os.getenv("MESH_ENABLED", "false").lower() == "true"
        self.deployment_role = self._detect_deployment_role()
        self.node_id = os.getenv("NODE_ID", f"guardian-{os.getpid()}")

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

        # NIC Detection (all methods are static)
        nic_info = {'interface': 'eth0', 'driver': 'unknown', 'xdp_drv': False, 'xdp_skb': True}
        try:
            iface = NICDetector.get_primary_interface() or 'eth0'
            info = NICDetector.get_nic_info(iface)
            cap = NICDetector.detect_capability(iface)
            nic_info = {
                'interface': iface,
                'driver': info.get('driver', 'unknown'),
                'xdp_drv': cap.xdp_drv,
                'xdp_skb': cap.xdp_skb,
            }
            logger.info(f"Primary NIC: {nic_info['interface']} ({nic_info['driver']})")
            logger.info(f"XDP capability: DRV={nic_info['xdp_drv']}, SKB={nic_info['xdp_skb']}")
        except Exception as e:
            logger.error(f"NIC detection failed: {e}")

        # Energy Monitoring
        try:
            self.energy_monitor = EnergyMonitor(
                deployment_role=self.deployment_role,
                network_interface=nic_info['interface']
            )
            logger.info(f"Energy monitoring initialized (role: {self.deployment_role.value})")
        except Exception as e:
            logger.warning(f"Energy monitoring not available: {e}")
            self.energy_monitor = None

        # XDP/eBPF Manager
        if self.xdp_enabled:
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

        # Qsecbit Analyzer — requires baseline telemetry parameters
        try:
            qsecbit_config = QsecbitConfig()
            # Default baseline: 4-dimensional system telemetry (CPU, Mem, Net, Disk)
            baseline_mu = np.array([0.1, 0.2, 0.15, 0.33])
            baseline_cov = np.eye(4) * 0.02
            quantum_anchor = 6.144  # Baseline system entropy
            self.qsecbit = QsecbitAnalyzer(
                baseline_mu=baseline_mu,
                baseline_cov=baseline_cov,
                quantum_anchor=quantum_anchor,
                config=qsecbit_config,
            )
            logger.info("Qsecbit analyzer initialized")
        except Exception as e:
            logger.error(f"Qsecbit initialization failed: {e}")
            self.qsecbit = None

        # Initialize E2E integration components
        self._initialize_e2e_components()

        logger.info("Component initialization completed")

    def _initialize_e2e_components(self):
        """Initialize E2E integration: ResponseOrchestrator, MeshBridge, DSM"""

        # Response Orchestrator - automated threat response
        if RESPONSE_AVAILABLE:
            try:
                policy = ResponsePolicy(
                    enable_xdp_blocking=self.xdp_enabled,
                    enable_firewall_rules=True,
                    enable_rate_limiting=True,
                    enable_session_termination=False,  # Dangerous
                    enable_quarantine=False,           # Requires SDN
                )
                self.response_orchestrator = ResponseOrchestrator(
                    xdp_manager=self.xdp_manager,
                    policy=policy,
                    data_dir=str(BASE_DIR / "data")
                )
                logger.info("ResponseOrchestrator initialized")
            except Exception as e:
                logger.error(f"ResponseOrchestrator initialization failed: {e}")
                self.response_orchestrator = None
        else:
            logger.info("ResponseOrchestrator not available (module not found)")

        # DSM Node - decentralized security mesh
        if DSM_AVAILABLE and self.dsm_enabled:
            try:
                tpm_key_path = os.getenv("TPM_KEY_PATH", "/var/lib/hookprobe/tpm/key")
                ledger_path = os.getenv("DSM_LEDGER_PATH", "/var/lib/hookprobe/dsm/microblocks")
                bootstrap_nodes = os.getenv("DSM_BOOTSTRAP_NODES", "").split(",")
                bootstrap_nodes = [n.strip() for n in bootstrap_nodes if n.strip()]

                self.dsm_node = DSMNode(
                    node_id=self.node_id,
                    tpm_key_path=tpm_key_path,
                    ledger_path=ledger_path,
                    bootstrap_nodes=bootstrap_nodes
                )
                self.gossip = self.dsm_node.gossip
                logger.info(f"DSM node initialized: {self.node_id}")
            except Exception as e:
                logger.error(f"DSM node initialization failed: {e}")
                self.dsm_node = None
        else:
            if not DSM_AVAILABLE:
                logger.info("DSM not available (module not found)")
            elif not self.dsm_enabled:
                logger.info("DSM disabled (set DSM_ENABLED=true to enable)")

        # Mesh Bridge - connects Qsecbit to mesh consciousness
        if MESH_BRIDGE_AVAILABLE and self.mesh_enabled:
            try:
                config = MeshBridgeConfig(
                    tier='guardian',
                    enable_mesh_reporting=True,
                    enable_cortex_events=True,
                    enable_dsm_microblocks=self.dsm_enabled,
                )
                self.mesh_bridge = QsecbitMeshBridge(
                    config=config,
                    dsm_node=self.dsm_node,
                    gossip=self.gossip
                )
                logger.info("MeshBridge initialized")
            except Exception as e:
                logger.error(f"MeshBridge initialization failed: {e}")
                self.mesh_bridge = None
        else:
            if not MESH_BRIDGE_AVAILABLE:
                logger.info("MeshBridge not available (module not found)")
            elif not self.mesh_enabled:
                logger.info("MeshBridge disabled (set MESH_ENABLED=true to enable)")

    def collect_metrics(self) -> Dict:
        """Collect metrics from all sources"""
        metrics = {
            "timestamp": time.time(),
            "uptime": int(time.time() - self.start_time)
        }

        # Energy metrics
        if self.energy_monitor:
            try:
                snapshot = self.energy_monitor.capture_snapshot()
                if snapshot:
                    anomalies = self.energy_monitor.detect_anomalies(snapshot)
                    metrics["energy"] = {
                        "package_watts": snapshot.package_watts,
                        "nic_watts": snapshot.nic_processes_watts,
                        "xdp_watts": snapshot.xdp_processes_watts,
                        "anomaly_score": anomalies.get("anomaly_score", 0.0),
                        "anomalies": anomalies.get("anomalies", []),
                    }
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
        if self.qsecbit:
            try:
                score = self.qsecbit.detect_threats()
                metrics["qsecbit"] = score.to_dict()
            except Exception as e:
                logger.error(f"Qsecbit analysis failed: {e}")

        return metrics

    def process_alerts(self, metrics: Dict):
        """
        Process alerts based on metrics.

        This is the core E2E integration point:
        1. Evaluate Qsecbit RAG status
        2. Create ThreatEvents for detected anomalies
        3. Execute ResponseOrchestrator actions
        4. Report threats to mesh via MeshBridge
        5. Create DSM microblocks for significant threats
        """
        if "qsecbit" not in metrics:
            return

        qsecbit_data = metrics["qsecbit"]
        rag_status = qsecbit_data.get("rag_status", "GREEN")
        score = qsecbit_data.get("score", 0.0)
        prev_rag = self.rag_history[-1]["status"] if self.rag_history else "GREEN"

        # Track RAG status changes
        if rag_status != prev_rag:
            self.rag_history.append({
                "status": rag_status,
                "score": score,
                "timestamp": datetime.now().isoformat()
            })
        if rag_status == "RED":
            logger.warning(f"RED ALERT: Qsecbit score {score:.3f} - System under stress!")
            self._handle_red_alert(metrics, score)

        elif rag_status == "AMBER":
            logger.warning(f"AMBER ALERT: Qsecbit score {score:.3f} - Defensive capacity declining")
            self._handle_amber_alert(metrics, score)

        # XDP rate limiting
        if self.xdp_manager and "xdp" in metrics:
            xdp_stats = metrics["xdp"]

            # Check for DDoS indicators
            if xdp_stats.get("drops", 0) > 1000:
                logger.warning(f"High XDP drop rate: {xdp_stats['drops']} packets")
                self._handle_ddos_indicator(xdp_stats)

    def _handle_red_alert(self, metrics: Dict, score: float):
        """
        Handle RED alert status - critical threat response.

        Actions:
        1. Create ThreatEvent from metrics
        2. Execute blocking responses via ResponseOrchestrator
        3. Report to mesh via MeshBridge
        4. Create DSM microblock for audit trail
        """
        if not THREAT_TYPES_AVAILABLE:
            logger.warning("ThreatTypes not available, cannot create ThreatEvent")
            return

        # Create ThreatEvent from Qsecbit metrics
        threat = self._create_threat_from_metrics(metrics, ThreatSeverity.CRITICAL)
        if not threat:
            return

        self.active_threats.append(threat)

        # Execute response via ResponseOrchestrator
        if self.response_orchestrator:
            try:
                results = self.response_orchestrator.respond(threat)
                for result in results:
                    logger.info(
                        f"Response action {result.action.name}: "
                        f"{'SUCCESS' if result.success else 'FAILED'} - {result.details}"
                    )
            except Exception as e:
                logger.error(f"ResponseOrchestrator failed: {e}")

        # Report to mesh via MeshBridge
        if self.mesh_bridge:
            try:
                reported = self.mesh_bridge.report_threat(threat)
                if reported:
                    logger.info(f"Threat {threat.id[:8]}... reported to mesh")
            except Exception as e:
                logger.error(f"MeshBridge reporting failed: {e}")

    def _handle_amber_alert(self, metrics: Dict, score: float):
        """
        Handle AMBER alert status - elevated threat warning.

        Actions:
        1. Create ThreatEvent from metrics
        2. Enable rate limiting if available
        3. Report to mesh for awareness
        """
        if not THREAT_TYPES_AVAILABLE:
            return

        # Create ThreatEvent with HIGH severity
        threat = self._create_threat_from_metrics(metrics, ThreatSeverity.HIGH)
        if not threat:
            return

        self.active_threats.append(threat)

        # Execute response (rate limiting, alerts)
        if self.response_orchestrator:
            try:
                results = self.response_orchestrator.respond(threat)
                for result in results:
                    if result.success:
                        logger.info(f"AMBER response: {result.action.name} - {result.details}")
            except Exception as e:
                logger.error(f"AMBER response failed: {e}")

        # Report to mesh
        if self.mesh_bridge:
            try:
                self.mesh_bridge.report_threat(threat)
            except Exception as e:
                logger.debug(f"Mesh reporting skipped: {e}")

    def _handle_ddos_indicator(self, xdp_stats: Dict):
        """Handle DDoS indicators from XDP statistics."""
        if not THREAT_TYPES_AVAILABLE:
            return

        # Create DDoS threat event
        threat = ThreatEvent(
            attack_type=AttackType.SYN_FLOOD,  # Most common DDoS
            layer=OSILayer.L4_TRANSPORT,
            source_ip=xdp_stats.get("top_attacker_ip", "unknown"),
            severity=ThreatSeverity.HIGH,
            confidence=0.85,
            detector="xdp_manager",
            description=f"DDoS indicator: {xdp_stats.get('drops', 0)} drops in monitoring window",
            evidence={
                "drops": xdp_stats.get("drops", 0),
                "packets_total": xdp_stats.get("packets", 0),
                "bytes_dropped": xdp_stats.get("bytes_dropped", 0),
            },
            qsecbit_contribution=0.3,
        )

        if self.response_orchestrator:
            self.response_orchestrator.respond(threat)

        if self.mesh_bridge:
            self.mesh_bridge.report_threat(threat)

    def _create_threat_from_metrics(
        self,
        metrics: Dict,
        severity: 'ThreatSeverity'
    ) -> Optional['ThreatEvent']:
        """
        Create a ThreatEvent from Qsecbit metrics.

        This converts generic anomaly scores into a structured threat event
        that can be processed by ResponseOrchestrator and shared via mesh.
        """
        if not THREAT_TYPES_AVAILABLE:
            return None

        qsecbit_data = metrics.get("qsecbit", {})
        energy_data = metrics.get("energy", {})
        xdp_data = metrics.get("xdp", {})

        # Determine attack type from metrics
        attack_type = AttackType.SYN_FLOOD  # Default
        layer = OSILayer.L4_TRANSPORT

        # Check for energy anomaly (cryptominer indicator)
        if energy_data.get("anomaly_score", 0) > 0.7:
            attack_type = AttackType.MALWARE_C2
            layer = OSILayer.L7_APPLICATION

        # Check for XDP indicators
        if xdp_data.get("drops", 0) > 1000:
            attack_type = AttackType.SYN_FLOOD
            layer = OSILayer.L4_TRANSPORT

        # Build evidence from all available metrics
        evidence = {
            "qsecbit_score": qsecbit_data.get("score", 0),
            "rag_status": qsecbit_data.get("rag_status", "UNKNOWN"),
            "drift": qsecbit_data.get("drift", 0),
            "p_attack": qsecbit_data.get("p_attack", 0),
        }

        if energy_data:
            evidence["energy_anomaly"] = energy_data.get("anomaly_score", 0)
            evidence["power_watts"] = energy_data.get("power_watts", 0)

        if xdp_data:
            evidence["xdp_drops"] = xdp_data.get("drops", 0)
            evidence["xdp_packets"] = xdp_data.get("packets", 0)

        threat = ThreatEvent(
            attack_type=attack_type,
            layer=layer,
            source_ip=xdp_data.get("top_attacker_ip"),  # May be None
            severity=severity,
            confidence=min(0.95, qsecbit_data.get("score", 0.5) + 0.3),
            detector="qsecbit_agent",
            description=f"Qsecbit anomaly detected (score={qsecbit_data.get('score', 0):.3f})",
            evidence=evidence,
            qsecbit_contribution=qsecbit_data.get("score", 0),
        )

        return threat

    def export_metrics(self, metrics: Dict):
        """Export metrics to external systems and stats file for AEGIS bridge."""
        if "qsecbit" in metrics:
            qsecbit_data = metrics["qsecbit"]
            logger.info(
                f"Qsecbit: {qsecbit_data.get('rag_status', 'N/A')} "
                f"score={qsecbit_data.get('score', 0.0):.3f}"
            )

            # Write stats file for AEGIS bridge consumption
            stats_dir = Path("/var/log/hookprobe/qsecbit")
            try:
                stats_dir.mkdir(parents=True, exist_ok=True)
                stats_file = stats_dir / "current.json"
                stats_file.write_text(json.dumps(qsecbit_data, default=str))
            except Exception as e:
                logger.warning(f"Failed to write stats file: {e}")

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
        """Stop the agent and clean up all components"""
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

        # Cleanup ResponseOrchestrator (save state)
        if self.response_orchestrator:
            try:
                self.response_orchestrator._save_state()
                self.response_orchestrator.cleanup_expired_blocks()
                logger.info("ResponseOrchestrator state saved")
            except Exception as e:
                logger.error(f"ResponseOrchestrator cleanup failed: {e}")

        # Cleanup DSM Node
        if self.dsm_node:
            try:
                self.dsm_node.shutdown()
                logger.info("DSM node shutdown completed")
            except Exception as e:
                logger.error(f"DSM node shutdown failed: {e}")

        # Log final statistics
        if self.mesh_bridge:
            stats = self.mesh_bridge.get_statistics()
            logger.info(
                f"MeshBridge stats: {stats['threats_reported']} reported, "
                f"{stats['threats_received']} received, "
                f"{stats['microblocks_created']} microblocks"
            )

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
