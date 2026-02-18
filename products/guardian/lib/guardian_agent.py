#!/usr/bin/env python3
"""
Guardian Agent - QSecBit Integration & Layer Threat Reporting

This agent integrates the Layer Threat Detector and Mobile Network Protection
modules with QSecBit for unified threat scoring and reporting.

Features:
- Unified L2-L7 threat detection and reporting
- QSecBit score integration with layer-specific metrics
- Mobile network protection status
- Real-time threat monitoring
- JSON/JSONL output for web UI and API consumption

Author: HookProbe Team
Version: 5.0.0
License: AGPL-3.0 - see LICENSE in this directory
"""

import os
import sys
import json
import time
import signal
import argparse
import subprocess
import shlex
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.threat_detection import LayerThreatDetector, OSILayer, ThreatSeverity
    from shared.mobile_security import MobileNetworkProtection, NetworkTrustLevel
except ImportError:
    try:
        # Fallback for local imports
        from .layer_threat_detector import LayerThreatDetector, OSILayer, ThreatSeverity
        from .mobile_network_protection import MobileNetworkProtection, NetworkTrustLevel
    except ImportError:
        # Last resort fallback
        LayerThreatDetector = None
        MobileNetworkProtection = None


@dataclass
class GuardianMetrics:
    """Comprehensive Guardian metrics for QSecBit integration"""
    timestamp: datetime
    qsecbit_score: float
    rag_status: str

    # Layer-specific threat counts
    layer_threats: Dict[str, Dict[str, int]]

    # Mobile protection status
    mobile_protection: Dict[str, Any]

    # Component scores
    components: Dict[str, float]

    # XDP/eBPF stats
    xdp_stats: Dict[str, int]

    # Network stats
    network_stats: Dict[str, Any]

    # IDS engine stats (NAPSE)
    ids_stats: Dict[str, int]

    # Recent threat summary
    recent_threats: List[Dict[str, Any]]

    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'score': self.qsecbit_score,
            'rag_status': self.rag_status,
            'layer_threats': self.layer_threats,
            'mobile_protection': self.mobile_protection,
            'components': self.components,
            'xdp': self.xdp_stats,
            'network': self.network_stats,
            'ids': self.ids_stats,
            'recent_threats': self.recent_threats
        }


class GuardianAgent:
    """
    Guardian Agent - Central coordination for threat detection and reporting

    Integrates:
    - LayerThreatDetector for L2-L7 threat detection
    - MobileNetworkProtection for hotel/public WiFi security
    - QSecBit for unified threat scoring
    - NAPSE IDS engine
    """

    def __init__(
        self,
        data_dir: str = "/opt/hookprobe/guardian/data",
        check_interval: int = 30,
        verbose: bool = False
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.check_interval = check_interval
        self.verbose = verbose
        self.running = False

        # Initialize components
        if LayerThreatDetector:
            self.threat_detector = LayerThreatDetector(data_dir=data_dir)
        else:
            self.threat_detector = None
            self._log("Warning: LayerThreatDetector not available")

        if MobileNetworkProtection:
            self.mobile_protection = MobileNetworkProtection(data_dir=data_dir)
        else:
            self.mobile_protection = None
            self._log("Warning: MobileNetworkProtection not available")

        # AEGIS-Lite AI assistant (cloud-only inference)
        self.aegis_lite = None
        try:
            from products.guardian.lib.aegis_lite import AegisLite
            self.aegis_lite = AegisLite()
            if self.aegis_lite.initialize():
                self._log("AEGIS-Lite initialized")
            else:
                self._log("Warning: AEGIS-Lite initialization failed")
                self.aegis_lite = None
        except ImportError:
            self._log("Warning: AEGIS-Lite not available")
        except Exception as e:
            self._log(f"Warning: AEGIS-Lite init error: {e}")

        # Stats file paths
        self.stats_file = self.data_dir / "stats.json"
        self.threats_file = self.data_dir / "threats.json"
        self.layer_stats_file = self.data_dir / "layer_stats.json"

        # Historical metrics
        self.metrics_history: List[GuardianMetrics] = []
        self.max_history = 1000

    def _log(self, message: str):
        """Log message if verbose mode enabled"""
        if self.verbose:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] {message}")

    def _run_command(self, cmd: Union[str, List[str]], timeout: int = 10) -> tuple:
        """Run command safely without shell=True to prevent command injection"""
        try:
            # Convert string to list for safe execution
            if isinstance(cmd, str):
                cmd_list = shlex.split(cmd)
            else:
                cmd_list = cmd

            result = subprocess.run(
                cmd_list, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip(), result.returncode == 0
        except Exception as e:
            return str(e), False

    # =========================================================================
    # THREAT DETECTION
    # =========================================================================

    def run_threat_detection(self) -> Dict[str, Any]:
        """Run comprehensive threat detection across all layers"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'layers': {},
            'summary': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }

        if not self.threat_detector:
            return results

        # Run detection
        report = self.threat_detector.detect_all_threats()

        # Map layer breakdown
        results['layers'] = report.get('layer_breakdown', {})
        results['summary'] = report.get('summary', {})
        results['rag_status'] = report.get('rag_status', 'UNKNOWN')
        results['recent_threats'] = report.get('recent_threats', [])
        results['top_threat_types'] = report.get('top_threat_types', {})

        return results

    def run_mobile_protection_check(self) -> Dict[str, Any]:
        """Run mobile network protection checks"""
        if not self.mobile_protection:
            return {
                'timestamp': datetime.now().isoformat(),
                'status': 'unavailable',
                'trust_level': 'UNKNOWN',
                'vpn_active': False
            }

        # Analyze current network
        self.mobile_protection.analyze_current_network()

        # Get protection report
        return self.mobile_protection.generate_protection_report()

    # =========================================================================
    # XDP/EBPF STATS
    # =========================================================================

    def get_xdp_stats(self) -> Dict[str, Any]:
        """Get XDP/eBPF statistics"""
        stats = {
            'xdp_enabled': False,
            'packets_passed': 0,
            'packets_dropped': 0,
            'packets_ratelimited': 0,
            'syn_flood_blocked': 0,
            'udp_flood_blocked': 0,
            'icmp_flood_blocked': 0
        }

        # Check if XDP is loaded
        output, success = self._run_command('ip link show | grep xdp')
        stats['xdp_enabled'] = bool(success and output)

        # Try to get XDP stats from bpftool
        output, success = self._run_command('bpftool map dump name xdp_stats 2>/dev/null')
        if success and output:
            try:
                # Parse bpftool output (simplified)
                # Real implementation would parse the map data properly
                pass
            except Exception:
                pass

        # Alternative: read from stats file if XDP program writes to it
        xdp_stats_file = self.data_dir / "xdp_stats.json"
        if xdp_stats_file.exists():
            try:
                with open(xdp_stats_file) as f:
                    xdp_data = json.load(f)
                    stats.update(xdp_data)
            except Exception:
                pass

        return stats

    # =========================================================================
    # IDS/IPS INTEGRATION (NAPSE)
    # =========================================================================

    def get_ids_stats(self) -> Dict[str, Any]:
        """Get NAPSE IDS engine statistics."""
        stats = {
            'running': False,
            'engine': 'napse',
            'alerts_total': 0,
            'connections_total': 0,
            'dns_queries': 0,
            'ssl_connections': 0,
        }

        # Check if NAPSE container is running
        output, success = self._run_command('podman ps --format "{{.Names}}" | grep -i napse')
        stats['running'] = bool(success and output.strip())

        if not stats['running']:
            return stats

        # Query NAPSE stats via its health/stats endpoint or PID file
        output, success = self._run_command(
            'test -f /run/napse/napse.pid && kill -0 $(cat /run/napse/napse.pid) 2>/dev/null'
        )
        stats['running'] = success

        return stats

    # =========================================================================
    # NETWORK STATISTICS
    # =========================================================================

    def get_network_stats(self) -> Dict[str, Any]:
        """Get network interface statistics"""
        stats = {
            'connections': 0,
            'interfaces': {},
            'nic_info': {}
        }

        # Get active connections count
        output, success = self._run_command('ss -tuln | wc -l')
        if success:
            try:
                stats['connections'] = int(output) - 1  # Subtract header
            except ValueError:
                pass

        # Get interface stats
        for iface in ['wlan0', 'wlan1', 'eth0', 'br0']:
            iface_stats = {}

            # RX bytes
            output, _ = self._run_command(f'cat /sys/class/net/{iface}/statistics/rx_bytes 2>/dev/null')
            if output and output.isdigit():
                iface_stats['rx_bytes'] = int(output)

            # TX bytes
            output, _ = self._run_command(f'cat /sys/class/net/{iface}/statistics/tx_bytes 2>/dev/null')
            if output and output.isdigit():
                iface_stats['tx_bytes'] = int(output)

            # RX packets
            output, _ = self._run_command(f'cat /sys/class/net/{iface}/statistics/rx_packets 2>/dev/null')
            if output and output.isdigit():
                iface_stats['rx_packets'] = int(output)

            # TX packets
            output, _ = self._run_command(f'cat /sys/class/net/{iface}/statistics/tx_packets 2>/dev/null')
            if output and output.isdigit():
                iface_stats['tx_packets'] = int(output)

            # Errors
            output, _ = self._run_command(f'cat /sys/class/net/{iface}/statistics/rx_errors 2>/dev/null')
            if output and output.isdigit():
                iface_stats['rx_errors'] = int(output)

            output, _ = self._run_command(f'cat /sys/class/net/{iface}/statistics/tx_errors 2>/dev/null')
            if output and output.isdigit():
                iface_stats['tx_errors'] = int(output)

            if iface_stats:
                stats['interfaces'][iface] = iface_stats

        return stats

    # =========================================================================
    # QSECBIT SCORE CALCULATION
    # =========================================================================

    def calculate_qsecbit_score(
        self,
        threat_report: Dict[str, Any],
        mobile_report: Dict[str, Any],
        ids_stats: Dict[str, Any],
        xdp_stats: Dict[str, Any]
    ) -> tuple:
        """Calculate unified QSecBit score from all components"""

        # Component weights
        WEIGHT_LAYER_THREATS = 0.30
        WEIGHT_MOBILE_PROTECTION = 0.20
        WEIGHT_IDS_ALERTS = 0.25
        WEIGHT_XDP_BLOCKING = 0.15
        WEIGHT_NETWORK_HEALTH = 0.10

        # 1. Layer threat score (0-1, higher = more threats = worse)
        threat_summary = threat_report.get('summary', {})
        total_threats = threat_summary.get('total_threats', 0)
        critical = threat_summary.get('critical', 0)
        high = threat_summary.get('high', 0)
        medium = threat_summary.get('medium', 0)

        # Weighted threat score
        threat_score = min(1.0, (critical * 1.0 + high * 0.7 + medium * 0.4) / 10.0)

        # 2. Mobile protection score (0-1, higher = less protected = worse)
        mobile_score = 1.0 - mobile_report.get('protection_score', 0.5)

        # 3. IDS alert score (0-1)
        ids_total = ids_stats.get('alerts_total', 0)
        ids_score = min(1.0, ids_total * 0.1 / 20.0)

        # 4. XDP blocking effectiveness (0-1, more blocks = potential attack = higher score)
        xdp_dropped = xdp_stats.get('packets_dropped', 0)
        xdp_passed = xdp_stats.get('packets_passed', 1)  # Avoid division by zero
        xdp_ratio = xdp_dropped / (xdp_dropped + xdp_passed) if (xdp_dropped + xdp_passed) > 0 else 0
        xdp_score = min(1.0, xdp_ratio * 2)  # Scale up, high block ratio = attack

        # 5. Network health (0-1)
        # For now, simple health check
        network_score = 0.1  # Baseline healthy

        # Calculate weighted score
        qsecbit_score = (
            WEIGHT_LAYER_THREATS * threat_score +
            WEIGHT_MOBILE_PROTECTION * mobile_score +
            WEIGHT_IDS_ALERTS * ids_score +
            WEIGHT_XDP_BLOCKING * xdp_score +
            WEIGHT_NETWORK_HEALTH * network_score
        )

        # Determine RAG status
        if qsecbit_score >= 0.70:
            rag_status = "RED"
        elif qsecbit_score >= 0.45:
            rag_status = "AMBER"
        else:
            rag_status = "GREEN"

        # Components for detailed reporting
        components = {
            'layer_threats': round(threat_score, 4),
            'mobile_protection': round(mobile_score, 4),
            'ids_alerts': round(ids_score, 4),
            'xdp_blocking': round(xdp_score, 4),
            'network_health': round(network_score, 4),
            'drift': round(threat_score, 4),  # For compatibility with qsecbit.py
            'attack_probability': round((threat_score + ids_score) / 2, 4),
            'classifier_decay': 0.0,
            'quantum_drift': round(mobile_score * 0.5, 4)
        }

        return round(qsecbit_score, 4), rag_status, components

    # =========================================================================
    # MAIN COLLECTION LOOP
    # =========================================================================

    def collect_metrics(self) -> GuardianMetrics:
        """Collect all metrics and calculate unified score"""
        self._log("Collecting metrics...")

        # Run all detections
        threat_report = self.run_threat_detection()
        mobile_report = self.run_mobile_protection_check()
        ids_stats = self.get_ids_stats()
        xdp_stats = self.get_xdp_stats()
        network_stats = self.get_network_stats()

        # Calculate QSecBit score
        qsecbit_score, rag_status, components = self.calculate_qsecbit_score(
            threat_report, mobile_report, ids_stats, xdp_stats
        )

        # Build layer threats summary
        layer_threats = {}
        for layer_name, layer_data in threat_report.get('layers', {}).items():
            layer_threats[layer_name] = {
                'total': layer_data.get('total_threats', 0),
                'critical': layer_data.get('critical', 0),
                'high': layer_data.get('high', 0),
                'medium': layer_data.get('medium', 0),
                'low': layer_data.get('low', 0),
                'blocked': layer_data.get('blocked', 0)
            }

        # Create metrics object
        metrics = GuardianMetrics(
            timestamp=datetime.now(),
            qsecbit_score=qsecbit_score,
            rag_status=rag_status,
            layer_threats=layer_threats,
            mobile_protection={
                'trust_level': mobile_report.get('trust_level', 'UNKNOWN'),
                'vpn_active': mobile_report.get('vpn_active', False),
                'protection_score': mobile_report.get('protection_score', 0.0),
                'anomalies': mobile_report.get('anomalies', []),
                'network_ssid': mobile_report.get('current_network', {}).get('ssid') if mobile_report.get('current_network') else None
            },
            components=components,
            xdp_stats=xdp_stats,
            network_stats=network_stats,
            ids_stats={
                'napse_running': ids_stats.get('running', False),
                'alerts_total': ids_stats.get('alerts_total', 0),
            },
            recent_threats=threat_report.get('recent_threats', [])[-10:]
        )

        # Store in history
        self.metrics_history.append(metrics)
        if len(self.metrics_history) > self.max_history:
            self.metrics_history = self.metrics_history[-self.max_history:]

        # Save to files
        self._save_metrics(metrics, threat_report)

        self._log(f"Metrics collected - Score: {qsecbit_score}, RAG: {rag_status}")

        return metrics

    def _save_metrics(self, metrics: GuardianMetrics, threat_report: Dict[str, Any]):
        """Save metrics to JSON files for web UI consumption"""
        # Save main stats file (for web UI)
        stats_data = {
            'status': 'active',
            'version': '5.0.0',
            'mode': 'guardian-edge',
            'timestamp': metrics.timestamp.isoformat(),
            'score': metrics.qsecbit_score,
            'rag_status': metrics.rag_status,
            'components': metrics.components,
            'xdp': metrics.xdp_stats,
            'network': metrics.network_stats,
            'energy': {
                'total_rx_bytes': sum(
                    iface.get('rx_bytes', 0)
                    for iface in metrics.network_stats.get('interfaces', {}).values()
                ),
                'total_tx_bytes': sum(
                    iface.get('tx_bytes', 0)
                    for iface in metrics.network_stats.get('interfaces', {}).values()
                ),
                'interfaces': metrics.network_stats.get('interfaces', {})
            },
            'threats': threat_report.get('summary', {}).get('total_threats', 0),
            'ids_alerts': metrics.ids_stats.get('alerts_total', 0),
            'layer_breakdown': metrics.layer_threats,
            'mobile_protection': metrics.mobile_protection
        }

        try:
            with open(self.stats_file, 'w') as f:
                json.dump(stats_data, f, indent=2)
        except Exception as e:
            self._log(f"Error saving stats: {e}")

        # Save layer-specific stats
        layer_data = {
            'timestamp': metrics.timestamp.isoformat(),
            'rag_status': metrics.rag_status,
            'layers': metrics.layer_threats,
            'summary': threat_report.get('summary', {}),
            'top_threat_types': threat_report.get('top_threat_types', {}),
            'detection_coverage': threat_report.get('detection_coverage', {})
        }

        try:
            with open(self.layer_stats_file, 'w') as f:
                json.dump(layer_data, f, indent=2)
        except Exception as e:
            self._log(f"Error saving layer stats: {e}")

    # =========================================================================
    # DAEMON MODE
    # =========================================================================

    def start_daemon(self):
        """Start the agent in daemon mode"""
        self._log("Starting Guardian Agent daemon...")
        self.running = True

        # Start AEGIS-Lite
        if self.aegis_lite:
            try:
                self.aegis_lite.start()
                self._log("AEGIS-Lite started")
            except Exception as e:
                self._log(f"Warning: AEGIS-Lite start failed: {e}")

        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        while self.running:
            try:
                self.collect_metrics()
            except Exception as e:
                self._log(f"Error collecting metrics: {e}")

            # Wait for next check
            time.sleep(self.check_interval)

        # Stop AEGIS-Lite on shutdown
        if self.aegis_lite:
            try:
                self.aegis_lite.stop()
                self._log("AEGIS-Lite stopped")
            except Exception as e:
                self._log(f"Warning: AEGIS-Lite stop failed: {e}")

        self._log("Guardian Agent daemon stopped")

    def _handle_signal(self, signum, frame):
        """Handle termination signals"""
        self._log(f"Received signal {signum}, shutting down...")
        self.running = False

    def run_once(self) -> Dict[str, Any]:
        """Run a single collection cycle and return results"""
        metrics = self.collect_metrics()
        return metrics.to_dict()

    # =========================================================================
    # API ENDPOINTS
    # =========================================================================

    def get_current_status(self) -> Dict[str, Any]:
        """Get current status for API/web UI"""
        if self.metrics_history:
            latest = self.metrics_history[-1]
            return latest.to_dict()
        else:
            # Run a quick collection
            metrics = self.collect_metrics()
            return metrics.to_dict()

    def get_layer_breakdown(self) -> Dict[str, Any]:
        """Get detailed layer breakdown for API/web UI"""
        if self.metrics_history:
            latest = self.metrics_history[-1]
            return {
                'timestamp': latest.timestamp.isoformat(),
                'layers': latest.layer_threats,
                'rag_status': latest.rag_status
            }
        return {}

    def get_threat_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get threat history for the specified time period"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [
            m.to_dict() for m in self.metrics_history
            if m.timestamp > cutoff
        ]


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='Guardian Agent - QSecBit Integration')
    parser.add_argument('--daemon', action='store_true', help='Run in daemon mode')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    parser.add_argument('--interval', type=int, default=30, help='Check interval in seconds')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--data-dir', default='/opt/hookprobe/guardian/data', help='Data directory')

    args = parser.parse_args()

    agent = GuardianAgent(
        data_dir=args.data_dir,
        check_interval=args.interval,
        verbose=args.verbose
    )

    if args.daemon:
        agent.start_daemon()
    elif args.once:
        result = agent.run_once()
        print(json.dumps(result, indent=2))
    else:
        # Default: run once and show status
        print("=" * 70)
        print("GUARDIAN AGENT - QSecBit Integration & Layer Threat Reporting")
        print("=" * 70)

        result = agent.run_once()

        print(f"\nTimestamp: {result['timestamp']}")
        print(f"QSecBit Score: {result['score']}")
        print(f"RAG Status: {result['rag_status']}")

        print(f"\n--- LAYER BREAKDOWN ---")
        for layer, stats in result.get('layer_threats', {}).items():
            print(f"  {layer}: {stats.get('total', 0)} threats "
                  f"(C:{stats.get('critical', 0)} H:{stats.get('high', 0)} "
                  f"M:{stats.get('medium', 0)} L:{stats.get('low', 0)})")

        print(f"\n--- MOBILE PROTECTION ---")
        mobile = result.get('mobile_protection', {})
        print(f"  Trust Level: {mobile.get('trust_level', 'UNKNOWN')}")
        print(f"  VPN Active: {mobile.get('vpn_active', False)}")
        print(f"  Protection Score: {mobile.get('protection_score', 0)}")

        print(f"\n--- IDS/IPS STATUS ---")
        ids = result.get('ids', {})
        print(f"  NAPSE: {'Running' if ids.get('napse_running') else 'Stopped'}")
        print(f"  IDS Alerts: {ids.get('alerts_total', 0)}")

        print(f"\n--- XDP STATS ---")
        xdp = result.get('xdp', {})
        print(f"  XDP Enabled: {xdp.get('xdp_enabled', False)}")
        print(f"  Packets Passed: {xdp.get('packets_passed', 0)}")
        print(f"  Packets Dropped: {xdp.get('packets_dropped', 0)}")

        print("=" * 70)


if __name__ == "__main__":
    main()
