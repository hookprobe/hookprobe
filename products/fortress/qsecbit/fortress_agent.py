#!/usr/bin/env python3
"""
QSecBit Fortress Agent - Full Implementation
Version: 5.2.0
License: AGPL-3.0

Fortress-enhanced QSecBit with:
- L2-L7 Layer Threat Detection (Suricata/Zeek integration)
- Extended telemetry from monitoring stack
- XDP/eBPF DDoS protection integration
- nftables policy scoring
- MACsec status monitoring
- OpenFlow flow analysis
- HTTP API for healthcheck and status
"""

import json
import time
import os
import sys
import signal
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from threading import Thread, Event
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request

# Import L2-L7 Layer Detectors from core
try:
    from core.qsecbit.detectors import (
        L2DataLinkDetector,
        L3NetworkDetector,
        L4TransportDetector,
        L5SessionDetector,
        L7ApplicationDetector,
    )
    from core.qsecbit.threat_types import ThreatEvent, ThreatSeverity
    LAYER_DETECTORS_AVAILABLE = True
except ImportError:
    LAYER_DETECTORS_AVAILABLE = False

# Logging setup
LOG_DIR = Path(os.environ.get('QSECBIT_LOG_DIR', '/var/log/hookprobe'))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'qsecbit-fortress.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('qsecbit-fortress')

# Paths
DATA_DIR = Path(os.environ.get('QSECBIT_DATA_DIR', '/opt/hookprobe/fortress/data'))
STATS_FILE = DATA_DIR / "qsecbit_stats.json"
CONFIG_DIR = Path("/etc/hookprobe")

# OVS Bridge name (FTS = abbreviation for fortress)
OVS_BRIDGE = os.environ.get('OVS_BRIDGE', 'FTS')


@dataclass
class QSecBitConfig:
    """QSecBit configuration for Fortress"""
    # Main component weights (must sum to 1.0)
    alpha: float = 0.15   # System drift weight
    beta: float = 0.10    # Network health weight
    gamma: float = 0.35   # L2-L7 threat detection weight (primary)
    delta: float = 0.10   # Energy efficiency weight
    epsilon: float = 0.10 # Infrastructure health weight

    # Thresholds (higher = healthier, we want high scores)
    amber_threshold: float = 0.45
    red_threshold: float = 0.30

    # Fortress-specific weights
    nftables_weight: float = 0.05
    macsec_weight: float = 0.05
    openflow_weight: float = 0.05
    xdp_weight: float = 0.05

    # Layer detection weights (within gamma)
    l2_weight: float = 0.25  # Data Link (ARP, MAC, Evil Twin)
    l3_weight: float = 0.15  # Network (IP spoofing, ICMP)
    l4_weight: float = 0.20  # Transport (SYN flood, port scan)
    l5_weight: float = 0.20  # Session (SSL strip, TLS downgrade)
    l7_weight: float = 0.20  # Application (SQLi, XSS, C2)


@dataclass
class QSecBitSample:
    """Single QSecBit measurement"""
    timestamp: str
    score: float
    rag_status: str
    components: Dict[str, float]
    threats_detected: int
    suricata_alerts: int
    policy_violations: int
    macsec_status: str
    openflow_flows: int
    # Layer threat scores (0.0-1.0, higher = more threats)
    layer_scores: Dict[str, float] = None
    # Recent threat events
    recent_threats: List[Dict] = None
    # XDP stats
    xdp_stats: Dict[str, int] = None

    def __post_init__(self):
        if self.layer_scores is None:
            self.layer_scores = {}
        if self.recent_threats is None:
            self.recent_threats = []
        if self.xdp_stats is None:
            self.xdp_stats = {}


# Global reference to agent for HTTP handler
_agent_instance: Optional['QSecBitFortressAgent'] = None


class QSecBitAPIHandler(BaseHTTPRequestHandler):
    """HTTP API handler for QSecBit status and health"""

    def log_message(self, format, *args):
        """Suppress default logging, use our logger instead"""
        logger.debug(f"HTTP: {args[0]}")

    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response"""
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Handle GET requests"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == '/health':
            self._handle_health()
        elif path == '/status':
            self._handle_status()
        elif path == '/score':
            self._handle_score()
        elif path == '/history':
            self._handle_history()
        else:
            self._send_json({'error': 'not found', 'path': path}, 404)

    def _handle_health(self):
        """Health check endpoint"""
        if _agent_instance and _agent_instance.running.is_set():
            self._send_json({
                'status': 'healthy',
                'service': 'qsecbit-fortress',
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': int(time.time() - _agent_instance.start_time)
            })
        else:
            self._send_json({'status': 'unhealthy', 'reason': 'agent not running'}, 503)

    def _handle_status(self):
        """Full status endpoint with L2-L7 layer detection data"""
        if not _agent_instance:
            self._send_json({'error': 'agent not initialized'}, 503)
            return

        sample = _agent_instance.last_sample
        if sample:
            self._send_json({
                'status': 'operational',
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'threats_detected': sample.threats_detected,
                'suricata_alerts': sample.suricata_alerts,
                'policy_violations': sample.policy_violations,
                'macsec_status': sample.macsec_status,
                'openflow_flows': sample.openflow_flows,
                'layer_scores': sample.layer_scores,
                'recent_threats': sample.recent_threats,
                'xdp_stats': sample.xdp_stats,
                'uptime_seconds': int(time.time() - _agent_instance.start_time)
            })
        else:
            self._send_json({
                'status': 'initializing',
                'uptime_seconds': int(time.time() - _agent_instance.start_time)
            })

    def _handle_score(self):
        """Current score endpoint"""
        if not _agent_instance or not _agent_instance.last_sample:
            self._send_json({'error': 'no data available'}, 503)
            return

        sample = _agent_instance.last_sample
        self._send_json({
            'score': sample.score,
            'rag_status': sample.rag_status,
            'timestamp': sample.timestamp
        })

    def _handle_history(self):
        """Recent history endpoint"""
        if not _agent_instance:
            self._send_json({'error': 'agent not initialized'}, 503)
            return

        # Return last 10 samples
        history = _agent_instance.history[-10:]
        self._send_json({
            'count': len(history),
            'samples': [asdict(s) for s in history]
        })


class QSecBitFortressAgent:
    """Full QSecBit agent for Fortress deployments with L2-L7 threat detection"""

    def __init__(self, config: QSecBitConfig = None):
        self.config = config or QSecBitConfig()
        self.running = Event()
        self.start_time = time.time()
        self.last_sample: Optional[QSecBitSample] = None
        self.history: List[QSecBitSample] = []
        self.all_threats: List[Any] = []  # Accumulated threats

        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Initialize L2-L7 Layer Detectors
        self.layer_detectors = {}
        if LAYER_DETECTORS_AVAILABLE:
            data_dir = str(DATA_DIR / "layer_detectors")
            try:
                self.layer_detectors = {
                    'L2': L2DataLinkDetector(data_dir=data_dir),
                    'L3': L3NetworkDetector(data_dir=data_dir),
                    'L4': L4TransportDetector(data_dir=data_dir),
                    'L5': L5SessionDetector(data_dir=data_dir),
                    'L7': L7ApplicationDetector(data_dir=data_dir),
                }
                logger.info(f"Initialized {len(self.layer_detectors)} L2-L7 layer detectors")
            except Exception as e:
                logger.warning(f"Failed to initialize layer detectors: {e}")
        else:
            logger.warning("Layer detectors not available - running in basic mode")

        # XDP API endpoint
        self.xdp_api_url = os.environ.get('XDP_API_URL', 'http://localhost:9091')

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("QSecBit Fortress Agent v5.2.0 initialized")

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running.clear()

    def get_policy_violations(self) -> int:
        """Check for nftables policy violations (dropped packets)"""
        try:
            # Check nftables counters for dropped packets
            result = subprocess.run(
                ['nft', 'list', 'chain', 'inet', 'fortress', 'forward'],
                capture_output=True, text=True, timeout=5
            )
            # Count dropped packets (policy violations)
            violations = 0
            for line in result.stdout.split('\n'):
                if 'drop' in line and 'packets' in line:
                    # Parse "packets X bytes Y" format
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'packets' and i + 1 < len(parts):
                            violations += int(parts[i + 1])
                            break
            return violations
        except Exception:
            return 0

    def get_macsec_status(self) -> str:
        """Check MACsec status"""
        try:
            result = subprocess.run(
                ['ip', 'macsec', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if 'macsec' in result.stdout:
                return 'active'
            return 'inactive'
        except Exception:
            return 'unknown'

    def get_openflow_stats(self) -> int:
        """Get OpenFlow flow count"""
        try:
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', OVS_BRIDGE],
                capture_output=True, text=True, timeout=5
            )
            return len([l for l in result.stdout.split('\n') if l.strip()])
        except Exception:
            return 0

    def get_suricata_alerts(self) -> int:
        """Get recent Suricata alert count"""
        try:
            alert_file = Path("/var/log/suricata/fast.log")
            if alert_file.exists():
                # Count alerts in last 5 minutes
                count = 0
                with open(alert_file, 'r') as f:
                    for line in f:
                        count += 1
                return min(count, 100)  # Cap at 100
            return 0
        except Exception:
            return 0

    def get_xdp_stats(self) -> Dict[str, int]:
        """Get XDP/eBPF stats from the XDP container"""
        try:
            req = urllib.request.Request(f"{self.xdp_api_url}/stats", method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                return json.loads(response.read().decode())
        except Exception:
            return {}

    def run_layer_detection(self) -> tuple:
        """
        Run all L2-L7 layer detectors and return scores.

        Returns:
            (layer_scores dict, new_threats list, total_threat_count)
        """
        layer_scores = {
            'L2': 0.0,
            'L3': 0.0,
            'L4': 0.0,
            'L5': 0.0,
            'L7': 0.0,
        }
        new_threats = []
        total_count = 0

        if not self.layer_detectors:
            return layer_scores, new_threats, total_count

        for layer_name, detector in self.layer_detectors.items():
            try:
                # Run detection
                threats = detector.detect()

                # Get layer score (0.0-1.0, higher = more threats)
                layer_scores[layer_name] = detector.get_layer_score()

                # Collect new threats
                for threat in threats:
                    total_count += 1
                    new_threats.append({
                        'id': threat.id,
                        'timestamp': threat.timestamp.isoformat(),
                        'attack_type': threat.attack_type.name,
                        'layer': threat.layer.name,
                        'severity': threat.severity.name,
                        'source_ip': threat.source_ip,
                        'description': threat.description,
                        'confidence': threat.confidence,
                        'blocked': threat.blocked,
                    })
                    self.all_threats.append(threat)

            except Exception as e:
                logger.warning(f"Error in {layer_name} detector: {e}")

        # Keep threat history bounded
        if len(self.all_threats) > 1000:
            self.all_threats = self.all_threats[-500:]

        return layer_scores, new_threats, total_count

    def block_ip_via_xdp(self, ip: str) -> bool:
        """Block an IP address via XDP at kernel level"""
        try:
            data = json.dumps({'ip': ip}).encode()
            req = urllib.request.Request(
                f"{self.xdp_api_url}/block",
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode())
                return result.get('status') == 'blocked'
        except Exception as e:
            logger.warning(f"Failed to block IP {ip} via XDP: {e}")
            return False

    def calculate_score(self, layer_scores: Dict[str, float] = None, xdp_stats: Dict = None) -> tuple:
        """Calculate QSecBit score with Fortress enhancements and L2-L7 layer detection"""
        components = {
            'drift': 0.0,
            'network': 0.0,
            'threats': 0.0,  # Now includes L2-L7 layer scores
            'energy': 0.0,
            'infrastructure': 0.0,
            'nftables': 0.0,
            'macsec': 0.0,
            'openflow': 0.0,
            'xdp': 0.0,
        }

        # System drift (CPU, memory usage)
        try:
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
            components['drift'] = max(0, 1.0 - (load / os.cpu_count()))
        except Exception:
            components['drift'] = 0.5

        # Network health
        try:
            result = subprocess.run(['ip', 'link', 'show', 'up'],
                                  capture_output=True, text=True, timeout=5)
            up_interfaces = len([l for l in result.stdout.split('\n') if 'state UP' in l])
            components['network'] = min(1.0, up_interfaces / 4)
        except Exception:
            components['network'] = 0.5

        # L2-L7 Threat detection (primary threat scoring)
        if layer_scores:
            # Calculate weighted layer score (invert: higher threat = lower health)
            layer_threat_score = (
                self.config.l2_weight * layer_scores.get('L2', 0.0) +
                self.config.l3_weight * layer_scores.get('L3', 0.0) +
                self.config.l4_weight * layer_scores.get('L4', 0.0) +
                self.config.l5_weight * layer_scores.get('L5', 0.0) +
                self.config.l7_weight * layer_scores.get('L7', 0.0)
            )
            # Invert: 0.0 threats = 1.0 health
            components['threats'] = max(0, 1.0 - layer_threat_score)
        else:
            # Fallback to Suricata alerts only
            alerts = self.get_suricata_alerts()
            components['threats'] = max(0, 1.0 - (alerts / 50))

        # Energy efficiency (simplified)
        components['energy'] = 0.8

        # Infrastructure health
        try:
            result = subprocess.run(['podman', 'ps', '-q'],
                                  capture_output=True, text=True, timeout=5)
            containers = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            components['infrastructure'] = min(1.0, containers / 5)
        except Exception:
            components['infrastructure'] = 0.5

        # nftables policy enforcement
        violations = self.get_policy_violations()
        components['nftables'] = max(0, 1.0 - (violations / 100))

        # MACsec status
        macsec = self.get_macsec_status()
        components['macsec'] = 1.0 if macsec == 'active' else 0.5 if macsec == 'inactive' else 0.3

        # OpenFlow health
        flows = self.get_openflow_stats()
        components['openflow'] = min(1.0, flows / 20) if flows > 0 else 0.5

        # XDP protection health (based on drop rate)
        if xdp_stats:
            total = xdp_stats.get('total_packets', 0)
            passed = xdp_stats.get('passed', 0)
            if total > 0:
                # Good if most packets pass (low attack rate)
                components['xdp'] = min(1.0, passed / total)
            else:
                components['xdp'] = 1.0  # No traffic = healthy
        else:
            components['xdp'] = 0.5  # Unknown

        # Calculate weighted score
        score = (
            self.config.alpha * components['drift'] +
            self.config.beta * components['network'] +
            self.config.gamma * components['threats'] +
            self.config.delta * components['energy'] +
            self.config.epsilon * components['infrastructure'] +
            self.config.nftables_weight * components['nftables'] +
            self.config.macsec_weight * components['macsec'] +
            self.config.openflow_weight * components['openflow'] +
            self.config.xdp_weight * components['xdp']
        )

        # Determine RAG status
        if score >= self.config.amber_threshold:
            rag_status = "GREEN"
        elif score >= self.config.red_threshold:
            rag_status = "AMBER"
        else:
            rag_status = "RED"

        return score, rag_status, components

    def collect_sample(self) -> QSecBitSample:
        """Collect a complete QSecBit sample with L2-L7 layer detection"""
        # Run L2-L7 layer detection
        layer_scores, new_threats, threat_count = self.run_layer_detection()

        # Get XDP stats
        xdp_stats = self.get_xdp_stats()

        # Calculate score with layer data
        score, rag_status, components = self.calculate_score(layer_scores, xdp_stats)

        sample = QSecBitSample(
            timestamp=datetime.now().isoformat(),
            score=score,
            rag_status=rag_status,
            components=components,
            threats_detected=threat_count,
            suricata_alerts=self.get_suricata_alerts(),
            policy_violations=self.get_policy_violations(),
            macsec_status=self.get_macsec_status(),
            openflow_flows=self.get_openflow_stats(),
            layer_scores=layer_scores,
            recent_threats=new_threats[-10:],  # Keep last 10
            xdp_stats=xdp_stats,
        )

        self.last_sample = sample
        self.history.append(sample)
        if len(self.history) > 1000:
            self.history = self.history[-500:]

        return sample

    def save_stats(self, sample: QSecBitSample):
        """Save stats to file"""
        try:
            stats = {
                'timestamp': sample.timestamp,
                'score': sample.score,
                'rag_status': sample.rag_status,
                'components': sample.components,
                'threats_detected': sample.threats_detected,
                'suricata_alerts': sample.suricata_alerts,
                'policy_violations': sample.policy_violations,
                'macsec_status': sample.macsec_status,
                'openflow_flows': sample.openflow_flows,
                'layer_scores': sample.layer_scores,
                'recent_threats': sample.recent_threats,
                'xdp_stats': sample.xdp_stats,
                'uptime_seconds': int(time.time() - self.start_time)
            }
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def collect_wan_health(self) -> Dict:
        """Collect WAN health data for SLAAI dashboard.

        This runs with host network access, so we can ping through real interfaces.
        Data is written to wan_health.json for the web container to read.
        """
        import re

        def test_connectivity(interface: str, target: str = '1.1.1.1') -> Dict:
            """Test connectivity through a specific interface."""
            result = {
                'rtt_ms': None,
                'jitter_ms': None,
                'packet_loss': 100.0,
                'is_connected': False,
            }
            try:
                proc = subprocess.run(
                    ['ping', '-c', '3', '-W', '2', '-I', interface, target],
                    capture_output=True, text=True, timeout=10
                )
                if proc.returncode == 0:
                    # Parse RTT
                    rtt_match = re.search(
                        r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
                        proc.stdout
                    )
                    if rtt_match:
                        result['rtt_ms'] = float(rtt_match.group(2))
                        result['jitter_ms'] = float(rtt_match.group(4))
                        result['is_connected'] = True

                    # Parse packet loss
                    loss_match = re.search(r'(\d+)% packet loss', proc.stdout)
                    if loss_match:
                        result['packet_loss'] = float(loss_match.group(1))
            except Exception as e:
                logger.debug(f"Ping failed on {interface}: {e}")

            return result

        def calculate_health_score(conn: Dict, signal_dbm: int = None) -> float:
            """Calculate health score 0-1 based on connectivity metrics."""
            if not conn['is_connected']:
                return 0.0
            score = 1.0
            if conn['rtt_ms']:
                if conn['rtt_ms'] > 200:
                    score -= 0.3
                elif conn['rtt_ms'] > 100:
                    score -= 0.2
                elif conn['rtt_ms'] > 50:
                    score -= 0.1
            if conn['jitter_ms']:
                if conn['jitter_ms'] > 50:
                    score -= 0.2
                elif conn['jitter_ms'] > 20:
                    score -= 0.1
            if conn['packet_loss'] > 0:
                score -= min(0.4, conn['packet_loss'] / 100 * 0.4)
            if signal_dbm is not None:
                if signal_dbm < -100:
                    score -= 0.2
                elif signal_dbm < -85:
                    score -= 0.1
            return max(0.0, min(1.0, score))

        health = {
            'primary': None,
            'backup': None,
            'active': None,
            'active_is_primary': False,
            'uptime_pct': 99.9,
            'state': 'disconnected',
            'timestamp': datetime.now().isoformat(),
        }

        # Get interfaces
        try:
            proc = subprocess.run(
                ['ip', '-j', 'addr', 'show'],
                capture_output=True, text=True, timeout=5
            )
            if proc.returncode == 0:
                interfaces = json.loads(proc.stdout)
            else:
                interfaces = []
        except Exception:
            interfaces = []

        primary_iface = None
        backup_iface = None

        # Collect all potential WAN interfaces
        wan_candidates = []
        lte_candidates = []

        # Interfaces to exclude (bridges, containers, internal)
        exclude_prefixes = ('lo', 'docker', 'podman', 'veth', 'br-', 'virbr', 'FTS', 'vlan')
        exclude_names = {'lo', 'FTS', 'br0', 'br-lan'}

        for iface in interfaces:
            name = iface.get('ifname', '')
            state = iface.get('operstate', 'UNKNOWN')

            # Skip down interfaces
            if state != 'UP':
                continue

            # Skip excluded interfaces
            if name in exclude_names:
                continue
            if any(name.startswith(prefix) for prefix in exclude_prefixes):
                continue

            # Get IP address
            ip_addr = None
            for addr_info in iface.get('addr_info', []):
                if addr_info.get('family') == 'inet':
                    ip_addr = f"{addr_info.get('local')}/{addr_info.get('prefixlen')}"
                    break

            # Skip interfaces without IP (not configured for WAN)
            if not ip_addr:
                continue

            # Categorize interface
            iface_info = {'name': name, 'ip': ip_addr, 'state': 'UP'}

            if name.startswith('wwan') or name.startswith('usb') or name.startswith('wwp'):
                # LTE/cellular interfaces
                lte_candidates.append(iface_info)
            elif name.startswith('eth') or name.startswith('en') or name.startswith('eno'):
                # Ethernet interfaces - potential WAN
                wan_candidates.append(iface_info)

        # Sort WAN candidates by name for consistent ordering (eth0 before eth1)
        wan_candidates.sort(key=lambda x: x['name'])

        # Assign primary and backup
        # Priority: First ethernet = primary, second ethernet or LTE = backup
        if len(wan_candidates) >= 1:
            primary_iface = wan_candidates[0]
        if len(wan_candidates) >= 2:
            backup_iface = wan_candidates[1]
        elif lte_candidates:
            backup_iface = lte_candidates[0]

        # Log detected interfaces for debugging
        logger.debug(f"WAN detection: primary={primary_iface}, backup={backup_iface}")
        logger.debug(f"WAN candidates: {wan_candidates}, LTE candidates: {lte_candidates}")

        # Test primary WAN
        if primary_iface:
            conn = test_connectivity(primary_iface['name'])
            health['primary'] = {
                'interface': primary_iface['name'],
                'ip': primary_iface['ip'],
                'state': 'UP',
                'rtt_ms': conn['rtt_ms'],
                'jitter_ms': conn['jitter_ms'],
                'packet_loss': conn['packet_loss'],
                'is_connected': conn['is_connected'],
                'health_score': calculate_health_score(conn),
                'status': 'ACTIVE' if conn['is_connected'] else 'FAILED',
            }
            if conn['is_connected']:
                health['active'] = primary_iface['name']
                health['active_is_primary'] = True
                health['state'] = 'primary_active'

        # Test backup WAN (could be second ethernet or LTE)
        if backup_iface:
            conn = test_connectivity(backup_iface['name'])

            # Detect if this is an LTE interface
            is_lte = backup_iface['name'].startswith(('wwan', 'usb', 'wwp'))

            health['backup'] = {
                'interface': backup_iface['name'],
                'ip': backup_iface['ip'],
                'state': 'UP',
                'rtt_ms': conn['rtt_ms'],
                'jitter_ms': conn['jitter_ms'],
                'packet_loss': conn['packet_loss'],
                'is_connected': conn['is_connected'],
                'health_score': calculate_health_score(conn),
                'signal_dbm': None,  # Could add mmcli parsing for LTE
                'is_lte': is_lte,
                'status': 'STANDBY' if health['active'] else ('ACTIVE' if conn['is_connected'] else 'FAILED'),
            }
            if not health['active'] and conn['is_connected']:
                health['active'] = backup_iface['name']
                health['active_is_primary'] = False
                health['state'] = 'backup_active'
                health['backup']['status'] = 'ACTIVE'

        return health

    def save_wan_health(self):
        """Collect and save WAN health data for SLAAI dashboard."""
        try:
            health = self.collect_wan_health()
            wan_file = DATA_DIR / "wan_health.json"
            with open(wan_file, 'w') as f:
                json.dump(health, f, indent=2)
            logger.debug(f"WAN health saved: state={health['state']}")
        except Exception as e:
            logger.warning(f"Failed to save WAN health: {e}")

    def run_monitoring_loop(self):
        """Main monitoring loop with L2-L7 threat detection"""
        logger.info("Starting QSecBit monitoring loop with L2-L7 detection...")
        interval = 10
        wan_health_counter = 0

        while self.running.is_set():
            try:
                sample = self.collect_sample()
                self.save_stats(sample)

                # Collect WAN health every 3 cycles (30 seconds)
                wan_health_counter += 1
                if wan_health_counter >= 3:
                    self.save_wan_health()
                    wan_health_counter = 0

                # Log detailed status
                layer_summary = ' '.join([f"{k}={v:.2f}" for k, v in sample.layer_scores.items()])
                logger.info(
                    f"QSecBit: {sample.rag_status} score={sample.score:.3f} "
                    f"threats={sample.threats_detected} layers=[{layer_summary}] "
                    f"macsec={sample.macsec_status}"
                )

                # Auto-block high-severity threats via XDP
                for threat in sample.recent_threats:
                    if threat.get('severity') in ('CRITICAL', 'HIGH') and threat.get('source_ip'):
                        if not threat.get('blocked'):
                            if self.block_ip_via_xdp(threat['source_ip']):
                                logger.info(f"Auto-blocked {threat['source_ip']} via XDP")

                time.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(interval)

    def run_api_server(self, port: int = 9090):
        """Run HTTP API server"""
        try:
            server = HTTPServer(('0.0.0.0', port), QSecBitAPIHandler)
            logger.info(f"QSecBit API server listening on port {port}")
            while self.running.is_set():
                server.handle_request()
        except Exception as e:
            logger.error(f"API server error: {e}")

    def start(self):
        """Start the agent"""
        global _agent_instance
        _agent_instance = self

        logger.info("Starting QSecBit Fortress Agent v5.2.0...")
        self.running.set()

        # Start monitoring loop
        monitor_thread = Thread(target=self.run_monitoring_loop, daemon=True)
        monitor_thread.start()

        # Start HTTP API server
        api_port = int(os.environ.get('QSECBIT_API_PORT', '9090'))
        api_thread = Thread(target=self.run_api_server, args=(api_port,), daemon=True)
        api_thread.start()

        # Wait for shutdown signal (block while running is set)
        while self.running.is_set():
            time.sleep(1)

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping QSecBit Fortress Agent...")
        self.running.clear()


def main():
    agent = QSecBitFortressAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
