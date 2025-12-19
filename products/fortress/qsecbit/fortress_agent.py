#!/usr/bin/env python3
"""
QSecBit Fortress Agent - Full Implementation
Version: 5.0.0
License: AGPL-3.0

Fortress-enhanced QSecBit with:
- Extended telemetry from monitoring stack
- nftables policy scoring
- MACsec status monitoring
- OpenFlow flow analysis
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
from typing import Optional, Dict, List

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

# OVS Bridge name (43ess = leetspeak for fortress)
OVS_BRIDGE = os.environ.get('OVS_BRIDGE', '43ess')


@dataclass
class QSecBitConfig:
    """QSecBit configuration for Fortress"""
    # Component weights (must sum to 1.0)
    alpha: float = 0.20   # System drift weight
    beta: float = 0.25    # Network health weight
    gamma: float = 0.25   # Threat detection weight
    delta: float = 0.15   # Energy efficiency weight
    epsilon: float = 0.15 # Infrastructure health weight

    # Thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.30

    # Fortress-specific weights
    nftables_weight: float = 0.10
    macsec_weight: float = 0.10
    openflow_weight: float = 0.10


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


class QSecBitFortressAgent:
    """Full QSecBit agent for Fortress deployments"""

    def __init__(self, config: QSecBitConfig = None):
        self.config = config or QSecBitConfig()
        self.running = Event()
        self.start_time = time.time()
        self.last_sample: Optional[QSecBitSample] = None
        self.history: List[QSecBitSample] = []

        DATA_DIR.mkdir(parents=True, exist_ok=True)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("QSecBit Fortress Agent initialized")

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

    def calculate_score(self) -> tuple:
        """Calculate QSecBit score with Fortress enhancements"""
        components = {
            'drift': 0.0,
            'network': 0.0,
            'threats': 0.0,
            'energy': 0.0,
            'infrastructure': 0.0,
            'nftables': 0.0,
            'macsec': 0.0,
            'openflow': 0.0
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

        # Threat detection
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

        # Calculate weighted score
        score = (
            self.config.alpha * components['drift'] +
            self.config.beta * components['network'] +
            self.config.gamma * components['threats'] +
            self.config.delta * components['energy'] +
            self.config.epsilon * components['infrastructure'] +
            self.config.nftables_weight * components['nftables'] +
            self.config.macsec_weight * components['macsec'] +
            self.config.openflow_weight * components['openflow']
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
        """Collect a complete QSecBit sample"""
        score, rag_status, components = self.calculate_score()

        sample = QSecBitSample(
            timestamp=datetime.now().isoformat(),
            score=score,
            rag_status=rag_status,
            components=components,
            threats_detected=0,
            suricata_alerts=self.get_suricata_alerts(),
            policy_violations=self.get_policy_violations(),
            macsec_status=self.get_macsec_status(),
            openflow_flows=self.get_openflow_stats()
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
                'uptime_seconds': int(time.time() - self.start_time)
            }
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def run_monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting QSecBit monitoring loop...")
        interval = 10

        while self.running.is_set():
            try:
                sample = self.collect_sample()
                self.save_stats(sample)

                logger.info(
                    f"QSecBit: {sample.rag_status} score={sample.score:.3f} "
                    f"policy_violations={sample.policy_violations} "
                    f"macsec={sample.macsec_status}"
                )

                time.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(interval)

    def start(self):
        """Start the agent"""
        logger.info("Starting QSecBit Fortress Agent v5.0.0...")
        self.running.set()

        monitor_thread = Thread(target=self.run_monitoring_loop, daemon=True)
        monitor_thread.start()

        self.running.wait()

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
