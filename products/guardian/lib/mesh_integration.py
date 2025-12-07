#!/usr/bin/env python3
"""
Guardian Mesh Integration - Decentralized Security Mesh for Guardian

This module integrates the Guardian tier with the HookProbe mesh consciousness,
enabling peer-to-peer threat intelligence sharing and coordinated defense.

Features:
- Automatic peer discovery on local network
- Real-time threat intelligence sharing
- Collective QSecBit scoring
- Autonomous operation when MSSP unavailable
- Coordinated defense response

Usage:
    from mesh_integration import GuardianMeshAgent

    agent = GuardianMeshAgent()
    agent.start()

    # Report a threat to the mesh
    agent.report_threat(
        threat_type="port_scan",
        severity=3,
        ioc_type="ip",
        ioc_value="192.168.1.100"
    )

Author: HookProbe Team
Version: 5.0.0
License: MIT
"""

import os
import sys
import json
import time
import signal
import logging
import hashlib
import secrets
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'shared'))

# Import mesh components
try:
    from mesh import (
        MeshConsciousness,
        TierRole,
        ConsciousnessState,
        ThreatIntelligence,
        create_consciousness,
    )
    MESH_AVAILABLE = True
except ImportError:
    MESH_AVAILABLE = False
    logging.warning("Mesh module not available - running in standalone mode")

# Import existing Guardian components
try:
    from guardian_agent import GuardianAgent, GuardianMetrics
    GUARDIAN_AVAILABLE = True
except ImportError:
    GUARDIAN_AVAILABLE = False


@dataclass
class MeshConfig:
    """Configuration for mesh integration."""

    # Neural seed - MUST be shared across all mesh nodes
    # In production, this would be provisioned during deployment
    neuro_seed: bytes = b"HookProbe-Mesh-Seed-v5.0-Liberty"

    # Bootstrap peers for initial mesh connection
    bootstrap_peers: List[str] = None

    # Data directory
    data_dir: str = "/opt/hookprobe/guardian/data"

    # Enable mesh mode
    enabled: bool = True

    # Autonomous mode (operate without MSSP)
    autonomous_enabled: bool = True

    # Threat sharing enabled
    threat_sharing: bool = True

    # Collective scoring enabled
    collective_scoring: bool = True

    # Check interval for mesh health
    health_check_interval: int = 60

    def __post_init__(self):
        if self.bootstrap_peers is None:
            self.bootstrap_peers = []


class GuardianMeshAgent:
    """
    Guardian Mesh Agent - Integrates Guardian with the decentralized mesh.

    This agent bridges the local Guardian threat detection with the
    collective mesh consciousness, enabling:

    1. Local threats to be shared with the mesh
    2. Mesh intelligence to inform local detection
    3. Collective QSecBit scoring
    4. Autonomous operation without MSSP
    """

    def __init__(
        self,
        config: Optional[MeshConfig] = None,
        guardian_agent: Optional['GuardianAgent'] = None,
    ):
        """
        Initialize mesh agent.

        Args:
            config: Mesh configuration
            guardian_agent: Existing Guardian agent instance
        """
        self.config = config or MeshConfig()
        self.guardian = guardian_agent

        # Logging
        self.logger = logging.getLogger("GuardianMeshAgent")

        # Mesh consciousness
        self.consciousness: Optional[MeshConsciousness] = None

        # Threading
        self.running = False
        self._threads: List[threading.Thread] = []
        self._stop_event = threading.Event()

        # Callbacks for threat handling
        self._on_mesh_threat: List[Callable[[ThreatIntelligence], None]] = []

        # Statistics
        self.stats = {
            'threats_reported': 0,
            'threats_received': 0,
            'collective_score_updates': 0,
            'mssp_fallbacks': 0,
            'autonomous_operations': 0,
        }

        # Last collective score
        self._collective_score: Optional[float] = None
        self._collective_rag: str = "UNKNOWN"

    def start(self) -> bool:
        """
        Start the mesh agent.

        Returns:
            True if started successfully
        """
        if not MESH_AVAILABLE:
            self.logger.error("Mesh module not available")
            return False

        if not self.config.enabled:
            self.logger.info("Mesh mode disabled in config")
            return False

        self.logger.info("Starting Guardian Mesh Agent")

        try:
            # Create mesh consciousness
            self.consciousness = create_consciousness(
                tier_name="guardian",
                neuro_seed=self.config.neuro_seed,
                data_dir=self.config.data_dir,
            )

            # Register callbacks
            self.consciousness.on_intelligence(self._handle_mesh_intel)
            self.consciousness.on_peer_joined(self._handle_peer_joined)
            self.consciousness.on_peer_left(self._handle_peer_left)

            # Awaken consciousness
            self.consciousness.awaken(self.config.bootstrap_peers)

            self.running = True

            # Start background threads
            self._start_threads()

            self.logger.info("Guardian Mesh Agent started")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start mesh agent: {e}")
            return False

    def stop(self) -> None:
        """Stop the mesh agent."""
        self.logger.info("Stopping Guardian Mesh Agent")

        self.running = False
        self._stop_event.set()

        # Stop consciousness
        if self.consciousness:
            self.consciousness.sleep()

        # Wait for threads
        for thread in self._threads:
            thread.join(timeout=2.0)

        self.logger.info("Guardian Mesh Agent stopped")

    def _start_threads(self) -> None:
        """Start background threads."""
        threads = [
            ("health_check", self._health_check_loop),
            ("threat_sync", self._threat_sync_loop),
        ]

        if self.config.collective_scoring:
            threads.append(("collective_score", self._collective_score_loop))

        for name, target in threads:
            thread = threading.Thread(
                target=target,
                name=f"mesh_{name}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def _health_check_loop(self) -> None:
        """Health check loop."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.config.health_check_interval)

            if self._stop_event.is_set():
                break

            self._check_mesh_health()

    def _threat_sync_loop(self) -> None:
        """Sync local threats to mesh."""
        while not self._stop_event.is_set():
            self._stop_event.wait(30)  # Every 30 seconds

            if self._stop_event.is_set():
                break

            if self.guardian and self.config.threat_sharing:
                self._sync_local_threats()

    def _collective_score_loop(self) -> None:
        """Update collective QSecBit score."""
        while not self._stop_event.is_set():
            self._stop_event.wait(60)  # Every minute

            if self._stop_event.is_set():
                break

            self._update_collective_score()

    # =========================================================================
    # THREAT HANDLING
    # =========================================================================

    def report_threat(
        self,
        threat_type: str,
        severity: int,
        ioc_type: str,
        ioc_value: str,
        confidence: float = 0.8,
        context: Optional[Dict] = None,
    ) -> bool:
        """
        Report a locally detected threat to the mesh.

        Args:
            threat_type: Type of threat
            severity: 1-5 (1=critical, 5=info)
            ioc_type: "ip", "domain", "hash", "pattern"
            ioc_value: The indicator value
            confidence: Detection confidence
            context: Additional context

        Returns:
            True if reported successfully
        """
        if not self.consciousness:
            return False

        try:
            intel = self.consciousness.report_threat(
                threat_type=threat_type,
                severity=severity,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                confidence=confidence,
                context=context,
            )

            self.stats['threats_reported'] += 1

            self.logger.info(
                f"Reported threat to mesh: {threat_type} "
                f"({ioc_type}={ioc_value})"
            )

            return True

        except Exception as e:
            self.logger.error(f"Failed to report threat: {e}")
            return False

    def lookup_threat(self, ioc_value: str) -> List[ThreatIntelligence]:
        """
        Lookup threat intelligence for an IOC.

        Args:
            ioc_value: The indicator to lookup

        Returns:
            List of matching intelligence
        """
        if not self.consciousness:
            return []

        return self.consciousness.lookup_threat(ioc_value)

    def _handle_mesh_intel(self, intel: ThreatIntelligence) -> None:
        """Handle intelligence received from mesh."""
        self.stats['threats_received'] += 1

        self.logger.info(
            f"Received mesh intel: {intel.threat_type} "
            f"({intel.ioc_type}={intel.ioc_value}) "
            f"from {intel.source_node_id.hex()[:8]}"
        )

        # Notify callbacks
        for callback in self._on_mesh_threat:
            try:
                callback(intel)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")

        # Could trigger local defense actions here based on severity
        if intel.severity <= 2:  # Critical or High
            self._trigger_defense_action(intel)

    def _trigger_defense_action(self, intel: ThreatIntelligence) -> None:
        """Trigger local defense action based on mesh intelligence."""
        self.logger.warning(
            f"Triggering defense for {intel.threat_type} "
            f"({intel.ioc_type}={intel.ioc_value})"
        )

        # Example: Block IP via XDP if threat is IP-based
        if intel.ioc_type == "ip":
            self._block_ip(intel.ioc_value)

    def _block_ip(self, ip: str) -> None:
        """Block an IP address via local firewall/XDP."""
        # This would integrate with XDP manager or iptables
        self.logger.info(f"Would block IP: {ip}")

    def _sync_local_threats(self) -> None:
        """Sync local Guardian threats to mesh."""
        if not self.guardian:
            return

        try:
            # Get recent threats from Guardian
            threat_report = self.guardian.run_threat_detection()

            for threat in threat_report.get('recent_threats', []):
                # Convert to mesh threat
                self.report_threat(
                    threat_type=threat.get('type', 'unknown'),
                    severity=threat.get('severity', 3),
                    ioc_type=threat.get('ioc_type', 'pattern'),
                    ioc_value=threat.get('ioc_value', str(threat)),
                    confidence=threat.get('confidence', 0.7),
                    context=threat,
                )

        except Exception as e:
            self.logger.error(f"Threat sync error: {e}")

    # =========================================================================
    # COLLECTIVE SCORING
    # =========================================================================

    def _update_collective_score(self) -> None:
        """Update collective QSecBit score from mesh."""
        if not self.consciousness:
            return

        try:
            # Get recent intelligence from mesh
            recent_intel = self.consciousness.threat_cache.get_recent(limit=100)

            if not recent_intel:
                return

            # Calculate collective threat score
            severity_weights = {1: 1.0, 2: 0.7, 3: 0.4, 4: 0.2, 5: 0.1}

            total_weight = 0.0
            for intel in recent_intel:
                # Weight by severity and confidence
                weight = severity_weights.get(intel.severity, 0.1)
                total_weight += weight * intel.confidence

            # Normalize to 0-1
            collective_threat = min(1.0, total_weight / 10.0)

            # Get local score
            local_score = 0.0
            if self.guardian:
                metrics = self.guardian.get_current_status()
                local_score = metrics.get('score', 0.0)

            # Combine local and collective (weighted average)
            # Local: 60%, Collective: 40%
            combined_score = local_score * 0.6 + collective_threat * 0.4

            self._collective_score = combined_score

            # Determine RAG status
            if combined_score >= 0.70:
                self._collective_rag = "RED"
            elif combined_score >= 0.45:
                self._collective_rag = "AMBER"
            else:
                self._collective_rag = "GREEN"

            self.stats['collective_score_updates'] += 1

            self.logger.debug(
                f"Collective score: {combined_score:.3f} ({self._collective_rag})"
            )

        except Exception as e:
            self.logger.error(f"Collective score update error: {e}")

    def get_collective_score(self) -> Dict[str, Any]:
        """Get current collective QSecBit score."""
        return {
            'score': self._collective_score,
            'rag_status': self._collective_rag,
            'peer_count': self.consciousness.peer_count if self.consciousness else 0,
            'intel_count': len(self.consciousness.threat_cache) if self.consciousness else 0,
        }

    # =========================================================================
    # HEALTH & STATUS
    # =========================================================================

    def _check_mesh_health(self) -> None:
        """Check mesh health and connectivity."""
        if not self.consciousness:
            return

        status = self.consciousness.get_status()

        if status['peer_count'] == 0:
            self.logger.warning("No mesh peers connected")

            # Try to reconnect
            if self.config.bootstrap_peers:
                for peer in self.config.bootstrap_peers:
                    try:
                        self.consciousness._connect_to_peer(peer)
                    except Exception:
                        pass

        # Check autonomous mode
        if status['state'] == 'AUTONOMOUS':
            self.stats['autonomous_operations'] += 1
            self.logger.info("Operating in autonomous mode")

    def _handle_peer_joined(self, peer: 'PeerNode') -> None:
        """Handle peer joining the mesh."""
        self.logger.info(
            f"Peer joined: {peer.node_id.hex()[:8]} ({peer.tier.name})"
        )

    def _handle_peer_left(self, peer: 'PeerNode') -> None:
        """Handle peer leaving the mesh."""
        self.logger.info(
            f"Peer left: {peer.node_id.hex()[:8]} ({peer.tier.name})"
        )

    def get_status(self) -> Dict[str, Any]:
        """Get mesh agent status."""
        mesh_status = {}
        if self.consciousness:
            mesh_status = self.consciousness.get_status()

        return {
            'running': self.running,
            'mesh': mesh_status,
            'stats': self.stats,
            'collective_score': self.get_collective_score(),
            'config': {
                'enabled': self.config.enabled,
                'autonomous_enabled': self.config.autonomous_enabled,
                'threat_sharing': self.config.threat_sharing,
                'bootstrap_peers': len(self.config.bootstrap_peers),
            },
        }

    def get_peers(self) -> List[Dict[str, Any]]:
        """Get list of mesh peers."""
        if not self.consciousness:
            return []
        return self.consciousness.get_peers()

    # =========================================================================
    # CALLBACKS
    # =========================================================================

    def on_mesh_threat(
        self,
        callback: Callable[[ThreatIntelligence], None],
    ) -> None:
        """Register callback for mesh threats."""
        self._on_mesh_threat.append(callback)


# =============================================================================
# DAEMON MODE
# =============================================================================

class GuardianMeshDaemon:
    """
    Daemon mode for Guardian Mesh Agent.

    Runs as a background service, integrating with systemd.
    """

    def __init__(
        self,
        config_file: str = "/opt/hookprobe/guardian/mesh.conf",
        data_dir: str = "/opt/hookprobe/guardian/data",
    ):
        self.config_file = Path(config_file)
        self.data_dir = Path(data_dir)

        # Load config
        self.config = self._load_config()

        # Create agents
        if GUARDIAN_AVAILABLE:
            self.guardian = GuardianAgent(
                data_dir=str(self.data_dir),
                verbose=True,
            )
        else:
            self.guardian = None

        self.mesh_agent = GuardianMeshAgent(
            config=self.config,
            guardian_agent=self.guardian,
        )

        self.running = False

    def _load_config(self) -> MeshConfig:
        """Load configuration from file."""
        config = MeshConfig()

        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    data = json.load(f)

                if 'neuro_seed' in data:
                    config.neuro_seed = bytes.fromhex(data['neuro_seed'])
                if 'bootstrap_peers' in data:
                    config.bootstrap_peers = data['bootstrap_peers']
                if 'enabled' in data:
                    config.enabled = data['enabled']
                if 'autonomous_enabled' in data:
                    config.autonomous_enabled = data['autonomous_enabled']
                if 'threat_sharing' in data:
                    config.threat_sharing = data['threat_sharing']

            except Exception as e:
                logging.warning(f"Could not load config: {e}")

        config.data_dir = str(self.data_dir)
        return config

    def start(self) -> None:
        """Start the daemon."""
        logging.info("Starting Guardian Mesh Daemon")

        self.running = True

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        # Start mesh agent
        if not self.mesh_agent.start():
            logging.error("Failed to start mesh agent")
            return

        # Start Guardian agent in daemon mode
        if self.guardian:
            threading.Thread(
                target=self.guardian.start_daemon,
                daemon=True,
            ).start()

        # Main loop
        while self.running:
            time.sleep(1)

        self.stop()

    def stop(self) -> None:
        """Stop the daemon."""
        logging.info("Stopping Guardian Mesh Daemon")

        self.running = False
        self.mesh_agent.stop()

        if self.guardian:
            self.guardian.running = False

    def _signal_handler(self, signum, frame) -> None:
        """Handle signals."""
        logging.info(f"Received signal {signum}")
        self.running = False


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Guardian Mesh Agent')
    parser.add_argument(
        '--config',
        default='/opt/hookprobe/guardian/mesh.conf',
        help='Configuration file',
    )
    parser.add_argument(
        '--data-dir',
        default='/opt/hookprobe/guardian/data',
        help='Data directory',
    )
    parser.add_argument(
        '--daemon',
        action='store_true',
        help='Run as daemon',
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose logging',
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    )

    if args.daemon:
        daemon = GuardianMeshDaemon(
            config_file=args.config,
            data_dir=args.data_dir,
        )
        daemon.start()
    else:
        # Quick test mode
        config = MeshConfig()
        agent = GuardianMeshAgent(config=config)

        if agent.start():
            print("Mesh agent started. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
                    status = agent.get_status()
                    print(f"Peers: {status['mesh'].get('peer_count', 0)}, "
                          f"Intel: {status['collective_score']['intel_count']}")
            except KeyboardInterrupt:
                pass
            finally:
                agent.stop()


if __name__ == '__main__':
    main()
