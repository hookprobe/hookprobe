#!/usr/bin/env python3
"""
Guardian Ad Block Integration - Extends Guardian Agent with AI Ad Blocking

This module integrates the AI-powered ad blocker into the Guardian agent,
adding ad blocking metrics to the Qsecbit score and enabling mesh-based
ad intelligence sharing.

Integration Points:
1. Qsecbit Score - Ad blocking adds privacy component
2. Threat Feed - Blocked ads appear as privacy threats
3. Mesh Intelligence - Ad domain IOCs shared across nodes
4. Statistics - Ad blocking stats in Guardian dashboard

Author: HookProbe Team
Version: 5.0.0
License: MIT
"""

import sys
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

# Add parent path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import Guardian components
try:
    from guardian_agent import GuardianAgent, GuardianMetrics
    GUARDIAN_AVAILABLE = True
except ImportError:
    GUARDIAN_AVAILABLE = False
    GuardianAgent = None

# Import ad blocker components
try:
    from ai_ad_blocker import (
        AIAdBlocker,
        AdBlockConfig,
        ClassificationResult,
        DomainCategory
    )
    from ad_mesh_intelligence import (
        AdMeshIntelligenceAgent,
        AdBlockQsecbitIntegration,
        create_ad_intelligence_system
    )
    AD_BLOCKER_AVAILABLE = True
except ImportError:
    AD_BLOCKER_AVAILABLE = False
    AIAdBlocker = None

# Import mesh integration
try:
    from mesh_integration import GuardianMeshAgent, MeshConfig
    MESH_AVAILABLE = True
except ImportError:
    MESH_AVAILABLE = False


@dataclass
class AdBlockMetrics:
    """Ad blocking metrics for Guardian dashboard."""
    enabled: bool
    total_queries: int
    blocked_count: int
    allowed_count: int
    block_rate: float
    blocklist_size: int
    ml_enabled: bool
    cname_enabled: bool
    federated_enabled: bool
    qsecbit_contribution: float
    recent_blocks: List[Dict[str, Any]]

    def to_dict(self) -> dict:
        return {
            'enabled': self.enabled,
            'total_queries': self.total_queries,
            'blocked_count': self.blocked_count,
            'allowed_count': self.allowed_count,
            'block_rate': self.block_rate,
            'blocklist_size': self.blocklist_size,
            'ml_enabled': self.ml_enabled,
            'cname_enabled': self.cname_enabled,
            'federated_enabled': self.federated_enabled,
            'qsecbit_contribution': self.qsecbit_contribution,
            'recent_blocks': self.recent_blocks
        }


class GuardianAdBlockAgent:
    """
    Extended Guardian Agent with AI Ad Blocking capabilities.

    This class wraps the standard GuardianAgent and adds:
    - AI-powered ad/tracker blocking
    - Privacy component in Qsecbit scoring
    - Mesh-based ad intelligence sharing
    - Ad blocking statistics and dashboard data
    """

    # Weight of ad blocking in Qsecbit calculation
    # Reduces other weights proportionally
    ADBLOCK_QSECBIT_WEIGHT = 0.08

    def __init__(
        self,
        guardian_agent: Optional['GuardianAgent'] = None,
        ad_blocker: Optional['AIAdBlocker'] = None,
        mesh_agent: Optional['GuardianMeshAgent'] = None,
        data_dir: str = "/opt/hookprobe/guardian/data",
        verbose: bool = False
    ):
        self.logger = logging.getLogger("GuardianAdBlockAgent")
        self.verbose = verbose
        self.data_dir = Path(data_dir)

        # Initialize Guardian agent
        if guardian_agent:
            self.guardian = guardian_agent
        elif GUARDIAN_AVAILABLE:
            self.guardian = GuardianAgent(
                data_dir=data_dir,
                verbose=verbose
            )
        else:
            self.guardian = None
            self.logger.warning("GuardianAgent not available")

        # Initialize ad blocker
        if ad_blocker:
            self.ad_blocker = ad_blocker
        elif AD_BLOCKER_AVAILABLE:
            config = AdBlockConfig(
                data_dir=str(self.data_dir / "adblock"),
                federated_enabled=MESH_AVAILABLE
            )
            self.ad_blocker = AIAdBlocker(config)
        else:
            self.ad_blocker = None
            self.logger.warning("AIAdBlocker not available")

        # Initialize mesh intelligence
        self.mesh_agent = mesh_agent
        self.mesh_intelligence: Optional[AdMeshIntelligenceAgent] = None
        self.qsecbit_integration: Optional[AdBlockQsecbitIntegration] = None

        if self.ad_blocker and AD_BLOCKER_AVAILABLE:
            self.mesh_intelligence = AdMeshIntelligenceAgent(
                ad_blocker=self.ad_blocker,
                mesh_agent=mesh_agent
            )
            self.qsecbit_integration = AdBlockQsecbitIntegration(
                ad_blocker=self.ad_blocker,
                mesh_intelligence=self.mesh_intelligence,
                weight=self.ADBLOCK_QSECBIT_WEIGHT
            )

        # Stats file for dashboard
        self.adblock_stats_file = self.data_dir / "adblock_stats.json"

        # Running state
        self.running = False

    def _log(self, message: str):
        """Log message if verbose mode enabled."""
        if self.verbose:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [AdBlock] {message}")
        self.logger.info(message)

    def get_adblock_metrics(self) -> AdBlockMetrics:
        """Get current ad blocking metrics."""
        if not self.ad_blocker:
            return AdBlockMetrics(
                enabled=False,
                total_queries=0,
                blocked_count=0,
                allowed_count=0,
                block_rate=0.0,
                blocklist_size=0,
                ml_enabled=False,
                cname_enabled=False,
                federated_enabled=False,
                qsecbit_contribution=0.0,
                recent_blocks=[]
            )

        stats = self.ad_blocker.get_stats()

        blocked_count = (
            stats.get('blocked_blocklist', 0) +
            stats.get('blocked_ml', 0) +
            stats.get('blocked_cname', 0)
        )

        qsecbit_contribution = 0.0
        if self.qsecbit_integration:
            component = self.qsecbit_integration.calculate_component()
            qsecbit_contribution = component['weighted_score']

        recent = self.ad_blocker.get_recent_classifications(20)
        recent_blocks = [c for c in recent if c.get('blocked', False)]

        return AdBlockMetrics(
            enabled=self.ad_blocker.config.enabled,
            total_queries=stats.get('total_queries', 0),
            blocked_count=blocked_count,
            allowed_count=stats.get('allowed', 0),
            block_rate=stats.get('block_rate', 0.0),
            blocklist_size=stats.get('blocklist_size', 0),
            ml_enabled=self.ad_blocker.config.ml_enabled,
            cname_enabled=self.ad_blocker.config.cname_check_enabled,
            federated_enabled=self.ad_blocker.config.federated_enabled,
            qsecbit_contribution=qsecbit_contribution,
            recent_blocks=recent_blocks[-10:]
        )

    def calculate_extended_qsecbit_score(
        self,
        base_score: float,
        base_components: Dict[str, float]
    ) -> tuple:
        """
        Calculate extended Qsecbit score including ad blocking.

        Takes the base score from Guardian and adds ad blocking component.
        Weights are adjusted to sum to 1.0.
        """
        if not self.qsecbit_integration:
            return base_score, base_components

        # Get ad blocking component
        adblock_component = self.qsecbit_integration.calculate_component()

        # Scale down base score to make room for ad blocking
        scale_factor = 1.0 - self.ADBLOCK_QSECBIT_WEIGHT
        adjusted_base = base_score * scale_factor

        # Add ad blocking contribution
        extended_score = adjusted_base + adblock_component['weighted_score']

        # Update components
        extended_components = base_components.copy()
        extended_components['ad_blocking'] = round(adblock_component['score'], 4)
        extended_components['ad_ratio'] = round(
            adblock_component['details'].get('ad_ratio', 0), 4
        )

        # Adjust other components proportionally
        for key in ['layer_threats', 'mobile_protection', 'ids_alerts',
                    'xdp_blocking', 'network_health']:
            if key in extended_components:
                extended_components[key] = round(
                    extended_components[key] * scale_factor, 4
                )

        return round(extended_score, 4), extended_components

    def collect_extended_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics including ad blocking data.

        Returns extended metrics dict suitable for Guardian dashboard.
        """
        metrics = {}

        # Collect base Guardian metrics
        if self.guardian:
            base_metrics = self.guardian.collect_metrics()
            metrics['guardian'] = base_metrics.to_dict()

            # Extend Qsecbit score
            extended_score, extended_components = self.calculate_extended_qsecbit_score(
                base_metrics.qsecbit_score,
                base_metrics.components
            )

            metrics['qsecbit_score'] = extended_score
            metrics['qsecbit_components'] = extended_components

            # Update RAG status if needed
            if extended_score >= 0.70:
                metrics['rag_status'] = "RED"
            elif extended_score >= 0.45:
                metrics['rag_status'] = "AMBER"
            else:
                metrics['rag_status'] = "GREEN"

        # Collect ad blocking metrics
        adblock_metrics = self.get_adblock_metrics()
        metrics['ad_blocking'] = adblock_metrics.to_dict()

        # Collect mesh intelligence
        if self.mesh_intelligence:
            intel = self.mesh_intelligence.get_mesh_intelligence()
            metrics['mesh_ad_intelligence'] = intel.to_dict()

        metrics['timestamp'] = datetime.now().isoformat()

        return metrics

    def save_stats(self):
        """Save ad blocking stats to file for dashboard."""
        try:
            metrics = self.collect_extended_metrics()

            self.adblock_stats_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.adblock_stats_file, 'w') as f:
                json.dump(metrics, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to save stats: {e}")

    def start(self):
        """Start the extended Guardian agent with ad blocking."""
        self.running = True

        # Start ad blocker background tasks
        if self.ad_blocker:
            self._log("Starting AI ad blocker...")
            self.ad_blocker.start_background_tasks()

            # Update blocklists on startup
            try:
                count = self.ad_blocker.update_blocklist()
                self._log(f"Loaded {count} blocked domains")
            except Exception as e:
                self.logger.warning(f"Blocklist update failed: {e}")

        # Start mesh intelligence
        if self.mesh_intelligence:
            self._log("Starting mesh ad intelligence...")
            self.mesh_intelligence.start()

        self._log("Guardian Ad Block Agent started")

    def stop(self):
        """Stop the extended Guardian agent."""
        self.running = False

        if self.mesh_intelligence:
            self.mesh_intelligence.stop()

        if self.ad_blocker:
            self.ad_blocker.stop()

        self._log("Guardian Ad Block Agent stopped")

    def classify_domain(self, domain: str) -> Dict[str, Any]:
        """
        Classify a domain through the ad blocker.

        Convenience method for external callers.
        """
        if not self.ad_blocker:
            return {
                'domain': domain,
                'blocked': False,
                'reason': 'Ad blocker not available'
            }

        result = self.ad_blocker.classify_domain(domain)
        return result.to_dict()


# =============================================================================
# Extended Guardian Metrics
# =============================================================================

def patch_guardian_agent_with_adblock(
    guardian: 'GuardianAgent',
    ad_blocker: 'AIAdBlocker'
) -> 'GuardianAgent':
    """
    Monkey-patch existing GuardianAgent to include ad blocking.

    This allows ad blocking to be added to an existing Guardian instance
    without creating a new wrapper class.
    """
    if not GUARDIAN_AVAILABLE or not AD_BLOCKER_AVAILABLE:
        return guardian

    # Store original method
    original_calculate_score = guardian.calculate_qsecbit_score

    # Create Qsecbit integration
    qsecbit_integration = AdBlockQsecbitIntegration(
        ad_blocker=ad_blocker,
        weight=0.08
    )

    def patched_calculate_qsecbit_score(
        threat_report, mobile_report, suricata_stats, xdp_stats
    ):
        # Call original
        base_score, rag_status, components = original_calculate_score(
            threat_report, mobile_report, suricata_stats, xdp_stats
        )

        # Add ad blocking component
        adblock_component = qsecbit_integration.calculate_component()

        # Adjust score
        scale_factor = 0.92  # 1.0 - 0.08
        adjusted_score = base_score * scale_factor + adblock_component['weighted_score']

        # Update components
        components['ad_blocking'] = round(adblock_component['score'], 4)

        # Recalculate RAG
        if adjusted_score >= 0.70:
            rag_status = "RED"
        elif adjusted_score >= 0.45:
            rag_status = "AMBER"
        else:
            rag_status = "GREEN"

        return round(adjusted_score, 4), rag_status, components

    # Apply patch
    guardian.calculate_qsecbit_score = patched_calculate_qsecbit_score
    guardian.ad_blocker = ad_blocker
    guardian.qsecbit_adblock = qsecbit_integration

    return guardian


# =============================================================================
# CLI and Main
# =============================================================================

def main():
    """Main entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Guardian Ad Block Integration"
    )
    parser.add_argument(
        '--test', action='store_true',
        help='Run integration test'
    )
    parser.add_argument(
        '--stats', action='store_true',
        help='Show current stats'
    )
    parser.add_argument(
        '--serve', action='store_true',
        help='Start the agent'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
    )

    if args.test:
        print("[*] Testing Guardian Ad Block Integration")
        print()

        # Create agent
        agent = GuardianAdBlockAgent(verbose=args.verbose)

        # Test classification
        test_domains = [
            "google.com",
            "doubleclick.net",
            "track.example.com",
            "facebook.com"
        ]

        print("[*] Domain Classifications:")
        for domain in test_domains:
            result = agent.classify_domain(domain)
            status = "BLOCKED" if result.get('blocked') else "allowed"
            print(f"  {domain}: {status}")

        print()

        # Get metrics
        metrics = agent.collect_extended_metrics()

        print(f"[*] Extended Qsecbit Score: {metrics.get('qsecbit_score', 'N/A')}")
        print(f"[*] RAG Status: {metrics.get('rag_status', 'N/A')}")

        if 'ad_blocking' in metrics:
            ab = metrics['ad_blocking']
            print()
            print("[*] Ad Blocking Stats:")
            print(f"    Total Queries: {ab['total_queries']}")
            print(f"    Blocked: {ab['blocked_count']}")
            print(f"    Block Rate: {ab['block_rate']:.2%}")
            print(f"    Qsecbit Contribution: {ab['qsecbit_contribution']:.4f}")

        print()
        print("[+] Integration test complete")
        return

    if args.stats:
        agent = GuardianAdBlockAgent(verbose=False)
        metrics = agent.collect_extended_metrics()
        print(json.dumps(metrics, indent=2))
        return

    if args.serve:
        import signal

        agent = GuardianAdBlockAgent(verbose=args.verbose)
        agent.start()

        def signal_handler(sig, frame):
            print("\n[*] Shutting down...")
            agent.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        print("[+] Guardian Ad Block Agent running. Press Ctrl+C to stop.")

        # Periodic stats collection
        import time
        while agent.running:
            time.sleep(30)
            agent.save_stats()

        return

    parser.print_help()


if __name__ == "__main__":
    main()
