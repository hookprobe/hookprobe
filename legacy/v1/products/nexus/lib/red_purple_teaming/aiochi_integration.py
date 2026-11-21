#!/usr/bin/env python3
"""
AIOCHI Integration for Nexus Purple Team

Gap #5 Fix: Provides direct communication between Nexus and AIOCHI
for querying bubble state during simulations and reporting vulnerabilities.

This module enables:
- Querying device trust scores for attack feasibility
- Fetching bubble configurations for digital twin creation
- Reporting discovered vulnerabilities back to AIOCHI
- Syncing defense outcomes for learning

Architecture:
    Nexus (Purple Team) ←→ AIOCHI Identity Engine (port 8060)
"""

import json
import logging
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Configuration
DEFAULT_AIOCHI_URL = 'http://aiochi-identity:8060'
DEFAULT_FORTRESS_URL = 'http://fortress-api:8443'
DEFAULT_TIMEOUT = 10  # seconds


@dataclass
class BubbleInfo:
    """Bubble information from AIOCHI."""
    bubble_id: str
    name: str
    bubble_type: str  # FAMILY, WORK, IOT, GUEST
    devices: List[str] = field(default_factory=list)
    vlan: int = 150
    internet: bool = True
    lan: bool = False
    d2d: bool = False

    @classmethod
    def from_dict(cls, data: Dict) -> 'BubbleInfo':
        policy = data.get('policy', {})
        return cls(
            bubble_id=data.get('bubble_id', ''),
            name=data.get('name', ''),
            bubble_type=data.get('bubble_type', 'GUEST'),
            devices=data.get('devices', []),
            vlan=policy.get('vlan', 150),
            internet=policy.get('internet', True),
            lan=policy.get('lan', False),
            d2d=policy.get('d2d', False),
        )


@dataclass
class DeviceTrustInfo:
    """Device trust information from AIOCHI."""
    mac: str
    trust_score: int  # 0-100
    trust_level: int  # 0-4 (L0-L4)
    ecosystem: str
    bubble_id: Optional[str]
    confidence: float
    last_action: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict) -> 'DeviceTrustInfo':
        return cls(
            mac=data.get('mac', ''),
            trust_score=data.get('trust_score', 0),
            trust_level=data.get('trust_level', 0),
            ecosystem=data.get('ecosystem', 'unknown'),
            bubble_id=data.get('bubble_id'),
            confidence=data.get('confidence', 0.0),
            last_action=data.get('last_action'),
        )


@dataclass
class VulnerabilityReport:
    """Vulnerability discovered during purple team simulation."""
    vuln_id: str
    attack_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: float
    bubble_id: Optional[str]
    description: str
    evidence: List[str]
    recommendations: List[str]
    mitre_technique: Optional[str] = None


class NexusAIOCHIClient:
    """
    AIOCHI client for Nexus Purple Team.

    Provides direct integration between Nexus and AIOCHI Identity Engine
    for purple team simulations.
    """

    def __init__(
        self,
        aiochi_url: str = None,
        fortress_url: str = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.aiochi_url = aiochi_url or os.environ.get('AIOCHI_URL', DEFAULT_AIOCHI_URL)
        self.fortress_url = fortress_url or os.environ.get('FORTRESS_URL', DEFAULT_FORTRESS_URL)
        self.timeout = timeout

        logger.info(f"Nexus AIOCHI client initialized: {self.aiochi_url}")

    def _request(
        self,
        base_url: str,
        method: str,
        endpoint: str,
        data: Dict = None,
        retries: int = 2,
    ) -> Optional[Dict]:
        """Make HTTP request with retries."""
        url = f"{base_url}{endpoint}"

        for attempt in range(retries + 1):
            try:
                if data:
                    payload = json.dumps(data).encode('utf-8')
                    request = urllib.request.Request(
                        url,
                        data=payload,
                        method=method,
                        headers={'Content-Type': 'application/json'},
                    )
                else:
                    request = urllib.request.Request(url, method=method)

                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    if response.status in (200, 201):
                        return json.loads(response.read().decode('utf-8'))
                    else:
                        logger.warning(f"Request to {endpoint} returned {response.status}")
                        return None

            except urllib.error.HTTPError as e:
                logger.warning(f"HTTP error {e.code} for {endpoint}")
                if attempt == retries:
                    return None
            except urllib.error.URLError as e:
                logger.debug(f"Connection error for {endpoint}: {e.reason}")
                if attempt == retries:
                    return None
            except Exception as e:
                logger.debug(f"Request error for {endpoint}: {e}")
                if attempt == retries:
                    return None

            # Wait before retry
            time.sleep(0.5 * (attempt + 1))

        return None

    # =========================================================================
    # BUBBLE QUERIES (For Digital Twin Creation)
    # =========================================================================

    def get_all_bubbles(self) -> List[BubbleInfo]:
        """
        Get all bubbles from AIOCHI.

        Used during Phase 1 (Digital Twin Creation) to create an accurate
        virtual replica of the Fortress SDN environment.

        Returns:
            List of BubbleInfo objects
        """
        response = self._request(self.aiochi_url, 'GET', '/api/bubbles')
        if response:
            bubbles = response.get('bubbles', [])
            return [BubbleInfo.from_dict(b) for b in bubbles]
        return []

    def get_bubble(self, bubble_id: str) -> Optional[BubbleInfo]:
        """Get a specific bubble by ID."""
        response = self._request(self.aiochi_url, 'GET', f'/api/bubble/{bubble_id}')
        if response:
            return BubbleInfo.from_dict(response)
        return None

    def get_bubble_devices(self, bubble_id: str) -> List[str]:
        """Get device MACs in a bubble."""
        bubble = self.get_bubble(bubble_id)
        return bubble.devices if bubble else []

    # =========================================================================
    # TRUST QUERIES (For Attack Feasibility)
    # =========================================================================

    def get_device_trust(self, mac: str) -> Optional[DeviceTrustInfo]:
        """
        Get device trust score from AIOCHI.

        Used during Phase 2 (Red Team Attacks) to assess attack feasibility
        based on device trust levels.

        Args:
            mac: Device MAC address

        Returns:
            DeviceTrustInfo with trust score and level
        """
        mac = mac.upper().replace('-', ':')
        response = self._request(self.aiochi_url, 'GET', f'/api/trust/{mac}')
        if response:
            response['mac'] = mac
            return DeviceTrustInfo.from_dict(response)
        return None

    def get_all_device_trusts(self) -> Dict[str, DeviceTrustInfo]:
        """
        Get trust info for all known devices.

        Returns:
            Dict mapping MAC -> DeviceTrustInfo
        """
        result = {}
        bubbles = self.get_all_bubbles()

        for bubble in bubbles:
            for mac in bubble.devices:
                trust = self.get_device_trust(mac)
                if trust:
                    result[mac] = trust

        return result

    # =========================================================================
    # VULNERABILITY REPORTING
    # =========================================================================

    def report_vulnerability(self, vuln: VulnerabilityReport) -> bool:
        """
        Report a discovered vulnerability to AIOCHI.

        Used after Phase 2 to inform AIOCHI of vulnerabilities discovered
        during purple team simulation.

        Args:
            vuln: VulnerabilityReport with details

        Returns:
            True if reported successfully
        """
        data = {
            'vuln_id': vuln.vuln_id,
            'attack_type': vuln.attack_type,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'bubble_id': vuln.bubble_id,
            'description': vuln.description,
            'evidence': vuln.evidence,
            'recommendations': vuln.recommendations,
            'mitre_technique': vuln.mitre_technique,
            'source': 'nexus_purple_team',
            'timestamp': datetime.now().isoformat(),
        }

        response = self._request(
            self.aiochi_url,
            'POST',
            '/api/vulnerability',
            data,
        )

        if response:
            logger.info(f"Reported vulnerability {vuln.vuln_id} to AIOCHI")
            return True

        logger.warning(f"Failed to report vulnerability {vuln.vuln_id}")
        return False

    def report_vulnerabilities_batch(
        self,
        vulnerabilities: List[VulnerabilityReport],
    ) -> int:
        """
        Report multiple vulnerabilities in batch.

        Returns:
            Number successfully reported
        """
        success_count = 0
        for vuln in vulnerabilities:
            if self.report_vulnerability(vuln):
                success_count += 1
        return success_count

    # =========================================================================
    # VALIDATION RESULTS
    # =========================================================================

    def send_validation_alert(
        self,
        simulation_id: str,
        defense_score: int,
        overall_risk: str,
        priority: str,
        bubbles_penetrated: int = 0,
        recommendations: List[str] = None,
    ) -> bool:
        """
        Send validation alert to Fortress.

        Gap #1 Integration: Uses the new Fortress API endpoints to
        send purple team validation results.

        Args:
            simulation_id: Unique simulation ID
            defense_score: Defense score (0-100)
            overall_risk: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
            priority: Alert priority (low, medium, high, critical)
            bubbles_penetrated: Number of bubbles compromised
            recommendations: List of security recommendations

        Returns:
            True if alert was accepted
        """
        data = {
            'alert_type': 'purple_team_validation',
            'priority': priority,
            'simulation_id': simulation_id,
            'defense_score': defense_score,
            'overall_risk': overall_risk,
            'bubbles_penetrated': bubbles_penetrated,
            'recommendations': recommendations or [],
            'timestamp': datetime.now().isoformat(),
        }

        response = self._request(
            self.fortress_url,
            'POST',
            '/api/v1/alerts',
            data,
        )

        if response and response.get('status') == 'received':
            logger.info(f"Sent validation alert for {simulation_id}")
            return True

        logger.warning(f"Failed to send validation alert for {simulation_id}")
        return False

    def send_optimization_request(
        self,
        simulation_id: str,
        optimizations: List[Dict],
    ) -> Dict:
        """
        Send optimization request to Fortress SDN Autopilot.

        Gap #1 Integration: Uses the new /api/v1/autopilot/optimize
        endpoint to apply purple team recommendations.

        Args:
            simulation_id: Source simulation ID
            optimizations: List of optimization dicts with:
                - parameter: Parameter name
                - action: 'increase', 'decrease', 'enable', 'disable'
                - old_value: Current value
                - new_value: Recommended value
                - reason: Why this change is recommended

        Returns:
            Dict with applied/failed counts
        """
        data = {
            'source': 'purple_team',
            'simulation_id': simulation_id,
            'optimizations': optimizations,
        }

        response = self._request(
            self.fortress_url,
            'POST',
            '/api/v1/autopilot/optimize',
            data,
        )

        if response:
            logger.info(
                f"Optimization request for {simulation_id}: "
                f"{response.get('applied_count', 0)} applied, "
                f"{response.get('failed_count', 0)} failed"
            )
            return response

        logger.warning(f"Failed to send optimization request for {simulation_id}")
        return {'applied_count': 0, 'failed_count': len(optimizations)}

    # =========================================================================
    # DEFENSE OUTCOMES (For Feedback Loop)
    # =========================================================================

    def get_defense_outcomes(
        self,
        since: str = None,
        limit: int = 100,
    ) -> List[Dict]:
        """
        Get recent defense outcomes from Fortress.

        Gap #6 Integration: Fetches real-world defense outcomes to
        compare against simulated results.

        Args:
            since: ISO timestamp to fetch outcomes after
            limit: Maximum outcomes to return

        Returns:
            List of defense outcome dicts
        """
        endpoint = f'/api/v1/defense/outcomes?limit={limit}'
        if since:
            endpoint += f'&since={since}'

        response = self._request(self.fortress_url, 'GET', endpoint)
        if response:
            return response.get('outcomes', [])
        return []

    def compare_simulation_to_reality(
        self,
        simulation_id: str,
        simulated_results: List[Dict],
    ) -> Dict:
        """
        Compare simulation results to real defense outcomes.

        Args:
            simulation_id: Simulation to compare
            simulated_results: List of simulated attack results

        Returns:
            Comparison metrics
        """
        # Get recent real outcomes
        real_outcomes = self.get_defense_outcomes(limit=500)

        comparison = {
            'simulation_id': simulation_id,
            'simulated_count': len(simulated_results),
            'real_count': len(real_outcomes),
            'correlation': {},
            'accuracy': 0.0,
        }

        if not real_outcomes:
            return comparison

        # Group by attack type
        real_by_type = {}
        for outcome in real_outcomes:
            attack_type = outcome.get('attack_type', 'unknown')
            if attack_type not in real_by_type:
                real_by_type[attack_type] = []
            real_by_type[attack_type].append(outcome)

        sim_by_type = {}
        for result in simulated_results:
            attack_type = result.get('attack_type', 'unknown')
            if attack_type not in sim_by_type:
                sim_by_type[attack_type] = []
            sim_by_type[attack_type].append(result)

        # Compare detection rates by type
        total_compared = 0
        total_matched = 0

        for attack_type in set(list(real_by_type.keys()) + list(sim_by_type.keys())):
            real_results = real_by_type.get(attack_type, [])
            sim_results = sim_by_type.get(attack_type, [])

            if real_results and sim_results:
                # Calculate detection rate for both
                real_detection_rate = sum(1 for r in real_results if r.get('detected', False)) / len(real_results)
                sim_detection_rate = sum(1 for r in sim_results if r.get('detected', False)) / len(sim_results)

                # Calculate accuracy (how close simulation was to reality)
                accuracy = 1 - abs(real_detection_rate - sim_detection_rate)

                comparison['correlation'][attack_type] = {
                    'real_detection_rate': real_detection_rate,
                    'simulated_detection_rate': sim_detection_rate,
                    'accuracy': accuracy,
                }

                total_compared += 1
                total_matched += accuracy

        if total_compared > 0:
            comparison['accuracy'] = total_matched / total_compared

        return comparison

    # =========================================================================
    # HEALTH CHECK
    # =========================================================================

    def health_check(self) -> Dict:
        """Check connectivity to AIOCHI and Fortress."""
        status = {
            'aiochi': {'connected': False, 'url': self.aiochi_url},
            'fortress': {'connected': False, 'url': self.fortress_url},
        }

        # Check AIOCHI
        response = self._request(self.aiochi_url, 'GET', '/health')
        if response:
            status['aiochi']['connected'] = True
            status['aiochi']['status'] = response.get('status')

        # Check Fortress
        response = self._request(self.fortress_url, 'GET', '/api/health')
        if response:
            status['fortress']['connected'] = True
            status['fortress']['version'] = response.get('version')

        return status


# =============================================================================
# SINGLETON
# =============================================================================

_client: Optional[NexusAIOCHIClient] = None


def get_nexus_aiochi_client() -> NexusAIOCHIClient:
    """Get the singleton Nexus AIOCHI client."""
    global _client
    if _client is None:
        _client = NexusAIOCHIClient()
    return _client


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Nexus AIOCHI Client')
    parser.add_argument('command', choices=['health', 'bubbles', 'trust', 'outcomes'])
    parser.add_argument('--mac', help='Device MAC address')
    parser.add_argument('--aiochi-url', help='AIOCHI URL override')
    parser.add_argument('--fortress-url', help='Fortress URL override')
    args = parser.parse_args()

    client = NexusAIOCHIClient(
        aiochi_url=args.aiochi_url,
        fortress_url=args.fortress_url,
    )

    if args.command == 'health':
        status = client.health_check()
        print("Connection Status:")
        print(f"  AIOCHI: {'✓' if status['aiochi']['connected'] else '✗'} {status['aiochi']['url']}")
        print(f"  Fortress: {'✓' if status['fortress']['connected'] else '✗'} {status['fortress']['url']}")

    elif args.command == 'bubbles':
        bubbles = client.get_all_bubbles()
        print(f"Active Bubbles ({len(bubbles)}):")
        for bubble in bubbles:
            print(f"  - {bubble.name} ({bubble.bubble_type}): {len(bubble.devices)} devices, VLAN {bubble.vlan}")

    elif args.command == 'trust':
        if not args.mac:
            print("Error: --mac required for trust lookup")
        else:
            trust = client.get_device_trust(args.mac)
            if trust:
                print(f"Device: {trust.mac}")
                print(f"  Trust Score: {trust.trust_score}/100")
                print(f"  Trust Level: L{trust.trust_level}")
                print(f"  Ecosystem: {trust.ecosystem}")
                print(f"  Bubble: {trust.bubble_id or 'Unassigned'}")
            else:
                print("Could not get trust info")

    elif args.command == 'outcomes':
        outcomes = client.get_defense_outcomes(limit=10)
        print(f"Recent Defense Outcomes ({len(outcomes)}):")
        for outcome in outcomes:
            detected = '✓' if outcome.get('detected') else '✗'
            blocked = '✓' if outcome.get('blocked') else '✗'
            print(f"  [{outcome.get('attack_type')}] Detected: {detected}, Blocked: {blocked}")
