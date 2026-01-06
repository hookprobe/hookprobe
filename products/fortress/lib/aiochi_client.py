#!/usr/bin/env python3
"""
AIOCHI Client for Fortress NAC Enforcement

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

This module provides a thin client for Fortress to communicate with AIOCHI:
- Query device identity and bubble assignments
- Apply NAC policies based on AIOCHI decisions
- Report new devices for AI-driven bubble assignment
- Sync OVS rules with AIOCHI bubble state

Architecture:
    AIOCHI (Brain) → Fortress (Enforcer)
    - AIOCHI holds bubble state and device identities (single source of truth)
    - Fortress queries AIOCHI and applies OVS/SDN rules
    - Fortress reports new devices for AIOCHI to enrich and assign

Endpoints Used:
    GET  /api/device/<mac>/bubble    - Get NAC policy for device
    GET  /api/enrichment/<mac>       - Get full device enrichment
    GET  /api/bubbles                - Get all bubbles for SDN sync
    GET  /api/policies               - Get policy matrix
    POST /api/device/<mac>/assign    - Request bubble assignment
    POST /api/bubble                 - Create bubble
    POST /api/sync/bulk              - Bulk sync (initial load)
"""

import json
import logging
import os
import subprocess
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from queue import Queue, Empty

logger = logging.getLogger(__name__)

# Configuration
CONFIG_FILE = Path('/etc/hookprobe/fortress.conf')
DEFAULT_AIOCHI_URL = 'http://aiochi-identity:8060'
DEFAULT_TIMEOUT = 5  # seconds
SYNC_INTERVAL = 30  # seconds between full syncs


@dataclass
class DevicePolicy:
    """NAC policy for a device from AIOCHI."""
    mac: str
    bubble_id: Optional[str]
    bubble_name: str
    bubble_type: str
    vlan: int
    internet: bool
    lan: bool
    d2d: bool

    @classmethod
    def from_dict(cls, data: Dict) -> 'DevicePolicy':
        policy = data.get('policy', {})
        return cls(
            mac=data.get('mac', ''),
            bubble_id=data.get('bubble_id'),
            bubble_name=data.get('bubble_name', 'Guest'),
            bubble_type=data.get('bubble_type', 'GUEST'),
            vlan=policy.get('vlan', 150),
            internet=policy.get('internet', True),
            lan=policy.get('lan', False),
            d2d=policy.get('d2d', False),
        )


@dataclass
class DeviceEnrichment:
    """Full enrichment data from AIOCHI."""
    mac: str
    human_label: str
    device_type: str
    vendor: str
    ecosystem: str
    trust_level: int
    confidence: float
    bubble_id: Optional[str]
    bubble_name: str
    bubble_type: str
    policy: Dict

    @classmethod
    def from_dict(cls, data: Dict) -> 'DeviceEnrichment':
        identity = data.get('identity', {})
        bubble = data.get('bubble', {})
        return cls(
            mac=identity.get('mac', ''),
            human_label=identity.get('human_label', ''),
            device_type=identity.get('device_type', ''),
            vendor=identity.get('vendor', ''),
            ecosystem=identity.get('ecosystem', 'unknown'),
            trust_level=identity.get('trust_level', 0),
            confidence=identity.get('confidence', 0.0),
            bubble_id=bubble.get('bubble_id'),
            bubble_name=bubble.get('name', 'Unassigned'),
            bubble_type=bubble.get('type', 'GUEST'),
            policy=bubble.get('policy', {}),
        )


class AIOCHIClient:
    """
    Client for communicating with AIOCHI Identity Engine.

    Handles:
    - Querying device policies for NAC enforcement
    - Requesting bubble assignments for new devices
    - Syncing OVS rules with AIOCHI bubble state
    - Caching to reduce API calls
    """

    def __init__(
        self,
        base_url: str = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache_ttl: int = 60,
    ):
        self.base_url = base_url or self._load_base_url()
        self.timeout = timeout
        self.cache_ttl = cache_ttl

        # Policy cache: mac -> (policy, timestamp)
        self._policy_cache: Dict[str, tuple] = {}
        self._cache_lock = threading.Lock()

        # Sync state
        self._last_sync: Optional[datetime] = None
        self._sync_running = False
        self._sync_thread: Optional[threading.Thread] = None

        # OVS rule queue (apply outside API calls)
        self._rule_queue: Queue = Queue()
        self._rule_worker: Optional[threading.Thread] = None

        logger.info(f"AIOCHI client initialized: {self.base_url}")

    def _load_base_url(self) -> str:
        """Load AIOCHI URL from config file."""
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f:
                    for line in f:
                        if line.strip().startswith('AIOCHI_URL='):
                            url = line.split('=', 1)[1].strip().strip('"\'')
                            if url and url != 'None':
                                return url
        except Exception as e:
            logger.debug(f"Could not load AIOCHI URL: {e}")

        # Check environment variable
        env_url = os.environ.get('AIOCHI_URL')
        if env_url:
            return env_url

        return DEFAULT_AIOCHI_URL

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
    ) -> Optional[Dict]:
        """Make HTTP request to AIOCHI."""
        url = f"{self.base_url}{endpoint}"

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
                if response.status == 200 or response.status == 201:
                    return json.loads(response.read().decode('utf-8'))
                else:
                    logger.warning(f"AIOCHI returned {response.status} for {endpoint}")
                    return None

        except urllib.error.HTTPError as e:
            logger.warning(f"AIOCHI HTTP error: {e.code} for {endpoint}")
            return None
        except urllib.error.URLError as e:
            logger.debug(f"AIOCHI connection error: {e.reason}")
            return None
        except Exception as e:
            logger.debug(f"AIOCHI request error: {e}")
            return None

    # =========================================================================
    # DEVICE POLICY QUERIES (For NAC Enforcement)
    # =========================================================================

    def get_device_policy(self, mac: str, use_cache: bool = True) -> Optional[DevicePolicy]:
        """
        Get NAC policy for a device.

        Args:
            mac: Device MAC address
            use_cache: Whether to use cached policy

        Returns:
            DevicePolicy with VLAN and access rules
        """
        mac = mac.upper().replace('-', ':')

        # Check cache
        if use_cache:
            with self._cache_lock:
                if mac in self._policy_cache:
                    policy, timestamp = self._policy_cache[mac]
                    if (datetime.now() - timestamp).total_seconds() < self.cache_ttl:
                        return policy

        # Query AIOCHI
        response = self._request('GET', f'/api/device/{mac}/bubble')
        if response:
            policy = DevicePolicy.from_dict(response)

            # Cache the result
            with self._cache_lock:
                self._policy_cache[mac] = (policy, datetime.now())

            return policy

        # Fallback: return guest policy
        return DevicePolicy(
            mac=mac,
            bubble_id=None,
            bubble_name='Guest',
            bubble_type='GUEST',
            vlan=150,
            internet=True,
            lan=False,
            d2d=False,
        )

    def get_device_enrichment(self, mac: str) -> Optional[DeviceEnrichment]:
        """
        Get full enrichment data for a device.

        Args:
            mac: Device MAC address

        Returns:
            DeviceEnrichment with identity and bubble info
        """
        mac = mac.upper().replace('-', ':')
        response = self._request('GET', f'/api/enrichment/{mac}')
        if response:
            return DeviceEnrichment.from_dict(response)
        return None

    # =========================================================================
    # BUBBLE MANAGEMENT (Forward to AIOCHI)
    # =========================================================================

    def create_bubble(
        self,
        bubble_id: str,
        name: str,
        bubble_type: str = 'GUEST',
        devices: List[str] = None,
        policy: Dict = None,
    ) -> bool:
        """
        Create a new bubble in AIOCHI.

        Args:
            bubble_id: Unique bubble identifier
            name: Human-readable name
            bubble_type: FAMILY, WORK, IOT, GUEST
            devices: Initial device MACs
            policy: Custom policy (optional)

        Returns:
            True if successful
        """
        data = {
            'bubble_id': bubble_id,
            'name': name,
            'bubble_type': bubble_type,
            'devices': devices or [],
        }
        if policy:
            data['policy'] = policy

        response = self._request('POST', '/api/bubble', data)
        if response and response.get('status') == 'created':
            logger.info(f"Created bubble in AIOCHI: {bubble_id}")
            return True
        return False

    def assign_device(
        self,
        mac: str,
        bubble_id: str,
        confidence: float = 0.0,
        reason: str = '',
    ) -> bool:
        """
        Assign a device to a bubble.

        Args:
            mac: Device MAC address
            bubble_id: Target bubble ID
            confidence: Assignment confidence (0.0-1.0)
            reason: Reason for assignment

        Returns:
            True if successful
        """
        mac = mac.upper().replace('-', ':')
        data = {
            'bubble_id': bubble_id,
            'confidence': confidence,
            'reason': reason,
        }

        response = self._request('POST', f'/api/device/{mac}/assign', data)
        if response and response.get('status') == 'assigned':
            # Invalidate cache
            with self._cache_lock:
                self._policy_cache.pop(mac, None)
            logger.info(f"Assigned {mac} to {bubble_id}")
            return True
        return False

    def get_all_bubbles(self) -> List[Dict]:
        """Get all bubbles from AIOCHI."""
        response = self._request('GET', '/api/bubbles')
        if response:
            return response.get('bubbles', [])
        return []

    def get_policies(self) -> Dict:
        """Get policy matrix from AIOCHI."""
        response = self._request('GET', '/api/policies')
        if response:
            return response.get('policies', {})
        return {}

    # =========================================================================
    # OVS RULE SYNC
    # =========================================================================

    def sync_ovs_rules(self, bridge: str = 'FTS') -> int:
        """
        Sync OVS rules with AIOCHI bubble state.

        Queries all bubbles and applies corresponding OpenFlow rules.

        Args:
            bridge: OVS bridge name

        Returns:
            Number of rules applied
        """
        bubbles = self.get_all_bubbles()
        if not bubbles:
            logger.warning("No bubbles from AIOCHI, skipping OVS sync")
            return 0

        rules_applied = 0

        for bubble in bubbles:
            policy = bubble.get('policy', {})
            vlan = policy.get('vlan', 150)
            devices = bubble.get('devices', [])

            for mac in devices:
                # Generate OpenFlow rule
                rule = self._generate_openflow_rule(mac, vlan, policy, bridge)
                if rule:
                    self._apply_ovs_rule(rule, bridge)
                    rules_applied += 1

        self._last_sync = datetime.now()
        logger.info(f"OVS sync complete: {rules_applied} rules applied")
        return rules_applied

    def _generate_openflow_rule(
        self,
        mac: str,
        vlan: int,
        policy: Dict,
        bridge: str,
    ) -> Optional[Dict]:
        """Generate OpenFlow rule for device policy."""
        return {
            'mac': mac,
            'vlan': vlan,
            'internet': policy.get('internet', True),
            'lan': policy.get('lan', False),
            'd2d': policy.get('d2d', False),
        }

    def _apply_ovs_rule(self, rule: Dict, bridge: str) -> bool:
        """Apply a single OVS rule."""
        mac = rule['mac']
        vlan = rule['vlan']

        try:
            # VLAN tag rule
            cmd = [
                'ovs-ofctl', 'add-flow', bridge,
                f"dl_src={mac},actions=mod_vlan_vid:{vlan},normal"
            ]
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            return True
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to apply OVS rule for {mac}: {e}")
            return False
        except subprocess.TimeoutExpired:
            logger.warning(f"OVS rule timeout for {mac}")
            return False

    # =========================================================================
    # DEVICE REPORTING (New devices to AIOCHI)
    # =========================================================================

    def report_new_device(
        self,
        mac: str,
        ip: str = '',
        hostname: str = '',
        dhcp_options: List[int] = None,
        mdns_services: List[str] = None,
    ) -> Optional[DeviceEnrichment]:
        """
        Report a new device to AIOCHI for identity enrichment.

        Args:
            mac: Device MAC address
            ip: IP address (from DHCP)
            hostname: Hostname (from DHCP or mDNS)
            dhcp_options: DHCP Option 55 fingerprint
            mdns_services: mDNS services discovered

        Returns:
            DeviceEnrichment if successful
        """
        mac = mac.upper().replace('-', ':')

        # First, trigger identity enrichment
        data = {
            'mac': mac,
            'ip': ip,
            'hostname': hostname,
            'dhcp_options': dhcp_options or [],
            'mdns_services': mdns_services or [],
        }

        # Report via presence endpoint
        self._request('POST', '/api/presence', data)

        # Then query for enrichment
        return self.get_device_enrichment(mac)

    # =========================================================================
    # BACKGROUND SYNC
    # =========================================================================

    def start_background_sync(self, interval: int = SYNC_INTERVAL):
        """Start background sync thread."""
        if self._sync_running:
            return

        self._sync_running = True
        self._sync_thread = threading.Thread(
            target=self._sync_loop,
            args=(interval,),
            daemon=True,
        )
        self._sync_thread.start()
        logger.info(f"Background sync started (interval: {interval}s)")

    def _sync_loop(self, interval: int):
        """Background sync loop."""
        while self._sync_running:
            try:
                self.sync_ovs_rules()
            except Exception as e:
                logger.warning(f"Background sync error: {e}")

            time.sleep(interval)

    def stop_background_sync(self):
        """Stop background sync thread."""
        self._sync_running = False
        if self._sync_thread:
            self._sync_thread.join(timeout=5.0)

    # =========================================================================
    # SDN AUTOPILOT → AIOCHI FEEDBACK (Gap #2 Fix)
    # =========================================================================

    def report_sdn_decision(
        self,
        mac: str,
        decision: str,
        reason: str,
        details: Dict = None,
    ) -> bool:
        """
        Report SDN Autopilot enforcement decision back to AIOCHI.

        Gap #2 Fix: Enables bidirectional sync so AIOCHI can learn from
        actual SDN enforcement outcomes.

        Args:
            mac: Device MAC address
            decision: 'accept', 'reject', 'override', 'quarantine'
            reason: Human-readable reason
            details: Additional context (optional)

        Returns:
            True if reported successfully
        """
        mac = mac.upper().replace('-', ':')
        data = {
            'mac': mac,
            'decision': decision,
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'source': 'sdn_autopilot',
        }
        if details:
            data['details'] = details

        response = self._request('POST', f'/api/device/{mac}/feedback', data)
        if response and response.get('status') in ('received', 'ok'):
            logger.debug(f"Reported SDN decision for {mac}: {decision}")
            return True

        logger.debug(f"Failed to report SDN decision for {mac}")
        return False

    def update_trust_adjustment(
        self,
        mac: str,
        adjustment: float,
        reason: str,
        attack_type: str = None,
    ) -> bool:
        """
        Send trust score adjustment from SDN Autopilot to AIOCHI.

        Gap #2 Fix: When SDN detects an attack or validates good behavior,
        this informs AIOCHI to update the device's trust score.

        Args:
            mac: Device MAC address
            adjustment: Trust adjustment (-10.0 to +10.0)
            reason: Reason for adjustment
            attack_type: Type of attack if negative (optional)

        Returns:
            True if adjustment accepted
        """
        mac = mac.upper().replace('-', ':')

        # Clamp adjustment to valid range
        adjustment = max(-10.0, min(10.0, adjustment))

        data = {
            'mac': mac,
            'adjustment': adjustment,
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'source': 'sdn_autopilot',
        }
        if attack_type:
            data['attack_type'] = attack_type

        response = self._request('POST', f'/api/device/{mac}/trust-adjust', data)
        if response and response.get('status') in ('applied', 'ok'):
            logger.info(f"Trust adjustment for {mac}: {adjustment:+.1f} ({reason})")

            # Invalidate cache as trust may affect policy
            with self._cache_lock:
                self._policy_cache.pop(mac, None)

            return True

        logger.debug(f"Failed to apply trust adjustment for {mac}")
        return False

    def report_defense_outcome(
        self,
        mac: str,
        attack_type: str,
        detected: bool,
        blocked: bool,
        detection_method: str,
        response_action: str = None,
    ) -> bool:
        """
        Report actual defense outcome to AIOCHI for learning.

        Gap #6 Integration: Feeds real-world outcomes back to AIOCHI
        and Nexus for improving detection accuracy.

        Args:
            mac: Target device MAC
            attack_type: Type of attack (ter_replay, mac_impersonation, etc.)
            detected: Whether attack was detected
            blocked: Whether attack was blocked
            detection_method: How it was detected (e.g., 'NEURO resonance drift')
            response_action: Action taken (quarantine, rate_limit, etc.)

        Returns:
            True if reported
        """
        mac = mac.upper().replace('-', ':')

        data = {
            'event_type': 'defense_outcome',
            'mac': mac,
            'attack_type': attack_type,
            'detected': detected,
            'blocked': blocked,
            'detection_method': detection_method,
            'response_action': response_action,
            'timestamp': datetime.now().isoformat(),
        }

        # Report to AIOCHI
        response = self._request('POST', '/api/defense-outcome', data)

        # Also report to Fortress API for Nexus to fetch
        try:
            import urllib.request
            fortress_url = 'http://localhost:8443/api/v1/defense/outcome'
            req = urllib.request.Request(
                fortress_url,
                data=json.dumps(data).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass  # Best effort

        return response is not None

    def report_optimization_applied(self, optimization: Dict) -> bool:
        """
        Report that Nexus optimization was applied.

        Gap #2 Integration: Informs AIOCHI when purple team optimizations
        are applied so it can track effectiveness.

        Args:
            optimization: Optimization record from Nexus

        Returns:
            True if reported
        """
        data = {
            'event_type': 'optimization_applied',
            'optimization_id': optimization.get('id'),
            'simulation_id': optimization.get('simulation_id'),
            'applied_count': len(optimization.get('applied', [])),
            'failed_count': len(optimization.get('failed', [])),
            'timestamp': datetime.now().isoformat(),
            'source': 'sdn_autopilot',
        }

        response = self._request('POST', '/api/optimization-applied', data)
        return response is not None

    def report_bubble_violation(
        self,
        mac: str,
        violation_type: str,
        bubble_id: str,
        details: Dict = None,
    ) -> bool:
        """
        Report a bubble policy violation to AIOCHI.

        Used when a device in a bubble violates its policy (e.g., attempting
        forbidden LAN access from Guest bubble).

        Args:
            mac: Device MAC address
            violation_type: 'internet_block', 'lan_block', 'd2d_block', 'vlan_hop'
            bubble_id: Current bubble ID
            details: Additional details

        Returns:
            True if reported
        """
        mac = mac.upper().replace('-', ':')

        data = {
            'mac': mac,
            'violation_type': violation_type,
            'bubble_id': bubble_id,
            'details': details or {},
            'timestamp': datetime.now().isoformat(),
        }

        response = self._request('POST', '/api/bubble-violation', data)
        if response:
            logger.warning(f"Bubble violation: {mac} in {bubble_id} - {violation_type}")
            return True
        return False

    # =========================================================================
    # HEALTH CHECK
    # =========================================================================

    def health_check(self) -> Dict:
        """Check AIOCHI connectivity and status."""
        response = self._request('GET', '/health')
        if response:
            return {
                'connected': True,
                'aiochi_url': self.base_url,
                'aiochi_status': response.get('status'),
                'bubbles_synced': response.get('bubbles_synced', 0),
                'devices_mapped': response.get('devices_mapped', 0),
                'local_cache_size': len(self._policy_cache),
                'last_sync': self._last_sync.isoformat() if self._last_sync else None,
            }
        return {
            'connected': False,
            'aiochi_url': self.base_url,
            'error': 'Cannot connect to AIOCHI Identity Engine',
        }


# =============================================================================
# SINGLETON
# =============================================================================

_client: Optional[AIOCHIClient] = None
_client_lock = threading.Lock()


def get_aiochi_client() -> AIOCHIClient:
    """Get the singleton AIOCHI client."""
    global _client

    with _client_lock:
        if _client is None:
            _client = AIOCHIClient()
        return _client


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='AIOCHI Client for Fortress')
    parser.add_argument('command', choices=['health', 'policy', 'bubbles', 'sync', 'enrich'])
    parser.add_argument('--mac', help='Device MAC address')
    parser.add_argument('--url', help='AIOCHI URL override')
    args = parser.parse_args()

    client = AIOCHIClient(base_url=args.url) if args.url else get_aiochi_client()

    if args.command == 'health':
        status = client.health_check()
        print("AIOCHI Connection Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")

    elif args.command == 'policy':
        if not args.mac:
            print("Error: --mac required for policy lookup")
        else:
            policy = client.get_device_policy(args.mac)
            if policy:
                print(f"Device: {policy.mac}")
                print(f"Bubble: {policy.bubble_name} ({policy.bubble_type})")
                print(f"VLAN: {policy.vlan}")
                print(f"Internet: {policy.internet}")
                print(f"LAN: {policy.lan}")
                print(f"D2D: {policy.d2d}")
            else:
                print("Could not get policy")

    elif args.command == 'bubbles':
        bubbles = client.get_all_bubbles()
        print(f"Active Bubbles ({len(bubbles)}):")
        for bubble in bubbles:
            devices = bubble.get('devices', [])
            print(f"  - {bubble.get('name')} ({bubble.get('bubble_type')}): {len(devices)} devices")

    elif args.command == 'sync':
        rules = client.sync_ovs_rules()
        print(f"Synced {rules} OVS rules")

    elif args.command == 'enrich':
        if not args.mac:
            print("Error: --mac required for enrichment")
        else:
            enrichment = client.get_device_enrichment(args.mac)
            if enrichment:
                print(f"Device: {enrichment.human_label}")
                print(f"Type: {enrichment.device_type}")
                print(f"Vendor: {enrichment.vendor}")
                print(f"Ecosystem: {enrichment.ecosystem}")
                print(f"Trust: L{enrichment.trust_level} ({enrichment.confidence:.0%})")
                print(f"Bubble: {enrichment.bubble_name} ({enrichment.bubble_type})")
            else:
                print("Could not get enrichment")
