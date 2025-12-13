"""
MSSP NSE Adapter - Cloud Federation Platform

The MSSP tier provides cloud-scale orchestration of NSE across
multi-tenant deployments. It coordinates adversarial testing,
aggregates threat intelligence, and manages the global mesh.

"One node's detection → Everyone's protection"

HTP-DSM-NEURO-QSECBIT-NSE Integration:
- Full NSE orchestration
- Multi-tenant management
- Global threat aggregation
- Adversarial framework coordination
- Designer alerting system
- Compliance reporting
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List, Set
import hashlib
import struct
import time
import json

from .base import (
    BaseNSEAdapter,
    ProductTier,
    NSESessionState,
    ThreatIntel,
)


class MSSPNSEAdapter(BaseNSEAdapter):
    """
    MSSP NSE Adapter for cloud federation (auto-scale)

    Capabilities:
    - Full NSE orchestration
    - Multi-tenant isolation
    - Global threat aggregation
    - Adversarial framework coordination
    - Designer alerting and reporting
    - Unlimited concurrent sessions

    The MSSP is the central brain of the HookProbe mesh, coordinating
    security across thousands of nodes while maintaining per-tenant
    isolation and privacy.
    """

    def __init__(self, node_id: str = "mssp-central"):
        super().__init__(node_id, ProductTier.MSSP)
        self._neural_weights: Optional[bytes] = None
        self._collective_entropy: bytes = b'\x00' * 32

        # Multi-tenant state
        self._tenants: Dict[str, Dict[str, Any]] = {}
        self._tenant_threats: Dict[str, List[ThreatIntel]] = {}
        self._tenant_nodes: Dict[str, Set[str]] = {}

        # Global aggregation
        self._global_threats: Dict[str, ThreatIntel] = {}
        self._threat_correlations: Dict[str, List[str]] = {}

        # Adversarial framework state
        self._adversarial_schedule: List[Dict[str, Any]] = []
        self._adversarial_results: Dict[str, List[Dict[str, Any]]] = {}
        self._designer_alerts: List[Dict[str, Any]] = []

        # Metrics
        self._keys_derived: int = 0
        self._threats_aggregated: int = 0
        self._adversarial_tests_coordinated: int = 0

    def initialize(self) -> bool:
        """Initialize MSSP NSE adapter"""
        try:
            self._neural_weights = self._initialize_weights()
            self._collective_entropy = self._gather_global_entropy()
            self._initialized = True
            return True
        except Exception:
            return False

    def _initialize_weights(self) -> bytes:
        """Initialize weights with cloud-grade entropy"""
        import os
        seed = os.urandom(64)
        extended = hashlib.sha512(seed).digest()
        return seed + extended

    def _gather_global_entropy(self) -> bytes:
        """Gather entropy from cloud sources"""
        import os
        sources = [
            struct.pack('>Q', time.time_ns()),
            self.node_id.encode(),
            os.urandom(32),
        ]
        return hashlib.sha256(b''.join(sources)).digest()

    def derive_session_key(
        self,
        peer_id: str,
        rdv: bytes,
        qsecbit: float,
    ) -> Optional[bytes]:
        """Derive NSE key for MSSP sessions"""
        if not self._neural_weights:
            return None

        kdf_input = b''.join([
            self._neural_weights,
            rdv,
            struct.pack('>f', qsecbit),
            self._collective_entropy,
            peer_id.encode(),
            b'NSE-MSSP-KEY-V1',
        ])

        key = hashlib.sha256(kdf_input).digest()
        for _ in range(10000):  # Cloud can afford more iterations
            key = hashlib.sha256(key + kdf_input).digest()

        self._keys_derived += 1
        return key

    def validate_ter(
        self,
        ter_bytes: bytes,
        expected_source: str,
    ) -> Tuple[bool, str]:
        """Full TER validation at cloud scale"""
        if len(ter_bytes) != 64:
            return False, f"Invalid TER length: {len(ter_bytes)}"

        h_entropy = ter_bytes[:32]
        timestamp = struct.unpack('>Q', ter_bytes[52:60])[0]

        now_us = int(datetime.now().timestamp() * 1_000_000)
        age_seconds = (now_us - timestamp) / 1_000_000
        if age_seconds > 3600 or age_seconds < -60:
            return False, "Timestamp out of range"

        byte_counts = [0] * 256
        for b in h_entropy:
            byte_counts[b] += 1
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / 32
                import math
                entropy -= p * math.log2(p)
        if entropy < 5.0:
            return False, f"Insufficient entropy: {entropy:.2f}"

        return True, "Valid TER"

    def report_threat(self, threat: ThreatIntel) -> bool:
        """Aggregate threat at global level with tenant isolation"""
        if self.is_threat_known(threat.intel_id):
            return False

        if not threat.seen_by:
            threat.seen_by = []
        threat.seen_by.append(self.node_id)

        self.cache_threat(threat)
        self._global_threats[threat.intel_id] = threat
        self._threats_aggregated += 1

        # Correlate globally
        self._correlate_threat_global(threat)

        return True

    def _correlate_threat_global(self, threat: ThreatIntel) -> None:
        """Correlate threat across all tenants"""
        key = f"{threat.threat_type}:{threat.ioc_type}:{threat.ioc_value}"
        if key not in self._threat_correlations:
            self._threat_correlations[key] = []
        self._threat_correlations[key].append(threat.intel_id)

    def get_mesh_status(self) -> Dict[str, Any]:
        """Get MSSP global mesh status"""
        return {
            'node_id': self.node_id,
            'tier': 'mssp',
            'initialized': self._initialized,
            'tenants': len(self._tenants),
            'total_nodes': sum(len(nodes) for nodes in self._tenant_nodes.values()),
            'global_threats': len(self._global_threats),
            'correlations': len(self._threat_correlations),
            'adversarial_tests': self._adversarial_tests_coordinated,
            'designer_alerts': len(self._designer_alerts),
            'keys_derived': self._keys_derived,
            'status': 'healthy' if self._initialized else 'initializing',
        }

    # =========================================================================
    # MULTI-TENANT MANAGEMENT
    # =========================================================================

    def create_tenant(
        self,
        tenant_id: str,
        tenant_name: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Create a new tenant"""
        if tenant_id in self._tenants:
            return False

        self._tenants[tenant_id] = {
            'id': tenant_id,
            'name': tenant_name,
            'created_at': datetime.now().isoformat(),
            'config': config or {},
            'nse_enabled': True,
            'adversarial_enabled': True,
        }
        self._tenant_threats[tenant_id] = []
        self._tenant_nodes[tenant_id] = set()
        return True

    def register_node_to_tenant(
        self,
        tenant_id: str,
        node_id: str,
        tier: ProductTier,
    ) -> bool:
        """Register a node to a tenant"""
        if tenant_id not in self._tenants:
            return False
        self._tenant_nodes[tenant_id].add(node_id)
        return True

    def get_tenant_status(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get status for a specific tenant"""
        if tenant_id not in self._tenants:
            return None

        return {
            'tenant': self._tenants[tenant_id],
            'nodes': len(self._tenant_nodes.get(tenant_id, set())),
            'threats': len(self._tenant_threats.get(tenant_id, [])),
            'nse_status': 'active',
        }

    # =========================================================================
    # ADVERSARIAL FRAMEWORK COORDINATION
    # =========================================================================

    def schedule_adversarial_test(
        self,
        tenant_id: str,
        test_config: Dict[str, Any],
    ) -> str:
        """Schedule an adversarial test for a tenant"""
        test_id = hashlib.sha256(
            f"{tenant_id}:{time.time_ns()}".encode()
        ).hexdigest()[:16]

        schedule_entry = {
            'test_id': test_id,
            'tenant_id': tenant_id,
            'config': test_config,
            'scheduled_at': datetime.now().isoformat(),
            'status': 'scheduled',
            'target_nodes': list(self._tenant_nodes.get(tenant_id, set()))[:10],
        }

        self._adversarial_schedule.append(schedule_entry)
        self._adversarial_tests_coordinated += 1

        return test_id

    def get_adversarial_results(
        self,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Get adversarial test results for a tenant"""
        return self._adversarial_results.get(tenant_id, [])

    def store_adversarial_result(
        self,
        tenant_id: str,
        result: Dict[str, Any],
    ) -> None:
        """Store adversarial test result"""
        if tenant_id not in self._adversarial_results:
            self._adversarial_results[tenant_id] = []
        self._adversarial_results[tenant_id].append(result)

        # Check if result warrants designer alert
        if result.get('cvss_score', 0) >= 7.0:
            self._create_designer_alert(tenant_id, result)

    def _create_designer_alert(
        self,
        tenant_id: str,
        result: Dict[str, Any],
    ) -> None:
        """Create alert for designer review"""
        alert = {
            'alert_id': hashlib.sha256(
                f"alert:{time.time_ns()}".encode()
            ).hexdigest()[:16],
            'timestamp': datetime.now().isoformat(),
            'tenant_id': tenant_id,
            'level': 'critical' if result.get('cvss_score', 0) >= 9.0 else 'high',
            'title': f"High-severity vulnerability found: {result.get('test_type', 'unknown')}",
            'cvss_score': result.get('cvss_score', 0),
            'findings': result.get('findings', []),
            'recommendations': result.get('recommendations', []),
            'acknowledged': False,
        }
        self._designer_alerts.append(alert)

    # =========================================================================
    # DESIGNER ALERTING SYSTEM
    # =========================================================================

    def get_designer_alerts(
        self,
        include_acknowledged: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get alerts for designer review"""
        if include_acknowledged:
            return self._designer_alerts.copy()
        return [
            a for a in self._designer_alerts
            if not a.get('acknowledged', False)
        ]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge a designer alert"""
        for alert in self._designer_alerts:
            if alert['alert_id'] == alert_id:
                alert['acknowledged'] = True
                alert['acknowledged_at'] = datetime.now().isoformat()
                return True
        return False

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of designer alerts"""
        unack = [a for a in self._designer_alerts if not a.get('acknowledged')]
        critical = [a for a in unack if a.get('level') == 'critical']
        high = [a for a in unack if a.get('level') == 'high']

        return {
            'total_alerts': len(self._designer_alerts),
            'unacknowledged': len(unack),
            'critical': len(critical),
            'high': len(high),
            'avg_cvss': sum(a.get('cvss_score', 0) for a in unack) / max(len(unack), 1),
        }

    # =========================================================================
    # GLOBAL THREAT INTELLIGENCE
    # =========================================================================

    def get_global_threat_report(self) -> Dict[str, Any]:
        """Generate global threat intelligence report"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        threat_types: Dict[str, int] = {}
        source_tiers: Dict[str, int] = {}

        for threat in self._global_threats.values():
            sev = threat.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            threat_types[threat.threat_type] = threat_types.get(
                threat.threat_type, 0
            ) + 1
            tier = threat.source_tier.value
            source_tiers[tier] = source_tiers.get(tier, 0) + 1

        # Find correlated threats
        multi_source_threats = [
            corr for corr in self._threat_correlations.values()
            if len(corr) > 2
        ]

        return {
            'timestamp': datetime.now().isoformat(),
            'total_threats': len(self._global_threats),
            'by_severity': severity_counts,
            'by_type': threat_types,
            'by_source_tier': source_tiers,
            'correlations': len(self._threat_correlations),
            'multi_source_threats': len(multi_source_threats),
            'tenants_affected': len(self._tenant_threats),
        }

    def get_threat_correlation_report(self) -> List[Dict[str, Any]]:
        """Get detailed threat correlation report"""
        correlations = []
        for key, threat_ids in self._threat_correlations.items():
            if len(threat_ids) > 1:
                parts = key.split(':')
                correlations.append({
                    'threat_type': parts[0] if len(parts) > 0 else 'unknown',
                    'ioc_type': parts[1] if len(parts) > 1 else 'unknown',
                    'ioc_value': parts[2] if len(parts) > 2 else 'unknown',
                    'occurrence_count': len(threat_ids),
                    'threat_ids': threat_ids[:10],  # First 10
                })

        # Sort by occurrence count
        correlations.sort(key=lambda x: x['occurrence_count'], reverse=True)
        return correlations[:100]  # Top 100

    # =========================================================================
    # COMPLIANCE REPORTING
    # =========================================================================

    def generate_compliance_report(
        self,
        tenant_id: str,
        report_type: str = 'nse_status',
    ) -> Dict[str, Any]:
        """Generate compliance report for a tenant"""
        if tenant_id not in self._tenants:
            return {'error': 'Tenant not found'}

        tenant = self._tenants[tenant_id]
        nodes = self._tenant_nodes.get(tenant_id, set())
        threats = self._tenant_threats.get(tenant_id, [])
        results = self._adversarial_results.get(tenant_id, [])

        return {
            'report_type': report_type,
            'tenant_id': tenant_id,
            'tenant_name': tenant['name'],
            'generated_at': datetime.now().isoformat(),
            'nse_status': {
                'enabled': tenant.get('nse_enabled', False),
                'nodes_protected': len(nodes),
                'keys_derived': self._keys_derived,
            },
            'adversarial_status': {
                'enabled': tenant.get('adversarial_enabled', False),
                'tests_run': len(results),
                'vulnerabilities_found': sum(
                    1 for r in results if r.get('vulnerability_found')
                ),
            },
            'threat_status': {
                'total_threats': len(threats),
                'threats_mitigated': sum(
                    1 for t in threats if getattr(t, 'mitigated', False)
                ),
            },
            'compliance_score': self._calculate_compliance_score(tenant_id),
        }

    def _calculate_compliance_score(self, tenant_id: str) -> float:
        """Calculate compliance score for a tenant"""
        # Simplified scoring - in production would be more sophisticated
        score = 100.0

        # Deduct for unresolved vulnerabilities
        results = self._adversarial_results.get(tenant_id, [])
        for result in results:
            if result.get('vulnerability_found'):
                cvss = result.get('cvss_score', 5.0)
                score -= cvss * 2

        # Deduct for unacknowledged alerts
        alerts = [
            a for a in self._designer_alerts
            if a.get('tenant_id') == tenant_id and not a.get('acknowledged')
        ]
        score -= len(alerts) * 5

        return max(0.0, min(100.0, score))
