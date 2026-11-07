"""
Mitigation Suggester - AI-Generated Vulnerability Fixes

Analyzes vulnerabilities and generates:
1. Specific code-level mitigations
2. Architectural recommendations
3. Implementation priorities
4. Defense-in-depth strategies
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import logging

from .analyzer import Vulnerability, VulnerabilitySeverity
from .attack_vectors import AttackCategory, AttackComplexity

logger = logging.getLogger(__name__)


class MitigationPriority(Enum):
    """Mitigation priority levels."""
    CRITICAL = 1    # Fix immediately
    HIGH = 2        # Fix this sprint
    MEDIUM = 3      # Fix next sprint
    LOW = 4         # Fix when convenient
    DEFERRED = 5    # Accept risk or defer


class MitigationType(Enum):
    """Types of mitigations."""
    CODE_FIX = "code_fix"
    CONFIGURATION = "configuration"
    ARCHITECTURE = "architecture"
    MONITORING = "monitoring"
    PROCESS = "process"
    DEFENSE_IN_DEPTH = "defense_in_depth"


@dataclass
class Mitigation:
    """
    A suggested mitigation for a vulnerability.
    """
    id: str
    vulnerability_id: str
    title: str
    description: str
    mitigation_type: MitigationType
    priority: MitigationPriority
    effort_estimate: str  # "hours", "days", "weeks"

    # Implementation details
    affected_files: List[str] = field(default_factory=list)
    code_changes: List[Dict[str, str]] = field(default_factory=list)
    configuration_changes: List[Dict[str, str]] = field(default_factory=list)
    tests_required: List[str] = field(default_factory=list)

    # Effectiveness
    risk_reduction: float = 0.0  # 0-100%
    residual_risk: str = "low"

    # References
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    # Status
    implemented: bool = False
    implemented_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'description': self.description,
            'type': self.mitigation_type.value,
            'priority': self.priority.name,
            'effort': self.effort_estimate,
            'affected_files': self.affected_files,
            'risk_reduction': f"{self.risk_reduction:.0f}%",
            'implemented': self.implemented,
        }


class MitigationSuggester:
    """
    Generates mitigation suggestions for vulnerabilities.

    Uses a knowledge base of NSE-specific mitigations and
    general security best practices.
    """

    def __init__(self):
        self.mitigations: Dict[str, Mitigation] = {}
        self._mitigation_counter = 0
        self._knowledge_base = self._load_knowledge_base()

    def _load_knowledge_base(self) -> Dict[str, Dict]:
        """Load mitigation knowledge base."""
        return {
            # TER Replay mitigations
            'TER Replay': {
                'mitigations': [
                    {
                        'title': 'Implement TER Sequence Validation',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Add strict sequence number validation to reject out-of-order TERs',
                        'files': ['core/neuro/core/ter.py', 'shared/mesh/unified_transport.py'],
                        'code_changes': [
                            {
                                'file': 'core/neuro/core/ter.py',
                                'change': 'Add validate_sequence() method that checks monotonic increment',
                            },
                            {
                                'file': 'shared/mesh/unified_transport.py',
                                'change': 'Call validate_sequence() in _handle_ter_sync()',
                            },
                        ],
                        'effort': 'hours',
                        'risk_reduction': 80,
                        'cwe': ['CWE-294'],  # Authentication Bypass by Capture-replay
                    },
                    {
                        'title': 'Add Timestamp Freshness Check',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Reject TERs with timestamps outside acceptable window (±100ms)',
                        'files': ['core/neuro/core/ter.py'],
                        'effort': 'hours',
                        'risk_reduction': 60,
                    },
                    {
                        'title': 'Implement Nonce-Based Anti-Replay',
                        'type': MitigationType.ARCHITECTURE,
                        'description': 'Add cryptographic nonce to TER structure',
                        'effort': 'days',
                        'risk_reduction': 95,
                    },
                ],
            },

            # Timing Attack mitigations
            'Timing': {
                'mitigations': [
                    {
                        'title': 'Use Constant-Time Comparison',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Replace == comparisons with hmac.compare_digest()',
                        'files': ['core/neuro/integration.py', 'core/htp/transport/htp.py'],
                        'code_changes': [
                            {
                                'file': 'core/neuro/integration.py',
                                'change': 'import hmac; use hmac.compare_digest() for all secret comparisons',
                            },
                        ],
                        'effort': 'hours',
                        'risk_reduction': 90,
                        'cwe': ['CWE-208'],  # Observable Timing Discrepancy
                    },
                    {
                        'title': 'Add Random Timing Jitter',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Add small random delays to crypto operations',
                        'files': ['core/neuro/integration.py'],
                        'effort': 'hours',
                        'risk_reduction': 40,
                    },
                    {
                        'title': 'Use Hardware Crypto (AES-NI)',
                        'type': MitigationType.ARCHITECTURE,
                        'description': 'Leverage hardware crypto for constant-time guarantees',
                        'effort': 'weeks',
                        'risk_reduction': 95,
                    },
                ],
            },

            # Entropy Poisoning mitigations
            'Entropy': {
                'mitigations': [
                    {
                        'title': 'Implement Entropy Quality Validation',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Check entropy quality before accepting TERs (NIST SP 800-90B)',
                        'files': ['core/neuro/core/ter.py'],
                        'code_changes': [
                            {
                                'file': 'core/neuro/core/ter.py',
                                'change': 'Add calculate_entropy() and reject if < 7.0 bits/byte',
                            },
                        ],
                        'effort': 'days',
                        'risk_reduction': 85,
                        'cwe': ['CWE-330'],  # Use of Insufficiently Random Values
                    },
                    {
                        'title': 'Add Hardware RNG Integration',
                        'type': MitigationType.ARCHITECTURE,
                        'description': 'Include TPM/RDRAND entropy in key derivation',
                        'files': ['core/neuro/integration.py'],
                        'effort': 'weeks',
                        'risk_reduction': 95,
                    },
                    {
                        'title': 'Implement Entropy Health Monitoring',
                        'type': MitigationType.MONITORING,
                        'description': 'Alert when entropy quality degrades',
                        'effort': 'days',
                        'risk_reduction': 50,
                    },
                ],
            },

            # Weight Prediction mitigations
            'Prediction': {
                'mitigations': [
                    {
                        'title': 'Add Non-Deterministic Weight Evolution',
                        'type': MitigationType.ARCHITECTURE,
                        'description': 'Include hardware-derived randomness in weight updates',
                        'files': ['core/neuro/neural/engine.py'],
                        'effort': 'days',
                        'risk_reduction': 90,
                    },
                    {
                        'title': 'Implement Weight Blinding',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Apply random blinding factor to weights before fingerprinting',
                        'files': ['core/neuro/integration.py'],
                        'effort': 'days',
                        'risk_reduction': 70,
                    },
                ],
            },

            # RDV Collision mitigations
            'RDV Collision': {
                'mitigations': [
                    {
                        'title': 'Use Full 256-bit RDV',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Do not truncate RDV - use full hash',
                        'files': ['shared/mesh/unified_transport.py'],
                        'effort': 'hours',
                        'risk_reduction': 99,
                        'cwe': ['CWE-328'],  # Reversible One-Way Hash
                    },
                    {
                        'title': 'Add Session Context to RDV',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Include session ID and timestamp in RDV derivation',
                        'files': ['core/neuro/integration.py'],
                        'effort': 'hours',
                        'risk_reduction': 80,
                    },
                ],
            },

            # PoSF Forgery mitigations
            'PoSF': {
                'mitigations': [
                    {
                        'title': 'Bind PoSF to Weight Fingerprint',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Include weight fingerprint in PoSF HMAC',
                        'files': ['core/neuro/core/posf.py'],
                        'effort': 'hours',
                        'risk_reduction': 85,
                    },
                    {
                        'title': 'Use TPM for PoSF Signing',
                        'type': MitigationType.ARCHITECTURE,
                        'description': 'Move PoSF signing to TPM for hardware protection',
                        'effort': 'weeks',
                        'risk_reduction': 95,
                        'cwe': ['CWE-347'],  # Improper Verification of Cryptographic Signature
                    },
                ],
            },

            # Collective Entropy Bypass mitigations
            'Collective': {
                'mitigations': [
                    {
                        'title': 'Require N-of-M Collective Entropy',
                        'type': MitigationType.ARCHITECTURE,
                        'description': 'Key derivation requires entropy from at least N of M nodes',
                        'files': ['core/neuro/integration.py', 'core/neuro/synaptic_encryption.py'],
                        'effort': 'weeks',
                        'risk_reduction': 95,
                    },
                    {
                        'title': 'Detect Missing Entropy Sources',
                        'type': MitigationType.MONITORING,
                        'description': 'Alert when collective entropy has fewer than N contributors',
                        'effort': 'days',
                        'risk_reduction': 60,
                    },
                ],
            },

            # Memory Extraction mitigations
            'Memory': {
                'mitigations': [
                    {
                        'title': 'Zero Memory After Key Use',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Explicitly zero key material after use',
                        'files': ['core/neuro/integration.py'],
                        'code_changes': [
                            {
                                'file': 'core/neuro/integration.py',
                                'change': 'Add _secure_zero(buffer) function and call after key use',
                            },
                        ],
                        'effort': 'hours',
                        'risk_reduction': 70,
                        'cwe': ['CWE-316'],  # Cleartext Storage of Sensitive Information in Memory
                    },
                    {
                        'title': 'Use Secure Enclave (SGX)',
                        'type': MitigationType.ARCHITECTURE,
                        'description': 'Run key derivation inside Intel SGX enclave',
                        'effort': 'weeks',
                        'risk_reduction': 95,
                    },
                ],
            },

            # Side Channel mitigations
            'Side Channel': {
                'mitigations': [
                    {
                        'title': 'Implement Constant-Time Algorithms',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Replace branching on secrets with constant-time alternatives',
                        'files': ['core/neuro/integration.py'],
                        'effort': 'days',
                        'risk_reduction': 80,
                        'cwe': ['CWE-385'],  # Covert Timing Channel
                    },
                    {
                        'title': 'Add Cache-Oblivious Access Patterns',
                        'type': MitigationType.CODE_FIX,
                        'description': 'Access lookup tables in fixed patterns',
                        'effort': 'days',
                        'risk_reduction': 75,
                    },
                ],
            },
        }

    def suggest_mitigations(self, vulnerability: Vulnerability) -> List[Mitigation]:
        """
        Generate mitigation suggestions for a vulnerability.

        Args:
            vulnerability: The vulnerability to mitigate

        Returns:
            List of suggested mitigations
        """
        suggestions = []

        # Find matching knowledge base entries
        for pattern, kb_entry in self._knowledge_base.items():
            if pattern.lower() in vulnerability.attack_vector.lower():
                for mit_data in kb_entry['mitigations']:
                    mit = self._create_mitigation(vulnerability, mit_data)
                    suggestions.append(mit)
                    self.mitigations[mit.id] = mit

        # Add generic defense-in-depth if no specific matches
        if not suggestions:
            suggestions.append(self._create_generic_mitigation(vulnerability))

        # Sort by priority
        suggestions.sort(key=lambda m: (m.priority.value, -m.risk_reduction))

        logger.info(f"Generated {len(suggestions)} mitigations for {vulnerability.id}")
        return suggestions

    def _create_mitigation(
        self,
        vuln: Vulnerability,
        data: Dict[str, Any]
    ) -> Mitigation:
        """Create mitigation from knowledge base data."""
        self._mitigation_counter += 1
        mit_id = f"MIT-{self._mitigation_counter:04d}"

        # Determine priority based on vulnerability severity
        priority_map = {
            VulnerabilitySeverity.CRITICAL: MitigationPriority.CRITICAL,
            VulnerabilitySeverity.HIGH: MitigationPriority.HIGH,
            VulnerabilitySeverity.MEDIUM: MitigationPriority.MEDIUM,
            VulnerabilitySeverity.LOW: MitigationPriority.LOW,
            VulnerabilitySeverity.NONE: MitigationPriority.DEFERRED,
        }
        priority = priority_map.get(vuln.severity, MitigationPriority.MEDIUM)

        return Mitigation(
            id=mit_id,
            vulnerability_id=vuln.id,
            title=data['title'],
            description=data['description'],
            mitigation_type=data.get('type', MitigationType.CODE_FIX),
            priority=priority,
            effort_estimate=data.get('effort', 'days'),
            affected_files=data.get('files', []),
            code_changes=data.get('code_changes', []),
            risk_reduction=data.get('risk_reduction', 50),
            cwe_ids=data.get('cwe', []),
        )

    def _create_generic_mitigation(self, vuln: Vulnerability) -> Mitigation:
        """Create generic defense-in-depth mitigation."""
        self._mitigation_counter += 1
        mit_id = f"MIT-{self._mitigation_counter:04d}"

        return Mitigation(
            id=mit_id,
            vulnerability_id=vuln.id,
            title="Defense-in-Depth Review",
            description=f"Conduct security review of {vuln.attack_vector} implementation",
            mitigation_type=MitigationType.DEFENSE_IN_DEPTH,
            priority=MitigationPriority.MEDIUM,
            effort_estimate='days',
            risk_reduction=30,
        )

    def get_prioritized_plan(self) -> List[Dict[str, Any]]:
        """
        Get prioritized mitigation implementation plan.

        Returns:
            Ordered list of mitigations to implement
        """
        # Group by priority
        by_priority = {}
        for mit in self.mitigations.values():
            if mit.implemented:
                continue
            if mit.priority not in by_priority:
                by_priority[mit.priority] = []
            by_priority[mit.priority].append(mit)

        # Build plan
        plan = []
        phase = 1

        for priority in sorted(by_priority.keys(), key=lambda p: p.value):
            mits = sorted(
                by_priority[priority],
                key=lambda m: -m.risk_reduction
            )

            plan.append({
                'phase': phase,
                'priority': priority.name,
                'mitigations': [m.to_dict() for m in mits],
                'total_effort': self._estimate_total_effort(mits),
                'expected_risk_reduction': self._calculate_combined_reduction(mits),
            })
            phase += 1

        return plan

    def _estimate_total_effort(self, mitigations: List[Mitigation]) -> str:
        """Estimate total effort for a set of mitigations."""
        effort_hours = {
            'hours': 4,
            'days': 24,
            'weeks': 120,
        }

        total_hours = sum(
            effort_hours.get(m.effort_estimate, 24)
            for m in mitigations
        )

        if total_hours <= 8:
            return "1 day"
        elif total_hours <= 40:
            return f"{total_hours // 8} days"
        else:
            return f"{total_hours // 40} weeks"

    def _calculate_combined_reduction(self, mitigations: List[Mitigation]) -> float:
        """Calculate combined risk reduction (not simply additive)."""
        if not mitigations:
            return 0.0

        # Risk reduction compounds: 80% + 50% = 90%, not 130%
        remaining_risk = 100.0
        for mit in mitigations:
            remaining_risk *= (1 - mit.risk_reduction / 100)

        return round(100 - remaining_risk, 1)

    def generate_report(self) -> str:
        """Generate mitigation report in markdown."""
        plan = self.get_prioritized_plan()

        lines = [
            "# NSE Vulnerability Mitigation Plan",
            f"Generated: {datetime.now().isoformat()}",
            "",
            "## Implementation Phases",
            "",
        ]

        for phase in plan:
            lines.extend([
                f"### Phase {phase['phase']}: {phase['priority']} Priority",
                f"- **Effort**: {phase['total_effort']}",
                f"- **Expected Risk Reduction**: {phase['expected_risk_reduction']}%",
                "",
            ])

            for mit in phase['mitigations']:
                lines.extend([
                    f"#### {mit['id']}: {mit['title']}",
                    f"- **Type**: {mit['type']}",
                    f"- **Vulnerability**: {mit['vulnerability_id']}",
                    f"- **Description**: {mit['description']}",
                    f"- **Files**: {', '.join(mit['affected_files']) or 'N/A'}",
                    f"- **Risk Reduction**: {mit['risk_reduction']}",
                    "",
                ])

        return '\n'.join(lines)

    def mark_implemented(self, mitigation_id: str) -> bool:
        """Mark a mitigation as implemented."""
        if mitigation_id not in self.mitigations:
            return False

        mit = self.mitigations[mitigation_id]
        mit.implemented = True
        mit.implemented_at = datetime.now()

        logger.info(f"Mitigation {mitigation_id} marked as implemented")
        return True
