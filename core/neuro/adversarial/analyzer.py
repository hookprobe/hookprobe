"""
Vulnerability Analyzer - Evaluates Attack Results

Analyzes attack results to:
1. Score vulnerabilities (CVSS-like)
2. Correlate related vulnerabilities
3. Track vulnerability trends
4. Generate risk assessments
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import logging

from .attack_vectors import AttackResult, AttackCategory, AttackComplexity

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Severity levels aligned with CVSS v3."""
    NONE = 0.0
    LOW = 3.9
    MEDIUM = 6.9
    HIGH = 8.9
    CRITICAL = 10.0

    @classmethod
    def from_score(cls, score: float) -> 'VulnerabilitySeverity':
        """Get severity from numeric score."""
        if score <= 0.0:
            return cls.NONE
        elif score <= 3.9:
            return cls.LOW
        elif score <= 6.9:
            return cls.MEDIUM
        elif score <= 8.9:
            return cls.HIGH
        else:
            return cls.CRITICAL


class VulnerabilityStatus(Enum):
    """Current status of a vulnerability."""
    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Vulnerability:
    """
    A discovered vulnerability in the NSE implementation.
    """
    id: str
    title: str
    description: str
    attack_vector: str
    category: AttackCategory
    severity: VulnerabilitySeverity
    cvss_score: float = 0.0

    # CVSS Components
    attack_complexity: AttackComplexity = AttackComplexity.MEDIUM
    privileges_required: str = "none"
    user_interaction: str = "none"
    scope: str = "unchanged"  # or "changed"
    confidentiality_impact: str = "high"
    integrity_impact: str = "high"
    availability_impact: str = "none"

    # Additional metadata
    affected_components: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # Lifecycle
    status: VulnerabilityStatus = VulnerabilityStatus.NEW
    discovered_at: datetime = field(default_factory=datetime.now)
    confirmed_at: Optional[datetime] = None
    mitigated_at: Optional[datetime] = None

    # Tracking
    test_count: int = 1
    last_tested: datetime = field(default_factory=datetime.now)
    reproducible: bool = True

    def calculate_cvss(self) -> float:
        """
        Calculate CVSS v3 base score.

        Simplified calculation - real CVSS is more complex.
        """
        # Attack complexity factor
        ac_factor = {
            AttackComplexity.LOW: 0.77,
            AttackComplexity.MEDIUM: 0.62,
            AttackComplexity.HIGH: 0.44,
            AttackComplexity.THEORETICAL: 0.25,
        }.get(self.attack_complexity, 0.5)

        # Impact factors
        impact_values = {'none': 0, 'low': 0.22, 'high': 0.56}
        c_impact = impact_values.get(self.confidentiality_impact, 0.56)
        i_impact = impact_values.get(self.integrity_impact, 0.56)
        a_impact = impact_values.get(self.availability_impact, 0)

        # Impact calculation
        impact = 1 - ((1 - c_impact) * (1 - i_impact) * (1 - a_impact))

        if self.scope == "changed":
            impact = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
        else:
            impact = 6.42 * impact

        # Exploitability
        pr_factor = 0.85 if self.privileges_required == "none" else 0.62
        ui_factor = 0.85 if self.user_interaction == "none" else 0.62
        exploitability = 8.22 * ac_factor * pr_factor * ui_factor

        # Final score
        if impact <= 0:
            return 0.0

        base_score = min(10, impact + exploitability)
        self.cvss_score = round(base_score, 1)
        self.severity = VulnerabilitySeverity.from_score(self.cvss_score)

        return self.cvss_score

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'attack_vector': self.attack_vector,
            'category': self.category.name,
            'severity': self.severity.name,
            'cvss_score': self.cvss_score,
            'status': self.status.value,
            'affected_components': self.affected_components,
            'evidence': self.evidence,
            'discovered_at': self.discovered_at.isoformat(),
            'reproducible': self.reproducible,
            'test_count': self.test_count,
        }


class VulnerabilityAnalyzer:
    """
    Analyzes attack results to identify and track vulnerabilities.
    """

    def __init__(self):
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.attack_history: List[AttackResult] = []
        self._correlation_rules: List[Dict] = self._load_correlation_rules()

    def analyze_result(self, result: AttackResult) -> Optional[Vulnerability]:
        """
        Analyze an attack result and create/update vulnerability.

        Args:
            result: AttackResult from an attack vector

        Returns:
            Vulnerability if one was identified
        """
        self.attack_history.append(result)

        if not result.success and not result.partial_success:
            logger.debug(f"Attack {result.attack_name} did not find vulnerability")
            return None

        # Generate vulnerability ID
        vuln_id = self._generate_vuln_id(result)

        if vuln_id in self.vulnerabilities:
            # Update existing vulnerability
            vuln = self.vulnerabilities[vuln_id]
            vuln.test_count += 1
            vuln.last_tested = datetime.now()
            vuln.evidence.extend(result.evidence)
            vuln.reproducible = result.success
            logger.info(f"Updated vulnerability {vuln_id} (test #{vuln.test_count})")
        else:
            # Create new vulnerability
            vuln = self._create_vulnerability(result, vuln_id)
            self.vulnerabilities[vuln_id] = vuln
            logger.warning(f"NEW VULNERABILITY: {vuln.title} (CVSS: {vuln.cvss_score})")

        return vuln

    def _generate_vuln_id(self, result: AttackResult) -> str:
        """Generate unique vulnerability ID."""
        # Hash of attack name + key details
        content = f"{result.attack_name}:{sorted(result.details.keys())}"
        return f"HOOKPROBE-{hashlib.sha256(content.encode()).hexdigest()[:8].upper()}"

    def _create_vulnerability(self, result: AttackResult, vuln_id: str) -> Vulnerability:
        """Create vulnerability from attack result."""
        # Map attack categories to impact
        category_impact = {
            AttackCategory.CRYPTOGRAPHIC: ('high', 'high', 'none'),
            AttackCategory.PROTOCOL: ('high', 'low', 'low'),
            AttackCategory.SIDE_CHANNEL: ('high', 'none', 'none'),
            AttackCategory.STATE_MANIPULATION: ('high', 'high', 'low'),
            AttackCategory.REPLAY: ('high', 'low', 'none'),
            AttackCategory.PREDICTION: ('high', 'high', 'none'),
            AttackCategory.INFRASTRUCTURE: ('high', 'high', 'high'),
        }

        # Get category from attack details
        category = AttackCategory.CRYPTOGRAPHIC
        for cat in AttackCategory:
            if cat.name.lower() in result.attack_name.lower():
                category = cat
                break

        c_impact, i_impact, a_impact = category_impact.get(
            category, ('high', 'low', 'none')
        )

        vuln = Vulnerability(
            id=vuln_id,
            title=f"NSE {result.attack_name} Vulnerability",
            description=f"Vulnerability discovered via {result.attack_name}. "
                       f"Attack succeeded with {result.confidence:.0%} confidence.",
            attack_vector=result.attack_name,
            category=category,
            severity=VulnerabilitySeverity.MEDIUM,  # Will be recalculated
            attack_complexity=AttackComplexity.MEDIUM,
            confidentiality_impact=c_impact,
            integrity_impact=i_impact,
            availability_impact=a_impact,
            affected_components=list(result.details.get('affected', ['NSE'])),
            evidence=result.evidence.copy(),
        )

        # Calculate CVSS
        vuln.calculate_cvss()

        # Adjust based on result scores
        if result.exploitability > 7:
            vuln.attack_complexity = AttackComplexity.LOW
            vuln.calculate_cvss()

        return vuln

    def _load_correlation_rules(self) -> List[Dict]:
        """Load vulnerability correlation rules."""
        return [
            {
                'name': 'timing_and_replay',
                'attacks': ['Timing', 'Replay'],
                'correlation': 'Combined timing and replay attacks can break authentication',
                'severity_boost': 1.5,
            },
            {
                'name': 'entropy_and_prediction',
                'attacks': ['Entropy', 'Prediction'],
                'correlation': 'Low entropy enables key prediction',
                'severity_boost': 2.0,
            },
            {
                'name': 'memory_and_side_channel',
                'attacks': ['Memory', 'Side Channel'],
                'correlation': 'Memory access patterns leak to side channels',
                'severity_boost': 1.3,
            },
        ]

    def correlate_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Find correlated vulnerabilities that together pose higher risk.

        Returns:
            List of correlation findings
        """
        correlations = []

        for rule in self._correlation_rules:
            matching = []
            for vuln_id, vuln in self.vulnerabilities.items():
                for attack_pattern in rule['attacks']:
                    if attack_pattern.lower() in vuln.attack_vector.lower():
                        matching.append(vuln)
                        break

            if len(matching) >= 2:
                combined_score = max(v.cvss_score for v in matching) * rule['severity_boost']
                correlations.append({
                    'rule': rule['name'],
                    'vulnerabilities': [v.id for v in matching],
                    'correlation': rule['correlation'],
                    'combined_cvss': min(10.0, combined_score),
                    'severity': VulnerabilitySeverity.from_score(combined_score).name,
                })

        return correlations

    def get_risk_assessment(self) -> Dict[str, Any]:
        """
        Generate overall risk assessment.

        Returns:
            Risk assessment summary
        """
        if not self.vulnerabilities:
            return {
                'overall_risk': 'LOW',
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'max_cvss': 0.0,
                'avg_cvss': 0.0,
                'recommendation': 'No vulnerabilities found. Continue monitoring.',
            }

        # Count by severity
        counts = {s: 0 for s in VulnerabilitySeverity}
        scores = []

        for vuln in self.vulnerabilities.values():
            counts[vuln.severity] += 1
            scores.append(vuln.cvss_score)

        max_cvss = max(scores)
        avg_cvss = sum(scores) / len(scores)

        # Determine overall risk
        if counts[VulnerabilitySeverity.CRITICAL] > 0:
            overall_risk = 'CRITICAL'
            recommendation = 'IMMEDIATE ACTION REQUIRED: Critical vulnerabilities found'
        elif counts[VulnerabilitySeverity.HIGH] > 0:
            overall_risk = 'HIGH'
            recommendation = 'Prioritize fixing high-severity vulnerabilities'
        elif counts[VulnerabilitySeverity.MEDIUM] > 2:
            overall_risk = 'MEDIUM'
            recommendation = 'Address medium vulnerabilities in next sprint'
        elif counts[VulnerabilitySeverity.MEDIUM] > 0:
            overall_risk = 'LOW-MEDIUM'
            recommendation = 'Schedule vulnerability remediation'
        else:
            overall_risk = 'LOW'
            recommendation = 'Minor issues found. Monitor and address during maintenance'

        # Check correlations
        correlations = self.correlate_vulnerabilities()
        if correlations:
            for corr in correlations:
                if corr['combined_cvss'] > max_cvss:
                    recommendation += f"\nWARNING: Correlated vulnerabilities increase risk ({corr['rule']})"

        return {
            'overall_risk': overall_risk,
            'critical_count': counts[VulnerabilitySeverity.CRITICAL],
            'high_count': counts[VulnerabilitySeverity.HIGH],
            'medium_count': counts[VulnerabilitySeverity.MEDIUM],
            'low_count': counts[VulnerabilitySeverity.LOW],
            'max_cvss': max_cvss,
            'avg_cvss': round(avg_cvss, 1),
            'total_vulnerabilities': len(self.vulnerabilities),
            'correlations': correlations,
            'recommendation': recommendation,
        }

    def get_vulnerability_timeline(self) -> List[Dict[str, Any]]:
        """Get timeline of discovered vulnerabilities."""
        timeline = []
        for vuln in sorted(
            self.vulnerabilities.values(),
            key=lambda v: v.discovered_at
        ):
            timeline.append({
                'timestamp': vuln.discovered_at.isoformat(),
                'id': vuln.id,
                'title': vuln.title,
                'severity': vuln.severity.name,
                'status': vuln.status.value,
            })
        return timeline

    def export_report(self, format: str = 'json') -> str:
        """
        Export vulnerability report.

        Args:
            format: 'json' or 'markdown'
        """
        assessment = self.get_risk_assessment()

        if format == 'json':
            report = {
                'generated_at': datetime.now().isoformat(),
                'risk_assessment': assessment,
                'vulnerabilities': [
                    v.to_dict() for v in self.vulnerabilities.values()
                ],
                'attack_history_count': len(self.attack_history),
            }
            return json.dumps(report, indent=2)

        elif format == 'markdown':
            lines = [
                "# NSE Security Assessment Report",
                f"Generated: {datetime.now().isoformat()}",
                "",
                "## Risk Summary",
                f"**Overall Risk Level**: {assessment['overall_risk']}",
                f"- Critical: {assessment['critical_count']}",
                f"- High: {assessment['high_count']}",
                f"- Medium: {assessment['medium_count']}",
                f"- Low: {assessment['low_count']}",
                "",
                f"**Recommendation**: {assessment['recommendation']}",
                "",
                "## Vulnerabilities",
            ]

            for vuln in sorted(
                self.vulnerabilities.values(),
                key=lambda v: -v.cvss_score
            ):
                lines.extend([
                    f"### {vuln.id}: {vuln.title}",
                    f"- **Severity**: {vuln.severity.name} (CVSS: {vuln.cvss_score})",
                    f"- **Status**: {vuln.status.value}",
                    f"- **Category**: {vuln.category.name}",
                    f"- **Description**: {vuln.description}",
                    "- **Evidence**:",
                ])
                for e in vuln.evidence[:5]:
                    lines.append(f"  - {e}")
                lines.append("")

            return '\n'.join(lines)

        else:
            raise ValueError(f"Unknown format: {format}")

    def update_vulnerability_status(
        self,
        vuln_id: str,
        status: VulnerabilityStatus
    ) -> bool:
        """Update vulnerability status."""
        if vuln_id not in self.vulnerabilities:
            return False

        vuln = self.vulnerabilities[vuln_id]
        vuln.status = status

        if status == VulnerabilityStatus.CONFIRMED:
            vuln.confirmed_at = datetime.now()
        elif status == VulnerabilityStatus.MITIGATED:
            vuln.mitigated_at = datetime.now()

        logger.info(f"Vulnerability {vuln_id} status updated to {status.value}")
        return True
