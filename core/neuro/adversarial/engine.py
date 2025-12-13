"""
Adversarial Test Engine - AI vs AI Security Testing

The main orchestrator for HookProbe's red team/blue team security testing.

This engine:
1. Runs attack vectors against NSE implementation
2. Analyzes results to find vulnerabilities
3. Suggests mitigations
4. Alerts designers to risks
5. Tracks security posture over time

"Know your vulnerabilities before someone else does"
"""

import time
import json
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Type
from enum import Enum

from .attack_vectors import (
    AttackVector,
    AttackResult,
    AttackCategory,
    AttackComplexity,
    ALL_ATTACK_VECTORS,
    TERReplayAttack,
    TimingAttack,
    EntropyPoisoningAttack,
    WeightPredictionAttack,
    RDVCollisionAttack,
    PoSFForgeryAttack,
    CollectiveEntropyBypassAttack,
    MemoryExtractionAttack,
    SideChannelAttack,
)
from .analyzer import VulnerabilityAnalyzer, Vulnerability, VulnerabilitySeverity
from .mitigator import MitigationSuggester, Mitigation, MitigationPriority
from .alerts import SecurityAlertSystem, SecurityAlert, AlertLevel

logger = logging.getLogger(__name__)


class TestMode(Enum):
    """Testing mode."""
    QUICK = "quick"         # Fast smoke test
    STANDARD = "standard"   # Normal assessment
    THOROUGH = "thorough"   # Comprehensive
    PARANOID = "paranoid"   # Leave no stone unturned


@dataclass
class AdversarialConfig:
    """Configuration for adversarial testing."""
    mode: TestMode = TestMode.STANDARD
    max_attack_time_seconds: int = 60
    enabled_categories: List[AttackCategory] = field(
        default_factory=lambda: list(AttackCategory)
    )
    max_complexity: AttackComplexity = AttackComplexity.HIGH
    generate_alerts: bool = True
    alert_file: Optional[str] = None
    report_dir: Optional[str] = None
    continuous_testing: bool = False
    test_interval_minutes: int = 60


@dataclass
class AssessmentResult:
    """Result of a security assessment."""
    id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float

    # Results
    attacks_run: int = 0
    attacks_succeeded: int = 0
    attacks_partial: int = 0
    attacks_failed: int = 0

    # Findings
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Risk
    overall_risk: str = "UNKNOWN"
    max_cvss: float = 0.0
    avg_cvss: float = 0.0

    # Mitigations
    mitigations_suggested: int = 0
    total_effort_estimate: str = "unknown"

    # Alerts
    alerts_generated: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_seconds': self.duration_seconds,
            'attacks': {
                'total': self.attacks_run,
                'succeeded': self.attacks_succeeded,
                'partial': self.attacks_partial,
                'failed': self.attacks_failed,
            },
            'vulnerabilities': {
                'total': self.vulnerabilities_found,
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
            },
            'risk': {
                'overall': self.overall_risk,
                'max_cvss': self.max_cvss,
                'avg_cvss': self.avg_cvss,
            },
            'mitigations': {
                'count': self.mitigations_suggested,
                'effort': self.total_effort_estimate,
            },
            'alerts': self.alerts_generated,
        }


class AdversarialTestEngine:
    """
    The main adversarial testing engine.

    Usage:
        engine = AdversarialTestEngine(target_stack=neuro_stack)
        result = engine.run_full_assessment()
        print(result.overall_risk)
    """

    def __init__(
        self,
        target_stack: Optional[Any] = None,
        config: Optional[AdversarialConfig] = None,
    ):
        """
        Initialize the adversarial test engine.

        Args:
            target_stack: NeuroSecurityStack to test
            config: Test configuration
        """
        self.target = target_stack
        self.config = config or AdversarialConfig()

        # Components
        self.analyzer = VulnerabilityAnalyzer()
        self.mitigator = MitigationSuggester()
        self.alerts = SecurityAlertSystem(
            alert_file=self.config.alert_file,
            min_alert_level=AlertLevel.WARNING,
        )

        # Attack vectors
        self._attack_vectors: List[Type[AttackVector]] = self._select_attack_vectors()

        # History
        self._assessment_history: List[AssessmentResult] = []
        self._assessment_counter = 0

        # Report directory
        if self.config.report_dir:
            Path(self.config.report_dir).mkdir(parents=True, exist_ok=True)

        logger.info(
            f"AdversarialTestEngine initialized: "
            f"mode={self.config.mode.value}, "
            f"attacks={len(self._attack_vectors)}"
        )

    def _select_attack_vectors(self) -> List[Type[AttackVector]]:
        """Select attack vectors based on configuration."""
        vectors = []

        for attack_class in ALL_ATTACK_VECTORS:
            # Check category
            if attack_class.category not in self.config.enabled_categories:
                continue

            # Check complexity
            complexity_order = [
                AttackComplexity.LOW,
                AttackComplexity.MEDIUM,
                AttackComplexity.HIGH,
                AttackComplexity.THEORETICAL,
            ]
            if complexity_order.index(attack_class.complexity) > \
               complexity_order.index(self.config.max_complexity):
                continue

            vectors.append(attack_class)

        # Adjust based on mode
        if self.config.mode == TestMode.QUICK:
            # Only run essential attacks
            essential = {TERReplayAttack, TimingAttack, EntropyPoisoningAttack}
            vectors = [v for v in vectors if v in essential]
        elif self.config.mode == TestMode.PARANOID:
            # Run everything multiple times
            pass

        return vectors

    def set_target(self, target_stack: Any):
        """Set the target stack to test."""
        self.target = target_stack

    def run_full_assessment(self) -> AssessmentResult:
        """
        Run a complete security assessment.

        Returns:
            AssessmentResult with findings
        """
        if not self.target:
            raise ValueError("No target stack set. Call set_target() first.")

        self._assessment_counter += 1
        assessment_id = f"ASSESS-{self._assessment_counter:04d}"
        start_time = datetime.now()

        logger.info(f"Starting security assessment {assessment_id}")

        # Track results
        attack_results: List[AttackResult] = []
        vulnerabilities: List[Vulnerability] = []

        # Run all attack vectors
        for attack_class in self._attack_vectors:
            try:
                logger.info(f"Running attack: {attack_class.name}")
                attack = attack_class()

                # Set timeout based on config
                result = self._run_attack_with_timeout(attack)
                attack_results.append(result)

                # Analyze result
                if result.success or result.partial_success:
                    vuln = self.analyzer.analyze_result(result)
                    if vuln:
                        vulnerabilities.append(vuln)

                        # Generate alert
                        if self.config.generate_alerts:
                            self.alerts.alert_from_vulnerability(vuln)

            except Exception as e:
                logger.error(f"Attack {attack_class.name} failed: {e}")

        # Get risk assessment
        risk_assessment = self.analyzer.get_risk_assessment()

        # Generate mitigations
        all_mitigations = []
        for vuln in vulnerabilities:
            mits = self.mitigator.suggest_mitigations(vuln)
            all_mitigations.extend(mits)

        # Build result
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        result = AssessmentResult(
            id=assessment_id,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            attacks_run=len(attack_results),
            attacks_succeeded=sum(1 for r in attack_results if r.success),
            attacks_partial=sum(1 for r in attack_results if r.partial_success and not r.success),
            attacks_failed=sum(1 for r in attack_results if not r.success and not r.partial_success),
            vulnerabilities_found=len(vulnerabilities),
            critical_count=risk_assessment['critical_count'],
            high_count=risk_assessment['high_count'],
            medium_count=risk_assessment['medium_count'],
            low_count=risk_assessment['low_count'],
            overall_risk=risk_assessment['overall_risk'],
            max_cvss=risk_assessment['max_cvss'],
            avg_cvss=risk_assessment['avg_cvss'],
            mitigations_suggested=len(all_mitigations),
            total_effort_estimate=self._estimate_total_effort(all_mitigations),
            alerts_generated=len(self.alerts.get_active_alerts()),
        )

        self._assessment_history.append(result)

        # Save report if configured
        if self.config.report_dir:
            self._save_report(result)

        # Log summary
        self._log_assessment_summary(result)

        return result

    def _run_attack_with_timeout(self, attack: AttackVector) -> AttackResult:
        """Run an attack with timeout."""
        # For now, just run directly
        # In production, would use threading with timeout
        return attack.execute(self.target)

    def _estimate_total_effort(self, mitigations: List[Mitigation]) -> str:
        """Estimate total effort for all mitigations."""
        effort_hours = {
            'hours': 4,
            'days': 24,
            'weeks': 120,
        }

        total = sum(
            effort_hours.get(m.effort_estimate, 24)
            for m in mitigations
        )

        if total <= 8:
            return "1 day"
        elif total <= 40:
            return f"{total // 8} days"
        else:
            return f"{total // 40} weeks"

    def _save_report(self, result: AssessmentResult):
        """Save assessment report."""
        if not self.config.report_dir:
            return

        report_path = Path(self.config.report_dir) / f"{result.id}.json"
        report = {
            'assessment': result.to_dict(),
            'vulnerabilities': self.analyzer.export_report('json'),
            'mitigations': self.mitigator.generate_report(),
            'alerts': self.alerts.generate_summary(),
        }

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Report saved to {report_path}")

    def _log_assessment_summary(self, result: AssessmentResult):
        """Log assessment summary."""
        logger.info("=" * 60)
        logger.info(f"SECURITY ASSESSMENT COMPLETE: {result.id}")
        logger.info("=" * 60)
        logger.info(f"Duration: {result.duration_seconds:.1f}s")
        logger.info(f"Attacks: {result.attacks_run} run, "
                   f"{result.attacks_succeeded} succeeded, "
                   f"{result.attacks_partial} partial")
        logger.info(f"Vulnerabilities: {result.vulnerabilities_found} found "
                   f"(C:{result.critical_count} H:{result.high_count} "
                   f"M:{result.medium_count} L:{result.low_count})")
        logger.info(f"Overall Risk: {result.overall_risk}")
        logger.info(f"Max CVSS: {result.max_cvss}")
        logger.info(f"Mitigations Suggested: {result.mitigations_suggested}")
        logger.info(f"Estimated Effort: {result.total_effort_estimate}")
        logger.info("=" * 60)

    def run_single_attack(
        self,
        attack_class: Type[AttackVector],
        **kwargs
    ) -> AttackResult:
        """
        Run a single attack vector.

        Args:
            attack_class: Attack vector class to run
            **kwargs: Additional arguments for the attack

        Returns:
            AttackResult
        """
        if not self.target:
            raise ValueError("No target stack set")

        attack = attack_class()
        return attack.execute(self.target, **kwargs)

    def run_category(self, category: AttackCategory) -> List[AttackResult]:
        """Run all attacks in a category."""
        results = []
        for attack_class in self._attack_vectors:
            if attack_class.category == category:
                try:
                    result = self.run_single_attack(attack_class)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Attack {attack_class.name} failed: {e}")
        return results

    def get_security_posture(self) -> Dict[str, Any]:
        """
        Get current security posture summary.

        Returns:
            Security posture information
        """
        risk = self.analyzer.get_risk_assessment()
        alert_stats = self.alerts.get_alert_statistics()
        plan = self.mitigator.get_prioritized_plan()

        return {
            'timestamp': datetime.now().isoformat(),
            'risk_level': risk['overall_risk'],
            'vulnerability_count': risk['total_vulnerabilities'],
            'max_cvss': risk['max_cvss'],
            'active_alerts': alert_stats['active_alerts'],
            'pending_mitigations': sum(
                len(p['mitigations']) for p in plan
            ),
            'critical_actions': [
                m['title'] for p in plan
                if p['priority'] == 'CRITICAL'
                for m in p['mitigations']
            ],
            'last_assessment': (
                self._assessment_history[-1].id
                if self._assessment_history else None
            ),
        }

    def compare_assessments(
        self,
        assessment_id_1: str,
        assessment_id_2: str
    ) -> Dict[str, Any]:
        """Compare two assessments to see changes."""
        a1 = next((a for a in self._assessment_history if a.id == assessment_id_1), None)
        a2 = next((a for a in self._assessment_history if a.id == assessment_id_2), None)

        if not a1 or not a2:
            return {'error': 'Assessment not found'}

        return {
            'comparison': f"{a1.id} vs {a2.id}",
            'risk_change': f"{a1.overall_risk} → {a2.overall_risk}",
            'vulnerability_change': a2.vulnerabilities_found - a1.vulnerabilities_found,
            'critical_change': a2.critical_count - a1.critical_count,
            'high_change': a2.high_count - a1.high_count,
            'cvss_change': a2.max_cvss - a1.max_cvss,
            'improved': a2.max_cvss <= a1.max_cvss,
        }

    def generate_designer_report(self) -> str:
        """
        Generate comprehensive report for designers.

        This is the main output that tells designers:
        1. What vulnerabilities exist
        2. How severe they are
        3. What to fix first
        4. How to fix them
        """
        lines = [
            "=" * 70,
            "HOOKPROBE NSE SECURITY ASSESSMENT REPORT",
            "=" * 70,
            f"Generated: {datetime.now().isoformat()}",
            "",
        ]

        # Risk Summary
        risk = self.analyzer.get_risk_assessment()
        lines.extend([
            "## RISK SUMMARY",
            f"Overall Risk Level: **{risk['overall_risk']}**",
            f"Max CVSS Score: {risk['max_cvss']}",
            f"Average CVSS Score: {risk['avg_cvss']}",
            "",
            f"Critical Vulnerabilities: {risk['critical_count']}",
            f"High Vulnerabilities: {risk['high_count']}",
            f"Medium Vulnerabilities: {risk['medium_count']}",
            f"Low Vulnerabilities: {risk['low_count']}",
            "",
            f"Recommendation: {risk['recommendation']}",
            "",
        ])

        # Correlations
        if risk.get('correlations'):
            lines.extend([
                "## CORRELATED VULNERABILITIES (INCREASED RISK)",
            ])
            for corr in risk['correlations']:
                lines.extend([
                    f"- {corr['rule']}: {corr['correlation']}",
                    f"  Combined CVSS: {corr['combined_cvss']}",
                ])
            lines.append("")

        # Mitigation Plan
        plan = self.mitigator.get_prioritized_plan()
        if plan:
            lines.extend([
                "## MITIGATION PRIORITY",
            ])
            for phase in plan:
                lines.extend([
                    f"### Phase {phase['phase']}: {phase['priority']}",
                    f"Effort: {phase['total_effort']}",
                    f"Risk Reduction: {phase['expected_risk_reduction']}%",
                ])
                for mit in phase['mitigations'][:3]:  # Top 3 per phase
                    lines.append(f"- {mit['title']}")
                lines.append("")

        # Active Alerts
        active_alerts = self.alerts.get_active_alerts()
        if active_alerts:
            lines.extend([
                "## ACTIVE SECURITY ALERTS",
            ])
            for alert in sorted(active_alerts, key=lambda a: a.level.value)[:5]:
                lines.extend([
                    f"[{alert.level.value.upper()}] {alert.title}",
                    f"  {alert.description[:100]}...",
                ])
            lines.append("")

        # History
        if self._assessment_history:
            lines.extend([
                "## ASSESSMENT HISTORY",
            ])
            for assess in self._assessment_history[-5:]:
                lines.append(
                    f"- {assess.id}: Risk={assess.overall_risk}, "
                    f"Vulns={assess.vulnerabilities_found}"
                )
            lines.append("")

        lines.extend([
            "=" * 70,
            "END OF REPORT",
            "=" * 70,
        ])

        return '\n'.join(lines)


# Convenience function
def create_adversarial_engine(
    target_stack: Any,
    mode: TestMode = TestMode.STANDARD,
    report_dir: Optional[str] = None,
) -> AdversarialTestEngine:
    """Create an adversarial test engine with common defaults."""
    config = AdversarialConfig(
        mode=mode,
        report_dir=report_dir,
        generate_alerts=True,
    )
    return AdversarialTestEngine(target_stack=target_stack, config=config)
