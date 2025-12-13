"""
Tests for the Adversarial Security Framework

Tests the AI vs AI security testing capabilities:
- Attack vectors
- Vulnerability analyzer
- Mitigation suggester
- Alert system
- Test engine

Run with: pytest tests/test_adversarial.py -v
"""

import pytest
import secrets
import time
from datetime import datetime
from unittest.mock import Mock, MagicMock

# Test markers
pytestmark = [pytest.mark.unit, pytest.mark.security]


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_neuro_stack():
    """Create a mock NeuroSecurityStack for testing."""
    stack = Mock()

    # HTP binding
    stack.htp_binding = Mock()
    stack.htp_binding.key_derivation = Mock()
    stack.htp_binding.key_derivation.weight_fingerprint = secrets.token_bytes(32)
    stack.htp_binding.key_derivation.collective_entropy = secrets.token_bytes(32)
    stack.htp_binding.get_session_key = Mock(return_value=secrets.token_bytes(32))

    # DSM validator
    stack.dsm_validator = Mock()
    stack.dsm_validator._current_weight_fingerprint = secrets.token_bytes(32)
    stack.dsm_validator.verify_consensus_vote = Mock(return_value=(False, "Invalid"))
    stack.dsm_validator.create_ter_checkpoint_proof = Mock()

    # Mesh auth
    stack.mesh_auth = Mock()
    stack.mesh_auth.generate_rdv_for_peer = Mock(return_value=secrets.token_bytes(32))
    stack.mesh_auth.validate_ter_sync = Mock(return_value=False)
    stack.mesh_auth.encrypt_payload = Mock(return_value=secrets.token_bytes(64))
    stack.mesh_auth.decrypt_payload = Mock(return_value=b"decrypted")

    # get_htp_session_key on stack itself
    stack.get_htp_session_key = Mock(return_value=secrets.token_bytes(32))

    return stack


@pytest.fixture
def attack_result_success():
    """Create a successful attack result."""
    from core.neuro.adversarial.attack_vectors import AttackResult
    return AttackResult(
        attack_name="Test Attack",
        success=True,
        partial_success=False,
        confidence=0.95,
        execution_time_ms=150.0,
        details={'key': 'value'},
        evidence=['Found vulnerability X', 'Exploit successful'],
        exploitability=8.0,
        impact=9.0,
    )


@pytest.fixture
def attack_result_failure():
    """Create a failed attack result."""
    from core.neuro.adversarial.attack_vectors import AttackResult
    return AttackResult(
        attack_name="Test Attack",
        success=False,
        partial_success=False,
        confidence=0.9,
        execution_time_ms=50.0,
        details={},
        evidence=['Attack blocked'],
        exploitability=0.0,
        impact=0.0,
    )


# ============================================================================
# Attack Vector Tests
# ============================================================================

class TestAttackVectors:
    """Test individual attack vectors."""

    def test_ter_replay_attack_structure(self):
        """TER replay attack has correct structure."""
        from core.neuro.adversarial.attack_vectors import TERReplayAttack

        attack = TERReplayAttack()
        assert attack.name == "TER Replay Attack"
        assert len(attack.get_prerequisites()) > 0
        assert len(attack.get_mitigations()) > 0

    def test_timing_attack_structure(self):
        """Timing attack has correct structure."""
        from core.neuro.adversarial.attack_vectors import TimingAttack

        attack = TimingAttack()
        assert "Timing" in attack.name
        assert len(attack.get_prerequisites()) > 0
        assert len(attack.get_mitigations()) > 0

    def test_attack_result_cvss_calculation(self, attack_result_success):
        """Attack result calculates CVSS score correctly."""
        score = attack_result_success.cvss_score()
        assert 0.0 <= score <= 10.0
        assert score == (8.0 + 9.0) / 2  # (exploitability + impact) / 2

    def test_ter_replay_attack_execution(self, mock_neuro_stack):
        """TER replay attack executes against target."""
        from core.neuro.adversarial.attack_vectors import TERReplayAttack

        attack = TERReplayAttack()
        result = attack.execute(mock_neuro_stack)

        assert result.attack_name == attack.name
        assert isinstance(result.success, bool)
        assert result.execution_time_ms > 0
        assert len(result.evidence) > 0

    def test_timing_attack_execution(self, mock_neuro_stack):
        """Timing attack executes and measures timing."""
        from core.neuro.adversarial.attack_vectors import TimingAttack

        attack = TimingAttack({'sample_count': 100})
        result = attack.execute(mock_neuro_stack)

        assert 'mean_zero_heavy_ns' in result.details
        assert 'mean_one_heavy_ns' in result.details
        assert 'timing_diff_percent' in result.details

    def test_entropy_poisoning_attack(self, mock_neuro_stack):
        """Entropy poisoning attack tests entropy validation."""
        from core.neuro.adversarial.attack_vectors import EntropyPoisoningAttack

        attack = EntropyPoisoningAttack()
        result = attack.execute(mock_neuro_stack)

        assert 'poisoned_accepted' in result.details
        assert 'poisoned_rejected' in result.details

    def test_rdv_collision_attack(self, mock_neuro_stack):
        """RDV collision attack tests for hash collisions."""
        from core.neuro.adversarial.attack_vectors import RDVCollisionAttack

        attack = RDVCollisionAttack()
        result = attack.execute(mock_neuro_stack, attempts=100)

        assert 'attempts' in result.details
        assert 'collisions_found' in result.details

    def test_posf_forgery_attack(self, mock_neuro_stack):
        """PoSF forgery attack attempts to forge signatures."""
        from core.neuro.adversarial.attack_vectors import PoSFForgeryAttack

        attack = PoSFForgeryAttack()
        result = attack.execute(mock_neuro_stack)

        assert result.attack_name == "PoSF Forgery Attack"
        # Should fail against properly configured mock
        assert not result.success or 'verification_reason' in result.details

    def test_all_attack_vectors_registered(self):
        """All attack vectors are in the registry."""
        from core.neuro.adversarial.attack_vectors import ALL_ATTACK_VECTORS

        assert len(ALL_ATTACK_VECTORS) >= 9
        names = [a.name for a in ALL_ATTACK_VECTORS]
        assert "TER Replay Attack" in names
        assert "Timing Side-Channel Attack" in names

    def test_get_attack_by_name(self):
        """Can retrieve attack by name."""
        from core.neuro.adversarial.attack_vectors import get_attack_by_name

        attack_class = get_attack_by_name("TER Replay Attack")
        assert attack_class is not None
        assert attack_class.name == "TER Replay Attack"

        # Unknown attack
        assert get_attack_by_name("Unknown Attack") is None


# ============================================================================
# Vulnerability Analyzer Tests
# ============================================================================

class TestVulnerabilityAnalyzer:
    """Test vulnerability analyzer."""

    def test_analyzer_initialization(self):
        """Analyzer initializes correctly."""
        from core.neuro.adversarial.analyzer import VulnerabilityAnalyzer

        analyzer = VulnerabilityAnalyzer()
        assert len(analyzer.vulnerabilities) == 0
        assert len(analyzer.attack_history) == 0

    def test_analyze_successful_attack(self, attack_result_success):
        """Analyzer creates vulnerability from successful attack."""
        from core.neuro.adversarial.analyzer import VulnerabilityAnalyzer

        analyzer = VulnerabilityAnalyzer()
        vuln = analyzer.analyze_result(attack_result_success)

        assert vuln is not None
        assert vuln.id.startswith("HOOKPROBE-")
        assert vuln.cvss_score > 0

    def test_analyze_failed_attack(self, attack_result_failure):
        """Analyzer returns None for failed attack."""
        from core.neuro.adversarial.analyzer import VulnerabilityAnalyzer

        analyzer = VulnerabilityAnalyzer()
        vuln = analyzer.analyze_result(attack_result_failure)

        assert vuln is None

    def test_vulnerability_cvss_calculation(self):
        """Vulnerability calculates CVSS correctly."""
        from core.neuro.adversarial.analyzer import (
            Vulnerability,
            VulnerabilitySeverity
        )
        from core.neuro.adversarial.attack_vectors import (
            AttackCategory,
            AttackComplexity
        )

        vuln = Vulnerability(
            id="TEST-001",
            title="Test Vulnerability",
            description="Test",
            attack_vector="Test Attack",
            category=AttackCategory.CRYPTOGRAPHIC,
            severity=VulnerabilitySeverity.HIGH,
            attack_complexity=AttackComplexity.LOW,
            confidentiality_impact="high",
            integrity_impact="high",
            availability_impact="none",
        )

        score = vuln.calculate_cvss()
        assert 0.0 <= score <= 10.0
        assert vuln.severity == VulnerabilitySeverity.from_score(score)

    def test_risk_assessment_empty(self):
        """Risk assessment works with no vulnerabilities."""
        from core.neuro.adversarial.analyzer import VulnerabilityAnalyzer

        analyzer = VulnerabilityAnalyzer()
        assessment = analyzer.get_risk_assessment()

        assert assessment['overall_risk'] == 'LOW'
        assert assessment['total_vulnerabilities'] == 0

    def test_risk_assessment_with_vulns(self, attack_result_success):
        """Risk assessment reflects vulnerabilities."""
        from core.neuro.adversarial.analyzer import VulnerabilityAnalyzer

        analyzer = VulnerabilityAnalyzer()
        analyzer.analyze_result(attack_result_success)
        assessment = analyzer.get_risk_assessment()

        assert assessment['total_vulnerabilities'] >= 1
        assert assessment['max_cvss'] > 0

    def test_export_report_json(self, attack_result_success):
        """Can export report as JSON."""
        from core.neuro.adversarial.analyzer import VulnerabilityAnalyzer
        import json

        analyzer = VulnerabilityAnalyzer()
        analyzer.analyze_result(attack_result_success)

        report = analyzer.export_report('json')
        parsed = json.loads(report)

        assert 'risk_assessment' in parsed
        assert 'vulnerabilities' in parsed

    def test_export_report_markdown(self, attack_result_success):
        """Can export report as Markdown."""
        from core.neuro.adversarial.analyzer import VulnerabilityAnalyzer

        analyzer = VulnerabilityAnalyzer()
        analyzer.analyze_result(attack_result_success)

        report = analyzer.export_report('markdown')

        assert "# NSE Security Assessment Report" in report
        assert "## Vulnerabilities" in report


# ============================================================================
# Mitigation Suggester Tests
# ============================================================================

class TestMitigationSuggester:
    """Test mitigation suggester."""

    def test_suggester_initialization(self):
        """Suggester initializes with knowledge base."""
        from core.neuro.adversarial.mitigator import MitigationSuggester

        suggester = MitigationSuggester()
        assert len(suggester._knowledge_base) > 0

    def test_suggest_mitigations_for_replay(self):
        """Suggests mitigations for TER replay vulnerability."""
        from core.neuro.adversarial.mitigator import MitigationSuggester
        from core.neuro.adversarial.analyzer import (
            Vulnerability,
            VulnerabilitySeverity
        )
        from core.neuro.adversarial.attack_vectors import AttackCategory

        suggester = MitigationSuggester()

        vuln = Vulnerability(
            id="TEST-001",
            title="TER Replay Vulnerability",
            description="TER sequences can be replayed",
            attack_vector="TER Replay Attack",
            category=AttackCategory.REPLAY,
            severity=VulnerabilitySeverity.HIGH,
        )

        mitigations = suggester.suggest_mitigations(vuln)

        assert len(mitigations) > 0
        assert any("Sequence" in m.title for m in mitigations)

    def test_suggest_mitigations_for_timing(self):
        """Suggests mitigations for timing vulnerability."""
        from core.neuro.adversarial.mitigator import MitigationSuggester
        from core.neuro.adversarial.analyzer import (
            Vulnerability,
            VulnerabilitySeverity
        )
        from core.neuro.adversarial.attack_vectors import AttackCategory

        suggester = MitigationSuggester()

        vuln = Vulnerability(
            id="TEST-002",
            title="Timing Attack Vulnerability",
            description="Timing variations detected",
            attack_vector="Timing Side-Channel Attack",
            category=AttackCategory.SIDE_CHANNEL,
            severity=VulnerabilitySeverity.MEDIUM,
        )

        mitigations = suggester.suggest_mitigations(vuln)

        assert len(mitigations) > 0
        assert any("Constant" in m.title for m in mitigations)

    def test_prioritized_plan(self):
        """Can generate prioritized mitigation plan."""
        from core.neuro.adversarial.mitigator import MitigationSuggester
        from core.neuro.adversarial.analyzer import (
            Vulnerability,
            VulnerabilitySeverity
        )
        from core.neuro.adversarial.attack_vectors import AttackCategory

        suggester = MitigationSuggester()

        # Add some mitigations
        for severity, name in [
            (VulnerabilitySeverity.CRITICAL, "Critical Vuln"),
            (VulnerabilitySeverity.HIGH, "High Vuln"),
            (VulnerabilitySeverity.MEDIUM, "Medium Vuln"),
        ]:
            vuln = Vulnerability(
                id=f"TEST-{name}",
                title=name,
                description="Test",
                attack_vector="TER Replay Attack",
                category=AttackCategory.REPLAY,
                severity=severity,
            )
            suggester.suggest_mitigations(vuln)

        plan = suggester.get_prioritized_plan()

        assert len(plan) > 0
        # Critical should be first
        assert plan[0]['priority'] == 'CRITICAL'


# ============================================================================
# Alert System Tests
# ============================================================================

class TestSecurityAlertSystem:
    """Test security alert system."""

    def test_alert_system_initialization(self):
        """Alert system initializes correctly."""
        from core.neuro.adversarial.alerts import SecurityAlertSystem

        alerts = SecurityAlertSystem()
        assert len(alerts.alerts) == 0

    def test_create_alert(self):
        """Can create security alert."""
        from core.neuro.adversarial.alerts import (
            SecurityAlertSystem,
            AlertLevel
        )

        alerts = SecurityAlertSystem()
        alert = alerts.create_alert(
            level=AlertLevel.WARNING,
            title="Test Alert",
            description="This is a test alert",
        )

        assert alert is not None
        assert alert.id.startswith("ALERT-")
        assert alert.level == AlertLevel.WARNING

    def test_alert_from_vulnerability(self):
        """Can create alert from vulnerability."""
        from core.neuro.adversarial.alerts import SecurityAlertSystem
        from core.neuro.adversarial.analyzer import (
            Vulnerability,
            VulnerabilitySeverity
        )
        from core.neuro.adversarial.attack_vectors import AttackCategory

        alerts = SecurityAlertSystem()

        vuln = Vulnerability(
            id="VULN-001",
            title="Critical Vulnerability",
            description="Very bad",
            attack_vector="Test Attack",
            category=AttackCategory.CRYPTOGRAPHIC,
            severity=VulnerabilitySeverity.CRITICAL,
            cvss_score=9.5,
        )

        alert = alerts.alert_from_vulnerability(vuln)

        assert alert is not None
        assert alert.vulnerability_id == vuln.id
        assert alert.cvss_score == 9.5

    def test_acknowledge_alert(self):
        """Can acknowledge an alert."""
        from core.neuro.adversarial.alerts import (
            SecurityAlertSystem,
            AlertLevel
        )

        alerts = SecurityAlertSystem()
        alert = alerts.create_alert(
            level=AlertLevel.WARNING,
            title="Test",
            description="Test",
        )

        result = alerts.acknowledge_alert(alert.id, "security-team")

        assert result is True
        assert alert.acknowledged is True
        assert alert.acknowledged_by == "security-team"

    def test_resolve_alert(self):
        """Can resolve an alert."""
        from core.neuro.adversarial.alerts import (
            SecurityAlertSystem,
            AlertLevel
        )

        alerts = SecurityAlertSystem()
        alert = alerts.create_alert(
            level=AlertLevel.WARNING,
            title="Test",
            description="Test",
        )

        result = alerts.resolve_alert(alert.id)

        assert result is True
        assert alert.resolved is True

    def test_get_active_alerts(self):
        """Can get active alerts."""
        from core.neuro.adversarial.alerts import (
            SecurityAlertSystem,
            AlertLevel
        )

        alerts = SecurityAlertSystem()

        # Create some alerts
        alert1 = alerts.create_alert(AlertLevel.WARNING, "Test 1", "Desc")
        alert2 = alerts.create_alert(AlertLevel.URGENT, "Test 2", "Desc")
        alerts.resolve_alert(alert1.id)

        active = alerts.get_active_alerts()

        assert len(active) == 1
        assert active[0].id == alert2.id

    def test_alert_statistics(self):
        """Can get alert statistics."""
        from core.neuro.adversarial.alerts import (
            SecurityAlertSystem,
            AlertLevel
        )

        alerts = SecurityAlertSystem()
        alerts.create_alert(AlertLevel.WARNING, "Test 1", "Desc")
        alerts.create_alert(AlertLevel.CRITICAL, "Test 2", "Desc")

        stats = alerts.get_alert_statistics()

        assert stats['total_alerts'] == 2
        assert stats['active_alerts'] == 2
        assert 'warning' in stats['by_level']
        assert 'critical' in stats['by_level']


# ============================================================================
# Adversarial Test Engine Tests
# ============================================================================

class TestAdversarialTestEngine:
    """Test the main adversarial test engine."""

    def test_engine_initialization(self, mock_neuro_stack):
        """Engine initializes correctly."""
        from core.neuro.adversarial.engine import AdversarialTestEngine

        engine = AdversarialTestEngine(target_stack=mock_neuro_stack)

        assert engine.target is not None
        assert len(engine._attack_vectors) > 0

    def test_engine_set_target(self, mock_neuro_stack):
        """Can set target after initialization."""
        from core.neuro.adversarial.engine import AdversarialTestEngine

        engine = AdversarialTestEngine()
        engine.set_target(mock_neuro_stack)

        assert engine.target is mock_neuro_stack

    def test_engine_run_single_attack(self, mock_neuro_stack):
        """Can run a single attack."""
        from core.neuro.adversarial.engine import AdversarialTestEngine
        from core.neuro.adversarial.attack_vectors import TERReplayAttack

        engine = AdversarialTestEngine(target_stack=mock_neuro_stack)
        result = engine.run_single_attack(TERReplayAttack)

        assert result.attack_name == "TER Replay Attack"
        assert isinstance(result.success, bool)

    def test_engine_run_full_assessment(self, mock_neuro_stack):
        """Can run full security assessment."""
        from core.neuro.adversarial.engine import (
            AdversarialTestEngine,
            AdversarialConfig,
            TestMode
        )

        config = AdversarialConfig(mode=TestMode.QUICK)
        engine = AdversarialTestEngine(
            target_stack=mock_neuro_stack,
            config=config,
        )

        result = engine.run_full_assessment()

        assert result.id.startswith("ASSESS-")
        assert result.attacks_run > 0
        assert result.duration_seconds > 0

    def test_engine_security_posture(self, mock_neuro_stack):
        """Can get security posture summary."""
        from core.neuro.adversarial.engine import AdversarialTestEngine

        engine = AdversarialTestEngine(target_stack=mock_neuro_stack)
        posture = engine.get_security_posture()

        assert 'risk_level' in posture
        assert 'vulnerability_count' in posture
        assert 'active_alerts' in posture

    def test_engine_designer_report(self, mock_neuro_stack):
        """Can generate designer report."""
        from core.neuro.adversarial.engine import (
            AdversarialTestEngine,
            AdversarialConfig,
            TestMode
        )

        config = AdversarialConfig(mode=TestMode.QUICK)
        engine = AdversarialTestEngine(
            target_stack=mock_neuro_stack,
            config=config,
        )

        # Run assessment first
        engine.run_full_assessment()

        report = engine.generate_designer_report()

        assert "HOOKPROBE NSE SECURITY ASSESSMENT REPORT" in report
        assert "RISK SUMMARY" in report

    def test_engine_compare_assessments(self, mock_neuro_stack):
        """Can compare two assessments."""
        from core.neuro.adversarial.engine import (
            AdversarialTestEngine,
            AdversarialConfig,
            TestMode
        )

        config = AdversarialConfig(mode=TestMode.QUICK)
        engine = AdversarialTestEngine(
            target_stack=mock_neuro_stack,
            config=config,
        )

        # Run two assessments
        result1 = engine.run_full_assessment()
        result2 = engine.run_full_assessment()

        comparison = engine.compare_assessments(result1.id, result2.id)

        assert 'comparison' in comparison
        assert 'risk_change' in comparison


# ============================================================================
# Integration Tests
# ============================================================================

class TestAdversarialIntegration:
    """Integration tests for the full adversarial workflow."""

    def test_full_workflow(self, mock_neuro_stack):
        """Test complete assessment → analysis → mitigation → alert workflow."""
        from core.neuro.adversarial import (
            AdversarialTestEngine,
            AdversarialConfig,
            TestMode,
        )

        # Configure
        config = AdversarialConfig(
            mode=TestMode.QUICK,
            generate_alerts=True,
        )

        # Run engine
        engine = AdversarialTestEngine(
            target_stack=mock_neuro_stack,
            config=config,
        )

        result = engine.run_full_assessment()

        # Verify full workflow
        assert result.attacks_run > 0

        # Check analyzer has results
        assert len(engine.analyzer.attack_history) > 0

        # Check mitigations if vulnerabilities found
        if result.vulnerabilities_found > 0:
            plan = engine.mitigator.get_prioritized_plan()
            assert len(plan) > 0

        # Check posture
        posture = engine.get_security_posture()
        assert posture['risk_level'] in ['LOW', 'LOW-MEDIUM', 'MEDIUM', 'HIGH', 'CRITICAL']


# Run with: pytest tests/test_adversarial.py -v
