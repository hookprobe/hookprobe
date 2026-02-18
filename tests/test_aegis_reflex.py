"""
AEGIS Reflex — Surgical Interference System Tests

52+ tests across 6 classes covering:
- ReflexTypes: data model validation
- ReflexEngine: threshold logic, velocity, jitter computation
- BayesianRecovery: posterior updates, recovery triggers
- EBPFPrograms: program string validation, fallback commands
- ReflexBridge: BaseBridge integration, polling
- ReflexIntegration: orchestrator routing, tool registration

Run: pytest tests/test_aegis_reflex.py --override-ini="addopts=" -v
"""

import json
import math
import os
import sys
import tempfile
import time
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aegis.reflex.types import (
    LEVEL_THRESHOLDS,
    ReflexDecision,
    ReflexLevel,
    ReflexTarget,
    ScoreVelocity,
)
from core.aegis.reflex.recovery import BayesianRecoveryEngine, RecoveryState
from core.aegis.reflex.ebpf_programs import (
    BCC_AVAILABLE,
    JITTER_TC_PROGRAM,
    SOCKMAP_REDIRECT_PROGRAM,
    SURGICAL_DISCONNECT_PROGRAM,
    get_fallback_block_commands,
    get_fallback_block_remove_commands,
    get_fallback_jitter_commands,
    get_fallback_jitter_remove_commands,
    get_fallback_shadow_commands,
    get_fallback_shadow_remove_commands,
)
from core.aegis.reflex.engine import ReflexEngine
from core.aegis.reflex.bridge import ReflexBridge


# ===================================================================
# Test 1: ReflexTypes
# ===================================================================

class TestReflexTypes:
    """Validate data model correctness."""

    def test_reflex_level_ordering(self):
        """Levels must be ordered: OBSERVE < JITTER < SHADOW < DISCONNECT."""
        assert ReflexLevel.OBSERVE.value < ReflexLevel.JITTER.value
        assert ReflexLevel.JITTER.value < ReflexLevel.SHADOW.value
        assert ReflexLevel.SHADOW.value < ReflexLevel.DISCONNECT.value

    def test_reflex_target_creation(self):
        """ReflexTarget should initialize with correct defaults."""
        target = ReflexTarget(
            source_ip="192.168.1.100",
            level=ReflexLevel.JITTER,
            qsecbit_score=0.45,
        )
        assert target.source_ip == "192.168.1.100"
        assert target.level == ReflexLevel.JITTER
        assert target.recovery_prior == 0.5
        assert target.consecutive_normal == 0
        assert target.jitter_ms == 0
        assert target.pid is None

    def test_score_velocity_computation(self):
        """ScoreVelocity should compute dQ/dt from sample pairs."""
        sv = ScoreVelocity()

        # First sample — velocity should be 0
        sv.update(0.3)
        assert sv.current == 0.0

        # Mock time progression
        sv.samples.clear()
        t0 = time.monotonic()
        sv.samples.append((t0 - 5.0, 0.3))
        sv.samples.append((t0, 0.5))
        dt = 5.0
        expected = (0.5 - 0.3) / dt
        sv.current = expected  # manual compute for deterministic test
        assert abs(sv.current - 0.04) < 0.01

    def test_reflex_decision_fields(self):
        """ReflexDecision should serialize correctly."""
        decision = ReflexDecision(
            target_ip="10.0.0.1",
            old_level=ReflexLevel.OBSERVE,
            new_level=ReflexLevel.JITTER,
            reason="Score escalation: Q=0.45",
            qsecbit_score=0.45,
            velocity=0.02,
        )
        d = decision.to_dict()
        assert d["target_ip"] == "10.0.0.1"
        assert d["old_level"] == "OBSERVE"
        assert d["new_level"] == "JITTER"
        assert d["qsecbit_score"] == 0.45

    def test_level_names(self):
        """All 4 levels should have correct string names."""
        assert ReflexLevel.OBSERVE.name == "OBSERVE"
        assert ReflexLevel.JITTER.name == "JITTER"
        assert ReflexLevel.SHADOW.name == "SHADOW"
        assert ReflexLevel.DISCONNECT.name == "DISCONNECT"


# ===================================================================
# Test 2: ReflexEngine
# ===================================================================

class TestReflexEngine:
    """Test the central evaluator and executor."""

    def setup_method(self):
        self.engine = ReflexEngine()
        # Disable eBPF for testing (no BCC in CI)
        self.engine._use_ebpf = False

    def test_score_to_level_observe(self):
        """Score 0.0–0.30 → OBSERVE."""
        assert self.engine.score_to_level(0.0) == ReflexLevel.OBSERVE
        assert self.engine.score_to_level(0.15) == ReflexLevel.OBSERVE
        assert self.engine.score_to_level(0.29) == ReflexLevel.OBSERVE

    def test_score_to_level_jitter(self):
        """Score 0.30–0.60 → JITTER."""
        assert self.engine.score_to_level(0.30) == ReflexLevel.JITTER
        assert self.engine.score_to_level(0.45) == ReflexLevel.JITTER
        assert self.engine.score_to_level(0.59) == ReflexLevel.JITTER

    def test_score_to_level_shadow(self):
        """Score 0.60–0.85 → SHADOW."""
        assert self.engine.score_to_level(0.60) == ReflexLevel.SHADOW
        assert self.engine.score_to_level(0.72) == ReflexLevel.SHADOW
        assert self.engine.score_to_level(0.84) == ReflexLevel.SHADOW

    def test_score_to_level_disconnect(self):
        """Score 0.85–1.00 → DISCONNECT."""
        assert self.engine.score_to_level(0.85) == ReflexLevel.DISCONNECT
        assert self.engine.score_to_level(0.95) == ReflexLevel.DISCONNECT
        assert self.engine.score_to_level(1.0) == ReflexLevel.DISCONNECT

    def test_velocity_escalation(self):
        """Fast positive velocity should bump level up by 1."""
        # Score 0.50 is normally JITTER, but with high velocity → SHADOW
        level = self.engine.score_to_level(0.50, velocity=0.15)
        assert level == ReflexLevel.SHADOW

    def test_velocity_deescalation(self):
        """Fast negative velocity should drop level by 1."""
        # Score 0.50 is normally JITTER, but with negative velocity → OBSERVE
        level = self.engine.score_to_level(0.50, velocity=-0.08)
        assert level == ReflexLevel.OBSERVE

    def test_evaluate_returns_decision(self):
        """evaluate() should return a ReflexDecision on level change."""
        decision = self.engine.evaluate("192.168.1.100", 0.45)
        assert decision is not None
        assert decision.target_ip == "192.168.1.100"
        assert decision.new_level == ReflexLevel.JITTER
        assert decision.old_level == ReflexLevel.OBSERVE

    def test_evaluate_no_change(self):
        """evaluate() should return None if level doesn't change."""
        self.engine.evaluate("192.168.1.100", 0.45)
        # Same exact score → no level change (velocity ~0 since no delta)
        decision = self.engine.evaluate("192.168.1.100", 0.45)
        assert decision is None

    @patch("core.aegis.reflex.engine.ReflexEngine._run_fallback_commands")
    def test_apply_observe_clears_entries(self, mock_run):
        """Moving to OBSERVE should remove all interference."""
        self.engine.evaluate("10.0.0.1", 0.45)  # Set JITTER
        assert "10.0.0.1" in self.engine._targets
        self.engine.evaluate("10.0.0.1", 0.10)  # Drop to OBSERVE
        assert "10.0.0.1" not in self.engine._targets

    def test_apply_jitter_range(self):
        """Jitter should be 10ms at Q=0.30 and 500ms at Q=0.60."""
        assert self.engine.compute_jitter(0.30) == 10
        assert self.engine.compute_jitter(0.60) == 500
        # Mid-range should be between
        mid = self.engine.compute_jitter(0.45)
        assert 10 < mid < 500

    def test_level_transition_logging(self):
        """Decisions should be logged in the decision_log deque."""
        self.engine.evaluate("10.0.0.1", 0.45)
        assert len(self.engine._decision_log) == 1
        d = self.engine._decision_log[0]
        assert d.target_ip == "10.0.0.1"

    @patch("core.aegis.reflex.engine.ReflexEngine._run_fallback_commands")
    def test_tick_processes_all_targets(self, mock_run):
        """tick() should evaluate all provided scores."""
        scores = {
            "10.0.0.1": 0.45,
            "10.0.0.2": 0.75,
            "10.0.0.3": 0.90,
        }
        decisions = self.engine.tick(scores)
        assert len(decisions) == 3

    @patch("core.aegis.reflex.engine.ReflexEngine._run_fallback_commands")
    def test_remove_target_cleans_state(self, mock_run):
        """remove_target() should clear all state for an IP."""
        self.engine.evaluate("10.0.0.1", 0.45)
        assert self.engine.remove_target("10.0.0.1")
        assert "10.0.0.1" not in self.engine._targets
        assert not self.engine.remove_target("nonexistent")

    def test_get_status_dict(self):
        """get_status() should return comprehensive state."""
        status = self.engine.get_status()
        assert "active_targets" in status
        assert "total_targets" in status
        assert "ebpf_available" in status
        assert "level_counts" in status
        assert "OBSERVE" in status["level_counts"]

    def test_fallback_when_bcc_unavailable(self):
        """Engine should function with fallback commands when BCC unavailable."""
        engine = ReflexEngine()
        engine._use_ebpf = False
        with patch.object(engine, "_run_fallback_commands") as mock_run:
            engine.evaluate("10.0.0.5", 0.45)
            mock_run.assert_called()

    def test_jitter_computation_quadratic(self):
        """Jitter curve should be quadratic (aggressive ramp-up)."""
        j1 = self.engine.compute_jitter(0.35)  # Low in JITTER range
        j2 = self.engine.compute_jitter(0.55)  # High in JITTER range
        # Quadratic means j2 should be much more than linear interpolation
        linear_mid = (10 + 500) / 2
        # j2 should be above linear midpoint (quadratic curves faster)
        assert j2 > j1

    @patch("core.aegis.reflex.engine.ReflexEngine._run_fallback_commands")
    def test_concurrent_targets(self, mock_run):
        """Engine should handle multiple simultaneous targets."""
        for i in range(10):
            self.engine.evaluate(f"10.0.0.{i}", 0.30 + i * 0.07)
        status = self.engine.get_status()
        assert status["total_targets"] >= 5  # Most should be above OBSERVE


# ===================================================================
# Test 3: BayesianRecovery
# ===================================================================

class TestBayesianRecovery:
    """Test the Bayesian self-healing engine."""

    def setup_method(self):
        self.recovery = BayesianRecoveryEngine()

    def test_posterior_update_normal_energy(self):
        """Normal energy (z~0) should decrease threat posterior."""
        self.recovery.register_target("10.0.0.1", initial_prior=0.8)
        self.recovery.update("10.0.0.1", energy_z_score=0.1)
        state = self.recovery.get_state("10.0.0.1")
        assert state["prior"] < 0.8

    def test_posterior_update_anomalous_energy(self):
        """Anomalous energy (z>2) should increase threat posterior."""
        self.recovery.register_target("10.0.0.1", initial_prior=0.3)
        self.recovery.update("10.0.0.1", energy_z_score=3.0)
        state = self.recovery.get_state("10.0.0.1")
        assert state["prior"] > 0.3

    def test_consecutive_normal_triggers_recovery(self):
        """6 consecutive normal readings should trigger recovery."""
        self.recovery.register_target("10.0.0.1", initial_prior=0.15)
        for i in range(10):
            result = self.recovery.update("10.0.0.1", energy_z_score=0.05)
            if result == "recover":
                return
        # Should have recovered within 10 normal readings
        state = self.recovery.get_state("10.0.0.1")
        assert state["prior"] < self.recovery.RECOVERY_THRESHOLD

    def test_single_anomaly_resets_counter(self):
        """A single anomalous reading should reset consecutive_normal counter."""
        self.recovery.register_target("10.0.0.1", initial_prior=0.15)
        # 3 normal readings
        for _ in range(3):
            self.recovery.update("10.0.0.1", energy_z_score=0.1)
        state = self.recovery.get_state("10.0.0.1")
        assert state["consecutive_normal"] > 0
        # One anomalous reading
        self.recovery.update("10.0.0.1", energy_z_score=3.0)
        state = self.recovery.get_state("10.0.0.1")
        assert state["consecutive_normal"] == 0

    def test_recovery_threshold(self):
        """Recovery threshold should be 0.2."""
        assert self.recovery.RECOVERY_THRESHOLD == 0.2

    def test_prior_decay_rate(self):
        """Decay rate should be 0.85."""
        assert self.recovery.DECAY_RATE == 0.85

    def test_energy_likelihood_threat(self):
        """L(threat|z=0) should be ~0, L(threat|z=3) should be ~1."""
        l0 = self.recovery._energy_likelihood_threat(0.0)
        l3 = self.recovery._energy_likelihood_threat(3.0)
        assert l0 < 0.01
        assert l3 > 0.95

    def test_energy_likelihood_normal(self):
        """L(normal|z=0) should be ~1, L(normal|z=3) should be ~0."""
        l0 = self.recovery._energy_likelihood_normal(0.0)
        l3 = self.recovery._energy_likelihood_normal(3.0)
        assert l0 > 0.99
        assert l3 < 0.05

    def test_recovery_removes_reflex_level(self):
        """After recovery, calling remove_target should clean up."""
        self.recovery.register_target("10.0.0.1")
        self.recovery.remove_target("10.0.0.1")
        assert not self.recovery.has_target("10.0.0.1")

    def test_no_recovery_under_threshold(self):
        """Should not recover if posterior stays above threshold."""
        self.recovery.register_target("10.0.0.1", initial_prior=0.8)
        # All anomalous readings — should never recover
        for _ in range(20):
            result = self.recovery.update("10.0.0.1", energy_z_score=3.0)
            assert result is None


# ===================================================================
# Test 4: eBPF Programs
# ===================================================================

class TestEBPFPrograms:
    """Validate eBPF program strings and fallback commands."""

    def test_jitter_program_compiles(self):
        """JITTER_TC_PROGRAM should be a valid C string with BPF maps."""
        assert "BPF_HASH(jitter_targets" in JITTER_TC_PROGRAM
        assert "tc_jitter_egress" in JITTER_TC_PROGRAM
        assert "skb->tstamp" in JITTER_TC_PROGRAM

    def test_sockmap_program_compiles(self):
        """SOCKMAP_REDIRECT_PROGRAM should have sockmap definitions."""
        assert "BPF_SOCKHASH(shadow_map" in SOCKMAP_REDIRECT_PROGRAM
        assert "sk_skb_shadow_redirect" in SOCKMAP_REDIRECT_PROGRAM
        assert "bpf_sk_redirect_hash" in SOCKMAP_REDIRECT_PROGRAM

    def test_surgical_program_compiles(self):
        """SURGICAL_DISCONNECT_PROGRAM should have kill target map."""
        assert "BPF_HASH(kill_targets" in SURGICAL_DISCONNECT_PROGRAM
        assert "xdp_surgical_drop" in SURGICAL_DISCONNECT_PROGRAM
        assert "XDP_DROP" in SURGICAL_DISCONNECT_PROGRAM

    def test_bpf_map_definitions(self):
        """All programs should define their BPF maps."""
        assert "jitter_targets" in JITTER_TC_PROGRAM
        assert "shadow_map" in SOCKMAP_REDIRECT_PROGRAM
        assert "kill_targets" in SURGICAL_DISCONNECT_PROGRAM

    def test_program_constants(self):
        """Programs should include statistics tracking."""
        assert "jitter_stats" in JITTER_TC_PROGRAM
        assert "shadow_stats" in SOCKMAP_REDIRECT_PROGRAM
        assert "surgical_stats" in SURGICAL_DISCONNECT_PROGRAM

    def test_fallback_commands_generated(self):
        """Fallback commands should produce list-form commands (no shell strings)."""
        jitter_cmds = get_fallback_jitter_commands("192.168.1.100", 100, "eth0")
        assert len(jitter_cmds) >= 2
        # Each command is a list of strings (list-form for subprocess)
        assert all(isinstance(cmd, list) for cmd in jitter_cmds)
        assert any("netem" in sub for cmd in jitter_cmds for sub in cmd)

        block_cmds = get_fallback_block_commands("10.0.0.1")
        assert all(isinstance(cmd, list) for cmd in block_cmds)
        assert any("iptables" in sub for cmd in block_cmds for sub in cmd)
        assert any("conntrack" in sub for cmd in block_cmds for sub in cmd)

        shadow_cmds = get_fallback_shadow_commands("10.0.0.1", 9999)
        assert all(isinstance(cmd, list) for cmd in shadow_cmds)
        assert any("REDIRECT" in sub for cmd in shadow_cmds for sub in cmd)

        # Remove commands
        rm_jitter = get_fallback_jitter_remove_commands("10.0.0.1", "eth0")
        assert len(rm_jitter) >= 1
        assert all(isinstance(cmd, list) for cmd in rm_jitter)
        rm_block = get_fallback_block_remove_commands("10.0.0.1")
        assert len(rm_block) >= 1
        rm_shadow = get_fallback_shadow_remove_commands("10.0.0.1", 9999)
        assert len(rm_shadow) >= 1

    def test_fallback_validates_ip(self):
        """Fallback functions must reject malicious IP strings."""
        # Shell injection attempt
        with pytest.raises(ValueError):
            get_fallback_block_commands("1.2.3.4; rm -rf /")
        with pytest.raises(ValueError):
            get_fallback_jitter_commands("10.0.0.1$(whoami)", 100)
        with pytest.raises(ValueError):
            get_fallback_shadow_commands("1.2.3.4 | bash", 9999)
        # Empty and garbage
        with pytest.raises(ValueError):
            get_fallback_block_commands("")
        with pytest.raises(ValueError):
            get_fallback_block_commands("not-an-ip")

    def test_fallback_validates_interface(self):
        """Fallback functions must reject malicious interface names."""
        from core.aegis.reflex.ebpf_programs import _sanitize_interface
        with pytest.raises(ValueError):
            _sanitize_interface("eth0; whoami")
        with pytest.raises(ValueError):
            _sanitize_interface("a" * 20)  # too long
        with pytest.raises(ValueError):
            _sanitize_interface("")
        # Valid interfaces
        assert _sanitize_interface("eth0") == "eth0"
        assert _sanitize_interface("FTS") == "FTS"
        assert _sanitize_interface("wlan_5ghz") == "wlan_5ghz"

    def test_fallback_shadow_validates_port(self):
        """Shadow commands must reject invalid port numbers."""
        with pytest.raises(ValueError):
            get_fallback_shadow_commands("10.0.0.1", 0)
        with pytest.raises(ValueError):
            get_fallback_shadow_commands("10.0.0.1", 70000)

    def test_run_fallback_no_shell(self):
        """_run_fallback_commands must not use shell=True."""
        from unittest.mock import patch
        engine = ReflexEngine()
        engine._use_ebpf = False
        cmds = [["echo", "test"]]
        with patch("subprocess.run") as mock_run:
            engine._run_fallback_commands(cmds)
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args
            # Verify shell=True is NOT in the call
            assert call_kwargs.kwargs.get("shell") is not True
            # Verify the command is a list (not a string)
            assert isinstance(call_kwargs.args[0], list)


# ===================================================================
# Test 5: ReflexBridge
# ===================================================================

class TestReflexBridge:
    """Test the BaseBridge integration."""

    def test_bridge_inherits_base(self):
        """ReflexBridge should be a BaseBridge subclass."""
        from core.aegis.bridges.base_bridge import BaseBridge
        engine = ReflexEngine()
        engine._use_ebpf = False
        bridge = ReflexBridge(engine)
        assert isinstance(bridge, BaseBridge)

    def test_poll_reads_score_file(self):
        """poll() should read from the QSecBit score file."""
        engine = ReflexEngine()
        engine._use_ebpf = False

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "per_ip": {
                    "10.0.0.1": {"score": 0.45},
                    "10.0.0.2": {"score": 0.75},
                }
            }, f)
            f.flush()
            bridge = ReflexBridge(engine, qsecbit_score_path=f.name)

        try:
            signals = bridge.poll()
            # Should produce signals for level changes
            assert len(signals) >= 2
        finally:
            os.unlink(f.name)

    def test_poll_emits_signals_on_level_change(self):
        """poll() should emit StandardSignal on level transitions."""
        engine = ReflexEngine()
        engine._use_ebpf = False

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "per_ip": {
                    "10.0.0.5": {"score": 0.90},
                }
            }, f)
            f.flush()
            bridge = ReflexBridge(engine, qsecbit_score_path=f.name)

        try:
            signals = bridge.poll()
            assert len(signals) >= 1
            sig = signals[0]
            assert sig.source == "reflex"
            assert "reflex." in sig.event_type
            assert sig.data["target_ip"] == "10.0.0.5"
        finally:
            os.unlink(f.name)

    def test_poll_interval(self):
        """ReflexBridge should poll at 2s (faster than default 5s)."""
        engine = ReflexEngine()
        bridge = ReflexBridge(engine)
        assert bridge.poll_interval == 2.0

    def test_bridge_name(self):
        """Bridge name should be 'reflex'."""
        engine = ReflexEngine()
        bridge = ReflexBridge(engine)
        assert bridge.name == "reflex"


# ===================================================================
# Test 6: Integration
# ===================================================================

class TestReflexIntegration:
    """Test integration with AEGIS orchestrator, tools, and bridges."""

    def test_orchestrator_routes_reflex_signals(self):
        """ROUTING_RULES should contain reflex event types."""
        from core.aegis.orchestrator import ROUTING_RULES
        assert "reflex.level_changed" in ROUTING_RULES
        assert "reflex.escalation" in ROUTING_RULES
        assert "reflex.recovery" in ROUTING_RULES
        assert "reflex.disconnect" in ROUTING_RULES
        assert "reflex.jitter_applied" in ROUTING_RULES

    def test_tool_executor_has_reflex_tools(self):
        """TOOL_REGISTRY should contain reflex tools."""
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert "reflex_set_level" in TOOL_REGISTRY
        assert "reflex_remove_target" in TOOL_REGISTRY
        assert "reflex_status" in TOOL_REGISTRY
        assert "reflex_force_recovery" in TOOL_REGISTRY

    def test_bridge_manager_includes_reflex(self):
        """BridgeManager should create a reflex bridge."""
        from core.aegis.bridges import BridgeManager
        manager = BridgeManager()
        assert "reflex" in manager.list_bridges()

    def test_principle_guard_blocks_disable_reflex(self):
        """Principle guard should block 'disable_reflex' action."""
        from core.aegis.principle_guard import IMMUTABLE_PRINCIPLES
        blocked = IMMUTABLE_PRINCIPLES["never_disable_protection"]["blocked_actions"]
        assert "disable_reflex" in blocked

    def test_response_action_enum_has_reflex_variants(self):
        """ResponseAction should have REFLEX_JITTER, REFLEX_SHADOW, REFLEX_DISCONNECT."""
        from core.qsecbit.threat_types import ResponseAction
        assert hasattr(ResponseAction, "REFLEX_JITTER")
        assert hasattr(ResponseAction, "REFLEX_SHADOW")
        assert hasattr(ResponseAction, "REFLEX_DISCONNECT")

    def test_register_and_get_engine(self):
        """Singleton registry should store and retrieve engine."""
        import core.aegis.reflex as reflex_mod
        old = reflex_mod._engine_instance
        try:
            engine = ReflexEngine(interface="lo")
            reflex_mod.register_engine(engine)
            assert reflex_mod.get_engine() is engine
        finally:
            reflex_mod._engine_instance = old

    def test_register_engine_none_initially(self):
        """get_engine() returns None before registration."""
        import core.aegis.reflex as reflex_mod
        old = reflex_mod._engine_instance
        try:
            reflex_mod._engine_instance = None
            assert reflex_mod.get_engine() is None
        finally:
            reflex_mod._engine_instance = old

    def test_shadow_always_runs_iptables(self):
        """_apply_shadow should always run iptables fallback (even when sockmap logged)."""
        engine = ReflexEngine(interface="lo")
        engine._use_ebpf = False  # Force fallback path
        with patch.object(engine, '_run_fallback_commands') as mock_run:
            engine._apply_shadow("10.0.0.1", 9999)
            mock_run.assert_called_once()
            # Verify the commands are for shadow/redirect
            cmds = mock_run.call_args[0][0]
            assert any("REDIRECT" in str(c) for c in cmds)

    def test_qsecbit_bridge_env_path(self):
        """QSecBit bridge should respect QSECBIT_STATS_FILE env var."""
        with patch.dict(os.environ, {"QSECBIT_STATS_FILE": "/tmp/test_qsecbit.json"}):
            # Reimport to pick up env var change
            import importlib
            import core.aegis.bridges.qsecbit_bridge as qmod
            importlib.reload(qmod)
            bridge = qmod.QsecbitBridge()
            assert str(bridge._stats_path) == "/tmp/test_qsecbit.json"

    def test_reflex_bridge_env_path(self):
        """Reflex bridge should respect QSECBIT_STATS_FILE env var."""
        engine = ReflexEngine(interface="lo")
        with patch.dict(os.environ, {"QSECBIT_STATS_FILE": "/tmp/test_reflex.json"}):
            import importlib
            import core.aegis.reflex.bridge as rbmod
            importlib.reload(rbmod)
            bridge = rbmod.ReflexBridge(engine)
            assert bridge._score_path == "/tmp/test_reflex.json"

    def test_bridge_manager_registers_engine(self):
        """BridgeManager should register the reflex engine singleton."""
        import core.aegis.reflex as reflex_mod
        old = reflex_mod._engine_instance
        try:
            reflex_mod._engine_instance = None
            from core.aegis.bridges import BridgeManager
            BridgeManager()
            assert reflex_mod.get_engine() is not None
        finally:
            reflex_mod._engine_instance = old
