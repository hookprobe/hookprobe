"""
Tests for Stage 4: eBPF Kernel-Level Healing

Covers:
- HealingEngine: process tracking, exec events, syscall events, scoring
- HealingEngine: kill, quarantine, hotpatch (dry_run mode)
- HealingEngine: network alert to PID correlation
- HealingBridge: signal emission for process, syscall, kill events
- AEGIS integration: routing rules, tool definitions, event bus types
- ResponseAction: KILL_PROCESS, QUARANTINE_PROCESS
"""

import time

import pytest


# =========================================================================
# HealingEngine — Process Tracking
# =========================================================================


class TestHealingEngineProcessTracking:

    def test_init(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine(dry_run=True)
        assert engine.dry_run is True
        assert engine.get_stats()["processes_tracked"] == 0

    def test_process_exec_event_clean(self):
        from core.napse.synthesis.healing_engine import HealingEngine, ProcessVerdict
        engine = HealingEngine()
        record = engine.process_exec_event(
            pid=1234, ppid=1, uid=1000, comm="vim",
            suspicious_score=0, flags=0,
        )
        assert record.pid == 1234
        assert record.verdict == ProcessVerdict.CLEAN
        assert engine.get_stats()["processes_tracked"] == 1

    def test_process_exec_event_suspicious(self):
        from core.napse.synthesis.healing_engine import HealingEngine, ProcessVerdict
        engine = HealingEngine()
        record = engine.process_exec_event(
            pid=5678, ppid=100, uid=33, comm="bash",
            suspicious_score=60, flags=0x02,  # FLAG_WEB_SHELL
        )
        assert record.verdict == ProcessVerdict.SUSPICIOUS
        assert record.suspicious_score == 60

    def test_process_exec_event_malicious(self):
        from core.napse.synthesis.healing_engine import HealingEngine, ProcessVerdict
        engine = HealingEngine()
        record = engine.process_exec_event(
            pid=9999, ppid=100, uid=0, comm="nc",
            suspicious_score=90, flags=0x0B,
        )
        assert record.verdict == ProcessVerdict.MALICIOUS

    def test_process_exec_score_accumulation(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine()
        r1 = engine.process_exec_event(pid=100, ppid=1, uid=0, comm="test", suspicious_score=30)
        assert r1.suspicious_score == 30
        r2 = engine.process_exec_event(pid=100, ppid=1, uid=0, comm="test", suspicious_score=70)
        assert r2.suspicious_score == 70  # takes max

    def test_get_suspicious_processes(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine()
        engine.process_exec_event(pid=1, ppid=0, uid=0, comm="clean", suspicious_score=0)
        engine.process_exec_event(pid=2, ppid=0, uid=0, comm="medium", suspicious_score=40)
        engine.process_exec_event(pid=3, ppid=0, uid=0, comm="high", suspicious_score=70)
        suspicious = engine.get_suspicious_processes(min_score=30)
        assert len(suspicious) == 2
        pids = {p.pid for p in suspicious}
        assert pids == {2, 3}

    def test_get_malicious_processes(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine()
        engine.process_exec_event(pid=1, ppid=0, uid=0, comm="legit", suspicious_score=50)
        engine.process_exec_event(pid=2, ppid=0, uid=0, comm="evil", suspicious_score=95)
        malicious = engine.get_malicious_processes()
        assert len(malicious) == 1
        assert malicious[0].pid == 2


# =========================================================================
# HealingEngine — Syscall Events
# =========================================================================


class TestHealingEngineSyscallEvents:

    def test_syscall_openat_event(self):
        from core.napse.synthesis.healing_engine import (
            HealingEngine, SyscallEvent, ProcessVerdict,
        )
        engine = HealingEngine()
        event = SyscallEvent(
            timestamp_ns=1000, pid=500, uid=0,
            syscall_type=1, severity=3,  # HIGH openat
            comm="cat", path="/etc/shadow",
        )
        record = engine.process_syscall_event(event)
        assert record is not None
        assert record.file_alerts == 1
        assert record.suspicious_score == 30  # severity * 10

    def test_syscall_connect_event(self):
        from core.napse.synthesis.healing_engine import HealingEngine, SyscallEvent
        engine = HealingEngine()
        event = SyscallEvent(
            timestamp_ns=2000, pid=600, uid=1000,
            syscall_type=2, severity=3,
            dst_port=4444, dst_ip=0xC0A80001,
            comm="nc",
        )
        record = engine.process_syscall_event(event)
        assert record.connection_alerts == 1
        assert record.suspicious_score == 45  # severity * 15

    def test_multiple_syscall_events_accumulate(self):
        from core.napse.synthesis.healing_engine import HealingEngine, SyscallEvent
        engine = HealingEngine()
        for i in range(5):
            event = SyscallEvent(
                timestamp_ns=i * 1000, pid=700, uid=0,
                syscall_type=1, severity=2,
                comm="hack", path="/etc/passwd",
            )
            engine.process_syscall_event(event)
        record = engine.get_process(700)
        assert record.file_alerts == 5
        assert record.suspicious_score == 100  # 5 * 20

    def test_syscall_callback(self):
        from core.napse.synthesis.healing_engine import HealingEngine, SyscallEvent
        events = []
        engine = HealingEngine(on_syscall_event=lambda e: events.append(e))
        event = SyscallEvent(
            timestamp_ns=3000, pid=800, uid=0,
            syscall_type=2, severity=3,
            dst_port=5555, comm="beacon",
        )
        engine.process_syscall_event(event)
        assert len(events) == 1


# =========================================================================
# HealingEngine — Kill / Quarantine / Hotpatch
# =========================================================================


class TestHealingEngineActions:

    def test_kill_process_dry_run(self):
        from core.napse.synthesis.healing_engine import HealingEngine, ProcessVerdict
        engine = HealingEngine(dry_run=True)
        engine.process_exec_event(pid=1000, ppid=1, uid=0, comm="evil", suspicious_score=90)
        result = engine.kill_process(1000, reason="Malicious activity")
        assert result is True
        record = engine.get_process(1000)
        assert record.verdict == ProcessVerdict.KILLED
        assert engine.get_stats()["processes_killed"] == 1

    def test_kill_process_idempotent(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine(dry_run=True)
        engine.kill_process(1000, reason="test")
        engine.kill_process(1000, reason="test again")
        assert engine.get_stats()["processes_killed"] == 1

    def test_quarantine_process_dry_run(self):
        from core.napse.synthesis.healing_engine import HealingEngine, ProcessVerdict
        engine = HealingEngine(dry_run=True)
        engine.process_exec_event(pid=2000, ppid=1, uid=0, comm="suspect", suspicious_score=60)
        result = engine.quarantine_process(2000, reason="Suspicious behavior")
        assert result is True
        record = engine.get_process(2000)
        assert record.verdict == ProcessVerdict.QUARANTINED
        assert engine.get_stats()["processes_quarantined"] == 1

    def test_quarantine_idempotent(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine(dry_run=True)
        engine.quarantine_process(2000)
        engine.quarantine_process(2000)
        assert engine.get_stats()["processes_quarantined"] == 1

    def test_apply_hotpatch(self):
        from core.napse.synthesis.healing_engine import HealingEngine, HotpatchRule
        engine = HealingEngine(dry_run=True)
        rule = HotpatchRule(syscall_nr=59, patch_type=1, target_comm="vuln_app")
        result = engine.apply_hotpatch(rule)
        assert result is True
        assert engine.get_stats()["hotpatches_applied"] == 1

    def test_remove_hotpatch(self):
        from core.napse.synthesis.healing_engine import HealingEngine, HotpatchRule
        engine = HealingEngine(dry_run=True)
        rule = HotpatchRule(syscall_nr=59, patch_type=1)
        engine.apply_hotpatch(rule)
        assert engine.remove_hotpatch(59) is True
        assert engine.remove_hotpatch(59) is False  # already removed

    def test_stats(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine(dry_run=True)
        engine.process_exec_event(pid=1, ppid=0, uid=0, comm="a", suspicious_score=10)
        engine.kill_process(99, reason="test")
        stats = engine.get_stats()
        assert stats["active_processes"] == 1
        assert stats["killed_pids"] == 1
        assert stats["dry_run"] is True


# =========================================================================
# HealingEngine — Network Correlation
# =========================================================================


class TestHealingEngineNetworkCorrelation:

    def test_ip_to_hex(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        assert HealingEngine._ip_to_hex("192.168.1.1") == "0101A8C0"
        assert HealingEngine._ip_to_hex("10.0.0.1") == "0100000A"

    def test_correlate_no_proc(self):
        from core.napse.synthesis.healing_engine import HealingEngine
        engine = HealingEngine(dry_run=True)
        # /proc/net/tcp won't have this connection
        result = engine.correlate_network_alert("192.168.1.100", 12345, "10.0.0.1", 80)
        # May return None if /proc/net/tcp doesn't have the entry
        assert engine.get_stats()["network_correlations"] == 1


# =========================================================================
# HealingBridge
# =========================================================================


class TestHealingBridge:

    def test_init_no_emitter(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        bridge = HealingBridge()
        assert bridge.get_stats()["has_emitter"] is False

    def test_init_with_emitter(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        bridge = HealingBridge(emit_signal=lambda *a: None)
        assert bridge.get_stats()["has_emitter"] is True

    def test_process_event_emission(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        from core.napse.synthesis.healing_engine import HealingEngine, ProcessVerdict
        signals = []

        def capture(source, event_type, severity, data):
            signals.append((source, event_type, severity, data))

        bridge = HealingBridge(emit_signal=capture)
        engine = HealingEngine(dry_run=True, on_process_event=bridge.on_process_event)

        engine.process_exec_event(pid=100, ppid=1, uid=0, comm="evil", suspicious_score=70)
        assert len(signals) == 1
        assert signals[0][0] == "healing"
        assert signals[0][1] == "healing.process_suspicious"
        assert signals[0][2] == "HIGH"
        assert signals[0][3]["pid"] == 100

    def test_process_event_malicious(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        from core.napse.synthesis.healing_engine import HealingEngine
        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        engine = HealingEngine(dry_run=True, on_process_event=bridge.on_process_event)
        engine.process_exec_event(pid=200, ppid=1, uid=0, comm="backdoor", suspicious_score=95)
        assert signals[0][1] == "healing.process_malicious"
        assert signals[0][2] == "CRITICAL"

    def test_low_score_not_emitted(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        from core.napse.synthesis.healing_engine import HealingEngine
        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        engine = HealingEngine(dry_run=True, on_process_event=bridge.on_process_event)
        engine.process_exec_event(pid=300, ppid=1, uid=0, comm="vim", suspicious_score=10)
        assert len(signals) == 0  # Below threshold

    def test_syscall_event_emission(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        from core.napse.synthesis.healing_engine import HealingEngine, SyscallEvent
        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        engine = HealingEngine(dry_run=True, on_syscall_event=bridge.on_syscall_event)
        event = SyscallEvent(
            timestamp_ns=1000, pid=400, uid=0,
            syscall_type=2, severity=3,
            dst_port=4444, comm="nc",
        )
        engine.process_syscall_event(event)
        assert len(signals) == 1
        assert "connect" in signals[0][1]

    def test_syscall_low_severity_not_emitted(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        from core.napse.synthesis.healing_engine import HealingEngine, SyscallEvent
        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        engine = HealingEngine(dry_run=True, on_syscall_event=bridge.on_syscall_event)
        event = SyscallEvent(
            timestamp_ns=1000, pid=500, uid=0,
            syscall_type=1, severity=1,  # LOW
            comm="cat",
        )
        engine.process_syscall_event(event)
        assert len(signals) == 0

    def test_kill_emission(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        bridge.on_kill(pid=600, comm="malware", reason="C2 connection")
        assert len(signals) == 1
        assert signals[0][1] == "healing.process_killed"

    def test_quarantine_emission(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        bridge.on_quarantine(pid=700, comm="suspect", reason="Lateral movement")
        assert len(signals) == 1
        assert signals[0][1] == "healing.process_quarantined"

    def test_hotpatch_emission(self):
        from core.napse.synthesis.healing_bridge import HealingBridge
        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        bridge.on_hotpatch(syscall_nr=59, target_comm="vuln_app")
        assert len(signals) == 1
        assert signals[0][1] == "healing.hotpatch_applied"


# =========================================================================
# AEGIS Integration
# =========================================================================


class TestAegisHealingIntegration:

    def test_event_bus_process_types(self):
        from core.napse.synthesis.event_bus import EventType
        assert hasattr(EventType, "PROCESS_EXEC")
        assert hasattr(EventType, "PROCESS_SUSPICIOUS")

    def test_routing_rules_healing(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "healing.process_suspicious" in ROUTING_RULES
        assert "GUARDIAN" in ROUTING_RULES["healing.process_suspicious"]
        assert "FORGE" in ROUTING_RULES["healing.process_suspicious"]

        assert "healing.process_malicious" in ROUTING_RULES
        assert "GUARDIAN" in ROUTING_RULES["healing.process_malicious"]
        assert "MEDIC" in ROUTING_RULES["healing.process_malicious"]

        assert "healing.process_killed" in ROUTING_RULES
        assert "healing.process_quarantined" in ROUTING_RULES
        assert "healing.syscall_connect" in ROUTING_RULES
        assert "healing.syscall_openat" in ROUTING_RULES
        assert "healing.hotpatch_applied" in ROUTING_RULES

    def test_tool_definitions(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert "kill_process" in TOOL_REGISTRY
        assert "quarantine_process" in TOOL_REGISTRY
        assert "apply_hotpatch" in TOOL_REGISTRY

    def test_kill_tool_requires_confirmation(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert TOOL_REGISTRY["kill_process"].requires_confirmation is True
        assert TOOL_REGISTRY["quarantine_process"].requires_confirmation is True
        assert TOOL_REGISTRY["apply_hotpatch"].requires_confirmation is True

    def test_kill_tool_agents(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert "GUARDIAN" in TOOL_REGISTRY["kill_process"].agents
        assert "MEDIC" in TOOL_REGISTRY["kill_process"].agents
        assert "FORGE" in TOOL_REGISTRY["apply_hotpatch"].agents

    def test_response_actions(self):
        # Read threat_types.py directly to avoid numpy dependency via qsecbit.__init__
        import pathlib
        source = pathlib.Path("core/qsecbit/threat_types.py").read_text()
        assert "KILL_PROCESS" in source
        assert "QUARANTINE_PROCESS" in source


# =========================================================================
# End-to-End: SIA Intent → Healing → AEGIS
# =========================================================================


class TestHealingE2E:

    def test_sia_to_healing_pipeline(self):
        """Simulate: SIA detects Execution intent → HealingEngine traces process → kill."""
        from core.napse.synthesis.healing_engine import HealingEngine, SyscallEvent
        from core.napse.synthesis.healing_bridge import HealingBridge

        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        engine = HealingEngine(
            dry_run=True,
            on_process_event=bridge.on_process_event,
            on_syscall_event=bridge.on_syscall_event,
        )

        # Step 1: SIA detects suspicious process (web shell)
        record = engine.process_exec_event(
            pid=1337, ppid=80, uid=33,  # www-data
            comm="bash", suspicious_score=60,
            flags=0x02,  # FLAG_WEB_SHELL
        )
        assert record.suspicious_score >= 60
        assert len(signals) >= 1

        # Step 2: Syscall monitor detects C2 connection
        event = SyscallEvent(
            timestamp_ns=1000, pid=1337, uid=33,
            syscall_type=2, severity=3,
            dst_port=4444, comm="bash",
        )
        engine.process_syscall_event(event)

        # Score should have escalated
        record = engine.get_process(1337)
        assert record.suspicious_score >= 90  # 60 + 45

        # Step 3: Kill the process
        engine.kill_process(1337, reason="SIA Execution intent + C2 connection")
        bridge.on_kill(1337, "bash", "SIA Execution intent + C2 connection")

        assert engine.get_stats()["processes_killed"] == 1
        # Should have emitted process + syscall + kill signals
        kill_signals = [s for s in signals if "killed" in s[1]]
        assert len(kill_signals) == 1

    def test_benign_process_not_flagged(self):
        """Normal admin activity should not trigger healing."""
        from core.napse.synthesis.healing_engine import HealingEngine, ProcessVerdict
        from core.napse.synthesis.healing_bridge import HealingBridge

        signals = []
        bridge = HealingBridge(emit_signal=lambda *a: signals.append(a))
        engine = HealingEngine(
            dry_run=True,
            on_process_event=bridge.on_process_event,
        )

        # Normal SSH session
        record = engine.process_exec_event(
            pid=5000, ppid=4999, uid=1000,
            comm="ssh", suspicious_score=0,
        )
        assert record.verdict == ProcessVerdict.CLEAN
        assert len(signals) == 0  # No signals for clean processes

    def test_full_healing_stats(self):
        from core.napse.synthesis.healing_engine import HealingEngine, SyscallEvent, HotpatchRule
        engine = HealingEngine(dry_run=True)

        # Track some processes
        engine.process_exec_event(pid=1, ppid=0, uid=0, comm="a", suspicious_score=50)
        engine.process_exec_event(pid=2, ppid=0, uid=0, comm="b", suspicious_score=95)

        # Some syscall events
        engine.process_syscall_event(SyscallEvent(
            timestamp_ns=1000, pid=3, uid=0, syscall_type=1, severity=3, comm="c",
        ))

        # Actions
        engine.kill_process(2, "malicious")
        engine.quarantine_process(1, "suspicious")
        engine.apply_hotpatch(HotpatchRule(syscall_nr=59))

        stats = engine.get_stats()
        assert stats["processes_tracked"] == 3
        assert stats["processes_killed"] == 1
        assert stats["processes_quarantined"] == 1
        assert stats["hotpatches_applied"] == 1
        assert stats["events_processed"] == 3
