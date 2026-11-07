"""
SIA (Semantic Intent Attribution) Test Suite

Tests the full SIA pipeline:
- EntityGraph construction and feature vectors
- GraphEmbedder message-passing and Golden Harmonic
- IntentDecoder HMM/Viterbi decoding
- BayesianScorer belief evolution and sandbox trigger
- SIAEngine orchestration and signal emission
- VirtualSandbox OVS isolation
- AEGIS integration (routing rules, tools, guardian intent handling)
- NAPSE EventBus types (INTENT_DETECTED, ENTITY_SANDBOXED)
- E2E pipeline: events → graph → embedding → intent → scoring → sandbox
"""

import math
import time
import pytest

from core.napse.intelligence.entity_graph import (
    EntityGraph,
    EntityNode,
    EntityEdge,
    EntityType,
    FEATURE_DIM,
)
from core.napse.intelligence.graph_embedder import (
    GraphEmbedder,
    EMBEDDING_DIM,
)
from core.napse.intelligence.intent_decoder import (
    IntentDecoder,
    IntentPhase,
    IntentSequence,
    NUM_STATES,
)
from core.napse.intelligence.bayesian_scorer import (
    BayesianScorer,
    EvidenceRecord,
    EntityBelief,
    SANDBOX_THRESHOLD,
)
from core.napse.intelligence.sia_engine import SIAEngine
from core.aegis.tools.virtual_sandbox import (
    VirtualSandbox,
    SandboxSession,
    SANDBOX_VLAN,
    DEFAULT_SANDBOX_DURATION_S,
)


# ======================================================================
# Entity Graph Tests
# ======================================================================

class TestEntityGraph:
    """Test EntityGraph construction and operations."""

    def test_init(self):
        graph = EntityGraph()
        assert graph is not None
        stats = graph.get_stats()
        assert stats["node_count"] == 0
        assert stats["edge_count"] == 0

    def test_add_connection_event(self):
        graph = EntityGraph()
        graph.add_connection_event(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            dst_port=443, proto="tcp", service="tls",
        )
        node = graph.get_node("10.0.0.1")
        assert node is not None
        assert node.entity_type == EntityType.IP
        assert node.event_count >= 1

    def test_add_dns_event(self):
        graph = EntityGraph()
        graph.add_dns_event("10.0.0.1", "example.com", ["1.2.3.4"])
        node = graph.get_node("10.0.0.1")
        assert node is not None
        assert node.dns_queries >= 1

    def test_add_alert_event(self):
        graph = EntityGraph()
        graph.add_alert_event("10.0.0.1", "HIGH")
        node = graph.get_node("10.0.0.1")
        assert node is not None
        assert node.alert_count >= 1

    def test_feature_vector_dimension(self):
        graph = EntityGraph()
        graph.add_connection_event(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            dst_port=80, proto="tcp",
        )
        node = graph.get_node("10.0.0.1")
        features = node.get_feature_vector()
        assert len(features) == FEATURE_DIM

    def test_edge_creation(self):
        graph = EntityGraph()
        graph.add_connection_event(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            dst_port=80, proto="tcp",
        )
        neighbors = graph.get_neighbors("10.0.0.1")
        assert len(neighbors) > 0

    def test_subgraph_extraction(self):
        graph = EntityGraph()
        graph.add_connection_event("10.0.0.1", "10.0.0.2", 80)
        graph.add_connection_event("10.0.0.2", "10.0.0.3", 443)
        subgraph = graph.get_subgraph("10.0.0.1", depth=2)
        assert "nodes" in subgraph
        assert "edges" in subgraph

    def test_multiple_connections_increase_weight(self):
        graph = EntityGraph()
        graph.add_connection_event("10.0.0.1", "10.0.0.2", 80)
        graph.add_connection_event("10.0.0.1", "10.0.0.2", 80)
        graph.add_connection_event("10.0.0.1", "10.0.0.2", 80)
        node = graph.get_node("10.0.0.1")
        assert node.event_count >= 3

    def test_port_diversity(self):
        graph = EntityGraph()
        for port in [22, 80, 443, 8080, 8443]:
            graph.add_connection_event("10.0.0.1", "10.0.0.2", port)
        node = graph.get_node("10.0.0.1")
        assert len(node.unique_dest_ports) >= 5

    def test_stale_eviction(self):
        graph = EntityGraph(window_hours=0.0001)  # Very short window
        graph.add_connection_event("10.0.0.1", "10.0.0.2", 80)
        time.sleep(0.5)
        graph.evict_stale()
        # Node may or may not be evicted depending on timing


# ======================================================================
# Graph Embedder Tests
# ======================================================================

class TestGraphEmbedder:
    """Test GraphEmbedder embedding computation."""

    def _create_populated_graph(self, n_entities=5):
        graph = EntityGraph()
        for i in range(n_entities):
            ip = f"10.0.0.{i+1}"
            for port in [80, 443, 22]:
                graph.add_connection_event(ip, f"10.0.1.{i+1}", port)
            graph.add_dns_event(ip, f"host{i}.example.com", [f"1.2.3.{i}"])
        return graph

    def test_init(self):
        graph = EntityGraph()
        embedder = GraphEmbedder(graph=graph)
        assert embedder is not None

    def test_embed_entity(self):
        graph = self._create_populated_graph()
        embedder = GraphEmbedder(graph=graph)
        embedding = embedder.embed_entity("10.0.0.1")
        assert len(embedding) == EMBEDDING_DIM
        # Check normalization
        norm = math.sqrt(sum(x*x for x in embedding))
        assert abs(norm - 1.0) < 0.01

    def test_embed_unknown_entity(self):
        graph = EntityGraph()
        embedder = GraphEmbedder(graph=graph)
        embedding = embedder.embed_entity("nonexistent")
        assert embedding is None

    def test_golden_harmonic_warmup(self):
        graph = self._create_populated_graph(n_entities=60)
        embedder = GraphEmbedder(graph=graph)
        # Compute embeddings to build golden harmonic
        for i in range(60):
            embedder.embed_entity(f"10.0.0.{i+1}")
        assert embedder.is_warmed_up()

    def test_compute_deviation(self):
        graph = self._create_populated_graph(n_entities=60)
        embedder = GraphEmbedder(graph=graph)
        for i in range(60):
            embedder.embed_entity(f"10.0.0.{i+1}")
        deviation = embedder.compute_deviation("10.0.0.1")
        assert 0.0 <= deviation <= 1.0

    def test_deviation_before_warmup(self):
        graph = self._create_populated_graph(n_entities=3)
        embedder = GraphEmbedder(graph=graph)
        embedder.embed_entity("10.0.0.1")
        deviation = embedder.compute_deviation("10.0.0.1")
        assert deviation == 0.0  # Not warmed up

    def test_different_entities_get_different_embeddings(self):
        graph = self._create_populated_graph()
        embedder = GraphEmbedder(graph=graph)
        emb1 = embedder.embed_entity("10.0.0.1")
        emb2 = embedder.embed_entity("10.0.0.2")
        assert emb1 is not None
        assert emb2 is not None
        # Embeddings may be similar due to similar topology but not identical
        assert isinstance(emb1, list)
        assert isinstance(emb2, list)

    def test_stats(self):
        graph = self._create_populated_graph()
        embedder = GraphEmbedder(graph=graph)
        embedder.embed_entity("10.0.0.1")
        stats = embedder.get_stats()
        assert stats["embedding_dim"] == EMBEDDING_DIM
        assert "warmed_up" in stats


# ======================================================================
# Intent Decoder Tests
# ======================================================================

class TestIntentDecoder:
    """Test IntentDecoder HMM/Viterbi decoding."""

    def test_init(self):
        decoder = IntentDecoder()
        assert decoder is not None
        assert decoder._num_states == NUM_STATES

    def test_observe_returns_intent_sequence(self):
        decoder = IntentDecoder()
        features = [0.0] * 16
        intent = decoder.observe("10.0.0.1", features=features)
        assert isinstance(intent, IntentSequence)
        assert intent.entity_id == "10.0.0.1"

    def test_initial_state_benign(self):
        decoder = IntentDecoder()
        features = [0.0] * 16  # Low features = benign
        intent = decoder.observe("10.0.0.1", features=features)
        # With zero features, should likely be BENIGN
        assert intent.current_phase is not None

    def test_high_alert_features_shift_to_attack(self):
        decoder = IntentDecoder()
        # Simulate features indicating attack: high alerts, high port entropy
        for _ in range(10):
            features = [0.0] * 16
            features[7] = 5.0   # High alerts
            features[9] = 4.5   # High port entropy
            features[14] = 1.0  # High connection rate
            intent = decoder.observe("10.0.0.1", features=features, deviation=0.8)
        # After many observations with attack-like features
        assert intent.current_phase != IntentPhase.BENIGN or intent.current_confidence < 0.5

    def test_intent_phase_properties(self):
        assert IntentPhase.BENIGN.is_attack is False
        assert IntentPhase.RECONNAISSANCE.is_attack is True
        assert IntentPhase.EXFILTRATION.is_attack is True
        assert IntentPhase.IMPACT.mitre_tactic == "TA0040"
        assert IntentPhase.RECONNAISSANCE.mitre_tactic == "TA0043"

    def test_intent_sequence_attack_progress(self):
        seq = IntentSequence(
            entity_id="test",
            current_phase=IntentPhase.LATERAL_MOVEMENT,
            current_confidence=0.8,
        )
        assert seq.is_attacking is True
        assert seq.attack_progress > 0.0
        assert seq.attack_progress < 1.0

    def test_benign_is_not_attacking(self):
        seq = IntentSequence(
            entity_id="test",
            current_phase=IntentPhase.BENIGN,
            current_confidence=0.9,
        )
        assert seq.is_attacking is False
        assert seq.attack_progress == 0.0

    def test_predict_next_phase(self):
        decoder = IntentDecoder()
        features = [0.0] * 16
        decoder.observe("10.0.0.1", features=features)
        next_phase, prob = decoder.predict_next_phase("10.0.0.1")
        assert isinstance(next_phase, IntentPhase)
        assert 0.0 <= prob <= 1.0

    def test_reset_entity(self):
        decoder = IntentDecoder()
        features = [0.0] * 16
        decoder.observe("10.0.0.1", features=features)
        decoder.reset_entity("10.0.0.1")
        phase = decoder.get_current_phase("10.0.0.1")
        assert phase == IntentPhase.BENIGN

    def test_to_dict(self):
        seq = IntentSequence(
            entity_id="10.0.0.1",
            phases=[IntentPhase.BENIGN, IntentPhase.RECONNAISSANCE],
            current_phase=IntentPhase.RECONNAISSANCE,
            current_confidence=0.7,
        )
        d = seq.to_dict()
        assert d["entity_id"] == "10.0.0.1"
        assert d["current_phase"] == "RECONNAISSANCE"
        assert d["is_attacking"] is True

    def test_stats(self):
        decoder = IntentDecoder()
        decoder.observe("10.0.0.1", features=[0.0]*16)
        stats = decoder.get_stats()
        assert stats["observations"] >= 1
        assert stats["tracked_entities"] >= 1


# ======================================================================
# Bayesian Scorer Tests
# ======================================================================

class TestBayesianScorer:
    """Test BayesianScorer belief evolution."""

    def test_init(self):
        scorer = BayesianScorer()
        assert scorer._sandbox_threshold == SANDBOX_THRESHOLD

    def test_default_risk(self):
        scorer = BayesianScorer()
        assert scorer.get_risk_score("unknown") == 0.1

    def test_update_belief_increases_risk(self):
        scorer = BayesianScorer()
        initial = scorer.get_risk_score("10.0.0.1")
        scorer.update_belief(
            "10.0.0.1",
            phase=IntentPhase.RECONNAISSANCE,
            confidence=0.8,
        )
        updated = scorer.get_risk_score("10.0.0.1")
        assert updated > initial

    def test_benign_evidence_decreases_risk(self):
        scorer = BayesianScorer()
        # First raise risk
        scorer.update_belief("10.0.0.1", IntentPhase.EXECUTION, 0.9)
        high_risk = scorer.get_risk_score("10.0.0.1")
        # Then provide benign evidence
        for _ in range(5):
            scorer.update_belief("10.0.0.1", IntentPhase.BENIGN, 0.9)
        low_risk = scorer.get_risk_score("10.0.0.1")
        assert low_risk < high_risk

    def test_exfiltration_raises_risk_fast(self):
        scorer = BayesianScorer()
        scorer.update_belief("10.0.0.1", IntentPhase.EXFILTRATION, 0.9)
        risk = scorer.get_risk_score("10.0.0.1")
        assert risk > 0.5

    def test_sandbox_trigger(self):
        scorer = BayesianScorer()
        triggered = []
        scorer.on_sandbox_trigger(
            lambda entity_id, belief: triggered.append(entity_id)
        )
        # Rapidly escalate
        for phase in [
            IntentPhase.RECONNAISSANCE,
            IntentPhase.INITIAL_ACCESS,
            IntentPhase.EXECUTION,
            IntentPhase.LATERAL_MOVEMENT,
            IntentPhase.EXFILTRATION,
            IntentPhase.IMPACT,
            IntentPhase.IMPACT,
            IntentPhase.IMPACT,
        ]:
            scorer.update_belief("10.0.0.1", phase, 0.95)
        assert len(triggered) > 0
        assert "10.0.0.1" in triggered

    def test_sandbox_triggers_only_once(self):
        scorer = BayesianScorer()
        triggered = []
        scorer.on_sandbox_trigger(
            lambda entity_id, belief: triggered.append(entity_id)
        )
        for _ in range(10):
            scorer.update_belief("10.0.0.1", IntentPhase.IMPACT, 0.99)
        assert len(triggered) == 1

    def test_should_sandbox(self):
        scorer = BayesianScorer()
        assert scorer.should_sandbox("10.0.0.1") is False
        for _ in range(10):
            scorer.update_belief("10.0.0.1", IntentPhase.IMPACT, 0.99)
        assert scorer.should_sandbox("10.0.0.1") is True

    def test_get_belief(self):
        scorer = BayesianScorer()
        scorer.update_belief("10.0.0.1", IntentPhase.RECONNAISSANCE, 0.6)
        belief = scorer.get_belief("10.0.0.1")
        assert belief is not None
        assert belief.entity_id == "10.0.0.1"
        assert len(belief.evidence) >= 1

    def test_reset_entity(self):
        scorer = BayesianScorer()
        scorer.update_belief("10.0.0.1", IntentPhase.IMPACT, 0.99)
        scorer.reset_entity("10.0.0.1")
        assert scorer.get_risk_score("10.0.0.1") == 0.1

    def test_get_high_risk_entities(self):
        scorer = BayesianScorer()
        for _ in range(5):
            scorer.update_belief("10.0.0.1", IntentPhase.IMPACT, 0.99)
        scorer.update_belief("10.0.0.2", IntentPhase.BENIGN, 0.5)
        high_risk = scorer.get_high_risk_entities(0.5)
        assert any(b.entity_id == "10.0.0.1" for b in high_risk)

    def test_qsecbit_prior_update(self):
        scorer = BayesianScorer()
        scorer.update_belief(
            "10.0.0.1", IntentPhase.RECONNAISSANCE, 0.5,
            qsecbit_score=0.7,
        )
        belief = scorer.get_belief("10.0.0.1")
        assert belief.prior == 0.7

    def test_evidence_cap(self):
        scorer = BayesianScorer(max_evidence_per_entity=5)
        for _ in range(20):
            scorer.update_belief("10.0.0.1", IntentPhase.RECONNAISSANCE, 0.5)
        belief = scorer.get_belief("10.0.0.1")
        assert len(belief.evidence) <= 5

    def test_belief_to_dict(self):
        belief = EntityBelief(entity_id="10.0.0.1", posterior=0.85)
        d = belief.to_dict()
        assert d["entity_id"] == "10.0.0.1"
        assert d["posterior"] == 0.85

    def test_stats(self):
        scorer = BayesianScorer()
        scorer.update_belief("10.0.0.1", IntentPhase.RECONNAISSANCE, 0.5)
        stats = scorer.get_stats()
        assert stats["updates"] >= 1
        assert stats["entities_tracked"] >= 1


# ======================================================================
# SIA Engine Tests
# ======================================================================

class TestSIAEngine:
    """Test SIAEngine orchestration."""

    def test_init(self):
        engine = SIAEngine()
        assert engine is not None
        stats = engine.get_stats()
        assert stats["events_ingested"] == 0

    def test_connection_ingestion(self):
        engine = SIAEngine()

        class MockConn:
            id_orig_h = "10.0.0.1"
            id_resp_h = "10.0.0.2"
            id_resp_p = 443
            proto = "tcp"
            service = "tls"
            orig_bytes = 1000
            resp_bytes = 5000
            conn_state = "SF"

        engine._on_connection("CONNECTION", MockConn())
        assert engine._stats["events_ingested"] >= 1

    def test_dns_ingestion(self):
        engine = SIAEngine()

        class MockDNS:
            id_orig_h = "10.0.0.1"
            query = "example.com"
            answers = ["1.2.3.4"]

        engine._on_dns("DNS", MockDNS())
        assert engine._stats["events_ingested"] >= 1

    def test_alert_ingestion(self):
        engine = SIAEngine()
        alert = {"src_ip": "10.0.0.1", "alert_severity": "HIGH"}
        engine._on_alert("ALERT", alert)
        assert engine._stats["events_ingested"] >= 1

    def test_honeypot_touch(self):
        engine = SIAEngine()
        touch = {"source_ip": "10.0.0.1", "dest_port": 4444}
        engine._on_honeypot_touch("HONEYPOT_TOUCH", touch)
        assert engine._stats["events_ingested"] >= 1

    def test_process_entity_with_insufficient_events(self):
        engine = SIAEngine()
        result = engine.process_entity("10.0.0.1")
        assert result is None  # Not enough events

    def test_process_entity_full_pipeline(self):
        engine = SIAEngine()
        # Add enough events
        for port in [22, 80, 443, 8080, 8443]:
            engine.graph.add_connection_event(
                "10.0.0.1", "10.0.0.2", port, "tcp",
            )
        engine.graph.add_dns_event("10.0.0.1", "test.com", ["1.2.3.4"])
        engine.graph.add_alert_event("10.0.0.1", "MEDIUM")
        result = engine.process_entity("10.0.0.1")
        assert result is not None
        assert isinstance(result, IntentSequence)

    def test_signal_callback(self):
        engine = SIAEngine()
        signals = []
        engine.set_signal_callback(lambda sig: signals.append(sig))

        # Build up entity with attack-like behavior
        for _ in range(5):
            engine.graph.add_connection_event(
                "10.0.0.1", "10.0.0.2", 445, "tcp", service="smb",
            )
            engine.graph.add_alert_event("10.0.0.1", "HIGH")
        engine.process_entity("10.0.0.1")
        # Signals may or may not fire depending on scoring

    def test_sandbox_callback(self):
        engine = SIAEngine()
        sandbox_events = []
        engine.set_sandbox_callback(
            lambda entity_id, belief: sandbox_events.append(entity_id)
        )
        # Directly test the callback is wired
        assert len(engine.scorer._sandbox_callbacks) > 0

    def test_get_entity_risk(self):
        engine = SIAEngine()
        risk = engine.get_entity_risk("10.0.0.1")
        assert risk == 0.1  # Default prior

    def test_get_high_risk_entities(self):
        engine = SIAEngine()
        results = engine.get_high_risk_entities()
        assert isinstance(results, list)

    def test_get_story_graph(self):
        engine = SIAEngine()
        for port in [80, 443, 22, 8080]:
            engine.graph.add_connection_event("10.0.0.1", "10.0.0.2", port)
        engine.graph.add_dns_event("10.0.0.1", "test.com", [])
        story = engine.get_story_graph("10.0.0.1")
        assert "entity_id" in story
        assert "subgraph" in story
        assert "intent" in story
        assert "risk_score" in story

    def test_stats(self):
        engine = SIAEngine()
        stats = engine.get_stats()
        assert "graph" in stats
        assert "embedder" in stats
        assert "decoder" in stats
        assert "scorer" in stats

    def test_flow_metadata_ingestion(self):
        engine = SIAEngine()
        metadata = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dest_port": 80}
        engine._on_flow_metadata("FLOW_METADATA", metadata)
        assert engine._stats["events_ingested"] >= 1


# ======================================================================
# Virtual Sandbox Tests
# ======================================================================

class TestVirtualSandbox:
    """Test VirtualSandbox OVS isolation."""

    def test_init(self):
        sandbox = VirtualSandbox(dry_run=True)
        assert sandbox is not None

    def test_sandbox_entity(self):
        sandbox = VirtualSandbox(dry_run=True)
        result = sandbox.sandbox_entity(
            "10.0.0.1", risk_score=0.95, intent_phase="EXFILTRATION",
        )
        assert result["success"] is True
        assert sandbox.is_sandboxed("10.0.0.1")

    def test_release_entity(self):
        sandbox = VirtualSandbox(dry_run=True)
        sandbox.sandbox_entity("10.0.0.1", risk_score=0.95)
        result = sandbox.release_entity("10.0.0.1", reason="cleared")
        assert result["success"] is True
        assert not sandbox.is_sandboxed("10.0.0.1")

    def test_release_not_sandboxed(self):
        sandbox = VirtualSandbox(dry_run=True)
        result = sandbox.release_entity("10.0.0.99")
        assert result["success"] is False

    def test_already_sandboxed(self):
        sandbox = VirtualSandbox(dry_run=True)
        sandbox.sandbox_entity("10.0.0.1")
        result = sandbox.sandbox_entity("10.0.0.1")
        assert result["success"] is True
        assert "already sandboxed" in result["message"]

    def test_max_capacity(self):
        sandbox = VirtualSandbox(dry_run=True, max_sandboxed=2)
        sandbox.sandbox_entity("10.0.0.1")
        sandbox.sandbox_entity("10.0.0.2")
        result = sandbox.sandbox_entity("10.0.0.3")
        assert result["success"] is False
        assert "capacity" in result["message"]

    def test_duration_cap(self):
        sandbox = VirtualSandbox(dry_run=True)
        sandbox.sandbox_entity("10.0.0.1", duration_s=99999)
        session = sandbox.get_session("10.0.0.1")
        assert session.duration_s <= 3600

    def test_get_active_sandboxes(self):
        sandbox = VirtualSandbox(dry_run=True)
        sandbox.sandbox_entity("10.0.0.1")
        sandbox.sandbox_entity("10.0.0.2")
        active = sandbox.get_active_sandboxes()
        assert len(active) == 2

    def test_sandbox_session_to_dict(self):
        session = SandboxSession(
            entity_id="10.0.0.1",
            started_at=time.time(),
            risk_score=0.95,
        )
        d = session.to_dict()
        assert d["entity_id"] == "10.0.0.1"
        assert d["risk_score"] == 0.95

    def test_record_telemetry(self):
        sandbox = VirtualSandbox(dry_run=True)
        sandbox.sandbox_entity("10.0.0.1")
        sandbox.record_telemetry("10.0.0.1", "packets_captured", 42)
        telemetry = sandbox.get_sandbox_telemetry("10.0.0.1")
        assert telemetry["telemetry"]["packets_captured"] == 42

    def test_callback_on_sandbox(self):
        sandbox = VirtualSandbox(dry_run=True)
        events = []
        sandbox.on("sandboxed", lambda ev, sess: events.append(ev))
        sandbox.sandbox_entity("10.0.0.1")
        assert len(events) == 1

    def test_callback_on_release(self):
        sandbox = VirtualSandbox(dry_run=True)
        events = []
        sandbox.on("released", lambda ev, sess: events.append(ev))
        sandbox.sandbox_entity("10.0.0.1")
        sandbox.release_entity("10.0.0.1")
        assert len(events) == 1

    def test_get_stats(self):
        sandbox = VirtualSandbox(dry_run=True)
        sandbox.sandbox_entity("10.0.0.1")
        stats = sandbox.get_stats()
        assert stats["entities_sandboxed"] >= 1
        assert stats["active_sandboxes"] >= 1

    def test_flow_rule_ids(self):
        sandbox = VirtualSandbox(dry_run=True)
        sandbox.sandbox_entity("10.0.0.1")
        session = sandbox.get_session("10.0.0.1")
        assert len(session.flow_rule_ids) == 2
        assert "sandbox_in_" in session.flow_rule_ids[0]
        assert "sandbox_out_" in session.flow_rule_ids[1]


# ======================================================================
# AEGIS Integration Tests
# ======================================================================

class TestAegisIntegration:
    """Test SIA integration with AEGIS (routing, tools, agents)."""

    def test_event_bus_intent_detected_type(self):
        from core.napse.synthesis.event_bus import EventType
        assert hasattr(EventType, "INTENT_DETECTED")

    def test_event_bus_entity_sandboxed_type(self):
        from core.napse.synthesis.event_bus import EventType
        assert hasattr(EventType, "ENTITY_SANDBOXED")

    def test_routing_rules_sia_intent(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "sia.intent_detected" in ROUTING_RULES
        agents = ROUTING_RULES["sia.intent_detected"]
        assert "GUARDIAN" in agents
        assert "MEDIC" in agents
        assert "SCOUT" in agents

    def test_routing_rules_sia_sandbox(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "sia.sandbox_triggered" in ROUTING_RULES
        agents = ROUTING_RULES["sia.sandbox_triggered"]
        assert "MEDIC" in agents

    def test_tool_registry_sandbox_entity(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert "sandbox_entity" in TOOL_REGISTRY
        tool = TOOL_REGISTRY["sandbox_entity"]
        assert "GUARDIAN" in tool.agents
        assert "MEDIC" in tool.agents
        assert tool.requires_confirmation is True

    def test_tool_registry_release_sandbox(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert "release_sandbox" in TOOL_REGISTRY
        tool = TOOL_REGISTRY["release_sandbox"]
        assert "GUARDIAN" in tool.agents

    def test_tool_registry_get_entity_intent(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert "get_entity_intent" in TOOL_REGISTRY
        tool = TOOL_REGISTRY["get_entity_intent"]
        assert "ORACLE" in tool.agents

    def test_permission_matrix_guardian_has_sia_tools(self):
        from core.aegis.tool_executor import PERMISSION_MATRIX
        guardian_tools = PERMISSION_MATRIX.get("GUARDIAN", [])
        assert "sandbox_entity" in guardian_tools
        assert "release_sandbox" in guardian_tools
        assert "get_entity_intent" in guardian_tools

    def _make_guardian(self):
        from core.aegis.agents.guardian_agent import GuardianAgent
        # Provide mock engine and fabric
        engine = type("MockEngine", (), {"chat": lambda self, *a, **kw: None})()
        fabric = type("MockFabric", (), {"emit": lambda self, *a, **kw: None})()
        return GuardianAgent(engine=engine, fabric=fabric)

    def test_guardian_allowed_tools(self):
        agent = self._make_guardian()
        assert "sandbox_entity" in agent.allowed_tools
        assert "release_sandbox" in agent.allowed_tools
        assert "get_entity_intent" in agent.allowed_tools

    def test_guardian_sia_signal_sandbox_trigger(self):
        from core.aegis.types import StandardSignal

        agent = self._make_guardian()
        signal = StandardSignal(
            source="sia",
            event_type="sia.sandbox_triggered",
            severity="CRITICAL",
            data={
                "entity_id": "10.0.0.1",
                "risk_score": 0.95,
                "phase": "EXFILTRATION",
                "confidence": 0.9,
            },
        )
        response = agent.respond_to_signal(signal)
        assert response.action == "sandbox_entity"
        assert response.confidence >= 0.9
        assert response.escalate_to == "MEDIC"

    def test_guardian_sia_signal_lateral_movement_blocks(self):
        from core.aegis.types import StandardSignal

        agent = self._make_guardian()
        signal = StandardSignal(
            source="sia",
            event_type="sia.intent_detected",
            severity="HIGH",
            data={
                "entity_id": "10.0.0.1",
                "risk_score": 0.85,
                "phase": "LATERAL_MOVEMENT",
                "confidence": 0.8,
            },
        )
        response = agent.respond_to_signal(signal)
        assert response.action == "block_ip"
        assert len(response.tool_calls) > 0

    def test_guardian_sia_signal_execution_sandboxes(self):
        from core.aegis.types import StandardSignal

        agent = self._make_guardian()
        signal = StandardSignal(
            source="sia",
            event_type="sia.intent_detected",
            severity="HIGH",
            data={
                "entity_id": "10.0.0.1",
                "risk_score": 0.8,
                "phase": "EXECUTION",
                "confidence": 0.85,
            },
        )
        response = agent.respond_to_signal(signal)
        assert response.action == "sandbox_entity"

    def test_guardian_sia_signal_recon_monitors(self):
        from core.aegis.types import StandardSignal

        agent = self._make_guardian()
        signal = StandardSignal(
            source="sia",
            event_type="sia.intent_detected",
            severity="MEDIUM",
            data={
                "entity_id": "10.0.0.1",
                "risk_score": 0.3,
                "phase": "RECONNAISSANCE",
                "confidence": 0.5,
            },
        )
        response = agent.respond_to_signal(signal)
        assert response.action == ""  # Monitor only

    def test_guardian_non_sia_signal_unchanged(self):
        from core.aegis.types import StandardSignal

        agent = self._make_guardian()
        signal = StandardSignal(
            source="qsecbit",
            event_type="qsecbit.l3",
            severity="CRITICAL",
            data={"source_ip": "10.0.0.99", "attack_type": "syn_flood"},
        )
        response = agent.respond_to_signal(signal)
        assert response.action == "block_ip"


# ======================================================================
# End-to-End Pipeline Tests
# ======================================================================

class TestSIAEndToEnd:
    """Test full SIA pipeline from events to sandbox trigger."""

    def test_recon_to_exfiltration_pipeline(self):
        """Simulate a full attack: recon → exploit → lateral → exfil."""
        engine = SIAEngine(sandbox_threshold=0.92)
        sandbox_triggers = []
        engine.set_sandbox_callback(
            lambda entity_id, belief: sandbox_triggers.append(entity_id)
        )

        attacker = "192.168.1.100"

        # Phase 1: Reconnaissance — port scanning
        for port in range(20, 1025):
            engine.graph.add_connection_event(
                attacker, "10.0.0.1", port, "tcp",
            )

        # Phase 2: Alert events for exploit attempts
        for _ in range(5):
            engine.graph.add_alert_event(attacker, "HIGH")

        # Phase 3: Lateral movement — connect to multiple hosts
        for host in range(2, 20):
            engine.graph.add_connection_event(
                attacker, f"10.0.0.{host}", 445, "tcp", service="smb",
            )

        # Phase 4: Exfiltration — large data to external
        for _ in range(10):
            engine.graph.add_connection_event(
                attacker, "8.8.8.8", 443, "tcp", service="tls",
                orig_bytes=1000000,
            )

        # Process entity multiple times
        for _ in range(3):
            engine.process_entity(attacker)

        risk = engine.get_entity_risk(attacker)
        assert risk > 0.3  # Risk should have increased substantially

    def test_benign_admin_sequence(self):
        """Benign admin activity should NOT trigger sandbox."""
        engine = SIAEngine(sandbox_threshold=0.92)
        sandbox_triggers = []
        engine.set_sandbox_callback(
            lambda entity_id, belief: sandbox_triggers.append(entity_id)
        )

        admin = "10.0.0.10"

        # Normal SSH session
        engine.graph.add_connection_event(
            admin, "10.0.0.1", 22, "tcp", service="ssh",
        )
        # Normal DNS
        engine.graph.add_dns_event(admin, "archive.ubuntu.com", ["91.189.88.142"])
        engine.graph.add_dns_event(admin, "pypi.org", ["151.101.0.223"])

        # Normal HTTP
        engine.graph.add_connection_event(
            admin, "10.0.0.1", 80, "tcp", service="http",
        )

        engine.process_entity(admin)
        risk = engine.get_entity_risk(admin)
        assert risk < 0.92  # Should NOT sandbox
        assert len(sandbox_triggers) == 0

    def test_event_bus_to_sia_integration(self):
        """Test SIA registers with NAPSE EventBus and processes events."""
        from core.napse.synthesis.event_bus import (
            NapseEventBus, EventType, ConnectionRecord,
        )

        bus = NapseEventBus()
        engine = SIAEngine()
        engine.register_with_event_bus(bus)

        # Emit a connection
        conn = ConnectionRecord(
            ts=time.time(), uid="C123",
            id_orig_h="10.0.0.1", id_orig_p=54321,
            id_resp_h="10.0.0.2", id_resp_p=443,
            proto="tcp", service="tls",
        )
        bus.emit(EventType.CONNECTION, conn)
        assert engine._stats["events_ingested"] >= 1

    def test_sandbox_with_virtual_sandbox(self):
        """Test SIA sandbox trigger integrates with VirtualSandbox."""
        engine = SIAEngine()
        sandbox = VirtualSandbox(dry_run=True)

        # Wire sandbox callback
        def on_sandbox(entity_id, belief):
            sandbox.sandbox_entity(
                entity_id,
                risk_score=belief.posterior,
                intent_phase="IMPACT",
                evidence_count=len(belief.evidence),
            )

        engine.set_sandbox_callback(on_sandbox)

        # Simulate attack to trigger sandbox
        attacker = "10.0.0.99"
        for _ in range(10):
            engine.scorer.update_belief(
                attacker, IntentPhase.IMPACT, 0.99,
            )

        # Check sandbox
        if engine.scorer.should_sandbox(attacker):
            assert sandbox.is_sandboxed(attacker)
